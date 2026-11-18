//! Host-owned authority records and pure destination/quota checks.
//!
//! IDs and decoded records are descriptive. Only the authenticated host may resolve them
//! into authority. Child allocation escrows the full limit; the ledger owns atomic ancestry
//! updates and releases unused backing when an allocation closes.
use std::net::IpAddr;

use serde::{Deserialize, Deserializer, Serialize};
use url::Url;

use super::invocation::Invocation;
use super::validation::{MAX_RECORD_ITEMS, bounded_vec, invalid, text_limit};
use super::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, Usage, WireInt, non_null_optional,
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

const MAX_URL_BYTES: usize = 8192;

fn denied() -> ProofError {
    ProofError::new(
        ErrorCode::PermissionDenied,
        "Authority does not match the current host binding",
    )
}

fn exhausted() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Requested resources exceed available quota",
    )
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureProject {
    pub project_id: EntityId,
    pub user_id: EntityId,
    pub scope_policy_id: EntityId,
    pub revision: WireInt,
}

impl FixtureProject {
    pub fn validate_owner(&self, user_id: EntityId) -> ProofResult<()> {
        if self.user_id != user_id {
            return Err(denied());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityProfile {
    pub identity_id: EntityId,
    pub project_id: EntityId,
    #[serde(deserialize_with = "bounded_vec")]
    pub secret_ref_names: Vec<CatalogId>,
}

impl IdentityProfile {
    pub fn validate_project(&self, project_id: EntityId) -> ProofResult<()> {
        if self.project_id != project_id {
            return Err(denied());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    LocalRead,
    LocalWrite,
    ActiveNetwork,
    DataEgress,
    Sensitive,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    SafeRead,
    Deduplicated,
    NonRetryable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolDescriptor {
    pub tool_id: CatalogId,
    pub version: ContractVersion,
    pub input_contract: CatalogId,
    pub output_contract: CatalogId,
    pub effect: Effect,
    #[serde(deserialize_with = "bounded_vec")]
    pub permissions: Vec<CatalogId>,
    pub limits: Usage,
    pub retry_class: RetryClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrant {
    pub grant_id: EntityId,
    pub project_id: EntityId,
    pub tool_id: CatalogId,
    pub tool_version: ContractVersion,
    pub provider_digest: Digest,
    pub scope_revision: WireInt,
    pub identity_id: EntityId,
    pub bounded_input_sha256: Digest,
    pub limits: Usage,
    pub expires_at: AuditTime,
    pub revoked: bool,
}

impl ApprovalGrant {
    /// Check a host-resolved grant for a new reservation or final effect admission.
    /// Historical provenance must not call this with today's grant state.
    pub fn validate_current(
        &self,
        invocation: &Invocation,
        requested: &Usage,
        now: AuditTime,
    ) -> ProofResult<()> {
        if self.revoked
            || now >= self.expires_at
            || invocation.grant_id != Some(self.grant_id)
            || invocation.project_id != self.project_id
            || invocation.tool_id != self.tool_id
            || invocation.tool_version != self.tool_version
            || invocation.provider_digest != self.provider_digest
            || invocation.scope_revision != self.scope_revision
            || invocation.identity_id != self.identity_id
            || invocation.input_sha256 != self.bounded_input_sha256
        {
            return Err(denied());
        }
        if requested.units > self.limits.units
            || requested.bytes > self.limits.bytes
            || requested.cpu_us > self.limits.cpu_us
            || requested.elapsed_us > self.limits.elapsed_us
        {
            return Err(exhausted());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "BudgetWire")]
pub struct Budget {
    pub budget_id: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_budget_id: Option<EntityId>,
    pub limit: WireInt,
    pub consumed: WireInt,
    pub reserved: WireInt,
    pub revision: WireInt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BudgetWire {
    budget_id: EntityId,
    #[serde(default, deserialize_with = "non_null_optional")]
    parent_budget_id: Option<EntityId>,
    limit: WireInt,
    consumed: WireInt,
    reserved: WireInt,
    revision: WireInt,
}

impl TryFrom<BudgetWire> for Budget {
    type Error = ProofError;
    fn try_from(value: BudgetWire) -> ProofResult<Self> {
        let budget = Self {
            budget_id: value.budget_id,
            parent_budget_id: value.parent_budget_id,
            limit: value.limit,
            consumed: value.consumed,
            reserved: value.reserved,
            revision: value.revision,
        };
        budget.validate()?;
        Ok(budget)
    }
}

impl Budget {
    pub fn validate(&self) -> ProofResult<()> {
        if self.parent_budget_id == Some(self.budget_id)
            || self
                .consumed
                .checked_add(self.reserved)
                .map_err(|_| exhausted())?
                > self.limit
        {
            return Err(exhausted());
        }
        Ok(())
    }

    fn next_revision(&self, expected: WireInt) -> ProofResult<WireInt> {
        self.validate()?;
        if self.revision != expected {
            return Err(denied());
        }
        self.revision
            .checked_add(WireInt::new(1)?)
            .map_err(Into::into)
    }

    pub fn reserve(&mut self, amount: WireInt, expected_revision: WireInt) -> ProofResult<()> {
        let revision = self.next_revision(expected_revision)?;
        let reserved = self.reserved.checked_add(amount).map_err(|_| exhausted())?;
        if self
            .consumed
            .checked_add(reserved)
            .map_err(|_| exhausted())?
            > self.limit
        {
            return Err(exhausted());
        }
        self.reserved = reserved;
        self.revision = revision;
        Ok(())
    }

    pub fn release(&mut self, amount: WireInt, expected_revision: WireInt) -> ProofResult<()> {
        self.settle(amount, WireInt::ZERO, expected_revision)
    }

    pub fn consume(&mut self, amount: WireInt, expected_revision: WireInt) -> ProofResult<()> {
        self.settle(amount, amount, expected_revision)
    }

    /// Resolve one reservation, releasing its unused portion in the same revision.
    pub fn settle(
        &mut self,
        reserved_amount: WireInt,
        actual_consumed: WireInt,
        expected_revision: WireInt,
    ) -> ProofResult<()> {
        let revision = self.next_revision(expected_revision)?;
        if actual_consumed > reserved_amount {
            return Err(exhausted());
        }
        let reserved = self
            .reserved
            .checked_sub(reserved_amount)
            .map_err(|_| exhausted())?;
        let consumed = self
            .consumed
            .checked_add(actual_consumed)
            .map_err(|_| exhausted())?;
        if consumed.checked_add(reserved).map_err(|_| exhausted())? > self.limit {
            return Err(exhausted());
        }
        self.reserved = reserved;
        self.consumed = consumed;
        self.revision = revision;
        Ok(())
    }

    /// Pure arithmetic only: the ledger must atomically persist both records, enforce ID
    /// uniqueness, and propagate actual consumption through ancestor escrow without reserving twice.
    pub fn allocate_child(
        &mut self,
        child_id: EntityId,
        limit: WireInt,
        expected_revision: WireInt,
    ) -> ProofResult<Self> {
        if child_id == self.budget_id {
            return Err(invalid());
        }
        self.reserve(limit, expected_revision)?;
        Ok(Self {
            budget_id: child_id,
            parent_budget_id: Some(self.budget_id),
            limit,
            consumed: WireInt::ZERO,
            reserved: WireInt::ZERO,
            revision: WireInt::ZERO,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Destination {
    scheme: Scheme,
    host: String,
    port: u16,
    path: String,
    query: Option<String>,
}

pub(crate) fn normalized_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(address)),
        address => address,
    }
}

impl Destination {
    /// One pure URL normalization path shared by policy and later connectors. No DNS occurs.
    pub fn parse(value: &str) -> ProofResult<Self> {
        if value.is_empty()
            || value.len() > MAX_URL_BYTES
            || value
                .bytes()
                .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control() || byte == b'\\')
        {
            return Err(invalid());
        }
        let (scheme_text, rest) = value.split_once("://").ok_or_else(invalid)?;
        let scheme = if scheme_text.eq_ignore_ascii_case("http") {
            Scheme::Http
        } else if scheme_text.eq_ignore_ascii_case("https") {
            Scheme::Https
        } else {
            return Err(invalid());
        };
        let authority = rest.split(['/', '?', '#']).next().ok_or_else(invalid)?;
        if authority.is_empty() || authority.contains('@') || authority.contains('%') {
            return Err(invalid());
        }
        let url = Url::parse(value).map_err(|_| invalid())?;
        if url.fragment().is_some() || !url.username().is_empty() || url.password().is_some() {
            return Err(invalid());
        }
        let host = match url.host().ok_or_else(invalid)? {
            url::Host::Domain(domain) => domain.to_owned(),
            url::Host::Ipv4(address) => address.to_string(),
            url::Host::Ipv6(address) => normalized_ip(IpAddr::V6(address)).to_string(),
        };
        if host.is_empty() || host.len() > 253 {
            return Err(invalid());
        }
        let port = url.port_or_known_default().ok_or_else(invalid)?;
        if port == 0 {
            return Err(invalid());
        }
        let path = canonical_path(url.path())?;
        Ok(Self {
            scheme,
            host,
            port,
            path,
            query: url.query().map(str::to_owned),
        })
    }

    pub const fn scheme(&self) -> &'static str {
        self.scheme.as_str()
    }
    pub fn host(&self) -> &str {
        &self.host
    }
    pub const fn port(&self) -> u16 {
        self.port
    }
    pub fn path(&self) -> &str {
        &self.path
    }
}

fn canonical_path(value: &str) -> ProofResult<String> {
    if value.is_empty() || value.len() > MAX_URL_BYTES || !value.starts_with('/') {
        return Err(invalid());
    }
    let mut path = String::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            // URL paths are ASCII percent-encoded by the reviewed URL parser.
            if !bytes[index].is_ascii() {
                return Err(invalid());
            }
            path.push(char::from(bytes[index]));
            index += 1;
            continue;
        }
        let pair = bytes.get(index + 1..index + 3).ok_or_else(invalid)?;
        let digit = |byte: u8| {
            char::from(byte)
                .to_digit(16)
                .map(|value| value as u8)
                .ok_or_else(invalid)
        };
        let decoded = (digit(pair[0])? << 4) | digit(pair[1])?;
        if decoded.is_ascii_control() || matches!(decoded, b'/' | b'\\' | b'%') {
            return Err(invalid());
        }
        if decoded.is_ascii_alphanumeric() || b"-._~".contains(&decoded) {
            path.push(char::from(decoded));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            path.push('%');
            path.push(char::from(HEX[usize::from(decoded >> 4)]));
            path.push(char::from(HEX[usize::from(decoded & 15)]));
        }
        index += 3;
    }
    Ok(path)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Exact,
    Prefix,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "PathRuleWire")]
pub struct PathRule {
    pub kind: PathKind,
    pub value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PathRuleWire {
    kind: PathKind,
    #[serde(deserialize_with = "path_text")]
    value: String,
}

fn path_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    text_limit::<D, MAX_URL_BYTES>(deserializer)
}

impl TryFrom<PathRuleWire> for PathRule {
    type Error = ProofError;
    fn try_from(value: PathRuleWire) -> ProofResult<Self> {
        if value.value.contains(['?', '#', '\\']) {
            return Err(invalid());
        }
        let normalized = Destination::parse(&format!("https://scope.invalid{}", value.value))?;
        if normalized.path != value.value {
            return Err(invalid());
        }
        Ok(Self {
            kind: value.kind,
            value: value.value,
        })
    }
}

impl PathRule {
    fn matches(&self, path: &str) -> bool {
        match self.kind {
            PathKind::Exact => path == self.value,
            PathKind::Prefix => path.starts_with(&self.value),
        }
    }
    fn contains(&self, child: &Self) -> bool {
        match self.kind {
            PathKind::Exact => child.kind == PathKind::Exact && self.value == child.value,
            PathKind::Prefix => child.value.starts_with(&self.value),
        }
    }
    fn overlaps(&self, other: &Self) -> bool {
        self.matches(&other.value) || other.matches(&self.value)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "DestinationRuleWire")]
pub struct DestinationRule {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    pub path: PathRule,
    pub resolved_addresses: Vec<IpAddr>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DestinationRuleWire {
    scheme: Scheme,
    #[serde(deserialize_with = "host_text")]
    host: String,
    port: u16,
    path: PathRule,
    #[serde(deserialize_with = "bounded_vec")]
    resolved_addresses: Vec<IpAddr>,
}

fn host_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    text_limit::<D, 253>(deserializer)
}

impl TryFrom<DestinationRuleWire> for DestinationRule {
    type Error = ProofError;
    fn try_from(value: DestinationRuleWire) -> ProofResult<Self> {
        if value.resolved_addresses.is_empty()
            || value.host.contains(['/', '?', '#', '@', '%', '[', ']'])
        {
            return Err(invalid());
        }
        let bracketed = value
            .host
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_ipv6());
        let url = if bracketed {
            format!(
                "{}://[{}]:{}/",
                value.scheme.as_str(),
                value.host,
                value.port
            )
        } else {
            format!("{}://{}:{}/", value.scheme.as_str(), value.host, value.port)
        };
        let destination = Destination::parse(&url)?;
        if destination.host != value.host {
            return Err(invalid());
        }
        if value
            .resolved_addresses
            .iter()
            .any(|address| normalized_ip(*address) != *address)
        {
            return Err(invalid());
        }
        Ok(Self {
            scheme: value.scheme,
            host: value.host,
            port: value.port,
            path: value.path,
            resolved_addresses: value.resolved_addresses,
        })
    }
}

impl DestinationRule {
    fn same_authority(&self, other: &Self) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port == other.port
    }
    fn matches(&self, destination: &Destination) -> bool {
        self.scheme == destination.scheme
            && self.host == destination.host
            && self.port == destination.port
            && self.path.matches(&destination.path)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopePolicy {
    pub scope_policy_id: EntityId,
    pub project_id: EntityId,
    pub revision: WireInt,
    #[serde(deserialize_with = "bounded_vec")]
    pub allowed_destinations: Vec<DestinationRule>,
    #[serde(deserialize_with = "bounded_vec")]
    pub exclusions: Vec<DestinationRule>,
}

#[derive(Clone, Copy, Debug)]
pub struct DestinationCheck<'a> {
    pub destination: &'a Destination,
    pub resolved_addresses: &'a [IpAddr],
    pub chosen_address: IpAddr,
    pub connect_authority: Option<&'a str>,
    pub server_name: Option<&'a str>,
    pub request_authority: Option<&'a str>,
}

impl ScopePolicy {
    pub fn authorize(&self, check: &DestinationCheck<'_>) -> ProofResult<()> {
        let out_of_scope = || {
            ProofError::new(
                ErrorCode::OutOfScope,
                "Destination is not explicitly permitted by current scope",
            )
        };
        if check.resolved_addresses.is_empty()
            || check.resolved_addresses.len() > MAX_RECORD_ITEMS
            || self
                .exclusions
                .iter()
                .any(|rule| rule.matches(check.destination))
        {
            return Err(out_of_scope());
        }
        let chosen = normalized_ip(check.chosen_address);
        if !check
            .resolved_addresses
            .iter()
            .any(|address| normalized_ip(*address) == chosen)
        {
            return Err(out_of_scope());
        }
        let permitted = self.allowed_destinations.iter().any(|rule| {
            rule.matches(check.destination)
                && check
                    .resolved_addresses
                    .iter()
                    .all(|address| rule.resolved_addresses.contains(&normalized_ip(*address)))
        });
        if !permitted {
            return Err(out_of_scope());
        }
        for authority in [check.connect_authority, check.request_authority]
            .into_iter()
            .flatten()
        {
            if !authority_matches(check.destination, authority)? {
                return Err(out_of_scope());
            }
        }
        if let Some(server_name) = check.server_name {
            if server_name.contains([':', '/', '?', '#', '@']) {
                return Err(out_of_scope());
            }
            let expected = Destination::parse(&format!("https://{server_name}/"))?;
            if expected.host() != check.destination.host() {
                return Err(out_of_scope());
            }
        }
        Ok(())
    }

    /// Conservative structural subset check. Discovery/DNS cannot expand a delegated policy.
    pub fn validate_child(&self, child: &Self) -> ProofResult<()> {
        if self.project_id != child.project_id {
            return Err(denied());
        }
        for rule in &child.allowed_destinations {
            if !self.allowed_destinations.iter().any(|parent| {
                parent.same_authority(rule)
                    && parent.path.contains(&rule.path)
                    && rule
                        .resolved_addresses
                        .iter()
                        .all(|address| parent.resolved_addresses.contains(address))
            }) {
                return Err(denied());
            }
            for exclusion in &self.exclusions {
                if exclusion.same_authority(rule)
                    && exclusion.path.overlaps(&rule.path)
                    && !child.exclusions.iter().any(|retained| {
                        retained.same_authority(exclusion)
                            && retained.path.contains(&exclusion.path)
                    })
                {
                    return Err(denied());
                }
            }
        }
        Ok(())
    }
}

fn authority_matches(destination: &Destination, authority: &str) -> ProofResult<bool> {
    if authority.contains(['/', '?', '#', '@']) {
        return Err(invalid());
    }
    let parsed = Destination::parse(&format!("{}://{authority}/", destination.scheme()))?;
    Ok(parsed.host == destination.host && parsed.port == destination.port)
}
