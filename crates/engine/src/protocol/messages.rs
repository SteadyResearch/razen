//! Role-bound wire payloads. References describe data; they never establish authority.
use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};
use std::fmt;
use std::marker::PhantomData;

use base64::Engine as _;
use base64::display::Base64Display;
use base64::engine::general_purpose::STANDARD;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::value::RawValue;

use super::codec::{ChannelRole, Direction};
use super::error::{ErrorCode, ProofError, ProofResult, Retryability};
use crate::domain::runtime::{RuntimeCapability, capabilities};
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage, WireInt,
    non_null_optional,
};

pub const MAX_REFERENCES: usize = 256;
pub const MAX_ATTESTATION_ENTRIES: usize = 128;
pub const MAX_OUTPUT_CHUNK_BYTES: usize = 65_536;
const MAX_BASE64_BYTES: usize = MAX_OUTPUT_CHUNK_BYTES.div_ceil(3) * 4;
const MAX_TEXT_BYTES: usize = 256;
const MAX_INPUT_DEPTH: usize = 64;
const MAX_INPUT_NODES: usize = 65_536;
const MAX_INPUT_STRING_BYTES: usize = 1_048_576;
const MAX_INPUT_KEY_BYTES: usize = 128;

#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum Message<'a> {
    RuntimeStart(RuntimeStart),
    RuntimeStarted(RuntimeStarted),
    ToolRequest(ToolRequest<'a>),
    ToolResult(ToolResult),
    RuntimeEvent(RuntimeEvent),
    RuntimeSteer(RuntimeSteer),
    RuntimeCancel(RuntimeCancel<'a>),
    RuntimeResult(RuntimeResult),
    RuntimeClose(RuntimeClose<'a>),
    RuntimeClosed(RuntimeClosed),
    SupervisorLaunch(SupervisorLaunch),
    SupervisorReady(Box<SupervisorReady<'a>>),
    SupervisorStarted(SupervisorStarted),
    SupervisorOutput(SupervisorOutput),
    SupervisorUsage(SupervisorUsage),
    SupervisorTerminated(SupervisorTerminated),
    SupervisorError(SupervisorError),
    SupervisorLeaseRefresh(SupervisorLeaseRefresh),
    SupervisorCancel(SupervisorControl<'a>),
    SupervisorClose(SupervisorControl<'a>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStart {
    pub binding_id: EntityId,
    pub contract_version: ContractVersion,
    #[serde(deserialize_with = "references")]
    pub context_refs: Vec<EntityId>,
    #[serde(deserialize_with = "catalog_ids")]
    pub tool_ids: Vec<CatalogId>,
    pub budget_summary: BudgetSummary,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetSummary {
    pub limit: WireInt,
    pub consumed: WireInt,
    pub reserved: WireInt,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeStarted {
    #[serde(deserialize_with = "capabilities")]
    pub capabilities: Vec<RuntimeCapability>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolRequest<'a> {
    pub call_id: EntityId,
    pub tool_id: CatalogId,
    pub tool_version: ContractVersion,
    #[serde(borrow)]
    pub input: &'a RawValue,
    pub source_control_revision: WireInt,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolResult {
    pub call_id: EntityId,
    pub invocation_id: EntityId,
    pub state: InvocationState,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub output_ref: Option<EntityId>,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub error: Option<ProofError>,
    pub usage: Usage,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeEvent {
    pub event_type: CatalogId,
    pub source_control_revision: WireInt,
    pub sequence: WireInt,
    #[serde(deserialize_with = "references")]
    pub data_refs: Vec<EntityId>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSteer {
    pub control_revision: WireInt,
    pub instruction_ref: EntityId,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCancel<'a> {
    pub control_revision: WireInt,
    #[serde(borrow, deserialize_with = "text")]
    pub reason: Cow<'a, str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompletionState {
    Completed,
    Failed,
    Cancelled,
    BudgetExhausted,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeResult {
    pub state: CompletionState,
    pub source_control_revision: WireInt,
    #[serde(deserialize_with = "references")]
    pub proposal_refs: Vec<EntityId>,
    pub usage: Usage,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub error: Option<ProofError>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClose<'a> {
    #[serde(borrow, deserialize_with = "text")]
    pub reason: Cow<'a, str>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeClosed {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorLaunch {
    pub binding_id: EntityId,
    pub invocation_id: EntityId,
    pub run_id: EntityId,
    pub attestation_id: EntityId,
    pub profile_sha256: Digest,
    pub approved_fixture_id: CatalogId,
    #[serde(deserialize_with = "artifact_references")]
    pub input_artifact_refs: Vec<ArtifactEvidenceRef>,
    pub lease_id: EntityId,
    pub control_revision: WireInt,
}

/// Artifact-only evidence; ownership, digest and artifact-length checks belong to resolution.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEvidenceRef {
    pub artifact_id: EntityId,
    pub sha256: Digest,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub range_start: Option<WireInt>,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub range_end: Option<WireInt>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorReady<'a> {
    pub invocation_id: EntityId,
    #[serde(borrow)]
    pub attestation: SandboxAttestation<'a>,
}

/// These maps record measured data. Decoding does not attest policy compliance or ID binding.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxAttestation<'a> {
    pub attestation_id: EntityId,
    pub run_id: EntityId,
    pub backend: CatalogId,
    #[serde(borrow, deserialize_with = "text")]
    pub manager_version: Cow<'a, str>,
    #[serde(borrow, deserialize_with = "image_digest")]
    pub image_digest: Cow<'a, str>,
    #[serde(borrow, deserialize_with = "text")]
    pub kernel_version: Cow<'a, str>,
    pub effective_config_sha256: Digest,
    pub provisioning_sha256: Digest,
    #[serde(deserialize_with = "catalog_map")]
    pub binary_digests: BTreeMap<CatalogId, Digest>,
    pub seccomp_sha256: Digest,
    #[serde(deserialize_with = "catalog_map")]
    pub namespace_checks: BTreeMap<CatalogId, bool>,
    #[serde(deserialize_with = "catalog_map")]
    pub controller_checks: BTreeMap<CatalogId, bool>,
    #[serde(deserialize_with = "catalog_map")]
    pub mount_checks: BTreeMap<CatalogId, bool>,
    #[serde(deserialize_with = "catalog_map")]
    pub socket_checks: BTreeMap<CatalogId, bool>,
    #[serde(deserialize_with = "catalog_map")]
    pub uid_checks: BTreeMap<CatalogId, bool>,
    #[serde(deserialize_with = "catalog_map")]
    pub observed_limits: BTreeMap<CatalogId, WireInt>,
    pub created_at: AuditTime,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorStarted {
    pub invocation_id: EntityId,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputStream {
    Stdout,
    Stderr,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorOutput {
    pub invocation_id: EntityId,
    pub stream: OutputStream,
    pub sequence: WireInt,
    #[serde(
        rename = "bytes_base64",
        deserialize_with = "output_chunk",
        serialize_with = "serialize_output_chunk"
    )]
    pub bytes: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorUsage {
    pub invocation_id: EntityId,
    pub cpu_time_us: WireInt,
    pub memory_peak_bytes: WireInt,
    pub pids_peak: WireInt,
    pub tmpfs_peak_bytes: WireInt,
    pub output_bytes: WireInt,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorTerminated {
    pub invocation_id: EntityId,
    pub outcome: CompletionState,
    pub empty_cgroup: bool,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub exit_code: Option<WireInt>,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub signal: Option<WireInt>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorError {
    pub invocation_id: EntityId,
    pub error: ProofError,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorLeaseRefresh {
    pub binding_id: EntityId,
    pub invocation_id: EntityId,
    pub lease_id: EntityId,
    pub control_revision: WireInt,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupervisorControl<'a> {
    pub binding_id: EntityId,
    pub invocation_id: EntityId,
    pub lease_id: EntityId,
    pub control_revision: WireInt,
    #[serde(borrow, deserialize_with = "text")]
    pub reason: Cow<'a, str>,
}

/// Decode exactly the authenticated role/direction's schema, never infer a role from payload.
pub fn decode_payload<'a>(
    payload: &'a RawValue,
    role: ChannelRole,
    direction: Direction,
    kind: &str,
) -> ProofResult<Message<'a>> {
    use ChannelRole::{Runtime, Supervisor};
    use Direction::{HostToPeer, PeerToHost};
    let message = match (role, direction, kind) {
        (Runtime, HostToPeer, "start") => Message::RuntimeStart(parse(payload)?),
        (Runtime, PeerToHost, "started") => Message::RuntimeStarted(parse(payload)?),
        (Runtime, PeerToHost, "tool_request") => Message::ToolRequest(parse(payload)?),
        (Runtime, HostToPeer, "tool_result") => Message::ToolResult(parse(payload)?),
        (Runtime, PeerToHost, "event") => Message::RuntimeEvent(parse(payload)?),
        (Runtime, HostToPeer, "steer") => Message::RuntimeSteer(parse(payload)?),
        (Runtime, HostToPeer, "cancel") => Message::RuntimeCancel(parse(payload)?),
        (Runtime, PeerToHost, "result") => Message::RuntimeResult(parse(payload)?),
        (Runtime, HostToPeer, "close") => Message::RuntimeClose(parse(payload)?),
        (Runtime, PeerToHost, "closed") => Message::RuntimeClosed(parse(payload)?),
        (Supervisor, HostToPeer, "launch") => Message::SupervisorLaunch(parse(payload)?),
        (Supervisor, PeerToHost, "ready") => Message::SupervisorReady(parse(payload)?),
        (Supervisor, PeerToHost, "started") => Message::SupervisorStarted(parse(payload)?),
        (Supervisor, PeerToHost, "output") => Message::SupervisorOutput(parse(payload)?),
        (Supervisor, PeerToHost, "usage") => Message::SupervisorUsage(parse(payload)?),
        (Supervisor, PeerToHost, "terminated") => Message::SupervisorTerminated(parse(payload)?),
        (Supervisor, PeerToHost, "error") => Message::SupervisorError(parse(payload)?),
        (Supervisor, HostToPeer, "lease_refresh") => {
            Message::SupervisorLeaseRefresh(parse(payload)?)
        }
        (Supervisor, HostToPeer, "cancel") => Message::SupervisorCancel(parse(payload)?),
        (Supervisor, HostToPeer, "close") => Message::SupervisorClose(parse(payload)?),
        _ => {
            return Err(ProofError::new(
                ErrorCode::InvalidInput,
                "Kind is not allowed on this channel",
            ));
        }
    };
    validate(&message)?;
    Ok(message)
}

fn parse<'a, T: Deserialize<'a>>(payload: &'a RawValue) -> ProofResult<T> {
    // from_str consumes the complete value and rejects trailing non-whitespace data.
    serde_json::from_str(payload.get()).map_err(|_| invalid_payload())
}

fn invalid_payload() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Message payload does not match its wire schema",
    )
}

fn validate(message: &Message<'_>) -> ProofResult<()> {
    match message {
        Message::RuntimeStart(start) => {
            if !start
                .budget_summary
                .consumed
                .checked_add(start.budget_summary.reserved)
                .is_ok_and(|total| total <= start.budget_summary.limit)
            {
                return Err(invalid_payload());
            }
        }
        Message::ToolRequest(request) => validate_raw_input(request.input)?,
        Message::ToolResult(result) => {
            if result.output_ref.is_some() && result.error.is_some()
                || result.state == InvocationState::Completed && result.error.is_some()
            {
                return Err(invalid_payload());
            }
            if result.state == InvocationState::OutcomeUnknown
                && !result.error.as_ref().is_some_and(|error| {
                    error.code == ErrorCode::OutcomeUnknown
                        && error.retryability == Retryability::Reconcile
                })
            {
                return Err(invalid_payload());
            }
        }
        Message::RuntimeResult(result) => {
            if result.state == CompletionState::Completed && result.error.is_some() {
                return Err(invalid_payload());
            }
        }
        Message::SupervisorLaunch(launch) => {
            for reference in &launch.input_artifact_refs {
                match (reference.range_start, reference.range_end) {
                    (None, None) => {}
                    (Some(start), Some(end)) if start <= end => {}
                    _ => return Err(invalid_payload()),
                }
            }
        }
        Message::SupervisorTerminated(termination)
            if (termination.exit_code.is_some() && termination.signal.is_some()
                || termination.exit_code.is_some_and(|code| code.get() > 255)
                || termination
                    .signal
                    .is_some_and(|signal| !(1..=64).contains(&signal.get()))) =>
        {
            return Err(invalid_payload());
        }
        _ => {}
    }
    Ok(())
}

fn references<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<EntityId>, D::Error> {
    bounded_vec::<D, EntityId, MAX_REFERENCES>(deserializer)
}

fn catalog_ids<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<CatalogId>, D::Error> {
    bounded_vec::<D, CatalogId, MAX_REFERENCES>(deserializer)
}

fn artifact_references<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ArtifactEvidenceRef>, D::Error> {
    bounded_vec::<D, ArtifactEvidenceRef, MAX_REFERENCES>(deserializer)
}

fn bounded_vec<'de, D, T, const MAX: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedSequence<T, const MAX: usize>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const MAX: usize> Visitor<'de> for BoundedSequence<T, MAX> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "an array of at most {MAX} entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut entries = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(MAX));
            while entries.len() < MAX {
                match sequence.next_element()? {
                    Some(entry) => entries.push(entry),
                    None => return Ok(entries),
                }
            }
            if sequence.next_element::<de::IgnoredAny>()?.is_some() {
                return Err(de::Error::custom("Collection exceeds its entry limit"));
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_seq(BoundedSequence::<T, MAX>(PhantomData))
}

fn catalog_map<'de, D, T>(deserializer: D) -> Result<BTreeMap<CatalogId, T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct CatalogMap<T>(PhantomData<T>);
    impl<'de, T: Deserialize<'de>> Visitor<'de> for CatalogMap<T> {
        type Value = BTreeMap<CatalogId, T>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded map with unique catalog keys")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut entries = BTreeMap::new();
            while let Some(key) = map.next_key::<CatalogId>()? {
                if entries.len() == MAX_ATTESTATION_ENTRIES {
                    return Err(de::Error::custom("Excessive attestation map keys"));
                }
                match entries.entry(key) {
                    Entry::Vacant(entry) => {
                        entry.insert(map.next_value()?);
                    }
                    Entry::Occupied(_) => {
                        return Err(de::Error::custom("Duplicate attestation map key"));
                    }
                }
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_map(CatalogMap(PhantomData))
}

fn borrowed_text<'de, D: Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<Cow<'de, str>, D::Error> {
    struct Text<const MAX: usize>;
    impl<'de, const MAX: usize> Visitor<'de> for Text<MAX> {
        type Value = Cow<'de, str>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a nonempty UTF-8 string of at most {MAX} bytes")
        }
        fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
            check_text::<E, MAX>(value)?;
            Ok(Cow::Borrowed(value))
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
            check_text::<E, MAX>(value)?;
            Ok(Cow::Owned(value.to_owned()))
        }
        fn visit_string<E: de::Error>(self, value: String) -> Result<Self::Value, E> {
            check_text::<E, MAX>(&value)?;
            Ok(Cow::Owned(value))
        }
    }
    deserializer.deserialize_str(Text::<MAX>)
}

fn check_text<E: de::Error, const MAX: usize>(value: &str) -> Result<(), E> {
    if value.is_empty() || value.len() > MAX {
        return Err(E::custom("String is empty or exceeds its byte limit"));
    }
    Ok(())
}

fn text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Cow<'de, str>, D::Error> {
    borrowed_text::<D, MAX_TEXT_BYTES>(deserializer)
}

fn image_digest<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Cow<'de, str>, D::Error> {
    let digest = borrowed_text::<D, 135>(deserializer)?;
    let valid = digest.strip_prefix("sha512:").is_some_and(|hex| {
        hex.len() == 128
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if !valid {
        return Err(de::Error::custom("Invalid upstream image SHA-512 digest"));
    }
    Ok(digest)
}

fn output_chunk<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let chunk = borrowed_text::<D, MAX_BASE64_BYTES>(deserializer)?;
    let bytes = STANDARD
        .decode(chunk.as_bytes())
        .map_err(|_| de::Error::custom("Invalid Base64 output chunk"))?;
    if bytes.is_empty() || bytes.len() > MAX_OUTPUT_CHUNK_BYTES {
        return Err(de::Error::custom("Empty or excessive decoded output chunk"));
    }
    Ok(bytes)
}

fn serialize_output_chunk<S: serde::Serializer>(
    bytes: &[u8],
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&Base64Display::new(bytes, &STANDARD))
}

// Only opaque tool input needs a structural walk: typed payloads already enforce their schema.
fn validate_raw_input(input: &RawValue) -> ProofResult<()> {
    let mut remaining = MAX_INPUT_NODES;
    let mut deserializer = serde_json::Deserializer::from_str(input.get());
    InputValue {
        remaining: &mut remaining,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(|_| invalid_payload())?;
    deserializer.end().map_err(|_| invalid_payload())
}

struct InputValue<'b> {
    remaining: &'b mut usize,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for InputValue<'_> {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        if *self.remaining == 0 || self.depth >= MAX_INPUT_DEPTH {
            return Err(de::Error::custom("Tool input exceeds structural limits"));
        }
        *self.remaining -= 1;
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for InputValue<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded JSON tool input with unique object keys")
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<(), E> {
        if value.len() > MAX_INPUT_STRING_BYTES {
            return Err(E::custom("Tool input string exceeds its byte limit"));
        }
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<(), A::Error> {
        let mut length = 0;
        loop {
            if length == MAX_REFERENCES {
                let _ = sequence.next_element_seed(InputLimit)?;
                return Ok(());
            }
            let next = sequence.next_element_seed(InputValue {
                remaining: &mut *self.remaining,
                depth: self.depth + 1,
            })?;
            if next.is_none() {
                return Ok(());
            }
            length += 1;
        }
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut keys = BTreeSet::new();
        loop {
            if keys.len() == MAX_REFERENCES {
                let _ = map.next_key_seed(InputLimit)?;
                return Ok(());
            }
            let Some(key) = map.next_key_seed(InputKey)? else {
                return Ok(());
            };
            if *self.remaining == 0 || !keys.insert(key) {
                return Err(de::Error::custom("Duplicate or excessive tool input keys"));
            }
            *self.remaining -= 1;
            map.next_value_seed(InputValue {
                remaining: &mut *self.remaining,
                depth: self.depth + 1,
            })?;
        }
    }
}

struct InputLimit;

impl<'de> DeserializeSeed<'de> for InputLimit {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
        Err(de::Error::custom(
            "Tool input collection exceeds its entry limit",
        ))
    }
}

struct InputKey;

impl<'de> DeserializeSeed<'de> for InputKey {
    type Value = Cow<'de, str>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for InputKey {
    type Value = Cow<'de, str>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON object key")
    }

    fn visit_borrowed_str<E: de::Error>(self, value: &'de str) -> Result<Self::Value, E> {
        if value.len() > MAX_INPUT_KEY_BYTES {
            return Err(E::custom("Tool input key exceeds its byte limit"));
        }
        Ok(Cow::Borrowed(value))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        if value.len() > MAX_INPUT_KEY_BYTES {
            return Err(E::custom("Tool input key exceeds its byte limit"));
        }
        Ok(Cow::Owned(value.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(json: &str) -> &RawValue {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn opaque_tool_input_rejects_nested_and_escape_equivalent_duplicate_keys() {
        for input in [
            r#"{"nested":{"offset":0,"offset":1}}"#,
            r#"{"nested":[{"offset":0,"\u006fffset":1}]}"#,
        ] {
            let json = format!(
                r#"{{"call_id":"0344f2f2-c854-4d37-9d20-bd7e83c66342","tool_id":"traffic.snapshot.read","tool_version":"0.1.0","input":{input},"source_control_revision":0}}"#
            );
            assert!(
                decode_payload(
                    payload(&json),
                    ChannelRole::Runtime,
                    Direction::PeerToHost,
                    "tool_request"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn opaque_tool_input_enforces_collection_depth_and_total_node_limits() {
        let oversized_array = format!("[{}]", vec!["0"; MAX_REFERENCES + 1].join(","));
        assert!(validate_raw_input(payload(&oversized_array)).is_err());
        let too_deep = format!(
            "{}0{}",
            "[".repeat(MAX_INPUT_DEPTH),
            "]".repeat(MAX_INPUT_DEPTH)
        );
        assert!(validate_raw_input(payload(&too_deep)).is_err());
        let row = format!("[{}]", vec!["0"; MAX_REFERENCES].join(","));
        let too_many_nodes = format!("[{}]", vec![row; MAX_REFERENCES].join(","));
        assert!(validate_raw_input(payload(&too_many_nodes)).is_err());
    }

    #[test]
    fn budget_summary_rejects_overcommitted_and_overflowing_totals() {
        for budget in [
            r#"{"limit":5,"consumed":4,"reserved":2}"#,
            r#"{"limit":9007199254740991,"consumed":9007199254740991,"reserved":1}"#,
            r#"{"limit":5,"consumed":0}"#,
            r#"{"limit":5,"consumed":0,"reserved":null}"#,
        ] {
            let json = format!(
                r#"{{"binding_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d","contract_version":"0.1.0","context_refs":[],"tool_ids":[],"budget_summary":{budget}}}"#
            );
            assert!(
                decode_payload(
                    payload(&json),
                    ChannelRole::Runtime,
                    Direction::HostToPeer,
                    "start"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn artifact_launch_rejects_snapshot_fields_partial_ranges_and_reversed_ranges() {
        for extra in [
            r#","snapshot_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d""#,
            r#","revision":0"#,
            r#","range_start":0"#,
            r#","range_start":2,"range_end":1"#,
            r#","range_start":null,"range_end":2"#,
        ] {
            let json = format!(
                r#"{{"binding_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d","invocation_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d","run_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d","attestation_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d","profile_sha256":"{}","approved_fixture_id":"R0-01","input_artifact_refs":[{{"artifact_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d","sha256":"{}"{extra}}}],"lease_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d","control_revision":0}}"#,
                "0".repeat(64),
                "0".repeat(64)
            );
            assert!(
                decode_payload(
                    payload(&json),
                    ChannelRole::Supervisor,
                    Direction::HostToPeer,
                    "launch"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn duplicate_attestation_map_keys_cannot_overwrite_failed_checks() {
        let mut duplicate =
            serde_json::Deserializer::from_str(r#"{"user_namespace":false,"user_namespace":true}"#);
        let result: Result<BTreeMap<CatalogId, bool>, _> = catalog_map(&mut duplicate);
        assert!(result.is_err());
        let mut invalid_key = serde_json::Deserializer::from_str(r#"{"not a catalog key":true}"#);
        let invalid_key: Result<BTreeMap<CatalogId, bool>, _> = catalog_map(&mut invalid_key);
        assert!(invalid_key.is_err());
    }

    #[test]
    fn authenticated_role_and_direction_reject_the_other_started_schema() {
        let supervisor = payload(r#"{"invocation_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d"}"#);
        assert!(
            decode_payload(
                supervisor,
                ChannelRole::Runtime,
                Direction::PeerToHost,
                "started"
            )
            .is_err()
        );
        assert!(
            decode_payload(
                supervisor,
                ChannelRole::Supervisor,
                Direction::HostToPeer,
                "started"
            )
            .is_err()
        );
        let runtime = payload(
            r#"{"capabilities":["brokered_calls","events","results","usage","cancellation","closure"]}"#,
        );
        assert!(
            decode_payload(
                runtime,
                ChannelRole::Supervisor,
                Direction::PeerToHost,
                "started"
            )
            .is_err()
        );
    }

    #[test]
    fn runtime_capabilities_reject_duplicates_unknowns_and_missing_mandatory_handles() {
        for json in [
            r#"{"capabilities":["brokered_calls","events","results","usage","cancellation","closure","events"]}"#,
            r#"{"capabilities":["brokered_calls","events","results","usage","cancellation","closure","shell"]}"#,
            r#"{"capabilities":["brokered_calls","events","results","usage","cancellation"]}"#,
            r#"{"capabilities":[],"capabilities":["brokered_calls","events","results","usage","cancellation","closure"]}"#,
        ] {
            assert!(
                decode_payload(
                    payload(json),
                    ChannelRole::Runtime,
                    Direction::PeerToHost,
                    "started"
                )
                .is_err()
            );
        }
    }

    #[test]
    fn output_chunks_reject_noncanonical_padding_and_empty_or_excessive_decoded_data() {
        for chunk in ["", "YQ", "YR==", "YWJ=", "YQ==\n", "====", "AA=A"] {
            let json = serde_json::json!({
                "invocation_id": "c1a77a92-a09e-4810-a25b-2abcaa899e3d",
                "stream": "stdout", "sequence": 0, "bytes_base64": chunk
            })
            .to_string();
            assert!(
                decode_payload(
                    payload(&json),
                    ChannelRole::Supervisor,
                    Direction::PeerToHost,
                    "output"
                )
                .is_err()
            );
        }
        let too_large = "A".repeat((MAX_OUTPUT_CHUNK_BYTES + 2).div_ceil(3) * 4);
        let json = format!(
            r#"{{"invocation_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d","stream":"stdout","sequence":0,"bytes_base64":"{too_large}"}}"#
        );
        assert!(
            decode_payload(
                payload(&json),
                ChannelRole::Supervisor,
                Direction::PeerToHost,
                "output"
            )
            .is_err()
        );
    }

    #[test]
    fn supervisor_output_decodes_binary_bytes_and_preserves_its_wire_representation() {
        let json = r#"{"invocation_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d","stream":"stdout","sequence":0,"bytes_base64":"AAECA/8="}"#;
        let message = decode_payload(
            payload(json),
            ChannelRole::Supervisor,
            Direction::PeerToHost,
            "output",
        )
        .unwrap();
        let Message::SupervisorOutput(output) = &message else {
            panic!("Expected supervisor output")
        };
        assert_eq!(output.bytes, [0, 1, 2, 3, 255]);
        assert_eq!(
            serde_json::to_value(message).unwrap()["bytes_base64"],
            "AAECA/8="
        );
    }

    #[test]
    fn terminated_rejects_null_conflicting_and_out_of_range_process_statuses() {
        for status in [
            r#", "exit_code":null"#,
            r#", "exit_code":0,"signal":9"#,
            r#", "exit_code":256"#,
            r#", "signal":0"#,
            r#", "signal":65"#,
        ] {
            let json = format!(
                r#"{{"invocation_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d","outcome":"failed","empty_cgroup":true{status}}}"#
            );
            assert!(
                decode_payload(
                    payload(&json),
                    ChannelRole::Supervisor,
                    Direction::PeerToHost,
                    "terminated"
                )
                .is_err()
            );
        }
    }
}
