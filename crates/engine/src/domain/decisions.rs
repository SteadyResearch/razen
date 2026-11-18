//! Source observations are not download verification, legal clearance, or human approval.
use crate::domain::{
    evidence::EvidenceRef,
    proofs::{ImageDigest, VersionPin},
    validation::{bounded_text, bounded_vec, text_limit},
    values::{AuditTime, CatalogId, Digest, EntityId, non_null_optional},
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use serde::{Deserialize, Deserializer, Serialize};

fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Dependency or decision record violates its bounded provenance contract",
    )
}
pub(crate) fn safe_text(value: &str, max: usize) -> bool {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        return false;
    }
    ![
        "/users/",
        "/home/",
        "/private/",
        "/var/root/",
        "begin private key",
        "begin rsa private key",
        "begin openssh private key",
        "authorization: bearer",
        "access_token=",
        "password=",
        "ssh_auth_sock=",
        "razen_fixture_secret",
    ]
    .iter()
    .any(|part| {
        value
            .as_bytes()
            .windows(part.len())
            .any(|bytes| bytes.eq_ignore_ascii_case(part.as_bytes()))
    })
}
/// Free-text public metadata is not a filesystem location. Validate that field
/// class structurally, rather than enumerating private directory prefixes.
pub(crate) fn filesystem_token(value: &str) -> bool {
    if value.contains('\\') {
        return true;
    }
    let safe_web_uri = |token: &str| {
        url::Url::parse(token).is_ok_and(|url| {
            matches!(url.scheme(), "https" | "http")
                && url.host_str().is_some()
                && url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none()
        })
    };
    // Punctuation inside a URL must not erase credentials, queries, or fragments.
    for (separator, _) in value.match_indices("://") {
        let scheme = value[..separator]
            .rsplit(|character: char| {
                !character.is_ascii_alphanumeric() && !matches!(character, '+' | '-' | '.')
            })
            .next()
            .unwrap_or_default();
        let start = separator - scheme.len();
        let target_end = if value[..start].ends_with("](") {
            let mut nesting = 0usize;
            value[start..]
                .char_indices()
                .find_map(|(offset, character)| {
                    match character {
                        '(' => nesting += 1,
                        ')' if nesting == 0 => return Some(start + offset),
                        ')' => nesting -= 1,
                        _ => {}
                    }
                    None
                })
        } else if value[..start].ends_with('<') {
            value[start..].find('>').map(|offset| start + offset)
        } else {
            None
        };
        let candidate = value[start..target_end.unwrap_or(value.len())]
            .trim_end_matches([')', ']', '>', '"', '\'', ',', ';']);
        if !safe_web_uri(candidate) {
            return true;
        }
    }
    value
        .split(['(', ')', '[', ']', '<', '>', '"', '\''])
        .any(|part| {
            let token = part.trim_matches([',', ';']);
            if safe_web_uri(token) {
                return false;
            }
            token.char_indices().any(|(index, ch)| {
                ch == '/'
                    && (index == 0
                        || token[..index].chars().next_back().is_some_and(|previous| {
                            !previous.is_alphanumeric() && !matches!(previous, '_' | '-' | '.')
                        }))
            })
        })
}
pub(crate) fn public_metadata(value: &str, max: usize) -> bool {
    safe_text(value, max) && !value.split_whitespace().any(filesystem_token)
}
/// Preserve upstream license claims verbatim; recognizing legacy SPDX syntax is
/// neither license selection nor legal clearance.
pub(crate) fn public_license_metadata(value: &str, max: usize) -> bool {
    public_metadata(value, max)
        || (safe_text(value, max)
            && spdx::Expression::parse_mode(
                value,
                spdx::ParseMode {
                    allow_slash_as_or_operator: true,
                    ..spdx::ParseMode::STRICT
                },
            )
            .is_ok())
}
pub(crate) fn stable_version(value: &str) -> bool {
    !value.split('+').next().unwrap_or(value).contains('-')
}
pub(crate) fn nonzero(digest: Digest) -> bool {
    digest != Digest::from_sha256([0; 32])
}
pub(crate) fn source_url(value: &str) -> bool {
    if !safe_text(value, 2048) {
        return false;
    }
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
    })
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DigestAlgorithm {
    Sha256,
    Sha512,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ArtifactHash {
    Sha256(Digest),
    Sha512(ImageDigest),
}
impl ArtifactHash {
    pub fn validate(&self, algorithm: DigestAlgorithm) -> ProofResult<()> {
        let valid = match (self, algorithm) {
            (Self::Sha256(d), DigestAlgorithm::Sha256) => nonzero(*d),
            (Self::Sha512(d), DigestAlgorithm::Sha512) => d
                .as_str()
                .strip_prefix("sha512:")
                .is_some_and(|hex| hex.bytes().any(|b| b != b'0')),
            _ => false,
        };
        if !valid {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ArtifactDigest {
    PublishedObserved {
        algorithm: DigestAlgorithm,
        digest: ArtifactHash,
    },
    DownloadedVerified {
        algorithm: DigestAlgorithm,
        digest: ArtifactHash,
    },
}
impl ArtifactDigest {
    pub fn downloaded_verified(&self) -> bool {
        matches!(self, Self::DownloadedVerified { .. })
    }
    pub fn parts(&self) -> (DigestAlgorithm, &ArtifactHash) {
        match self {
            Self::PublishedObserved { algorithm, digest }
            | Self::DownloadedVerified { algorithm, digest } => (*algorithm, digest),
        }
    }
    pub fn validate(&self) -> ProofResult<()> {
        let (a, d) = self.parts();
        d.validate(a)
    }
}
/// A dependency name is not a catalog authority handle; Debian binary names additionally permit '+'.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DependencyName(String);
impl DependencyName {
    pub fn parse(value: &str) -> ProofResult<Self> {
        if value.is_empty()
            || value.len() > 128
            || !value.as_bytes()[0].is_ascii_alphanumeric()
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:+-".contains(&byte))
        {
            return Err(invalid());
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl std::fmt::Display for DependencyName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl<'de> Deserialize<'de> for DependencyName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&text_limit::<D, 128>(d)?).map_err(serde::de::Error::custom)
    }
}
/// Cargo/tool versions reuse VersionPin; Debian epochs/revisions additionally permit ':'/'~'.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct DependencyVersion(String);
impl DependencyVersion {
    pub fn parse(value: &str) -> ProofResult<Self> {
        if VersionPin::parse(value).is_err()
            && (value.len() > 128
                || !value.as_bytes().first().is_some_and(u8::is_ascii_digit)
                || !value
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-+_:~".contains(&b)))
        {
            return Err(invalid());
        }
        Ok(Self(value.to_owned()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for DependencyVersion {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::parse(&text_limit::<D, 128>(d)?).map_err(serde::de::Error::custom)
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum MinimumRust {
    Declared { version: VersionPin },
    Undeclared,
    NotApplicable,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "DependencyWire")]
pub struct DependencyRecord {
    pub name: DependencyName,
    pub source_url: String,
    pub checked_at: AuditTime,
    pub latest_stable_observed: DependencyVersion,
    pub selected_version: DependencyVersion,
    pub artifact_digest: ArtifactDigest,
    pub license_expression: String,
    pub minimum_rust: MinimumRust,
    pub compatibility_evidence_refs: Vec<EvidenceRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approved_exception_ref: Option<EvidenceRef>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DependencyWire {
    name: DependencyName,
    #[serde(deserialize_with = "text_limit::<_,2048>")]
    source_url: String,
    checked_at: AuditTime,
    latest_stable_observed: DependencyVersion,
    selected_version: DependencyVersion,
    artifact_digest: ArtifactDigest,
    #[serde(deserialize_with = "text_limit::<_,2048>")]
    license_expression: String,
    minimum_rust: MinimumRust,
    #[serde(deserialize_with = "bounded_vec")]
    compatibility_evidence_refs: Vec<EvidenceRef>,
    #[serde(default, deserialize_with = "non_null_optional")]
    approved_exception_ref: Option<EvidenceRef>,
}
impl TryFrom<DependencyWire> for DependencyRecord {
    type Error = ProofError;
    fn try_from(w: DependencyWire) -> ProofResult<Self> {
        let value = Self {
            name: w.name,
            source_url: w.source_url,
            checked_at: w.checked_at,
            latest_stable_observed: w.latest_stable_observed,
            selected_version: w.selected_version,
            artifact_digest: w.artifact_digest,
            license_expression: w.license_expression,
            minimum_rust: w.minimum_rust,
            compatibility_evidence_refs: w.compatibility_evidence_refs,
            approved_exception_ref: w.approved_exception_ref,
        };
        value.validate()?;
        Ok(value)
    }
}
impl DependencyRecord {
    pub fn validate(&self) -> ProofResult<()> {
        self.artifact_digest.validate()?;
        if !safe_text(self.name.as_str(), 128)
            || !source_url(&self.source_url)
            || !public_license_metadata(&self.license_expression, 2048)
            || self.compatibility_evidence_refs.is_empty()
            || self.compatibility_evidence_refs.len() > 64
            || (!matches!(self.minimum_rust, MinimumRust::NotApplicable)
                && (!stable_version(self.latest_stable_observed.as_str())
                    || !stable_version(self.selected_version.as_str())))
        {
            return Err(invalid());
        }
        for (index, reference) in self.compatibility_evidence_refs.iter().enumerate() {
            validate_reference(reference)?;
            if self.compatibility_evidence_refs[..index].contains(reference) {
                return Err(invalid());
            }
        }
        if let Some(reference) = &self.approved_exception_ref {
            validate_reference(reference)?;
        }
        Ok(())
    }
}
pub(crate) fn validate_reference(reference: &EvidenceRef) -> ProofResult<()> {
    reference.validate()?;
    let digest = match reference {
        EvidenceRef::Snapshot { sha256, .. } | EvidenceRef::Artifact { sha256, .. } => *sha256,
    };
    if !nonzero(digest) {
        return Err(invalid());
    }
    Ok(())
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencySelection {
    pub name: DependencyName,
    pub selected_version: DependencyVersion,
    pub latest_stable_observed: DependencyVersion,
    pub selected_source_sha256: Digest,
    pub latest_source_sha256: Digest,
}
impl DependencySelection {
    pub fn validate(&self) -> ProofResult<()> {
        if !nonzero(self.selected_source_sha256) || !nonzero(self.latest_source_sha256) {
            return Err(invalid());
        }
        Ok(())
    }
}
/// A manifest is a sealed byte sequence, not a fabricated canonical artifact UUID.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DecisionEvidence {
    RunManifest { run_id: EntityId, sha256: Digest },
    Evidence { reference: EvidenceRef },
    DependencySelection { selection: DependencySelection },
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionStatus {
    Recorded,
    Pending,
    Blocked,
    Approved,
    Rejected,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "DecisionWire")]
pub struct DecisionRecord {
    pub decision_id: CatalogId,
    pub subject: String,
    pub decision: String,
    pub rationale: String,
    pub alternatives: Vec<String>,
    pub evidence_refs: Vec<DecisionEvidence>,
    pub status: DecisionStatus,
    pub reviewer: String,
    pub reviewed_at: AuditTime,
}
#[derive(Deserialize)]
struct Note(#[serde(deserialize_with = "text_limit::<_,4096>")] String);
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DecisionWire {
    decision_id: CatalogId,
    #[serde(deserialize_with = "bounded_text")]
    subject: String,
    #[serde(deserialize_with = "text_limit::<_,4096>")]
    decision: String,
    #[serde(deserialize_with = "text_limit::<_,4096>")]
    rationale: String,
    #[serde(deserialize_with = "bounded_vec")]
    alternatives: Vec<Note>,
    #[serde(deserialize_with = "bounded_vec")]
    evidence_refs: Vec<DecisionEvidence>,
    status: DecisionStatus,
    #[serde(deserialize_with = "bounded_text")]
    reviewer: String,
    reviewed_at: AuditTime,
}
impl TryFrom<DecisionWire> for DecisionRecord {
    type Error = ProofError;
    fn try_from(w: DecisionWire) -> ProofResult<Self> {
        let value = Self {
            decision_id: w.decision_id,
            subject: w.subject,
            decision: w.decision,
            rationale: w.rationale,
            alternatives: w.alternatives.into_iter().map(|n| n.0).collect(),
            evidence_refs: w.evidence_refs,
            status: w.status,
            reviewer: w.reviewer,
            reviewed_at: w.reviewed_at,
        };
        value.validate()?;
        Ok(value)
    }
}
impl DecisionRecord {
    pub fn validate(&self) -> ProofResult<()> {
        if !public_metadata(self.subject.as_str(), 256)
            || !public_metadata(&self.decision, 4096)
            || !public_metadata(&self.rationale, 4096)
            || !public_metadata(&self.reviewer, 256)
            || self.alternatives.is_empty()
            || self.alternatives.len() > 32
            || self.alternatives.iter().any(|a| !public_metadata(a, 4096))
            || (self.evidence_refs.is_empty() && self.status != DecisionStatus::Recorded)
            || self.evidence_refs.len() > 64
        {
            return Err(invalid());
        }
        let mut manifests = 0;
        for (index, reference) in self.evidence_refs.iter().enumerate() {
            if self.evidence_refs[..index].contains(reference) {
                return Err(invalid());
            }
            match reference {
                DecisionEvidence::RunManifest { sha256, .. } => {
                    manifests += 1;
                    if !nonzero(*sha256) {
                        return Err(invalid());
                    }
                }
                DecisionEvidence::Evidence { reference } => validate_reference(reference)?,
                DecisionEvidence::DependencySelection { selection } => selection.validate()?,
            }
        }
        if manifests > 1 {
            return Err(invalid());
        }
        Ok(())
    }
}
