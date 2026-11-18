use std::borrow::Cow;
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::domain::values::{ByteRange, CatalogId, Digest, EntityId, WireInt, non_null_optional};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

pub const MAX_BODY_BYTES: usize = 1_048_576;
pub const MAX_CHUNK_BYTES: usize = 65_536;
const MAX_HEADER_BYTES: usize = 65_536;

pub(crate) fn invalid(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::InvalidInput, message)
}

pub(crate) fn denied() -> ProofError {
    ProofError::new(
        ErrorCode::PermissionDenied,
        "The record is not owned by this context",
    )
}

pub(crate) fn bounded_text<'de, D: Deserializer<'de>, const N: usize>(
    deserializer: D,
) -> Result<String, D::Error> {
    struct TextVisitor<const N: usize>;
    impl<const N: usize> Visitor<'_> for TextVisitor<N> {
        type Value = String;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a string of at most {N} UTF-8 bytes")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
            check_text(value, N).map_err(E::custom)?;
            Ok(value.to_owned())
        }
        fn visit_string<E: de::Error>(self, value: String) -> Result<String, E> {
            check_text(&value, N).map_err(E::custom)?;
            Ok(value)
        }
    }
    deserializer.deserialize_str(TextVisitor::<N>)
}

pub(crate) fn check_text(value: &str, max: usize) -> ProofResult<()> {
    if value.is_empty() || value.len() > max || value.contains('\0') {
        return Err(invalid(
            "Text is empty, oversized, or contains a forbidden character",
        ));
    }
    Ok(())
}

pub(crate) fn bounded_vec<'de, D, T, const N: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct ListVisitor<T, const N: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const N: usize> Visitor<'de> for ListVisitor<T, N> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "a list of at most {N} entries")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Vec<T>, A::Error> {
            if sequence.size_hint().is_some_and(|size| size > N) {
                return Err(de::Error::custom("List exceeds its entry limit"));
            }
            let mut entries = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(N));
            while let Some(entry) = sequence.next_element()? {
                if entries.len() == N {
                    return Err(de::Error::custom("List exceeds its entry limit"));
                }
                entries.push(entry);
            }
            Ok(entries)
        }
    }
    deserializer.deserialize_seq(ListVisitor::<T, N>(std::marker::PhantomData))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Representation {
    RawBody,
    Http1Body,
    Http2SemanticBody,
    DecodedBody,
    RedactedBody,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireHeader")]
pub struct Header {
    pub name: String,
    pub value: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireHeader {
    #[serde(deserialize_with = "bounded_text::<_, 128>")]
    name: String,
    // Empty values are legal HTTP fields.
    #[serde(deserialize_with = "header_value")]
    value: String,
}

fn header_value<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    struct HeaderValueVisitor;
    impl Visitor<'_> for HeaderValueVisitor {
        type Value = String;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a bounded HTTP header value")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<String, E> {
            if value.len() > 8192 || value.bytes().any(|b| (b < 32 && b != b'\t') || b == 127) {
                return Err(E::custom("Invalid HTTP header value"));
            }
            Ok(value.to_owned())
        }
        fn visit_string<E: de::Error>(self, value: String) -> Result<String, E> {
            if value.len() > 8192 || value.bytes().any(|b| (b < 32 && b != b'\t') || b == 127) {
                return Err(E::custom("Invalid HTTP header value"));
            }
            Ok(value)
        }
    }
    deserializer.deserialize_str(HeaderValueVisitor)
}

impl TryFrom<WireHeader> for Header {
    type Error = ProofError;
    fn try_from(wire: WireHeader) -> ProofResult<Self> {
        let header = Self {
            name: wire.name,
            value: wire.value,
        };
        header.validate()?;
        Ok(header)
    }
}

impl Header {
    pub fn validate(&self) -> ProofResult<()> {
        check_text(&self.name, 128)?;
        if !self
            .name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte))
            || self.value.len() > 8192
            || self
                .value
                .bytes()
                .any(|byte| (byte < 32 && byte != b'\t') || byte == 127)
        {
            return Err(invalid("Invalid HTTP header entry"));
        }
        Ok(())
    }
}

fn validate_headers(headers: &[Header]) -> ProofResult<()> {
    if headers.len() > 256 {
        return Err(invalid("Too many HTTP header entries"));
    }
    let mut total = 0usize;
    for header in headers {
        header.validate()?;
        total = total
            .checked_add(header.name.len())
            .and_then(|n| n.checked_add(header.value.len()))
            .ok_or_else(|| invalid("HTTP header length overflow"))?;
        if total > MAX_HEADER_BYTES {
            return Err(invalid("HTTP headers exceed their byte limit"));
        }
    }
    Ok(())
}

fn validate_framing(
    headers: &[Header],
    representation: Representation,
    length: Option<WireInt>,
) -> ProofResult<()> {
    let mut content_length = None;
    let mut transfer_encoding = false;
    for header in headers {
        if representation == Representation::Http2SemanticBody
            && (header.name.bytes().any(|byte| byte.is_ascii_uppercase())
                || [
                    "connection",
                    "proxy-connection",
                    "keep-alive",
                    "transfer-encoding",
                    "upgrade",
                ]
                .iter()
                .any(|name| header.name.eq_ignore_ascii_case(name))
                || (header.name.eq_ignore_ascii_case("te")
                    && !header.value.trim().eq_ignore_ascii_case("trailers")))
        {
            return Err(invalid(
                "Header is not valid in an HTTP/2 semantic representation",
            ));
        }
        if header.name.eq_ignore_ascii_case("content-length") {
            let value = header.value.trim();
            if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(invalid("Invalid Content-Length framing"));
            }
            let parsed = value
                .parse::<u64>()
                .map_err(|_| invalid("Content-Length overflow"))?;
            let parsed = WireInt::new(parsed)?;
            if content_length.is_some_and(|existing| existing != parsed) {
                return Err(invalid("Conflicting Content-Length framing"));
            }
            content_length = Some(parsed);
        }
        if header.name.eq_ignore_ascii_case("transfer-encoding") {
            if transfer_encoding || !header.value.trim().eq_ignore_ascii_case("chunked") {
                return Err(invalid("Ambiguous Transfer-Encoding framing"));
            }
            transfer_encoding = true;
        }
    }
    if (transfer_encoding && content_length.is_some())
        || content_length.is_some_and(|declared| length.is_some_and(|actual| declared != actual))
    {
        return Err(invalid("Headers conflict with the body framing"));
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireSnapshot")]
pub struct Snapshot {
    pub snapshot_id: EntityId,
    pub project_id: EntityId,
    pub revision: WireInt,
    pub sha256: Digest,
    pub length_bytes: WireInt,
    pub body_ref: EntityId,
    pub representation: Representation,
    pub headers: Vec<Header>,
    pub truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derived_from: Option<EntityId>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSnapshot {
    snapshot_id: EntityId,
    project_id: EntityId,
    revision: WireInt,
    sha256: Digest,
    length_bytes: WireInt,
    body_ref: EntityId,
    representation: Representation,
    #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
    headers: Vec<Header>,
    truncated: bool,
    #[serde(default, deserialize_with = "non_null_optional")]
    derived_from: Option<EntityId>,
}

impl TryFrom<WireSnapshot> for Snapshot {
    type Error = ProofError;
    fn try_from(wire: WireSnapshot) -> ProofResult<Self> {
        let record = Self {
            snapshot_id: wire.snapshot_id,
            project_id: wire.project_id,
            revision: wire.revision,
            sha256: wire.sha256,
            length_bytes: wire.length_bytes,
            body_ref: wire.body_ref,
            representation: wire.representation,
            headers: wire.headers,
            truncated: wire.truncated,
            derived_from: wire.derived_from,
        };
        record.validate()?;
        Ok(record)
    }
}

impl Snapshot {
    pub fn validate(&self) -> ProofResult<()> {
        if self.derived_from == Some(self.snapshot_id)
            || self.length_bytes.get() > MAX_BODY_BYTES as u64
        {
            return Err(invalid("Invalid snapshot derivation or body length"));
        }
        validate_headers(&self.headers)?;
        // A truncated capture may carry the complete message's declared length.
        validate_framing(
            &self.headers,
            self.representation,
            (!self.truncated).then_some(self.length_bytes),
        )?;
        Ok(())
    }

    pub fn validate_bytes(
        &self,
        project_id: EntityId,
        current_revision: WireInt,
        bytes: &[u8],
    ) -> ProofResult<()> {
        if self.project_id != project_id {
            return Err(denied());
        }
        if self.revision != current_revision {
            return Err(ProofError::new(
                ErrorCode::StaleSnapshot,
                "The snapshot revision is stale",
            ));
        }
        self.validate()?;
        validate_digest(self.sha256, self.length_bytes, bytes)
    }

    pub fn read_bytes<'a>(
        &self,
        project_id: EntityId,
        current_revision: WireInt,
        bytes: &'a [u8],
        offset: WireInt,
        max_bytes: WireInt,
    ) -> ProofResult<&'a [u8]> {
        if max_bytes.get() > MAX_CHUNK_BYTES as u64 || offset > self.length_bytes {
            return Err(invalid("Body read exceeds its range or chunk limit"));
        }
        let end = offset.checked_add(max_bytes)?.min(self.length_bytes);
        self.validate_bytes(project_id, current_revision, bytes)?;
        let start =
            usize::try_from(offset.get()).map_err(|_| invalid("Body offset is not addressable"))?;
        let end =
            usize::try_from(end.get()).map_err(|_| invalid("Body offset is not addressable"))?;
        Ok(&bytes[start..end])
    }
}

fn validate_digest(sha256: Digest, length: WireInt, bytes: &[u8]) -> ProofResult<()> {
    if u64::try_from(bytes.len()).ok() != Some(length.get()) || Digest::of(bytes) != sha256 {
        return Err(ProofError::new(
            ErrorCode::IntegrityError,
            "Evidence bytes do not match the canonical hash and length",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    Original,
    Redacted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireArtifact")]
pub struct Artifact {
    pub artifact_id: EntityId,
    pub project_id: EntityId,
    pub kind: CatalogId,
    pub relative_path: String,
    pub sha256: Digest,
    pub length_bytes: WireInt,
    pub origin_invocation_id: EntityId,
    pub redaction_status: RedactionStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireArtifact {
    artifact_id: EntityId,
    project_id: EntityId,
    kind: CatalogId,
    #[serde(deserialize_with = "bounded_text::<_, 1024>")]
    relative_path: String,
    sha256: Digest,
    length_bytes: WireInt,
    origin_invocation_id: EntityId,
    redaction_status: RedactionStatus,
}

impl TryFrom<WireArtifact> for Artifact {
    type Error = ProofError;
    fn try_from(wire: WireArtifact) -> ProofResult<Self> {
        let record = Self {
            artifact_id: wire.artifact_id,
            project_id: wire.project_id,
            kind: wire.kind,
            relative_path: wire.relative_path,
            sha256: wire.sha256,
            length_bytes: wire.length_bytes,
            origin_invocation_id: wire.origin_invocation_id,
            redaction_status: wire.redaction_status,
        };
        record.validate()?;
        Ok(record)
    }
}

impl Artifact {
    /// Lexical containment only. The host must resolve this beneath its owned directory
    /// without following external symlinks, then supply the bytes from that open handle.
    pub fn validate(&self) -> ProofResult<()> {
        check_text(&self.relative_path, 1024)?;
        if self.relative_path.contains(['\\', ':'])
            || self.relative_path.chars().any(char::is_control)
            || self
                .relative_path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
        {
            return Err(invalid(
                "Artifact path is not a normalized owned relative path",
            ));
        }
        Ok(())
    }

    pub fn validate_bytes(&self, project_id: EntityId, bytes: &[u8]) -> ProofResult<()> {
        if self.project_id != project_id {
            return Err(denied());
        }
        self.validate()?;
        validate_digest(self.sha256, self.length_bytes, bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct EvidenceRange {
    pub range_start: WireInt,
    pub range_end: WireInt,
}

impl EvidenceRange {
    pub fn new(range_start: WireInt, range_end: WireInt) -> ProofResult<Self> {
        if range_start > range_end {
            return Err(invalid("Evidence range is reversed"));
        }
        Ok(Self {
            range_start,
            range_end,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(untagged)]
pub enum EvidenceRef {
    Snapshot {
        snapshot_id: EntityId,
        revision: WireInt,
        sha256: Digest,
        #[serde(flatten, skip_serializing_if = "Option::is_none")]
        range: Option<EvidenceRange>,
    },
    Artifact {
        artifact_id: EntityId,
        sha256: Digest,
        #[serde(flatten, skip_serializing_if = "Option::is_none")]
        range: Option<EvidenceRange>,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireEvidenceRef {
    #[serde(default, deserialize_with = "non_null_optional")]
    snapshot_id: Option<EntityId>,
    #[serde(default, deserialize_with = "non_null_optional")]
    artifact_id: Option<EntityId>,
    #[serde(default, deserialize_with = "non_null_optional")]
    revision: Option<WireInt>,
    sha256: Digest,
    #[serde(default, deserialize_with = "non_null_optional")]
    range_start: Option<WireInt>,
    #[serde(default, deserialize_with = "non_null_optional")]
    range_end: Option<WireInt>,
}

impl<'de> Deserialize<'de> for EvidenceRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WireEvidenceRef::deserialize(deserializer)?;
        let range = match (wire.range_start, wire.range_end) {
            (None, None) => None,
            (Some(start), Some(end)) => {
                Some(EvidenceRange::new(start, end).map_err(de::Error::custom)?)
            }
            _ => return Err(de::Error::custom("Evidence range endpoints must be paired")),
        };
        match (wire.snapshot_id, wire.artifact_id, wire.revision) {
            (Some(snapshot_id), None, Some(revision)) => Ok(Self::Snapshot {
                snapshot_id,
                revision,
                sha256: wire.sha256,
                range,
            }),
            (None, Some(artifact_id), None) => Ok(Self::Artifact {
                artifact_id,
                sha256: wire.sha256,
                range,
            }),
            _ => Err(de::Error::custom(
                "Evidence must be exactly a revisioned snapshot or an unrevisioned artifact",
            )),
        }
    }
}

fn resolved_range(range: Option<EvidenceRange>, length: WireInt) -> ProofResult<ByteRange> {
    match range {
        Some(range) => Ok(ByteRange::new(range.range_start, range.range_end, length)?),
        None => Ok(ByteRange::new(WireInt::ZERO, length, length)?),
    }
}

impl EvidenceRef {
    pub fn validate(&self) -> ProofResult<()> {
        let range = match self {
            Self::Snapshot { range, .. } | Self::Artifact { range, .. } => range,
        };
        if let Some(range) = range {
            EvidenceRange::new(range.range_start, range.range_end)?;
        }
        Ok(())
    }

    pub fn validate_snapshot(
        &self,
        project_id: EntityId,
        current_revision: WireInt,
        canonical: &Snapshot,
        bytes: &[u8],
    ) -> ProofResult<ByteRange> {
        let Self::Snapshot {
            snapshot_id,
            revision,
            sha256,
            range,
        } = self
        else {
            return Err(invalid("Artifact evidence cannot resolve as a snapshot"));
        };
        if canonical.project_id != project_id || *snapshot_id != canonical.snapshot_id {
            return Err(denied());
        }
        if *revision != canonical.revision || *revision != current_revision {
            return Err(ProofError::new(
                ErrorCode::StaleSnapshot,
                "The evidence revision is stale",
            ));
        }
        if *sha256 != canonical.sha256 {
            return Err(ProofError::new(
                ErrorCode::IntegrityError,
                "Evidence hash does not match the canonical snapshot",
            ));
        }
        canonical.validate_bytes(project_id, current_revision, bytes)?;
        resolved_range(*range, canonical.length_bytes)
    }

    pub fn validate_artifact(
        &self,
        project_id: EntityId,
        canonical: &Artifact,
        bytes: &[u8],
    ) -> ProofResult<ByteRange> {
        let Self::Artifact {
            artifact_id,
            sha256,
            range,
        } = self
        else {
            return Err(invalid("Snapshot evidence cannot resolve as an artifact"));
        };
        if canonical.project_id != project_id || *artifact_id != canonical.artifact_id {
            return Err(denied());
        }
        if *sha256 != canonical.sha256 {
            return Err(ProofError::new(
                ErrorCode::IntegrityError,
                "Evidence hash does not match the canonical artifact",
            ));
        }
        canonical.validate_bytes(project_id, bytes)?;
        resolved_range(*range, canonical.length_bytes)
    }
}

fn deserialize_chunk<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    struct ChunkVisitor;
    impl Visitor<'_> for ChunkVisitor {
        type Value = Vec<u8>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a canonical Base64 body chunk")
        }
        fn visit_str<E: de::Error>(self, value: &str) -> Result<Vec<u8>, E> {
            if value.len() > 87_384 {
                return Err(E::custom("Patch bytes exceed the encoded chunk limit"));
            }
            let decoded = STANDARD
                .decode(value.as_bytes())
                .map_err(|_| E::custom("Invalid Base64 patch bytes"))?;
            if decoded.len() > MAX_CHUNK_BYTES {
                return Err(E::custom("Patch bytes exceed the chunk limit"));
            }
            Ok(decoded)
        }
    }
    deserializer.deserialize_str(ChunkVisitor)
}

fn serialize_chunk<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&STANDARD.encode(bytes))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum PatchOperation {
    ReplaceBody {
        range_start: WireInt,
        range_end: WireInt,
        #[serde(
            deserialize_with = "deserialize_chunk",
            serialize_with = "serialize_chunk"
        )]
        bytes_base64: Vec<u8>,
    },
    ReplaceHeaders {
        #[serde(deserialize_with = "bounded_vec::<_, _, 256>")]
        headers: Vec<Header>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WirePatch")]
pub struct Patch {
    pub patch_id: EntityId,
    pub project_id: EntityId,
    pub base_snapshot_id: EntityId,
    pub base_revision: WireInt,
    pub base_sha256: Digest,
    pub operations: Vec<PatchOperation>,
    pub actor_ref: EntityId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePatch {
    patch_id: EntityId,
    project_id: EntityId,
    base_snapshot_id: EntityId,
    base_revision: WireInt,
    base_sha256: Digest,
    #[serde(deserialize_with = "bounded_vec::<_, _, 64>")]
    operations: Vec<PatchOperation>,
    actor_ref: EntityId,
}

impl TryFrom<WirePatch> for Patch {
    type Error = ProofError;
    fn try_from(wire: WirePatch) -> ProofResult<Self> {
        let record = Self {
            patch_id: wire.patch_id,
            project_id: wire.project_id,
            base_snapshot_id: wire.base_snapshot_id,
            base_revision: wire.base_revision,
            base_sha256: wire.base_sha256,
            operations: wire.operations,
            actor_ref: wire.actor_ref,
        };
        record.validate()?;
        Ok(record)
    }
}

#[derive(Debug)]
pub struct PatchedSnapshot<'a> {
    pub snapshot: Snapshot,
    pub body: Cow<'a, [u8]>,
}

impl Patch {
    /// Body ranges refer to the immutable base, in increasing non-overlapping order.
    pub fn validate(&self) -> ProofResult<()> {
        if self.operations.len() > 64 {
            return Err(invalid("Too many patch operations"));
        }
        let mut previous_range: Option<(WireInt, WireInt)> = None;
        let mut replaced_headers = false;
        for operation in &self.operations {
            match operation {
                PatchOperation::ReplaceBody {
                    range_start,
                    range_end,
                    bytes_base64,
                } => {
                    if range_start > range_end
                        || bytes_base64.len() > MAX_CHUNK_BYTES
                        || previous_range
                            .is_some_and(|(start, end)| *range_start < end || *range_start == start)
                    {
                        return Err(invalid(
                            "Patch body ranges are invalid, overlapping, or oversized",
                        ));
                    }
                    previous_range = Some((*range_start, *range_end));
                }
                PatchOperation::ReplaceHeaders { headers } => {
                    if replaced_headers {
                        return Err(invalid("A patch cannot replace headers more than once"));
                    }
                    validate_headers(headers)?;
                    replaced_headers = true;
                }
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply<'a>(
        &self,
        project_id: EntityId,
        current_revision: WireInt,
        base: &Snapshot,
        bytes: &'a [u8],
        new_snapshot_id: EntityId,
        new_body_ref: EntityId,
    ) -> ProofResult<PatchedSnapshot<'a>> {
        if self.project_id != project_id
            || base.project_id != project_id
            || self.base_snapshot_id != base.snapshot_id
        {
            return Err(denied());
        }
        if self.base_revision != current_revision || base.revision != current_revision {
            return Err(ProofError::new(
                ErrorCode::StaleSnapshot,
                "The patch base revision is stale",
            ));
        }
        if self.base_sha256 != base.sha256 {
            return Err(ProofError::new(
                ErrorCode::IntegrityError,
                "Patch hash does not match the canonical base",
            ));
        }
        if new_snapshot_id == base.snapshot_id {
            return Err(invalid(
                "An accepted patch requires a new snapshot identity",
            ));
        }
        self.validate()?;
        base.validate_bytes(project_id, current_revision, bytes)?;
        let revision = current_revision.checked_add(WireInt::new(1)?)?;
        let mut length = base.length_bytes;
        let mut changed = false;
        let mut headers = &base.headers;
        for operation in &self.operations {
            match operation {
                PatchOperation::ReplaceBody {
                    range_start,
                    range_end,
                    bytes_base64,
                } => {
                    if base.truncated {
                        return Err(invalid(
                            "A truncated body cannot be patched as a complete message",
                        ));
                    }
                    let range = ByteRange::new(*range_start, *range_end, base.length_bytes)?;
                    length = length
                        .checked_sub(range.len())?
                        .checked_add(WireInt::new(bytes_base64.len() as u64)?)?;
                    if length.get() > MAX_BODY_BYTES as u64 {
                        return Err(invalid("Patched body exceeds its byte limit"));
                    }
                    let start = range_start.get() as usize;
                    let end = range_end.get() as usize;
                    changed |= &bytes[start..end] != bytes_base64.as_slice();
                }
                PatchOperation::ReplaceHeaders {
                    headers: replacement,
                } => headers = replacement,
            }
        }
        if changed && (new_body_ref == base.body_ref || new_body_ref == new_snapshot_id) {
            return Err(invalid("Changed bytes require a distinct body identity"));
        }
        validate_framing(
            headers,
            base.representation,
            (!base.truncated).then_some(length),
        )?;
        let body = if changed {
            let mut result = Vec::with_capacity(length.get() as usize);
            let mut cursor = 0usize;
            for operation in &self.operations {
                if let PatchOperation::ReplaceBody {
                    range_start,
                    range_end,
                    bytes_base64,
                } = operation
                {
                    result.extend_from_slice(&bytes[cursor..range_start.get() as usize]);
                    result.extend_from_slice(bytes_base64);
                    cursor = range_end.get() as usize;
                }
            }
            result.extend_from_slice(&bytes[cursor..]);
            Cow::Owned(result)
        } else {
            Cow::Borrowed(bytes)
        };
        let snapshot = Snapshot {
            snapshot_id: new_snapshot_id,
            project_id,
            revision,
            sha256: if changed {
                Digest::of(body.as_ref())
            } else {
                base.sha256
            },
            length_bytes: length,
            body_ref: if changed { new_body_ref } else { base.body_ref },
            representation: base.representation,
            headers: headers.clone(),
            truncated: base.truncated,
            derived_from: Some(base.snapshot_id),
        };
        snapshot.validate()?;
        Ok(PatchedSnapshot { snapshot, body })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationStatus {
    Proposed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireObservationProposal")]
pub struct ObservationProposal {
    pub proposal_id: EntityId,
    pub project_id: EntityId,
    pub rule_id: CatalogId,
    pub title: String,
    pub evidence_refs: Vec<EvidenceRef>,
    pub actor_ref: EntityId,
    pub status: ObservationStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireObservationProposal {
    proposal_id: EntityId,
    project_id: EntityId,
    rule_id: CatalogId,
    #[serde(deserialize_with = "bounded_text::<_, 256>")]
    title: String,
    #[serde(deserialize_with = "bounded_vec::<_, _, 32>")]
    evidence_refs: Vec<EvidenceRef>,
    actor_ref: EntityId,
    status: ObservationStatus,
}

impl TryFrom<WireObservationProposal> for ObservationProposal {
    type Error = ProofError;
    fn try_from(wire: WireObservationProposal) -> ProofResult<Self> {
        let record = Self {
            proposal_id: wire.proposal_id,
            project_id: wire.project_id,
            rule_id: wire.rule_id,
            title: wire.title,
            evidence_refs: wire.evidence_refs,
            actor_ref: wire.actor_ref,
            status: wire.status,
        };
        record.validate()?;
        Ok(record)
    }
}

impl ObservationProposal {
    pub fn validate(&self) -> ProofResult<()> {
        check_text(&self.title, 256)?;
        if self.evidence_refs.is_empty() || self.evidence_refs.len() > 32 {
            return Err(invalid(
                "An observation requires bounded evidence references",
            ));
        }
        for reference in &self.evidence_refs {
            reference.validate()?;
        }
        Ok(())
    }
}
