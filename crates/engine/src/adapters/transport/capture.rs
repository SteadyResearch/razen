use super::{Limits, bounded, invalid, protocol};
use crate::adapters::evidence_store::EvidenceStore;
use crate::domain::evidence::{Header, RedactionStatus, Representation, Snapshot};
use crate::domain::values::{CatalogId, Digest, EntityId, WireInt};
use crate::protocol::error::{ProofError, ProofResult};
use rama::bytes::Bytes;
use rama::http::body::util::BodyExt;
use rama::http::{HeaderMap, StreamingBody};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureFact {
    pub length_bytes: u64,
    pub sha256: Digest,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 4096>")]
    pub chunks: Vec<u64>,
    pub truncated: bool,
}
pub(crate) struct Captured {
    pub bytes: Vec<u8>,
    pub fact: CaptureFact,
}
pub(crate) struct CaptureFailure {
    pub error: ProofError,
    bytes: Vec<u8>,
    chunk_bytes: usize,
}

impl CaptureFailure {
    pub(crate) fn into_parts(self) -> (Captured, ProofError) {
        let fact = fact(&self.bytes, self.chunk_bytes, true);
        (
            Captured {
                bytes: self.bytes,
                fact,
            },
            self.error,
        )
    }
}

/// Logical capture chunks are independent of arbitrary network frame splitting.
pub(crate) fn fact(bytes: &[u8], chunk_bytes: usize, truncated: bool) -> CaptureFact {
    CaptureFact {
        length_bytes: bytes.len() as u64,
        sha256: Digest::of(bytes),
        chunks: bytes
            .chunks(chunk_bytes)
            .map(|chunk| chunk.len() as u64)
            .collect(),
        truncated,
    }
}

pub(crate) fn headers(headers: &HeaderMap) -> ProofResult<Vec<Header>> {
    if headers.len() > 256 {
        return Err(bounded());
    }
    headers
        .iter()
        .map(|(name, value)| {
            let header = Header {
                name: name.as_str().to_owned(),
                value: std::str::from_utf8(value.as_bytes())
                    .map_err(|_| invalid())?
                    .to_owned(),
            };
            header.validate()?;
            Ok(header)
        })
        .collect()
}

pub(crate) fn encoding(headers: &HeaderMap) -> ProofResult<()> {
    for value in headers.get_all("content-encoding").iter() {
        if !value
            .to_str()
            .map_err(|_| protocol())?
            .trim()
            .eq_ignore_ascii_case("identity")
        {
            return Err(protocol());
        }
    }
    for value in headers.get_all("transfer-encoding").iter() {
        if !value
            .to_str()
            .map_err(|_| protocol())?
            .trim()
            .eq_ignore_ascii_case("chunked")
        {
            return Err(protocol());
        }
    }
    Ok(())
}

pub(crate) async fn collect<B>(body: B, limits: &Limits) -> Result<Captured, CaptureFailure>
where
    B: StreamingBody<Data = Bytes> + Unpin,
{
    collect_classified(body, limits, |_| protocol()).await
}

pub(crate) async fn collect_http1(
    body: rama::http::core::body::Incoming,
    limits: &Limits,
) -> Result<Captured, CaptureFailure> {
    collect_classified(body, limits, super::http1::classify_error).await
}

async fn collect_classified<B>(
    mut body: B,
    limits: &Limits,
    classify: impl Fn(B::Error) -> ProofError,
) -> Result<Captured, CaptureFailure>
where
    B: StreamingBody<Data = Bytes> + Unpin,
{
    let mut bytes = Vec::new();
    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => return Err(failure(classify(error), bytes, limits.chunk_bytes)),
        };
        let data = match frame.into_data() {
            Ok(data) => data,
            Err(_) => return Err(failure(protocol(), bytes, limits.chunk_bytes)),
        };
        for chunk in data.chunks(limits.chunk_bytes) {
            let available = limits.body_bytes.saturating_sub(bytes.len());
            if chunk.len() > available {
                if let Err(error) = append(&mut bytes, &chunk[..available], limits.body_bytes) {
                    return Err(failure(error, bytes, limits.chunk_bytes));
                }
                return Err(failure(bounded(), bytes, limits.chunk_bytes));
            }
            if let Err(error) = append(&mut bytes, chunk, limits.body_bytes) {
                return Err(failure(error, bytes, limits.chunk_bytes));
            }
        }
    }
    let fact = fact(&bytes, limits.chunk_bytes, false);
    Ok(Captured { bytes, fact })
}
pub(crate) fn failure(error: ProofError, bytes: Vec<u8>, chunk_bytes: usize) -> CaptureFailure {
    CaptureFailure {
        error,
        bytes,
        chunk_bytes,
    }
}

pub(crate) struct SnapshotBody<'a> {
    pub bytes: &'a [u8],
    pub headers: Vec<Header>,
    pub representation: Representation,
    pub truncated: bool,
    pub derived_from: Option<EntityId>,
}

pub(crate) fn snapshot(
    store: &EvidenceStore,
    project: EntityId,
    origin: EntityId,
    body: SnapshotBody<'_>,
) -> ProofResult<EntityId> {
    let SnapshotBody {
        bytes,
        headers,
        representation,
        truncated,
        derived_from,
    } = body;
    let artifact = store.write_artifact(
        project,
        CatalogId::parse("http-body")?,
        origin,
        bytes,
        RedactionStatus::Original,
    )?;
    let snapshot = Snapshot {
        snapshot_id: EntityId::new(),
        project_id: project,
        revision: WireInt::ZERO,
        sha256: artifact.sha256,
        length_bytes: artifact.length_bytes,
        body_ref: artifact.artifact_id,
        representation,
        headers,
        truncated,
        derived_from,
    };
    snapshot.validate()?;
    Ok(store.install_snapshot(snapshot)?.snapshot_id)
}

pub(crate) fn read_complete(
    store: &EvidenceStore,
    project: EntityId,
    id: EntityId,
    revision: WireInt,
    limits: &Limits,
) -> ProofResult<Vec<u8>> {
    let snapshot = store.snapshot(project, id, revision)?;
    if snapshot.truncated || snapshot.length_bytes.get() > limits.body_bytes as u64 {
        return Err(invalid());
    }
    let reader = store.snapshot_reader(project, id, revision)?;
    let mut bytes = Vec::with_capacity(snapshot.length_bytes.get() as usize);
    while bytes.len() < snapshot.length_bytes.get() as usize {
        let length =
            (snapshot.length_bytes.get() - bytes.len() as u64).min(limits.chunk_bytes as u64);
        bytes.extend_from_slice(
            &reader.read(WireInt::new(bytes.len() as u64)?, WireInt::new(length)?)?,
        );
    }
    Ok(bytes)
}

pub(crate) fn append(bytes: &mut Vec<u8>, chunk: &[u8], limit: usize) -> ProofResult<()> {
    let needed = bytes.len().checked_add(chunk.len()).ok_or_else(bounded)?;
    if needed > limit {
        return Err(bounded());
    }
    if needed > bytes.capacity() {
        let capacity = needed.max(bytes.capacity().saturating_mul(2)).min(limit);
        bytes
            .try_reserve_exact(capacity - bytes.len())
            .map_err(|_| bounded())?;
    }
    bytes.extend_from_slice(chunk);
    Ok(())
}
