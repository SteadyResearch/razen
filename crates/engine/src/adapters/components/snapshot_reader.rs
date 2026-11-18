use super::bindings::SnapshotReference;
use super::{ComponentCapacity, SlotKind, error, invalid};
use crate::adapters::evidence_store::EvidenceStore;
use crate::application::{
    admission::{EffectPermit, HostAdmission, TrustedBinding},
    profile::LoadedProfile,
};
use crate::domain::{
    evidence::Snapshot,
    values::{Digest, EntityId, WireInt},
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use serde::{Deserialize, Serialize};
use std::io::{ErrorKind, Read};
use std::os::unix::net::UnixStream;
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadFact {
    pub snapshot: SnapshotReference,
    #[serde(with = "super::wit_number")]
    pub offset: u64,
    pub max_bytes: u32,
    pub bytes: u64,
    pub sha256: Digest,
    pub elapsed_us: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProofError>,
}
/// Trusted fixture body-source dependency. The retained writer is owned by the
/// caller; withholding bytes exercises a genuine blocked native broker read.
pub struct BlockedRead {
    reader: Mutex<UnixStream>,
    entered: (Mutex<bool>, Condvar),
}
impl BlockedRead {
    pub fn new() -> ProofResult<(Arc<Self>, UnixStream)> {
        let (reader, writer) = UnixStream::pair().map_err(|_| invalid())?;
        reader
            .set_read_timeout(Some(Duration::from_millis(5)))
            .map_err(|_| invalid())?;
        Ok((
            Arc::new(Self {
                reader: Mutex::new(reader),
                entered: (Mutex::new(false), Condvar::new()),
            }),
            writer,
        ))
    }
    pub fn wait_entered(&self, deadline: Duration) -> ProofResult<()> {
        let entered = self.entered.0.lock().map_err(|_| invalid())?;
        let (entered, _) = self
            .entered
            .1
            .wait_timeout_while(entered, deadline, |ready| !*ready)
            .map_err(|_| invalid())?;
        if !*entered {
            return Err(error(
                ErrorCode::Timeout,
                "Broker did not enter the actual blocked read",
            ));
        }
        Ok(())
    }
    fn wait(&self, deadline: Instant, cancelled: &AtomicBool) -> ProofResult<()> {
        let mut reader = self.reader.lock().map_err(|_| invalid())?;
        *self.entered.0.lock().map_err(|_| invalid())? = true;
        self.entered.1.notify_all();
        let mut byte = [0];
        loop {
            if cancelled.load(Ordering::SeqCst) {
                return Err(error(
                    ErrorCode::Cancelled,
                    "Component broker read cancelled",
                ));
            }
            if Instant::now() >= deadline {
                return Err(error(
                    ErrorCode::Timeout,
                    "Independent component host-call deadline expired",
                ));
            }
            match reader.read(&mut byte) {
                Ok(1) => return Ok(()),
                Ok(_) => {
                    return Err(error(
                        ErrorCode::Cancelled,
                        "Component broker body source closed",
                    ));
                }
                Err(cause)
                    if matches!(
                        cause.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) => {}
                Err(_) => {
                    return Err(error(
                        ErrorCode::ProviderUnavailable,
                        "Component broker body source failed",
                    ));
                }
            }
        }
    }
}
pub struct SnapshotBroker<'a> {
    evidence: Arc<EvidenceStore>,
    admission: Arc<HostAdmission>,
    binding: Arc<TrustedBinding>,
    permit: &'a EffectPermit,
    snapshot: Arc<Snapshot>,
    capacity: Arc<ComponentCapacity>,
    chunk_limit: u64,
    byte_limit: u64,
    consumed: u64,
    deadline: Duration,
    pub cancelled: Arc<AtomicBool>,
    pub blocked: Option<Arc<BlockedRead>>,
    pub reads: Vec<ReadFact>,
}
impl<'a> SnapshotBroker<'a> {
    pub fn new(
        evidence: Arc<EvidenceStore>,
        admission: Arc<HostAdmission>,
        binding: Arc<TrustedBinding>,
        permit: &'a EffectPermit,
        snapshot: Arc<Snapshot>,
        profile: &LoadedProfile,
        capacity: Arc<ComponentCapacity>,
    ) -> ProofResult<Self> {
        admission.recheck_effect(&binding, permit)?;
        if binding.project_id() != snapshot.project_id {
            return Err(error(
                ErrorCode::PermissionDenied,
                "Snapshot belongs to another project",
            ));
        }
        let byte_limit = profile
            .config()
            .transport
            .body_limit_bytes
            .get()
            .min(snapshot.length_bytes.get());
        Ok(Self {
            evidence,
            admission,
            binding,
            permit,
            snapshot,
            capacity,
            chunk_limit: profile.config().transport.chunk_limit_bytes.get(),
            byte_limit,
            consumed: 0,
            deadline: Duration::from_millis(profile.config().component.host_call_deadline_ms.get()),
            cancelled: Arc::new(AtomicBool::new(false)),
            blocked: None,
            reads: Vec::new(),
        })
    }
    pub fn invocation_id(&self) -> EntityId {
        self.permit.invocation_id()
    }
    pub fn project_id(&self) -> EntityId {
        self.binding.project_id()
    }
    pub fn reference(&self) -> SnapshotReference {
        reference(&self.snapshot)
    }
    pub fn consumed(&self) -> u64 {
        self.consumed
    }
    pub(crate) fn enclosing_cancelled(&self) -> bool {
        self.admission.enclosing_cancelled()
    }
    pub fn read(
        &mut self,
        snapshot: SnapshotReference,
        offset: u64,
        max_bytes: u32,
    ) -> ProofResult<Vec<u8>> {
        if self.reads.len() >= 4096 {
            return Err(error(
                ErrorCode::BudgetExhausted,
                "Component host-call count exceeds bounded audit capacity",
            ));
        }
        let started = Instant::now();
        let outcome = self.read_inner(&snapshot, offset, max_bytes, started);
        self.reads.push(ReadFact {
            snapshot,
            offset,
            max_bytes,
            bytes: outcome.as_ref().map_or(0, |bytes| bytes.len() as u64),
            sha256: outcome
                .as_ref()
                .map_or_else(|_| Digest::of(b""), |bytes| Digest::of(bytes)),
            elapsed_us: started.elapsed().as_micros() as u64,
            error: outcome.as_ref().err().cloned(),
        });
        outcome
    }
    fn read_inner(
        &mut self,
        snapshot: &SnapshotReference,
        offset: u64,
        max_bytes: u32,
        started: Instant,
    ) -> ProofResult<Vec<u8>> {
        let _slot = self.capacity.acquire(SlotKind::HostCall)?;
        self.admission.recheck_effect(&self.binding, self.permit)?;
        validate_reference(&self.snapshot, snapshot)?;
        if u64::from(max_bytes) > self.chunk_limit {
            return Err(error(
                ErrorCode::BudgetExhausted,
                "Component snapshot chunk exceeds its byte limit",
            ));
        }
        let end = offset
            .checked_add(u64::from(max_bytes))
            .ok_or_else(invalid)?;
        if max_bytes == 0
            || offset > self.snapshot.length_bytes.get()
            || end > self.snapshot.length_bytes.get()
        {
            return Err(invalid());
        }
        if u64::from(max_bytes) > self.chunk_limit
            || self
                .consumed
                .checked_add(u64::from(max_bytes))
                .is_none_or(|count| count > self.byte_limit)
        {
            return Err(error(
                ErrorCode::BudgetExhausted,
                "Component snapshot chunk or cumulative byte budget exceeded",
            ));
        }
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(error(
                ErrorCode::Cancelled,
                "Component read cancelled before I/O",
            ));
        }
        self.capacity.read_started();
        let deadline = started + self.deadline;
        if let Some(blocked) = &self.blocked {
            blocked.wait(deadline, &self.cancelled)?;
        }
        self.admission.recheck_effect(&self.binding, self.permit)?;
        let reader = self.evidence.snapshot_reader(
            self.binding.project_id(),
            self.snapshot.snapshot_id,
            self.snapshot.revision,
        )?;
        if reader.metadata() != self.snapshot.as_ref() {
            return Err(error(
                ErrorCode::StaleSnapshot,
                "Host-bound snapshot metadata differs from immutable evidence",
            ));
        }
        if Instant::now() >= deadline {
            return Err(error(
                ErrorCode::Timeout,
                "Independent component host-call deadline expired",
            ));
        }
        let bytes = reader.read(WireInt::new(offset)?, WireInt::new(u64::from(max_bytes))?)?;
        if Instant::now() >= deadline {
            return Err(error(
                ErrorCode::Timeout,
                "Component body read exceeded independent deadline",
            ));
        }
        self.consumed += bytes.len() as u64;
        Ok(bytes)
    }
}
pub fn reference(snapshot: &Snapshot) -> SnapshotReference {
    SnapshotReference {
        snapshot_id: snapshot.snapshot_id.to_string(),
        revision: snapshot.revision.get(),
        sha256: snapshot.sha256.to_string(),
        length_bytes: snapshot.length_bytes.get(),
    }
}
pub fn validate_reference(snapshot: &Snapshot, supplied: &SnapshotReference) -> ProofResult<()> {
    if supplied.snapshot_id != snapshot.snapshot_id.to_string() {
        return Err(error(
            ErrorCode::PermissionDenied,
            "Component supplied a foreign snapshot",
        ));
    }
    if supplied.revision != snapshot.revision.get() {
        return Err(error(
            ErrorCode::StaleSnapshot,
            "Component supplied a stale snapshot revision",
        ));
    }
    if supplied.sha256 != snapshot.sha256.to_string() {
        return Err(error(
            ErrorCode::StaleSnapshot,
            "Component supplied a substituted snapshot hash",
        ));
    }
    if supplied.length_bytes != snapshot.length_bytes.get() {
        return Err(invalid());
    }
    Ok(())
}
