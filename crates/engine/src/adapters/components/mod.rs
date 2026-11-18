//! One engine-owned capacity is shared by every Store, native runner and broker.
pub mod bindings;
pub(crate) mod fixture_import;
mod resource_checks;
pub mod runner;
pub mod snapshot_reader;
pub mod supervisor;
pub(crate) mod wit_number;
use crate::application::profile::LoadedProfile;
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use serde::{Deserialize, Serialize};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

pub struct ComponentCapacity {
    invocations: AtomicUsize,
    host_calls: AtomicUsize,
    invocation_peak: AtomicUsize,
    host_call_peak: AtomicUsize,
    spawns: AtomicUsize,
    reads: AtomicUsize,
    invocation_cap: usize,
    host_call_cap: usize,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapacityState {
    pub invocations: usize,
    pub host_calls: usize,
    pub invocation_peak: usize,
    pub host_call_peak: usize,
    pub spawns: usize,
    pub reads: usize,
}
#[derive(Clone, Copy)]
pub(crate) enum SlotKind {
    Invocation,
    HostCall,
}
pub(crate) struct Slot {
    capacity: Arc<ComponentCapacity>,
    kind: SlotKind,
}
impl ComponentCapacity {
    pub fn from_profile(profile: &LoadedProfile) -> ProofResult<Self> {
        let limits = &profile.config().component;
        let invocation_cap =
            usize::try_from(limits.max_concurrent_invocations.get()).map_err(|_| invalid())?;
        let host_call_cap =
            usize::try_from(limits.max_concurrent_host_calls.get()).map_err(|_| invalid())?;
        if invocation_cap != 1 || host_call_cap != 1 {
            return Err(invalid());
        }
        Ok(Self {
            invocations: AtomicUsize::new(0),
            host_calls: AtomicUsize::new(0),
            invocation_peak: AtomicUsize::new(0),
            host_call_peak: AtomicUsize::new(0),
            spawns: AtomicUsize::new(0),
            reads: AtomicUsize::new(0),
            invocation_cap,
            host_call_cap,
        })
    }
    pub fn state(&self) -> CapacityState {
        CapacityState {
            invocations: self.invocations.load(Ordering::SeqCst),
            host_calls: self.host_calls.load(Ordering::SeqCst),
            invocation_peak: self.invocation_peak.load(Ordering::SeqCst),
            host_call_peak: self.host_call_peak.load(Ordering::SeqCst),
            spawns: self.spawns.load(Ordering::SeqCst),
            reads: self.reads.load(Ordering::SeqCst),
        }
    }
    pub(crate) fn acquire(self: &Arc<Self>, kind: SlotKind) -> ProofResult<Slot> {
        let (counter, cap, peak) = match kind {
            SlotKind::Invocation => (
                &self.invocations,
                self.invocation_cap,
                &self.invocation_peak,
            ),
            SlotKind::HostCall => (&self.host_calls, self.host_call_cap, &self.host_call_peak),
        };
        let active = counter
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |current| {
                (current < cap).then_some(current + 1)
            })
            .map_err(|_| {
                ProofError::new(
                    ErrorCode::BudgetExhausted,
                    "Engine-wide component capacity is occupied; no work queued",
                )
            })?
            + 1;
        peak.fetch_max(active, Ordering::SeqCst);
        Ok(Slot {
            capacity: Arc::clone(self),
            kind,
        })
    }
    pub(crate) fn spawned(&self) {
        self.spawns.fetch_add(1, Ordering::SeqCst);
    }
    pub(crate) fn read_started(&self) {
        self.reads.fetch_add(1, Ordering::SeqCst);
    }
}
impl Drop for Slot {
    fn drop(&mut self) {
        match self.kind {
            SlotKind::Invocation => &self.capacity.invocations,
            SlotKind::HostCall => &self.capacity.host_calls,
        }
        .fetch_sub(1, Ordering::SeqCst);
    }
}
pub(crate) fn error(code: ErrorCode, message: &'static str) -> ProofError {
    ProofError::new(code, message)
}
pub(crate) fn invalid() -> ProofError {
    error(
        ErrorCode::InvalidInput,
        "Invalid bounded component contract",
    )
}
