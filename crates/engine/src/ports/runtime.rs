use crate::{
    domain::{
        runtime::{Lease, RuntimeBinding},
        values::{EntityId, WireInt},
    },
    protocol::error::ProofResult,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeContainment {
    pub invocation_id: EntityId,
    pub empty_cgroup: bool,
    pub vm_force_stopped: bool,
    pub observed_vm_status: String,
    pub elapsed_us: u64,
    pub control_error: Option<crate::protocol::error::ProofError>,
}
/// Parent-authenticated I/O only. Frames use the public product protocol; correlation IDs
/// are never admission authority. Control acknowledgment is deliberately not an adapter operation.
pub trait Runtime {
    fn binding(&self) -> &RuntimeBinding;
    fn lease(&self) -> &Lease;
    fn send(&mut self, frame: &[u8]) -> ProofResult<()>;
    fn poll(&mut self) -> ProofResult<Option<Vec<u8>>>;
    fn refresh(&mut self, revision: WireInt) -> ProofResult<()>;
    fn contain(&mut self, revision: WireInt) -> ProofResult<RuntimeContainment>;
}
