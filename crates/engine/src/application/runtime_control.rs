//! Runtime control is deliberately two-phase: durable host ACK first, any adapter I/O later.
use crate::{
    application::{
        admission::TrustedBinding,
        control::{ControlAck, ControlAction, ControlClient, ControlCommand},
        proof_host::ProofHost,
    },
    domain::{
        runtime::RuntimeState,
        values::{EntityId, WireInt},
    },
    ports::runtime::{Runtime, RuntimeContainment},
    protocol::error::{ErrorCode, ProofError, ProofResult},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Clone, Copy, Debug)]
pub enum RuntimeIntervention {
    Pause,
    Steer,
    Cancel,
    Revoke,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CanonicalContinuity {
    pub investigation_id: EntityId,
    pub session_id: EntityId,
    pub budget_id: EntityId,
    pub consumed_before: WireInt,
    pub consumed_after: WireInt,
    pub control_revision: WireInt,
}

pub struct RuntimeControl<'a> {
    host: &'a ProofHost,
    client: Arc<ControlClient>,
}
impl<'a> RuntimeControl<'a> {
    pub fn new(host: &'a ProofHost) -> ProofResult<Self> {
        Ok(Self {
            host,
            client: host.control_client()?,
        })
    }
    /// This API cannot consult the runtime or model: neither is an argument or a field.
    /// Desired canonical mode is not an observation that an uncooperative worker paused.
    pub fn acknowledge(
        &self,
        binding: &TrustedBinding,
        intervention: RuntimeIntervention,
    ) -> ProofResult<ControlAck> {
        if binding.project_id() != self.host.project.project_id
            || binding.investigation_id() != self.host.session.investigation_id
            || binding.session_id() != self.host.session.session_id
        {
            return Err(invalid(
                "Runtime control does not own this investigation/session",
            ));
        }
        let action = match intervention {
            RuntimeIntervention::Pause | RuntimeIntervention::Steer => ControlAction::Pause,
            RuntimeIntervention::Cancel | RuntimeIntervention::Revoke => ControlAction::Cancel,
        };
        self.client.request(&ControlCommand {
            request_id: EntityId::new(),
            investigation_id: binding.investigation_id(),
            expected_revision: binding.control_revision(),
            action,
        })
    }
    pub fn contain_after_ack(
        &self,
        runtime: &mut dyn Runtime,
        ack: &ControlAck,
    ) -> ProofResult<RuntimeContainment> {
        let stored = self.host.ledger.read_control(ack.state.investigation_id)?;
        if stored != ack.state
            || stored.admission_open
            || ack.state.investigation_id != runtime.binding().investigation_id
            || ack.state.revision <= runtime.lease().control_revision
        {
            return Err(invalid(
                "Containment requires the already durable current closed barrier",
            ));
        }
        runtime.contain(ack.state.revision)
    }
    /// The caller must first observe containment. Fresh authority is derived from current
    /// canonical context, never a runtime checkpoint, echoed ID, lease or model proposal.
    pub fn reconstruct_binding(
        &self,
        previous: &dyn Runtime,
        ack: &ControlAck,
    ) -> ProofResult<(Arc<TrustedBinding>, CanonicalContinuity)> {
        if previous.binding().state != RuntimeState::Closed
            || previous.binding().investigation_id != self.host.session.investigation_id
            || previous.binding().session_id != self.host.session.session_id
        {
            return Err(invalid(
                "Reconstruction requires observed closure of the old owned runtime",
            ));
        }
        let before = self.host.ledger.read_budget(self.host.budget_id)?;
        let current = self.host.ledger.read_control(ack.state.investigation_id)?;
        if current != ack.state
            || current.mode != crate::domain::execution::ControlMode::Paused
            || current.admission_open
        {
            return Err(invalid(
                "Only a current paused investigation may reconstruct",
            ));
        }
        let resumed = self.client.request(&ControlCommand {
            request_id: EntityId::new(),
            investigation_id: current.investigation_id,
            expected_revision: current.revision,
            action: ControlAction::Resume,
        })?;
        let binding = self.host.bind_local()?;
        let after = self.host.ledger.read_budget(self.host.budget_id)?;
        if after.limit != before.limit
            || after.consumed < before.consumed
            || binding.control_revision() != resumed.state.revision
        {
            return Err(invalid(
                "Reconstruction changed canonical quota or current policy",
            ));
        }
        let continuity = CanonicalContinuity {
            investigation_id: binding.investigation_id(),
            session_id: binding.session_id(),
            budget_id: binding.budget_id(),
            consumed_before: before.consumed,
            consumed_after: after.consumed,
            control_revision: binding.control_revision(),
        };
        Ok((binding, continuity))
    }
}
fn invalid(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::InvalidInput, message)
}
