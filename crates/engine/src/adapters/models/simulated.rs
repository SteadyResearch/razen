//! A deliberately offline fixture. It has no provider client, credentials, URL, or socket handle.
use crate::{
    application::effect_meter::EffectMeter,
    domain::values::{ContractVersion, EntityId},
    ports::model::{Model, ModelCapabilities, ModelRequest, ModelResponse},
    protocol::error::{ErrorCode, ProofError, ProofResult},
};
use std::collections::BTreeSet;

pub struct SimulatedModel {
    cancelled: BTreeSet<EntityId>,
    generated: BTreeSet<EntityId>,
}
impl SimulatedModel {
    pub fn new() -> Self {
        Self {
            cancelled: BTreeSet::new(),
            generated: BTreeSet::new(),
        }
    }
}
impl Default for SimulatedModel {
    fn default() -> Self {
        Self::new()
    }
}
impl Model for SimulatedModel {
    fn capabilities(&self) -> ModelCapabilities {
        ModelCapabilities {
            offline: true,
            network: false,
            cancellation: true,
            max_proposals: 1,
            max_context_refs: 256,
        }
    }
    fn generate(&mut self, request: ModelRequest<'_>) -> ProofResult<ModelResponse> {
        if request.provider != "offline-simulated" {
            return Err(error(
                ErrorCode::ProviderUnavailable,
                "Only the explicitly offline fixture provider is available",
            ));
        }
        if self.cancelled.contains(&request.request_id) {
            return Err(error(
                ErrorCode::Cancelled,
                "Offline model request was cancelled",
            ));
        }
        if self.generated.contains(&request.request_id) {
            return Err(error(
                ErrorCode::InvalidInput,
                "Model request ID cannot be regenerated",
            ));
        }
        if self.generated.len() + self.cancelled.len() >= 256 {
            return Err(error(
                ErrorCode::BudgetExhausted,
                "Bounded offline model request history exhausted",
            ));
        }
        if request.model != "fixed-r0-proposal"
            || request.version != ContractVersion::V0_1_0
            || request.output_contract != ContractVersion::V0_1_0
            || request.purpose != "runtime-boundary-proof"
            || request.context_refs.len() > 256
        {
            return Err(error(
                ErrorCode::InvalidInput,
                "Model selection, purpose, output contract or context exceeds the reviewed fixture",
            ));
        }
        let mut meter = EffectMeter::start();
        let proposal = "Read only the host-selected investigation context through context.read; propose no direct external effect.";
        meter.add_bytes(proposal.len())?;
        meter.dispatched = true;
        let usage = meter.usage()?;
        if usage.units > request.budget.units
            || usage.bytes > request.budget.bytes
            || usage.cpu_us > request.budget.cpu_us
            || usage.elapsed_us > request.budget.elapsed_us
        {
            return Err(error(
                ErrorCode::BudgetExhausted,
                "Offline model output exceeds its selected budget",
            ));
        }
        self.generated.insert(request.request_id);
        Ok(ModelResponse {
            request_id: request.request_id,
            provider: request.provider.into(),
            model: request.model.into(),
            version: request.version,
            purpose: request.purpose.into(),
            output_contract: request.output_contract,
            context_refs: request.context_refs.to_vec(),
            capabilities: self.capabilities(),
            proposals: vec![proposal.into()],
            usage,
        })
    }
    fn cancel(&mut self, request_id: EntityId) -> ProofResult<()> {
        if self.generated.contains(&request_id) {
            return Err(error(
                ErrorCode::InvalidInput,
                "Completed synchronous model request cannot be undone",
            ));
        }
        if !self.cancelled.contains(&request_id)
            && self.generated.len() + self.cancelled.len() >= 256
        {
            return Err(error(
                ErrorCode::BudgetExhausted,
                "Bounded offline model cancellation history exhausted",
            ));
        }
        self.cancelled.insert(request_id);
        Ok(())
    }
}
fn error(code: ErrorCode, message: &'static str) -> ProofError {
    ProofError::new(code, message)
}
