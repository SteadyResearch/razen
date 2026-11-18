use crate::{
    domain::values::{ContractVersion, EntityId, Usage, WireInt},
    protocol::error::ProofResult,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCapabilities {
    pub offline: bool,
    pub network: bool,
    pub cancellation: bool,
    pub max_proposals: u16,
    pub max_context_refs: u16,
}

pub struct ModelRequest<'a> {
    pub request_id: EntityId,
    pub provider: &'a str,
    pub model: &'a str,
    pub version: ContractVersion,
    pub context_refs: &'a [EntityId],
    pub purpose: &'a str,
    pub output_contract: ContractVersion,
    pub budget: Usage,
}
impl<'a> ModelRequest<'a> {
    pub fn offline(context_refs: &'a [EntityId]) -> Self {
        Self {
            request_id: EntityId::new(),
            provider: "offline-simulated",
            model: "fixed-r0-proposal",
            version: ContractVersion::V0_1_0,
            context_refs,
            purpose: "runtime-boundary-proof",
            output_contract: ContractVersion::V0_1_0,
            budget: Usage {
                units: WireInt::new(1).expect("one wire unit"),
                bytes: WireInt::new(65536).expect("bounded bytes"),
                cpu_us: WireInt::new(1_000_000).expect("bounded cpu"),
                elapsed_us: WireInt::new(1_000_000).expect("bounded time"),
            },
        }
    }
}
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelResponse {
    pub request_id: EntityId,
    pub provider: String,
    pub model: String,
    pub version: ContractVersion,
    pub purpose: String,
    pub output_contract: ContractVersion,
    pub context_refs: Vec<EntityId>,
    pub capabilities: ModelCapabilities,
    pub proposals: Vec<String>,
    pub usage: Usage,
}

pub trait Model {
    fn capabilities(&self) -> ModelCapabilities;
    fn generate(&mut self, request: ModelRequest<'_>) -> ProofResult<ModelResponse>;
    fn cancel(&mut self, request_id: EntityId) -> ProofResult<()>;
}
