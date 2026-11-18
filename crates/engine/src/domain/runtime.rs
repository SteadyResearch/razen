//! Runtime state and lease audit records are metadata, never transferable admission authority.
use std::fmt;

use serde::de::{self, DeserializeSeed, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::validation::invalid;
use super::values::{AuditTime, CatalogId, ContractVersion, Digest, EntityId, WireInt};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeCapability {
    BrokeredCalls,
    Events,
    Results,
    Usage,
    Cancellation,
    Closure,
    NativePause,
    NativeSteering,
}

impl RuntimeCapability {
    pub const REQUIRED: [Self; 6] = [
        Self::BrokeredCalls,
        Self::Events,
        Self::Results,
        Self::Usage,
        Self::Cancellation,
        Self::Closure,
    ];

    pub fn validate_set(capabilities: &[Self]) -> ProofResult<()> {
        if capabilities.len() > 8 {
            return Err(invalid());
        }
        let mut seen = 0_u8;
        for capability in capabilities {
            let bit = 1 << (*capability as u8);
            if seen & bit != 0 {
                return Err(invalid());
            }
            seen |= bit;
        }
        if seen & 0b0011_1111 != 0b0011_1111 {
            return Err(invalid());
        }
        Ok(())
    }
}

pub(crate) fn capabilities<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<RuntimeCapability>, D::Error> {
    struct Capabilities;
    impl<'de> Visitor<'de> for Capabilities {
        type Value = Vec<RuntimeCapability>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("at most eight distinct runtime capabilities including the six required capabilities")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            if sequence.size_hint().is_some_and(|size| size > 8) {
                return Err(de::Error::custom("Too many runtime capabilities"));
            }
            let Some(first) = sequence.next_element()? else {
                return Err(de::Error::custom(
                    "Required runtime capabilities are missing",
                ));
            };
            let mut capabilities = Vec::with_capacity(8);
            capabilities.push(first);
            while capabilities.len() < 8 {
                let Some(capability) = sequence.next_element()? else {
                    break;
                };
                capabilities.push(capability);
            }
            if sequence
                .next_element_seed(RejectAdditionalCapability)?
                .is_some()
            {
                return Err(de::Error::custom("Too many runtime capabilities"));
            }
            RuntimeCapability::validate_set(&capabilities).map_err(de::Error::custom)?;
            Ok(capabilities)
        }
    }
    deserializer.deserialize_seq(Capabilities)
}

struct RejectAdditionalCapability;
impl<'de> DeserializeSeed<'de> for RejectAdditionalCapability {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _: D) -> Result<(), D::Error> {
        Err(de::Error::custom("Too many runtime capabilities"))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeState {
    Created,
    Running,
    WaitingApproval,
    Paused,
    Cancelling,
    Cancelled,
    Completed,
    Failed,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "RuntimeBindingWire")]
pub struct RuntimeBinding {
    pub binding_id: EntityId,
    pub run_id: EntityId,
    pub adapter_id: CatalogId,
    pub adapter_version: ContractVersion,
    pub runtime_digest: Digest,
    pub capabilities: Vec<RuntimeCapability>,
    pub investigation_id: EntityId,
    pub session_id: EntityId,
    pub state: RuntimeState,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeBindingWire {
    binding_id: EntityId,
    run_id: EntityId,
    adapter_id: CatalogId,
    adapter_version: ContractVersion,
    runtime_digest: Digest,
    #[serde(deserialize_with = "capabilities")]
    capabilities: Vec<RuntimeCapability>,
    investigation_id: EntityId,
    session_id: EntityId,
    state: RuntimeState,
}

impl TryFrom<RuntimeBindingWire> for RuntimeBinding {
    type Error = ProofError;
    fn try_from(wire: RuntimeBindingWire) -> ProofResult<Self> {
        Ok(Self {
            binding_id: wire.binding_id,
            run_id: wire.run_id,
            adapter_id: wire.adapter_id,
            adapter_version: wire.adapter_version,
            runtime_digest: wire.runtime_digest,
            capabilities: wire.capabilities,
            investigation_id: wire.investigation_id,
            session_id: wire.session_id,
            state: wire.state,
        })
    }
}

impl RuntimeBinding {
    pub fn validate(&self) -> ProofResult<()> {
        RuntimeCapability::validate_set(&self.capabilities)
    }

    pub fn transition(&mut self, next: RuntimeState) -> ProofResult<()> {
        use RuntimeState::*;
        self.validate()?;
        if !matches!(
            (self.state, next),
            (Created, Running | Cancelling | Failed | Closed)
                | (
                    Running,
                    WaitingApproval | Paused | Cancelling | Completed | Failed
                )
                | (WaitingApproval, Running | Paused | Cancelling | Failed)
                | (Paused, Running | Cancelling | Failed)
                | (Cancelling, Cancelled | Failed)
                | (Cancelled | Completed | Failed, Closed)
        ) {
            return Err(invalid());
        }
        self.state = next;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    Expired,
    Revoked,
    Closed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub lease_id: EntityId,
    pub invocation_id: EntityId,
    pub owner_binding_id: EntityId,
    pub control_revision: WireInt,
    pub expires_at: AuditTime,
    pub state: LeaseState,
}

impl Lease {
    /// This consistency check does not replace grants, host admission, or the independent guest monotonic timer.
    pub fn validate_current(
        &self,
        binding: EntityId,
        invocation: EntityId,
        revision: WireInt,
        now: AuditTime,
    ) -> ProofResult<()> {
        if self.owner_binding_id != binding
            || self.invocation_id != invocation
            || self.control_revision != revision
            || self.state != LeaseState::Active
            || now >= self.expires_at
        {
            return Err(ProofError::new(
                ErrorCode::PermissionDenied,
                "Lease is not current for this owned binding and invocation",
            ));
        }
        Ok(())
    }

    /// Losing the owning process revokes a recorded active lease even before its audit expiry.
    pub fn invalidate_after_restart(&mut self) {
        if self.state == LeaseState::Active {
            self.state = LeaseState::Revoked;
        }
    }
}
