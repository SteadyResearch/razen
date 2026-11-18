//! Common durable execution records, independent of runtime, transport, or storage adapters.
use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::validation::{MAX_RECORD_ITEMS, bounded_vec, invalid};
use super::values::{AuditTime, CatalogId, ContractVersion, EntityId, WireInt, non_null_optional};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub checkpoint_id: EntityId,
    pub run_id: EntityId,
    pub schema_version: ContractVersion,
    pub control_revision: WireInt,
    pub scope_revision: WireInt,
    #[serde(deserialize_with = "bounded_vec")]
    pub budget_refs: Vec<EntityId>,
    #[serde(deserialize_with = "bounded_vec")]
    pub invocation_refs: Vec<EntityId>,
    #[serde(deserialize_with = "bounded_vec")]
    pub lease_refs: Vec<EntityId>,
    #[serde(deserialize_with = "event_cursors")]
    pub event_cursors: BTreeMap<EntityId, WireInt>,
    pub created_at: AuditTime,
}

fn event_cursors<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<BTreeMap<EntityId, WireInt>, D::Error> {
    struct Cursors;
    impl<'de> Visitor<'de> for Cursors {
        type Value = BTreeMap<EntityId, WireInt>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bounded unique aggregate event cursors")
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
            let mut cursors = BTreeMap::new();
            while let Some(key) = map.next_key::<EntityId>()? {
                if cursors.len() == MAX_RECORD_ITEMS || cursors.contains_key(&key) {
                    return Err(de::Error::custom("duplicate or excessive event cursors"));
                }
                cursors.insert(key, map.next_value()?);
            }
            Ok(cursors)
        }
    }
    deserializer.deserialize_map(Cursors)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlMode {
    Running,
    Paused,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ControlStateWire")]
pub struct ControlState {
    pub investigation_id: EntityId,
    pub revision: WireInt,
    pub mode: ControlMode,
    pub admission_open: bool,
    pub instruction_ref: EntityId,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlStateWire {
    investigation_id: EntityId,
    revision: WireInt,
    mode: ControlMode,
    admission_open: bool,
    instruction_ref: EntityId,
}

impl TryFrom<ControlStateWire> for ControlState {
    type Error = ProofError;
    fn try_from(value: ControlStateWire) -> ProofResult<Self> {
        let state = Self {
            investigation_id: value.investigation_id,
            revision: value.revision,
            mode: value.mode,
            admission_open: value.admission_open,
            instruction_ref: value.instruction_ref,
        };
        state.validate()?;
        Ok(state)
    }
}

impl ControlState {
    pub fn validate(&self) -> ProofResult<()> {
        if self.mode != ControlMode::Running && self.admission_open {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "ControlMeasurementWire")]
pub struct ControlMeasurement {
    pub request_id: EntityId,
    pub clock_epoch_id: EntityId,
    pub received_us: WireInt,
    pub barrier_active_us: WireInt,
    pub acknowledged_us: WireInt,
    pub affected_revision: WireInt,
    pub late_admissions: WireInt,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlMeasurementWire {
    request_id: EntityId,
    clock_epoch_id: EntityId,
    received_us: WireInt,
    barrier_active_us: WireInt,
    acknowledged_us: WireInt,
    affected_revision: WireInt,
    late_admissions: WireInt,
}

impl TryFrom<ControlMeasurementWire> for ControlMeasurement {
    type Error = ProofError;
    fn try_from(value: ControlMeasurementWire) -> ProofResult<Self> {
        let measurement = Self {
            request_id: value.request_id,
            clock_epoch_id: value.clock_epoch_id,
            received_us: value.received_us,
            barrier_active_us: value.barrier_active_us,
            acknowledged_us: value.acknowledged_us,
            affected_revision: value.affected_revision,
            late_admissions: value.late_admissions,
        };
        measurement.validate()?;
        Ok(measurement)
    }
}

impl ControlMeasurement {
    pub fn validate(&self) -> ProofResult<()> {
        if self.received_us > self.barrier_active_us
            || self.barrier_active_us > self.acknowledged_us
        {
            return Err(invalid());
        }
        Ok(())
    }

    pub fn ack_elapsed_us(&self) -> ProofResult<WireInt> {
        self.validate()?;
        self.acknowledged_us
            .checked_sub(self.received_us)
            .map_err(Into::into)
    }

    /// Validates recorded measurements, not an assertion that a barrier actually committed.
    pub fn validate_barrier_deadline(&self, deadline_us: WireInt) -> ProofResult<()> {
        if self.ack_elapsed_us()? > deadline_us {
            return Err(ProofError::new(
                ErrorCode::Timeout,
                "Control acknowledgment exceeded its deadline",
            ));
        }
        if self.late_admissions != WireInt::ZERO {
            return Err(ProofError::new(
                ErrorCode::IntegrityError,
                "Stale admissions occurred after the control barrier",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Event {
    pub event_id: EntityId,
    pub schema_version: ContractVersion,
    pub project_id: EntityId,
    pub aggregate_id: EntityId,
    pub aggregate_sequence: WireInt,
    pub event_type: CatalogId,
    pub timestamp: AuditTime,
    pub correlation_id: EntityId,
    pub causation_id: EntityId,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub control_revision: Option<WireInt>,
    #[serde(deserialize_with = "bounded_vec")]
    pub data_refs: Vec<EntityId>,
    pub published: bool,
}

/// The event is the transactional outbox record; delivery does not introduce a second schema.
pub type OutboxEntry = Event;
