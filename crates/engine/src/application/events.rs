//! Bounded, ordered at-least-once delivery. A late audit event never grants admission.
use std::collections::BTreeMap;

use crate::domain::execution::Event;
use crate::domain::values::{ContractVersion, EntityId, WireInt};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventDisposition {
    Accepted,
    Duplicate,
    Late,
}

pub struct EventConsumer {
    capacity: usize,
    seen: BTreeMap<EntityId, Event>,
    cursors: BTreeMap<EntityId, WireInt>,
}

impl EventConsumer {
    pub fn new(capacity: usize) -> ProofResult<Self> {
        if !(1..=16_384).contains(&capacity) {
            return Err(invalid());
        }
        Ok(Self {
            capacity,
            seen: BTreeMap::new(),
            cursors: BTreeMap::new(),
        })
    }

    pub fn cursor(&self, aggregate: EntityId) -> WireInt {
        self.cursors
            .get(&aggregate)
            .copied()
            .unwrap_or(WireInt::ZERO)
    }

    pub fn accept(
        &mut self,
        event: &Event,
        current_control_revision: WireInt,
    ) -> ProofResult<EventDisposition> {
        if event.schema_version != ContractVersion::V0_1_0
            || event.aggregate_sequence == WireInt::ZERO
            || event.data_refs.len() > 256
            || event
                .control_revision
                .is_some_and(|revision| revision > current_control_revision)
        {
            return Err(invalid());
        }
        if let Some(previous) = self.seen.get(&event.event_id) {
            // Publication is transport metadata; every other canonical field is immutable.
            let same = previous.schema_version == event.schema_version
                && previous.project_id == event.project_id
                && previous.aggregate_id == event.aggregate_id
                && previous.aggregate_sequence == event.aggregate_sequence
                && previous.event_type == event.event_type
                && previous.timestamp == event.timestamp
                && previous.correlation_id == event.correlation_id
                && previous.causation_id == event.causation_id
                && previous.control_revision == event.control_revision
                && previous.data_refs == event.data_refs;
            return if same {
                Ok(EventDisposition::Duplicate)
            } else {
                Err(integrity())
            };
        }
        if event.aggregate_sequence
            != self
                .cursor(event.aggregate_id)
                .checked_add(WireInt::new(1)?)?
        {
            return Err(ProofError::new(
                ErrorCode::StaleSnapshot,
                "Event gap or conflicting aggregate sequence makes delivery incomplete",
            ));
        }
        if self.seen.len() == self.capacity {
            return Err(ProofError::new(
                ErrorCode::BudgetExhausted,
                "Required event retention capacity is exhausted; delivery is incomplete",
            ));
        }
        let late = event
            .control_revision
            .is_some_and(|revision| revision < current_control_revision);
        self.cursors
            .insert(event.aggregate_id, event.aggregate_sequence);
        self.seen.insert(event.event_id, event.clone());
        Ok(if late {
            EventDisposition::Late
        } else {
            EventDisposition::Accepted
        })
    }
}

fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Event violates the bounded ordered delivery contract",
    )
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Duplicate event ID has different immutable facts",
    )
}
