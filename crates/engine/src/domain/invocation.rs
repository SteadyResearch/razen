//! Canonical invocation records and host-trusted transition provenance.
//!
//! The public wire record never carries history. History storage is an internal ledger/fixture
//! format, not a credential and not acceptable from peers. Its grant snapshots prove checks
//! at recorded assignment times, never current authorization after restart.
use std::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use super::authority::ApprovalGrant;
use super::validation::{MAX_METADATA_BYTES, bounded_text, invalid};
use super::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage, WireInt,
    non_null_optional,
};
use crate::protocol::error::{ProofError, ProofResult};

const MAX_RECORD_BYTES: usize = 1_048_576;
// Longest legal path: proposed -> waiting -> reserved -> sending -> unknown -> terminal.
const MAX_HISTORY_TRANSITIONS: usize = 5;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "InvocationWire")]
pub struct Invocation {
    pub invocation_id: EntityId,
    pub run_id: EntityId,
    pub project_id: EntityId,
    pub investigation_id: EntityId,
    pub session_id: EntityId,
    pub actor_ref: EntityId,
    pub tool_id: CatalogId,
    pub tool_version: ContractVersion,
    pub provider_digest: Digest,
    pub input_ref: EntityId,
    pub input_sha256: Digest,
    pub input_revision: WireInt,
    pub control_revision: WireInt,
    pub scope_revision: WireInt,
    pub identity_id: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<EntityId>,
    pub budget_id: EntityId,
    pub attempt: WireInt,
    pub causation_id: EntityId,
    pub deduplication_key: String,
    pub state: InvocationState,
    pub usage: Usage,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_ref: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProofError>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InvocationWire {
    invocation_id: EntityId,
    run_id: EntityId,
    project_id: EntityId,
    investigation_id: EntityId,
    session_id: EntityId,
    actor_ref: EntityId,
    tool_id: CatalogId,
    tool_version: ContractVersion,
    provider_digest: Digest,
    input_ref: EntityId,
    input_sha256: Digest,
    input_revision: WireInt,
    control_revision: WireInt,
    scope_revision: WireInt,
    identity_id: EntityId,
    #[serde(default, deserialize_with = "non_null_optional")]
    grant_id: Option<EntityId>,
    budget_id: EntityId,
    attempt: WireInt,
    causation_id: EntityId,
    #[serde(deserialize_with = "bounded_text")]
    deduplication_key: String,
    state: InvocationState,
    usage: Usage,
    #[serde(default, deserialize_with = "non_null_optional")]
    output_ref: Option<EntityId>,
    #[serde(default, deserialize_with = "non_null_optional")]
    error: Option<ProofError>,
}

impl InvocationWire {
    pub(crate) fn entity_id(&self) -> EntityId {
        self.invocation_id
    }

    pub(crate) fn into_validated(
        self,
        history: Option<&InvocationHistory>,
    ) -> ProofResult<Invocation> {
        let record = self.into_record();
        record.validate(history)?;
        Ok(record)
    }

    fn into_record(self) -> Invocation {
        Invocation {
            invocation_id: self.invocation_id,
            run_id: self.run_id,
            project_id: self.project_id,
            investigation_id: self.investigation_id,
            session_id: self.session_id,
            actor_ref: self.actor_ref,
            tool_id: self.tool_id,
            tool_version: self.tool_version,
            provider_digest: self.provider_digest,
            input_ref: self.input_ref,
            input_sha256: self.input_sha256,
            input_revision: self.input_revision,
            control_revision: self.control_revision,
            scope_revision: self.scope_revision,
            identity_id: self.identity_id,
            grant_id: self.grant_id,
            budget_id: self.budget_id,
            attempt: self.attempt,
            causation_id: self.causation_id,
            deduplication_key: self.deduplication_key,
            state: self.state,
            usage: self.usage,
            output_ref: self.output_ref,
            error: self.error,
        }
    }
}

impl TryFrom<InvocationWire> for Invocation {
    type Error = ProofError;
    fn try_from(value: InvocationWire) -> ProofResult<Self> {
        let record = value.into_record();
        record.validate(None)?;
        Ok(record)
    }
}

impl Invocation {
    /// Decode the exact canonical wire object. A cancelled record requires separate trusted
    /// provenance, either the complete current history or its immediately preceding state.
    pub fn parse_json(bytes: &[u8], history: Option<&InvocationHistory>) -> ProofResult<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid());
        }
        let wire: InvocationWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let record = wire.into_record();
        record.validate(history)?;
        Ok(record)
    }

    pub fn validate(&self, history: Option<&InvocationHistory>) -> ProofResult<()> {
        self.validate_shape()?;
        if let Some(history) = history {
            if history.last() != self {
                history.validate_next(self)?;
            }
        } else if self.state == InvocationState::Cancelled {
            return Err(invalid());
        }
        Ok(())
    }

    fn validate_shape(&self) -> ProofResult<()> {
        use InvocationState::*;
        let correct_grant = match self.state {
            Proposed | Rejected | WaitingApproval => self.grant_id.is_none(),
            Reserved | Sending | Completed | Failed | OutcomeUnknown => self.grant_id.is_some(),
            Cancelled => true, // Only host history can establish which shape is valid.
        };
        if !correct_grant
            || self.deduplication_key.is_empty()
            || self.deduplication_key.len() > MAX_METADATA_BYTES
            || self.deduplication_key.chars().any(char::is_control)
            || (self.output_ref.is_some() && self.error.is_some())
            || (self.state == Completed && self.error.is_some())
            || self
                .error
                .as_ref()
                .and_then(|error| error.invocation_id)
                .is_some_and(|id| id != self.invocation_id)
        {
            return Err(invalid());
        }
        Ok(())
    }

    fn same_binding(&self, other: &Self) -> bool {
        self.invocation_id == other.invocation_id
            && self.run_id == other.run_id
            && self.project_id == other.project_id
            && self.investigation_id == other.investigation_id
            && self.session_id == other.session_id
            && self.actor_ref == other.actor_ref
            && self.tool_id == other.tool_id
            && self.tool_version == other.tool_version
            && self.provider_digest == other.provider_digest
            && self.input_ref == other.input_ref
            && self.input_sha256 == other.input_sha256
            && self.input_revision == other.input_revision
            && self.control_revision == other.control_revision
            && self.scope_revision == other.scope_revision
            && self.identity_id == other.identity_id
            && self.budget_id == other.budget_id
            && self.attempt == other.attempt
            && self.causation_id == other.causation_id
            && self.deduplication_key == other.deduplication_key
    }
}

#[derive(Clone, Debug)]
pub struct InvocationHistory {
    initial: Invocation,
    transitions: Vec<TransitionFact>,
}

#[derive(Clone, Debug, Serialize)]
struct TransitionFact {
    invocation: Invocation,
    recorded_at: AuditTime,
    #[serde(skip_serializing_if = "Option::is_none")]
    admission_grant: Option<ApprovalGrant>,
}

impl InvocationHistory {
    pub fn event_sequence(&self) -> WireInt {
        WireInt::new(self.transitions.len() as u64 + 1)
            .expect("history has at most five transitions")
    }

    pub fn start(proposed: &Invocation) -> ProofResult<Self> {
        proposed.validate(None)?;
        if proposed.state != InvocationState::Proposed {
            return Err(invalid());
        }
        Ok(Self {
            initial: proposed.clone(),
            transitions: Vec::new(),
        })
    }

    pub fn last(&self) -> &Invocation {
        self.transitions
            .last()
            .map_or(&self.initial, |fact| &fact.invocation)
    }

    fn validate_next(&self, next: &Invocation) -> ProofResult<()> {
        next.validate_shape()?;
        let previous = self.last();
        if !previous.same_binding(next)
            || !legal_transition(previous.state, next.state)
            || next.usage.units < previous.usage.units
            || next.usage.bytes < previous.usage.bytes
            || next.usage.cpu_us < previous.usage.cpu_us
            || next.usage.elapsed_us < previous.usage.elapsed_us
        {
            return Err(invalid());
        }
        if next.state == InvocationState::Reserved {
            if previous.grant_id.is_some() || next.grant_id.is_none() {
                return Err(invalid());
            }
        } else if previous.grant_id != next.grant_id {
            return Err(invalid());
        }
        Ok(())
    }

    /// Called only by the trusted host. Assignment/final admission snapshots must come from
    /// the canonical grant registry, not caller input. Other transitions preserve provenance
    /// without requiring the historical grant still to be live.
    pub fn record(
        &mut self,
        next: &Invocation,
        current_grant: Option<&ApprovalGrant>,
        at: AuditTime,
    ) -> ProofResult<()> {
        self.validate_next(next)?;
        if self.transitions.len() == MAX_HISTORY_TRANSITIONS {
            return Err(invalid());
        }
        let admission_grant = if matches!(
            next.state,
            InvocationState::Reserved | InvocationState::Sending
        ) {
            let grant = current_grant.ok_or_else(invalid)?;
            grant.validate_current(next, &next.usage, at)?;
            Some(grant.clone())
        } else {
            None
        };
        self.transitions.push(TransitionFact {
            invocation: next.clone(),
            recorded_at: at,
            admission_grant,
        });
        Ok(())
    }

    /// Export internal host-created facts. Never expose this as transferable authority.
    pub fn export_json(&self) -> ProofResult<Vec<u8>> {
        #[derive(Serialize)]
        struct Storage<'a> {
            schema_version: ContractVersion,
            initial: &'a Invocation,
            transitions: &'a [TransitionFact],
        }
        let bytes = serde_json::to_vec(&Storage {
            schema_version: ContractVersion::V0_1_0,
            initial: &self.initial,
            transitions: &self.transitions,
        })
        .map_err(|_| invalid())?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid());
        }
        Ok(bytes)
    }

    /// Restore only from the integrity-checked owned ledger or trusted canonical fixtures.
    /// Validation replays the grant snapshots at their recorded assignment times; current
    /// live grants must still be checked independently before any new effect.
    pub fn restore_json(bytes: &[u8]) -> ProofResult<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(invalid());
        }
        let storage: HistoryStorage = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let _version = storage.schema_version;
        let mut history = Self::start(&storage.initial.into_record())?;
        for fact in storage.transitions {
            let next = fact.invocation.into_record();
            let admission = matches!(
                next.state,
                InvocationState::Reserved | InvocationState::Sending
            );
            if !admission && fact.admission_grant.is_some() {
                return Err(invalid());
            }
            history.record(&next, fact.admission_grant.as_ref(), fact.recorded_at)?;
        }
        Ok(history)
    }
}

fn legal_transition(from: InvocationState, to: InvocationState) -> bool {
    use InvocationState::*;
    matches!(
        (from, to),
        (Proposed, Rejected | WaitingApproval | Reserved)
            | (WaitingApproval, Reserved | Cancelled)
            | (Reserved, Cancelled | Sending)
            | (Sending, Completed | Failed | OutcomeUnknown)
            | (OutcomeUnknown, Completed | Failed)
    )
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HistoryStorage {
    schema_version: ContractVersion,
    initial: InvocationWire,
    #[serde(deserialize_with = "history_facts")]
    transitions: Vec<StoredTransition>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredTransition {
    invocation: InvocationWire,
    recorded_at: AuditTime,
    #[serde(default, deserialize_with = "non_null_optional")]
    admission_grant: Option<ApprovalGrant>,
}

fn history_facts<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<StoredTransition>, D::Error> {
    struct Facts;
    impl<'de> Visitor<'de> for Facts {
        type Value = Vec<StoredTransition>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("bounded host transition facts")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Self::Value, A::Error> {
            let mut facts = Vec::new();
            while let Some(fact) = sequence.next_element()? {
                if facts.len() == MAX_HISTORY_TRANSITIONS {
                    return Err(de::Error::custom("too many invocation transitions"));
                }
                facts.push(fact);
            }
            Ok(facts)
        }
    }
    deserializer.deserialize_seq(Facts)
}
