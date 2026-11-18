//! Typed contract data does not confer authority. History is supplied only by the
//! trusted fixture/ledger boundary, never by a peer's document.
use std::borrow::Cow;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use rustix::fs::{self, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;

use super::error::{ErrorCode, ProofError, ProofResult};
use crate::domain::authority::{
    ApprovalGrant, Budget, FixtureProject, IdentityProfile, ScopePolicy, ToolDescriptor,
};
use crate::domain::evidence::{Artifact, EvidenceRef, ObservationProposal, Patch, Snapshot};
use crate::domain::execution::{Checkpoint, ControlMeasurement, ControlState, Event};
use crate::domain::invocation::{Invocation, InvocationHistory, InvocationWire};
use crate::domain::knowledge::{
    AssetGraph, InvestigationGraph, InvestigationSession, MemoryItem, Trace, WorkflowDefinition,
    validate_example_links,
};
use crate::domain::proofs::{ProofCase, ProofResult as CaseResult, Run, WorkPackage};
use crate::domain::validation::bounded_vec;
use crate::domain::values::{ContractVersion, EntityId};

const MAX_DOCUMENT_BYTES: usize = 1_048_576;
const MAX_FIXTURE_BYTES: usize = 8 * 1_048_576;
const MAX_BODY_BYTES: usize = 1_048_576;
const MAX_BODY_BASE64: usize = MAX_BODY_BYTES.div_ceil(3) * 4;
const MAX_HISTORIES: usize = 256;

#[derive(Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "type", content = "fields", rename_all = "snake_case")]
pub enum ContractRecord {
    FixtureProject(FixtureProject),
    ScopePolicy(ScopePolicy),
    IdentityProfile(IdentityProfile),
    ToolDescriptor(ToolDescriptor),
    ApprovalGrant(ApprovalGrant),
    Budget(Budget),
    Snapshot(Snapshot),
    Patch(Patch),
    Artifact(Artifact),
    EvidenceRef(EvidenceRef),
    ObservationProposal(ObservationProposal),
    Invocation(Box<Invocation>),
    Checkpoint(Checkpoint),
    ControlState(ControlState),
    ControlMeasurement(ControlMeasurement),
    Event(Event),
    InvestigationSession(InvestigationSession),
    AssetGraph(AssetGraph),
    InvestigationGraph(InvestigationGraph),
    WorkflowDefinition(WorkflowDefinition),
    Trace(Trace),
    MemoryItem(MemoryItem),
    WorkPackage(WorkPackage),
    ProofCase(ProofCase),
    Run(Box<Run>),
    ProofResult(CaseResult),
}

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct ContractDocument {
    pub schema_version: ContractVersion,
    pub record: ContractRecord,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentWire<'a> {
    schema_version: ContractVersion,
    #[serde(borrow)]
    record: RecordWire<'a>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordWire<'a> {
    #[serde(borrow)]
    r#type: Cow<'a, str>,
    #[serde(borrow)]
    fields: &'a RawValue,
}

/// Context construction is a trusted-host operation, not a wire deserialization API.
#[derive(Debug)]
pub struct TrustedContractContext {
    histories: BTreeMap<EntityId, InvocationHistory>,
}

impl TrustedContractContext {
    pub fn from_histories(histories: Vec<InvocationHistory>) -> ProofResult<Self> {
        if histories.len() > MAX_HISTORIES {
            return Err(capacity());
        }
        let mut indexed = BTreeMap::new();
        for history in histories {
            let id = history.last().invocation_id;
            if indexed.insert(id, history).is_some() {
                return Err(invalid());
            }
        }
        Ok(Self { histories: indexed })
    }
}

pub fn parse_document(
    bytes: &[u8],
    context: &TrustedContractContext,
) -> ProofResult<ContractDocument> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(capacity());
    }
    let wire: DocumentWire<'_> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let fields = wire.record.fields;
    let record = match wire.record.r#type.as_ref() {
        "fixture_project" => ContractRecord::FixtureProject(parse(fields)?),
        "scope_policy" => ContractRecord::ScopePolicy(parse(fields)?),
        "identity_profile" => ContractRecord::IdentityProfile(parse(fields)?),
        "tool_descriptor" => ContractRecord::ToolDescriptor(parse(fields)?),
        "approval_grant" => ContractRecord::ApprovalGrant(parse(fields)?),
        "budget" => ContractRecord::Budget(parse(fields)?),
        "snapshot" => ContractRecord::Snapshot(parse(fields)?),
        "patch" => ContractRecord::Patch(parse(fields)?),
        "artifact" => ContractRecord::Artifact(parse(fields)?),
        "evidence_ref" => ContractRecord::EvidenceRef(parse(fields)?),
        "observation_proposal" => ContractRecord::ObservationProposal(parse(fields)?),
        "invocation" => {
            // One typed decode: choose provenance from the decoded ID before validation.
            let candidate: InvocationWire = parse(fields)?;
            let history = context.histories.get(&candidate.entity_id());
            ContractRecord::Invocation(Box::new(candidate.into_validated(history)?))
        }
        "checkpoint" => ContractRecord::Checkpoint(parse(fields)?),
        "control_state" => ContractRecord::ControlState(parse(fields)?),
        "control_measurement" => ContractRecord::ControlMeasurement(parse(fields)?),
        "event" => ContractRecord::Event(parse(fields)?),
        "investigation_session" => ContractRecord::InvestigationSession(parse(fields)?),
        "asset_graph" => ContractRecord::AssetGraph(parse(fields)?),
        "investigation_graph" => ContractRecord::InvestigationGraph(parse(fields)?),
        "workflow_definition" => ContractRecord::WorkflowDefinition(parse(fields)?),
        "trace" => ContractRecord::Trace(parse(fields)?),
        "memory_item" => ContractRecord::MemoryItem(parse(fields)?),
        "work_package" => ContractRecord::WorkPackage(parse(fields)?),
        "proof_case" => ContractRecord::ProofCase(parse(fields)?),
        "run" => ContractRecord::Run(parse(fields)?),
        "proof_result" => ContractRecord::ProofResult(parse(fields)?),
        _ => return Err(invalid()),
    };
    Ok(ContractDocument {
        schema_version: wire.schema_version,
        record,
    })
}

fn parse<'a, T: Deserialize<'a>>(raw: &'a RawValue) -> ProofResult<T> {
    serde_json::from_str(raw.get()).map_err(|_| invalid())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixturePackWire<'a> {
    schema_version: ContractVersion,
    #[serde(borrow, deserialize_with = "bounded_vec")]
    histories: Vec<&'a RawValue>,
    #[serde(borrow, deserialize_with = "bounded_vec")]
    records: Vec<&'a RawValue>,
    #[serde(borrow, deserialize_with = "bounded_vec")]
    bodies: Vec<BodyWire<'a>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyWire<'a> {
    body_id: EntityId,
    // Checked-in fixture source uses canonical unescaped Base64 literals, not peer text.
    #[serde(borrow)]
    bytes_base64: &'a str,
}

#[derive(Debug)]
pub struct FixtureBody {
    pub body_id: EntityId,
    pub bytes: Vec<u8>,
}

/// Synthetic schema examples and their actual bytes; never executed-proof evidence.
#[derive(Debug)]
pub struct CanonicalFixtures {
    context: TrustedContractContext,
    records: Vec<ContractDocument>,
    bodies: BTreeMap<EntityId, FixtureBody>,
}

impl CanonicalFixtures {
    pub fn load(path: &Path) -> ProofResult<Self> {
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        let mut file = File::from(fs::open(path, flags, Mode::empty()).map_err(|_| integrity())?);
        let stat = fs::fstat(&file).map_err(|_| integrity())?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
            || stat.st_size <= 0
            || stat.st_size > MAX_FIXTURE_BYTES as i64
            || stat.st_nlink != 1
        {
            return Err(integrity());
        }
        let mut bytes = Vec::with_capacity(stat.st_size as usize);
        (&mut file)
            .take(MAX_FIXTURE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| integrity())?;
        if bytes.len() > MAX_FIXTURE_BYTES {
            return Err(capacity());
        }
        Self::from_bytes(&bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> ProofResult<Self> {
        if bytes.len() > MAX_FIXTURE_BYTES {
            return Err(capacity());
        }
        let wire: FixturePackWire<'_> = serde_json::from_slice(bytes).map_err(|_| invalid())?;
        let _version = wire.schema_version;
        let histories = wire
            .histories
            .into_iter()
            .map(|raw| InvocationHistory::restore_json(raw.get().as_bytes()))
            .collect::<ProofResult<Vec<_>>>()?;
        let context = TrustedContractContext::from_histories(histories)?;
        let records = wire
            .records
            .into_iter()
            .map(|raw| parse_document(raw.get().as_bytes(), &context))
            .collect::<ProofResult<Vec<_>>>()?;
        let mut bodies = BTreeMap::new();
        for body in wire.bodies {
            if body.bytes_base64.len() > MAX_BODY_BASE64 {
                return Err(capacity());
            }
            let bytes = STANDARD.decode(body.bytes_base64).map_err(|_| invalid())?;
            if bytes.len() > MAX_BODY_BYTES {
                return Err(capacity());
            }
            let body = FixtureBody {
                body_id: body.body_id,
                bytes,
            };
            if bodies.insert(body.body_id, body).is_some() {
                return Err(invalid());
            }
        }
        let fixtures = Self {
            context,
            records,
            bodies,
        };
        fixtures.validate_references()?;
        Ok(fixtures)
    }

    pub fn context(&self) -> &TrustedContractContext {
        &self.context
    }
    pub fn records(&self) -> &[ContractDocument] {
        &self.records
    }
    pub fn bodies(&self) -> impl Iterator<Item = &FixtureBody> {
        self.bodies.values()
    }

    pub fn body(&self, id: EntityId) -> ProofResult<&[u8]> {
        self.bodies
            .get(&id)
            .map(|body| body.bytes.as_slice())
            .ok_or_else(invalid)
    }

    fn validate_reference(&self, project: EntityId, reference: EvidenceRef) -> ProofResult<()> {
        match reference {
            EvidenceRef::Snapshot { snapshot_id, .. } => {
                let snapshot = self
                    .records
                    .iter()
                    .find_map(|document| match &document.record {
                        ContractRecord::Snapshot(snapshot)
                            if snapshot.snapshot_id == snapshot_id =>
                        {
                            Some(snapshot)
                        }
                        _ => None,
                    })
                    .ok_or_else(invalid)?;
                reference.validate_snapshot(
                    project,
                    snapshot.revision,
                    snapshot,
                    self.body(snapshot.body_ref)?,
                )?;
            }
            EvidenceRef::Artifact { artifact_id, .. } => {
                let artifact = self
                    .records
                    .iter()
                    .find_map(|document| match &document.record {
                        ContractRecord::Artifact(artifact)
                            if artifact.artifact_id == artifact_id =>
                        {
                            Some(artifact)
                        }
                        _ => None,
                    })
                    .ok_or_else(invalid)?;
                reference.validate_artifact(project, artifact, self.body(artifact_id)?)?;
            }
        }
        Ok(())
    }

    fn validate_references(&self) -> ProofResult<()> {
        let (mut assets, mut investigation, mut workflow, mut trace, mut session) =
            (None, None, None, None, None);
        for document in &self.records {
            match &document.record {
                ContractRecord::Snapshot(snapshot) => {
                    snapshot.validate_bytes(
                        snapshot.project_id,
                        snapshot.revision,
                        self.body(snapshot.body_ref)?,
                    )?;
                }
                ContractRecord::Artifact(artifact) => {
                    artifact
                        .validate_bytes(artifact.project_id, self.body(artifact.artifact_id)?)?;
                }
                ContractRecord::ObservationProposal(proposal) => {
                    for reference in &proposal.evidence_refs {
                        self.validate_reference(proposal.project_id, *reference)?;
                    }
                }
                ContractRecord::InvestigationSession(value) => {
                    if session.replace(value).is_some() {
                        return Err(invalid());
                    }
                }
                ContractRecord::AssetGraph(value) => {
                    if assets.replace(value).is_some() {
                        return Err(invalid());
                    }
                }
                ContractRecord::InvestigationGraph(value) => {
                    if investigation.replace(value).is_some() {
                        return Err(invalid());
                    }
                }
                ContractRecord::WorkflowDefinition(value) => {
                    if workflow.replace(value).is_some() {
                        return Err(invalid());
                    }
                }
                ContractRecord::Trace(value) if trace.replace(value).is_some() => {
                    return Err(invalid());
                }
                _ => {}
            }
        }
        if let (Some(assets), Some(investigation), Some(workflow), Some(trace), Some(session)) =
            (assets, investigation, workflow, trace, session)
        {
            validate_example_links(assets, investigation, workflow, trace, session)?;
            for reference in &session.evidence_refs {
                self.validate_reference(assets.project_id, *reference)?;
            }
        } else if assets.is_some()
            || investigation.is_some()
            || workflow.is_some()
            || trace.is_some()
            || session.is_some()
        {
            return Err(invalid());
        }
        Ok(())
    }
}

fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Canonical contract data does not match its schema or context",
    )
}
fn capacity() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Canonical contract input exceeds its bounded size",
    )
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Canonical fixture source integrity is invalid",
    )
}
