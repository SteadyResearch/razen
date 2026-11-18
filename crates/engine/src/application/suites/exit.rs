//! EXIT-01 consumes actual prepared observations. EXIT-02 exercises CONTROLLEDGATEFIXTURE policy inputs.
//! Controlled record passes are never runtime observations or a claim that the current run passed 35 cases.
use super::CaseObservation;
use crate::{
    adapters::{evidence_store::EvidenceStore, ledger::Ledger},
    application::{
        harness::{
            CaseSelection, CommandStatus, MAX_METADATA_BYTES, ReviewStatus, ScenarioManifest,
        },
        inventory,
        profile::LoadedProfile,
        proof_host::ProofHost,
        provenance::{self, SourceEvidence},
        review::{self, ReviewContext},
    },
    domain::{
        decisions::{DecisionEvidence, DecisionRecord, DecisionStatus},
        evidence::{Artifact, EvidenceRef, RedactionStatus},
        proofs::{Assertions, CaseStatus, CheckName, ProofResult as CaseResult, Run},
        validation::bounded_vec,
        values::{AuditTime, CatalogId, ContractVersion, Digest, EntityId, Usage, WireInt},
    },
    protocol::error::{ErrorCode, ProofError, ProofResult},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Exit observations, controlled gate fixture, or immutable source bindings are invalid",
    )
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlledKind {
    ControlledGateFixture,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlledGateFixture {
    pub kind: ControlledKind,
    pub source_run_id: EntityId,
    pub run: Run,
    pub selection: CaseSelection,
    #[serde(deserialize_with = "bounded_vec")]
    pub results: Vec<CaseResult>,
    #[serde(deserialize_with = "fixture_bytes")]
    pub manifest_bytes: Vec<u8>,
    pub manifest_sha256: Digest,
    pub artifact: Artifact,
    #[serde(deserialize_with = "fixture_bytes")]
    pub artifact_bytes: Vec<u8>,
    pub review: DecisionRecord,
}
fn fixture_bytes<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    crate::domain::evidence::bounded_vec::<D, u8, 4096>(d)
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlledManifest {
    kind: ControlledKind,
    run_id: EntityId,
    profile_sha256: Digest,
    fixture_manifest_sha256: Digest,
    results_sha256: Digest,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "case_id", deny_unknown_fields)]
enum Report {
    #[serde(rename = "EXIT-01")]
    Provenance {
        schema_version: ContractVersion,
        run_id: EntityId,
        profile_sha256: Digest,
        register: SourceEvidence,
    },
    #[serde(rename = "EXIT-02")]
    Gate {
        schema_version: ContractVersion,
        run_id: EntityId,
        profile_sha256: Digest,
        fixture: Box<ControlledGateFixture>,
    },
}
pub fn execute(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo: &Path,
    case_id: &CatalogId,
) -> ProofResult<CaseObservation> {
    let bytes = host.workspace.read(
        Path::new(crate::application::harness::LIVE_RUN_PATH),
        MAX_METADATA_BYTES,
    )?;
    let run: Run = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    run.validate()?;
    if run.run_id != host.workspace.run_id() || run.profile_sha256 != profile.sha256() {
        return Err(invalid());
    }
    let (observed, report) = match case_id.as_str() {
        "EXIT-01" => {
            let captured = provenance::collect(host, profile, repo, &run)?;
            provenance::verify_report_sources(
                &captured,
                &run,
                profile,
                &host.evidence,
                &host.ledger,
                host.project.project_id,
            )?;
            let register = provenance::publish_register(host, &captured)?;
            (
                provenance_checks()?,
                Report::Provenance {
                    schema_version: ContractVersion::V0_1_0,
                    run_id: run.run_id,
                    profile_sha256: profile.sha256(),
                    register,
                },
            )
        }
        "EXIT-02" => {
            let bytes = provenance::read_repository_file(
                repo,
                "fixtures/scenarios/manifest.json",
                MAX_METADATA_BYTES,
            )?;
            if bytes.len() > MAX_METADATA_BYTES || Digest::of(&bytes) != run.fixture_manifest_sha256
            {
                return Err(invalid());
            }
            let manifest: ScenarioManifest =
                serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            let selection = manifest.select(
                crate::application::cli::Suite::All,
                None,
                run.fixture_manifest_sha256,
            )?;
            let fixture = controlled_fixture(&run, selection, profile)?;
            let checks = evaluate_controlled_fixture(&fixture, profile)?;
            (
                checks,
                Report::Gate {
                    schema_version: ContractVersion::V0_1_0,
                    run_id: run.run_id,
                    profile_sha256: profile.sha256(),
                    fixture: Box::new(fixture),
                },
            )
        }
        _ => return Err(invalid()),
    };
    Ok(CaseObservation {
        case_id: case_id.clone(),
        observed,
        report: serde_json::to_value(report).map_err(|_| invalid())?,
        attachment_paths: Vec::new(),
    })
}
pub fn verify_report(
    result: &CaseResult,
    value: &Value,
    project: EntityId,
    run: &Run,
    profile: &LoadedProfile,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<Assertions> {
    let report = Report::deserialize(value).map_err(|_| invalid())?;
    if result.run_id != run.run_id || run.profile_sha256 != profile.sha256() {
        return Err(invalid());
    }
    match report {
        Report::Provenance {
            run_id,
            profile_sha256,
            register,
            ..
        } => {
            if result.case_id.as_str() != "EXIT-01"
                || run_id != run.run_id
                || profile_sha256 != profile.sha256()
            {
                return Err(invalid());
            }
            let references = register
                .evidence_refs
                .iter()
                .map(|reference| match reference {
                    EvidenceRef::Artifact {
                        artifact_id,
                        range: None,
                        ..
                    } => Ok(*artifact_id),
                    _ => Err(invalid()),
                })
                .collect::<ProofResult<Vec<_>>>()?;
            if references != run.dependency_record_refs {
                return Err(invalid());
            }
            let captured = provenance::read_register(&register, run, evidence, ledger, project)?;
            provenance::verify_report_sources(&captured, run, profile, evidence, ledger, project)?;
            provenance_checks()
        }
        Report::Gate {
            run_id,
            profile_sha256,
            fixture,
            ..
        } => {
            if result.case_id.as_str() != "EXIT-02"
                || run_id != run.run_id
                || profile_sha256 != profile.sha256()
                || fixture.source_run_id != run.run_id
                || fixture.run.run_id == run.run_id
            {
                return Err(invalid());
            }
            evaluate_controlled_fixture(&fixture, profile)
        }
    }
}
fn provenance_checks() -> ProofResult<Assertions> {
    Assertions::new([
        (CheckName::StablePins, true),
        (CheckName::Provenance, true),
        (CheckName::LicensesRecorded, true),
        (CheckName::DecisionsRecorded, true),
        (CheckName::RawMeasurements, true),
    ])
}
/// Deliberately synthetic policy inputs, never publication of an operational packet or a real review.json.
pub fn controlled_fixture(
    source_run: &Run,
    selection: CaseSelection,
    profile: &LoadedProfile,
) -> ProofResult<ControlledGateFixture> {
    selection.validate()?;
    source_run.validate()?;
    if source_run.profile_sha256 != profile.sha256() || selection.selected_case_ids.len() != 35 {
        return Err(invalid());
    }
    let mut run = source_run.clone();
    run.run_id = EntityId::new();
    run.clock_epoch_id = EntityId::new();
    run.finished_at = Some(AuditTime::now());
    let artifact_bytes=b"CONTROLLEDGATEFIXTURE: immutable byte and record-policy consumer probes; no runtime proof".to_vec();
    let artifact = Artifact {
        artifact_id: EntityId::new(),
        project_id: EntityId::new(),
        kind: CatalogId::parse("controlled-gate-fixture")?,
        relative_path: "evidence/controlled-gate-fixture.bin".to_owned(),
        sha256: Digest::of(&artifact_bytes),
        length_bytes: WireInt::new(artifact_bytes.len() as u64)?,
        origin_invocation_id: EntityId::new(),
        redaction_status: RedactionStatus::Original,
    };
    let reference = EvidenceRef::Artifact {
        artifact_id: artifact.artifact_id,
        sha256: artifact.sha256,
        range: None,
    };
    let results = selection
        .inventory
        .cases()
        .iter()
        .map(|case| CaseResult {
            run_id: run.run_id,
            case_id: case.case_id.clone(),
            status: CaseStatus::Passed,
            expected: case.expected.clone(),
            observed: case.expected.clone(),
            evidence_refs: vec![reference],
            elapsed_us: WireInt::ZERO,
            usage: Usage::default(),
            error: None,
        })
        .collect::<Vec<_>>();
    let manifest = ControlledManifest {
        kind: ControlledKind::ControlledGateFixture,
        run_id: run.run_id,
        profile_sha256: profile.sha256(),
        fixture_manifest_sha256: run.fixture_manifest_sha256,
        results_sha256: Digest::of(&serde_json::to_vec(&results).map_err(|_| invalid())?),
    };
    let manifest_bytes = serde_json::to_vec(&manifest).map_err(|_| invalid())?;
    let manifest_sha256 = Digest::of(&manifest_bytes);
    let review = DecisionRecord {
        decision_id: CatalogId::parse("EXIT-REVIEW")?,
        subject: "CONTROLLEDGATEFIXTURE review-policy input".to_owned(),
        decision: "Exercise explicit approval branch on controlled data only".to_owned(),
        rationale:
            "This is a verifier fixture, not a human decision or an approval of the current run"
                .to_owned(),
        alternatives: vec![
            "Pending fixture disposition".to_owned(),
            "Rejected fixture disposition".to_owned(),
        ],
        evidence_refs: vec![
            DecisionEvidence::RunManifest {
                run_id: run.run_id,
                sha256: manifest_sha256,
            },
            DecisionEvidence::Evidence { reference },
        ],
        status: DecisionStatus::Approved,
        reviewer: "CONTROLLEDGATEFIXTURE (not a maintainer)".to_owned(),
        reviewed_at: AuditTime::now(),
    };
    Ok(ControlledGateFixture {
        kind: ControlledKind::ControlledGateFixture,
        source_run_id: source_run.run_id,
        run,
        selection,
        results,
        manifest_bytes,
        manifest_sha256,
        artifact,
        artifact_bytes,
        review,
    })
}
pub fn evaluate_controlled_fixture(
    fixture: &ControlledGateFixture,
    profile: &LoadedProfile,
) -> ProofResult<Assertions> {
    if fixture.source_run_id == fixture.run.run_id
        || fixture.manifest_bytes.len() > 4096
        || Digest::of(&fixture.manifest_bytes) != fixture.manifest_sha256
    {
        return Err(invalid());
    }
    let manifest: ControlledManifest =
        serde_json::from_slice(&fixture.manifest_bytes).map_err(|_| invalid())?;
    if manifest.run_id != fixture.run.run_id
        || manifest.profile_sha256 != profile.sha256()
        || manifest.fixture_manifest_sha256 != fixture.run.fixture_manifest_sha256
        || manifest.results_sha256
            != Digest::of(&serde_json::to_vec(&fixture.results).map_err(|_| invalid())?)
    {
        return Err(invalid());
    }
    fixture
        .artifact
        .validate_bytes(fixture.artifact.project_id, &fixture.artifact_bytes)?;
    let reference = EvidenceRef::Artifact {
        artifact_id: fixture.artifact.artifact_id,
        sha256: fixture.artifact.sha256,
        range: None,
    };
    reference.validate_artifact(
        fixture.artifact.project_id,
        &fixture.artifact,
        &fixture.artifact_bytes,
    )?;
    let baseline =
        inventory::evaluate(&fixture.selection, &fixture.run, &fixture.results, profile)?;
    let complete = baseline.counts.total.get() == 35
        && baseline.counts.passed.get() == 35
        && baseline.full_status == CommandStatus::Passed;
    if !complete {
        return Err(invalid());
    }
    let required = [reference];
    let context = ReviewContext {
        run: &fixture.run,
        manifest_sha256: fixture.manifest_sha256,
        profile,
        gate: &baseline,
        required_evidence: &required,
        now: fixture.review.reviewed_at,
    };
    let unreviewed = review::assess(&context, None)?;
    let approved = review::assess(&context, Some(&fixture.review))?;
    let mut approval_required = unreviewed.review_status == ReviewStatus::Unreviewed
        && !unreviewed.r0_exit_ready
        && approved.review_status == ReviewStatus::Approved
        && approved.r0_exit_ready;
    for status in [
        DecisionStatus::Recorded,
        DecisionStatus::Pending,
        DecisionStatus::Blocked,
        DecisionStatus::Rejected,
    ] {
        let mut decision = fixture.review.clone();
        decision.status = status;
        let assessed = review::assess(&context, Some(&decision))?;
        approval_required &= !assessed.r0_exit_ready
            && assessed.review_status
                == if status == DecisionStatus::Rejected {
                    ReviewStatus::Rejected
                } else {
                    ReviewStatus::Unreviewed
                };
    }
    let mut stale = fixture.review.clone();
    stale.evidence_refs[0] = DecisionEvidence::RunManifest {
        run_id: fixture.run.run_id,
        sha256: Digest::of(b"changed controlled manifest"),
    };
    approval_required &= !review::assess(&context, Some(&stale))?.r0_exit_ready;
    let mut results = fixture
        .results
        .iter()
        .map(|result| CaseResult {
            run_id: result.run_id,
            case_id: result.case_id.clone(),
            status: result.status,
            expected: result.expected.clone(),
            observed: result.observed.clone(),
            evidence_refs: result.evidence_refs.clone(),
            elapsed_us: result.elapsed_us,
            usage: result.usage,
            error: result.error.clone(),
        })
        .collect::<Vec<_>>();
    let mut failure_blocks = true;
    for status in [
        CaseStatus::Failed,
        CaseStatus::Blocked,
        CaseStatus::Unexecuted,
    ] {
        results[0].status = status;
        let gate = inventory::evaluate(&fixture.selection, &fixture.run, &results, profile)?;
        let context = ReviewContext {
            gate: &gate,
            ..context
        };
        failure_blocks &= gate.full_status != CommandStatus::Passed
            && !review::assess(&context, Some(&fixture.review))?.r0_exit_ready;
    }
    results[0].status = CaseStatus::Passed;
    let partial = CaseSelection {
        schema_version: fixture.selection.schema_version,
        fixture_catalog: fixture.selection.fixture_catalog.clone(),
        fixture_manifest_sha256: fixture.selection.fixture_manifest_sha256,
        inventory: crate::domain::proofs::ProofInventory::new(
            fixture.selection.inventory.packages().to_vec(),
            fixture.selection.inventory.cases().to_vec(),
        )?,
        selected_case_ids: fixture
            .selection
            .selected_case_ids
            .iter()
            .filter(|id| id.as_str().starts_with("CON-"))
            .cloned()
            .collect(),
    };
    for result in &mut results {
        if !result.case_id.as_str().starts_with("CON-") {
            result.status = CaseStatus::Unexecuted;
            result.observed = Assertions::new([])?;
            result.evidence_refs.clear();
        }
    }
    let gate = inventory::evaluate(&partial, &fixture.run, &results, profile)?;
    failure_blocks &= gate.selected_status == CommandStatus::Passed
        && gate.full_status == CommandStatus::Incomplete
        && gate.counts.passed.get() == 5
        && gate.counts.unexecuted.get() == 30;
    let mut changed = fixture.artifact_bytes.clone();
    let changed_bytes = if let Some(first) = changed.first_mut() {
        *first ^= 1;
        changed.as_slice()
    } else {
        &[1]
    };
    let changed_rejected = fixture
        .artifact
        .validate_bytes(fixture.artifact.project_id, changed_bytes)
        .is_err();
    let mut unsafe_path = fixture.artifact.clone();
    unsafe_path.relative_path = "../outside".to_owned();
    let path_rejected = unsafe_path
        .validate_bytes(fixture.artifact.project_id, &fixture.artifact_bytes)
        .is_err();
    let foreign_rejected = reference
        .validate_artifact(EntityId::new(), &fixture.artifact, &fixture.artifact_bytes)
        .is_err();
    let r0_only = fixture.selection.inventory.packages().len() == 5
        && fixture.selection.inventory.cases().len() == 35
        && fixture.run.run_id != fixture.source_run_id;
    Assertions::new([
        (CheckName::CompleteInventory, complete),
        (
            CheckName::PacketIntegrity,
            changed_rejected && path_rejected && foreign_rejected,
        ),
        (CheckName::FailureBlocksExit, failure_blocks),
        (CheckName::ApprovalRequired, approval_required),
        (CheckName::R0Only, r0_only),
    ])
}

/// The register chunks contain DependencyRecord values; their actual canonical artifact IDs bind Run.
pub fn dependency_record_refs(value: &Value) -> ProofResult<Vec<EntityId>> {
    let report = Report::deserialize(value).map_err(|_| invalid())?;
    let Report::Provenance { register, .. } = report else {
        return Err(invalid());
    };
    register
        .evidence_refs
        .iter()
        .map(|reference| match reference {
            EvidenceRef::Artifact {
                artifact_id,
                range: None,
                ..
            } => Ok(*artifact_id),
            _ => Err(invalid()),
        })
        .collect()
}
