//! Operational REC drivers and immutable, read-only canonical fact verification.
//! REC-03 kills the actual ledger-owning engine worker after its completion commit.
//! A separate controlled run adds an unchanged native SDK message/opaque-binding
//! epoch-denial exercise. Its controller host closes normally; it never substitutes
//! for the crash seam. Lease JSON is audit metadata, not transferable authority.
//! A fresh approved SDK GET proves channel recovery without replaying either POST.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::CaseObservation;
use crate::adapters::evidence_store::EvidenceStore;
use crate::adapters::ledger::Ledger;
use crate::adapters::workspace::OwnedDirectory;
use crate::application::profile::LoadedProfile;
use crate::application::proof_host::ProofHost;
use crate::application::recovery::{RecoveryPrograms, RecoveryReport, run_fixture, verify_saved};
use crate::domain::proofs::{Assertions, CheckName, Run};
use crate::domain::values::{CatalogId, Digest, EntityId};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    project_id: EntityId,
    run_id: EntityId,
    scenario_root: PathBuf,
    facts: RecoveryReport,
    facts_sha256: Digest,
}

fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Recovery report lacks canonical owned factual evidence",
    )
}

pub fn execute(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo_root: &Path,
    case_id: &CatalogId,
) -> ProofResult<CaseObservation> {
    let engine = std::env::current_exe().map_err(|_| invalid())?;
    if engine.file_name().and_then(|name| name.to_str()) != Some("razen-engine") {
        return Err(invalid());
    }
    let receiver = engine
        .parent()
        .ok_or_else(invalid)?
        .join("razen-fixture-receiver");
    let relative = PathBuf::from(format!("recovery-{}", case_id.as_str()));
    let workspace = Arc::new(OwnedDirectory::create(
        host.workspace.path(),
        &relative,
        EntityId::new(),
    )?);
    let facts = run_fixture(
        &workspace,
        profile,
        repo_root,
        &RecoveryPrograms { engine, receiver },
        case_id,
    )?;
    if facts.engine_sha256 != host.provider_digest {
        return Err(invalid());
    }
    let bytes = workspace.read(Path::new("recovery-facts.json"), 4 * 1024 * 1024)?;
    let observed = assertions(&facts)?;
    let report = Report {
        project_id: host.project.project_id,
        run_id: host.workspace.run_id(),
        scenario_root: relative.clone(),
        facts,
        facts_sha256: Digest::of(&bytes),
    };
    Ok(CaseObservation {
        case_id: case_id.clone(),
        observed,
        report: serde_json::to_value(report).map_err(|_| invalid())?,
        attachment_paths: vec![relative.join("recovery-facts.json")],
    })
}

pub fn verify_report(
    result: &crate::domain::proofs::ProofResult,
    report: &Value,
    project: EntityId,
    run: &Run,
    profile: &LoadedProfile,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<Assertions> {
    let bytes = serde_json::to_vec(report).map_err(|_| invalid())?;
    if bytes.len()
        > profile
            .config()
            .protocol
            .invocation_output_limit_bytes
            .get() as usize
    {
        return Err(invalid());
    }
    let report: Report = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if report.project_id != project
        || report.run_id != run.run_id
        || run.run_id != ledger.run_id()
        || result.run_id != run.run_id
        || result.case_id != report.facts.case_id
        || report.facts.profile_sha256 != profile.sha256()
        || run.profile_sha256 != profile.sha256()
        || report.scenario_root != format!("recovery-{}", result.case_id.as_str())
        || run
            .environment
            .binary_digests
            .get(&CatalogId::parse("razen-engine")?)
            != Some(&report.facts.engine_sha256)
        || run
            .environment
            .binary_digests
            .get(&CatalogId::parse("razen-fixture-receiver")?)
            != Some(&report.facts.receiver_sha256)
        || run
            .environment
            .fixture_digests
            .get(&CatalogId::parse("recovery-scenarios")?)
            != Some(&report.facts.fixture_sha256)
    {
        return Err(invalid());
    }
    // EvidenceStore's existing owned workspace is the only path root. It is never
    // inferred from serialized absolute paths or a report-provided host directory.
    let root = evidence.workspace();
    let workspace = OwnedDirectory::open(root.path(), &report.scenario_root)?;
    let saved = workspace.read(Path::new("recovery-facts.json"), 4 * 1024 * 1024)?;
    if Digest::of(&saved) != report.facts_sha256
        || serde_json::from_slice::<Value>(&saved).map_err(|_| invalid())?
            != serde_json::to_value(&report.facts).map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    verify_saved(&workspace, profile, &report.facts)?;
    assertions(&report.facts)
}

fn assertions(facts: &RecoveryReport) -> ProofResult<Assertions> {
    facts.validate()?;
    use CheckName::*;
    let checks: &[CheckName] = match facts.case_id.as_str() {
        "REC-01" => &[
            ReservationSeams,
            ConsumptionPreserved,
            ReservationReconciled,
            ZeroResends,
        ],
        "REC-02" => &[
            SendingSeams,
            UnknownRestored,
            ConsumptionPreserved,
            ReadOnlyReconciliation,
            ZeroResends,
        ],
        "REC-03" => &[
            CompletionRestored,
            EventsDeduplicated,
            ConsumptionPreserved,
            ZeroResends,
        ],
        "REC-04" => &[CurrentAuthority, CurrentVersions, StaleWorkDenied],
        "REC-05" => &[StorageFaults, AdmissionClosed, PartialEvidence, ZeroResends],
        _ => return Err(invalid()),
    };
    // Validation above independently derives each case's required invariants from
    // actual canonical histories/counters/errors. No incoming assertion map is used.
    Assertions::new(checks.iter().copied().map(|name| (name, true)))
}
