//! Immutable post-engine publication and bounded, read-only packet inspection.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::Arc;

use rustix::fs::{self, AtFlags, Dir, FileType, Mode, OFlags};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use super::cli::Suite;
use super::harness::{
    CaseSelection, CommandStatus, Counts, EngineBootstrap, EngineOutcome, MAX_METADATA_BYTES,
    MAX_TRACE_BYTES, PacketVerdict, ReviewStatus, ScenarioManifest, TRACE_PATH,
};
use super::parser_fuzz::{FuzzReport, FuzzTarget};
use super::profile::LoadedProfile;
use crate::adapters::evidence_store::EvidenceStore;
use crate::adapters::ledger::{Ledger, StoredInvocation};
use crate::adapters::workspace::OwnedDirectory;
use crate::domain::authority::Budget;
use crate::domain::evidence::{Artifact, EvidenceRef, MAX_CHUNK_BYTES};
use crate::domain::execution::Event;
use crate::domain::knowledge::{
    AssetGraph, InvestigationGraph, InvestigationSession, MemoryItem, MemoryLevel, Trace,
    WorkflowDefinition, validate_example_links,
};
use crate::domain::proofs::{
    Assertions, CaseStatus, CheckName, PackageStatus, ProofResult as CaseResult, Run,
    RunEnvironment,
};
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, InvocationState, WireInt,
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

// Seal the full run's separate artifact bodies, catalog records and recovery files.
const MAX_FILES: usize = 16_384;
const MAX_DEPTH: usize = 32;
const MAX_PACKET_BYTES: u64 = 512 * 1024 * 1024;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const FILE_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
const PUBLISHED: &[&str] = &[
    "run.json",
    "versions.json",
    "results.json",
    "trace.jsonl",
    "exit.json",
];

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileSeal {
    path: String,
    sha256: Digest,
    length_bytes: WireInt,
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: ContractVersion,
    run_id: EntityId,
    bootstrap: EngineBootstrap,
    files: Vec<FileSeal>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Versions {
    schema_version: ContractVersion,
    profile_sha256: Digest,
    selected_profile_ref: String,
    observed: RunEnvironment,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Exit {
    schema_version: ContractVersion,
    run_id: EntityId,
    counts: Counts,
    selected_status: CommandStatus,
    full_status: CommandStatus,
    review_status: ReviewStatus,
    r0_exit_ready: bool,
    interrupted: bool,
    #[serde(
        default,
        deserialize_with = "crate::domain::values::non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    error: Option<ProofError>,
    trace_sha256: Digest,
    trace_length_bytes: WireInt,
}

/// Caller must first reap the engine process and join its control resources.
/// The read-only ledger lease independently refuses a still-live writer.
pub fn publish(
    workspace: &OwnedDirectory,
    bootstrap: &EngineBootstrap,
    selection: &CaseSelection,
    outcome: &EngineOutcome,
) -> ProofResult<PacketVerdict> {
    let initial = scan(workspace)?;
    if PUBLISHED
        .iter()
        .any(|path| initial.iter().any(|file| file.path == *path))
        || exists(workspace, "manifest.json")?
        || exists(workspace, "review.json")?
    {
        return Err(integrity());
    }
    let profile = load_profile(workspace)?;
    validate_snapshots(workspace, bootstrap, selection, outcome, &profile)?;
    let trace = workspace.read(Path::new(TRACE_PATH), MAX_TRACE_BYTES)?;
    let ledger = Ledger::open_readonly(workspace, &profile)?;
    validate_proof(
        workspace,
        &initial,
        &ValidationContext {
            bootstrap,
            selection,
            outcome,
            profile: &profile,
        },
        &trace,
        &ledger,
    )?;
    let verdict = verdict(selection, outcome, &profile)?;
    let versions = Versions {
        schema_version: ContractVersion::V0_1_0,
        profile_sha256: profile.sha256(),
        selected_profile_ref: "profile.json".to_owned(),
        observed: outcome.run.environment.clone(),
    };
    let exit = exit_record(outcome, &verdict);
    write_json(workspace, "run.json", &outcome.run)?;
    write_json(workspace, "versions.json", &versions)?;
    write_json(workspace, "results.json", &outcome.results)?;
    workspace.write_new(Path::new("trace.jsonl"), &trace)?;
    write_json(workspace, "exit.json", &exit)?;
    let files = scan(workspace)?;
    // Publication cannot quietly absorb a changed preexisting input/evidence file.
    for previous in &initial {
        if files.iter().find(|file| file.path == previous.path) != Some(previous) {
            return Err(integrity());
        }
    }
    if files.len() != initial.len() + PUBLISHED.len() {
        return Err(integrity());
    }
    let manifest = Manifest {
        schema_version: ContractVersion::V0_1_0,
        run_id: workspace.run_id(),
        bootstrap: bootstrap.clone(),
        files,
    };
    write_json(workspace, "manifest.json", &manifest)?;
    let manifest_sha256 =
        Digest::of(&workspace.read(Path::new("manifest.json"), MAX_METADATA_BYTES)?);
    assess_review(
        workspace,
        selection,
        outcome,
        &profile,
        manifest_sha256,
        verdict,
    )
}

/// No reruns, reconstruction, migrations, package work, or missing-layout repair.
pub fn verify(workspace: &OwnedDirectory) -> ProofResult<PacketVerdict> {
    let manifest_bytes = workspace.read(Path::new("manifest.json"), MAX_METADATA_BYTES)?;
    let manifest: Manifest = decode(&manifest_bytes)?;
    let files = scan(workspace)?;
    if manifest.schema_version != ContractVersion::V0_1_0
        || manifest.run_id != workspace.run_id()
        || manifest.files != files
    {
        return Err(integrity());
    }
    let profile = load_profile(workspace)?;
    let selection: CaseSelection = read_json(workspace, "cases.json")?;
    let run: Run = read_json(workspace, "run.json")?;
    let results: Vec<CaseResult> = read_json(workspace, "results.json")?;
    let exit: Exit = read_json(workspace, "exit.json")?;
    let versions: Versions = read_json(workspace, "versions.json")?;
    let outcome = EngineOutcome {
        schema_version: ContractVersion::V0_1_0,
        run,
        results,
        trace_sha256: exit.trace_sha256,
        trace_length_bytes: exit.trace_length_bytes,
        interrupted: exit.interrupted,
        error: exit.error.clone(),
    };
    validate_snapshots(
        workspace,
        &manifest.bootstrap,
        &selection,
        &outcome,
        &profile,
    )?;
    if versions.schema_version != ContractVersion::V0_1_0
        || versions.profile_sha256 != profile.sha256()
        || versions.selected_profile_ref != "profile.json"
        || versions.observed != outcome.run.environment
    {
        return Err(integrity());
    }
    let trace = workspace.read(Path::new("trace.jsonl"), MAX_TRACE_BYTES)?;
    let ledger = Ledger::open_readonly(workspace, &profile)?;
    validate_proof(
        workspace,
        &files,
        &ValidationContext {
            bootstrap: &manifest.bootstrap,
            selection: &selection,
            outcome: &outcome,
            profile: &profile,
        },
        &trace,
        &ledger,
    )?;
    let verdict = verdict(&selection, &outcome, &profile)?;
    if encode(&exit)? != encode(&exit_record(&outcome, &verdict))? || scan(workspace)? != files {
        return Err(integrity());
    }
    let assessed = assess_review(
        workspace,
        &selection,
        &outcome,
        &profile,
        Digest::of(&manifest_bytes),
        verdict,
    )?;
    if scan(workspace)? != files
        || workspace.read(Path::new("manifest.json"), MAX_METADATA_BYTES)? != manifest_bytes
    {
        return Err(integrity());
    }
    Ok(assessed)
}

fn load_profile(workspace: &OwnedDirectory) -> ProofResult<LoadedProfile> {
    LoadedProfile::from_bytes(&workspace.read(Path::new("profile.json"), MAX_METADATA_BYTES)?)
}

fn validate_snapshots(
    workspace: &OwnedDirectory,
    bootstrap: &EngineBootstrap,
    selection: &CaseSelection,
    outcome: &EngineOutcome,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    if bootstrap.schema_version != ContractVersion::V0_1_0
        || outcome.schema_version != ContractVersion::V0_1_0
        || selection.schema_version != ContractVersion::V0_1_0
        || bootstrap.run_id != workspace.run_id()
        || outcome.run.finished_at.is_none()
    {
        return Err(integrity());
    }
    outcome.validate(bootstrap, selection, profile)?;
    let actual_selection: CaseSelection = read_json(workspace, "cases.json")?;
    if encode(&actual_selection)? != encode(selection)? {
        return Err(integrity());
    }
    let raw = workspace.read(Path::new("fixture-manifest.json"), MAX_METADATA_BYTES)?;
    if Digest::of(&raw) != bootstrap.fixture_manifest_sha256 {
        return Err(integrity());
    }
    let source: ScenarioManifest = decode(&raw)?;
    let full = source.select(Suite::All, None, Digest::of(&raw))?;
    if full.schema_version != selection.schema_version
        || full.fixture_catalog != selection.fixture_catalog
        || encode(&full.inventory)? != encode(&selection.inventory)?
    {
        return Err(integrity());
    }
    let environment = &outcome.run.environment;
    for (key, expected) in [
        ("pilot-profile", profile.sha256()),
        ("scenario-manifest", bootstrap.fixture_manifest_sha256),
        ("contract-scenarios", bootstrap.contract_examples_sha256),
    ] {
        if environment.fixture_digests.get(&CatalogId::parse(key)?) != Some(&expected) {
            return Err(integrity());
        }
    }
    super::inventory::validate_selected_environment(selection, &outcome.run, profile)?;
    if environment
        .binary_digests
        .get(&CatalogId::parse("razen-proof")?)
        != Some(&bootstrap.orchestrator_sha256)
    {
        return Err(integrity());
    }
    Ok(())
}

struct ValidationContext<'a> {
    bootstrap: &'a EngineBootstrap,
    selection: &'a CaseSelection,
    outcome: &'a EngineOutcome,
    profile: &'a LoadedProfile,
}

fn validate_proof(
    workspace: &OwnedDirectory,
    files: &[FileSeal],
    context: &ValidationContext<'_>,
    trace: &[u8],
    ledger: &Ledger,
) -> ProofResult<()> {
    let &ValidationContext {
        selection,
        outcome,
        profile,
        ..
    } = context;
    if outcome.run.dependency_record_refs.len() > 16 {
        return Err(integrity());
    }
    for required in [
        ".razen-run.json",
        "profile.json",
        "fixture-manifest.json",
        "cases.json",
        "ledger.sqlite",
        "ledger.lock",
        "evidence/store.json",
        "evidence/.writer",
    ] {
        if !files.iter().any(|file| file.path == required) {
            return Err(integrity());
        }
    }
    if trace.len() as u64 != outcome.trace_length_bytes.get()
        || Digest::of(trace) != outcome.trace_sha256
    {
        return Err(integrity());
    }
    // Both adapters open only existing descriptors and hold shared native leases.
    let path = workspace.path();
    let owner = Arc::new(OwnedDirectory::open(
        path.parent().ok_or_else(integrity)?,
        Path::new(path.file_name().ok_or_else(integrity)?),
    )?);
    if owner.run_id() != workspace.run_id() {
        return Err(integrity());
    }
    let evidence = EvidenceStore::open_readonly(owner)?;
    let invocations = ledger.invocations()?;
    let by_id: BTreeMap<_, _> = invocations
        .iter()
        .map(|stored| (stored.invocation.invocation_id, stored))
        .collect();
    if by_id.len() != invocations.len() {
        return Err(integrity());
    }
    validate_quotas(ledger, &invocations)?;
    let artifacts = evidence.artifacts()?;
    let by_artifact: BTreeMap<_, _> = artifacts
        .iter()
        .map(|artifact| (artifact.artifact_id, artifact.as_ref()))
        .collect();
    for reference in &outcome.run.dependency_record_refs {
        let artifact = by_artifact.get(reference).ok_or_else(integrity)?;
        evidence.verify_artifact(artifact.project_id, *reference)?;
    }
    validate_trace(trace, ledger, outcome, &by_id, &by_artifact)?;
    for artifact in &artifacts {
        let origin = by_id
            .get(&artifact.origin_invocation_id)
            .ok_or_else(integrity)?;
        if origin.invocation.run_id != workspace.run_id()
            || origin.invocation.project_id != artifact.project_id
        {
            return Err(integrity());
        }
        evidence.verify_artifact(artifact.project_id, artifact.artifact_id)?;
    }
    // No extra uncommitted bodies may masquerade as catalogued proof data.
    let bodies: BTreeSet<_> = artifacts
        .iter()
        .map(|artifact| artifact.relative_path.as_str())
        .collect();
    if files
        .iter()
        .filter(|file| file.path.starts_with("evidence/bodies/"))
        .any(|file| !bodies.contains(file.path.as_str()))
    {
        return Err(integrity());
    }
    for stored in &invocations {
        validate_invocation(stored, &by_artifact, &evidence, outcome, ledger)?;
    }
    let sessions: BTreeSet<_> = invocations
        .iter()
        .map(|stored| stored.invocation.session_id)
        .collect();
    for id in sessions {
        let session = ledger.read_session(id)?;
        for reference in &session.session.evidence_refs {
            resolve(&evidence, session.project_id, reference)?;
        }
    }
    for snapshot in evidence.snapshots()? {
        let bytes = snapshot_bytes(
            &evidence,
            snapshot.project_id,
            snapshot.snapshot_id,
            snapshot.revision,
        )?;
        snapshot.validate_bytes(snapshot.project_id, snapshot.revision, &bytes)?;
    }
    let projects: BTreeSet<_> = artifacts
        .iter()
        .map(|artifact| artifact.project_id)
        .collect();
    for project in projects {
        for proposal in evidence.proposals(project)? {
            for reference in &proposal.evidence_refs {
                resolve(&evidence, project, reference)?;
            }
        }
    }
    let gate = super::inventory::evaluate(selection, &outcome.run, &outcome.results, profile)?;
    if gate.full_status == CommandStatus::Passed && outcome.run.dependency_record_refs.is_empty() {
        return Err(integrity());
    }
    let mut used = BTreeSet::new();
    for result in &outcome.results {
        let case = selection
            .inventory
            .cases()
            .iter()
            .find(|case| case.case_id == result.case_id)
            .ok_or_else(integrity)?;
        let package = selection
            .inventory
            .packages()
            .iter()
            .find(|package| package.package_id == case.package_id)
            .ok_or_else(integrity)?;
        if result.status == CaseStatus::Passed || result.observed.iter().next().is_some() {
            for prerequisite in &package.requires {
                let index = gate
                    .package_order
                    .iter()
                    .position(|package| package.package_id == *prerequisite)
                    .ok_or_else(integrity)?;
                if gate.package_statuses[index] != PackageStatus::Passed {
                    return Err(integrity());
                }
            }
        }
        validate_result(
            result,
            context,
            &by_id,
            &by_artifact,
            &evidence,
            ledger,
            &mut used,
        )?;
    }
    for stored in invocations
        .iter()
        .filter(|stored| stored.invocation.tool_id.as_str() == "proof.case.execute")
    {
        let invocation = &stored.invocation;
        if invocation.state == InvocationState::Completed
            && !used.contains(&invocation.invocation_id)
        {
            return Err(integrity());
        }
    }
    validate_campaigns(workspace, files, outcome, profile, &evidence)?;
    Ok(())
}

fn validate_quotas(ledger: &Ledger, invocations: &[StoredInvocation]) -> ProofResult<()> {
    let budgets = ledger.budgets()?;
    let by_id: BTreeMap<_, _> = budgets
        .iter()
        .map(|budget| (budget.budget_id, budget))
        .collect();
    let mut roots = budgets
        .iter()
        .filter(|budget| budget.parent_budget_id.is_none());
    if by_id.len() != budgets.len()
        || roots.next().is_none_or(|root| root.limit.get() != 4096)
        || roots.next().is_some()
    {
        return Err(integrity());
    }
    let mut consumed = BTreeMap::<EntityId, WireInt>::new();
    let mut holds = BTreeMap::<EntityId, WireInt>::new();
    for stored in invocations {
        let invocation = &stored.invocation;
        let hold = holds.entry(invocation.budget_id).or_insert(WireInt::ZERO);
        *hold = hold.checked_add(stored.reserved_units)?;
        let settled = matches!(
            invocation.state,
            InvocationState::Completed | InvocationState::Failed | InvocationState::Cancelled
        );
        let mut next = Some(invocation.budget_id);
        let mut seen = BTreeSet::new();
        while let Some(id) = next {
            if seen.len() >= MAX_DEPTH || !seen.insert(id) {
                return Err(integrity());
            }
            let budget = by_id.get(&id).ok_or_else(integrity)?;
            if settled {
                let total = consumed.entry(id).or_insert(WireInt::ZERO);
                *total = total.checked_add(invocation.usage.units)?;
            }
            next = budget.parent_budget_id;
        }
    }
    for budget in &budgets {
        let mut reserved = holds
            .get(&budget.budget_id)
            .copied()
            .unwrap_or(WireInt::ZERO);
        for child in budgets
            .iter()
            .filter(|child| child.parent_budget_id == Some(budget.budget_id))
        {
            reserved = reserved.checked_add(child.limit.checked_sub(child.consumed)?)?;
        }
        if budget.consumed
            != consumed
                .get(&budget.budget_id)
                .copied()
                .unwrap_or(WireInt::ZERO)
            || budget.reserved != reserved
        {
            return Err(integrity());
        }
    }
    Ok(())
}

fn validate_invocation(
    stored: &StoredInvocation,
    artifacts: &BTreeMap<EntityId, &Artifact>,
    evidence: &EvidenceStore,
    outcome: &EngineOutcome,
    ledger: &Ledger,
) -> ProofResult<()> {
    let invocation = &stored.invocation;
    invocation.validate(Some(&stored.history))?;
    if stored.history.last() != invocation
        || invocation.run_id != outcome.run.run_id
        || outcome
            .run
            .environment
            .binary_digests
            .get(&CatalogId::parse("razen-engine")?)
            != Some(&invocation.provider_digest)
    {
        return Err(integrity());
    }
    let input = artifacts.get(&invocation.input_ref).ok_or_else(integrity)?;
    if input.project_id != invocation.project_id
        || input.sha256 != invocation.input_sha256
        || input.origin_invocation_id != invocation.invocation_id
    {
        return Err(integrity());
    }
    if let Some(id) = invocation.output_ref {
        let output = artifacts.get(&id).ok_or_else(integrity)?;
        if output.project_id != invocation.project_id
            || output.origin_invocation_id != invocation.invocation_id
        {
            return Err(integrity());
        }
        evidence.verify_artifact(output.project_id, id)?;
    }
    let project = ledger.read_project(invocation.project_id)?;
    let control = ledger.read_control(invocation.investigation_id)?;
    let instruction = artifacts
        .get(&control.instruction_ref)
        .ok_or_else(integrity)?;
    if instruction.project_id != project.project_id {
        return Err(integrity());
    }
    Ok(())
}

fn validate_partial_result(
    result: &CaseResult,
    context: &ValidationContext<'_>,
    invocations: &BTreeMap<EntityId, &StoredInvocation>,
    artifacts: &BTreeMap<EntityId, &Artifact>,
    evidence: &EvidenceStore,
    used: &mut BTreeSet<EntityId>,
) -> ProofResult<()> {
    let &ValidationContext {
        outcome,
        profile,
        bootstrap,
        ..
    } = context;
    let error = result.error.as_ref().ok_or_else(integrity)?;
    let Some(id) = error.invocation_id else {
        if !zero_usage(result) || !result.evidence_refs.is_empty() {
            return Err(integrity());
        }
        return Ok(());
    };
    let stored = invocations.get(&id).ok_or_else(integrity)?;
    let invocation = &stored.invocation;
    if invocation.tool_id.as_str() != "proof.case.execute"
        || invocation.state == InvocationState::Completed
        || invocation.usage != result.usage
        || !used.insert(id)
    {
        return Err(integrity());
    }
    if invocation.error.as_ref() != Some(error)
        && !(outcome.error.as_ref() == Some(error)
            && matches!(
                error.code,
                ErrorCode::IntegrityError | ErrorCode::OutcomeUnknown
            )
            && matches!(
                invocation.state,
                InvocationState::Sending | InvocationState::OutcomeUnknown
            ))
    {
        return Err(integrity());
    }
    let input: Value = decode(&evidence.read_artifact(
        invocation.project_id,
        invocation.input_ref,
        MAX_METADATA_BYTES,
    )?)?;
    if input["case_id"] != serde_json::to_value(&result.case_id).map_err(|_| integrity())?
        || input["profile_sha256"]
            != serde_json::to_value(profile.sha256()).map_err(|_| integrity())?
        || input["fixture_manifest_sha256"]
            != serde_json::to_value(bootstrap.fixture_manifest_sha256).map_err(|_| integrity())?
    {
        return Err(integrity());
    }
    let mut ids = BTreeSet::new();
    for reference in &result.evidence_refs {
        let EvidenceRef::Artifact {
            artifact_id,
            range: None,
            ..
        } = reference
        else {
            return Err(integrity());
        };
        let artifact = artifacts.get(artifact_id).ok_or_else(integrity)?;
        if artifact.origin_invocation_id != id || !ids.insert(*artifact_id) {
            return Err(integrity());
        }
        resolve(evidence, invocation.project_id, reference)?;
    }
    let actual: BTreeSet<_> = artifacts
        .values()
        .filter(|artifact| artifact.origin_invocation_id == id)
        .map(|artifact| artifact.artifact_id)
        .collect();
    if ids != actual {
        return Err(integrity());
    }
    Ok(())
}

fn validate_result(
    result: &CaseResult,
    context: &ValidationContext<'_>,
    invocations: &BTreeMap<EntityId, &StoredInvocation>,
    artifacts: &BTreeMap<EntityId, &Artifact>,
    evidence: &EvidenceStore,
    ledger: &Ledger,
    used: &mut BTreeSet<EntityId>,
) -> ProofResult<()> {
    let &ValidationContext {
        outcome,
        bootstrap,
        selection,
        profile,
    } = context;
    if result.status == CaseStatus::Unexecuted {
        if result.observed.iter().next().is_some()
            || !result.evidence_refs.is_empty()
            || result.error.is_some()
            || !zero_usage(result)
        {
            return Err(integrity());
        }
        return Ok(());
    }
    if !selection.selected_case_ids.contains(&result.case_id)
        || result.elapsed_us != result.usage.elapsed_us
    {
        return Err(integrity());
    }
    if result.observed.iter().next().is_none() && result.status != CaseStatus::Passed {
        return validate_partial_result(result, context, invocations, artifacts, evidence, used);
    }
    let first = result.evidence_refs.first().ok_or_else(integrity)?;
    let EvidenceRef::Artifact {
        artifact_id,
        range: None,
        ..
    } = first
    else {
        return Err(integrity());
    };
    let report_artifact = artifacts.get(artifact_id).ok_or_else(integrity)?;
    let stored = invocations
        .get(&report_artifact.origin_invocation_id)
        .ok_or_else(integrity)?;
    let invocation = &stored.invocation;
    if invocation.tool_id.as_str() != "proof.case.execute"
        || invocation.state != InvocationState::Completed
        || invocation.output_ref != Some(*artifact_id)
        || invocation.usage != result.usage
        || stored.reserved_units != WireInt::ZERO
        || !used.insert(invocation.invocation_id)
        || report_artifact.kind.as_str() != "case-execution-report"
    {
        return Err(integrity());
    }
    let input: Value = decode(&evidence.read_artifact(
        invocation.project_id,
        invocation.input_ref,
        MAX_METADATA_BYTES,
    )?)?;
    for (field, expected) in [
        (
            "schema_version",
            serde_json::to_value(ContractVersion::V0_1_0),
        ),
        (
            "profile_id",
            serde_json::to_value(&profile.config().profile_id),
        ),
        ("case_id", serde_json::to_value(&result.case_id)),
        ("profile_sha256", serde_json::to_value(profile.sha256())),
        (
            "fixture_manifest_sha256",
            serde_json::to_value(bootstrap.fixture_manifest_sha256),
        ),
        (
            "invocation_id",
            serde_json::to_value(invocation.invocation_id),
        ),
        ("project_id", serde_json::to_value(invocation.project_id)),
        ("actor_ref", serde_json::to_value(invocation.actor_ref)),
        ("session_id", serde_json::to_value(invocation.session_id)),
        ("identity_id", serde_json::to_value(invocation.identity_id)),
        ("budget_id", serde_json::to_value(invocation.budget_id)),
        (
            "investigation_id",
            serde_json::to_value(invocation.investigation_id),
        ),
        (
            "provider_digest",
            serde_json::to_value(invocation.provider_digest),
        ),
        (
            "scope_revision",
            serde_json::to_value(invocation.scope_revision),
        ),
        (
            "control_revision",
            serde_json::to_value(invocation.control_revision),
        ),
    ] {
        if input.get(field) != Some(&expected.map_err(|_| integrity())?) {
            return Err(integrity());
        }
    }
    let all_observed = result.observed.iter().count() == result.expected.iter().count()
        && result
            .expected
            .iter()
            .all(|(name, value)| result.observed.get(name) == Some(value));
    if (result.status == CaseStatus::Passed) != all_observed
        || result.status == CaseStatus::Blocked
        || (result.status == CaseStatus::Passed && result.error.is_some())
        || (result.status == CaseStatus::Failed
            && result
                .error
                .as_ref()
                .is_none_or(|error| error.invocation_id != Some(invocation.invocation_id)))
    {
        return Err(integrity());
    }
    let mut ids = BTreeSet::new();
    let mut bytes = 0_u64;
    for reference in &result.evidence_refs {
        let EvidenceRef::Artifact {
            artifact_id,
            range: None,
            ..
        } = reference
        else {
            return Err(integrity());
        };
        let artifact = artifacts.get(artifact_id).ok_or_else(integrity)?;
        if artifact.origin_invocation_id != invocation.invocation_id || !ids.insert(*artifact_id) {
            return Err(integrity());
        }
        resolve(evidence, invocation.project_id, reference)?;
        bytes = bytes
            .checked_add(artifact.length_bytes.get())
            .ok_or_else(integrity)?;
    }
    let published: BTreeSet<_> = artifacts
        .values()
        .filter(|artifact| {
            artifact.origin_invocation_id == invocation.invocation_id
                && artifact.artifact_id != invocation.input_ref
        })
        .map(|artifact| artifact.artifact_id)
        .collect();
    if ids != published || bytes != result.usage.bytes.get() {
        return Err(integrity());
    }
    let report: Value = decode(&evidence.read_artifact(
        invocation.project_id,
        *artifact_id,
        MAX_METADATA_BYTES,
    )?)?;
    if !report.is_object() || outcome.run.run_id != result.run_id {
        return Err(integrity());
    }
    validate_report_observations(
        result,
        &report,
        invocation.project_id,
        outcome,
        profile,
        evidence,
        ledger,
    )
}

fn has_code(value: &Value, code: ErrorCode) -> ProofResult<bool> {
    Ok(ProofError::deserialize(value)
        .map_err(|_| integrity())?
        .code
        == code)
}

fn completed_report_call(ledger: &Ledger, id: &Value) -> ProofResult<StoredInvocation> {
    let stored = ledger.read_invocation(EntityId::deserialize(id).map_err(|_| integrity())?)?;
    if stored.invocation.state != InvocationState::Completed {
        return Err(integrity());
    }
    Ok(stored)
}

fn validate_report_observations(
    result: &CaseResult,
    report: &Value,
    project: EntityId,
    outcome: &EngineOutcome,
    profile: &LoadedProfile,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<()> {
    use CheckName::*;
    let checks = match result.case_id.as_str() {
        id if id.starts_with("CMP-") => super::suites::components::verify_report(
            result,
            report,
            project,
            &outcome.run,
            profile,
            evidence,
            ledger,
        )?,
        id if id.starts_with("NET-") => super::suites::transport::verify_report(
            result,
            report,
            project,
            &outcome.run,
            profile,
            evidence,
            ledger,
        )?,
        id if id.starts_with("RUN-") => super::suites::runtime::verify_report(
            result,
            report,
            project,
            &outcome.run,
            profile,
            evidence,
            ledger,
        )?,
        id if id.starts_with("REC-") => super::suites::recovery::verify_report(
            result,
            report,
            project,
            &outcome.run,
            profile,
            evidence,
            ledger,
        )?,
        id if id.starts_with("EXIT-") => super::suites::exit::verify_report(
            result,
            report,
            project,
            &outcome.run,
            profile,
            evidence,
            ledger,
        )?,
        "CON-01" => {
            let records = report["round_trips"].as_array().ok_or_else(integrity)?;
            let stable = records
                .iter()
                .all(|record| record["equal"] == true && record["schema_version"] == "0.1.0");
            let resolved = report["resolved_evidence"]
                .as_array()
                .ok_or_else(integrity)?;
            for entry in resolved {
                let reference =
                    EvidenceRef::deserialize(&entry["reference"]).map_err(|_| integrity())?;
                if EntityId::deserialize(&entry["project_id"]).map_err(|_| integrity())? != project
                    || entry["expected_sha256"] != entry["observed_sha256"]
                {
                    return Err(integrity());
                }
                resolve(evidence, project, &reference)?;
            }
            Assertions::new([
                (RoundTrip, !records.is_empty() && stable),
                (StableReferences, stable && !resolved.is_empty()),
                (
                    EvidenceVariants,
                    resolved.iter().any(|entry| entry["kind"] == "artifact")
                        && resolved.iter().any(|entry| entry["kind"] == "snapshot"),
                ),
            ])?
        }
        "CON-02" => {
            let framing = FuzzReport::deserialize(&report["framing"]).map_err(|_| integrity())?;
            let typed = FuzzReport::deserialize(&report["contracts"]).map_err(|_| integrity())?;
            let complete = |observed: &FuzzReport| {
                let limits = &profile.config().parser_fuzz;
                observed.counterexamples == 0
                    && observed.executed_inputs == limits.max_inputs.get()
                    && observed.max_inputs == limits.max_inputs.get()
                    && observed.profile_sha256 == profile.sha256()
                    && observed.seed == limits.seed.get()
                    && observed.mutation_version == limits.mutation_version
                    && observed.max_input_bytes == limits.max_input_bytes.get()
                    && observed.deadline_ms == limits.deadline_ms.get()
                    && observed.elapsed_us <= limits.deadline_ms.get() * 1000
            };
            Assertions::new([
                (
                    InvalidRejected,
                    report["rejections"].as_array().ok_or_else(integrity)?.len() == 9,
                ),
                (FramingFuzz, complete(&framing)),
                (TypedFuzz, complete(&typed)),
                (CompleteBudget, complete(&framing) && complete(&typed)),
                (
                    Replayable,
                    framing.replay_checks > 0 && typed.replay_checks > 0,
                ),
            ])?
        }
        "CON-03" => {
            let artifact = evidence.artifact(
                project,
                EntityId::deserialize(&report["artifact_id"]).map_err(|_| integrity())?,
            )?;
            let snapshot_id =
                EntityId::deserialize(&report["snapshot_id"]).map_err(|_| integrity())?;
            let snapshot = evidence
                .snapshots()?
                .into_iter()
                .find(|snapshot| snapshot.snapshot_id == snapshot_id)
                .ok_or_else(integrity)?;
            if snapshot.project_id != project || snapshot.body_ref != artifact.artifact_id {
                return Err(integrity());
            }
            let rejection = &report["rejections"];
            Assertions::new([
                (
                    StaleRejected,
                    has_code(&rejection["stale_patch"]["error"], ErrorCode::StaleSnapshot)?
                        && has_code(
                            &rejection["hash_mismatch"]["error"],
                            ErrorCode::IntegrityError,
                        )?,
                ),
                (
                    ForeignRejected,
                    has_code(
                        &rejection["foreign_evidence"]["error"],
                        ErrorCode::PermissionDenied,
                    )? && has_code(
                        &rejection["unauthorized_identity"]["error"],
                        ErrorCode::PermissionDenied,
                    )? && has_code(
                        &rejection["unauthorized_binding"]["error"],
                        ErrorCode::PermissionDenied,
                    )?,
                ),
                (
                    OriginalUnchanged,
                    report["original_sha256"] == report["after_sha256"]
                        && report["original_sha256"]
                            == serde_json::to_value(snapshot.sha256).map_err(|_| integrity())?,
                ),
            ])?
        }
        "CON-04" => consumer_report_checks(report, project, ledger)?,
        "CON-05" => {
            let structures = &report["structures"];
            let assets =
                AssetGraph::deserialize(&structures["asset_graph"]).map_err(|_| integrity())?;
            let investigation = InvestigationGraph::deserialize(&structures["investigation_graph"])
                .map_err(|_| integrity())?;
            let workflow = WorkflowDefinition::deserialize(&structures["execution_dag"])
                .map_err(|_| integrity())?;
            let trace =
                Trace::deserialize(&structures["execution_trace"]).map_err(|_| integrity())?;
            let session = InvestigationSession::deserialize(&report["canonical_session"])
                .map_err(|_| integrity())?;
            validate_example_links(&assets, &investigation, &workflow, &trace, &session)?;
            for reference in session
                .evidence_refs
                .iter()
                .chain(
                    investigation
                        .nodes
                        .iter()
                        .flat_map(|node| &node.evidence_refs),
                )
                .chain(trace.entries.iter().flat_map(|entry| &entry.evidence_refs))
            {
                resolve(evidence, project, reference)?;
            }
            if assets.project_id != project {
                return Err(integrity());
            }
            let ids = [
                assets.graph_id,
                investigation.graph_id,
                workflow.workflow_id,
                trace.trace_id,
            ];
            let distinct = ids
                .iter()
                .enumerate()
                .all(|(index, id)| !ids[..index].contains(id));
            let user = ledger.read_project(project)?.user_id;
            session.authorize_access(user, session.session_id)?;
            let selected = Vec::<MemoryItem>::deserialize(&report["selected_memory"])
                .map_err(|_| integrity())?;
            let mut filtered = true;
            for item in &selected {
                filtered &= item
                    .authorize_access(
                        user,
                        item.level,
                        if item.level == MemoryLevel::Session {
                            Some(session.session_id)
                        } else {
                            None
                        },
                        outcome.run.started_at,
                    )
                    .is_ok();
                evidence.verify_artifact(project, item.content_ref)?;
            }
            for excluded in report["excluded_missing_content"]
                .as_array()
                .ok_or_else(integrity)?
            {
                let id = EntityId::deserialize(&excluded[0]).map_err(|_| integrity())?;
                let content = EntityId::deserialize(&excluded[1]).map_err(|_| integrity())?;
                filtered &= !selected
                    .iter()
                    .any(|item| item.memory_id == id || item.content_ref == content);
            }
            for (artifact_field, invocation_field, hash_field) in [
                (
                    "context_artifact_id",
                    "context_invocation_id",
                    Some("context_sha256"),
                ),
                (
                    "canonical_context_artifact_id",
                    "canonical_context_invocation_id",
                    None,
                ),
            ] {
                let artifact = evidence.artifact(
                    project,
                    EntityId::deserialize(&report[artifact_field]).map_err(|_| integrity())?,
                )?;
                let call = completed_report_call(ledger, &report[invocation_field])?;
                if artifact.origin_invocation_id != call.invocation.invocation_id
                    || call.invocation.project_id != project
                {
                    return Err(integrity());
                }
                if let Some(field) = hash_field
                    && report[field]
                        != serde_json::to_value(artifact.sha256).map_err(|_| integrity())?
                {
                    return Err(integrity());
                }
                let context: Value = decode(&evidence.read_artifact(
                    project,
                    artifact.artifact_id,
                    MAX_METADATA_BYTES,
                )?)?;
                if artifact_field == "canonical_context_artifact_id" {
                    filtered &= context["record"] == report["canonical_session"];
                } else {
                    let retrieved = context["memory_examples"]
                        .as_array()
                        .ok_or_else(integrity)?;
                    filtered &= retrieved.len() == selected.len();
                    for (entry, item) in retrieved.iter().zip(&selected) {
                        filtered &= entry["record"]
                            == serde_json::to_value(item).map_err(|_| integrity())?;
                    }
                }
            }
            let source =
                MemoryItem::deserialize(&report["promotion"]["source"]).map_err(|_| integrity())?;
            let promoted = MemoryItem::deserialize(&report["promotion"]["promoted"])
                .map_err(|_| integrity())?;
            let generalized = evidence.artifact(project, promoted.content_ref)?;
            if report["promotion"]["generalized_sha256"]
                != serde_json::to_value(generalized.sha256).map_err(|_| integrity())?
            {
                return Err(integrity());
            }
            Assertions::new([
                (
                    GraphsDistinct,
                    distinct
                        && has_code(
                            &report["rejections"]["cross_session_trace"],
                            ErrorCode::PermissionDenied,
                        )?,
                ),
                (OwnershipFiltered, filtered),
                (
                    TwoMemoryLevels,
                    selected.iter().any(|item| item.level == MemoryLevel::User)
                        && selected
                            .iter()
                            .any(|item| item.level == MemoryLevel::Session),
                ),
                (
                    PromotionBounded,
                    promoted.content_ref != source.content_ref
                        && promoted.promotion_source_id == Some(source.memory_id)
                        && promoted.valid_until <= source.valid_until,
                ),
            ])?
        }
        _ => return Err(integrity()),
    };
    if checks != result.observed {
        return Err(integrity());
    }
    Ok(())
}

fn consumer_report_checks(
    report: &Value,
    project: EntityId,
    ledger: &Ledger,
) -> ProofResult<Assertions> {
    use CheckName::*;
    let direct = completed_report_call(ledger, &report["completed_invocation_id"])?;
    let runtime = completed_report_call(ledger, &report["runtime_completed_invocation_id"])?;
    let child_call = completed_report_call(ledger, &report["child_invocation_id"])?;
    for stored in [&direct, &runtime, &child_call] {
        if stored.invocation.project_id != project {
            return Err(integrity());
        }
    }
    let mut no_effects = true;
    for denial in report["consumer_denials"]
        .as_array()
        .ok_or_else(integrity)?
    {
        for (id, error) in [
            ("harness_invocation_id", "harness_error"),
            ("runtime_invocation_id", "runtime_error"),
        ] {
            let stored = ledger
                .read_invocation(EntityId::deserialize(&denial[id]).map_err(|_| integrity())?)?;
            let actual = ProofError::deserialize(&denial[error]).map_err(|_| integrity())?;
            no_effects &= stored.invocation.error.as_ref() == Some(&actual)
                && stored.invocation.output_ref.is_none()
                && stored.invocation.usage.units == WireInt::ZERO;
        }
    }
    let grant = ledger
        .read_grant(EntityId::deserialize(&report["revoked_grant_id"]).map_err(|_| integrity())?)?;
    let before = Budget::deserialize(&report["parent_before"]).map_err(|_| integrity())?;
    let escrowed = Budget::deserialize(&report["parent_escrowed"]).map_err(|_| integrity())?;
    let after = Budget::deserialize(&report["parent_after"]).map_err(|_| integrity())?;
    let child = Budget::deserialize(&report["child_after"]).map_err(|_| integrity())?;
    if before.budget_id != escrowed.budget_id
        || before.budget_id != after.budget_id
        || before.limit != escrowed.limit
        || before.limit != after.limit
    {
        return Err(integrity());
    }
    if ledger.read_budget(child.budget_id)? != child
        || child_call.invocation.budget_id != child.budget_id
    {
        return Err(integrity());
    }
    let mut bounded = child.parent_budget_id == Some(before.budget_id);
    for field in ["scope", "tools", "identity", "permissions", "root_rebind"] {
        bounded &= has_code(
            &report["child_rejections"][field],
            ErrorCode::PermissionDenied,
        )?;
    }
    let quota = escrowed.reserved == before.reserved.checked_add(child.limit)?
        && escrowed.consumed == before.consumed
        && child.consumed == child_call.invocation.usage.units
        && after.consumed == before.consumed.checked_add(child.consumed)?
        && after.reserved == escrowed.reserved.checked_sub(child.consumed)?
        && has_code(
            &report["child_rejections"]["overdraw"],
            ErrorCode::BudgetExhausted,
        )?
        && has_code(
            &report["child_rejections"]["sibling_allocation"],
            ErrorCode::BudgetExhausted,
        )?;
    let wire = &report["runtime_wire_observations"];
    let equivalent = no_effects
        && direct.invocation.invocation_id != runtime.invocation.invocation_id
        && report["completed_invocation_id"] == report["duplicate_invocation_id"]
        && report["harness_binding_id"]
            == serde_json::to_value(direct.invocation.actor_ref).map_err(|_| integrity())?
        && report["runtime_binding_id"]
            == serde_json::to_value(runtime.invocation.actor_ref).map_err(|_| integrity())?
        && report["consumed_before_duplicate"] == report["consumed_after_duplicate"]
        && wire["before_replay_budget"] == wire["after_replay_budget"]
        && wire["first_invocation_id"] != wire["other_invocation_id"]
        && has_code(
            &wire["cross_binding_correlation_error"],
            ErrorCode::InvalidInput,
        )?;
    Assertions::new([
        (ConsumerEquivalence, equivalent),
        (
            RevocationEnforced,
            grant.revoked && has_code(&report["revocation_error"], ErrorCode::ApprovalRequired)?,
        ),
        (ChildScopeBounded, bounded),
        (AggregateQuota, quota),
    ])
}

fn snapshot_bytes(
    evidence: &EvidenceStore,
    project: EntityId,
    id: EntityId,
    revision: WireInt,
) -> ProofResult<Vec<u8>> {
    let snapshot = evidence.snapshot(project, id, revision)?;
    let length = snapshot.length_bytes.get();
    if length > 32 * 1024 * 1024 {
        return Err(capacity());
    }
    let reader = evidence.snapshot_reader(project, id, revision)?;
    let mut bytes = Vec::with_capacity(length as usize);
    while (bytes.len() as u64) < length {
        let count = (length - bytes.len() as u64).min(MAX_CHUNK_BYTES as u64);
        bytes.extend_from_slice(
            &reader.read(WireInt::new(bytes.len() as u64)?, WireInt::new(count)?)?,
        );
    }
    Ok(bytes)
}

fn resolve(
    evidence: &EvidenceStore,
    project: EntityId,
    reference: &EvidenceRef,
) -> ProofResult<()> {
    match reference {
        EvidenceRef::Artifact { artifact_id, .. } => {
            let artifact = evidence.artifact(project, *artifact_id)?;
            let bytes = evidence.read_artifact(project, *artifact_id, 32 * 1024 * 1024)?;
            reference.validate_artifact(project, &artifact, &bytes)?;
        }
        EvidenceRef::Snapshot {
            snapshot_id,
            revision,
            ..
        } => {
            let snapshot = evidence.snapshot(project, *snapshot_id, *revision)?;
            let bytes = snapshot_bytes(evidence, project, *snapshot_id, *revision)?;
            reference.validate_snapshot(project, *revision, &snapshot, &bytes)?;
        }
    }
    Ok(())
}

fn validate_trace(
    trace: &[u8],
    ledger: &Ledger,
    outcome: &EngineOutcome,
    invocations: &BTreeMap<EntityId, &StoredInvocation>,
    artifacts: &BTreeMap<EntityId, &Artifact>,
) -> ProofResult<()> {
    if !trace.is_empty() && trace.last() != Some(&b'\n') {
        return Err(integrity());
    }
    let mut lines = trace.split(|byte| *byte == b'\n');
    let mut cursor = WireInt::ZERO;
    let mut sequences = BTreeMap::new();
    let mut last_types = BTreeMap::new();
    loop {
        let page = ledger.event_page(cursor, 256)?;
        if page.events.is_empty() {
            break;
        }
        for event in page.events {
            let actual: Event = decode(lines.next().ok_or_else(integrity)?)?;
            if actual != event
                || event.timestamp < outcome.run.started_at
                || outcome
                    .run
                    .finished_at
                    .is_none_or(|finished| event.timestamp > finished)
                || event.published
            {
                return Err(integrity());
            }
            if let Some(stored) = invocations.get(&event.aggregate_id) {
                if event.project_id != stored.invocation.project_id
                    || event.control_revision != Some(stored.invocation.control_revision)
                {
                    return Err(integrity());
                }
                sequences.insert(event.aggregate_id, event.aggregate_sequence);
                last_types.insert(event.aggregate_id, event.event_type);
            } else {
                let control = ledger.read_control(event.aggregate_id)?;
                if event
                    .control_revision
                    .is_none_or(|revision| revision > control.revision)
                    || !invocations.values().any(|stored| {
                        stored.invocation.investigation_id == control.investigation_id
                            && stored.invocation.project_id == event.project_id
                    })
                {
                    return Err(integrity());
                }
            }
            for id in event.data_refs {
                if id == event.aggregate_id {
                    continue;
                }
                let artifact = artifacts.get(&id).ok_or_else(integrity)?;
                if artifact.project_id != event.project_id {
                    return Err(integrity());
                }
            }
        }
        if page.last_position <= cursor {
            return Err(integrity());
        }
        cursor = page.last_position;
    }
    if lines.next() != Some(&b""[..]) || lines.next().is_some() {
        return Err(integrity());
    }
    for (id, stored) in invocations {
        let state = serde_json::to_value(stored.invocation.state).map_err(|_| integrity())?;
        let expected = format!("invocation.{}", state.as_str().ok_or_else(integrity)?);
        if sequences.get(id) != Some(&stored.history.event_sequence())
            || last_types
                .get(id)
                .is_none_or(|kind| kind.as_str() != expected)
        {
            return Err(integrity());
        }
    }
    Ok(())
}

fn validate_campaigns(
    workspace: &OwnedDirectory,
    files: &[FileSeal],
    outcome: &EngineOutcome,
    profile: &LoadedProfile,
    evidence: &EvidenceStore,
) -> ProofResult<()> {
    let Some(result) = outcome.results.iter().find(|result| {
        result.case_id.as_str() == "CON-02"
            && result.observed.iter().next().is_some()
            && !result.evidence_refs.is_empty()
    }) else {
        return Ok(());
    };
    let directories: BTreeSet<_> = files
        .iter()
        .filter_map(|file| file.path.split_once('/'))
        .map(|(first, _)| first)
        .filter(|first| first.starts_with("contract-campaigns-"))
        .collect();
    if directories.len() != 1 {
        return Err(integrity());
    }
    let directory = directories.first().ok_or_else(integrity)?;
    let campaign = OwnedDirectory::open(workspace.path(), Path::new(directory))?;
    if campaign.run_id() != workspace.run_id() {
        return Err(integrity());
    }
    let manifest = workspace.read(
        Path::new(&format!("{directory}/corpus-manifest.json")),
        MAX_METADATA_BYTES,
    )?;
    let corpus_sha = Digest::of(&manifest);
    if outcome
        .run
        .environment
        .fixture_digests
        .get(&CatalogId::parse("parser-corpus-manifest")?)
        != Some(&corpus_sha)
    {
        return Err(integrity());
    }
    let all_artifacts = evidence.artifacts()?;
    let EvidenceRef::Artifact { artifact_id, .. } =
        result.evidence_refs.first().ok_or_else(integrity)?
    else {
        return Err(integrity());
    };
    let report_artifact = all_artifacts
        .iter()
        .find(|artifact| artifact.artifact_id == *artifact_id)
        .ok_or_else(integrity)?;
    let case_report: Value = decode(&evidence.read_artifact(
        report_artifact.project_id,
        *artifact_id,
        MAX_METADATA_BYTES,
    )?)?;
    let corpus: Value = decode(&manifest)?;
    let seeds = corpus["entries"].as_array().ok_or_else(integrity)?;
    let attachment_hashes: BTreeSet<_> = result
        .evidence_refs
        .iter()
        .skip(1)
        .map(|reference| {
            let EvidenceRef::Artifact { artifact_id, .. } = reference else {
                return Err(integrity());
            };
            let artifact = all_artifacts
                .iter()
                .find(|artifact| artifact.artifact_id == *artifact_id)
                .ok_or_else(integrity)?;
            Ok(artifact.sha256)
        })
        .collect::<ProofResult<_>>()?;
    for (target, prefix) in [
        (FuzzTarget::Framing, "framing"),
        (FuzzTarget::Contracts, "contracts"),
    ] {
        let bytes = workspace.read(
            Path::new(&format!("{directory}/{prefix}-fuzz.json")),
            MAX_METADATA_BYTES,
        )?;
        let report: FuzzReport = decode(&bytes)?;
        let limits = &profile.config().parser_fuzz;
        if report.target != target
            || report.profile_sha256 != profile.sha256()
            || report.corpus_sha256 != corpus_sha
            || report.seed != limits.seed.get()
            || report.mutation_version != limits.mutation_version
            || report.max_inputs != limits.max_inputs.get()
            || report.max_input_bytes != limits.max_input_bytes.get()
            || report.deadline_ms != limits.deadline_ms.get()
            || !attachment_hashes.contains(&Digest::of(&bytes))
            || report.counterexamples != 0
            || report.executed_inputs != limits.max_inputs.get()
            || case_report[prefix] != serde_json::to_value(&report).map_err(|_| integrity())?
        {
            return Err(integrity());
        }
        let replay = workspace.read(
            Path::new(&format!("{directory}/{prefix}-seed-replays.json")),
            MAX_METADATA_BYTES,
        )?;
        let entries: Vec<Value> = decode(&replay)?;
        if entries.is_empty()
            || entries.len() as u64 != report.replay_checks
            || entries
                .iter()
                .any(|entry| entry["original"] != "rejected" || entry["replay"] != "rejected")
            || !attachment_hashes.contains(&Digest::of(&replay))
        {
            return Err(integrity());
        }
        let mut rejected: Vec<_> = seeds
            .iter()
            .filter(|seed| seed["target"] == prefix && seed["valid"] == false)
            .map(|seed| {
                Ok((
                    seed["sha256"].as_str().ok_or_else(integrity)?,
                    seed.get("role").and_then(Value::as_str),
                    seed.get("direction").and_then(Value::as_str),
                ))
            })
            .collect::<ProofResult<_>>()?;
        let mut replayed: Vec<_> = entries
            .iter()
            .map(|entry| {
                if entry["context"]["expectation"] != "reject" {
                    return Err(integrity());
                }
                Ok((
                    entry["input_sha256"].as_str().ok_or_else(integrity)?,
                    entry["context"].get("role").and_then(Value::as_str),
                    entry["context"].get("direction").and_then(Value::as_str),
                ))
            })
            .collect::<ProofResult<_>>()?;
        rejected.sort_unstable();
        replayed.sort_unstable();
        if rejected != replayed {
            return Err(integrity());
        }
    }
    if !attachment_hashes.contains(&corpus_sha) || result.evidence_refs.len() != 6 {
        return Err(integrity());
    }
    Ok(())
}

fn zero_usage(result: &CaseResult) -> bool {
    result.elapsed_us == WireInt::ZERO
        && result.usage.units == WireInt::ZERO
        && result.usage.bytes == WireInt::ZERO
        && result.usage.cpu_us == WireInt::ZERO
        && result.usage.elapsed_us == WireInt::ZERO
}

fn verdict(
    selection: &CaseSelection,
    outcome: &EngineOutcome,
    profile: &LoadedProfile,
) -> ProofResult<PacketVerdict> {
    let gate = super::inventory::evaluate(selection, &outcome.run, &outcome.results, profile)?;
    let apply_outcome = |status| {
        if outcome
            .error
            .as_ref()
            .is_some_and(|error| error.code != ErrorCode::Cancelled)
        {
            return CommandStatus::Failed;
        }
        if status == CommandStatus::Failed || status == CommandStatus::Blocked {
            return status;
        }
        if outcome.interrupted
            || outcome
                .error
                .as_ref()
                .is_some_and(|error| error.code == ErrorCode::Cancelled)
        {
            return CommandStatus::Incomplete;
        }
        status
    };
    Ok(PacketVerdict {
        counts: gate.counts,
        selected_status: apply_outcome(gate.selected_status),
        full_status: apply_outcome(gate.full_status),
        review_status: ReviewStatus::Unreviewed,
        r0_exit_ready: false,
    })
}

fn assess_review(
    workspace: &OwnedDirectory,
    selection: &CaseSelection,
    outcome: &EngineOutcome,
    profile: &LoadedProfile,
    manifest_sha256: Digest,
    mut verdict: PacketVerdict,
) -> ProofResult<PacketVerdict> {
    let mut gate = super::inventory::evaluate(selection, &outcome.run, &outcome.results, profile)?;
    gate.selected_status = verdict.selected_status;
    gate.full_status = verdict.full_status;
    // The immutable manifest covers every case attachment and register/source byte.
    // Explicitly require each actual case report plus every canonical provenance chunk.
    // 35 reports + at most 16 register chunks + one manifest fit DecisionRecord's 64 refs.
    let mut required = Vec::with_capacity(51);
    for result in &outcome.results {
        if let Some(reference) = result.evidence_refs.first()
            && !required.contains(reference)
        {
            required.push(*reference);
        }
    }
    let path = workspace.path();
    let owner = Arc::new(OwnedDirectory::open(
        path.parent().ok_or_else(integrity)?,
        Path::new(path.file_name().ok_or_else(integrity)?),
    )?);
    let evidence = EvidenceStore::open_readonly(owner)?;
    if outcome.run.dependency_record_refs.len() > 16
        || (gate.full_status == CommandStatus::Passed
            && outcome.run.dependency_record_refs.is_empty())
    {
        return Err(integrity());
    }
    let artifacts = evidence.artifacts()?;
    for id in &outcome.run.dependency_record_refs {
        let artifact = artifacts
            .iter()
            .find(|artifact| artifact.artifact_id == *id)
            .ok_or_else(integrity)?;
        evidence.verify_artifact(artifact.project_id, *id)?;
        let reference = EvidenceRef::Artifact {
            artifact_id: *id,
            sha256: artifact.sha256,
            range: None,
        };
        if !required.contains(&reference) {
            required.push(reference);
        }
    }
    let context = super::review::ReviewContext {
        run: &outcome.run,
        manifest_sha256,
        profile,
        gate: &gate,
        required_evidence: &required,
        now: AuditTime::now(),
    };
    let assessment = super::review::read_and_assess(workspace, &context)?;
    verdict.review_status = assessment.review_status;
    verdict.r0_exit_ready = assessment.r0_exit_ready;
    Ok(verdict)
}

fn exit_record(outcome: &EngineOutcome, verdict: &PacketVerdict) -> Exit {
    Exit {
        schema_version: ContractVersion::V0_1_0,
        run_id: outcome.run.run_id,
        counts: verdict.counts,
        selected_status: verdict.selected_status,
        full_status: verdict.full_status,
        review_status: verdict.review_status,
        r0_exit_ready: verdict.r0_exit_ready,
        interrupted: outcome.interrupted,
        error: outcome.error.clone(),
        trace_sha256: outcome.trace_sha256,
        trace_length_bytes: outcome.trace_length_bytes,
    }
}

fn scan(workspace: &OwnedDirectory) -> ProofResult<Vec<FileSeal>> {
    let root = workspace.lock_directory()?;
    let mut files = Vec::new();
    let mut total = 0;
    scan_directory(&root, "", 0, &mut files, &mut total)?;
    files.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn scan_directory(
    directory: &File,
    prefix: &str,
    depth: usize,
    files: &mut Vec<FileSeal>,
    total: &mut u64,
) -> ProofResult<()> {
    if depth > MAX_DEPTH {
        return Err(capacity());
    }
    let uid = rustix::process::geteuid().as_raw();
    let before = directory.metadata().map_err(|_| integrity())?;
    validate_metadata(&before, true, uid)?;
    let mut entries = 0;
    for entry in Dir::read_from(directory).map_err(|_| integrity())? {
        let entry = entry.map_err(|_| integrity())?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        entries += 1;
        if entries > MAX_FILES {
            return Err(capacity());
        }
        let text = name.to_str().map_err(|_| integrity())?;
        if text.len() > 255 || text.chars().any(char::is_control) {
            return Err(integrity());
        }
        let path = if prefix.is_empty() {
            text.to_owned()
        } else {
            format!("{prefix}/{text}")
        };
        if path.len() > 4096 {
            return Err(capacity());
        }
        let named =
            fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| integrity())?;
        let kind = FileType::from_raw_mode(named.st_mode);
        if prefix.is_empty() && text == "review.json" {
            if kind != FileType::RegularFile
                || named.st_uid != uid
                || named.st_mode as u32 & 0o7777 != 0o600
                || named.st_nlink != 1
                || named.st_size < 0
                || named.st_size > 256 * 1024
            {
                return Err(integrity());
            }
            continue;
        }
        if prefix.is_empty() && text == "manifest.json" {
            if kind != FileType::RegularFile {
                return Err(integrity());
            }
            continue;
        }
        match kind {
            FileType::Directory => {
                let child = File::from(
                    fs::openat(directory, name, DIRECTORY_FLAGS, Mode::empty())
                        .map_err(|_| integrity())?,
                );
                let metadata = child.metadata().map_err(|_| integrity())?;
                validate_metadata(&metadata, true, uid)?;
                if metadata.dev() != named.st_dev as u64 || metadata.ino() != named.st_ino as u64 {
                    return Err(integrity());
                }
                if !(prefix.is_empty() && text == "ephemeral") {
                    if files.len() >= MAX_FILES {
                        return Err(capacity());
                    }
                    files.push(FileSeal {
                        path: path.clone(),
                        sha256: Digest::of(b""),
                        length_bytes: WireInt::ZERO,
                        device: metadata.dev(),
                        inode: metadata.ino(),
                        uid: metadata.uid(),
                        mode: metadata.mode(),
                        links: metadata.nlink(),
                    });
                    scan_directory(&child, &path, depth + 1, files, total)?;
                }
                let after = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| integrity())?;
                if after.st_dev != named.st_dev || after.st_ino != named.st_ino {
                    return Err(integrity());
                }
            }
            FileType::RegularFile => {
                if files.len() >= MAX_FILES {
                    return Err(capacity());
                }
                let mut file = File::from(
                    fs::openat(directory, name, FILE_FLAGS, Mode::empty())
                        .map_err(|_| integrity())?,
                );
                let before = file.metadata().map_err(|_| integrity())?;
                validate_metadata(&before, false, uid)?;
                if before.dev() != named.st_dev as u64 || before.ino() != named.st_ino as u64 {
                    return Err(integrity());
                }
                *total = total.checked_add(before.len()).ok_or_else(capacity)?;
                if *total > MAX_PACKET_BYTES {
                    return Err(capacity());
                }
                let mut hash = Sha256::new();
                let mut length = 0_u64;
                let mut buffer = [0_u8; 16 * 1024];
                loop {
                    let count = file.read(&mut buffer).map_err(|_| integrity())?;
                    if count == 0 {
                        break;
                    }
                    length = length.checked_add(count as u64).ok_or_else(capacity)?;
                    if length > before.len() {
                        return Err(integrity());
                    }
                    hash.update(&buffer[..count]);
                }
                let after = file.metadata().map_err(|_| integrity())?;
                let current = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW)
                    .map_err(|_| integrity())?;
                if !same_file(&before, &after)
                    || current.st_dev as u64 != before.dev()
                    || current.st_ino as u64 != before.ino()
                    || length != before.len()
                {
                    return Err(integrity());
                }
                files.push(FileSeal {
                    path,
                    sha256: Digest::from_sha256(hash.finalize().into()),
                    length_bytes: WireInt::new(length)?,
                    device: before.dev(),
                    inode: before.ino(),
                    uid: before.uid(),
                    mode: before.mode(),
                    links: before.nlink(),
                });
            }
            _ => return Err(integrity()),
        }
    }
    let after = directory.metadata().map_err(|_| integrity())?;
    if !same_file(&before, &after) {
        return Err(integrity());
    }
    Ok(())
}

fn validate_metadata(metadata: &Metadata, directory: bool, uid: u32) -> ProofResult<()> {
    if metadata.uid() != uid
        || metadata.mode() & 0o7777 != if directory { 0o700 } else { 0o600 }
        || (directory && !metadata.is_dir())
        || (!directory && (!metadata.is_file() || metadata.nlink() != 1))
    {
        return Err(integrity());
    }
    Ok(())
}

fn same_file(left: &Metadata, right: &Metadata) -> bool {
    left.dev() == right.dev()
        && left.ino() == right.ino()
        && left.len() == right.len()
        && left.uid() == right.uid()
        && left.mode() == right.mode()
        && left.nlink() == right.nlink()
        && left.mtime() == right.mtime()
        && left.mtime_nsec() == right.mtime_nsec()
        && left.ctime() == right.ctime()
        && left.ctime_nsec() == right.ctime_nsec()
}

fn exists(workspace: &OwnedDirectory, name: &str) -> ProofResult<bool> {
    let root = workspace.lock_directory()?;
    match fs::statat(&root, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(rustix::io::Errno::NOENT) => Ok(false),
        Err(_) => Err(integrity()),
    }
}

fn read_json<T: DeserializeOwned>(workspace: &OwnedDirectory, relative: &str) -> ProofResult<T> {
    decode(&workspace.read(Path::new(relative), MAX_METADATA_BYTES)?)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> ProofResult<T> {
    serde_json::from_slice(bytes).map_err(|_| integrity())
}
struct MetadataBuffer(Vec<u8>);

impl std::io::Write for MetadataBuffer {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_METADATA_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other(
                "Packet metadata exceeds its finite bound",
            ));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn encode(value: &impl Serialize) -> ProofResult<Vec<u8>> {
    let mut buffer = MetadataBuffer(Vec::new());
    serde_json::to_writer(&mut buffer, value).map_err(|_| capacity())?;
    Ok(buffer.0)
}
fn write_json(
    workspace: &OwnedDirectory,
    relative: &str,
    value: &impl Serialize,
) -> ProofResult<()> {
    workspace.write_new(Path::new(relative), &encode(value)?)?;
    Ok(())
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Packet identity, coverage, provenance, or evidence integrity is invalid",
    )
}
fn capacity() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Packet exceeds its finite filesystem or metadata bounds",
    )
}
