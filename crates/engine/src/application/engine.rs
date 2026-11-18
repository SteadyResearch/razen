//! Trusted, fresh-run composition of the bounded synchronous proof worker.
//! Controllers contain host authority and must never cross the private process boundary.
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc::SyncSender,
};

use serde::{Serialize, de::DeserializeOwned};

use super::case_execution;
use super::control::{ControlAck, ControlAction, ControlClient, ControlCommand};
use super::control_owner::OwnedControl;
use super::environment;
use super::harness::{
    BOOTSTRAP_PATH, CaseSelection, EXAMPLES_PATH, EngineBootstrap, EngineOutcome, EngineReady,
    MAX_METADATA_BYTES, MAX_TRACE_BYTES, OUTCOME_PATH, READY_PATH, ScenarioManifest, TRACE_PATH,
};
use super::profile::LoadedProfile;
use super::proof_host::ProofHost;
use crate::adapters::ledger::Ledger;
use crate::adapters::native_files::executable_digest;
use crate::adapters::workspace::OwnedDirectory;
use crate::domain::evidence::EvidenceRef;
use crate::domain::execution::ControlMode;
use crate::domain::proofs::{
    Assertions, CaseStatus, PackageStatus, ProofCase, ProofInventory, ProofResult as CaseResult,
    Run,
};
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, Usage, WireInt,
};
use crate::protocol::contracts::CanonicalFixtures;
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

/// Cached host-only authority. Requesting control does not reopen run metadata,
/// discover a socket by a peer-supplied path, or wait for the execution worker.
#[derive(Clone)]
pub struct EngineControl {
    client: Arc<ControlClient>,
    ledger: Arc<Ledger>,
    investigation_id: EntityId,
}

impl EngineControl {
    pub fn request_cancel(&self) -> ProofResult<ControlAck> {
        let current = self.ledger.read_control(self.investigation_id)?;
        self.client.request(&ControlCommand {
            request_id: EntityId::new(),
            investigation_id: self.investigation_id,
            expected_revision: current.revision,
            action: ControlAction::Cancel,
        })
    }

    /// Reconcile an overlapping stop against actual durable state, never a fabricated ACK.
    pub(crate) fn cancel_barrier(&self) -> ProofResult<()> {
        if self.ledger.read_control(self.investigation_id)?.mode == ControlMode::Cancelled {
            return Ok(());
        }
        match self.request_cancel() {
            Ok(_) => Ok(()),
            Err(error) => {
                if self.ledger.read_control(self.investigation_id)?.mode == ControlMode::Cancelled {
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    }
}

struct Sources {
    bootstrap: EngineBootstrap,
    selection: CaseSelection,
    profile: LoadedProfile,
    examples: CanonicalFixtures,
}

impl Sources {
    fn read(workspace: &OwnedDirectory) -> ProofResult<Self> {
        let bootstrap: EngineBootstrap =
            decode(&workspace.read(Path::new(BOOTSTRAP_PATH), MAX_METADATA_BYTES)?)?;
        let profile_bytes = workspace.read(Path::new("profile.json"), MAX_METADATA_BYTES)?;
        let manifest_bytes =
            workspace.read(Path::new("fixture-manifest.json"), MAX_METADATA_BYTES)?;
        let examples_bytes = workspace.read(Path::new(EXAMPLES_PATH), MAX_METADATA_BYTES)?;
        let selection: CaseSelection =
            decode(&workspace.read(Path::new("cases.json"), MAX_METADATA_BYTES)?)?;
        if bootstrap.run_id != workspace.run_id()
            || bootstrap.schema_version != ContractVersion::V0_1_0
            || bootstrap.started_at > AuditTime::now()
            || bootstrap.profile_sha256 != Digest::of(&profile_bytes)
            || bootstrap.fixture_manifest_sha256 != Digest::of(&manifest_bytes)
            || bootstrap.contract_examples_sha256 != Digest::of(&examples_bytes)
            || selection.fixture_manifest_sha256 != bootstrap.fixture_manifest_sha256
            || selection.schema_version != bootstrap.schema_version
        {
            return Err(integrity());
        }
        let manifest: ScenarioManifest = decode(&manifest_bytes)?;
        if manifest.schema_version != bootstrap.schema_version
            || manifest.fixture_catalog != selection.fixture_catalog
        {
            return Err(integrity());
        }
        let inventory = ProofInventory::new(manifest.packages, manifest.cases)?;
        if inventory.packages() != selection.inventory.packages()
            || inventory.cases() != selection.inventory.cases()
        {
            return Err(integrity());
        }
        selection.validate()?;
        Ok(Self {
            bootstrap,
            selection,
            profile: LoadedProfile::from_bytes(&profile_bytes)?,
            examples: CanonicalFixtures::from_bytes(&examples_bytes)?,
        })
    }
}

/// Owns only its fresh canonical host and the auxiliary private control endpoint.
/// The caller retains the run directory; no packet or unrelated process is removed.
pub fn execute(
    workspace: Arc<OwnedDirectory>,
    repo_root: &Path,
    cancel: Arc<AtomicBool>,
    ready: SyncSender<EngineControl>,
) -> ProofResult<EngineOutcome> {
    let sources = Sources::read(&workspace)?;
    let engine_sha256 = executable_digest()?;
    let observed = environment::observe(
        repo_root,
        &workspace,
        &sources.profile,
        BTreeMap::from([
            (CatalogId::parse("razen-engine")?, engine_sha256),
            (
                CatalogId::parse("razen-proof")?,
                sources.bootstrap.orchestrator_sha256,
            ),
        ]),
        &sources.selection.selected_case_ids,
    )?;
    for (id, expected) in [
        (
            "scenario-manifest",
            sources.bootstrap.fixture_manifest_sha256,
        ),
        (
            "contract-scenarios",
            sources.bootstrap.contract_examples_sha256,
        ),
        ("pilot-profile", sources.bootstrap.profile_sha256),
    ] {
        if observed.fixture_digests.get(&CatalogId::parse(id)?) != Some(&expected) {
            return Err(integrity());
        }
    }
    let host = ProofHost::create(
        workspace.clone(),
        &sources.profile,
        sources.examples,
        sources.bootstrap.contract_examples_sha256,
        engine_sha256,
    )?;
    let owner = OwnedControl::start(workspace.clone(), host.control.clone())?;
    host.install_control_client(owner.client()?)?;
    let controller = EngineControl {
        client: host.control_client()?,
        ledger: host.ledger.clone(),
        investigation_id: host.session.investigation_id,
    };
    let mut outcome = EngineOutcome {
        schema_version: ContractVersion::V0_1_0,
        run: Run {
            run_id: workspace.run_id(),
            contract_version: ContractVersion::V0_1_0,
            profile_id: sources.profile.config().profile_id.clone(),
            profile_sha256: sources.profile.sha256(),
            clock_epoch_id: host.control.clock_epoch_id(),
            started_at: sources.bootstrap.started_at,
            finished_at: None,
            environment: observed,
            dependency_record_refs: Vec::new(),
            fixture_manifest_sha256: sources.bootstrap.fixture_manifest_sha256,
        },
        results: sources
            .selection
            .inventory
            .cases()
            .iter()
            .map(|case| unexecuted(workspace.run_id(), case))
            .collect::<ProofResult<Vec<_>>>()?,
        trace_sha256: Digest::of(b""),
        trace_length_bytes: WireInt::ZERO,
        interrupted: false,
        error: None,
    };
    // Sources' parsed examples have moved into the canonical host; all remaining
    // validation uses the original source hashes and validated inventory/profile.
    let mut ready_sent = false;
    let work = (|| {
        super::inventory::validate_selected_environment(
            &sources.selection,
            &outcome.run,
            &sources.profile,
        )?;
        persist(
            &host,
            &sources.bootstrap,
            &sources.selection,
            &sources.profile,
            &mut outcome,
        )?;
        let record = EngineReady {
            schema_version: ContractVersion::V0_1_0,
            run_id: workspace.run_id(),
            engine_pid: WireInt::new(u64::from(std::process::id()))?,
            control_resource_id: owner.resource_id(),
            investigation_id: host.session.investigation_id,
            clock_epoch_id: host.control.clock_epoch_id(),
        };
        workspace.write_new(Path::new(READY_PATH), &encode(&record, MAX_METADATA_BYTES)?)?;
        ready
            .try_send(controller.clone())
            .map_err(|_| unavailable())?;
        ready_sent = true;
        run_cases(
            &case_execution::ExecutionContext {
                host: &host,
                profile: &sources.profile,
                repo_root,
            },
            &sources.bootstrap,
            &sources.selection,
            &cancel,
            &controller,
            &mut outcome,
        )
    })();
    let mut terminal_error = None;
    if let Err(error) = work {
        if error.code == ErrorCode::IntegrityError {
            host.admission.invalidate_integrity();
        }
        if !ready_sent || error.code == ErrorCode::OutputInvalid {
            terminal_error = Some(error.clone());
        }
        outcome.error = Some(error);
        // Close the real admission barrier if work aborted, without altering any
        // held quota, uncertain invocation, or existing evidence.
        let closed = (|| {
            if host
                .ledger
                .read_control(host.session.investigation_id)?
                .mode
                != ControlMode::Cancelled
                && let Err(error) = controller.request_cancel()
                && host
                    .ledger
                    .read_control(host.session.investigation_id)?
                    .mode
                    != ControlMode::Cancelled
            {
                return Err(error);
            }
            Ok::<_, ProofError>(())
        })();
        if let Err(error) = closed {
            terminal_error = Some(error);
        }
    }
    let cleanup = owner.shutdown();
    if let Err(error) = &cleanup {
        outcome.error = Some(error.clone());
    }
    if host
        .ledger
        .read_control(host.session.investigation_id)?
        .mode
        == ControlMode::Cancelled
    {
        outcome.interrupted = true;
        if outcome.error.is_none() {
            outcome.error = Some(ProofError::new(
                ErrorCode::Cancelled,
                "Engine run was cancelled",
            ));
        }
    }
    outcome.run.finished_at = Some(AuditTime::now());
    // No server can append another control event after the final trace export.
    persist(
        &host,
        &sources.bootstrap,
        &sources.selection,
        &sources.profile,
        &mut outcome,
    )?;
    cleanup?;
    if let Some(error) = terminal_error {
        return Err(error);
    }
    Ok(outcome)
}

fn run_cases(
    context: &case_execution::ExecutionContext<'_>,
    bootstrap: &EngineBootstrap,
    selection: &CaseSelection,
    cancel: &AtomicBool,
    controller: &EngineControl,
    outcome: &mut EngineOutcome,
) -> ProofResult<()> {
    let &case_execution::ExecutionContext {
        host,
        profile,
        repo_root,
    } = context;
    for package in super::inventory::topological_packages(&selection.inventory)? {
        for (index, case) in selection
            .inventory
            .cases()
            .iter()
            .enumerate()
            .filter(|(_, case)| {
                case.package_id == package.package_id
                    && selection.selected_case_ids.contains(&case.case_id)
            })
        {
            if cancelled(host, cancel, controller, outcome)? {
                return Ok(());
            }
            let mut prerequisites_passed = true;
            for dependency in &package.requires {
                if selection
                    .inventory
                    .package_status(&outcome.run, &outcome.results, dependency)?
                    != PackageStatus::Passed
                {
                    prerequisites_passed = false;
                    break;
                }
            }
            if !prerequisites_passed {
                let error = ProofError::new(
                    ErrorCode::ProviderUnavailable,
                    "Required proof package has not passed",
                );
                outcome.results[index].status = CaseStatus::Blocked;
                outcome.results[index].error = Some(error);
            } else {
                match case_execution::execute(
                    host,
                    profile,
                    repo_root,
                    case,
                    bootstrap.fixture_manifest_sha256,
                ) {
                    Ok(result) => outcome.results[index] = result,
                    Err(error) => {
                        outcome.results[index] = failed(host, case, error.clone())?;
                        if outcome.error.is_none() {
                            outcome.error = Some(error.clone());
                        }
                        if matches!(
                            error.code,
                            ErrorCode::IntegrityError | ErrorCode::OutcomeUnknown
                        ) {
                            host.admission.invalidate_integrity();
                            return Err(error);
                        }
                    }
                }
            }
            if case.case_id.as_str() == "EXIT-01"
                && outcome.results[index].status == CaseStatus::Passed
            {
                outcome.run.dependency_record_refs =
                    exit_dependency_refs(host, &outcome.results[index])?;
            }
            if outcome.error.is_none() {
                outcome.error = outcome.results[index].error.clone();
            }
            persist(host, bootstrap, selection, profile, outcome)?;
            if cancelled(host, cancel, controller, outcome)? {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn exit_dependency_refs(host: &ProofHost, result: &CaseResult) -> ProofResult<Vec<EntityId>> {
    let Some(EvidenceRef::Artifact {
        artifact_id,
        sha256,
        range: None,
    }) = result.evidence_refs.first()
    else {
        return Err(integrity());
    };
    let artifact = host
        .evidence
        .artifact(host.project.project_id, *artifact_id)?;
    if artifact.sha256 != *sha256 || artifact.kind.as_str() != "case-execution-report" {
        return Err(integrity());
    }
    let invocation = host.ledger.read_invocation(artifact.origin_invocation_id)?;
    if invocation.invocation.tool_id.as_str() != "proof.case.execute"
        || invocation.invocation.output_ref != Some(*artifact_id)
        || invocation.invocation.state != crate::domain::values::InvocationState::Completed
    {
        return Err(integrity());
    }
    let bytes = host.evidence.read_artifact(
        host.project.project_id,
        *artifact_id,
        usize::try_from(artifact.length_bytes.get()).map_err(|_| integrity())?,
    )?;
    let report = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
    super::suites::exit::dependency_record_refs(&report)
}

fn cancelled(
    host: &ProofHost,
    cancel: &AtomicBool,
    controller: &EngineControl,
    outcome: &mut EngineOutcome,
) -> ProofResult<bool> {
    loop {
        let (mode, admission_open) = host.control.enclosing_dispatch_state()?;
        if cancel.load(Ordering::SeqCst) && mode != ControlMode::Cancelled {
            match controller.request_cancel() {
                Ok(_) => continue,
                Err(error) => {
                    if host
                        .ledger
                        .read_control(host.session.investigation_id)?
                        .mode
                        != ControlMode::Cancelled
                    {
                        return Err(error);
                    }
                }
            }
        } else if mode == ControlMode::Running && admission_open {
            return Ok(false);
        } else if mode != ControlMode::Cancelled {
            // Never occupy the independent control endpoint or retry any provider effect.
            std::thread::sleep(std::time::Duration::from_millis(10));
            continue;
        }
        outcome.interrupted = true;
        if outcome.error.is_none() {
            outcome.error = Some(ProofError::new(
                ErrorCode::Cancelled,
                "Engine run was cancelled",
            ));
        }
        return Ok(true);
    }
}

fn unexecuted(run_id: EntityId, case: &ProofCase) -> ProofResult<CaseResult> {
    Ok(CaseResult {
        run_id,
        case_id: case.case_id.clone(),
        status: CaseStatus::Unexecuted,
        expected: case.expected.clone(),
        observed: Assertions::new([])?,
        evidence_refs: Vec::new(),
        elapsed_us: WireInt::ZERO,
        usage: Usage::default(),
        error: None,
    })
}

fn failed(host: &ProofHost, case: &ProofCase, error: ProofError) -> ProofResult<CaseResult> {
    let mut result = unexecuted(host.workspace.run_id(), case)?;
    result.status = if error.code == ErrorCode::ProviderUnavailable {
        CaseStatus::Blocked
    } else {
        CaseStatus::Failed
    };
    if let Some(id) = error.invocation_id {
        let stored = host.ledger.read_invocation(id)?;
        if stored.invocation.tool_id.as_str() != "proof.case.execute" {
            return Err(integrity());
        }
        result.usage = stored.invocation.usage;
        result.elapsed_us = stored.invocation.usage.elapsed_us;
        for artifact in host
            .evidence
            .artifacts()?
            .iter()
            .filter(|artifact| artifact.origin_invocation_id == id)
        {
            if result.evidence_refs.len() == 128 {
                return Err(integrity());
            }
            result.evidence_refs.push(EvidenceRef::Artifact {
                artifact_id: artifact.artifact_id,
                sha256: artifact.sha256,
                range: None,
            });
        }
    }
    result.error = Some(error);
    result.validate()?;
    Ok(result)
}

fn persist(
    host: &ProofHost,
    bootstrap: &EngineBootstrap,
    selection: &CaseSelection,
    profile: &LoadedProfile,
    outcome: &mut EngineOutcome,
) -> ProofResult<()> {
    let trace = historical_trace(&host.ledger)?;
    outcome.trace_sha256 = Digest::of(&trace);
    outcome.trace_length_bytes = WireInt::new(trace.len() as u64)?;
    outcome.validate(bootstrap, selection, profile)?;
    let metadata = encode(outcome, MAX_METADATA_BYTES)?;
    host.workspace.atomic_write(
        Path::new(super::harness::LIVE_RUN_PATH),
        &encode(&outcome.run, MAX_METADATA_BYTES)?,
    )?;
    host.workspace.atomic_write(Path::new(TRACE_PATH), &trace)?;
    host.workspace
        .atomic_write(Path::new(OUTCOME_PATH), &metadata)?;
    Ok(())
}

fn historical_trace(ledger: &Ledger) -> ProofResult<Vec<u8>> {
    let mut trace = BoundedBuffer {
        bytes: Vec::new(),
        limit: MAX_TRACE_BYTES,
    };
    let mut cursor = WireInt::ZERO;
    loop {
        let page = ledger.event_page(cursor, 256)?;
        if page.events.is_empty() {
            break;
        }
        if page.last_position <= cursor {
            return Err(integrity());
        }
        cursor = page.last_position;
        for event in page.events {
            // Event's closed schema contains only identifiers, revision, timestamp,
            // and catalog tags: no raw bodies, capabilities, or filesystem paths.
            serde_json::to_writer(&mut trace, &event).map_err(|_| storage())?;
            trace.write_all(b"\n").map_err(|_| storage())?;
        }
    }
    Ok(trace.bytes)
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}
impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("Engine snapshot exceeds its finite bound"));
        }
        let required = self.bytes.len() + bytes.len();
        if required > self.bytes.capacity() {
            let capacity = required
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode(value: &impl Serialize, limit: usize) -> ProofResult<Vec<u8>> {
    let mut output = BoundedBuffer {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut output, value).map_err(|_| storage())?;
    Ok(output.bytes)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> ProofResult<T> {
    serde_json::from_slice(bytes).map_err(|_| integrity())
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Engine immutable source or durable state failed validation",
    )
}
fn storage() -> ProofError {
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Engine snapshot could not be encoded within its bound",
    )
}
fn unavailable() -> ProofError {
    ProofError::new(
        ErrorCode::ProviderUnavailable,
        "Engine host controller is unavailable",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::execution::Event;
    mod private_root {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/private_root.rs"
        ));
    }

    #[test]
    fn trace_exports_more_than_one_page_of_real_committed_control_changes() {
        let root = private_root::PrivateRoot::new();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = LoadedProfile::load(
            &repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let examples = std::fs::read(repository.join("fixtures/scenarios/contracts.json")).unwrap();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        let host = ProofHost::create(
            workspace.clone(),
            &profile,
            CanonicalFixtures::from_bytes(&examples).unwrap(),
            Digest::of(&examples),
            executable_digest().unwrap(),
        )
        .unwrap();
        let owner = OwnedControl::start(workspace, host.control.clone()).unwrap();
        let client = owner.client().unwrap();
        for _ in 0..140 {
            for action in [ControlAction::Pause, ControlAction::Resume] {
                let state = host
                    .ledger
                    .read_control(host.session.investigation_id)
                    .unwrap();
                client
                    .request(&ControlCommand {
                        request_id: EntityId::new(),
                        investigation_id: state.investigation_id,
                        expected_revision: state.revision,
                        action,
                    })
                    .unwrap();
            }
        }
        owner.shutdown().unwrap();
        let trace = historical_trace(&host.ledger).unwrap();
        let observed: Vec<Event> = trace
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect();
        assert!(observed.len() > 256);
        let mut expected = Vec::new();
        let mut cursor = WireInt::ZERO;
        loop {
            let page = host.ledger.event_page(cursor, 73).unwrap();
            if page.events.is_empty() {
                break;
            }
            cursor = page.last_position;
            expected.extend(page.events);
        }
        assert_eq!(observed, expected);
    }

    #[test]
    fn snapshot_buffer_accepts_exact_bound_without_allocating_or_returning_truncated_overflow() {
        let mut buffer = BoundedBuffer {
            bytes: Vec::new(),
            limit: 17,
        };
        for _ in 0..17 {
            buffer.write_all(b"x").unwrap();
        }
        assert_eq!(buffer.bytes.len(), 17);
        assert!(buffer.bytes.capacity() <= 17);
        assert!(buffer.write_all(b"x").is_err());
        assert_eq!(buffer.bytes, b"xxxxxxxxxxxxxxxxx");
    }

    #[test]
    fn review_paused_dispatch_waits_for_resume_instead_of_returning_permission_to_run_a_case() {
        use std::sync::mpsc::{self, RecvTimeoutError};
        use std::time::Duration;
        let root = private_root::PrivateRoot::new();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let profile = LoadedProfile::load(
            &repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let examples = std::fs::read(repository.join("fixtures/scenarios/contracts.json")).unwrap();
        let manifest = std::fs::read(repository.join("fixtures/scenarios/manifest.json")).unwrap();
        let selection =
            serde_json::from_slice::<super::super::harness::ScenarioManifest>(&manifest)
                .unwrap()
                .select(
                    super::super::cli::Suite::Contracts,
                    Some(&CatalogId::parse("CON-01").unwrap()),
                    Digest::of(&manifest),
                )
                .unwrap();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        let digest = executable_digest().unwrap();
        let host = ProofHost::create(
            workspace.clone(),
            &profile,
            CanonicalFixtures::from_bytes(&examples).unwrap(),
            Digest::of(&examples),
            digest,
        )
        .unwrap();
        let observed = environment::observe(
            &repository,
            &workspace,
            &profile,
            BTreeMap::from([
                (CatalogId::parse("razen-engine").unwrap(), digest),
                (CatalogId::parse("razen-proof").unwrap(), digest),
            ]),
            &selection.selected_case_ids,
        )
        .unwrap();
        let mut outcome = EngineOutcome {
            schema_version: ContractVersion::V0_1_0,
            run: Run {
                run_id: workspace.run_id(),
                contract_version: ContractVersion::V0_1_0,
                profile_id: profile.config().profile_id.clone(),
                profile_sha256: profile.sha256(),
                clock_epoch_id: host.control.clock_epoch_id(),
                started_at: AuditTime::now(),
                finished_at: None,
                environment: observed,
                dependency_record_refs: Vec::new(),
                fixture_manifest_sha256: Digest::of(&manifest),
            },
            results: selection
                .inventory
                .cases()
                .iter()
                .map(|case| unexecuted(workspace.run_id(), case))
                .collect::<ProofResult<Vec<_>>>()
                .unwrap(),
            trace_sha256: Digest::of(b""),
            trace_length_bytes: WireInt::ZERO,
            interrupted: false,
            error: None,
        };
        let owner = OwnedControl::start(workspace, host.control.clone()).unwrap();
        host.install_control_client(owner.client().unwrap())
            .unwrap();
        let client = host.control_client().unwrap();
        let investigation_id = host.session.investigation_id;
        client
            .request(&ControlCommand {
                request_id: EntityId::new(),
                investigation_id,
                expected_revision: WireInt::ZERO,
                action: ControlAction::Pause,
            })
            .unwrap();
        let controller = EngineControl {
            client: client.clone(),
            ledger: host.ledger.clone(),
            investigation_id,
        };
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = std::thread::spawn(move || {
            let result = cancelled(&host, &worker_cancel, &controller, &mut outcome);
            sender.send((result, outcome)).unwrap();
        });
        let premature = receiver.recv_timeout(Duration::from_millis(250));
        let returned_while_paused = premature.is_ok();
        let resumed = client.request(&ControlCommand {
            request_id: EntityId::new(),
            investigation_id,
            expected_revision: WireInt::new(1).unwrap(),
            action: ControlAction::Resume,
        });
        if resumed.is_err() {
            cancel.store(true, Ordering::SeqCst);
        }
        let completed = match premature {
            Ok(value) => value,
            Err(RecvTimeoutError::Timeout) => {
                receiver.recv_timeout(Duration::from_secs(3)).unwrap()
            }
            Err(error) => panic!("owned dispatcher disconnected: {error}"),
        };
        worker.join().unwrap();
        owner.shutdown().unwrap();
        resumed.unwrap();
        assert!(
            !returned_while_paused,
            "a paused dispatcher returned permission to execute"
        );
        assert!(!completed.0.unwrap());
        assert!(!completed.1.interrupted);
        assert!(completed.1.error.is_none());
    }
}
