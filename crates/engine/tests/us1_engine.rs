use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool, mpsc};
use std::thread;

use razen_engine::adapters::ledger::Ledger;
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::cli::Suite;
use razen_engine::application::engine::{EngineControl, execute};
use razen_engine::application::harness::{
    BOOTSTRAP_PATH, CaseSelection, EXAMPLES_PATH, EngineBootstrap, EngineOutcome, EngineReady,
    MAX_METADATA_BYTES, MAX_TRACE_BYTES, OUTCOME_PATH, READY_PATH, ScenarioManifest, TRACE_PATH,
};
use razen_engine::application::profile::LoadedProfile;
use razen_engine::domain::proofs::{CaseStatus, IsolationStatus};
use razen_engine::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, WireInt,
};
use razen_engine::protocol::error::{ErrorCode, ProofResult};
use sha2::{Digest as _, Sha256};

#[path = "support/owned_child.rs"]
mod owned_child;
#[path = "support/private_root.rs"]
mod private_root;

struct Fixture {
    root: private_root::PrivateRoot,
    repo: PathBuf,
    workspace: Arc<OwnedDirectory>,
    bootstrap: EngineBootstrap,
    selection: CaseSelection,
    profile: LoadedProfile,
}

fn binary_digest() -> Digest {
    let mut file = File::open(std::env::current_exe().unwrap()).unwrap();
    let mut hash = Sha256::new();
    let mut chunk = [0; 16384];
    loop {
        let count = file.read(&mut chunk).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&chunk[..count]);
    }
    Digest::from_sha256(hash.finalize().into())
}

impl Fixture {
    fn new(suite: Suite, case: Option<&str>, change: impl FnOnce(&mut EngineBootstrap)) -> Self {
        let root = private_root::PrivateRoot::new();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        let profile_bytes =
            fs::read(repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json")).unwrap();
        let profile = LoadedProfile::from_bytes(&profile_bytes).unwrap();
        let manifest = fs::read(repo.join("fixtures/scenarios/manifest.json")).unwrap();
        let examples = fs::read(repo.join("fixtures/scenarios/contracts.json")).unwrap();
        let selection = serde_json::from_slice::<ScenarioManifest>(&manifest)
            .unwrap()
            .select(
                suite,
                case.map(|id| CatalogId::parse(id).unwrap()).as_ref(),
                Digest::of(&manifest),
            )
            .unwrap();
        let mut bootstrap = EngineBootstrap {
            schema_version: ContractVersion::V0_1_0,
            run_id: workspace.run_id(),
            started_at: AuditTime::now(),
            profile_sha256: profile.sha256(),
            fixture_manifest_sha256: Digest::of(&manifest),
            contract_examples_sha256: Digest::of(&examples),
            orchestrator_sha256: binary_digest(),
        };
        change(&mut bootstrap);
        for (name, bytes) in [
            ("profile.json", profile_bytes),
            ("fixture-manifest.json", manifest),
            ("cases.json", serde_json::to_vec(&selection).unwrap()),
            (EXAMPLES_PATH, examples),
            (BOOTSTRAP_PATH, serde_json::to_vec(&bootstrap).unwrap()),
        ] {
            workspace.write_new(Path::new(name), &bytes).unwrap();
        }
        Self {
            root,
            repo,
            workspace,
            bootstrap,
            selection,
            profile,
        }
    }

    fn run(&self, cancelled: bool) -> (ProofResult<EngineOutcome>, mpsc::Receiver<EngineControl>) {
        let (ready, receiver) = mpsc::sync_channel(1);
        let result = execute(
            self.workspace.clone(),
            &self.repo,
            Arc::new(AtomicBool::new(cancelled)),
            ready,
        );
        (result, receiver)
    }

    fn outcome(&self) -> EngineOutcome {
        serde_json::from_slice(
            &self
                .workspace
                .read(Path::new(OUTCOME_PATH), MAX_METADATA_BYTES)
                .unwrap(),
        )
        .unwrap()
    }
}

#[test]
fn rejects_wrong_run_and_each_raw_source_digest_before_creating_host_state() {
    let changes: [fn(&mut EngineBootstrap); 4] = [
        |bootstrap| bootstrap.run_id = EntityId::new(),
        |bootstrap| bootstrap.profile_sha256 = Digest::of(b"other profile"),
        |bootstrap| bootstrap.fixture_manifest_sha256 = Digest::of(b"other manifest"),
        |bootstrap| bootstrap.contract_examples_sha256 = Digest::of(b"other examples"),
    ];
    for change in changes {
        let fixture = Fixture::new(Suite::Contracts, Some("CON-01"), change);
        let (result, ready) = fixture.run(false);
        assert_eq!(result.unwrap_err().code, ErrorCode::IntegrityError);
        assert!(ready.try_recv().is_err());
        assert!(!fixture.workspace.path().join("ledger.sqlite").exists());
        assert!(!fixture.workspace.path().join(OUTCOME_PATH).exists());
    }
}

#[test]
fn contracts_execute_real_campaigns_leave_other_thirty_unexecuted_and_persist_exact_trace() {
    let fixture = Fixture::new(Suite::Contracts, None, |_| {});
    let (result, ready) = fixture.run(false);
    let outcome = result.unwrap();
    let controller = ready.recv().unwrap();
    outcome
        .validate(&fixture.bootstrap, &fixture.selection, &fixture.profile)
        .unwrap();
    assert_eq!(outcome.results.len(), 35);
    assert!(
        outcome.results[..5]
            .iter()
            .all(|result| result.status == CaseStatus::Passed
                && !result.evidence_refs.is_empty()
                && result.usage.units.get() == 1
                && result.usage.bytes.get() > 0)
    );
    assert!(
        outcome.results[5..]
            .iter()
            .all(|result| result.status == CaseStatus::Unexecuted
                && result.evidence_refs.is_empty()
                && result.observed.iter().next().is_none()
                && result.usage == Default::default())
    );
    assert!(!outcome.interrupted);
    assert!(outcome.error.is_none());
    assert!(outcome.run.finished_at.is_some());
    assert_eq!(
        outcome.run.environment.isolation_status,
        IsolationStatus::NotRequired
    );
    assert_eq!(
        outcome.run.environment.binary_digests[&CatalogId::parse("razen-engine").unwrap()],
        binary_digest()
    );
    assert_eq!(
        outcome.run.environment.binary_digests[&CatalogId::parse("razen-proof").unwrap()],
        fixture.bootstrap.orchestrator_sha256
    );
    assert!(outcome.run.dependency_record_refs.is_empty());
    let ready: EngineReady = serde_json::from_slice(
        &fixture
            .workspace
            .read(Path::new(READY_PATH), MAX_METADATA_BYTES)
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ready.run_id, fixture.workspace.run_id());
    assert_eq!(ready.engine_pid.get(), u64::from(std::process::id()));
    assert_eq!(ready.clock_epoch_id, outcome.run.clock_epoch_id);
    assert!(
        !Path::new("/private/tmp")
            .join(format!("razen-ctl-{}", ready.control_resource_id))
            .exists()
    );
    let persisted = fixture.outcome();
    assert_eq!(
        serde_json::to_value(&persisted).unwrap(),
        serde_json::to_value(&outcome).unwrap()
    );
    let trace = fixture
        .workspace
        .read(Path::new(TRACE_PATH), MAX_TRACE_BYTES)
        .unwrap();
    assert_eq!(Digest::of(&trace), outcome.trace_sha256);
    assert_eq!(trace.len() as u64, outcome.trace_length_bytes.get());
    drop(controller);
    let ledger = Ledger::open(&fixture.workspace, &fixture.profile).unwrap();
    let mut cursor = WireInt::ZERO;
    let mut expected = Vec::new();
    loop {
        let page = ledger.event_page(cursor, 256).unwrap();
        if page.events.is_empty() {
            break;
        }
        cursor = page.last_position;
        for event in page.events {
            serde_json::to_writer(&mut expected, &event).unwrap();
            expected.push(b'\n');
        }
    }
    assert_eq!(
        trace, expected,
        "trace contains every durable event in historical order"
    );
    assert_eq!(
        ledger
            .invocations()
            .unwrap()
            .iter()
            .filter(|entry| entry.invocation.tool_id.as_str() == "proof.case.execute")
            .count(),
        5
    );
}

#[test]
fn preexisting_cancel_still_publishes_owned_final_state_without_admitting_any_case() {
    let fixture = Fixture::new(Suite::Contracts, None, |_| {});
    let (result, ready) = fixture.run(true);
    let outcome = result.unwrap();
    drop(ready.recv().unwrap());
    outcome
        .validate(&fixture.bootstrap, &fixture.selection, &fixture.profile)
        .unwrap();
    assert!(outcome.interrupted);
    assert_eq!(outcome.error.as_ref().unwrap().code, ErrorCode::Cancelled);
    assert!(outcome.run.finished_at.is_some());
    assert!(
        outcome
            .results
            .iter()
            .all(|result| result.status == CaseStatus::Unexecuted)
    );
    let ledger = Ledger::open(&fixture.workspace, &fixture.profile).unwrap();
    assert!(
        ledger
            .controls()
            .unwrap()
            .iter()
            .all(|state| !state.admission_open)
    );
    assert!(
        ledger
            .invocations()
            .unwrap()
            .iter()
            .all(|entry| entry.invocation.tool_id.as_str() != "proof.case.execute")
    );
}

#[test]
fn closed_ready_receiver_fails_visibly_and_joins_owned_control_without_running_cases() {
    let fixture = Fixture::new(Suite::Contracts, Some("CON-01"), |_| {});
    let (ready, receiver) = mpsc::sync_channel(1);
    drop(receiver);
    assert!(
        execute(
            fixture.workspace.clone(),
            &fixture.repo,
            Arc::new(AtomicBool::new(false)),
            ready
        )
        .is_err()
    );
    let record: EngineReady = serde_json::from_slice(
        &fixture
            .workspace
            .read(Path::new(READY_PATH), MAX_METADATA_BYTES)
            .unwrap(),
    )
    .unwrap();
    assert!(
        !Path::new("/private/tmp")
            .join(format!("razen-ctl-{}", record.control_resource_id))
            .exists()
    );
    let outcome = fixture.outcome();
    assert!(outcome.error.is_some());
    assert!(
        outcome
            .results
            .iter()
            .all(|result| result.status == CaseStatus::Unexecuted)
    );
}

#[test]
fn reopening_a_completed_workspace_never_adopts_its_previous_host_authority() {
    let fixture = Fixture::new(Suite::Contracts, Some("CON-01"), |_| {});
    let (first, ready) = fixture.run(false);
    first.unwrap();
    drop(ready.recv().unwrap());
    let before = fixture
        .workspace
        .read(Path::new(OUTCOME_PATH), MAX_METADATA_BYTES)
        .unwrap();
    let reopened = Arc::new(OwnedDirectory::open(fixture.root.path(), Path::new("run")).unwrap());
    let (sender, receiver) = mpsc::sync_channel(1);
    assert!(
        execute(
            reopened,
            &fixture.repo,
            Arc::new(AtomicBool::new(false)),
            sender
        )
        .is_err()
    );
    assert!(receiver.try_recv().is_err());
    assert_eq!(
        fixture
            .workspace
            .read(Path::new(OUTCOME_PATH), MAX_METADATA_BYTES)
            .unwrap(),
        before
    );
}

#[test]
fn host_controller_cancels_real_durable_state_while_worker_is_active() {
    let fixture = Fixture::new(Suite::Contracts, None, |_| {});
    let (sender, receiver) = mpsc::sync_channel(1);
    let workspace = fixture.workspace.clone();
    let repo = fixture.repo.clone();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = cancel.clone();
    let worker = thread::spawn(move || execute(workspace, &repo, worker_cancel, sender));
    let controller = receiver.recv().unwrap();
    let ack = controller.request_cancel().unwrap();
    assert!(!ack.state.admission_open);
    assert_eq!(
        ack.state.mode,
        razen_engine::domain::execution::ControlMode::Cancelled
    );
    assert!(ack.measurement.acknowledged_us.get() - ack.measurement.received_us.get() <= 1_000_000);
    let outcome = worker.join().unwrap().unwrap();
    assert_eq!(ack.measurement.clock_epoch_id, outcome.run.clock_epoch_id);
    assert!(outcome.interrupted);
    assert!(
        outcome
            .results
            .iter()
            .any(|result| result.status == CaseStatus::Unexecuted)
    );
    drop(controller);
    let ledger = Ledger::open(&fixture.workspace, &fixture.profile).unwrap();
    assert_eq!(
        ledger.read_control(ack.state.investigation_id).unwrap(),
        ack.state
    );
}

#[test]
fn self_consistent_copied_examples_cannot_repin_the_actual_repository_fixture() {
    let mut fixture = Fixture::new(Suite::Contracts, Some("CON-01"), |_| {});
    let path = fixture.workspace.path().join(EXAMPLES_PATH);
    let mut bytes = fs::read(&path).unwrap();
    bytes.push(b'\n');
    fixture.bootstrap.contract_examples_sha256 = Digest::of(&bytes);
    // Adversarial replacement of both private inputs still cannot replace the
    // independent trusted repository observation.
    fs::write(path, &bytes).unwrap();
    fs::write(
        fixture.workspace.path().join(BOOTSTRAP_PATH),
        serde_json::to_vec(&fixture.bootstrap).unwrap(),
    )
    .unwrap();
    let (result, ready) = fixture.run(false);
    assert_eq!(result.unwrap_err().code, ErrorCode::IntegrityError);
    assert!(ready.try_recv().is_err());
    assert!(!fixture.workspace.path().join("ledger.sqlite").exists());
}

#[test]
fn actual_engine_parent_eof_commits_cancellation_before_cases_and_leaves_unrelated_process_alive() {
    let fixture = Fixture::new(Suite::Contracts, None, |_| {});
    let mut unrelated = owned_child::OwnedChild::sleep();
    let lease =
        razen_engine::application::harness::EngineLease::create(&fixture.workspace).unwrap();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_razen-engine"));
    command
        .arg("--workspace")
        .arg(fixture.workspace.path().canonicalize().unwrap())
        .arg("--run-id")
        .arg(fixture.workspace.run_id().to_string())
        .current_dir(&fixture.repo)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("LC_ALL", "C")
        .stdin(std::process::Stdio::null())
        .stdout(lease.child_stdio().unwrap())
        .stderr(std::process::Stdio::null());
    let mut engine = owned_child::OwnedChild::spawn(&mut command);
    drop(command);
    drop(lease);
    assert_eq!(engine.wait_for_exit().code(), Some(4));
    let outcome = fixture.outcome();
    outcome
        .validate(&fixture.bootstrap, &fixture.selection, &fixture.profile)
        .unwrap();
    assert!(outcome.interrupted);
    assert_eq!(outcome.error.as_ref().unwrap().code, ErrorCode::Cancelled);
    assert!(
        outcome
            .results
            .iter()
            .all(|result| result.status == CaseStatus::Unexecuted)
    );
    let ledger = Ledger::open_readonly(&fixture.workspace, &fixture.profile).unwrap();
    assert!(ledger.controls().unwrap().iter().all(|state| state.mode
        == razen_engine::domain::execution::ControlMode::Cancelled
        && !state.admission_open));
    assert!(
        ledger
            .invocations()
            .unwrap()
            .iter()
            .all(|row| row.invocation.tool_id.as_str() != "proof.case.execute")
    );
    unrelated.assert_running();
    unrelated.kill_and_wait();
}

#[test]
fn killed_startup_before_ready_keeps_inherited_lease_until_real_child_exit_and_can_be_cleaned() {
    use razen_engine::application::harness::{ENGINE_LEASE_PATH, EngineLease};
    use rustix::fs::{FlockOperation, flock};
    let fixture = Fixture::new(Suite::Contracts, Some("CON-01"), |_| {});
    let lease = EngineLease::create(&fixture.workspace).unwrap();
    // Block the actual engine before its first workspace read, not through a
    // fake READY or an injected execution/provider outcome.
    let directory = File::open(fixture.workspace.path()).unwrap();
    flock(&directory, FlockOperation::LockExclusive).unwrap();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_razen-engine"));
    command
        .args(["--workspace"])
        .arg(fixture.workspace.path())
        .arg("--run-id")
        .arg(fixture.workspace.run_id().to_string())
        .current_dir(&fixture.repo)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(std::process::Stdio::piped())
        .stdout(lease.child_stdio().unwrap())
        .stderr(std::process::Stdio::null());
    let mut engine = owned_child::OwnedChild::spawn(&mut command);
    drop(command);
    drop(lease); // Simulates losing every orchestrator-side lease descriptor.
    let independent = File::open(fixture.workspace.path().join(ENGINE_LEASE_PATH)).unwrap();
    assert!(
        flock(&independent, FlockOperation::NonBlockingLockExclusive).is_err(),
        "the forked engine must already hold the very same locked native object"
    );
    engine.assert_running();
    engine.kill_and_wait();
    drop(directory);
    assert!(!fixture.workspace.path().join(READY_PATH).exists());
    let quiescent = EngineLease::quiescent(&fixture.workspace).unwrap().unwrap();
    drop(quiescent);
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_razen-proof"))
        .arg("cleanup")
        .arg("--run")
        .arg(fixture.workspace.path())
        .current_dir(&fixture.repo)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert!(!fixture.workspace.path().join(BOOTSTRAP_PATH).exists());
    assert!(fixture.workspace.path().join(ENGINE_LEASE_PATH).exists());
    assert!(!fixture.workspace.path().join("run.json").exists());
}

#[test]
fn killed_engine_control_resource_is_authenticated_and_reclaimed_before_ownership_records_disappear()
 {
    use razen_engine::application::harness::EngineLease;
    let fixture = Fixture::new(Suite::Contracts, None, |_| {});
    let lease = EngineLease::create(&fixture.workspace).unwrap();
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_razen-engine"));
    command
        .arg("--workspace")
        .arg(fixture.workspace.path())
        .arg("--run-id")
        .arg(fixture.workspace.run_id().to_string())
        .current_dir(&fixture.repo)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .stdin(std::process::Stdio::piped())
        .stdout(lease.child_stdio().unwrap())
        .stderr(std::process::Stdio::null());
    let mut engine = owned_child::OwnedChild::spawn(&mut command);
    drop(command);
    drop(lease);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    let ready: EngineReady = loop {
        if let Ok(bytes) = fixture
            .workspace
            .read(Path::new(READY_PATH), MAX_METADATA_BYTES)
        {
            break serde_json::from_slice(&bytes).unwrap();
        }
        assert!(std::time::Instant::now() < deadline);
        engine.assert_running();
        thread::sleep(std::time::Duration::from_millis(5));
    };
    assert!(EngineLease::quiescent(&fixture.workspace).is_err());
    #[cfg(target_os = "macos")]
    let base = Path::new("/private/tmp");
    #[cfg(not(target_os = "macos"))]
    let base = Path::new("/tmp");
    let auxiliary = base.join(format!("razen-ctl-{}", ready.control_resource_id));
    assert!(auxiliary.join("ephemeral/control.sock").exists());
    assert!(auxiliary.join("ephemeral/control.token").exists());
    engine.kill_and_wait();
    let ledger_before = fs::read(fixture.workspace.path().join("ledger.sqlite")).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_razen-proof"))
        .arg("cleanup")
        .arg("--run")
        .arg(fixture.workspace.path())
        .current_dir(&fixture.repo)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0), "{:?}", output.stderr);
    assert!(!auxiliary.exists());
    assert_eq!(
        fs::read(fixture.workspace.path().join("ledger.sqlite")).unwrap(),
        ledger_before
    );
    assert!(
        !fixture
            .workspace
            .path()
            .join(format!(
                "ephemeral/control-resource-{}.json",
                ready.control_resource_id
            ))
            .exists()
    );
}

#[test]
fn replacement_execution_lease_never_proves_original_engine_quiescence() {
    use razen_engine::application::harness::{ENGINE_LEASE_PATH, EngineLease};
    use std::os::unix::fs::PermissionsExt;
    let fixture = Fixture::new(Suite::Contracts, Some("CON-01"), |_| {});
    let lease = EngineLease::create(&fixture.workspace).unwrap();
    let path = fixture.workspace.path().join(ENGINE_LEASE_PATH);
    let bytes = fs::read(&path).unwrap();
    fs::rename(
        &path,
        fixture
            .workspace
            .path()
            .join("retained-original-lease.json"),
    )
    .unwrap();
    fs::write(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(EngineLease::quiescent(&fixture.workspace).is_err());
    drop(lease);
    assert!(
        EngineLease::quiescent(&fixture.workspace).is_err(),
        "closing the old holder cannot authorize a substituted native object"
    );
}
