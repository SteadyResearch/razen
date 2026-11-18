use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use razen_engine::adapters::ledger::Ledger;
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::control::{
    ControlAction, ControlClient, ControlCommand, ControlServer, ControlService,
};
use razen_engine::application::profile::LoadedProfile;
use razen_engine::domain::execution::ControlState;
use razen_engine::domain::values::{EntityId, WireInt};
use razen_engine::protocol::error::ErrorCode;
use rusqlite::{Connection, OpenFlags};
use serde_json::{Value, json};

struct TestRun {
    workspace: Arc<OwnedDirectory>,
    profile: LoadedProfile,
    investigation: EntityId,
}

impl TestRun {
    fn new() -> Self {
        let run_id = EntityId::new();
        // macOS Unix socket names are bounded; this is a unique, marked private run.
        let relative = format!("rz-control-{run_id}");
        let workspace = Arc::new(
            OwnedDirectory::create(Path::new("/private/tmp"), Path::new(&relative), run_id)
                .unwrap(),
        );
        let profile = LoadedProfile::load(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        Self {
            workspace,
            profile,
            investigation: EntityId::new(),
        }
    }

    fn start(
        &self,
    ) -> (
        Arc<Ledger>,
        Arc<ControlService>,
        ControlServer,
        ControlClient,
    ) {
        let ledger = Arc::new(Ledger::create(&self.workspace, &self.profile).unwrap());
        let state: ControlState = serde_json::from_value(json!({
            "investigation_id": self.investigation, "revision": 0,
            "mode": "running", "admission_open": true, "instruction_ref": EntityId::new()
        }))
        .unwrap();
        ledger
            .insert_control(&state, EntityId::new(), WireInt::ZERO)
            .unwrap();
        let service = Arc::new(
            ControlService::new(Arc::clone(&ledger), &self.profile, self.investigation).unwrap(),
        );
        let server =
            ControlServer::start(Arc::clone(&self.workspace), Arc::clone(&service)).unwrap();
        let client = ControlClient::new(&self.workspace).unwrap();
        (ledger, service, server, client)
    }

    fn command(&self, revision: u64, action: ControlAction) -> ControlCommand {
        ControlCommand {
            request_id: EntityId::new(),
            investigation_id: self.investigation,
            expected_revision: WireInt::new(revision).unwrap(),
            action,
        }
    }
}

impl Drop for TestRun {
    fn drop(&mut self) {
        let result = std::fs::remove_dir_all(self.workspace.path());
        if !thread::panicking() {
            result.expect("remove only this test's newly created private run");
        }
    }
}

#[test]
fn ten_durable_control_barriers_complete_while_a_consumer_is_actually_blocked() {
    let run = TestRun::new();
    let (ledger, service, server, client) = run.start();
    let (entered_tx, entered_rx) = mpsc::sync_channel(1);
    let (release_tx, release_rx) = mpsc::sync_channel(1);
    let consumer = thread::spawn(move || {
        entered_tx.send(()).unwrap();
        release_rx
            .recv_timeout(Duration::from_secs(10))
            .expect("release blocked owned consumer");
    });
    entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    let mut revision = 0;
    for _ in 0..10 {
        service
            .check_admission(run.investigation, WireInt::new(revision).unwrap())
            .unwrap();
        let command = run.command(revision, ControlAction::Pause);
        let ack = client.request(&command).unwrap();
        revision += 1;
        assert_eq!(ack.request_id, command.request_id);
        assert!(ack.measurement.ack_elapsed_us().unwrap().get() <= 1_000_000);
        assert_eq!(ack.measurement.late_admissions.get(), 0);
        assert_eq!(ack.measurement.affected_revision.get(), revision);
        let stored = serde_json::to_value(ledger.read_control(run.investigation).unwrap()).unwrap();
        assert_eq!(stored["revision"], revision);
        assert_eq!(stored["mode"], "paused");
        assert_eq!(stored["admission_open"], false);
        assert_eq!(serde_json::to_value(&ack.state).unwrap(), stored);
        for _ in 0..32 {
            assert!(
                service
                    .check_admission(run.investigation, WireInt::new(revision - 1).unwrap())
                    .is_err()
            );
        }
        let resumed = client
            .request(&run.command(revision, ControlAction::Resume))
            .unwrap();
        revision += 1;
        assert_eq!(resumed.measurement.affected_revision.get(), revision);
    }
    release_tx.send(()).unwrap();
    consumer.join().unwrap();
    server.shutdown().unwrap();
    drop(client);
    drop(service);
    drop(ledger);
    let reopened = Ledger::open(&run.workspace, &run.profile).unwrap();
    assert_eq!(
        serde_json::to_value(reopened.read_control(run.investigation).unwrap()).unwrap()["revision"],
        20
    );
}

#[test]
fn unauthenticated_control_changes_nothing_and_a_subsequent_authenticated_request_succeeds() {
    let run = TestRun::new();
    let (ledger, _service, server, client) = run.start();
    let command = run.command(0, ControlAction::Pause);
    let mut stream =
        UnixStream::connect(run.workspace.path().join("ephemeral/control.sock")).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut request = serde_json::to_vec(&json!({
        "protocol": "razen.control/0.1.0", "capability": "0".repeat(64), "command": command
    }))
    .unwrap();
    request.push(b'\n');
    stream.write_all(&request).unwrap();
    let mut response = Vec::new();
    BufReader::new(stream)
        .take(4097)
        .read_until(b'\n', &mut response)
        .unwrap();
    assert!(response.len() <= 4096);
    let response: Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(response["error"]["code"], "permission_denied");
    let unchanged = serde_json::to_value(ledger.read_control(run.investigation).unwrap()).unwrap();
    assert_eq!(unchanged["revision"], 0);
    assert_eq!(unchanged["admission_open"], true);
    let ack = client
        .request(&run.command(0, ControlAction::Pause))
        .unwrap();
    assert_eq!(ack.measurement.affected_revision.get(), 1);
    server.shutdown().unwrap();
}

#[test]
fn stale_resume_cannot_reopen_admission_or_move_the_durable_revision_backwards() {
    let run = TestRun::new();
    let (ledger, service, server, client) = run.start();
    client
        .request(&run.command(0, ControlAction::Pause))
        .unwrap();
    let error = client
        .request(&run.command(0, ControlAction::Resume))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::StaleSnapshot);
    let state = serde_json::to_value(ledger.read_control(run.investigation).unwrap()).unwrap();
    assert_eq!(state["revision"], 1);
    assert_eq!(state["admission_open"], false);
    assert!(
        service
            .check_admission(run.investigation, WireInt::ZERO)
            .is_err()
    );
    client
        .request(&run.command(1, ControlAction::Resume))
        .unwrap();
    assert!(
        service
            .check_admission(run.investigation, WireInt::ZERO)
            .is_err()
    );
    service
        .check_admission(run.investigation, WireInt::new(2).unwrap())
        .unwrap();
    server.shutdown().unwrap();
}

#[test]
fn a_real_sqlite_writer_conflict_closes_admission_before_waiting_and_never_returns_an_active_ack() {
    let run = TestRun::new();
    let (ledger, service, server, client) = run.start();
    let path = run
        .workspace
        .path()
        .join("ledger.sqlite")
        .canonicalize()
        .unwrap();
    let blocker = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .unwrap();
    blocker.execute_batch("BEGIN IMMEDIATE").unwrap();
    let command = run.command(0, ControlAction::Pause);
    let request = thread::spawn(move || client.request(&command));
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if service
            .check_admission(run.investigation, WireInt::ZERO)
            .is_err()
        {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "receipt did not close admission independently of SQLite"
        );
        thread::sleep(Duration::from_millis(1));
    }
    let error = request.join().unwrap().unwrap_err();
    assert_eq!(error.code, ErrorCode::IntegrityError);
    blocker.execute_batch("ROLLBACK").unwrap();
    assert!(
        service
            .check_admission(run.investigation, WireInt::ZERO)
            .is_err()
    );
    let state = serde_json::to_value(ledger.read_control(run.investigation).unwrap()).unwrap();
    assert_eq!(
        state["revision"], 0,
        "failed persistence must not be acknowledged as a new revision"
    );
    server.shutdown().unwrap();
}
