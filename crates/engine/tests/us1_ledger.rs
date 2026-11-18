use std::path::Path;

use razen_engine::adapters::ledger::{Ledger, StoredInvocation};
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::profile::LoadedProfile;
use razen_engine::domain::authority::Budget;
use razen_engine::domain::execution::{Checkpoint, ControlMode, Event};
use razen_engine::domain::invocation::InvocationHistory;
use razen_engine::domain::values::{AuditTime, EntityId, InvocationState, WireInt};
use razen_engine::protocol::contracts::{CanonicalFixtures, ContractRecord};
use razen_engine::protocol::error::{ErrorCode, ProofError};
use serde_json::{Value, json};

struct TestRun {
    workspace: OwnedDirectory,
    profile: LoadedProfile,
}

impl TestRun {
    fn new() -> Self {
        let run_id = EntityId::new();
        let relative = format!("razen-us1-ledger-{run_id}");
        let workspace =
            OwnedDirectory::create(&std::env::temp_dir(), Path::new(&relative), run_id).unwrap();
        let profile = LoadedProfile::load(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        Self { workspace, profile }
    }

    fn create(&self) -> Ledger {
        Ledger::create(&self.workspace, &self.profile).unwrap()
    }
}

impl Drop for TestRun {
    fn drop(&mut self) {
        let result = std::fs::remove_dir_all(self.workspace.path());
        if !std::thread::panicking() {
            result.expect("remove only this test's uniquely created run directory");
        }
    }
}

fn count(value: u64) -> WireInt {
    WireInt::new(value).unwrap()
}

fn budget(id: EntityId, parent: Option<EntityId>, limit: u64) -> Budget {
    let mut value = json!({
        "budget_id": id, "limit": limit, "consumed": 0, "reserved": 0, "revision": 0
    });
    if let Some(parent) = parent {
        value["parent_budget_id"] = json!(parent);
    }
    serde_json::from_value(value).unwrap()
}

fn event(project: EntityId, aggregate: EntityId, sequence: u64) -> Event {
    serde_json::from_value(json!({
        "event_id": EntityId::new(), "schema_version": "0.1.0", "project_id": project,
        "aggregate_id": aggregate, "aggregate_sequence": sequence,
        "event_type": "quota.reserved", "timestamp": AuditTime::now(),
        "correlation_id": EntityId::new(), "causation_id": EntityId::new(),
        "control_revision": 0, "data_refs": [aggregate], "published": false
    }))
    .unwrap()
}

fn checkpoint(run: &TestRun, budget_id: EntityId) -> Checkpoint {
    serde_json::from_value(json!({
        "checkpoint_id": EntityId::new(), "run_id": run.workspace.run_id(),
        "schema_version": "0.1.0", "control_revision": 0, "scope_revision": 0,
        "budget_refs": [budget_id], "invocation_refs": [], "lease_refs": [],
        "event_cursors": {}, "created_at": AuditTime::now()
    }))
    .unwrap()
}

fn budget_json(ledger: &Ledger, id: EntityId) -> Value {
    serde_json::to_value(ledger.read_budget(id).unwrap()).unwrap()
}

#[test]
fn ledger_applies_the_pinned_durability_settings_and_excludes_a_second_writer() {
    let run = TestRun::new();
    let ledger = run.create();
    let settings = ledger.settings().unwrap();
    assert_eq!(settings.journal_mode, "delete");
    assert_eq!(settings.synchronous, 2);
    assert!(settings.fullfsync);
    assert!(settings.foreign_keys);
    assert_eq!(settings.busy_timeout_ms, 250);
    let error = Ledger::open(&run.workspace, &run.profile)
        .err()
        .expect("second writer must be refused");
    assert_eq!(error.code, ErrorCode::IntegrityError);
}

#[test]
fn child_escrow_is_backed_once_and_failed_reservations_change_neither_balance() {
    let run = TestRun::new();
    let ledger = run.create();
    let parent = EntityId::new();
    let child = EntityId::new();
    ledger.insert_budget(&budget(parent, None, 10)).unwrap();
    let error = ledger
        .insert_budget(&budget(child, Some(parent), 5))
        .unwrap_err();
    assert_eq!(
        error.code,
        ErrorCode::PermissionDenied,
        "A bare child cannot invent backing"
    );
    ledger
        .transaction(|tx| tx.allocate_child(parent, child, count(5), count(0)))
        .unwrap();
    ledger
        .transaction(|tx| tx.reserve_budget(child, count(4), count(0)))
        .unwrap();
    for (id, reserved) in [(parent, 5), (child, 4)] {
        let stored = budget_json(&ledger, id);
        assert_eq!(stored["reserved"], reserved);
        assert_eq!(stored["consumed"], 0);
        assert_eq!(stored["revision"], 1);
    }
    let before = [budget_json(&ledger, parent), budget_json(&ledger, child)];
    let error = ledger
        .transaction(|tx| tx.reserve_budget(child, count(2), count(1)))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::BudgetExhausted);
    assert_eq!(
        [budget_json(&ledger, parent), budget_json(&ledger, child)],
        before
    );
}

#[test]
fn sibling_allocations_share_the_actual_parent_balance_instead_of_copying_it() {
    let run = TestRun::new();
    let ledger = run.create();
    let parent = EntityId::new();
    let first = EntityId::new();
    let second = EntityId::new();
    ledger.insert_budget(&budget(parent, None, 5)).unwrap();
    ledger
        .transaction(|tx| tx.allocate_child(parent, first, count(4), count(0)))
        .unwrap();
    let error = ledger
        .transaction(|tx| tx.allocate_child(parent, second, count(2), count(1)))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::BudgetExhausted);
    assert_eq!(budget_json(&ledger, parent)["reserved"], 4);
    assert!(
        ledger.read_budget(second).is_err(),
        "Failed allocation left an unbacked child"
    );
    ledger
        .transaction(|tx| tx.allocate_child(parent, second, count(1), count(1)))
        .unwrap();
    ledger
        .transaction(|tx| tx.reserve_budget(first, count(4), count(0)))
        .unwrap();
    ledger
        .transaction(|tx| tx.reserve_budget(second, count(1), count(0)))
        .unwrap();
    assert_eq!(budget_json(&ledger, parent)["reserved"], 5);
    assert_eq!(budget_json(&ledger, first)["reserved"], 4);
    assert_eq!(budget_json(&ledger, second)["reserved"], 1);
}

#[test]
fn settling_usage_releases_only_unspent_reservation_and_survives_reopening() {
    let run = TestRun::new();
    let parent = EntityId::new();
    let child = EntityId::new();
    {
        let ledger = run.create();
        ledger.insert_budget(&budget(parent, None, 10)).unwrap();
        ledger
            .transaction(|tx| tx.allocate_child(parent, child, count(5), count(0)))
            .unwrap();
        ledger
            .transaction(|tx| tx.reserve_budget(child, count(4), count(0)))
            .unwrap();
        ledger
            .transaction(|tx| tx.settle_budget(child, count(4), count(3), count(1)))
            .unwrap();
    }
    let reopened = Ledger::open(&run.workspace, &run.profile).unwrap();
    for (id, reserved) in [(parent, 2), (child, 0)] {
        let stored = budget_json(&reopened, id);
        assert_eq!(stored["consumed"], 3);
        assert_eq!(stored["reserved"], reserved);
        assert_eq!(stored["revision"], 2);
    }
    let before = budget_json(&reopened, child);
    let error = reopened
        .transaction(|tx| tx.reserve_budget(child, count(1), count(0)))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::StaleSnapshot);
    assert_eq!(budget_json(&reopened, child), before);
}

#[test]
fn quota_outbox_and_checkpoint_rollback_together_and_commit_together() {
    let run = TestRun::new();
    let ledger = run.create();
    let budget_id = EntityId::new();
    ledger.insert_budget(&budget(budget_id, None, 10)).unwrap();
    let expected_event = event(EntityId::new(), budget_id, 1);
    let expected_checkpoint = checkpoint(&run, budget_id);
    let error = ledger
        .transaction(|tx| {
            tx.reserve_budget(budget_id, count(3), count(0))?;
            tx.append_event(&expected_event)?;
            tx.write_checkpoint(&expected_checkpoint)?;
            Err::<(), _>(ProofError::new(
                ErrorCode::Cancelled,
                "Deliberate transaction abort",
            ))
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(budget_json(&ledger, budget_id)["reserved"], 0);
    assert!(ledger.outbox(256).unwrap().is_empty());
    assert!(ledger.latest_checkpoint().unwrap().is_none());
    ledger
        .transaction(|tx| {
            tx.reserve_budget(budget_id, count(3), count(0))?;
            tx.append_event(&expected_event)?;
            tx.write_checkpoint(&expected_checkpoint)
        })
        .unwrap();
    assert_eq!(budget_json(&ledger, budget_id)["reserved"], 3);
    assert_eq!(
        serde_json::to_value(ledger.outbox(256).unwrap()).unwrap(),
        json!([expected_event])
    );
    assert_eq!(
        serde_json::to_value(ledger.latest_checkpoint().unwrap().unwrap()).unwrap(),
        json!(expected_checkpoint)
    );
}

#[test]
fn checkpoint_history_keeps_pace_with_events_without_resetting_budget() {
    let run = TestRun::new();
    let ledger = run.create();
    let budget_id = EntityId::new();
    ledger.insert_budget(&budget(budget_id, None, 10)).unwrap();
    let project = EntityId::new();
    let aggregate = EntityId::new();
    let expected: Vec<_> = (1..=4097)
        .map(|sequence| event(project, aggregate, sequence))
        .collect();
    let mut latest = checkpoint(&run, budget_id);
    ledger
        .transaction(|tx| {
            tx.reserve_budget(budget_id, count(3), WireInt::ZERO)?;
            for event in &expected {
                latest.checkpoint_id = EntityId::new();
                latest
                    .event_cursors
                    .insert(aggregate, event.aggregate_sequence);
                tx.append_event(event)?;
                tx.write_checkpoint(&latest)?;
            }
            Ok(())
        })
        .unwrap();
    drop(ledger);
    let ledger = Ledger::open(&run.workspace, &run.profile).unwrap();
    assert_eq!(ledger.latest_checkpoint().unwrap().unwrap(), latest);
    let restored = ledger.read_budget(budget_id).unwrap();
    assert_eq!(restored.reserved, count(3));
    assert_eq!(restored.consumed, WireInt::ZERO);
    assert_eq!(restored.limit, count(10));
    let mut cursor = WireInt::ZERO;
    let mut observed = Vec::new();
    loop {
        let page = ledger.event_page(cursor, 73).unwrap();
        if page.events.is_empty() {
            break;
        }
        cursor = page.last_position;
        observed.extend(page.events);
    }
    assert_eq!(observed, expected);
}

#[test]
fn outbox_rejects_duplicate_identity_and_duplicate_aggregate_sequence_without_losing_prior_events()
{
    let run = TestRun::new();
    let ledger = run.create();
    let project = EntityId::new();
    let aggregate = EntityId::new();
    let first = event(project, aggregate, 1);
    ledger.transaction(|tx| tx.append_event(&first)).unwrap();
    assert_eq!(
        ledger
            .transaction(|tx| tx.append_event(&first))
            .unwrap_err()
            .code,
        ErrorCode::IntegrityError
    );
    let collision = event(project, aggregate, 1);
    assert_eq!(
        ledger
            .transaction(|tx| tx.append_event(&collision))
            .unwrap_err()
            .code,
        ErrorCode::IntegrityError
    );
    let second = event(project, aggregate, 2);
    ledger.transaction(|tx| tx.append_event(&second)).unwrap();
    assert_eq!(
        serde_json::to_value(ledger.outbox(256).unwrap()).unwrap(),
        json!([first, second])
    );
}

#[test]
fn existing_foreign_database_or_corrupt_header_is_never_reinitialized() {
    let run = TestRun::new();
    let foreign = b"unrelated user data, not a ledger";
    run.workspace
        .write_new(Path::new("ledger.sqlite"), foreign)
        .unwrap();
    assert_eq!(
        Ledger::open(&run.workspace, &run.profile)
            .err()
            .unwrap()
            .code,
        ErrorCode::IntegrityError
    );
    assert_eq!(
        Ledger::create(&run.workspace, &run.profile)
            .err()
            .unwrap()
            .code,
        ErrorCode::IntegrityError
    );
    assert_eq!(
        run.workspace
            .read(Path::new("ledger.sqlite"), 1024)
            .unwrap(),
        foreign
    );
}

#[test]
fn a_different_profile_cannot_reopen_the_same_run_and_reset_its_budget() {
    let run = TestRun::new();
    let id = EntityId::new();
    {
        let ledger = run.create();
        ledger.insert_budget(&budget(id, None, 7)).unwrap();
        ledger
            .transaction(|tx| tx.reserve_budget(id, count(2), count(0)))
            .unwrap();
    }
    let mut config = serde_json::to_value(run.profile.config()).unwrap();
    config["transport"]["requests_per_case"] = json!(19);
    let different = LoadedProfile::from_bytes(&serde_json::to_vec(&config).unwrap()).unwrap();
    assert_eq!(
        Ledger::open(&run.workspace, &different).err().unwrap().code,
        ErrorCode::IntegrityError
    );
    let reopened = Ledger::open(&run.workspace, &run.profile).unwrap();
    assert_eq!(budget_json(&reopened, id)["reserved"], 2);
}

fn seed_stored_reservation(run: &TestRun, ledger: &Ledger) -> StoredInvocation {
    let fixtures = CanonicalFixtures::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/scenarios/contracts.json"),
    )
    .unwrap();
    let mut proposed = fixtures
        .records()
        .iter()
        .find_map(|document| match &document.record {
            ContractRecord::Invocation(invocation)
                if invocation.state == InvocationState::Proposed =>
            {
                Some(invocation.as_ref().clone())
            }
            _ => None,
        })
        .unwrap();
    proposed.run_id = run.workspace.run_id();
    proposed.control_revision = WireInt::ZERO;
    let grant = fixtures
        .records()
        .iter()
        .find_map(|document| match &document.record {
            ContractRecord::ApprovalGrant(grant) if !grant.revoked => Some(grant),
            _ => None,
        })
        .unwrap();
    let mut control = fixtures
        .records()
        .iter()
        .find_map(|document| match &document.record {
            ContractRecord::ControlState(control) => Some(control.clone()),
            _ => None,
        })
        .unwrap();
    control.revision = WireInt::ZERO;
    ledger
        .insert_budget(&budget(proposed.budget_id, None, 100))
        .unwrap();
    ledger
        .insert_control(&control, proposed.project_id, proposed.scope_revision)
        .unwrap();
    let mut stored = StoredInvocation {
        history: InvocationHistory::start(&proposed).unwrap(),
        requested: serde_json::from_value(
            json!({"units": 1, "bytes": 0, "cpu_us": 0, "elapsed_us": 0}),
        )
        .unwrap(),
        source_control_revision: proposed.control_revision,
        invocation: proposed,
        reserved_units: WireInt::ZERO,
    };
    ledger
        .transaction(|tx| tx.insert_invocation(&stored))
        .unwrap();
    stored.invocation.state = InvocationState::Reserved;
    stored.invocation.grant_id = Some(grant.grant_id);
    stored
        .history
        .record(&stored.invocation, Some(grant), AuditTime::now())
        .unwrap();
    stored.reserved_units = count(1);
    let event = event(
        stored.invocation.project_id,
        stored.invocation.invocation_id,
        1,
    );
    let mut checkpoint = checkpoint(run, stored.invocation.budget_id);
    checkpoint.control_revision = stored.invocation.control_revision;
    checkpoint.scope_revision = stored.invocation.scope_revision;
    checkpoint
        .invocation_refs
        .push(stored.invocation.invocation_id);
    checkpoint
        .event_cursors
        .insert(event.aggregate_id, event.aggregate_sequence);
    ledger
        .transaction(|tx| {
            tx.reserve_budget(stored.invocation.budget_id, count(1), count(0))?;
            tx.update_invocation(&stored, InvocationState::Proposed)?;
            tx.append_event(&event)?;
            tx.write_checkpoint(&checkpoint)
        })
        .unwrap();
    stored
}

#[test]
fn authorized_invocation_history_and_held_quota_survive_reopen_without_dedup_reset() {
    let run = TestRun::new();
    let reserved = {
        let ledger = run.create();
        seed_stored_reservation(&run, &ledger)
    };
    let ledger = Ledger::open(&run.workspace, &run.profile).unwrap();
    let restored = ledger
        .read_invocation(reserved.invocation.invocation_id)
        .unwrap();
    assert_eq!(restored.invocation, reserved.invocation);
    assert_eq!(restored.reserved_units, count(1));
    assert_eq!(
        restored.history.export_json().unwrap(),
        reserved.history.export_json().unwrap()
    );
    assert_eq!(
        budget_json(&ledger, reserved.invocation.budget_id)["reserved"],
        1
    );
    let mut duplicate = reserved.invocation.clone();
    duplicate.invocation_id = EntityId::new();
    duplicate.state = InvocationState::Proposed;
    duplicate.grant_id = None;
    let duplicate = StoredInvocation {
        history: InvocationHistory::start(&duplicate).unwrap(),
        requested: reserved.requested,
        source_control_revision: reserved.source_control_revision,
        invocation: duplicate,
        reserved_units: WireInt::ZERO,
    };
    let error = ledger
        .transaction(|tx| tx.insert_invocation(&duplicate))
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::IntegrityError);
    assert_eq!(
        ledger
            .read_invocation(reserved.invocation.invocation_id)
            .unwrap()
            .invocation,
        reserved.invocation
    );
    assert_eq!(
        budget_json(&ledger, reserved.invocation.budget_id)["reserved"],
        1
    );
}

#[test]
fn control_cancellation_atomically_releases_real_reservations_but_keeps_assigned_grant_history() {
    let run = TestRun::new();
    let ledger = run.create();
    let reserved = seed_stored_reservation(&run, &ledger);
    let mut paused = ledger
        .read_control(reserved.invocation.investigation_id)
        .unwrap();
    let previous_revision = paused.revision;
    paused.revision = previous_revision.checked_add(count(1)).unwrap();
    paused.mode = ControlMode::Paused;
    paused.admission_open = false;
    let error = ledger
        .transaction(|tx| {
            tx.apply_control(&paused, previous_revision)?;
            Err::<(), _>(ProofError::new(
                ErrorCode::Cancelled,
                "Abort the complete control transaction",
            ))
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    assert_eq!(
        ledger
            .read_invocation(reserved.invocation.invocation_id)
            .unwrap()
            .invocation
            .state,
        InvocationState::Reserved
    );
    assert_eq!(
        budget_json(&ledger, reserved.invocation.budget_id)["reserved"],
        1
    );
    assert_eq!(
        ledger
            .read_control(paused.investigation_id)
            .unwrap()
            .revision,
        previous_revision
    );
    ledger
        .transaction(|tx| tx.apply_control(&paused, previous_revision))
        .unwrap();
    let cancelled = ledger
        .read_invocation(reserved.invocation.invocation_id)
        .unwrap();
    assert_eq!(cancelled.invocation.state, InvocationState::Cancelled);
    assert_eq!(cancelled.invocation.grant_id, reserved.invocation.grant_id);
    assert_eq!(cancelled.reserved_units, WireInt::ZERO);
    assert_eq!(cancelled.history.last(), &cancelled.invocation);
    assert_eq!(
        budget_json(&ledger, reserved.invocation.budget_id)["reserved"],
        0
    );
    let checkpoint = ledger.latest_checkpoint().unwrap().unwrap();
    assert_eq!(checkpoint.control_revision, paused.revision);
    assert!(
        checkpoint
            .invocation_refs
            .contains(&cancelled.invocation.invocation_id)
    );
    let events = ledger.outbox(256).unwrap();
    let cancellation = events
        .iter()
        .find(|event| event.event_type.as_str() == "invocation.cancelled")
        .unwrap();
    assert_eq!(
        cancellation.control_revision,
        Some(cancelled.invocation.control_revision)
    );
    assert_ne!(cancellation.control_revision, Some(paused.revision));
    drop(ledger);
    let reopened = Ledger::open(&run.workspace, &run.profile).unwrap();
    assert_eq!(
        reopened
            .read_invocation(cancelled.invocation.invocation_id)
            .unwrap()
            .invocation,
        cancelled.invocation
    );
    assert_eq!(
        budget_json(&reopened, reserved.invocation.budget_id)["reserved"],
        0
    );
}

#[test]
fn requested_limits_and_submitted_revision_are_immutable_and_survive_reopen() {
    let run = TestRun::new();
    let ledger = run.create();
    let reserved = seed_stored_reservation(&run, &ledger);
    let fixtures = CanonicalFixtures::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/scenarios/contracts.json"),
    )
    .unwrap();
    let grant = fixtures
        .records()
        .iter()
        .find_map(|document| match &document.record {
            ContractRecord::ApprovalGrant(grant) if !grant.revoked => Some(grant),
            _ => None,
        })
        .unwrap();
    let mut sending = reserved.clone();
    sending.invocation.state = InvocationState::Sending;
    sending
        .history
        .record(&sending.invocation, Some(grant), AuditTime::now())
        .unwrap();
    for dimension in 0..5 {
        let mut changed = sending.clone();
        match dimension {
            0 => changed.requested.units = count(2),
            1 => changed.requested.bytes = count(1),
            2 => changed.requested.cpu_us = count(1),
            3 => changed.requested.elapsed_us = count(1),
            4 => changed.source_control_revision = count(1),
            _ => unreachable!(),
        }
        let error = ledger
            .transaction(|tx| tx.update_invocation(&changed, InvocationState::Reserved))
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(
            ledger
                .read_invocation(reserved.invocation.invocation_id)
                .unwrap()
                .invocation
                .state,
            InvocationState::Reserved
        );
    }
    drop(ledger);
    let reopened = Ledger::open(&run.workspace, &run.profile).unwrap();
    let restored = reopened
        .read_invocation(reserved.invocation.invocation_id)
        .unwrap();
    assert_eq!(restored.requested, reserved.requested);
    assert_eq!(
        restored.source_control_revision,
        reserved.source_control_revision
    );
    assert_eq!(restored.reserved_units, reserved.reserved_units);
}

#[test]
fn bounded_event_pages_export_all_committed_history_without_the_delivery_queue_truncation() {
    let run = TestRun::new();
    let ledger = run.create();
    let project = EntityId::new();
    let aggregate = EntityId::new();
    let expected: Vec<_> = (1..=300)
        .map(|sequence| event(project, aggregate, sequence))
        .collect();
    ledger
        .transaction(|tx| {
            for event in &expected {
                tx.append_event(event)?;
            }
            Ok(())
        })
        .unwrap();
    let mut cursor = WireInt::ZERO;
    let mut observed = Vec::new();
    loop {
        let page = ledger.event_page(cursor, 73).unwrap();
        if page.events.is_empty() {
            assert_eq!(page.last_position, cursor);
            break;
        }
        assert!(page.events.len() <= 73);
        assert!(page.last_position > cursor);
        cursor = page.last_position;
        observed.extend(page.events);
    }
    assert_eq!(observed, expected);
    for limit in [0, 257] {
        assert_eq!(
            ledger.event_page(WireInt::ZERO, limit).unwrap_err().code,
            ErrorCode::InvalidInput
        );
    }
}

#[test]
fn readonly_history_inspection_preserves_files_and_rejects_writer_callbacks() {
    let run = TestRun::new();
    let reserved = {
        let ledger = run.create();
        seed_stored_reservation(&run, &ledger)
    };
    let database_before = run
        .workspace
        .read(Path::new("ledger.sqlite"), 16 * 1024 * 1024)
        .unwrap();
    let lock_before = run.workspace.read(Path::new("ledger.lock"), 256).unwrap();
    let names = || {
        let mut entries: Vec<_> = std::fs::read_dir(run.workspace.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        entries.sort();
        entries
    };
    let names_before = names();
    let reader = Ledger::open_readonly(&run.workspace, &run.profile).unwrap();
    let second_reader = Ledger::open_readonly(&run.workspace, &run.profile).unwrap();
    assert_eq!(
        second_reader
            .read_budget(reserved.invocation.budget_id)
            .unwrap()
            .reserved,
        count(1)
    );
    assert_eq!(
        Ledger::open(&run.workspace, &run.profile)
            .err()
            .unwrap()
            .code,
        ErrorCode::IntegrityError
    );
    drop(second_reader);
    let restored = reader
        .read_invocation(reserved.invocation.invocation_id)
        .unwrap();
    assert_eq!(restored.invocation, reserved.invocation);
    assert_eq!(
        restored.history.export_json().unwrap(),
        reserved.history.export_json().unwrap()
    );
    assert_eq!(
        reader
            .read_budget(reserved.invocation.budget_id)
            .unwrap()
            .reserved,
        count(1)
    );
    assert_eq!(
        reader.event_page(WireInt::ZERO, 1).unwrap().events[0].aggregate_id,
        reserved.invocation.invocation_id
    );
    let called = std::sync::atomic::AtomicBool::new(false);
    let error = reader
        .transaction(|_| {
            called.store(true, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert!(!called.load(std::sync::atomic::Ordering::SeqCst));
    drop(reader);
    assert_eq!(
        run.workspace
            .read(Path::new("ledger.sqlite"), 16 * 1024 * 1024)
            .unwrap(),
        database_before
    );
    assert_eq!(
        run.workspace.read(Path::new("ledger.lock"), 256).unwrap(),
        lock_before
    );
    assert_eq!(names(), names_before);
}

#[test]
fn readonly_inspection_neither_adopts_live_writers_nor_recreates_missing_state() {
    let run = TestRun::new();
    assert!(Ledger::open_readonly(&run.workspace, &run.profile).is_err());
    assert!(!run.workspace.path().join("ledger.sqlite").exists());
    assert!(!run.workspace.path().join("ledger.lock").exists());
    let writer = run.create();
    assert_eq!(
        Ledger::open_readonly(&run.workspace, &run.profile)
            .err()
            .unwrap()
            .code,
        ErrorCode::IntegrityError
    );
    drop(writer);
    std::fs::remove_file(run.workspace.path().join("ledger.lock")).unwrap();
    assert!(Ledger::open_readonly(&run.workspace, &run.profile).is_err());
    assert!(!run.workspace.path().join("ledger.lock").exists());
}

#[test]
fn readonly_budget_listing_includes_unspent_child_escrow_without_invocations() {
    let run = TestRun::new();
    let parent = EntityId::new();
    let child = EntityId::new();
    {
        let writer = run.create();
        writer.insert_budget(&budget(parent, None, 10)).unwrap();
        writer
            .transaction(|tx| tx.allocate_child(parent, child, count(7), WireInt::ZERO))
            .unwrap();
    }
    let reader = Ledger::open_readonly(&run.workspace, &run.profile).unwrap();
    assert!(reader.invocations().unwrap().is_empty());
    let budgets = reader.budgets().unwrap();
    let mut expected = [parent, child];
    expected.sort();
    assert_eq!(
        budgets
            .iter()
            .map(|budget| budget.budget_id)
            .collect::<Vec<_>>(),
        expected
    );
    let root = budgets
        .iter()
        .find(|budget| budget.budget_id == parent)
        .unwrap();
    let allocation = budgets
        .iter()
        .find(|budget| budget.budget_id == child)
        .unwrap();
    assert_eq!(root.reserved, count(7));
    assert_eq!(allocation.parent_budget_id, Some(parent));
    assert_eq!(allocation.limit, count(7));
    assert_eq!(allocation.consumed, WireInt::ZERO);
    assert_eq!(allocation.reserved, WireInt::ZERO);
}
