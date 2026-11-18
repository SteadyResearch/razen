//! Real private engine workers and independent receiver processes; never restored-state simulations.
use std::path::Path;
use std::sync::Arc;

use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::events::{EventConsumer, EventDisposition};
use razen_engine::application::profile::LoadedProfile;
use razen_engine::application::recovery::{RecoveryPrograms, run_fixture};
use razen_engine::domain::execution::Event;
use razen_engine::domain::values::{AuditTime, CatalogId, ContractVersion, EntityId, WireInt};

#[path = "support/private_root.rs"]
mod private_root;

fn event(aggregate: EntityId, sequence: u64, revision: u64) -> Event {
    Event {
        event_id: EntityId::new(),
        schema_version: ContractVersion::V0_1_0,
        project_id: EntityId::new(),
        aggregate_id: aggregate,
        aggregate_sequence: WireInt::new(sequence).unwrap(),
        event_type: CatalogId::parse("invocation.completed").unwrap(),
        timestamp: AuditTime::now(),
        correlation_id: EntityId::new(),
        causation_id: EntityId::new(),
        control_revision: Some(WireInt::new(revision).unwrap()),
        data_refs: vec![aggregate],
        published: false,
    }
}

#[test]
fn event_redelivery_is_idempotent_but_changed_immutable_facts_are_integrity_errors() {
    let aggregate = EntityId::new();
    let first = event(aggregate, 1, 0);
    let mut consumer = EventConsumer::new(8).unwrap();
    assert_eq!(
        consumer.accept(&first, WireInt::ZERO).unwrap(),
        EventDisposition::Accepted
    );
    assert_eq!(
        consumer.accept(&first, WireInt::ZERO).unwrap(),
        EventDisposition::Duplicate
    );
    let mut conflicting = first.clone();
    conflicting.causation_id = EntityId::new();
    assert!(consumer.accept(&conflicting, WireInt::ZERO).is_err());
    assert_eq!(consumer.cursor(aggregate).get(), 1);
}

#[test]
fn old_revision_is_audited_late_and_gaps_and_capacity_are_visible_errors() {
    let aggregate = EntityId::new();
    let mut consumer = EventConsumer::new(2).unwrap();
    assert_eq!(
        consumer
            .accept(&event(aggregate, 1, 0), WireInt::new(1).unwrap())
            .unwrap(),
        EventDisposition::Late
    );
    assert!(
        consumer
            .accept(&event(aggregate, 3, 1), WireInt::new(1).unwrap())
            .is_err()
    );
    assert_eq!(consumer.cursor(aggregate).get(), 1);
    assert_eq!(
        consumer
            .accept(&event(aggregate, 2, 1), WireInt::new(1).unwrap())
            .unwrap(),
        EventDisposition::Accepted
    );
    assert!(
        consumer
            .accept(&event(aggregate, 3, 1), WireInt::new(1).unwrap())
            .is_err()
    );
    assert!(EventConsumer::new(0).is_err());
}
#[test]
fn publication_marker_is_not_an_immutable_change_and_future_revision_is_rejected() {
    let aggregate = EntityId::new();
    let first = event(aggregate, 1, 0);
    let mut consumer = EventConsumer::new(8).unwrap();
    assert_eq!(
        consumer.accept(&first, WireInt::ZERO).unwrap(),
        EventDisposition::Accepted
    );
    let mut delivered = first.clone();
    delivered.published = true;
    assert_eq!(
        consumer.accept(&delivered, WireInt::ZERO).unwrap(),
        EventDisposition::Duplicate
    );
    assert!(
        consumer
            .accept(&event(aggregate, 2, 2), WireInt::new(1).unwrap())
            .is_err()
    );
    assert_eq!(consumer.cursor(aggregate).get(), 1);
}

#[test]
fn distinct_event_ids_cannot_claim_the_same_aggregate_sequence() {
    let aggregate = EntityId::new();
    let first = event(aggregate, 1, 0);
    let mut consumer = EventConsumer::new(8).unwrap();
    consumer.accept(&first, WireInt::ZERO).unwrap();
    let mut collision = first.clone();
    collision.event_id = EntityId::new();
    assert!(consumer.accept(&collision, WireInt::ZERO).is_err());
    assert_eq!(consumer.cursor(aggregate).get(), 1);
}

fn recovery_case(case: &str) {
    let root = private_root::PrivateRoot::new();
    let directory = Arc::new(
        OwnedDirectory::create(root.path(), Path::new("scenario"), EntityId::new()).unwrap(),
    );
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let profile =
        LoadedProfile::load(&repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"))
            .unwrap();
    let programs = RecoveryPrograms {
        engine: Path::new(env!("CARGO_BIN_EXE_razen-engine")).to_path_buf(),
        receiver: Path::new(env!("CARGO_BIN_EXE_razen-fixture-receiver")).to_path_buf(),
    };
    let report = run_fixture(
        &directory,
        &profile,
        &repo,
        &programs,
        &CatalogId::parse(case).unwrap(),
    )
    .unwrap();
    report.validate().unwrap();
    assert_eq!(report.case_id.as_str(), case);
    assert!(!report.scenarios.is_empty());
    for scenario in &report.scenarios {
        assert_eq!(scenario.worker_signal, 9);
        assert_eq!(
            scenario.receiver_after_kill,
            scenario.receiver_after_restart
        );
        assert_eq!(
            scenario.before.budget.consumed,
            scenario.after.budget.consumed
        );
        assert_ne!(scenario.worker_epoch, scenario.restart_epoch);
        assert_eq!(scenario.before.run_id, scenario.after.run_id);
    }
    let seams: Vec<_> = report
        .scenarios
        .iter()
        .map(|scenario| scenario.seam.as_str())
        .collect();
    match case {
        "REC-01" => {
            assert_eq!(
                seams,
                ["before_reservation_commit", "after_reservation_commit"]
            );
            for scenario in &report.scenarios {
                assert_eq!(scenario.receiver_after_restart, 0);
                assert_eq!(scenario.after.budget.reserved, WireInt::ZERO);
                assert!(
                    scenario
                        .after
                        .invocations
                        .iter()
                        .all(|invocation| invocation.state
                            != razen_engine::domain::values::InvocationState::Reserved)
                );
            }
        }
        "REC-02" => {
            assert_eq!(seams, ["after_sending_commit", "after_receiver_increment"]);
            for (scenario, arrivals) in report.scenarios.iter().zip([0, 1]) {
                assert_eq!(scenario.receiver_after_restart, arrivals);
                let target = scenario
                    .after
                    .invocations
                    .iter()
                    .find(|invocation| invocation.invocation_id == scenario.invocation_id)
                    .unwrap();
                assert_eq!(
                    target.state,
                    razen_engine::domain::values::InvocationState::OutcomeUnknown
                );
                assert_eq!(target.usage.units, WireInt::ZERO);
                assert_eq!(scenario.after.budget.reserved.get(), 4);
            }
        }
        "REC-03" => {
            assert_eq!(seams, ["after_completion_commit"]);
            let scenario = &report.scenarios[0];
            assert_eq!(scenario.receiver_after_restart, 1);
            assert_eq!(scenario.after.budget.reserved, WireInt::ZERO);
            assert_eq!(
                scenario
                    .after
                    .invocations
                    .iter()
                    .find(|invocation| invocation.invocation_id == scenario.invocation_id)
                    .unwrap()
                    .state,
                razen_engine::domain::values::InvocationState::Completed
            );
            assert!(scenario.runtime_admission.is_none());
            assert_eq!(
                scenario
                    .after
                    .invocations
                    .iter()
                    .find(|invocation| invocation.invocation_id == scenario.invocation_id)
                    .unwrap()
                    .tool_id
                    .as_str(),
                "proof.recovery.post"
            );
            let channel = report.channel_scenario.as_ref().unwrap();
            assert_ne!(channel.before.run_id, scenario.before.run_id);
            assert_ne!(
                channel.before.budget.budget_id,
                scenario.before.budget.budget_id
            );
            assert_ne!(
                channel.before.project.project_id,
                scenario.before.project.project_id
            );
            assert_ne!(channel.invocation_id, scenario.invocation_id);
            assert_eq!(channel.receiver_after_restart, 1);
            let admission = channel.runtime_admission.as_ref().unwrap();
            assert_eq!(admission.original_message, admission.submitted_message);
            assert_eq!(admission.original_lease, admission.submitted_lease);
            assert_eq!(
                admission.submitted_lease.state,
                razen_engine::domain::runtime::LeaseState::Active
            );
            assert_ne!(
                admission.original_lease.owner_binding_id,
                admission.current_binding_id
            );
            assert_eq!(
                admission.error.code,
                razen_engine::protocol::error::ErrorCode::PermissionDenied
            );
            assert_eq!(admission.error, admission.authority_error);
            // Equal/current control revisions isolate loss of the REAL opaque
            // host/channel capability, not a stale revision or revoked audit flag.
            assert_eq!(
                admission.original_lease.control_revision,
                admission.current_control_revision
            );
            assert_eq!(
                serde_json::to_value(&admission.before).unwrap(),
                serde_json::to_value(&admission.after).unwrap()
            );
            assert_eq!(admission.before.budget, admission.after.budget);
            assert_eq!(admission.before.grants, admission.after.grants);
            assert_eq!(admission.before.identities, admission.after.identities);
            assert_eq!(admission.before.controls, admission.after.controls);
            let original_before = admission
                .before
                .invocations
                .iter()
                .position(|invocation| invocation.invocation_id == channel.invocation_id)
                .unwrap();
            let original_after = admission
                .after
                .invocations
                .iter()
                .position(|invocation| invocation.invocation_id == channel.invocation_id)
                .unwrap();
            assert_eq!(
                admission.before.histories[original_before],
                admission.after.histories[original_after]
            );
            assert_eq!(admission.receiver_before, 1);
            assert_eq!(admission.receiver_after, 1);
            assert_eq!(admission.receiver_after_healthy, 1);
            let healthy = channel
                .after
                .invocations
                .iter()
                .find(|invocation| invocation.invocation_id == admission.healthy_invocation_id)
                .unwrap();
            assert_eq!(healthy.tool_id.as_str(), "http.send");
            assert_eq!(
                healthy.state,
                razen_engine::domain::values::InvocationState::Completed
            );
            assert!(healthy.usage.units.get() > 0);
            assert!(healthy.output_ref.is_some());
            // A revoked audit copy cannot stand in for submitting the live old message.
            let mut circular = report.clone();
            circular
                .channel_scenario
                .as_mut()
                .unwrap()
                .runtime_admission
                .as_mut()
                .unwrap()
                .submitted_lease
                .state = razen_engine::domain::runtime::LeaseState::Revoked;
            assert!(circular.validate().is_err());
            let mut accepted = report.clone();
            accepted
                .channel_scenario
                .as_mut()
                .unwrap()
                .runtime_admission
                .as_mut()
                .unwrap()
                .error = razen_engine::protocol::error::ProofError::new(
                razen_engine::protocol::error::ErrorCode::StaleSnapshot,
                "revision-only rejection",
            );
            assert!(accepted.validate().is_err());
            // An orderly controller-host close plus a killed SDK sender is
            // additional channel evidence, never the ledger-owner crash seam.
            let mut substituted = report.clone();
            substituted.scenarios[0] = channel.clone();
            assert!(substituted.validate().is_err());
            assert!(!report.deliveries.is_empty());
        }
        "REC-04" => assert_eq!(report.authority_attempts.len(), 6),
        "REC-05" => {
            let kinds: Vec<_> = report
                .storage_faults
                .iter()
                .map(|fault| fault.kind.as_str())
                .collect();
            assert_eq!(
                kinds,
                [
                    "sqlite_full",
                    "injected_sync_eio",
                    "damaged_ledger",
                    "incompatible_checkpoint"
                ]
            );
            assert!(
                report
                    .storage_faults
                    .iter()
                    .all(|fault| fault.error.is_some() && fault.admission_error.is_some())
            );
        }
        _ => panic!("unknown recovery case"),
    }
}

#[test]
fn rec01_both_reservation_seams_release_only_unspent_hold_without_post_or_quota_reset() {
    recovery_case("REC-01");
}
#[test]
fn rec02_both_sending_seams_retain_full_unknown_hold_even_with_zero_receiver_arrivals() {
    recovery_case("REC-02");
}
#[test]
fn rec03_completed_attempt_event_redelivery_and_old_lease_never_repeat_effect() {
    recovery_case("REC-03");
}
#[test]
fn rec04_changed_current_scope_grant_control_identity_and_version_deny_stale_work() {
    recovery_case("REC-04");
}
#[test]
fn rec05_actual_full_sync_damage_and_checkpoint_errors_close_admission_with_partial_evidence() {
    recovery_case("REC-05");
}

fn engine_digest() -> razen_engine::domain::values::Digest {
    use sha2::{Digest as _, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(env!("CARGO_BIN_EXE_razen-engine")).unwrap();
    let mut hash = Sha256::new();
    let mut bytes = [0; 65_536];
    loop {
        let length = file.read(&mut bytes).unwrap();
        if length == 0 {
            break;
        }
        hash.update(&bytes[..length]);
    }
    razen_engine::domain::values::Digest::from_sha256(hash.finalize().into())
}

#[test]
fn grantless_proposed_and_waiting_intents_reconcile_legally_without_assigning_authority_or_consumption()
 {
    use razen_engine::application::admission::PreparedCall;
    use razen_engine::application::proof_host::ProofHost;
    use razen_engine::application::recovery::reconcile;
    use razen_engine::domain::values::{Digest, InvocationState, Usage};
    use razen_engine::protocol::contracts::CanonicalFixtures;
    use razen_engine::protocol::error::ErrorCode;
    let root = private_root::PrivateRoot::new();
    let workspace = Arc::new(
        OwnedDirectory::create(root.path(), Path::new("pending"), EntityId::new()).unwrap(),
    );
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let profile =
        LoadedProfile::load(&repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"))
            .unwrap();
    let examples = std::fs::read(repo.join("fixtures/scenarios/contracts.json")).unwrap();
    let host = ProofHost::create(
        Arc::clone(&workspace),
        &profile,
        CanonicalFixtures::from_bytes(&examples).unwrap(),
        Digest::of(&examples),
        engine_digest(),
    )
    .unwrap();
    let binding = host.bind_local().unwrap();
    let tool = host.ledger.read_tool(&binding.allowed_tools()[0]).unwrap();
    let input = host
        .evidence
        .artifacts()
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    let prepared = |id| PreparedCall {
        invocation_id: id,
        call_id: EntityId::new(),
        tool_id: tool.descriptor.tool_id.clone(),
        tool_version: tool.descriptor.version,
        input_ref: input.artifact_id,
        input_sha256: input.sha256,
        input_revision: WireInt::ZERO,
        source_control_revision: binding.control_revision(),
        requested: Usage {
            units: WireInt::new(1).unwrap(),
            bytes: WireInt::ZERO,
            cpu_us: WireInt::ZERO,
            elapsed_us: WireInt::ZERO,
        },
    };
    // These are canonical policy/state tests, not a claim that a metadata call ran a provider.
    let proposed = prepared(EntityId::new());
    host.admission.propose(&binding, &proposed).unwrap();
    let waiting = prepared(EntityId::new());
    assert_eq!(
        host.admission.reserve(&binding, &waiting).unwrap_err().code,
        ErrorCode::ApprovalRequired
    );
    let before = host.ledger.read_budget(host.budget_id).unwrap();
    let changed = reconcile(&host.ledger).unwrap();
    assert!(changed.contains(&proposed.invocation_id));
    assert!(changed.contains(&waiting.invocation_id));
    for (id, state) in [
        (proposed.invocation_id, InvocationState::Rejected),
        (waiting.invocation_id, InvocationState::Cancelled),
    ] {
        let stored = host.ledger.read_invocation(id).unwrap();
        assert_eq!(stored.invocation.state, state);
        assert!(stored.invocation.grant_id.is_none());
        assert_eq!(stored.reserved_units, WireInt::ZERO);
        stored.invocation.validate(Some(&stored.history)).unwrap();
    }
    assert_eq!(host.ledger.read_budget(host.budget_id).unwrap(), before);
    assert!(reconcile(&host.ledger).unwrap().is_empty());
    drop(binding);
    drop(host);
    let ledger =
        razen_engine::adapters::ledger::Ledger::open_readonly(&workspace, &profile).unwrap();
    assert_eq!(
        reconcile(&ledger).unwrap_err().code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(ledger.read_budget(before.budget_id).unwrap(), before);
}
