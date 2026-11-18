#[path = "support/component_fixture.rs"]
mod component_fixture;
use component_fixture::{Fixture, assert_reaped_successors};

fn controls(report: &serde_json::Value, deadline_ms: u64) {
    let samples = report["control_measurements"].as_array().unwrap();
    assert!(
        !samples.is_empty(),
        "actual durable control barriers are required"
    );
    for sample in samples {
        assert!(sample["ack_elapsed_us"].as_u64().unwrap() <= deadline_ms * 1000);
        assert!(
            sample["revision_after"].as_u64().unwrap()
                > sample["revision_before"].as_u64().unwrap()
        );
        assert!(sample["ticket_id"].is_string());
    }
}
#[test]
fn real_infinite_guest_is_interrupted_reaped_and_followed_by_fresh_valid_execution() {
    let fixture = Fixture::new();
    let observation = fixture.execute("CMP-02");
    assert_reaped_successors(&observation.report);
    let failed = &observation.report["runs"][0];
    assert_eq!(failed["variant"], "fixture-loop");
    assert_ne!(failed["outcome"], "completed");
    assert!(
        failed["elapsed_us"].as_u64().unwrap()
            <= fixture
                .profile
                .config()
                .component
                .invocation_deadline_ms
                .get()
                * 1000
                + 1_000_000
    );
}
#[test]
fn real_growth_hits_store_limits_and_overlapping_runners_share_one_immediate_invocation_cap() {
    let fixture = Fixture::new();
    let observation = fixture.execute("CMP-03");
    assert_reaped_successors(&observation.report);
    let overlap = &observation.report["invocation_overlap"];
    assert_eq!(overlap["peak_admitted"], 1);
    assert_eq!(overlap["rejection"]["code"], "budget_exhausted");
    assert_eq!(overlap["extra_spawns"], 0);
    assert_eq!(overlap["queued"], 0);
    assert!(overlap["rejection_elapsed_us"].as_u64().unwrap() < 250_000);
    controls(
        &observation.report,
        fixture.profile.config().control.ack_deadline_ms.get(),
    );
    assert!(
        observation.report["runs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|run| run["variant"] == "fixture-grow" && run["outcome"] != "completed")
    );
}
#[test]
fn blocked_actual_broker_has_independent_deadline_and_global_host_call_slot_before_io() {
    let fixture = Fixture::new();
    let observation = fixture.execute("CMP-05");
    assert_reaped_successors(&observation.report);
    let overlap = &observation.report["host_call_overlap"];
    assert_eq!(overlap["peak_admitted"], 1);
    assert_eq!(overlap["rejection"]["code"], "budget_exhausted");
    assert_eq!(overlap["extra_reads"], 0);
    assert_eq!(overlap["queued"], 0);
    assert!(overlap["rejection_elapsed_us"].as_u64().unwrap() < 250_000);
    assert_eq!(overlap["blocked_error"]["code"], "timeout");
    assert!(
        overlap["blocked_elapsed_us"].as_u64().unwrap()
            <= fixture
                .profile
                .config()
                .component
                .host_call_deadline_ms
                .get()
                * 1000
                + 100_000
    );
    controls(
        &observation.report,
        fixture.profile.config().control.ack_deadline_ms.get(),
    );
}
#[test]
fn success_trap_timeout_cancellation_and_both_saturations_release_after_real_terminal_cleanup() {
    let fixture = Fixture::new();
    let observation = fixture.execute("CMP-07");
    assert_reaped_successors(&observation.report);
    let paths = observation.report["release_paths"].as_array().unwrap();
    for required in [
        "success",
        "trap",
        "timeout",
        "cancelled",
        "invocation_saturation",
        "host_call_saturation",
    ] {
        assert!(
            paths.iter().any(|path| path == required),
            "missing actual terminal path {required}"
        );
    }
    controls(
        &observation.report,
        fixture.profile.config().control.ack_deadline_ms.get(),
    );
}

#[test]
fn enclosing_cancel_stops_and_reaps_a_live_native_component_without_a_local_cancel_flag() {
    use razen_engine::adapters::components::supervisor::ApprovedComponents;
    use razen_engine::application::{
        admission::BindingSpec,
        component_proof,
        control::{ControlAction, ControlCommand},
    };
    use razen_engine::domain::{
        execution::{ControlMode, ControlState},
        knowledge::InvestigationSession,
        values::{CatalogId, ContractVersion, EntityId, WireInt},
    };
    use razen_engine::protocol::{error::ErrorCode, messages::ToolRequest};
    use serde_json::value::RawValue;
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, Instant};

    let fixture = Fixture::new();
    let tool =
        component_proof::registered_tool(fixture.host.provider_digest, &fixture.profile).unwrap();
    match fixture
        .host
        .ledger
        .find_tool(&tool.descriptor.tool_id)
        .unwrap()
    {
        None => fixture.host.ledger.insert_tool(&tool).unwrap(),
        Some(existing) => assert!(existing == tool),
    }
    let session = InvestigationSession {
        investigation_id: EntityId::new(),
        session_id: EntityId::new(),
        user_id: fixture.host.project.user_id,
        goal: "Observe enclosing cancellation of an owned component".to_owned(),
        control_revision: WireInt::ZERO,
        branch_refs: Vec::new(),
        evidence_refs: Vec::new(),
    };
    let instruction = fixture
        .host
        .ledger
        .read_control(fixture.host.session.investigation_id)
        .unwrap()
        .instruction_ref;
    fixture
        .host
        .ledger
        .insert_control(
            &ControlState {
                investigation_id: session.investigation_id,
                revision: WireInt::ZERO,
                mode: ControlMode::Running,
                admission_open: true,
                instruction_ref: instruction,
            },
            fixture.host.project.project_id,
            fixture.host.scope.revision,
        )
        .unwrap();
    fixture
        .host
        .ledger
        .insert_session(&session, fixture.host.project.project_id)
        .unwrap();
    fixture
        .host
        .control
        .register_existing(session.investigation_id)
        .unwrap();
    let spec = BindingSpec {
        user_id: session.user_id,
        project_id: fixture.host.project.project_id,
        investigation_id: session.investigation_id,
        session_id: session.session_id,
        identity_id: fixture.host.identity.identity_id,
        budget_id: fixture.host.budget_id,
        provider_digest: fixture.host.provider_digest,
        allowed_tools: vec![tool.descriptor.tool_id],
        permissions: tool.descriptor.permissions,
    };
    let binding = Arc::new(fixture.host.admission.bind(spec.clone()).unwrap());
    let snapshot = fixture
        .host
        .evidence
        .snapshots()
        .unwrap()
        .into_iter()
        .find(|snapshot| snapshot.project_id == binding.project_id() && !snapshot.truncated)
        .unwrap();
    let input = RawValue::from_string(
        serde_json::to_string(&component_proof::ComponentInput {
            variant: "fixture-loop".to_owned(),
            snapshot_id: snapshot.snapshot_id,
            revision: snapshot.revision,
            sha256: snapshot.sha256,
        })
        .unwrap(),
    )
    .unwrap();
    let request = ToolRequest {
        call_id: EntityId::new(),
        tool_id: CatalogId::parse(component_proof::TOOL).unwrap(),
        tool_version: ContractVersion::V0_1_0,
        input: &input,
        source_control_revision: binding.control_revision(),
    };
    let prepared = component_proof::prepare(
        &fixture.host.admission,
        &fixture.host.evidence,
        &binding,
        &request,
        &fixture.profile,
    )
    .unwrap();
    fixture.host.approve(&binding, &prepared.call).unwrap();
    let approved = ApprovedComponents::load(&fixture.repository, &fixture.profile).unwrap();
    let local_cancel = Arc::new(AtomicBool::new(false));
    let before = fixture.host.component_capacity.state().spawns;
    let (spawn_observed, acknowledgement, result) = std::thread::scope(|scope| {
        let worker = scope.spawn(|| {
            component_proof::execute_prepared(
                Arc::clone(&fixture.host.admission),
                Arc::clone(&fixture.host.evidence),
                Arc::clone(&binding),
                prepared,
                &approved,
                &fixture.profile,
                Arc::clone(&fixture.host.component_capacity),
                None,
                Arc::clone(&local_cancel),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while fixture.host.component_capacity.state().spawns == before && Instant::now() < deadline
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        let spawn_observed = fixture.host.component_capacity.state().spawns > before;
        let acknowledgement = fixture
            .host
            .control_client()
            .unwrap()
            .request(&ControlCommand {
                request_id: EntityId::new(),
                investigation_id: fixture.host.session.investigation_id,
                expected_revision: WireInt::ZERO,
                action: ControlAction::Cancel,
            });
        (spawn_observed, acknowledgement, worker.join().unwrap())
    });
    acknowledgement.unwrap();
    assert!(
        spawn_observed,
        "cancellation must follow an observed real native spawn"
    );
    assert!(
        !local_cancel.load(Ordering::SeqCst),
        "the separate local flag was never cancelled"
    );
    let execution = result.unwrap();
    assert_eq!(
        execution.fact.error.as_ref().unwrap().code,
        ErrorCode::Cancelled
    );
    assert!(execution.fact.pid > 0);
    assert!(execution.fact.reaped);
    assert_eq!(execution.fact.invocations_after, 0);
    assert_eq!(execution.fact.host_calls_after, 0);
    assert!(
        execution.fact.reads.is_empty(),
        "the pure loop cannot supply a host-call cancellation checkpoint"
    );
    assert_eq!(
        fixture.host.admission.bind(spec).err().unwrap().code,
        ErrorCode::Cancelled
    );
}
