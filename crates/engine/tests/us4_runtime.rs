use razen_engine::{
    adapters::models::simulated::SimulatedModel,
    ports::model::{Model, ModelRequest},
    protocol::{
        codec::{ChannelRole, Direction, decode_frame},
        error::ErrorCode,
    },
};
use serde_json::json;
#[path = "support/runtime_fixture.rs"]
mod runtime_fixture;

fn frame(kind: &str, payload: serde_json::Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&json!({"protocol":"razen.proof/0.1.0", "message_id":razen_engine::domain::values::EntityId::new(), "kind":kind, "payload":payload})).unwrap();
    bytes.push(b'\n');
    bytes
}

#[test]
fn runtime_and_supervisor_started_payloads_and_directions_are_not_interchangeable() {
    let runtime = frame(
        "started",
        json!({"capabilities":["brokered_calls","events","results","usage","cancellation","closure"]}),
    );
    let supervisor = frame(
        "started",
        json!({"invocation_id":razen_engine::domain::values::EntityId::new()}),
    );
    assert!(decode_frame(&runtime, 65536, ChannelRole::Runtime, Direction::PeerToHost).is_ok());
    assert!(
        decode_frame(
            &supervisor,
            65536,
            ChannelRole::Supervisor,
            Direction::PeerToHost
        )
        .is_ok()
    );
    assert!(
        decode_frame(
            &runtime,
            65536,
            ChannelRole::Supervisor,
            Direction::PeerToHost
        )
        .is_err()
    );
    assert!(
        decode_frame(
            &supervisor,
            65536,
            ChannelRole::Runtime,
            Direction::PeerToHost
        )
        .is_err()
    );
    assert!(decode_frame(&runtime, 65536, ChannelRole::Runtime, Direction::HostToPeer).is_err());
    assert!(
        decode_frame(
            &supervisor,
            65536,
            ChannelRole::Supervisor,
            Direction::HostToPeer
        )
        .is_err()
    );
}

#[test]
fn supervisor_replies_reject_foreign_invocations_and_unregistered_launch_correlations() {
    use razen_engine::{
        adapters::guest::transport::SupervisorBinding,
        domain::values::{EntityId, WireInt},
    };
    let invocation = EntityId::new();
    let launch = EntityId::new();
    let mut binding = SupervisorBinding::new(
        EntityId::new(),
        invocation,
        EntityId::new(),
        EntityId::new(),
        WireInt::ZERO,
        65536,
    );
    binding.register_request(launch).unwrap();
    for (origin, correlation) in [(EntityId::new(), launch), (invocation, EntityId::new())] {
        let mut bytes = serde_json::to_vec(&json!({"protocol":"razen.proof/0.1.0","message_id":EntityId::new(),"correlation_id":correlation,"kind":"started","payload":{"invocation_id":origin}})).unwrap();
        bytes.push(b'\n');
        assert!(binding.accept(&bytes, 65536).is_err());
    }
}
#[test]
fn offline_model_rejects_real_provider_before_delivering_any_proposal() {
    let mut model = SimulatedModel::new();
    let mut real = ModelRequest::offline(&[]);
    real.provider = "real-provider";
    let error = model.generate(real).unwrap_err();
    assert_eq!(error.code, ErrorCode::ProviderUnavailable);
    let proposal = model.generate(ModelRequest::offline(&[])).unwrap();
    assert_eq!(proposal.provider.as_str(), "offline-simulated");
    assert!(!proposal.capabilities.network);
    assert_eq!(proposal.proposals.len(), 1);
}

#[test]
fn offline_model_cancellation_and_output_budget_are_enforced_without_provider_fallback() {
    use razen_engine::domain::values::WireInt;
    let mut model = SimulatedModel::new();
    let cancelled = ModelRequest::offline(&[]);
    model.cancel(cancelled.request_id).unwrap();
    assert_eq!(
        model.generate(cancelled).unwrap_err().code,
        ErrorCode::Cancelled
    );
    let mut exhausted = ModelRequest::offline(&[]);
    exhausted.budget.bytes = WireInt::ZERO;
    assert_eq!(
        model.generate(exhausted).unwrap_err().code,
        ErrorCode::BudgetExhausted
    );
    let mut wrong_purpose = ModelRequest::offline(&[]);
    wrong_purpose.purpose = "outbound-disclosure";
    assert_eq!(
        model.generate(wrong_purpose).unwrap_err().code,
        ErrorCode::InvalidInput
    );
}

#[test]
fn actual_native_runtime_consumes_context_and_completes_brokered_lifecycle_without_model_egress() {
    let fixture = runtime_fixture::Fixture::new();
    let observation = fixture.execute("RUN-01");
    let runs = observation.report["runs"].as_array().unwrap();
    assert!(
        runs.iter()
            .any(|run| run["runtime_result"]["state"] == "completed")
    );
    assert!(runs.iter().any(|run| run["cancel_sent"] == true));
    for run in runs {
        assert!(run["transport_pid"].as_u64().unwrap() > 0);
        assert_eq!(run["termination"]["empty_cgroup"], true);
        assert_eq!(run["termination"]["cgroup_populated_after"], 0);
        assert_eq!(run["transport_reaped"], true);
    }
    let observer = &observation.report["model_observer"];
    let mut tampered = observation.report.clone();
    tampered["runs"][0]["runtime_result"]["source_control_revision"] = json!(999);
    assert!(fixture.verify(&observation, &tampered).is_err());
    let mut substituted = observation.report.clone();
    substituted["runs"][0]["launch"]["binding_id"] =
        json!(razen_engine::domain::values::EntityId::new());
    assert!(fixture.verify(&observation, &substituted).is_err());
    assert_actual_supervisor_identifies_launch(&fixture, &observation.report["runs"][0]);
    assert!(observer["healthy_arrivals"].as_u64().unwrap() > 0);
    assert_eq!(observer["unauthorized_arrivals"], 0);
}

#[test]
fn ten_noncooperative_native_workers_ack_durable_barriers_before_containment_and_reconstruct_fresh()
{
    let fixture = runtime_fixture::Fixture::new();
    let observation = fixture.execute("RUN-06");
    let samples = observation.report["control_samples"].as_array().unwrap();
    let mut forged_ack = observation.report.clone();
    forged_ack["control_samples"][0]["ack_elapsed_us"] =
        json!(samples[0]["ack_elapsed_us"].as_u64().unwrap() + 1);
    assert!(fixture.verify(&observation, &forged_ack).is_err());
    assert_eq!(samples.len(), 10);
    for sample in samples {
        assert!(sample["ack_elapsed_us"].as_u64().unwrap() <= 1_000_000);
        assert!(
            sample["new_revision"].as_u64().unwrap() > sample["old_revision"].as_u64().unwrap()
        );
        assert_eq!(sample["stale_error"]["code"], "stale_snapshot");
        assert_eq!(sample["old_lease_refresh_denied"], true);
        assert_eq!(sample["contained_before_reconstruction"], true);
        assert_ne!(sample["old_binding_id"], sample["new_binding_id"]);
        assert_ne!(sample["old_lease_id"], sample["new_lease_id"]);
        assert_ne!(sample["old_invocation_id"], sample["new_invocation_id"]);
        assert_eq!(sample["session_before"], sample["session_after"]);
        assert_eq!(
            sample["investigation_before"],
            sample["investigation_after"]
        );
        assert!(
            sample["consumed_after"].as_u64().unwrap()
                >= sample["consumed_before"].as_u64().unwrap()
        );
    }
}

#[test]
fn actual_late_frames_preserve_causality_and_duplicates_do_not_repeat_effects_or_reset_quota() {
    let fixture = runtime_fixture::Fixture::new();
    let observation = fixture.execute("RUN-07");
    let late = &observation.report["late_delivery"];
    let mut relabelled = observation.report.clone();
    relabelled["late_delivery"]["retained_revision"] =
        relabelled["late_delivery"]["current_revision"].clone();
    assert!(fixture.verify(&observation, &relabelled).is_err());
    assert_eq!(late["duplicate_event"], true);
    assert_eq!(late["duplicate_result"], true);
    assert_eq!(
        late["effects_before_duplicate"],
        late["effects_after_duplicate"]
    );
    assert_eq!(late["origin_revision"], late["retained_revision"]);
    assert_eq!(late["late_tool_error"]["code"], "stale_snapshot");
    assert!(late["current_revision"].as_u64().unwrap() > late["origin_revision"].as_u64().unwrap());
    assert!(late["consumed_after"].as_u64().unwrap() >= late["consumed_before"].as_u64().unwrap());
}

fn assert_actual_supervisor_identifies_launch(
    fixture: &runtime_fixture::Fixture,
    fact: &serde_json::Value,
) {
    use razen_engine::{
        adapters::guest::transport::SupervisorBinding,
        domain::values::{EntityId, WireInt},
    };
    let id = |value: &serde_json::Value| EntityId::parse(value.as_str().unwrap()).unwrap();
    let bytes = fixture
        .host
        .evidence
        .read_artifact(
            fixture.host.project.project_id,
            id(&fact["supervisor_artifact_id"]),
            4 * 1024 * 1024,
        )
        .unwrap();
    let transcript: Vec<serde_json::Value> = serde_json::from_slice(&bytes).unwrap();
    let ready = transcript
        .iter()
        .find(|frame| frame["kind"] == "ready")
        .unwrap();
    let binding = || {
        let mut channel = SupervisorBinding::new(
            id(&fact["binding_id"]),
            id(&fact["invocation_id"]),
            id(&fact["run_id"]),
            id(&fact["attestation_id"]),
            WireInt::new(fact["control_revision"].as_u64().unwrap()).unwrap(),
            2 * 1024 * 1024,
        );
        channel
            .register_request(id(&ready["correlation_id"]))
            .unwrap();
        channel
    };
    let encode = |value: &serde_json::Value| {
        let mut bytes = serde_json::to_vec(value).unwrap();
        bytes.push(b'\n');
        bytes
    };
    let mut correct = binding();
    assert!(correct.accept(&encode(ready), 1_048_576).is_ok());
    let started = transcript
        .iter()
        .find(|frame| frame["kind"] == "started")
        .unwrap();
    assert!(correct.accept(&encode(started), 1_048_576).is_ok());
    for pointer in [
        "/payload/invocation_id",
        "/payload/attestation/attestation_id",
        "/payload/attestation/run_id",
        "/correlation_id",
    ] {
        let mut foreign = ready.clone();
        *foreign.pointer_mut(pointer).unwrap() = json!(EntityId::new());
        assert!(
            binding().accept(&encode(&foreign), 1_048_576).is_err(),
            "{pointer}"
        );
    }
}
