use std::borrow::Cow;
use std::sync::Arc;

use razen_engine::application::consumers::{HarnessConsumer, SimulatedRuntimeConsumer};
use razen_engine::application::control::{ControlAction, ControlCommand};
use razen_engine::application::control_owner::OwnedControl;
use razen_engine::domain::values::{EntityId, InvocationState, WireInt};
use razen_engine::protocol::codec::{ChannelRole, Direction, decode_frame};
use razen_engine::protocol::engine::RuntimeIngressKind;
use razen_engine::protocol::error::ErrorCode;
use razen_engine::protocol::messages::{
    Message, RuntimeCancel, RuntimeClose, RuntimeSteer, ToolResult,
};
use serde_json::json;

#[path = "support/consumers.rs"]
mod consumers;
use consumers::{ConsumerFixture, capabilities, frame, raw, request};

fn reply(kind: RuntimeIngressKind) -> Arc<Vec<u8>> {
    match kind {
        RuntimeIngressKind::ToolReply(bytes) => bytes,
        other => panic!("Expected tool reply, got {other:?}"),
    }
}

fn result(bytes: &[u8]) -> ToolResult {
    match decode_frame(
        bytes,
        1_048_576,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )
    .unwrap()
    .into_message()
    {
        Message::ToolResult(result) => result,
        other => panic!("Expected actual typed tool result, got {other:?}"),
    }
}

#[test]
fn direct_and_versioned_consumers_share_real_reads_proposals_denials_and_canonical_actor_ids() {
    let fixture = ConsumerFixture::new();
    let host = &fixture.host;
    let direct = HarnessConsumer::new(host.bind_local().unwrap(), Arc::clone(&host.registry));
    let mut runtime = SimulatedRuntimeConsumer::new(
        host.bind_local().unwrap(),
        Arc::clone(&host.registry),
        &fixture.profile,
        vec![],
        fixture.summary(),
    )
    .unwrap();
    assert_eq!(direct.binding().binding_id(), direct.binding().actor_ref());
    assert_eq!(
        runtime.binding().binding_id(),
        runtime.binding().actor_ref()
    );
    assert_ne!(
        direct.binding().binding_id(),
        runtime.binding().binding_id()
    );

    let input = fixture.snapshot_input();
    let denied_direct = direct
        .call(&request(
            EntityId::new(),
            "traffic.snapshot.read",
            &input,
            WireInt::ZERO,
        ))
        .unwrap();
    let denied_runtime = runtime
        .call(&request(
            EntityId::new(),
            "traffic.snapshot.read",
            &input,
            WireInt::ZERO,
        ))
        .unwrap();
    assert_eq!(
        denied_direct.error.unwrap().code,
        ErrorCode::ApprovalRequired
    );
    assert_eq!(
        denied_runtime.error.unwrap().code,
        ErrorCode::ApprovalRequired
    );
    assert_eq!(
        host.ledger
            .read_budget(host.budget_id)
            .unwrap()
            .consumed
            .get(),
        1
    );

    let shared_call_id = EntityId::new();
    let read = request(
        shared_call_id,
        "traffic.snapshot.read",
        &input,
        WireInt::ZERO,
    );
    fixture.approve(direct.binding(), &read);
    fixture.approve(runtime.binding(), &read);
    let before = host.ledger.read_budget(host.budget_id).unwrap();
    let direct_result = direct.call(&read).unwrap();
    let runtime_result = runtime.call(&read).unwrap();
    let start = decode_frame(
        runtime.start_frame(),
        1_048_576,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )
    .unwrap();
    let Message::RuntimeStart(start_payload) = start.into_message() else {
        panic!("Missing runtime start")
    };
    assert_eq!(start_payload.binding_id, runtime.binding().binding_id());
    let request_wire = runtime.last_request_frame().unwrap().to_vec();
    let wire_request = decode_frame(
        &request_wire,
        1_048_576,
        ChannelRole::Runtime,
        Direction::PeerToHost,
    )
    .unwrap();
    let wire_reply = decode_frame(
        runtime.last_reply_frame().unwrap(),
        1_048_576,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )
    .unwrap();
    assert_eq!(wire_reply.correlation_id, Some(wire_request.message_id));
    let replayed = runtime.receive(&request_wire).unwrap();
    assert!(replayed.duplicate);
    assert_eq!(
        result(&reply(replayed.kind)).invocation_id,
        runtime_result.invocation_id
    );
    assert_eq!(direct_result.state, InvocationState::Completed);
    assert_eq!(runtime_result.state, InvocationState::Completed);
    assert_ne!(direct_result.invocation_id, runtime_result.invocation_id);
    let read_output = |r: &ToolResult| {
        host.evidence
            .read_artifact(host.project.project_id, r.output_ref.unwrap(), 1_048_576)
            .unwrap()
    };
    assert_eq!(read_output(&direct_result), read_output(&runtime_result));
    assert_eq!(
        host.ledger
            .read_invocation(direct_result.invocation_id)
            .unwrap()
            .invocation
            .actor_ref,
        direct.binding().binding_id()
    );
    assert_eq!(
        host.ledger
            .read_invocation(runtime_result.invocation_id)
            .unwrap()
            .invocation
            .actor_ref,
        runtime.binding().binding_id()
    );
    let charged = host.ledger.read_budget(host.budget_id).unwrap();
    assert_eq!(charged.consumed.get(), before.consumed.get() + 2);
    assert_eq!(
        runtime.call(&read).unwrap().invocation_id,
        runtime_result.invocation_id
    );
    assert_eq!(
        direct.call(&read).unwrap().invocation_id,
        direct_result.invocation_id
    );
    assert_eq!(host.ledger.read_budget(host.budget_id).unwrap(), charged);

    let proposal_input = fixture.proposal_input();
    let proposal_request = request(
        EntityId::new(),
        "observation.propose",
        &proposal_input,
        WireInt::ZERO,
    );
    fixture.approve(runtime.binding(), &proposal_request);
    let proposed = runtime.call(&proposal_request).unwrap();
    assert_eq!(proposed.state, InvocationState::Completed);
    let proposals = host.evidence.proposals(host.project.project_id).unwrap();
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].actor_ref, runtime.binding().binding_id());
    assert_eq!(
        runtime.call(&proposal_request).unwrap().invocation_id,
        proposed.invocation_id
    );
    assert_eq!(
        host.evidence.proposals(host.project.project_id).unwrap(),
        proposals
    );

    let context_input =
        raw(json!({"kind": "investigation", "record_id": host.session.investigation_id}));
    let context = request(
        EntityId::new(),
        "context.read",
        &context_input,
        WireInt::ZERO,
    );
    fixture.approve(runtime.binding(), &context);
    assert_eq!(
        runtime.call(&context).unwrap().state,
        InvocationState::Completed
    );
}

#[test]
fn broker_requires_one_real_start_handshake_and_rejects_role_direction_and_foreign_correlations() {
    let fixture = ConsumerFixture::new();
    let mut broker = fixture.broker();
    let event = frame(
        EntityId::new(),
        "event",
        None,
        json!({"event_type": "fixture.proposal", "source_control_revision": 0, "sequence": 0, "data_refs": []}),
    );
    assert_eq!(
        broker.receive(&event).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    let context = vec![
        fixture
            .host
            .ledger
            .read_control(fixture.host.session.investigation_id)
            .unwrap()
            .instruction_ref,
    ];
    let start = broker.start(context.clone(), fixture.summary()).unwrap();
    let envelope = decode_frame(
        &start,
        1_048_576,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )
    .unwrap();
    let start_id = envelope.message_id;
    let Message::RuntimeStart(payload) = envelope.into_message() else {
        panic!("Not a real start")
    };
    assert_eq!(payload.binding_id, broker.binding().binding_id());
    assert_eq!(payload.context_refs, context);
    assert_eq!(payload.budget_summary.limit, fixture.summary().limit);
    assert_eq!(
        broker.start(vec![], fixture.summary()).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    for payload in [
        json!({"invocation_id": EntityId::new()}),
        json!({"capabilities": ["brokered_calls"]}),
    ] {
        assert_eq!(
            broker
                .receive(&frame(EntityId::new(), "started", Some(start_id), payload))
                .unwrap_err()
                .code,
            ErrorCode::InvalidInput
        );
    }
    assert_eq!(
        broker
            .receive(&frame(
                EntityId::new(),
                "started",
                Some(EntityId::new()),
                capabilities()
            ))
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    broker
        .receive(&frame(
            EntityId::new(),
            "started",
            Some(start_id),
            capabilities(),
        ))
        .unwrap();
    assert_eq!(
        broker
            .receive(&frame(
                EntityId::new(),
                "started",
                Some(start_id),
                capabilities()
            ))
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        broker
            .receive(&frame(
                EntityId::new(),
                "steer",
                None,
                json!({"control_revision": 0, "instruction_ref": EntityId::new()})
            ))
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        broker
            .receive(&frame(EntityId::new(), "launch", None, json!({})))
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );

    let (mut other, other_start) = fixture.started();
    assert_eq!(broker.receive(&frame(EntityId::new(), "event", Some(other_start),
        json!({"event_type": "fixture.proposal", "source_control_revision": 0, "sequence": 1, "data_refs": []}))).unwrap_err().code, ErrorCode::InvalidInput);
    let shared_id = EntityId::new();
    let shared = frame(
        shared_id,
        "event",
        None,
        json!({"event_type": "fixture.proposal", "source_control_revision": 0, "sequence": 1, "data_refs": []}),
    );
    assert!(!broker.receive(&shared).unwrap().duplicate);
    assert!(!other.receive(&shared).unwrap().duplicate);
}

#[test]
fn exact_wire_replay_reuses_actual_reply_without_charge_and_changed_bytes_fail_closed() {
    let fixture = ConsumerFixture::new();
    let (mut broker, start) = fixture.started();
    let input = fixture.proposal_input();
    let call = request(
        EntityId::new(),
        "observation.propose",
        &input,
        WireInt::ZERO,
    );
    fixture.approve(broker.binding(), &call);
    let id = EntityId::new();
    let wire = frame(
        id,
        "tool_request",
        Some(start),
        serde_json::to_value(&call).unwrap(),
    );
    let first = broker.receive(&wire).unwrap();
    assert_eq!(first.message_id, id);
    assert!(!first.duplicate);
    let bytes = reply(first.kind);
    let decoded = decode_frame(
        &bytes,
        1_048_576,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )
    .unwrap();
    assert_eq!(decoded.correlation_id, Some(id));
    assert_ne!(decoded.message_id, id);
    assert_eq!(result(&bytes).state, InvocationState::Completed);
    let budget = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    let artifacts = fixture.host.evidence.artifacts().unwrap();
    let proposals = fixture
        .host
        .evidence
        .proposals(fixture.host.project.project_id)
        .unwrap();
    let replay = broker.receive(&wire).unwrap();
    assert!(replay.duplicate);
    assert!(
        Arc::ptr_eq(&bytes, &reply(replay.kind)),
        "replay must not copy cached frame bytes"
    );
    let mut changed = wire.clone();
    changed.insert(changed.len() - 1, b' ');
    assert_eq!(
        broker.receive(&changed).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        fixture
            .host
            .ledger
            .read_budget(fixture.host.budget_id)
            .unwrap(),
        budget
    );
    assert_eq!(fixture.host.evidence.artifacts().unwrap(), artifacts);
    assert_eq!(
        fixture
            .host
            .evidence
            .proposals(fixture.host.project.project_id)
            .unwrap(),
        proposals
    );
}

#[test]
fn tool_reply_cannot_be_correlated_from_another_binding_or_a_future_message() {
    let fixture = ConsumerFixture::new();
    let (mut left, left_start) = fixture.started();
    let (mut right, _) = fixture.started();
    let input = fixture.snapshot_input();
    let call = request(
        EntityId::new(),
        "traffic.snapshot.read",
        &input,
        WireInt::ZERO,
    );
    let id = EntityId::new();
    let wire = frame(
        id,
        "tool_request",
        Some(left_start),
        serde_json::to_value(&call).unwrap(),
    );
    let left_result = result(&reply(left.receive(&wire).unwrap().kind));
    assert_eq!(left_result.error.unwrap().code, ErrorCode::ApprovalRequired);
    assert_eq!(
        right.receive(&wire).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    let right_wire = frame(
        id,
        "tool_request",
        None,
        serde_json::to_value(&call).unwrap(),
    );
    let right_result = result(&reply(right.receive(&right_wire).unwrap().kind));
    assert_ne!(left_result.invocation_id, right_result.invocation_id);
    let future = EntityId::new();
    assert_eq!(right.receive(&frame(future, "event", Some(future),
        json!({"event_type": "fixture.proposal", "source_control_revision": 0, "sequence": 0, "data_refs": []}))).unwrap_err().code, ErrorCode::InvalidInput);
}

#[test]
fn typed_untrusted_events_results_and_duplicates_remain_deliverable_without_canonical_effects() {
    let fixture = ConsumerFixture::new();
    let (mut broker, _) = fixture.started();
    let budget = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    let invocations = fixture.host.ledger.invocations().unwrap().len();
    let claimed = EntityId::new();
    let id = EntityId::new();
    let event = frame(
        id,
        "event",
        None,
        json!({"event_type": "fixture.proposal", "source_control_revision": 987, "sequence": 2, "data_refs": [claimed]}),
    );
    for duplicate in [false, true] {
        let ingress = broker.receive(&event).unwrap();
        assert_eq!(ingress.duplicate, duplicate);
        let RuntimeIngressKind::Event(value) = ingress.kind else {
            panic!("Event was silently discarded")
        };
        assert_eq!(value.source_control_revision.get(), 987);
        assert_eq!(value.data_refs, vec![claimed]);
    }
    assert_eq!(broker.binding().control_revision(), WireInt::ZERO);
    let done = frame(
        EntityId::new(),
        "result",
        None,
        json!({"state": "completed", "source_control_revision": 987, "proposal_refs": [claimed],
            "usage": {"units": 999, "bytes": 999, "cpu_us": 999, "elapsed_us": 999}}),
    );
    for duplicate in [false, true] {
        let ingress = broker.receive(&done).unwrap();
        assert_eq!(ingress.duplicate, duplicate);
        let RuntimeIngressKind::Result(value) = ingress.kind else {
            panic!("Result was silently discarded")
        };
        assert_eq!(value.source_control_revision.get(), 987);
        assert_eq!(value.proposal_refs, vec![claimed]);
    }
    assert_eq!(
        fixture
            .host
            .ledger
            .read_budget(fixture.host.budget_id)
            .unwrap(),
        budget
    );
    assert_eq!(
        fixture.host.ledger.invocations().unwrap().len(),
        invocations
    );
    assert!(
        fixture
            .host
            .evidence
            .proposals(fixture.host.project.project_id)
            .unwrap()
            .is_empty()
    );
    let input = fixture.snapshot_input();
    assert_eq!(
        broker
            .receive(&frame(
                EntityId::new(),
                "tool_request",
                None,
                serde_json::to_value(request(
                    EntityId::new(),
                    "traffic.snapshot.read",
                    &input,
                    WireInt::ZERO
                ))
                .unwrap()
            ))
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
}

#[test]
fn claimed_current_revision_cannot_upgrade_an_old_binding_after_pause_resume() {
    let fixture = ConsumerFixture::new();
    let host = &fixture.host;
    let mut runtime = SimulatedRuntimeConsumer::new(
        host.bind_local().unwrap(),
        Arc::clone(&host.registry),
        &fixture.profile,
        vec![],
        fixture.summary(),
    )
    .unwrap();
    let input = fixture.snapshot_input();
    let call = request(
        EntityId::new(),
        "traffic.snapshot.read",
        &input,
        WireInt::new(2).unwrap(),
    );
    fixture.approve(runtime.binding(), &call);
    let server =
        OwnedControl::start(Arc::clone(&host.workspace), Arc::clone(&host.control)).unwrap();
    let client = OwnedControl::client_for(&host.workspace, server.resource_id()).unwrap();
    for (revision, action) in [(0, ControlAction::Pause), (1, ControlAction::Resume)] {
        client
            .request(&ControlCommand {
                request_id: EntityId::new(),
                investigation_id: host.session.investigation_id,
                expected_revision: WireInt::new(revision).unwrap(),
                action,
            })
            .unwrap();
    }
    let before = host.ledger.read_budget(host.budget_id).unwrap();
    let denied = runtime.call(&call).unwrap();
    assert_eq!(denied.error.unwrap().code, ErrorCode::StaleSnapshot);
    assert_eq!(runtime.binding().control_revision(), WireInt::ZERO);
    assert_eq!(host.ledger.read_budget(host.budget_id).unwrap(), before);
    server.shutdown().unwrap();
}

#[test]
fn cancel_close_and_closed_never_allow_new_execution_or_revive_the_binding() {
    let fixture = ConsumerFixture::new();
    let (mut broker, _) = fixture.started();
    let instruction = fixture
        .host
        .ledger
        .read_control(fixture.host.session.investigation_id)
        .unwrap()
        .instruction_ref;
    assert_eq!(
        broker
            .steer(RuntimeSteer {
                control_revision: WireInt::ZERO,
                instruction_ref: instruction
            })
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput,
        "native steering was not declared"
    );
    let cancel = broker
        .cancel(RuntimeCancel {
            control_revision: WireInt::ZERO,
            reason: Cow::Borrowed("trusted cancellation"),
        })
        .unwrap();
    assert!(matches!(
        decode_frame(
            &cancel,
            1_048_576,
            ChannelRole::Runtime,
            Direction::HostToPeer
        )
        .unwrap()
        .into_message(),
        Message::RuntimeCancel(_)
    ));
    let input = fixture.snapshot_input();
    let call = request(
        EntityId::new(),
        "traffic.snapshot.read",
        &input,
        WireInt::ZERO,
    );
    fixture.approve(broker.binding(), &call);
    let before = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    assert_eq!(
        broker
            .receive(&frame(
                EntityId::new(),
                "tool_request",
                None,
                serde_json::to_value(&call).unwrap()
            ))
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    let close = broker
        .close(RuntimeClose {
            reason: Cow::Borrowed("finished"),
        })
        .unwrap();
    let close_id = decode_frame(
        &close,
        1_048_576,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )
    .unwrap()
    .message_id;
    let closed_wire = frame(EntityId::new(), "closed", Some(close_id), json!({}));
    assert!(matches!(
        broker.receive(&closed_wire).unwrap().kind,
        RuntimeIngressKind::Closed
    ));
    assert!(broker.receive(&closed_wire).unwrap().duplicate);
    assert_eq!(
        broker
            .receive(&frame(EntityId::new(), "started", None, capabilities()))
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        broker.start(vec![], fixture.summary()).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(
        fixture
            .host
            .ledger
            .read_budget(fixture.host.budget_id)
            .unwrap(),
        before
    );
}

#[test]
fn bounded_message_retention_rejects_new_work_explicitly_but_keeps_existing_replays() {
    let fixture = ConsumerFixture::new();
    let (mut broker, _) = fixture.started();
    let capacity = fixture.profile.config().protocol.event_queue_capacity.get()
        + fixture
            .profile
            .config()
            .protocol
            .admission_queue_capacity
            .get();
    let first = frame(
        EntityId::new(),
        "event",
        None,
        json!({"event_type": "fixture.proposal", "source_control_revision": 0, "sequence": 0, "data_refs": []}),
    );
    broker.receive(&first).unwrap();
    let mut saturated = false;
    for sequence in 1..=capacity {
        let next = frame(
            EntityId::new(),
            "event",
            None,
            json!({"event_type": "fixture.proposal", "source_control_revision": 0, "sequence": sequence, "data_refs": []}),
        );
        match broker.receive(&next) {
            Ok(_) => {}
            Err(error) => {
                assert_eq!(error.code, ErrorCode::BudgetExhausted);
                saturated = true;
                break;
            }
        }
    }
    assert!(
        saturated,
        "message retention is not bounded by profile capacities"
    );
    let replay = broker.receive(&first).unwrap();
    assert!(replay.duplicate);
    assert!(matches!(replay.kind, RuntimeIngressKind::Event(_)));
}

#[test]
fn native_steering_requires_explicit_declaration_and_routes_actual_versioned_payload() {
    let fixture = ConsumerFixture::new();
    let mut broker = fixture.broker();
    let start = broker.start(vec![], fixture.summary()).unwrap();
    let start_id = decode_frame(
        &start,
        1_048_576,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )
    .unwrap()
    .message_id;
    let mut declared = capabilities();
    declared["capabilities"]
        .as_array_mut()
        .unwrap()
        .push(json!("native_steering"));
    broker
        .receive(&frame(EntityId::new(), "started", Some(start_id), declared))
        .unwrap();
    let instruction_ref = fixture
        .host
        .ledger
        .read_control(fixture.host.session.investigation_id)
        .unwrap()
        .instruction_ref;
    let bytes = broker
        .steer(RuntimeSteer {
            control_revision: WireInt::new(7).unwrap(),
            instruction_ref,
        })
        .unwrap();
    let Message::RuntimeSteer(steer) = decode_frame(
        &bytes,
        1_048_576,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )
    .unwrap()
    .into_message() else {
        panic!("Steering was not routed")
    };
    assert_eq!(steer.instruction_ref, instruction_ref);
    assert_eq!(steer.control_revision.get(), 7);
    assert_eq!(
        broker.binding().control_revision(),
        WireInt::ZERO,
        "descriptive steering must not change authority"
    );
}

#[test]
fn malformed_and_oversized_wire_input_cannot_create_invocations_or_spend_budget() {
    let fixture = ConsumerFixture::new();
    let (mut broker, _) = fixture.started();
    let budget = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    let count = fixture.host.ledger.invocations().unwrap().len();
    let limit = fixture.profile.config().protocol.message_limit_bytes.get() as usize;
    assert_eq!(
        broker.receive(&vec![b' '; limit + 1]).unwrap_err().code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(
        broker.receive(b"{}\n").unwrap_err().code,
        ErrorCode::InvalidInput
    );
    let mut unknown_version = frame(
        EntityId::new(),
        "event",
        None,
        json!({"event_type": "fixture.proposal", "source_control_revision": 0, "sequence": 0, "data_refs": []}),
    );
    let offset = unknown_version
        .windows(b"razen.proof/0.1.0".len())
        .position(|bytes| bytes == b"razen.proof/0.1.0")
        .unwrap();
    unknown_version[offset] = b'x';
    assert_eq!(
        broker.receive(&unknown_version).unwrap_err().code,
        ErrorCode::UnsupportedVersion
    );
    assert_eq!(
        fixture
            .host
            .ledger
            .read_budget(fixture.host.budget_id)
            .unwrap(),
        budget
    );
    assert_eq!(fixture.host.ledger.invocations().unwrap().len(), count);
}
