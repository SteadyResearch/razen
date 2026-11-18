use razen_engine::application::parser_fuzz::{FuzzTarget, run_framing};
use std::io::Cursor;

use razen_engine::protocol::codec::{
    BoundedQueue, ChannelRole, DiagnosticBuffer, Direction, decode_frame, encode_frame,
    encode_frame_into, read_frame,
};
use razen_engine::protocol::error::ErrorCode;

#[path = "support/parser_mutation.rs"]
mod parser_mutation;

const RUNTIME: &[u8] = b"{\"protocol\":\"razen.proof/0.1.0\",\"message_id\":\"0344f2f2-c854-4d37-9d20-bd7e83c66342\",\"kind\":\"started\",\"payload\":{\"capabilities\":[\"brokered_calls\",\"events\",\"results\",\"usage\",\"cancellation\",\"closure\"]}}\n";
const SUPERVISOR: &[u8] = b"{\"protocol\":\"razen.proof/0.1.0\",\"message_id\":\"0344f2f2-c854-4d37-9d20-bd7e83c66342\",\"kind\":\"started\",\"payload\":{\"invocation_id\":\"c1a77a92-a09e-4810-a25b-2abcaa899e3d\"}}\n";

#[test]
fn runtime_and_supervisor_started_payloads_cannot_choose_their_channel_role() {
    let runtime = decode_frame(RUNTIME, 4096, ChannelRole::Runtime, Direction::PeerToHost).unwrap();
    let supervisor = decode_frame(
        SUPERVISOR,
        4096,
        ChannelRole::Supervisor,
        Direction::PeerToHost,
    )
    .unwrap();
    assert_eq!(runtime.kind.as_ref(), "started");
    assert_eq!(supervisor.kind.as_ref(), "started");
    assert!(
        decode_frame(
            RUNTIME,
            4096,
            ChannelRole::Supervisor,
            Direction::PeerToHost
        )
        .is_err()
    );
    assert!(
        decode_frame(
            SUPERVISOR,
            4096,
            ChannelRole::Runtime,
            Direction::PeerToHost
        )
        .is_err()
    );
    assert!(decode_frame(RUNTIME, 4096, ChannelRole::Runtime, Direction::HostToPeer).is_err());
    let encoded = encode_frame(&runtime, 4096).unwrap();
    let restored =
        decode_frame(&encoded, 4096, ChannelRole::Runtime, Direction::PeerToHost).unwrap();
    assert_eq!(restored.message_id, runtime.message_id);
    assert_eq!(restored.payload.get(), runtime.payload.get());
}

#[test]
fn duplicate_unknown_and_malformed_wire_fields_are_rejected_not_normalized_away() {
    let original = std::str::from_utf8(RUNTIME).unwrap();
    let attacks = [
        original.replace(
            "\"kind\":\"started\"",
            "\"kind\":\"started\",\"kind\":\"result\"",
        ),
        original.replace("\"payload\":", "\"role\":\"supervisor\",\"payload\":"),
        original.replace("\"capabilities\":", "\"capabilities\":[],\"capabilities\":"),
        original.replace(
            "\"capabilities\":",
            "\"grant_id\":\"forged\",\"capabilities\":",
        ),
        original.replace("0344f2f2-c854-4d37-9d20-bd7e83c66342", "message-1"),
        original.replace("\"kind\":\"started\"", "\"kind\":\"not-a-kind\""),
    ];
    for attack in attacks {
        assert!(
            decode_frame(
                attack.as_bytes(),
                4096,
                ChannelRole::Runtime,
                Direction::PeerToHost
            )
            .is_err()
        );
    }
    for bytes in [
        b"{\"protocol\":\n".as_slice(),
        b"\xff\n".as_slice(),
        &RUNTIME[..RUNTIME.len() - 1],
    ] {
        assert!(decode_frame(bytes, 4096, ChannelRole::Runtime, Direction::PeerToHost).is_err());
    }
    let version = original.replace("razen.proof/0.1.0", "razen.proof/9.0.0");
    assert_eq!(
        decode_frame(
            version.as_bytes(),
            4096,
            ChannelRole::Runtime,
            Direction::PeerToHost
        )
        .unwrap_err()
        .code,
        ErrorCode::UnsupportedVersion
    );
}

#[test]
fn framing_bounds_apply_before_drain_and_preserve_separate_messages() {
    let mut oversized = Cursor::new(vec![b'x'; 4096]);
    assert!(read_frame(&mut oversized, 64).is_err());
    assert!(
        oversized.position() <= 65,
        "oversized frame was drained beyond budget"
    );
    let both = [RUNTIME, SUPERVISOR].concat();
    let mut reader = Cursor::new(both);
    assert_eq!(read_frame(&mut reader, 4096).unwrap().unwrap(), RUNTIME);
    assert_eq!(read_frame(&mut reader, 4096).unwrap().unwrap(), SUPERVISOR);
    assert!(read_frame(&mut reader, 4096).unwrap().is_none());
    let runtime = decode_frame(RUNTIME, 4096, ChannelRole::Runtime, Direction::PeerToHost).unwrap();
    assert!(encode_frame(&runtime, 64).is_err());
    let mut encoded = encode_frame(&runtime, 4096).unwrap();
    assert!(encode_frame_into(&runtime, &mut encoded, 64).is_err());
    assert!(
        encoded.is_empty(),
        "Failed encoding exposed a partial or previous frame"
    );
    encode_frame_into(&runtime, &mut encoded, 4096).unwrap();
    let restored =
        decode_frame(&encoded, 4096, ChannelRole::Runtime, Direction::PeerToHost).unwrap();
    assert_eq!(restored.message_id, runtime.message_id);
    assert!(decode_frame(RUNTIME, 64, ChannelRole::Runtime, Direction::PeerToHost).is_err());
}

#[test]
fn queue_saturation_reports_failure_without_dropping_previously_admitted_work() {
    let mut queue = BoundedQueue::new(2).unwrap();
    queue.push("first").unwrap();
    queue.push("second").unwrap();
    assert_eq!(
        queue.push("third").unwrap_err().code,
        ErrorCode::BudgetExhausted
    );
    assert_eq!(queue.pop(), Some("first"));
    assert_eq!(queue.pop(), Some("second"));
    assert_eq!(queue.pop(), None);
    assert!(BoundedQueue::<u8>::new(0).is_err());
}

#[test]
fn diagnostic_limits_remain_visible_and_split_secret_markers_are_redacted() {
    let mut diagnostics = DiagnosticBuffer::new(64).unwrap();
    diagnostics.push(b"fixture RA").unwrap();
    diagnostics.push(b"ZEN_SECRET_CANARY stderr").unwrap();
    assert_eq!(
        diagnostics.push(&[b'x'; 64]).unwrap_err().code,
        ErrorCode::BudgetExhausted
    );
    let output = diagnostics.finish(&[b"RAZEN_SECRET_CANARY"]);
    assert!(output.truncated);
    assert!(output.bytes.len() <= 64);
    assert!(
        !output
            .bytes
            .windows(b"RAZEN_SECRET_CANARY".len())
            .any(|bytes| bytes == b"RAZEN_SECRET_CANARY")
    );
    assert!(output.bytes.starts_with(b"fixture "));
}

#[test]
fn complete_seeded_framing_campaign_checks_real_roundtrip_and_rejection_oracles() {
    parser_mutation::assert_campaign(FuzzTarget::Framing, run_framing);
}

#[test]
fn tool_results_reject_unknown_states_lossy_usage_and_conflicting_outputs() {
    let result = serde_json::json!({
        "protocol":"razen.proof/0.1.0",
        "message_id":"0344f2f2-c854-4d37-9d20-bd7e83c66342",
        "kind":"tool_result",
        "payload":{
            "call_id":"0344f2f2-c854-4d37-9d20-bd7e83c66342",
            "invocation_id":"c1a77a92-a09e-4810-a25b-2abcaa899e3d",
            "state":"completed",
            "output_ref":"a13be608-16ac-4ab4-ae10-248b266318a1",
            "usage":{"units":1,"bytes":3,"cpu_us":0,"elapsed_us":1}
        }
    });
    let encoded = encode_frame(&result, 4096).unwrap();
    let decoded =
        decode_frame(&encoded, 4096, ChannelRole::Runtime, Direction::HostToPeer).unwrap();
    assert_eq!(decoded.kind.as_ref(), "tool_result");
    for (pointer, value) in [
        ("/payload/state", serde_json::json!("retrying")),
        ("/payload/usage/units", serde_json::json!(-1)),
        (
            "/payload/usage/bytes",
            serde_json::json!(9007199254740992u64),
        ),
        ("/payload/usage/cpu_us", serde_json::json!(0.5)),
    ] {
        let mut invalid = result.clone();
        *invalid.pointer_mut(pointer).unwrap() = value;
        let encoded = encode_frame(&invalid, 4096).unwrap();
        assert!(decode_frame(&encoded, 4096, ChannelRole::Runtime, Direction::HostToPeer).is_err());
    }
    let mut conflicting = result;
    conflicting["payload"]["error"] = serde_json::json!({
        "code":"invalid_input","message":"Input rejected",
        "retryability":"never","diagnostic_refs":[]
    });
    let encoded = encode_frame(&conflicting, 4096).unwrap();
    assert!(decode_frame(&encoded, 4096, ChannelRole::Runtime, Direction::HostToPeer).is_err());
}
