#[allow(dead_code)]
#[path = "../src/adapters/transport/io.rs"]
mod transport_io;

#[path = "support/transport_fixtures.rs"]
pub mod fixtures;

use fixtures::{Fixture, exchanges};
use razen_engine::domain::values::Digest;

#[test]
fn http1_forward_preserves_duplicate_headers_binary_body_and_real_capture() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-01");
    let facts = exchanges(&observation);
    assert_eq!(
        facts.len(),
        fixture.profile.config().transport.requests_per_case.get() as usize
    );
    for fact in facts {
        assert_eq!(fact["mode"], "http1_forward");
        assert_eq!(fact["receiver_method"], "POST");
        assert_eq!(fact["receiver_target"], "/echo?fixture=binary");
        assert_eq!(
            fact["receiver_headers"]["x-razen-duplicate"],
            serde_json::json!(["first", "second"])
        );
        assert_eq!(fact["status"], 200);
        let request = fixture.body(fact, "request_snapshot_id");
        let response = fixture.body(fact, "response_snapshot_id");
        assert!(request.contains(&0));
        assert!(request.iter().any(|b| *b >= 128));
        assert_eq!(request, response);
        assert_eq!(
            serde_json::to_value(Digest::of(&request)).unwrap(),
            fact["receiver_body_sha256"]
        );
        assert!(fact["receiver_sequence"].as_u64().unwrap() > 0);
    }
}

#[test]
fn connect_carries_real_verified_tls_bytes_without_claiming_plaintext_inspection() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-02");
    for fact in exchanges(&observation) {
        assert_eq!(fact["mode"], "https_connect_tunnel");
        assert_eq!(fact["inspection"], "opaque");
        assert!(fact["tunnel_client_bytes"].as_u64().unwrap() > 0);
        assert!(fact["tunnel_upstream_bytes"].as_u64().unwrap() > 0);
        assert_eq!(fact["request_body_sha256"], fact["receiver_body_sha256"]);
        assert_eq!(fact["status"], 200);
        assert!(
            fact.get("response_snapshot_id").is_none(),
            "opaque proxy cannot publish a decrypted capture"
        );
    }
    assert!(!exchanges(&observation).is_empty());
}

#[test]
fn https_http1_uses_explicit_client_roots_and_independently_verified_upstream() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-03");
    for fact in exchanges(&observation) {
        assert_eq!(fact["client_alpn"], "http/1.1");
        assert_eq!(fact["upstream_alpn"], "http/1.1");
        assert_eq!(fact["connect_host"], fact["tls_server_name"]);
        assert_eq!(fact["connect_authority"], fact["request_authority"]);
        assert_eq!(
            fixture.body(fact, "request_snapshot_id"),
            fixture.body(fact, "response_snapshot_id")
        );
        assert!(fact["upstream_peer_certificate_sha256"].is_string());
    }
    assert_eq!(
        observation.report["trust"]["before_sha256"],
        observation.report["trust"]["after_sha256"]
    );
    assert!(!exchanges(&observation).is_empty());
}

#[test]
fn https_h2_negotiates_both_legs_and_runs_two_overlapping_streams() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-04");
    let facts = exchanges(&observation);
    assert!(facts.len() >= 2);
    for fact in facts {
        assert_eq!(fact["client_alpn"], "h2");
        assert_eq!(fact["upstream_alpn"], "h2");
        assert_eq!(fact["upstream_http_version"], "HTTP/2.0");
        assert_eq!(fact["client_http_version"], "HTTP/2.0");
        assert_eq!(
            fact["receiver_headers"]["x-razen-duplicate"],
            serde_json::json!(["first", "second"])
        );
        assert_eq!(
            fixture.body(fact, "request_snapshot_id"),
            fixture.body(fact, "response_snapshot_id")
        );
    }
    assert_eq!(facts[0]["connection_id"], facts[1]["connection_id"]);
    assert_ne!(facts[0]["stream_id"], facts[1]["stream_id"]);
    let start0 = facts[0]["receiver_started_us"].as_u64().unwrap();
    let end0 = facts[0]["receiver_finished_us"].as_u64().unwrap();
    let start1 = facts[1]["receiver_started_us"].as_u64().unwrap();
    let end1 = facts[1]["receiver_finished_us"].as_u64().unwrap();
    assert!(
        start0 < end1 && start1 < end0,
        "sequential requests do not prove concurrency"
    );
}

#[test]
fn warm_measurement_retains_separate_actual_direct_and_proxy_samples() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-01");
    let measurements = &observation.report["measurement"];
    let config = &fixture.profile.config().measurement;
    assert_eq!(
        measurements["warmup_exchanges"].as_u64().unwrap(),
        config.latency_warmup_exchanges.get()
    );
    assert_eq!(
        measurements["sample_body_bytes"].as_u64().unwrap(),
        config.sample_body_bytes.get()
    );
    for name in ["direct_us", "proxy_us"] {
        let values = measurements[name].as_array().unwrap();
        assert_eq!(values.len(), config.latency_sample_exchanges.get() as usize);
        assert!(values.iter().all(|value| value.as_u64().unwrap() > 0));
    }
    assert!(
        measurements["direct_receiver_count"].as_u64().unwrap()
            >= config.latency_warmup_exchanges.get() + config.latency_sample_exchanges.get()
    );
    assert!(
        measurements["proxy_receiver_count"].as_u64().unwrap()
            >= config.latency_warmup_exchanges.get() + config.latency_sample_exchanges.get()
    );
}
