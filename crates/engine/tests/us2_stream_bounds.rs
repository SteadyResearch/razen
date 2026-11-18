#[allow(dead_code)]
#[path = "../src/adapters/transport/io.rs"]
mod transport_io;

#[path = "support/transport_fixtures.rs"]
pub mod fixtures;

use fixtures::{Fixture, attempt, exchanges};

#[test]
fn actual_body_and_framing_failures_are_bounded_visible_and_never_partial_successes() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-07");
    for variant in [
        "oversized_body",
        "truncated_content_length",
        "truncated_chunked",
        "conflicting_framing",
        "unsupported_encoding",
        "unsupported_protocol",
        "redirect_limit",
    ] {
        let fact = attempt(&observation, variant);
        assert!(
            fact["error_code"].is_string(),
            "missing explicit error: {variant}"
        );
        assert!(
            fact["captured_bytes"].as_u64().unwrap()
                <= fixture.profile.config().transport.body_limit_bytes.get()
        );
        assert_eq!(fact["replacement_published"], false);
        assert!(matches!(
            fact["representation"].as_str().unwrap(),
            "truncated" | "rejected" | "opaque"
        ));
        assert!(fact["healthy_arrivals"].as_u64().unwrap() > 0);
        assert!(fact["invocation_id"].is_string());
        assert!(
            fact["forbidden_after"].as_u64().unwrap() > fact["forbidden_before"].as_u64().unwrap(),
            "a missing fault receiver is not a protocol rejection"
        );
        assert_eq!(
            fact["error_code"],
            if ["oversized_body", "redirect_limit"].contains(&variant) {
                "budget_exhausted"
            } else if ["truncated_content_length", "truncated_chunked"].contains(&variant) {
                "provider_unavailable"
            } else {
                "unsupported_protocol"
            }
        );
        if ["truncated_content_length", "truncated_chunked"].contains(&variant) {
            let id = serde_json::from_value(fact["invocation_id"].clone()).unwrap();
            let stored = fixture.host.ledger.read_invocation(id).unwrap();
            assert_eq!(
                stored.invocation.state,
                razen_engine::domain::values::InvocationState::OutcomeUnknown
            );
            assert!(
                stored.reserved_units.get() > 0,
                "ambiguous dispatch must retain its reconciliation hold"
            );
            assert!(stored.invocation.output_ref.is_none());
        }
    }
    for fact in exchanges(&observation) {
        assert_eq!(fact["status"], 200);
        assert_eq!(
            fixture.body(fact, "request_snapshot_id"),
            fixture.body(fact, "response_snapshot_id")
        );
    }
    assert!(
        !exchanges(&observation).is_empty(),
        "body denials require successful complete-body controls"
    );
    let redirect = attempt(&observation, "redirect_limit");
    let invocation_id = serde_json::from_value(redirect["invocation_id"].clone()).unwrap();
    let invocation = fixture.host.ledger.read_invocation(invocation_id).unwrap();
    let artifact_id = serde_json::from_value(redirect["result_artifact_id"].clone()).unwrap();
    let bytes = fixture
        .host
        .evidence
        .read_artifact(invocation.invocation.project_id, artifact_id, 2 * 1_048_576)
        .unwrap();
    let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    let snapshot_id = serde_json::from_value(record["input_snapshot_id"].clone()).unwrap();
    let source = fixture
        .host
        .evidence
        .snapshot(
            invocation.invocation.project_id,
            snapshot_id,
            razen_engine::domain::values::WireInt::ZERO,
        )
        .unwrap();
    let arrivals = redirect["forbidden_after"].as_u64().unwrap()
        - redirect["forbidden_before"].as_u64().unwrap();
    assert_eq!(
        record["io"]["attempted_request_body_bytes"]
            .as_u64()
            .unwrap(),
        arrivals * source.length_bytes.get()
    );
    let timing = fixture
        .host
        .evidence
        .artifacts()
        .unwrap()
        .into_iter()
        .find(|artifact| {
            artifact.origin_invocation_id == invocation_id
                && artifact.kind.as_str() == "http-send-timing"
        })
        .unwrap();
    assert_eq!(
        invocation.invocation.usage.bytes.get(),
        source.length_bytes.get()
            + record["io"]["attempted_request_body_bytes"]
                .as_u64()
                .unwrap()
            + record["io"]["captured_response_body_bytes"]
                .as_u64()
                .unwrap()
            + bytes.len() as u64
            + timing.length_bytes.get()
    );
}

#[test]
fn sdk_success_output_resolves_an_exchange_and_measured_timing_not_a_raw_record() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-03");
    for id in observation.report["provider_invocation_ids"]
        .as_array()
        .unwrap()
    {
        let stored = fixture
            .host
            .ledger
            .read_invocation(serde_json::from_value(id.clone()).unwrap())
            .unwrap();
        let bytes = fixture
            .host
            .evidence
            .read_artifact(
                stored.invocation.project_id,
                stored.invocation.output_ref.unwrap(),
                65_536,
            )
            .unwrap();
        let output: razen_engine::application::http_send::HttpSendOutput =
            serde_json::from_slice(&bytes).unwrap();
        let exchange = fixture
            .host
            .evidence
            .read_artifact(
                stored.invocation.project_id,
                output.exchange_ref,
                2 * 1_048_576,
            )
            .unwrap();
        let record: razen_engine::application::http_send::SendRecord =
            serde_json::from_slice(&exchange).unwrap();
        assert_eq!(record.invocation_id, stored.invocation.invocation_id);
        assert!(output.response_snapshot_ref.is_some());
        assert!(
            fixture
                .host
                .evidence
                .artifact(stored.invocation.project_id, output.timing_ref)
                .is_ok()
        );
    }
}

#[test]
fn reset_is_attributed_to_one_real_h2_stream_and_concurrent_and_successor_streams_survive() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-08");
    let reset = attempt(&observation, "h2_stream_reset");
    assert!(reset["error_code"].is_string());
    assert!(reset["stream_id"].as_u64().unwrap() > 0);
    assert!(
        reset["reset_observed_us"].as_u64().unwrap() > reset["stream_started_us"].as_u64().unwrap()
    );
    let facts = exchanges(&observation);
    assert!(
        facts.len() >= 2,
        "concurrent valid stream plus fresh successor required"
    );
    let concurrent = &facts[0];
    assert_eq!(concurrent["connection_id"], reset["connection_id"]);
    assert_ne!(concurrent["stream_id"], reset["stream_id"]);
    assert!(
        concurrent["receiver_started_us"].as_u64().unwrap()
            < reset["reset_observed_us"].as_u64().unwrap()
    );
    assert!(
        concurrent["receiver_finished_us"].as_u64().unwrap()
            > reset["stream_started_us"].as_u64().unwrap()
    );
    assert!(
        facts[1]["receiver_started_us"].as_u64().unwrap()
            > reset["reset_observed_us"].as_u64().unwrap()
    );
    assert_eq!(
        facts[1]["connection_id"], reset["connection_id"],
        "successor must reuse the reset connection"
    );
    for fact in facts {
        assert_eq!(fact["client_alpn"], "h2");
        assert_eq!(fact["upstream_alpn"], "h2");
        assert_eq!(fact["status"], 200);
        assert_eq!(
            fixture.body(fact, "request_snapshot_id"),
            fixture.body(fact, "response_snapshot_id")
        );
    }
}

#[test]
fn real_connect_and_forward_partial_bodies_never_publish_completed_http_success() {
    use fixtures::{Reply, TlsFixture, WireReceiver, configuration, runtime};
    use razen_engine::adapters::transport::Mode;
    use razen_engine::domain::values::InvocationState;
    use razen_engine::protocol::error::ErrorCode;
    use std::sync::Arc;

    for mode in [Mode::Http1Forward, Mode::HttpsConnectTunnel] {
        for response in [
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nshort".to_vec(),
        ] {
            let runtime = runtime();
            let tls = TlsFixture::new();
            let encrypted = mode == Mode::HttpsConnectTunnel;
            let endpoint = WireReceiver::start(
                &runtime,
                encrypted.then(|| Arc::clone(&tls.server)),
                Reply::Wire(response),
            );
            let fixture = Fixture::scoped(&[endpoint.rule(encrypted)]);
            let binding = fixture.http_binding();
            let registry = fixture
                .host
                .http_registry(
                    &fixture.profile,
                    configuration(mode, Arc::clone(&tls.roots), endpoint.address.port()),
                )
                .unwrap();
            let body = b"consumed before a truncated successful response";
            let input = fixture.request(&binding, &endpoint.url(encrypted), body, Vec::new());
            let result = fixture.send(&registry, &binding, &input);
            assert_eq!(endpoint.bodies(), vec![body.to_vec()]);
            assert_eq!(result.state, InvocationState::OutcomeUnknown);
            assert_eq!(
                result.error.as_ref().unwrap().code,
                ErrorCode::OutcomeUnknown
            );
            assert!(result.output_ref.is_none());
            let stored = fixture
                .host
                .ledger
                .read_invocation(result.invocation_id)
                .unwrap();
            assert!(stored.reserved_units.get() > 0);
            stored.invocation.validate(Some(&stored.history)).unwrap();
            let record = fixture.record(&result);
            assert!(
                record.exchanges.is_empty(),
                "a bounded prefix is not a completed response"
            );
            assert!(
                record
                    .stream_errors
                    .iter()
                    .any(|error| error.error.code == ErrorCode::ProviderUnavailable)
            );
            if mode != Mode::HttpsConnectTunnel {
                assert_eq!(record.partial_captures.len(), 1);
                assert!(record.partial_captures[0].capture.truncated);
                assert!(record.partial_captures[0].capture.length_bytes <= 5);
            }
        }
    }
}

#[test]
fn a_consumed_post_with_a_lost_response_retains_the_actual_canonical_reconciliation_hold() {
    use fixtures::{Reply, WireReceiver, configuration, runtime};
    use razen_engine::adapters::transport::Mode;
    use razen_engine::domain::values::InvocationState;
    use razen_engine::protocol::error::ErrorCode;
    use std::sync::Arc;

    let runtime = runtime();
    let endpoint = WireReceiver::start(&runtime, None, Reply::Lost);
    let fixture = Fixture::scoped(&[endpoint.rule(false)]);
    let binding = fixture.http_binding();
    let registry = fixture
        .host
        .http_registry(
            &fixture.profile,
            configuration(
                Mode::Http1Forward,
                Arc::new(rustls::RootCertStore::empty()),
                endpoint.address.port(),
            ),
        )
        .unwrap();
    let body = b"side effect consumed; no HTTP response bytes";
    let input = fixture.request(&binding, &endpoint.url(false), body, Vec::new());
    let result = fixture.send(&registry, &binding, &input);
    assert_eq!(endpoint.bodies(), vec![body.to_vec()]);
    assert_eq!(result.state, InvocationState::OutcomeUnknown);
    assert_eq!(
        result.error.as_ref().unwrap().code,
        ErrorCode::OutcomeUnknown
    );
    assert!(result.output_ref.is_none());
    let stored = fixture
        .host
        .ledger
        .read_invocation(result.invocation_id)
        .unwrap();
    assert!(stored.reserved_units.get() > 0);
    stored.invocation.validate(Some(&stored.history)).unwrap();
    let record = fixture.record(&result);
    assert!(record.exchanges.is_empty());
    assert_eq!(record.io.attempted_request_body_bytes, body.len() as u64);
    assert_eq!(record.io.captured_response_body_bytes, 0);
    assert_eq!(
        record.stream_errors[0].error.code,
        ErrorCode::ProviderUnavailable
    );
}

#[test]
fn h2_consumed_post_disconnect_and_bounded_response_prefixes_preserve_the_upstream_cause() {
    use fixtures::{H2Receiver, H2Reply, TlsFixture, configuration, runtime};
    use razen_engine::adapters::transport::Mode;
    use razen_engine::domain::evidence::Representation;
    use razen_engine::domain::values::{Digest, InvocationState, WireInt};
    use razen_engine::protocol::error::ErrorCode;
    use std::sync::Arc;

    const LIMIT: usize = 1_048_576;
    let prefix = rama::bytes::Bytes::from_static(b"real retained HTTP/2 response prefix");
    for (reply, expected_code, expected_body) in [
        (H2Reply::Lost, ErrorCode::ProviderUnavailable, Vec::new()),
        (
            H2Reply::Oversized(LIMIT + 1),
            ErrorCode::BudgetExhausted,
            vec![b'X'; LIMIT],
        ),
        (
            H2Reply::DisconnectAfterPrefix(prefix.clone()),
            ErrorCode::ProviderUnavailable,
            prefix.to_vec(),
        ),
    ] {
        let runtime = runtime();
        let tls = TlsFixture::h2();
        let healthy = H2Receiver::start(&runtime, Arc::clone(&tls.server), H2Reply::Echo);
        let endpoint = H2Receiver::start(&runtime, Arc::clone(&tls.server), reply);
        let fixture = Fixture::scoped(&[healthy.rule(), endpoint.rule()]);
        assert_eq!(
            fixture.profile.config().transport.body_limit_bytes.get(),
            LIMIT as u64
        );
        let binding = fixture.http_binding();
        let make_registry = |port| {
            let mut config = configuration(Mode::HttpsHttp2Intercept, Arc::clone(&tls.roots), port);
            config.ingress_tls = Some(Arc::clone(&tls.server));
            fixture
                .host
                .http_registry(&fixture.profile, config)
                .unwrap()
        };
        let body = b"the independent HTTP/2 receiver fully consumed this POST";
        let control = make_registry(healthy.address.port());
        let input = fixture.request(&binding, &healthy.url(), body, Vec::new());
        let completed = fixture.send(&control, &binding, &input);
        assert_eq!(completed.state, InvocationState::Completed);
        assert_eq!(healthy.bodies(), vec![body.to_vec()]);
        let control_record = fixture.record(&completed);
        assert_eq!(
            control_record.exchanges[0].client_alpn.as_deref(),
            Some("h2")
        );
        assert_eq!(
            control_record.exchanges[0].upstream_alpn.as_deref(),
            Some("h2")
        );

        let registry = make_registry(endpoint.address.port());
        let input = fixture.request(&binding, &endpoint.url(), body, Vec::new());
        let result = fixture.send(&registry, &binding, &input);
        assert_eq!(
            endpoint.bodies(),
            vec![body.to_vec()],
            "the POST must actually reach and be consumed by the upstream"
        );
        let unknown = expected_code == ErrorCode::ProviderUnavailable;
        assert_eq!(
            result.state,
            if unknown {
                InvocationState::OutcomeUnknown
            } else {
                InvocationState::Failed
            }
        );
        assert_eq!(
            result.error.as_ref().unwrap().code,
            if unknown {
                ErrorCode::OutcomeUnknown
            } else {
                expected_code
            }
        );
        assert!(result.output_ref.is_none());
        let stored = fixture
            .host
            .ledger
            .read_invocation(result.invocation_id)
            .unwrap();
        assert_eq!(stored.reserved_units.get() > 0, unknown);
        stored.invocation.validate(Some(&stored.history)).unwrap();
        let record = fixture.record(&result);
        assert!(
            record.exchanges.is_empty(),
            "the relay-generated RST is not a completed HTTP response"
        );
        assert_eq!(record.stream_errors.len(), 1);
        assert_eq!(
            record.stream_errors[0].error.code, expected_code,
            "the client-side RST must not replace the actual upstream cause"
        );
        assert!(record.stream_errors[0].stream_id > 0);
        assert_eq!(record.io.attempted_request_body_bytes, body.len() as u64);
        assert_eq!(
            record.io.captured_response_body_bytes,
            expected_body.len() as u64
        );
        if expected_body.is_empty() {
            assert!(record.partial_captures.is_empty());
        } else {
            assert_eq!(record.partial_captures.len(), 1);
            let partial = &record.partial_captures[0];
            assert_eq!(partial.error.code, expected_code);
            assert_eq!(partial.capture.length_bytes, expected_body.len() as u64);
            assert_eq!(partial.capture.sha256, Digest::of(&expected_body));
            assert!(partial.capture.truncated);
            assert!(partial.capture.chunks.iter().all(
                |length| *length <= fixture.profile.config().transport.chunk_limit_bytes.get()
            ));
            let snapshot = fixture
                .host
                .evidence
                .snapshot(
                    stored.invocation.project_id,
                    partial.snapshot_id,
                    WireInt::ZERO,
                )
                .unwrap();
            assert_eq!(snapshot.representation, Representation::Http2SemanticBody);
            assert!(snapshot.truncated);
            let retained = fixture
                .host
                .evidence
                .read_artifact(stored.invocation.project_id, snapshot.body_ref, LIMIT)
                .unwrap();
            assert_eq!(retained, expected_body);
        }
        let retained_bytes: u64 = fixture
            .host
            .evidence
            .artifacts()
            .unwrap()
            .iter()
            .filter(|artifact| {
                artifact.origin_invocation_id == result.invocation_id
                    && artifact.kind.as_str() != "http-send-input"
            })
            .map(|artifact| artifact.length_bytes.get())
            .sum();
        assert_eq!(
            stored.invocation.usage.bytes.get(),
            body.len() as u64
                + record.io.attempted_request_body_bytes
                + record.io.captured_response_body_bytes
                + retained_bytes,
            "both actual network capture and retained immutable prefix are charged"
        );
    }
}
