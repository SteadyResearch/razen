#[allow(dead_code)]
#[path = "../src/adapters/transport/io.rs"]
mod transport_io;

#[path = "support/transport_fixtures.rs"]
pub mod fixtures;

use fixtures::{Fixture, assert_denied, attempt};

#[test]
fn excluded_redirect_dns_mapped_and_ungranted_destinations_never_reach_healthy_receivers() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-05");
    for variant in [
        "excluded",
        "redirect_pivot",
        "dns_change",
        "dns_mixed_answers",
        "ipv4_mapped_ipv6",
        "ungranted_loopback_port",
        "ungranted_private_port",
        "userinfo",
        "ambiguous_authority",
        "ipv6_zone",
    ] {
        let fact = attempt(&observation, variant);
        assert_denied(fact);
        assert_eq!(fact["counter_kind"], "tcp_accept");
        assert_eq!(
            fact["error_code"].as_str().unwrap(),
            if ["userinfo", "ambiguous_authority", "ipv6_zone"].contains(&variant) {
                "invalid_input"
            } else {
                "out_of_scope"
            }
        );
    }
    assert!(
        attempt(&observation, "redirect_pivot")["redirects_observed"]
            .as_u64()
            .unwrap()
            > 0
    );
    assert!(
        attempt(&observation, "dns_change")["resolution_count"]
            .as_u64()
            .unwrap()
            >= 2
    );
    assert!(
        attempt(&observation, "dns_mixed_answers")["resolved_addresses"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );
}

#[test]
fn invalid_upstream_certificate_and_all_authority_pivots_fail_without_trust_bypass() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-06");
    for variant in [
        "invalid_upstream_certificate",
        "connect_sni_mismatch",
        "decrypted_authority_mismatch",
        "client_root_removed",
    ] {
        assert_denied(attempt(&observation, variant));
        assert_eq!(
            attempt(&observation, variant)["error_code"],
            if variant == "decrypted_authority_mismatch" {
                "out_of_scope"
            } else {
                "permission_denied"
            }
        );
    }
    assert_eq!(
        attempt(&observation, "invalid_upstream_certificate")["error_code"],
        "permission_denied"
    );
    let trust = &observation.report["trust"];
    assert_eq!(trust["before_sha256"], trust["after_sha256"]);
    assert!(trust["before_artifact_id"].is_string());
    assert!(trust["after_artifact_id"].is_string());
    assert!(trust["public_root_artifact_id"].is_string());
    let bytes = serde_json::to_vec(&observation.report).unwrap();
    let public = String::from_utf8_lossy(&bytes);
    for marker in [
        "PRIVATE KEY",
        "CLIENT_RANDOM",
        "SSLKEYLOGFILE",
        "RAZEN_FIXTURE_CREDENTIAL_DO_NOT_EXPORT_20261116",
        "RAZEN_FIXTURE_HOST_CANARY_20261116",
        "/Users/",
    ] {
        assert!(
            !public.contains(marker),
            "prohibited marker escaped: {marker}"
        );
    }
}

#[test]
fn every_transport_provider_invocation_has_real_current_grant_usage_and_canonical_trace() {
    let fixture = Fixture::new();
    let observation = fixture.execute("NET-01");
    let ids = observation.report["provider_invocation_ids"]
        .as_array()
        .unwrap();
    assert!(!ids.is_empty());
    for id in ids {
        let id = serde_json::from_value(id.clone()).unwrap();
        let stored = fixture.host.ledger.read_invocation(id).unwrap();
        assert_eq!(stored.invocation.tool_id.as_str(), "http.send");
        assert!(stored.invocation.grant_id.is_some());
        assert_eq!(
            stored.invocation.state,
            razen_engine::domain::values::InvocationState::Completed
        );
        assert!(stored.invocation.usage.bytes.get() > 0);
        assert!(stored.invocation.usage.elapsed_us.get() > 0);
        assert!(stored.invocation.usage.cpu_us.get() > 0);
        assert_eq!(stored.reserved_units.get(), 0);
        stored.invocation.validate(Some(&stored.history)).unwrap();
        let grant = fixture
            .host
            .ledger
            .read_grant(stored.invocation.grant_id.unwrap())
            .unwrap();
        assert_eq!(grant.bounded_input_sha256, stored.invocation.input_sha256);
        assert_eq!(grant.identity_id, stored.invocation.identity_id);
    }
}

#[test]
fn permitted_http_to_https_redirect_negotiates_verified_tls_and_never_sends_plaintext() {
    use fixtures::{Reply, TlsFixture, WireReceiver, configuration, runtime};
    use razen_engine::adapters::transport::Mode;
    use razen_engine::domain::values::InvocationState;
    use razen_engine::protocol::error::ErrorCode;
    use std::sync::Arc;

    let runtime = runtime();
    let tls = TlsFixture::new();
    let secure = WireReceiver::start(&runtime, Some(Arc::clone(&tls.server)), Reply::Echo);
    let redirect = WireReceiver::start(&runtime, None, Reply::Redirect(secure.url(true)));
    let fixture = Fixture::scoped(&[redirect.rule(false), secure.rule(true)]);
    let binding = fixture.http_binding();
    let config = configuration(
        Mode::Http1Forward,
        Arc::clone(&tls.roots),
        redirect.address.port(),
    );
    let registry = fixture
        .host
        .http_registry(&fixture.profile, config.clone())
        .unwrap();
    let body = b"actual consumed POST through a verified scheme transition";
    let input = fixture.request(&binding, &redirect.url(false), body, Vec::new());
    let result = fixture.send(&registry, &binding, &input);
    assert_eq!(result.state, InvocationState::Completed);
    assert_eq!(redirect.bodies(), vec![body.to_vec()]);
    assert_eq!(secure.bodies(), vec![body.to_vec()]);
    assert_eq!(secure.tls_accepted(), 1);
    assert_eq!(secure.plaintext(), 0);
    let record = fixture.record(&result);
    assert_eq!(record.redirects_observed, 1);
    assert_eq!(record.connections.len(), 2);
    assert_eq!(
        record.exchanges[0].upstream_alpn.as_deref(),
        Some("http/1.1")
    );
    assert!(
        record.exchanges[0]
            .upstream_peer_certificate_sha256
            .is_some()
    );

    // The same real destination is reachable, but removing its explicit root
    // causes an observed TLS rejection, not plaintext or an OS-trust fallback.
    let mut untrusted = config;
    untrusted.upstream_roots = Arc::new(rustls::RootCertStore::empty());
    let registry = fixture
        .host
        .http_registry(&fixture.profile, untrusted)
        .unwrap();
    let input = fixture.request(&binding, &redirect.url(false), body, Vec::new());
    let rejected = fixture.send(&registry, &binding, &input);
    assert_ne!(rejected.state, InvocationState::Completed);
    assert_eq!(rejected.error.unwrap().code, ErrorCode::PermissionDenied);
    secure.wait_tls_rejected(1);
    assert_eq!(secure.bodies(), vec![body.to_vec()]);
    assert_eq!(secure.plaintext(), 0);
}

#[test]
fn private_host_credential_is_not_forwarded_across_a_redirect_origin_or_published() {
    use fixtures::{Reply, TlsFixture, WireReceiver, configuration, runtime};
    use razen_engine::adapters::transport::Mode;
    use razen_engine::domain::values::InvocationState;
    use razen_engine::protocol::error::ErrorCode;
    use std::sync::Arc;

    let runtime = runtime();
    let tls = TlsFixture::new();
    let secure = WireReceiver::start(&runtime, Some(Arc::clone(&tls.server)), Reply::Echo);
    let redirect = WireReceiver::start(&runtime, None, Reply::Redirect(secure.url(true)));
    let fixture = Fixture::scoped(&[redirect.rule(false), secure.rule(true)]);
    let binding = fixture.http_binding();
    let token = format!(
        "owned-private-redirect-{}",
        razen_engine::domain::values::EntityId::new()
    );
    let registry = fixture.secret_registry(
        configuration(
            Mode::Http1Forward,
            Arc::clone(&tls.roots),
            redirect.address.port(),
        ),
        &binding,
        &token,
    );
    let input = fixture.request(
        &binding,
        &redirect.url(false),
        b"owned credential scope probe",
        Vec::new(),
    );
    let result = fixture.send(&registry, &binding, &input);
    assert_ne!(result.state, InvocationState::Completed);
    assert_eq!(result.error.unwrap().code, ErrorCode::PermissionDenied);
    assert_eq!(
        redirect.authorizations(),
        vec![Some(format!("Bearer {token}"))]
    );
    assert!(secure.bodies().is_empty());
    assert_eq!(
        secure.tls_accepted(),
        0,
        "cross-origin credential rejection must precede the next connection"
    );
    for artifact in fixture.host.evidence.artifacts().unwrap() {
        let bytes = fixture
            .host
            .evidence
            .read_artifact(artifact.project_id, artifact.artifact_id, 8 * 1_048_576)
            .unwrap();
        assert!(
            !bytes
                .windows(token.len())
                .any(|bytes| bytes == token.as_bytes()),
            "private credential escaped an immutable artifact"
        );
    }
}

#[test]
fn verified_https_redirect_cannot_downgrade_to_an_allowed_plaintext_origin() {
    use fixtures::{Reply, TlsFixture, WireReceiver, configuration, runtime};
    use razen_engine::adapters::transport::Mode;
    use razen_engine::domain::values::InvocationState;
    use razen_engine::protocol::error::ErrorCode;
    use std::sync::Arc;

    let runtime = runtime();
    let tls = TlsFixture::new();
    let plaintext = WireReceiver::start(&runtime, None, Reply::Echo);
    let redirect = WireReceiver::start(
        &runtime,
        Some(Arc::clone(&tls.server)),
        Reply::Redirect(plaintext.url(false)),
    );
    let fixture = Fixture::scoped(&[redirect.rule(true), plaintext.rule(false)]);
    let binding = fixture.http_binding();
    let mut config = configuration(
        Mode::HttpsHttp1Intercept,
        Arc::clone(&tls.roots),
        redirect.address.port(),
    );
    config.ingress_tls = Some(Arc::clone(&tls.server));
    let registry = fixture
        .host
        .http_registry(&fixture.profile, config)
        .unwrap();
    let input = fixture.request(
        &binding,
        &redirect.url(true),
        b"no TLS downgrade",
        Vec::new(),
    );
    let result = fixture.send(&registry, &binding, &input);
    assert_ne!(result.state, InvocationState::Completed);
    assert_eq!(result.error.unwrap().code, ErrorCode::PermissionDenied);
    assert_eq!(redirect.tls_accepted(), 1);
    assert!(plaintext.bodies().is_empty());

    let control = fixture
        .host
        .http_registry(
            &fixture.profile,
            configuration(
                Mode::Http1Forward,
                Arc::clone(&tls.roots),
                plaintext.address.port(),
            ),
        )
        .unwrap();
    let input = fixture.request(
        &binding,
        &plaintext.url(false),
        b"healthy allowed plaintext observer",
        Vec::new(),
    );
    assert_eq!(
        fixture.send(&control, &binding, &input).state,
        InvocationState::Completed
    );
    assert_eq!(
        plaintext.bodies(),
        vec![b"healthy allowed plaintext observer".to_vec()]
    );
}
