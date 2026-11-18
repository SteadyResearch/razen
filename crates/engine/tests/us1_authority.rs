use std::net::IpAddr;

use razen_engine::domain::authority::{
    ApprovalGrant, Budget, Destination, DestinationCheck, FixtureProject, IdentityProfile,
    ScopePolicy,
};
use razen_engine::domain::invocation::{Invocation, InvocationHistory};
use razen_engine::domain::values::{AuditTime, EntityId, Usage, WireInt};
use razen_engine::protocol::error::ErrorCode;
use serde_json::{Value, json};

const PROJECT: &str = "11111111-1111-4111-8111-111111111111";
const IDENTITY: &str = "22222222-2222-4222-8222-222222222222";
const GRANT: &str = "33333333-3333-4333-8333-333333333333";
const INVOCATION: &str = "44444444-4444-4444-8444-444444444444";
const BUDGET: &str = "55555555-5555-4555-8555-555555555555";
const OTHER: &str = "66666666-6666-4666-8666-666666666666";
const USER: &str = "77777777-7777-4777-8777-777777777777";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const DIFFERENT_DIGEST: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

fn wire(value: u64) -> WireInt {
    WireInt::new(value).unwrap()
}

fn id(value: &str) -> EntityId {
    EntityId::parse(value).unwrap()
}

fn at(value: &str) -> AuditTime {
    AuditTime::parse(value).unwrap()
}

fn usage(units: u64, bytes: u64, cpu_us: u64, elapsed_us: u64) -> Usage {
    Usage {
        units: wire(units),
        bytes: wire(bytes),
        cpu_us: wire(cpu_us),
        elapsed_us: wire(elapsed_us),
    }
}

fn invocation_json(state: &str) -> Value {
    let mut value = json!({"invocation_id": INVOCATION, "run_id": OTHER, "project_id": PROJECT,
        "investigation_id": OTHER, "session_id": OTHER, "actor_ref": USER,
        "tool_id": "http.send", "tool_version": "0.1.0", "provider_digest": DIGEST,
        "input_ref": OTHER, "input_sha256": DIGEST, "input_revision": 2,
        "control_revision": 4, "scope_revision": 3, "identity_id": IDENTITY,
        "budget_id": BUDGET, "attempt": 1, "causation_id": OTHER,
        "deduplication_key": "fixture.effect.1", "state": state,
        "usage": {"units": 0, "bytes": 0, "cpu_us": 0, "elapsed_us": 0}});
    if !matches!(state, "proposed" | "waiting_approval" | "rejected") {
        value["grant_id"] = json!(GRANT);
    }
    value
}

fn invocation(value: &Value, history: Option<&InvocationHistory>) -> Invocation {
    Invocation::parse_json(&serde_json::to_vec(value).unwrap(), history).unwrap()
}

fn grant_json() -> Value {
    json!({"grant_id": GRANT, "project_id": PROJECT, "tool_id": "http.send",
        "tool_version": "0.1.0", "provider_digest": DIGEST, "scope_revision": 3,
        "identity_id": IDENTITY, "bounded_input_sha256": DIGEST,
        "limits": {"units": 10, "bytes": 1024, "cpu_us": 100, "elapsed_us": 1000},
        "expires_at": "2026-11-16T14:00:00Z", "revoked": false})
}

fn grant(value: Value) -> ApprovalGrant {
    serde_json::from_value(value).unwrap()
}

fn budget_json() -> Value {
    json!({"budget_id": BUDGET, "limit": 100, "consumed": 20, "reserved": 30, "revision": 4})
}

fn budget(value: Value) -> Budget {
    serde_json::from_value(value).unwrap()
}

fn rule(host: &str, port: u16, path: &str, addresses: &[&str]) -> Value {
    json!({"scheme": "https", "host": host, "port": port,
        "path": {"kind": "prefix", "value": path}, "resolved_addresses": addresses})
}

fn scope_json() -> Value {
    json!({"scope_policy_id": OTHER, "project_id": PROJECT, "revision": 3,
        "allowed_destinations": [rule("fixture.example", 443, "/allowed/", &["127.0.0.1", "::1"])],
        "exclusions": [rule("fixture.example", 443, "/allowed/private/", &["127.0.0.1", "::1"])]})
}

fn policy(value: Value) -> ScopePolicy {
    serde_json::from_value(value).unwrap()
}

fn ip(value: &str) -> IpAddr {
    value.parse().unwrap()
}

fn check<'a>(
    destination: &'a Destination,
    addresses: &'a [IpAddr],
    chosen: &str,
) -> DestinationCheck<'a> {
    DestinationCheck {
        destination,
        resolved_addresses: addresses,
        chosen_address: ip(chosen),
        connect_authority: None,
        server_name: None,
        request_authority: None,
    }
}

#[test]
fn owned_fixture_project_and_identity_reject_foreign_owners_despite_valid_ids() {
    let project: FixtureProject = serde_json::from_value(json!({"project_id": PROJECT,
        "user_id": USER, "scope_policy_id": OTHER, "revision": 3}))
    .unwrap();
    assert!(project.validate_owner(id(USER)).is_ok());
    assert_eq!(
        project.validate_owner(id(OTHER)).unwrap_err().code,
        ErrorCode::PermissionDenied
    );
    let identity: IdentityProfile = serde_json::from_value(json!({"identity_id": IDENTITY,
        "project_id": PROJECT, "secret_ref_names": ["synthetic.fixture.authorization"]}))
    .unwrap();
    assert!(identity.validate_project(id(PROJECT)).is_ok());
    assert_eq!(
        identity.validate_project(id(OTHER)).unwrap_err().code,
        ErrorCode::PermissionDenied
    );
}

#[test]
fn current_grant_binds_every_admission_dimension_and_does_not_authorize_by_id_possession() {
    let live = grant(grant_json());
    let reserved = invocation(&invocation_json("reserved"), None);
    let now = at("2026-11-16T13:00:00Z");
    assert!(
        live.validate_current(&reserved, &usage(10, 1024, 100, 1000), now)
            .is_ok()
    );
    for (field, replacement) in [
        ("grant_id", json!(OTHER)),
        ("project_id", json!(OTHER)),
        ("tool_id", json!("context.read")),
        ("provider_digest", json!(DIFFERENT_DIGEST)),
        ("scope_revision", json!(4)),
        ("identity_id", json!(OTHER)),
        ("input_sha256", json!(DIFFERENT_DIGEST)),
    ] {
        let mut request = invocation_json("reserved");
        request[field] = replacement;
        let request = invocation(&request, None);
        assert!(
            live.validate_current(&request, &usage(1, 1, 1, 1), now)
                .is_err(),
            "unbound {field}"
        );
    }
    for requested in [
        usage(11, 1, 1, 1),
        usage(1, 1025, 1, 1),
        usage(1, 1, 101, 1),
        usage(1, 1, 1, 1001),
    ] {
        assert_eq!(
            live.validate_current(&reserved, &requested, now)
                .unwrap_err()
                .code,
            ErrorCode::BudgetExhausted
        );
    }
    let mut revoked = grant_json();
    revoked["revoked"] = json!(true);
    let revoked = grant(revoked);
    assert_eq!(
        revoked
            .validate_current(&reserved, &usage(1, 1, 1, 1), now)
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    for now in [at("2026-11-16T14:00:00Z"), at("2026-11-16T14:00:01Z")] {
        assert_eq!(
            live.validate_current(&reserved, &usage(1, 1, 1, 1), now)
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );
    }
}

#[test]
fn historical_revocation_and_expiry_do_not_erase_provenance_or_admit_another_effect() {
    let now = at("2026-11-16T13:00:00Z");
    let later = at("2026-11-16T15:00:00Z");
    let live = grant(grant_json());
    let proposed = invocation(&invocation_json("proposed"), None);
    let reserved = invocation(&invocation_json("reserved"), None);
    let sending = invocation(&invocation_json("sending"), None);
    let mut reserved_history = InvocationHistory::start(&proposed).unwrap();
    reserved_history
        .record(&reserved, Some(&live), now)
        .unwrap();

    let mut revoked = grant_json();
    revoked["revoked"] = json!(true);
    let revoked = grant(revoked);
    let cancelled = invocation(&invocation_json("cancelled"), Some(&reserved_history));
    reserved_history
        .clone()
        .record(&cancelled, Some(&revoked), later)
        .unwrap();
    assert!(
        reserved_history
            .clone()
            .record(&sending, Some(&revoked), now)
            .is_err()
    );
    assert!(
        reserved_history
            .clone()
            .record(&sending, Some(&live), later)
            .is_err()
    );
    assert!(
        InvocationHistory::start(&proposed)
            .unwrap()
            .record(&reserved, Some(&revoked), now)
            .is_err()
    );

    let mut sending_history = reserved_history;
    sending_history.record(&sending, Some(&live), now).unwrap();
    for state in ["completed", "failed", "outcome_unknown"] {
        let historic = invocation(&invocation_json(state), Some(&sending_history));
        let mut history = sending_history.clone();
        history.record(&historic, Some(&revoked), later).unwrap();
        assert_eq!(historic.grant_id, Some(id(GRANT)));
        assert!(
            revoked
                .validate_current(&historic, &usage(1, 1, 1, 1), now)
                .is_err()
        );
        if state == "outcome_unknown" {
            assert!(
                history.record(&sending, Some(&live), now).is_err(),
                "unknown effect must never automatically resend"
            );
            let completed = invocation(&invocation_json("completed"), Some(&history));
            history.record(&completed, None, later).unwrap();
        }
    }
}

#[test]
fn checked_budget_reservation_release_and_consumption_preserve_totals_and_revision() {
    let mut aggregate = budget(budget_json());
    aggregate.reserve(wire(50), wire(4)).unwrap();
    assert_eq!(
        (aggregate.consumed, aggregate.reserved, aggregate.revision),
        (wire(20), wire(80), wire(5))
    );
    aggregate.consume(wire(25), wire(5)).unwrap();
    assert_eq!(
        (aggregate.consumed, aggregate.reserved, aggregate.revision),
        (wire(45), wire(55), wire(6))
    );
    aggregate.release(wire(10), wire(6)).unwrap();
    assert_eq!(
        (aggregate.consumed, aggregate.reserved, aggregate.revision),
        (wire(45), wire(45), wire(7))
    );
    let restored = budget(serde_json::to_value(&aggregate).unwrap());
    assert_eq!(restored.consumed, wire(45));
    assert_eq!(restored.reserved, wire(45));
    assert_eq!(restored.revision, wire(7));
}

#[test]
fn budget_failures_are_atomic_and_never_wrap_or_reset_quota() {
    let original = budget(budget_json());
    for operation in [
        "over_reserve",
        "over_release",
        "over_consume",
        "stale_revision",
    ] {
        let mut aggregate = original.clone();
        let before = serde_json::to_value(&aggregate).unwrap();
        let result = match operation {
            "over_reserve" => aggregate.reserve(wire(51), wire(4)),
            "over_release" => aggregate.release(wire(31), wire(4)),
            "over_consume" => aggregate.consume(wire(31), wire(4)),
            _ => aggregate.reserve(wire(1), wire(3)),
        };
        assert!(result.is_err(), "accepted {operation}");
        assert_eq!(
            serde_json::to_value(aggregate).unwrap(),
            before,
            "partial {operation}"
        );
    }
    for (consumed, reserved) in [(100_u64, 1_u64), (9_007_199_254_740_991, 1)] {
        let mut bad = budget_json();
        bad["consumed"] = json!(consumed);
        bad["reserved"] = json!(reserved);
        assert!(serde_json::from_value::<Budget>(bad).is_err());
    }
    let mut max_revision = budget_json();
    max_revision["revision"] = json!(9_007_199_254_740_991_u64);
    let mut max_revision = budget(max_revision);
    let before = serde_json::to_value(&max_revision).unwrap();
    assert!(
        max_revision
            .reserve(wire(1), wire(9_007_199_254_740_991))
            .is_err()
    );
    assert_eq!(serde_json::to_value(max_revision).unwrap(), before);
    let mut self_parent = budget_json();
    self_parent["parent_budget_id"] = json!(BUDGET);
    assert!(serde_json::from_value::<Budget>(self_parent).is_err());
}

#[test]
fn child_budget_is_backed_by_parent_reservation_not_a_copy_of_available_balance() {
    let mut parent = budget(budget_json());
    let mut child = parent.allocate_child(id(OTHER), wire(40), wire(4)).unwrap();
    assert_eq!(
        (parent.consumed, parent.reserved, parent.revision),
        (wire(20), wire(70), wire(5))
    );
    assert_eq!(child.parent_budget_id, Some(parent.budget_id));
    assert_eq!(
        (child.limit, child.consumed, child.reserved, child.revision),
        (wire(40), wire(0), wire(0), wire(0))
    );
    child.reserve(wire(40), wire(0)).unwrap();
    assert!(child.reserve(wire(1), wire(1)).is_err());
    let before = serde_json::to_value(&parent).unwrap();
    assert!(parent.allocate_child(id(USER), wire(11), wire(5)).is_err());
    assert_eq!(serde_json::to_value(&parent).unwrap(), before);
    assert!(
        parent
            .allocate_child(parent.budget_id, wire(1), wire(5))
            .is_err()
    );
    assert_eq!(serde_json::to_value(parent).unwrap(), before);
}

#[test]
fn canonical_url_path_normalizes_hosts_default_ports_dot_segments_and_mapped_addresses() {
    let normalized =
        Destination::parse("HTTPS://FIXTURE.Example:443/allowed/./x/../item?view=1").unwrap();
    assert_eq!(normalized.scheme(), "https");
    assert_eq!(normalized.host(), "fixture.example");
    assert_eq!(normalized.port(), 443);
    assert_eq!(normalized.path(), "/allowed/item");
    let ordinary = Destination::parse("https://fixture.example/allowed/item?view=1").unwrap();
    assert_eq!(normalized, ordinary);
    let mapped = Destination::parse("https://[::ffff:127.0.0.1]:8443/allowed/item").unwrap();
    let ipv4 = Destination::parse("https://127.0.0.1:8443/allowed/item").unwrap();
    assert_eq!(mapped, ipv4);
    assert_eq!(
        Destination::parse("https://[0:0:0:0:0:0:0:1]:8443/").unwrap(),
        Destination::parse("https://[::1]:8443/").unwrap()
    );
    for ambiguous in [
        "https://user:password@fixture.example/allowed/",
        "https://@fixture.example/allowed/",
        "https://fixture.example\\@127.0.0.1/allowed/",
        "https://fixture.example:443:80/allowed/",
        "https://[fe80::1%25en0]/allowed/",
        "https://fixture.example/allowed/#hidden",
        "ftp://fixture.example/allowed/",
        "https:///fixture.example/allowed/",
        "https://fixture.example\n/allowed/",
        "https://fixture.example:0/allowed/",
    ] {
        assert!(
            Destination::parse(ambiguous).is_err(),
            "accepted {ambiguous:?}"
        );
    }
}

#[test]
fn scope_uses_normalized_destination_exclusion_first_and_denies_redirect_pivots() {
    let scope = policy(scope_json());
    let addresses = [ip("127.0.0.1"), ip("::1")];
    let allowed = Destination::parse("https://FIXTURE.EXAMPLE:443/allowed/ok").unwrap();
    assert!(
        scope
            .authorize(&check(&allowed, &addresses, "127.0.0.1"))
            .is_ok()
    );
    for url in [
        "https://fixture.example/allowed/private/secret",
        "https://fixture.example/allowed/public/../private/secret",
        "https://fixture.example/allowed/%2e%2e/private/secret",
        "https://fixture.example/not-allowed/",
        "https://fixture.example/allowedness/",
        "http://fixture.example/allowed/ok",
        "https://fixture.example:8443/allowed/ok",
        "https://other.example/allowed/ok",
        "https://127.0.0.1/allowed/ok",
    ] {
        let denied = Destination::parse(url).unwrap();
        assert_eq!(
            scope
                .authorize(&check(&denied, &addresses, "127.0.0.1"))
                .unwrap_err()
                .code,
            ErrorCode::OutOfScope,
            "admitted {url}"
        );
    }
    let mut empty = scope_json();
    empty["allowed_destinations"] = json!([]);
    assert!(
        policy(empty)
            .authorize(&check(&allowed, &addresses, "127.0.0.1"))
            .is_err()
    );
}

#[test]
fn every_dns_answer_and_actual_connected_address_must_be_explicitly_granted() {
    let scope = policy(scope_json());
    let destination = Destination::parse("https://fixture.example/allowed/ok").unwrap();
    for (answers, chosen) in [
        (vec![ip("127.0.0.1"), ip("10.0.0.1")], "127.0.0.1"),
        (vec![ip("127.0.0.1")], "10.0.0.1"),
        (vec![ip("127.0.0.1")], "::1"),
        (vec![], "127.0.0.1"),
        (vec![ip("192.168.1.1")], "192.168.1.1"),
        (vec![ip("169.254.169.254")], "169.254.169.254"),
    ] {
        assert!(
            scope
                .authorize(&check(&destination, &answers, chosen))
                .is_err(),
            "admitted {answers:?} / {chosen}"
        );
    }
    let mapped = [ip("::ffff:127.0.0.1")];
    assert!(
        scope
            .authorize(&check(&destination, &mapped, "127.0.0.1"))
            .is_ok()
    );
    assert!(
        scope
            .authorize(&check(&destination, &[ip("127.0.0.1")], "::ffff:127.0.0.1"))
            .is_ok()
    );
    let mut literal = scope_json();
    literal["allowed_destinations"] = json!([rule("127.0.0.1", 8443, "/allowed/", &["127.0.0.1"])]);
    literal["exclusions"] = json!([]);
    let literal = policy(literal);
    let mapped_url = Destination::parse("https://[::ffff:127.0.0.1]:8443/allowed/ok").unwrap();
    assert!(
        literal
            .authorize(&check(&mapped_url, &mapped, "127.0.0.1"))
            .is_ok()
    );
    let other_port = Destination::parse("https://127.0.0.1:8444/allowed/ok").unwrap();
    assert!(
        literal
            .authorize(&check(&other_port, &mapped, "127.0.0.1"))
            .is_err()
    );
}

#[test]
fn connect_server_name_and_request_authority_must_agree_with_the_canonical_url() {
    let scope = policy(scope_json());
    let destination = Destination::parse("https://fixture.example/allowed/ok").unwrap();
    let addresses = [ip("127.0.0.1")];
    let mut request = check(&destination, &addresses, "127.0.0.1");
    request.connect_authority = Some("FIXTURE.EXAMPLE:443");
    request.server_name = Some("fixture.example");
    request.request_authority = Some("fixture.example:443");
    assert!(scope.authorize(&request).is_ok());
    for mismatch in [
        "other.example:443",
        "fixture.example:8443",
        "user@fixture.example:443",
        "fixture.example:443:80",
    ] {
        request.connect_authority = Some(mismatch);
        assert!(scope.authorize(&request).is_err(), "CONNECT {mismatch}");
    }
    request.connect_authority = Some("fixture.example:443");
    request.server_name = Some("other.example");
    assert!(scope.authorize(&request).is_err());
    request.server_name = Some("fixture.example");
    for mismatch in [
        "other.example",
        "fixture.example:8443",
        "fixture.example@other.example",
    ] {
        request.request_authority = Some(mismatch);
        assert!(
            scope.authorize(&request).is_err(),
            "request authority {mismatch}"
        );
    }
}

#[test]
fn child_scope_can_only_narrow_destinations_addresses_paths_and_exclusions() {
    let parent = policy(scope_json());
    let mut narrow = scope_json();
    narrow["scope_policy_id"] = json!(USER);
    narrow["allowed_destinations"] = json!([rule(
        "fixture.example",
        443,
        "/allowed/public/",
        &["127.0.0.1"]
    )]);
    assert!(parent.validate_child(&policy(narrow.clone())).is_ok());
    for (field, replacement) in [
        ("host", json!("other.example")),
        ("port", json!(8443)),
        ("scheme", json!("http")),
        ("path", json!({"kind": "prefix", "value": "/"})),
        ("resolved_addresses", json!(["127.0.0.1", "10.0.0.1"])),
    ] {
        let mut escalated = narrow.clone();
        escalated["allowed_destinations"][0][field] = replacement;
        assert!(
            parent.validate_child(&policy(escalated)).is_err(),
            "escalated {field}"
        );
    }
    let mut removed_exclusion = scope_json();
    removed_exclusion["scope_policy_id"] = json!(USER);
    removed_exclusion["exclusions"] = json!([]);
    assert!(parent.validate_child(&policy(removed_exclusion)).is_err());
    let mut foreign = narrow;
    foreign["project_id"] = json!(OTHER);
    assert!(parent.validate_child(&policy(foreign)).is_err());
}

#[test]
fn exact_path_rules_do_not_silently_become_prefix_rules() {
    let mut exact = scope_json();
    exact["allowed_destinations"][0]["path"] = json!({"kind": "exact", "value": "/allowed/item"});
    let exact = policy(exact);
    let addresses = [ip("127.0.0.1")];
    let allowed = Destination::parse("https://fixture.example/allowed/item?view=1").unwrap();
    assert!(
        exact
            .authorize(&check(&allowed, &addresses, "127.0.0.1"))
            .is_ok()
    );
    let denied = Destination::parse("https://fixture.example/allowed/item/child").unwrap();
    assert!(
        exact
            .authorize(&check(&denied, &addresses, "127.0.0.1"))
            .is_err()
    );
}

#[test]
fn quota_totals_are_checked_at_the_exact_wire_integer_ceiling() {
    let maximum = 9_007_199_254_740_991_u64;
    let mut value = budget_json();
    value["limit"] = json!(maximum);
    value["consumed"] = json!(maximum);
    value["reserved"] = json!(1);
    assert!(serde_json::from_value::<Budget>(value.clone()).is_err());
    value["reserved"] = json!(0);
    let mut aggregate = budget(value);
    let before = serde_json::to_value(&aggregate).unwrap();
    assert!(aggregate.reserve(wire(1), wire(4)).is_err());
    assert_eq!(serde_json::to_value(aggregate).unwrap(), before);
}

#[test]
fn settlement_releases_one_reservation_and_charges_actual_usage_in_one_revision() {
    for actual in [0, 12, 30] {
        let mut aggregate = budget(budget_json());
        aggregate.settle(wire(30), wire(actual), wire(4)).unwrap();
        assert_eq!(aggregate.consumed, wire(20 + actual));
        assert_eq!(aggregate.reserved, wire(0));
        assert_eq!(aggregate.revision, wire(5));
    }
    for (reserved, actual, revision) in [(31, 1, 4), (20, 21, 4), (20, 12, 3)] {
        let mut aggregate = budget(budget_json());
        let before = serde_json::to_value(&aggregate).unwrap();
        assert!(
            aggregate
                .settle(wire(reserved), wire(actual), wire(revision))
                .is_err()
        );
        assert_eq!(serde_json::to_value(aggregate).unwrap(), before);
    }
    let mut partial = budget(budget_json());
    partial.settle(wire(20), wire(12), wire(4)).unwrap();
    assert_eq!(
        (partial.consumed, partial.reserved, partial.revision),
        (wire(32), wire(10), wire(5))
    );
    let mut exhausted_revision = budget_json();
    exhausted_revision["revision"] = json!(9_007_199_254_740_991_u64);
    let mut exhausted_revision = budget(exhausted_revision);
    let before = serde_json::to_value(&exhausted_revision).unwrap();
    assert!(
        exhausted_revision
            .settle(wire(20), wire(12), wire(9_007_199_254_740_991))
            .is_err()
    );
    assert_eq!(serde_json::to_value(exhausted_revision).unwrap(), before);
}

#[test]
fn durable_history_restores_admission_facts_without_reviving_current_authority() {
    let now = at("2026-11-16T13:00:00Z");
    let later = at("2026-11-16T15:00:00Z");
    let live = grant(grant_json());
    let proposed = invocation(&invocation_json("proposed"), None);
    let reserved = invocation(&invocation_json("reserved"), None);
    let sending = invocation(&invocation_json("sending"), None);
    let mut history = InvocationHistory::start(&proposed).unwrap();
    history.record(&reserved, Some(&live), now).unwrap();
    let stored = history.export_json().unwrap();
    let mut restored = InvocationHistory::restore_json(&stored).unwrap();
    assert_eq!(restored.export_json().unwrap(), stored);

    let mut revoked = grant_json();
    revoked["revoked"] = json!(true);
    let revoked = grant(revoked);
    assert!(
        restored
            .clone()
            .record(&sending, Some(&revoked), later)
            .is_err()
    );
    let cancelled = invocation(&invocation_json("cancelled"), Some(&restored));
    restored.record(&cancelled, None, later).unwrap();
    assert_eq!(cancelled.grant_id, Some(id(GRANT)));
    let cancelled_storage = restored.export_json().unwrap();
    let restored_cancelled = InvocationHistory::restore_json(&cancelled_storage).unwrap();
    assert_eq!(restored_cancelled.export_json().unwrap(), cancelled_storage);
    assert!(
        serde_json::to_value(&cancelled)
            .unwrap()
            .get("history")
            .is_none()
    );

    let mut sending_history = history;
    sending_history.record(&sending, Some(&live), now).unwrap();
    let unknown = invocation(&invocation_json("outcome_unknown"), Some(&sending_history));
    sending_history.record(&unknown, None, later).unwrap();
    let mut restored_unknown =
        InvocationHistory::restore_json(&sending_history.export_json().unwrap()).unwrap();
    assert!(restored_unknown.record(&sending, Some(&live), now).is_err());
    let completed = invocation(&invocation_json("completed"), Some(&restored_unknown));
    restored_unknown.record(&completed, None, later).unwrap();
}

#[test]
fn durable_history_rejects_missing_tampered_duplicated_and_unknown_storage_facts() {
    let proposed = invocation(&invocation_json("proposed"), None);
    let reserved = invocation(&invocation_json("reserved"), None);
    let live = grant(grant_json());
    let mut history = InvocationHistory::start(&proposed).unwrap();
    history
        .record(&reserved, Some(&live), at("2026-11-16T13:00:00Z"))
        .unwrap();
    let encoded = history.export_json().unwrap();
    let stored: Value = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(stored["schema_version"], json!("0.1.0"));
    assert_eq!(stored["initial"], invocation_json("proposed"));
    assert_eq!(
        stored["transitions"][0]["invocation"],
        invocation_json("reserved")
    );
    let recorded_grant: ApprovalGrant =
        serde_json::from_value(stored["transitions"][0]["admission_grant"].clone()).unwrap();
    assert_eq!(
        recorded_grant, live,
        "Historical assignment must preserve the complete typed grant"
    );
    for field in ["schema_version", "initial", "transitions"] {
        let mut missing = stored.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(InvocationHistory::restore_json(&serde_json::to_vec(&missing).unwrap()).is_err());
    }
    let mut version = stored.clone();
    version["schema_version"] = json!("0.2.0");
    assert!(InvocationHistory::restore_json(&serde_json::to_vec(&version).unwrap()).is_err());
    let mut unknown = stored.clone();
    unknown["peer_authorized"] = json!(true);
    assert!(InvocationHistory::restore_json(&serde_json::to_vec(&unknown).unwrap()).is_err());
    for field in ["invocation", "recorded_at", "admission_grant"] {
        let mut missing = stored.clone();
        missing["transitions"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            InvocationHistory::restore_json(&serde_json::to_vec(&missing).unwrap()).is_err(),
            "missing {field}"
        );
    }
    let mut stale = stored.clone();
    stale["transitions"][0]["recorded_at"] = json!("2026-11-16T15:00:00Z");
    assert!(InvocationHistory::restore_json(&serde_json::to_vec(&stale).unwrap()).is_err());
    let mut revoked_at_assignment = stored.clone();
    revoked_at_assignment["transitions"][0]["admission_grant"]["revoked"] = json!(true);
    assert!(
        InvocationHistory::restore_json(&serde_json::to_vec(&revoked_at_assignment).unwrap())
            .is_err()
    );
    let mut mismatch = stored.clone();
    mismatch["transitions"][0]["invocation"]["grant_id"] = json!(OTHER);
    assert!(InvocationHistory::restore_json(&serde_json::to_vec(&mismatch).unwrap()).is_err());
    let mut bad_transition = stored.clone();
    bad_transition["transitions"][0]["invocation"]["state"] = json!("sending");
    assert!(
        InvocationHistory::restore_json(&serde_json::to_vec(&bad_transition).unwrap()).is_err()
    );
    let text = String::from_utf8(encoded).unwrap();
    let duplicated = format!("{{\"schema_version\":\"0.1.0\",{}", &text[1..]);
    assert!(InvocationHistory::restore_json(duplicated.as_bytes()).is_err());
    let mut unbounded = stored.clone();
    unbounded["transitions"] = json!(vec![stored["transitions"][0].clone(); 4097]);
    assert!(InvocationHistory::restore_json(&serde_json::to_vec(&unbounded).unwrap()).is_err());
}
