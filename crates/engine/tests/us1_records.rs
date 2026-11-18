use std::fmt::Debug;

use razen_engine::domain::authority::{
    ApprovalGrant, Budget, FixtureProject, IdentityProfile, ScopePolicy, ToolDescriptor,
};
use razen_engine::domain::execution::{
    Checkpoint, ControlMeasurement, ControlMode, ControlState, Event, OutboxEntry,
};
use razen_engine::domain::invocation::{Invocation, InvocationHistory};
use razen_engine::domain::values::{AuditTime, InvocationState};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const PROJECT: &str = "11111111-1111-4111-8111-111111111111";
const USER: &str = "22222222-2222-4222-8222-222222222222";
const SCOPE: &str = "33333333-3333-4333-8333-333333333333";
const IDENTITY: &str = "44444444-4444-4444-8444-444444444444";
const INVOCATION: &str = "55555555-5555-4555-8555-555555555555";
const GRANT: &str = "66666666-6666-4666-8666-666666666666";
const BUDGET: &str = "77777777-7777-4777-8777-777777777777";
const RUN: &str = "88888888-8888-4888-8888-888888888888";
const INVESTIGATION: &str = "99999999-9999-4999-8999-999999999999";
const SESSION: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const INPUT: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const OTHER: &str = "cccccccc-cccc-4ccc-8ccc-cccccccccccc";
const DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn usage() -> Value {
    json!({"units": 1, "bytes": 64, "cpu_us": 10, "elapsed_us": 20})
}

fn project() -> Value {
    json!({"project_id": PROJECT, "user_id": USER, "scope_policy_id": SCOPE, "revision": 3})
}

fn scope() -> Value {
    json!({
        "scope_policy_id": SCOPE, "project_id": PROJECT, "revision": 3,
        "allowed_destinations": [{"scheme": "https", "host": "fixture.example", "port": 443,
            "path": {"kind": "prefix", "value": "/allowed/"},
            "resolved_addresses": ["127.0.0.1"]}],
        "exclusions": []
    })
}

fn identity() -> Value {
    json!({"identity_id": IDENTITY, "project_id": PROJECT,
        "secret_ref_names": ["synthetic.fixture.authorization"]})
}

fn descriptor() -> Value {
    json!({"tool_id": "http.send", "version": "0.1.0",
        "input_contract": "http.send.input", "output_contract": "http.send.output",
        "effect": "active_network", "permissions": ["fixture.http.send"],
        "limits": usage(), "retry_class": "non_retryable"})
}

fn grant() -> Value {
    json!({"grant_id": GRANT, "project_id": PROJECT, "tool_id": "http.send",
        "tool_version": "0.1.0", "provider_digest": DIGEST, "scope_revision": 3,
        "identity_id": IDENTITY, "bounded_input_sha256": DIGEST, "limits": usage(),
        "expires_at": "2026-11-16T14:00:00Z", "revoked": false})
}

fn budget() -> Value {
    json!({"budget_id": BUDGET, "limit": 100, "consumed": 20, "reserved": 30, "revision": 4})
}

fn invocation(state: &str, has_grant: bool) -> Value {
    let mut value = json!({
        "invocation_id": INVOCATION, "run_id": RUN, "project_id": PROJECT,
        "investigation_id": INVESTIGATION, "session_id": SESSION, "actor_ref": USER,
        "tool_id": "http.send", "tool_version": "0.1.0", "provider_digest": DIGEST,
        "input_ref": INPUT, "input_sha256": DIGEST, "input_revision": 2,
        "control_revision": 4, "scope_revision": 3, "identity_id": IDENTITY,
        "budget_id": BUDGET, "attempt": 1, "causation_id": OTHER,
        "deduplication_key": "fixture.effect.1", "state": state, "usage": usage()
    });
    if has_grant {
        value["grant_id"] = json!(GRANT);
    }
    value
}

fn checkpoint() -> Value {
    json!({"checkpoint_id": OTHER, "run_id": RUN, "schema_version": "0.1.0",
        "control_revision": 4, "scope_revision": 3, "budget_refs": [BUDGET],
        "invocation_refs": [INVOCATION], "lease_refs": [INPUT],
        "event_cursors": {INVOCATION: 9}, "created_at": "2026-11-16T13:00:00Z"})
}

fn control() -> Value {
    json!({"investigation_id": INVESTIGATION, "revision": 4, "mode": "running",
        "admission_open": true, "instruction_ref": INPUT})
}

fn measurement() -> Value {
    json!({"request_id": OTHER, "clock_epoch_id": RUN, "received_us": 100,
        "barrier_active_us": 200, "acknowledged_us": 300, "affected_revision": 5,
        "late_admissions": 0})
}

fn event() -> Value {
    json!({"event_id": OTHER, "schema_version": "0.1.0", "project_id": PROJECT,
        "aggregate_id": INVOCATION, "aggregate_sequence": 9, "event_type": "invocation.reserved",
        "timestamp": "2026-11-16T13:00:00Z", "correlation_id": RUN, "causation_id": INPUT,
        "data_refs": [INVOCATION], "published": false})
}

fn round_trip<T: DeserializeOwned + Serialize + Debug + PartialEq>(value: &Value) -> T {
    let record: T = serde_json::from_value(value.clone()).expect("valid canonical record");
    let encoded = serde_json::to_vec(&record).unwrap();
    let decoded: T = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(
        decoded, record,
        "Serialization must preserve all typed record values"
    );
    record
}

fn strict_record<T: DeserializeOwned + Serialize + Debug + PartialEq>(
    value: Value,
    optional: &[&str],
) {
    round_trip::<T>(&value);
    for (field, original) in value.as_object().unwrap() {
        if !optional.contains(&field.as_str()) {
            let mut missing = value.clone();
            missing.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<T>(missing).is_err(),
                "missing required {field}"
            );
        }
        let mut nullable = value.clone();
        nullable[field] = Value::Null;
        assert!(
            serde_json::from_value::<T>(nullable).is_err(),
            "nullable {field}"
        );
        let encoded = serde_json::to_string(&value).unwrap();
        let duplicate = format!(
            "{{{}:{original},{}",
            serde_json::to_string(field).unwrap(),
            &encoded[1..]
        );
        assert!(
            serde_json::from_str::<T>(&duplicate).is_err(),
            "duplicate {field}"
        );
    }
    let mut unknown = value;
    unknown["unreviewed_extension"] = json!(true);
    assert!(serde_json::from_value::<T>(unknown).is_err());
}

fn parse_invocation(value: &Value, history: Option<&InvocationHistory>) -> Invocation {
    let record = Invocation::parse_json(&serde_json::to_vec(value).unwrap(), history)
        .expect("valid invocation and provenance");
    assert_eq!(serde_json::to_value(&record).unwrap(), *value);
    record
}

fn now() -> AuditTime {
    AuditTime::parse("2026-11-16T13:00:00Z").unwrap()
}

#[test]
fn complete_authority_and_execution_records_round_trip_without_defaulting_fields() {
    strict_record::<FixtureProject>(project(), &[]);
    strict_record::<ScopePolicy>(scope(), &[]);
    strict_record::<IdentityProfile>(identity(), &[]);
    strict_record::<ToolDescriptor>(descriptor(), &[]);
    strict_record::<ApprovalGrant>(grant(), &[]);
    strict_record::<Budget>(budget(), &["parent_budget_id"]);
    strict_record::<Checkpoint>(checkpoint(), &[]);
    strict_record::<ControlState>(control(), &[]);
    strict_record::<ControlMeasurement>(measurement(), &[]);
    strict_record::<Event>(event(), &["control_revision"]);
    strict_record::<OutboxEntry>(event(), &["control_revision"]);
}

#[test]
fn optional_fields_are_omitted_not_null_and_present_fields_are_preserved() {
    let mut child_budget = budget();
    child_budget["parent_budget_id"] = json!(OTHER);
    strict_record::<Budget>(child_budget, &["parent_budget_id"]);
    let mut revisioned_event = event();
    revisioned_event["control_revision"] = json!(4);
    strict_record::<Event>(revisioned_event, &["control_revision"]);
    let mut nullable_budget = budget();
    nullable_budget["parent_budget_id"] = Value::Null;
    assert!(serde_json::from_value::<Budget>(nullable_budget).is_err());
    let mut nullable_event = event();
    nullable_event["control_revision"] = Value::Null;
    assert!(serde_json::from_value::<Event>(nullable_event).is_err());
    let mut completed = invocation("completed", true);
    completed["output_ref"] = json!(OTHER);
    parse_invocation(&completed, None);
    let mut failed = invocation("failed", true);
    failed["error"] = json!({"code": "permission_denied", "message": "Fixture denied",
        "invocation_id": INVOCATION, "retryability": "never", "diagnostic_refs": []});
    parse_invocation(&failed, None);
    for field in ["output_ref", "error"] {
        let mut value = invocation("completed", true);
        value[field] = Value::Null;
        assert!(Invocation::parse_json(&serde_json::to_vec(&value).unwrap(), None).is_err());
    }
    failed["output_ref"] = json!(OTHER);
    assert!(Invocation::parse_json(&serde_json::to_vec(&failed).unwrap(), None).is_err());
}

#[test]
fn invocation_rejects_every_missing_required_field_duplicate_unknown_and_numeric_coercion() {
    let value = invocation("reserved", true);
    parse_invocation(&value, None);
    for (field, original) in value.as_object().unwrap() {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            Invocation::parse_json(&serde_json::to_vec(&missing).unwrap(), None).is_err(),
            "missing {field}"
        );
        let encoded = serde_json::to_string(&value).unwrap();
        let duplicate = format!(
            "{{{}:{original},{}",
            serde_json::to_string(field).unwrap(),
            &encoded[1..]
        );
        assert!(
            Invocation::parse_json(duplicate.as_bytes(), None).is_err(),
            "duplicate {field}"
        );
        let mut nullable = value.clone();
        nullable[field] = Value::Null;
        assert!(
            Invocation::parse_json(&serde_json::to_vec(&nullable).unwrap(), None).is_err(),
            "null {field}"
        );
    }
    for extra in ["history", "authority", "role"] {
        let mut unknown = value.clone();
        unknown[extra] = json!([]);
        assert!(Invocation::parse_json(&serde_json::to_vec(&unknown).unwrap(), None).is_err());
    }
    for field in [
        "input_revision",
        "control_revision",
        "scope_revision",
        "attempt",
    ] {
        for invalid in [
            json!(-1),
            json!(1.5),
            json!("1"),
            json!(9_007_199_254_740_992_u64),
        ] {
            let mut bad = value.clone();
            bad[field] = invalid;
            assert!(
                Invocation::parse_json(&serde_json::to_vec(&bad).unwrap(), None).is_err(),
                "invalid {field}"
            );
        }
    }
    for counter in ["units", "bytes", "cpu_us", "elapsed_us"] {
        let mut missing = value.clone();
        missing["usage"].as_object_mut().unwrap().remove(counter);
        assert!(Invocation::parse_json(&serde_json::to_vec(&missing).unwrap(), None).is_err());
    }
}

#[test]
fn state_dependent_grant_matrix_accepts_only_the_documented_non_cancelled_shapes() {
    for state in ["proposed", "rejected", "waiting_approval"] {
        parse_invocation(&invocation(state, false), None);
        assert!(
            Invocation::parse_json(&serde_json::to_vec(&invocation(state, true)).unwrap(), None)
                .is_err()
        );
    }
    for state in [
        "reserved",
        "sending",
        "completed",
        "failed",
        "outcome_unknown",
    ] {
        parse_invocation(&invocation(state, true), None);
        assert!(
            Invocation::parse_json(
                &serde_json::to_vec(&invocation(state, false)).unwrap(),
                None
            )
            .is_err()
        );
    }
    for state in [
        "proposed",
        "rejected",
        "waiting_approval",
        "reserved",
        "sending",
        "completed",
        "failed",
        "outcome_unknown",
        "cancelled",
    ] {
        let mut value = invocation(state, false);
        value["grant_id"] = Value::Null;
        assert!(Invocation::parse_json(&serde_json::to_vec(&value).unwrap(), None).is_err());
        for placeholder in ["", "grant-pending", "00000000-0000-0000-0000-000000000000"] {
            value["grant_id"] = json!(placeholder);
            assert!(Invocation::parse_json(&serde_json::to_vec(&value).unwrap(), None).is_err());
        }
    }
    let mut unknown = invocation("approved", true);
    assert!(Invocation::parse_json(&serde_json::to_vec(&unknown).unwrap(), None).is_err());
    unknown["state"] = json!("Reserved");
    assert!(Invocation::parse_json(&serde_json::to_vec(&unknown).unwrap(), None).is_err());
}

#[test]
fn cancellation_requires_trusted_history_and_preserves_exact_assignment_provenance() {
    for has_grant in [false, true] {
        assert!(
            Invocation::parse_json(
                &serde_json::to_vec(&invocation("cancelled", has_grant)).unwrap(),
                None
            )
            .is_err()
        );
    }
    let proposed = parse_invocation(&invocation("proposed", false), None);
    let waiting = parse_invocation(&invocation("waiting_approval", false), None);
    let mut waiting_history = InvocationHistory::start(&proposed).unwrap();
    waiting_history.record(&waiting, None, now()).unwrap();
    let absent = parse_invocation(&invocation("cancelled", false), Some(&waiting_history));
    waiting_history.record(&absent, None, now()).unwrap();
    assert_eq!(absent.state, InvocationState::Cancelled);
    assert!(
        Invocation::parse_json(
            &serde_json::to_vec(&invocation("cancelled", true)).unwrap(),
            Some(&waiting_history)
        )
        .is_err()
    );

    let reserved = parse_invocation(&invocation("reserved", true), None);
    let live_grant: ApprovalGrant = serde_json::from_value(grant()).unwrap();
    let mut reserved_history = InvocationHistory::start(&proposed).unwrap();
    reserved_history
        .record(&reserved, Some(&live_grant), now())
        .unwrap();
    let retained = parse_invocation(&invocation("cancelled", true), Some(&reserved_history));
    reserved_history.record(&retained, None, now()).unwrap();
    assert!(
        Invocation::parse_json(
            &serde_json::to_vec(&invocation("cancelled", false)).unwrap(),
            Some(&reserved_history)
        )
        .is_err()
    );
    let mut substituted = invocation("cancelled", true);
    substituted["grant_id"] = json!(OTHER);
    assert!(
        Invocation::parse_json(
            &serde_json::to_vec(&substituted).unwrap(),
            Some(&reserved_history)
        )
        .is_err()
    );
    substituted["grant_id"] = json!(GRANT);
    substituted["invocation_id"] = json!(OTHER);
    assert!(
        Invocation::parse_json(
            &serde_json::to_vec(&substituted).unwrap(),
            Some(&reserved_history)
        )
        .is_err()
    );
}

#[test]
fn only_the_complete_documented_transition_graph_is_accepted() {
    let live_grant: ApprovalGrant = serde_json::from_value(grant()).unwrap();
    let paths: &[&[&str]] = &[
        &["proposed", "rejected"],
        &["proposed", "waiting_approval", "cancelled"],
        &["proposed", "reserved", "cancelled"],
        &[
            "proposed",
            "waiting_approval",
            "reserved",
            "sending",
            "completed",
        ],
        &["proposed", "reserved", "sending", "failed"],
        &[
            "proposed",
            "reserved",
            "sending",
            "outcome_unknown",
            "completed",
        ],
        &[
            "proposed",
            "reserved",
            "sending",
            "outcome_unknown",
            "failed",
        ],
    ];
    let edges = [
        ("proposed", "rejected"),
        ("proposed", "waiting_approval"),
        ("proposed", "reserved"),
        ("waiting_approval", "reserved"),
        ("waiting_approval", "cancelled"),
        ("reserved", "cancelled"),
        ("reserved", "sending"),
        ("sending", "completed"),
        ("sending", "failed"),
        ("sending", "outcome_unknown"),
        ("outcome_unknown", "completed"),
        ("outcome_unknown", "failed"),
    ];
    let states = [
        "proposed",
        "rejected",
        "waiting_approval",
        "reserved",
        "sending",
        "completed",
        "failed",
        "outcome_unknown",
        "cancelled",
    ];
    let assert_forbidden = |history: &InvocationHistory, last: &str, assigned: bool| {
        for next_state in states {
            if edges.contains(&(last, next_state)) {
                continue;
            }
            let has_grant = match next_state {
                "proposed" | "rejected" | "waiting_approval" => false,
                "cancelled" => assigned,
                _ => true,
            };
            let shape = invocation(next_state, has_grant);
            let mut fork = history.clone();
            if let Ok(next) =
                Invocation::parse_json(&serde_json::to_vec(&shape).unwrap(), Some(&fork))
            {
                assert!(
                    fork.record(&next, Some(&live_grant), now()).is_err(),
                    "accepted {last} -> {next_state}"
                );
            }
        }
    };
    for path in paths {
        let proposed = parse_invocation(&invocation("proposed", false), None);
        let mut history = InvocationHistory::start(&proposed).unwrap();
        let mut assigned = false;
        assert_forbidden(&history, "proposed", assigned);
        for state in &path[1..] {
            assigned |= *state == "reserved";
            let next = parse_invocation(&invocation(state, assigned), Some(&history));
            let grant = matches!(*state, "reserved" | "sending").then_some(&live_grant);
            history.record(&next, grant, now()).unwrap();
            assert_forbidden(&history, state, assigned);
        }
    }
    let reserved = parse_invocation(&invocation("reserved", true), None);
    assert!(InvocationHistory::start(&reserved).is_err());
    let proposed = parse_invocation(&invocation("proposed", false), None);
    let mut history = InvocationHistory::start(&proposed).unwrap();
    assert!(history.record(&reserved, None, now()).is_err());
    let mut changed = invocation("reserved", true);
    for (field, replacement) in [
        ("run_id", json!(OTHER)),
        ("project_id", json!(OTHER)),
        ("session_id", json!(OTHER)),
        ("identity_id", json!(OTHER)),
        ("budget_id", json!(OTHER)),
        ("input_ref", json!(OTHER)),
        ("deduplication_key", json!("different.effect")),
        ("attempt", json!(2)),
    ] {
        changed[field] = replacement;
        let next = parse_invocation(&changed, None);
        assert!(
            history
                .clone()
                .record(&next, Some(&live_grant), now())
                .is_err(),
            "changed {field}"
        );
        changed = invocation("reserved", true);
    }
}

#[test]
fn versions_catalog_handles_and_entity_namespaces_are_not_interchangeable() {
    for version in ["0.1", "0.1.1", "1.0.0", "latest", "0.1.0+unreviewed"] {
        let mut tool = descriptor();
        tool["version"] = json!(version);
        assert!(serde_json::from_value::<ToolDescriptor>(tool).is_err());
        let mut approval = grant();
        approval["tool_version"] = json!(version);
        assert!(serde_json::from_value::<ApprovalGrant>(approval).is_err());
        let mut cp = checkpoint();
        cp["schema_version"] = json!(version);
        assert!(serde_json::from_value::<Checkpoint>(cp).is_err());
        let mut ev = event();
        ev["schema_version"] = json!(version);
        assert!(serde_json::from_value::<Event>(ev).is_err());
        let mut inv = invocation("proposed", false);
        inv["tool_version"] = json!(version);
        assert!(Invocation::parse_json(&serde_json::to_vec(&inv).unwrap(), None).is_err());
    }
    for bad in [
        "R0-01",
        "CON-01",
        "not-a-uuid",
        "11111111-1111-1111-8111-111111111111",
    ] {
        let mut value = project();
        value["project_id"] = json!(bad);
        assert!(serde_json::from_value::<FixtureProject>(value).is_err());
    }
    let mut tool = descriptor();
    tool["tool_id"] = json!("fixture:local-read.v1");
    round_trip::<ToolDescriptor>(&tool);
    tool["tool_id"] = json!("../../executable");
    assert!(serde_json::from_value::<ToolDescriptor>(tool).is_err());
}

#[test]
fn nested_unknowns_duplicate_cursors_and_incomplete_resource_limits_are_rejected() {
    let mut value = descriptor();
    value["limits"]["network"] = json!(true);
    assert!(serde_json::from_value::<ToolDescriptor>(value).is_err());
    for counter in ["units", "bytes", "cpu_us", "elapsed_us"] {
        let mut tool = descriptor();
        tool["limits"].as_object_mut().unwrap().remove(counter);
        assert!(serde_json::from_value::<ToolDescriptor>(tool).is_err());
        let mut approval = grant();
        approval["limits"].as_object_mut().unwrap().remove(counter);
        assert!(serde_json::from_value::<ApprovalGrant>(approval).is_err());
    }
    let encoded = serde_json::to_string(&checkpoint()).unwrap();
    let cursor = format!("\"{INVOCATION}\":9");
    let duplicated = encoded.replace(&cursor, &format!("{cursor},{cursor}"));
    assert_ne!(duplicated, encoded);
    assert!(serde_json::from_str::<Checkpoint>(&duplicated).is_err());
    let mut bad_cursor = checkpoint();
    bad_cursor["event_cursors"] = json!({"not-an-aggregate": 1});
    assert!(serde_json::from_value::<Checkpoint>(bad_cursor).is_err());
    let mut policy = scope();
    policy["allowed_destinations"][0]["trusted"] = json!(true);
    assert!(serde_json::from_value::<ScopePolicy>(policy).is_err());
    let mut policy = scope();
    policy["allowed_destinations"][0]["path"]["bypass"] = json!(true);
    assert!(serde_json::from_value::<ScopePolicy>(policy).is_err());
}

#[test]
fn descriptor_effects_and_retry_classes_are_closed_and_identity_is_references_only() {
    for effect in [
        "local_read",
        "local_write",
        "active_network",
        "data_egress",
        "sensitive",
    ] {
        let mut tool = descriptor();
        tool["effect"] = json!(effect);
        round_trip::<ToolDescriptor>(&tool);
    }
    for retry_class in ["safe_read", "deduplicated", "non_retryable"] {
        let mut tool = descriptor();
        tool["retry_class"] = json!(retry_class);
        round_trip::<ToolDescriptor>(&tool);
    }
    for (field, invalid) in [("effect", "network"), ("retry_class", "automatic")] {
        let mut tool = descriptor();
        tool[field] = json!(invalid);
        assert!(serde_json::from_value::<ToolDescriptor>(tool).is_err());
    }
    let mut profile = identity();
    profile["secret_values"] = json!(["synthetic-secret-not-a-reference"]);
    assert!(serde_json::from_value::<IdentityProfile>(profile).is_err());
}

#[test]
fn control_records_validate_closed_modes_and_monotonic_host_local_measurement() {
    for (mode, expected) in [
        ("running", ControlMode::Running),
        ("paused", ControlMode::Paused),
        ("cancelled", ControlMode::Cancelled),
    ] {
        let mut value = control();
        value["mode"] = json!(mode);
        value["admission_open"] = json!(mode == "running");
        let record: ControlState = round_trip(&value);
        assert_eq!(record.mode, expected);
    }
    for mode in ["paused", "cancelled", "stopping", "Running"] {
        let mut value = control();
        value["mode"] = json!(mode);
        assert!(serde_json::from_value::<ControlState>(value).is_err());
    }
    for (field, invalid) in [("barrier_active_us", 99), ("acknowledged_us", 199)] {
        let mut value = measurement();
        value[field] = json!(invalid);
        assert!(serde_json::from_value::<ControlMeasurement>(value).is_err());
    }
    let record: ControlMeasurement = serde_json::from_value(measurement()).unwrap();
    assert_eq!(record.ack_elapsed_us().unwrap().get(), 200);
    assert!(
        record
            .validate_barrier_deadline(
                razen_engine::domain::values::WireInt::new(1_000_000).unwrap()
            )
            .is_ok()
    );
    let mut late = measurement();
    late["late_admissions"] = json!(1);
    let late: ControlMeasurement = serde_json::from_value(late).unwrap();
    assert!(
        late.validate_barrier_deadline(
            razen_engine::domain::values::WireInt::new(1_000_000).unwrap()
        )
        .is_err()
    );
    let mut slow = measurement();
    slow["acknowledged_us"] = json!(1_000_101);
    let slow: ControlMeasurement = serde_json::from_value(slow).unwrap();
    assert!(
        slow.validate_barrier_deadline(
            razen_engine::domain::values::WireInt::new(1_000_000).unwrap()
        )
        .is_err()
    );
}

#[test]
fn bounded_record_metadata_rejects_oversized_utf8_and_collections() {
    let mut profile = identity();
    profile["secret_ref_names"] = json!(vec!["synthetic.fixture"; 4097]);
    assert!(serde_json::from_value::<IdentityProfile>(profile).is_err());
    let mut tool = descriptor();
    tool["permissions"] = json!(vec!["fixture.read"; 4097]);
    assert!(serde_json::from_value::<ToolDescriptor>(tool).is_err());
    let mut ev = event();
    ev["data_refs"] = json!(vec![INPUT; 4097]);
    assert!(serde_json::from_value::<Event>(ev).is_err());
    let mut cp = checkpoint();
    cp["invocation_refs"] = json!(vec![INVOCATION; 4097]);
    assert!(serde_json::from_value::<Checkpoint>(cp).is_err());
    let mut policy = scope();
    policy["allowed_destinations"] = json!(vec![scope()["allowed_destinations"][0].clone(); 4097]);
    assert!(serde_json::from_value::<ScopePolicy>(policy).is_err());
    let mut inv = invocation("proposed", false);
    inv["deduplication_key"] = json!("é".repeat(524_289));
    assert!(Invocation::parse_json(&serde_json::to_vec(&inv).unwrap(), None).is_err());
}

#[test]
fn destination_and_path_rules_require_every_field_and_reject_nested_duplicates() {
    let canonical = scope();
    let destination = &canonical["allowed_destinations"][0];
    for field in ["scheme", "host", "port", "path", "resolved_addresses"] {
        let mut missing = canonical.clone();
        missing["allowed_destinations"][0]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            serde_json::from_value::<ScopePolicy>(missing).is_err(),
            "missing destination {field}"
        );
        let mut nullable = canonical.clone();
        nullable["allowed_destinations"][0][field] = Value::Null;
        assert!(
            serde_json::from_value::<ScopePolicy>(nullable).is_err(),
            "null destination {field}"
        );
        let duplicate_rule = format!(
            "{{{}:{},{}",
            serde_json::to_string(field).unwrap(),
            destination[field],
            &serde_json::to_string(destination).unwrap()[1..],
        );
        let encoded = serde_json::to_string(&canonical).unwrap().replace(
            &serde_json::to_string(destination).unwrap(),
            &duplicate_rule,
        );
        assert!(
            serde_json::from_str::<ScopePolicy>(&encoded).is_err(),
            "duplicate destination {field}"
        );
    }
    for field in ["kind", "value"] {
        let mut missing = canonical.clone();
        missing["allowed_destinations"][0]["path"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        assert!(
            serde_json::from_value::<ScopePolicy>(missing).is_err(),
            "missing path {field}"
        );
    }
    for port in [
        json!(0),
        json!(65536),
        json!(-1),
        json!(443.0),
        json!("443"),
    ] {
        let mut invalid = canonical.clone();
        invalid["allowed_destinations"][0]["port"] = port;
        assert!(serde_json::from_value::<ScopePolicy>(invalid).is_err());
    }
    let mut kind = canonical.clone();
    kind["allowed_destinations"][0]["path"]["kind"] = json!("regex");
    assert!(serde_json::from_value::<ScopePolicy>(kind).is_err());
    let mut invalid_address = canonical;
    invalid_address["allowed_destinations"][0]["resolved_addresses"] = json!(["fixture.example"]);
    assert!(serde_json::from_value::<ScopePolicy>(invalid_address).is_err());
}
