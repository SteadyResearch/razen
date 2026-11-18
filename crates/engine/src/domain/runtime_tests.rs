use super::runtime::{Lease, LeaseState, RuntimeBinding, RuntimeCapability, RuntimeState};
use super::values::{AuditTime, Digest, EntityId, WireInt};
use crate::protocol::error::ErrorCode;
use serde_json::{Value, json};
use std::time::Duration;

fn binding() -> Value {
    json!({"binding_id":EntityId::new(),"run_id":EntityId::new(),"adapter_id":"fixture.simulated",
        "adapter_version":"0.1.0","runtime_digest":Digest::of(b"reviewed runtime fixture bytes"),
        "capabilities":["brokered_calls","events","results","usage","cancellation","closure"],
        "investigation_id":EntityId::new(),"session_id":EntityId::new(),"state":"created"})
}

#[test]
fn closed_runtime_cannot_resume_or_change_origin_after_valid_controlled_lifecycle() {
    let mut runtime: RuntimeBinding = serde_json::from_value(binding()).unwrap();
    let origin = (
        runtime.binding_id,
        runtime.run_id,
        runtime.investigation_id,
        runtime.session_id,
    );
    for next in [
        RuntimeState::Running,
        RuntimeState::WaitingApproval,
        RuntimeState::Running,
        RuntimeState::Paused,
        RuntimeState::Running,
        RuntimeState::Cancelling,
        RuntimeState::Cancelled,
        RuntimeState::Closed,
    ] {
        runtime.transition(next).unwrap();
    }
    assert_eq!(
        runtime.transition(RuntimeState::Running).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(runtime.state, RuntimeState::Closed);
    assert_eq!(
        (
            runtime.binding_id,
            runtime.run_id,
            runtime.investigation_id,
            runtime.session_id
        ),
        origin
    );
    assert_eq!(serde_json::to_value(&runtime).unwrap()["state"], "closed");
    let mut completed: RuntimeBinding = serde_json::from_value(binding()).unwrap();
    completed.transition(RuntimeState::Running).unwrap();
    completed.transition(RuntimeState::Completed).unwrap();
    assert!(completed.transition(RuntimeState::Running).is_err());
    completed.transition(RuntimeState::Closed).unwrap();
}

#[test]
fn runtime_records_reject_missing_null_unknown_fields_states_and_capability_escalation_shapes() {
    let valid = binding();
    for key in valid.as_object().unwrap().keys() {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(key);
        assert!(serde_json::from_value::<RuntimeBinding>(missing).is_err());
        let mut null = valid.clone();
        null[key] = Value::Null;
        assert!(serde_json::from_value::<RuntimeBinding>(null).is_err());
    }
    for (key, value) in [
        ("authority", json!(true)),
        ("state", json!("confirmed")),
        ("adapter_version", json!("1.0.0")),
        ("binding_id", json!("peer:untrusted")),
        ("capabilities", json!([])),
        (
            "capabilities",
            json!([
                "brokered_calls",
                "events",
                "results",
                "usage",
                "cancellation",
                "closure",
                "closure"
            ]),
        ),
        (
            "capabilities",
            json!([
                "brokered_calls",
                "events",
                "results",
                "usage",
                "cancellation",
                "closure",
                "ambient_network"
            ]),
        ),
    ] {
        let mut bad = valid.clone();
        bad[key] = value;
        assert!(serde_json::from_value::<RuntimeBinding>(bad).is_err());
    }
    let mut native = RuntimeCapability::REQUIRED.to_vec();
    native.extend([
        RuntimeCapability::NativePause,
        RuntimeCapability::NativeSteering,
    ]);
    RuntimeCapability::validate_set(&native).unwrap();
    native.push(RuntimeCapability::NativePause);
    assert!(RuntimeCapability::validate_set(&native).is_err());
}

#[test]
fn restored_lease_never_renews_authority_changes_owner_or_extends_expiry() {
    let now: AuditTime = serde_json::from_str("\"2026-11-16T12:00:00Z\"").unwrap();
    let expires = now.checked_add(Duration::from_secs(1)).unwrap();
    let owner = EntityId::new();
    let invocation = EntityId::new();
    let mut lease: Lease = serde_json::from_value(json!({"lease_id":EntityId::new(),
        "invocation_id":invocation,"owner_binding_id":owner,"control_revision":0,
        "expires_at":expires,"state":"active"}))
    .unwrap();
    lease
        .validate_current(owner, invocation, WireInt::ZERO, now)
        .unwrap();
    for (binding, call, revision, at) in [
        (EntityId::new(), invocation, WireInt::ZERO, now),
        (owner, EntityId::new(), WireInt::ZERO, now),
        (owner, invocation, WireInt::new(1).unwrap(), now),
        (owner, invocation, WireInt::ZERO, expires),
    ] {
        assert_eq!(
            lease
                .validate_current(binding, call, revision, at)
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );
    }
    lease.invalidate_after_restart();
    assert_eq!(lease.state, LeaseState::Revoked);
    assert_eq!(lease.expires_at, expires);
    assert_eq!(
        (
            lease.owner_binding_id,
            lease.invocation_id,
            lease.control_revision
        ),
        (owner, invocation, WireInt::ZERO)
    );
    assert!(
        lease
            .validate_current(owner, invocation, WireInt::ZERO, now)
            .is_err()
    );
    let historical: Lease = serde_json::from_slice(&serde_json::to_vec(&lease).unwrap()).unwrap();
    assert!(
        historical
            .validate_current(owner, invocation, WireInt::ZERO, now)
            .is_err()
    );
}

#[test]
fn lease_shape_and_terminal_states_do_not_silently_become_an_active_default() {
    let mut value = json!({"lease_id":EntityId::new(),"invocation_id":EntityId::new(),
        "owner_binding_id":EntityId::new(),"control_revision":0,
        "expires_at":"2026-11-16T12:00:00Z","state":"closed"});
    let mut lease: Lease = serde_json::from_value(value.clone()).unwrap();
    lease.invalidate_after_restart();
    assert_eq!(lease.state, LeaseState::Closed);
    for (key, replacement) in [
        ("state", json!("renewed")),
        ("control_revision", json!(0.5)),
        ("expires_at", Value::Null),
        ("grant_id", json!(EntityId::new())),
    ] {
        let original = value.clone();
        value[key] = replacement;
        assert!(serde_json::from_value::<Lease>(value).is_err());
        value = original;
    }
}
