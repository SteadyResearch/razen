//! Policy/state tests against the canonical SQLite ledger, not provider-I/O proofs.
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use razen_engine::adapters::ledger::{Ledger, RegisteredTool};
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::admission::{
    BindingSpec, HostAdmission, PreparedCall, TrustedBinding,
};
use razen_engine::application::control::{
    ControlAction, ControlClient, ControlCommand, ControlServer, ControlService,
};
use razen_engine::application::profile::LoadedProfile;
use razen_engine::domain::authority::{
    ApprovalGrant, Budget, Destination, DestinationCheck, FixtureProject, IdentityProfile,
    ScopePolicy,
};
use razen_engine::domain::execution::ControlState;
use razen_engine::domain::invocation::{Invocation, InvocationHistory};
use razen_engine::domain::knowledge::InvestigationSession;
use razen_engine::domain::values::{CatalogId, Digest, EntityId, InvocationState, Usage, WireInt};
use razen_engine::protocol::error::{ErrorCode, ProofError};
use serde_json::json;

fn wire(value: u64) -> WireInt {
    WireInt::new(value).unwrap()
}
fn catalog(value: &str) -> CatalogId {
    CatalogId::parse(value).unwrap()
}
fn usage(units: u64) -> Usage {
    serde_json::from_value(json!({"units": units, "bytes": 0, "cpu_us": 0, "elapsed_us": 0}))
        .unwrap()
}
fn budget(id: EntityId, limit: u64) -> Budget {
    serde_json::from_value(json!({
        "budget_id": id, "limit": limit, "consumed": 0, "reserved": 0, "revision": 0
    }))
    .unwrap()
}

struct TestRun {
    workspace: Arc<OwnedDirectory>,
    profile: LoadedProfile,
}

impl TestRun {
    fn new() -> Self {
        let run_id = EntityId::new();
        // Short owned paths fit the actual Unix control socket on macOS.
        let workspace = Arc::new(
            OwnedDirectory::create(
                Path::new("/private/tmp"),
                Path::new(&format!("rz-admit-{run_id}")),
                run_id,
            )
            .unwrap(),
        );
        let profile = LoadedProfile::load(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        Self { workspace, profile }
    }

    fn create(&self) -> Arc<Ledger> {
        Arc::new(Ledger::create(&self.workspace, &self.profile).unwrap())
    }

    fn reopen(&self) -> Arc<Ledger> {
        Arc::new(Ledger::open(&self.workspace, &self.profile).unwrap())
    }

    fn admission(
        &self,
        ledger: &Arc<Ledger>,
        enclosing_investigation_id: EntityId,
    ) -> HostAdmission {
        let service = Arc::new(
            ControlService::new(
                Arc::clone(ledger),
                &self.profile,
                enclosing_investigation_id,
            )
            .unwrap(),
        );
        HostAdmission::new(Arc::clone(ledger), service)
    }
}

impl Drop for TestRun {
    fn drop(&mut self) {
        let result = std::fs::remove_dir_all(self.workspace.path());
        if !std::thread::panicking() {
            result.expect("remove only this test's unique owned directory");
        }
    }
}

struct Fixture {
    project: FixtureProject,
    scope: ScopePolicy,
    identity: IdentityProfile,
    tool: RegisteredTool,
    session: InvestigationSession,
    control: ControlState,
    budget_id: EntityId,
}

impl Fixture {
    fn new() -> Self {
        let project: FixtureProject = serde_json::from_value(json!({
            "project_id": EntityId::new(), "user_id": EntityId::new(),
            "scope_policy_id": EntityId::new(), "revision": 0
        }))
        .unwrap();
        let scope: ScopePolicy = serde_json::from_value(json!({
            "scope_policy_id": project.scope_policy_id, "project_id": project.project_id,
            "revision": 0,
            "allowed_destinations": [{"scheme": "https", "host": "fixture.invalid", "port": 443,
                "path": {"kind": "prefix", "value": "/owned/"}, "resolved_addresses": ["192.0.2.7"]}],
            "exclusions": [{"scheme": "https", "host": "fixture.invalid", "port": 443,
                "path": {"kind": "prefix", "value": "/owned/private/"}, "resolved_addresses": ["192.0.2.7"]}]
        })).unwrap();
        let identity: IdentityProfile = serde_json::from_value(json!({
            "identity_id": EntityId::new(), "project_id": project.project_id, "secret_ref_names": []
        }))
        .unwrap();
        // Reviewed descriptive catalog data only: no network provider is instantiated here.
        let tool = RegisteredTool {
            descriptor: serde_json::from_value(json!({
                "tool_id": "http.send", "version": "0.1.0", "input_contract": "http.send.input",
                "output_contract": "http.send.output", "effect": "active_network",
                "permissions": ["fixture.http"], "limits": {
                    "units": 10, "bytes": 65536, "cpu_us": 100000, "elapsed_us": 1000000
                }, "retry_class": "non_retryable"
            }))
            .unwrap(),
            provider_digest: Digest::of(b"reviewed policy-test descriptor, not a running provider"),
        };
        let session: InvestigationSession = serde_json::from_value(json!({
            "investigation_id": EntityId::new(), "session_id": EntityId::new(),
            "user_id": project.user_id, "goal": "Inspect owned synthetic policy inputs",
            "control_revision": 0, "branch_refs": [], "evidence_refs": []
        }))
        .unwrap();
        let control = serde_json::from_value(json!({
            "investigation_id": session.investigation_id, "revision": 0,
            "mode": "running", "admission_open": true, "instruction_ref": EntityId::new()
        }))
        .unwrap();
        Self {
            project,
            scope,
            identity,
            tool,
            session,
            control,
            budget_id: EntityId::new(),
        }
    }

    fn install(&self, ledger: &Ledger) {
        ledger
            .transaction(|tx| {
                tx.insert_project(&self.project)?;
                tx.insert_scope(&self.scope)?;
                tx.insert_identity(&self.identity)?;
                tx.insert_tool(&self.tool)
            })
            .unwrap();
        ledger
            .insert_control(&self.control, self.project.project_id, self.scope.revision)
            .unwrap();
        ledger
            .insert_session(&self.session, self.project.project_id)
            .unwrap();
        ledger.insert_budget(&budget(self.budget_id, 20)).unwrap();
    }

    fn spec(&self) -> BindingSpec {
        BindingSpec {
            user_id: self.project.user_id,
            project_id: self.project.project_id,
            investigation_id: self.session.investigation_id,
            session_id: self.session.session_id,
            identity_id: self.identity.identity_id,
            budget_id: self.budget_id,
            provider_digest: self.tool.provider_digest,
            allowed_tools: vec![self.tool.descriptor.tool_id.clone()],
            permissions: self.tool.descriptor.permissions.clone(),
        }
    }

    fn call(&self) -> PreparedCall {
        PreparedCall {
            invocation_id: EntityId::new(),
            call_id: EntityId::new(),
            tool_id: self.tool.descriptor.tool_id.clone(),
            tool_version: self.tool.descriptor.version,
            // The frozen API permits trusted metadata fixtures; registry tests cover actual artifacts.
            input_ref: EntityId::new(),
            input_sha256: Digest::of(b"canonical policy-test input"),
            input_revision: wire(0),
            source_control_revision: wire(0),
            requested: usage(4),
        }
    }

    fn grant(&self, call: &PreparedCall) -> ApprovalGrant {
        serde_json::from_value(json!({
            "grant_id": EntityId::new(), "project_id": self.project.project_id,
            "tool_id": call.tool_id, "tool_version": call.tool_version,
            "provider_digest": self.tool.provider_digest, "scope_revision": self.scope.revision,
            "identity_id": self.identity.identity_id, "bounded_input_sha256": call.input_sha256,
            "limits": self.tool.descriptor.limits, "expires_at": "2099-01-01T00:00:00Z", "revoked": false
        })).unwrap()
    }

    fn approve(&self, ledger: &Ledger, call: &PreparedCall) -> ApprovalGrant {
        let grant = self.grant(call);
        ledger.insert_grant(&grant).unwrap();
        grant
    }

    fn command(&self, revision: u64, action: ControlAction) -> ControlCommand {
        ControlCommand {
            request_id: EntityId::new(),
            investigation_id: self.session.investigation_id,
            expected_revision: wire(revision),
            action,
        }
    }
}

fn assert_balance(ledger: &Ledger, id: EntityId, reserved: u64, consumed: u64) {
    let stored = ledger.read_budget(id).unwrap();
    assert_eq!(stored.reserved, wire(reserved));
    assert_eq!(stored.consumed, wire(consumed));
}

fn assert_persisted(ledger: &Ledger, expected: &Invocation, held: u64) {
    let stored = ledger.read_invocation(expected.invocation_id).unwrap();
    assert_eq!(&stored.invocation, expected);
    assert_eq!(stored.reserved_units, wire(held));
    assert_eq!(stored.history.last(), expected);
    let history = InvocationHistory::restore_json(&stored.history.export_json().unwrap()).unwrap();
    assert_eq!(history.last(), expected);
    let events: Vec<_> = ledger
        .outbox(256)
        .unwrap()
        .into_iter()
        .filter(|event| event.aggregate_id == expected.invocation_id)
        .collect();
    assert_eq!(events.len() as u64, stored.history.event_sequence().get());
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event.aggregate_sequence, wire(index as u64 + 1));
        assert_eq!(event.control_revision, Some(expected.control_revision));
        assert_eq!(event.project_id, expected.project_id);
    }
    let checkpoint = ledger
        .latest_checkpoint()
        .unwrap()
        .expect("state change has a durable checkpoint");
    assert!(checkpoint.invocation_refs.contains(&expected.invocation_id));
    assert!(checkpoint.budget_refs.contains(&expected.budget_id));
}

fn assert_denial(
    ledger: &Ledger,
    call: &PreparedCall,
    error: ProofError,
    code: ErrorCode,
    state: InvocationState,
) -> Invocation {
    assert_eq!(error.code, code);
    assert_eq!(error.invocation_id, Some(call.invocation_id));
    let invocation = ledger
        .read_invocation(call.invocation_id)
        .unwrap()
        .invocation;
    assert_eq!(invocation.state, state);
    assert!(
        invocation.grant_id.is_none(),
        "denial must not invent assigned authority"
    );
    assert_eq!(invocation.error.as_ref().unwrap().code, code);
    assert_persisted(ledger, &invocation, 0);
    invocation
}

#[test]
fn trusted_binding_and_successful_admission_settle_actual_usage_and_survive_restart() {
    let run = TestRun::new();
    let fixture = Fixture::new();
    let completed;
    {
        let ledger = run.create();
        fixture.install(&ledger);
        let admission = run.admission(&ledger, fixture.control.investigation_id);
        let binding = admission.bind(fixture.spec()).unwrap();
        assert_eq!(binding.user_id(), fixture.project.user_id);
        assert_eq!(binding.project_id(), fixture.project.project_id);
        assert_eq!(binding.investigation_id(), fixture.session.investigation_id);
        assert_eq!(binding.session_id(), fixture.session.session_id);
        assert_eq!(binding.identity_id(), fixture.identity.identity_id);
        assert_eq!(binding.budget_id(), fixture.budget_id);
        assert_eq!(binding.provider_digest(), fixture.tool.provider_digest);
        assert_eq!(binding.scope_revision(), wire(0));
        assert_eq!(binding.control_revision(), wire(0));
        let call = fixture.call();
        let grant = fixture.approve(&ledger, &call);
        let reserved = admission.reserve(&binding, &call).unwrap();
        assert_eq!(reserved.state, InvocationState::Reserved);
        assert_eq!(reserved.invocation_id, call.invocation_id);
        assert_eq!(reserved.run_id, ledger.run_id());
        assert_eq!(reserved.actor_ref, binding.actor_ref());
        assert_eq!(reserved.grant_id, Some(grant.grant_id));
        assert_persisted(&ledger, &reserved, 4);
        assert_balance(&ledger, fixture.budget_id, 4, 0);
        let permit = admission
            .begin_effect(&binding, reserved.invocation_id)
            .unwrap();
        assert_eq!(permit.invocation_id(), reserved.invocation_id);
        admission.recheck_effect(&binding, &permit).unwrap();
        completed = admission
            .complete(&binding, permit, usage(2), None)
            .unwrap();
        assert_eq!(completed.state, InvocationState::Completed);
        assert_eq!(completed.usage, usage(2));
        assert_persisted(&ledger, &completed, 0);
        assert_balance(&ledger, fixture.budget_id, 0, 2);
        assert_eq!(
            admission
                .invocation(completed.invocation_id)
                .unwrap()
                .invocation,
            completed
        );
    }
    let ledger = run.reopen();
    assert_persisted(&ledger, &completed, 0);
    assert_balance(&ledger, fixture.budget_id, 0, 2);
}

#[test]
fn absent_approval_is_a_durable_waiting_record_not_an_implicit_grant() {
    let run = TestRun::new();
    let fixture = Fixture::new();
    let denied;
    {
        let ledger = run.create();
        fixture.install(&ledger);
        let admission = run.admission(&ledger, fixture.control.investigation_id);
        let binding = admission.bind(fixture.spec()).unwrap();
        let call = fixture.call();
        denied = assert_denial(
            &ledger,
            &call,
            admission.reserve(&binding, &call).unwrap_err(),
            ErrorCode::ApprovalRequired,
            InvocationState::WaitingApproval,
        );
        assert!(
            admission
                .begin_effect(&binding, call.invocation_id)
                .is_err()
        );
        assert!(ledger.grants().unwrap().is_empty());
        assert_balance(&ledger, fixture.budget_id, 0, 0);
    }
    let ledger = run.reopen();
    assert_persisted(&ledger, &denied, 0);
    assert_balance(&ledger, fixture.budget_id, 0, 0);
}

#[test]
fn explicit_host_approval_can_reserve_a_waiting_call_without_replacing_its_identity() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let binding = admission.bind(fixture.spec()).unwrap();
    let call = fixture.call();
    assert_denial(
        &ledger,
        &call,
        admission.reserve(&binding, &call).unwrap_err(),
        ErrorCode::ApprovalRequired,
        InvocationState::WaitingApproval,
    );
    fixture.approve(&ledger, &call);
    let reserved = admission.reserve(&binding, &call).unwrap();
    assert_eq!(reserved.invocation_id, call.invocation_id);
    assert_eq!(reserved.state, InvocationState::Reserved);
    assert_persisted(&ledger, &reserved, 4);
    assert_balance(&ledger, fixture.budget_id, 4, 0);
}

#[test]
fn revoked_expired_or_wrong_digest_grants_never_authorize_reservation() {
    for case in ["revoked", "expired", "digest"] {
        let run = TestRun::new();
        let ledger = run.create();
        let fixture = Fixture::new();
        fixture.install(&ledger);
        let admission = run.admission(&ledger, fixture.control.investigation_id);
        let binding = admission.bind(fixture.spec()).unwrap();
        let call = fixture.call();
        let mut grant = fixture.grant(&call);
        if case == "expired" {
            grant.expires_at = serde_json::from_value(json!("2000-01-01T00:00:00Z")).unwrap();
        }
        if case == "digest" {
            grant.bounded_input_sha256 = Digest::of(b"different input");
        }
        ledger.insert_grant(&grant).unwrap();
        if case == "revoked" {
            ledger.revoke_grant(grant.grant_id).unwrap();
        }
        assert_denial(
            &ledger,
            &call,
            admission.reserve(&binding, &call).unwrap_err(),
            ErrorCode::ApprovalRequired,
            InvocationState::WaitingApproval,
        );
        assert_balance(&ledger, fixture.budget_id, 0, 0);
    }
}

#[test]
fn revocation_between_reservation_and_final_admission_cancels_and_releases_durably() {
    let run = TestRun::new();
    let fixture = Fixture::new();
    let cancelled;
    {
        let ledger = run.create();
        fixture.install(&ledger);
        let admission = run.admission(&ledger, fixture.control.investigation_id);
        let binding = admission.bind(fixture.spec()).unwrap();
        let call = fixture.call();
        let grant = fixture.approve(&ledger, &call);
        admission.reserve(&binding, &call).unwrap();
        ledger.revoke_grant(grant.grant_id).unwrap();
        let error = admission
            .begin_effect(&binding, call.invocation_id)
            .err()
            .expect("revoked grant cannot send");
        assert_eq!(error.code, ErrorCode::PermissionDenied);
        assert_eq!(error.invocation_id, Some(call.invocation_id));
        cancelled = ledger
            .read_invocation(call.invocation_id)
            .unwrap()
            .invocation;
        assert_eq!(cancelled.state, InvocationState::Cancelled);
        assert_eq!(cancelled.grant_id, Some(grant.grant_id));
        assert_persisted(&ledger, &cancelled, 0);
        assert_balance(&ledger, fixture.budget_id, 0, 0);
        assert!(
            admission
                .begin_effect(&binding, call.invocation_id)
                .is_err()
        );
    }
    let ledger = run.reopen();
    assert_persisted(&ledger, &cancelled, 0);
    assert_balance(&ledger, fixture.budget_id, 0, 0);
}

#[test]
fn scope_epoch_change_cancels_reserved_work_and_cannot_be_upgraded_by_peer_revision() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let binding = admission.bind(fixture.spec()).unwrap();
    let call = fixture.call();
    fixture.approve(&ledger, &call);
    admission.reserve(&binding, &call).unwrap();
    let mut scope = fixture.scope.clone();
    scope.revision = wire(1);
    ledger.replace_scope(&scope, wire(0)).unwrap();
    let error = admission
        .begin_effect(&binding, call.invocation_id)
        .err()
        .expect("old scope cannot send");
    assert_eq!(error.code, ErrorCode::StaleSnapshot);
    let cancelled = ledger
        .read_invocation(call.invocation_id)
        .unwrap()
        .invocation;
    assert_eq!(cancelled.state, InvocationState::Cancelled);
    assert_eq!(cancelled.scope_revision, wire(0));
    assert_persisted(&ledger, &cancelled, 0);
    assert_balance(&ledger, fixture.budget_id, 0, 0);
    let mut forged = fixture.call();
    forged.source_control_revision = wire(1);
    assert!(admission.reserve(&binding, &forged).is_err());
    assert_eq!(binding.scope_revision(), wire(0));
    assert_eq!(
        ledger.latest_checkpoint().unwrap().unwrap().scope_revision,
        wire(1)
    );
}

#[test]
fn authenticated_cancel_releases_reserved_work_and_old_binding_never_revives() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let service = Arc::new(
        ControlService::new(
            Arc::clone(&ledger),
            &run.profile,
            fixture.control.investigation_id,
        )
        .unwrap(),
    );
    let server = ControlServer::start(Arc::clone(&run.workspace), Arc::clone(&service)).unwrap();
    let client = ControlClient::new(&run.workspace).unwrap();
    let admission = HostAdmission::new(Arc::clone(&ledger), service);
    let binding = admission.bind(fixture.spec()).unwrap();
    let call = fixture.call();
    let grant = fixture.approve(&ledger, &call);
    admission.reserve(&binding, &call).unwrap();
    client
        .request(&fixture.command(0, ControlAction::Cancel))
        .unwrap();
    assert!(
        admission
            .begin_effect(&binding, call.invocation_id)
            .is_err()
    );
    let cancelled = ledger
        .read_invocation(call.invocation_id)
        .unwrap()
        .invocation;
    assert_eq!(cancelled.state, InvocationState::Cancelled);
    assert_eq!(cancelled.grant_id, Some(grant.grant_id));
    assert_persisted(&ledger, &cancelled, 0);
    assert_balance(&ledger, fixture.budget_id, 0, 0);
    let mut forged = fixture.call();
    forged.source_control_revision = wire(1);
    assert!(admission.reserve(&binding, &forged).is_err());
    assert!(admission.bind(fixture.spec()).is_err());
    server.shutdown().unwrap();
}

#[test]
fn pause_and_resume_require_new_host_binding_not_payload_control_revision() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let service = Arc::new(
        ControlService::new(
            Arc::clone(&ledger),
            &run.profile,
            fixture.control.investigation_id,
        )
        .unwrap(),
    );
    let server = ControlServer::start(Arc::clone(&run.workspace), Arc::clone(&service)).unwrap();
    let client = ControlClient::new(&run.workspace).unwrap();
    let admission = HostAdmission::new(Arc::clone(&ledger), service);
    let old = admission.bind(fixture.spec()).unwrap();
    client
        .request(&fixture.command(0, ControlAction::Pause))
        .unwrap();
    assert!(admission.bind(fixture.spec()).is_err());
    client
        .request(&fixture.command(1, ControlAction::Resume))
        .unwrap();
    let mut call = fixture.call();
    call.source_control_revision = wire(2);
    fixture.approve(&ledger, &call);
    assert_denial(
        &ledger,
        &call,
        admission.reserve(&old, &call).unwrap_err(),
        ErrorCode::StaleSnapshot,
        InvocationState::Rejected,
    );
    assert_eq!(old.control_revision(), wire(0));
    let fresh = admission.bind(fixture.spec()).unwrap();
    assert_eq!(fresh.control_revision(), wire(2));
    call.invocation_id = EntityId::new();
    call.call_id = EntityId::new();
    assert_eq!(
        admission.reserve(&fresh, &call).unwrap().state,
        InvocationState::Reserved
    );
    server.shutdown().unwrap();
}

#[test]
fn already_admitted_success_failure_and_unknown_keep_historical_origin_after_barrier() {
    for outcome in ["complete", "fail", "unknown"] {
        let run = TestRun::new();
        let fixture = Fixture::new();
        let finished;
        {
            let ledger = run.create();
            fixture.install(&ledger);
            let service = Arc::new(
                ControlService::new(
                    Arc::clone(&ledger),
                    &run.profile,
                    fixture.control.investigation_id,
                )
                .unwrap(),
            );
            let server =
                ControlServer::start(Arc::clone(&run.workspace), Arc::clone(&service)).unwrap();
            let client = ControlClient::new(&run.workspace).unwrap();
            let admission = HostAdmission::new(Arc::clone(&ledger), service);
            let binding = admission.bind(fixture.spec()).unwrap();
            let call = fixture.call();
            let grant = fixture.approve(&ledger, &call);
            admission.reserve(&binding, &call).unwrap();
            let permit = admission
                .begin_effect(&binding, call.invocation_id)
                .unwrap();
            client
                .request(&fixture.command(0, ControlAction::Cancel))
                .unwrap();
            ledger.revoke_grant(grant.grant_id).unwrap();
            let mut scope = fixture.scope.clone();
            scope.revision = wire(1);
            ledger.replace_scope(&scope, wire(0)).unwrap();
            assert!(admission.recheck_effect(&binding, &permit).is_err());
            finished = match outcome {
                "complete" => admission.complete(&binding, permit, usage(2), None),
                "fail" => admission.fail(
                    &binding,
                    permit,
                    usage(2),
                    ProofError::new(ErrorCode::ProviderUnavailable, "Known policy-test failure"),
                ),
                _ => admission.outcome_unknown(
                    &binding,
                    permit,
                    usage(2),
                    ProofError::new(
                        ErrorCode::OutcomeUnknown,
                        "Policy-test outcome needs reconciliation",
                    ),
                ),
            }
            .unwrap();
            assert_eq!(finished.control_revision, wire(0));
            assert_eq!(finished.scope_revision, wire(0));
            assert_eq!(finished.grant_id, Some(grant.grant_id));
            let expected = match outcome {
                "complete" => InvocationState::Completed,
                "fail" => InvocationState::Failed,
                _ => InvocationState::OutcomeUnknown,
            };
            assert_eq!(finished.state, expected);
            let held = if outcome == "unknown" { 4 } else { 0 };
            assert_persisted(&ledger, &finished, held);
            assert_balance(
                &ledger,
                fixture.budget_id,
                held,
                if outcome == "unknown" { 0 } else { 2 },
            );
            let checkpoint = ledger.latest_checkpoint().unwrap().unwrap();
            assert_eq!(checkpoint.control_revision, wire(1));
            assert_eq!(checkpoint.scope_revision, wire(1));
            assert!(
                admission
                    .begin_effect(&binding, call.invocation_id)
                    .is_err()
            );
            server.shutdown().unwrap();
        }
        let ledger = run.reopen();
        assert_persisted(&ledger, &finished, if outcome == "unknown" { 4 } else { 0 });
    }
}

#[test]
fn sending_and_unknown_duplicates_never_reopen_effect_or_charge_again() {
    let run = TestRun::new();
    let fixture = Fixture::new();
    let call = fixture.call();
    let unknown;
    {
        let ledger = run.create();
        fixture.install(&ledger);
        let admission = run.admission(&ledger, fixture.control.investigation_id);
        let binding = admission.bind(fixture.spec()).unwrap();
        fixture.approve(&ledger, &call);
        let reserved = admission.reserve(&binding, &call).unwrap();
        assert_eq!(admission.reserve(&binding, &call).unwrap(), reserved);
        assert_balance(&ledger, fixture.budget_id, 4, 0);
        let permit = admission
            .begin_effect(&binding, call.invocation_id)
            .unwrap();
        assert!(
            admission
                .begin_effect(&binding, call.invocation_id)
                .is_err()
        );
        assert_eq!(
            admission.reserve(&binding, &call).unwrap().state,
            InvocationState::Sending
        );
        unknown = admission
            .outcome_unknown(
                &binding,
                permit,
                usage(1),
                ProofError::new(
                    ErrorCode::OutcomeUnknown,
                    "No resend without reconciliation",
                ),
            )
            .unwrap();
        assert_eq!(admission.reserve(&binding, &call).unwrap(), unknown);
        assert!(
            admission
                .begin_effect(&binding, call.invocation_id)
                .is_err()
        );
        assert_persisted(&ledger, &unknown, 4);
        assert_balance(&ledger, fixture.budget_id, 4, 0);
    }
    let ledger = run.reopen();
    assert_persisted(&ledger, &unknown, 4);
    assert_balance(&ledger, fixture.budget_id, 4, 0);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let rebound = admission.bind(fixture.spec()).unwrap();
    assert!(
        admission
            .begin_effect(&rebound, call.invocation_id)
            .is_err()
    );
    assert_balance(&ledger, fixture.budget_id, 4, 0);
}

#[test]
fn identical_peer_call_ids_are_distinct_across_bindings_but_same_binding_is_deduplicated() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let first = admission.bind(fixture.spec()).unwrap();
    let second = admission.bind(fixture.spec()).unwrap();
    assert_ne!(first.binding_id(), second.binding_id());
    assert!(
        admission
            .existing_invocation(&first, EntityId::new())
            .unwrap()
            .is_none()
    );
    let call = fixture.call();
    fixture.approve(&ledger, &call);
    let one = admission.reserve(&first, &call).unwrap();
    let found = admission
        .existing_invocation(&first, call.call_id)
        .unwrap()
        .unwrap();
    assert_eq!(found.invocation, one);
    assert!(
        admission
            .existing_invocation(&second, call.call_id)
            .unwrap()
            .is_none()
    );
    let mut duplicate = fixture.call();
    duplicate.call_id = call.call_id;
    duplicate.input_ref = call.input_ref;
    let repeated = admission.reserve(&first, &duplicate).unwrap();
    assert_eq!(repeated.invocation_id, one.invocation_id);
    assert_eq!(repeated.deduplication_key, one.deduplication_key);
    assert_balance(&ledger, fixture.budget_id, 4, 0);
    let two = admission.reserve(&second, &duplicate).unwrap();
    assert_ne!(one.invocation_id, two.invocation_id);
    assert_ne!(one.deduplication_key, two.deduplication_key);
    assert_balance(&ledger, fixture.budget_id, 8, 0);
    assert_eq!(ledger.invocations().unwrap().len(), 2);
    assert!(admission.begin_effect(&second, one.invocation_id).is_err());
    let permit = admission.begin_effect(&first, one.invocation_id).unwrap();
    assert!(admission.recheck_effect(&second, &permit).is_err());
    admission.recheck_effect(&first, &permit).unwrap();
    admission.complete(&first, permit, usage(1), None).unwrap();
    assert_balance(&ledger, fixture.budget_id, 4, 1);
}

#[test]
fn bind_checks_canonical_owner_session_identity_provider_tools_and_permissions() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    admission.bind(fixture.spec()).unwrap();
    for case in [
        "user",
        "project",
        "session",
        "investigation",
        "identity",
        "provider",
        "tool",
        "permission",
    ] {
        let admission = run.admission(&ledger, fixture.control.investigation_id);
        admission.bind(fixture.spec()).unwrap();
        let mut spec = fixture.spec();
        match case {
            "user" => spec.user_id = EntityId::new(),
            "project" => spec.project_id = EntityId::new(),
            "session" => spec.session_id = EntityId::new(),
            "investigation" => spec.investigation_id = EntityId::new(),
            "identity" => spec.identity_id = EntityId::new(),
            "provider" => spec.provider_digest = Digest::of(b"unreviewed provider"),
            "tool" => spec.allowed_tools = vec![catalog("unknown.tool")],
            _ => spec.permissions.clear(),
        }
        assert!(
            admission.bind(spec).is_err(),
            "mismatched {case} cannot establish authority"
        );
    }
    let foreign_project: FixtureProject = serde_json::from_value(json!({
        "project_id": EntityId::new(), "user_id": EntityId::new(),
        "scope_policy_id": EntityId::new(), "revision": 0
    }))
    .unwrap();
    let foreign_scope: ScopePolicy = serde_json::from_value(json!({
        "scope_policy_id": foreign_project.scope_policy_id, "project_id": foreign_project.project_id,
        "revision": 0, "allowed_destinations": [], "exclusions": []
    })).unwrap();
    let foreign_identity: IdentityProfile = serde_json::from_value(json!({
        "identity_id": EntityId::new(), "project_id": foreign_project.project_id, "secret_ref_names": []
    })).unwrap();
    ledger
        .transaction(|tx| {
            tx.insert_project(&foreign_project)?;
            tx.insert_scope(&foreign_scope)?;
            tx.insert_identity(&foreign_identity)
        })
        .unwrap();
    let mut spec = fixture.spec();
    spec.identity_id = foreign_identity.identity_id;
    assert!(
        admission.bind(spec).is_err(),
        "a real but foreign canonical identity is not authority"
    );
    assert!(ledger.invocations().unwrap().is_empty());
    assert_balance(&ledger, fixture.budget_id, 0, 0);
}

#[test]
fn malformed_tool_and_resource_requests_are_persisted_rejections_without_assigned_grants() {
    for case in [
        "unknown",
        "permission",
        "units",
        "bytes",
        "cpu",
        "elapsed",
        "budget",
    ] {
        let run = TestRun::new();
        let ledger = run.create();
        let fixture = Fixture::new();
        fixture.install(&ledger);
        let admission = run.admission(&ledger, fixture.control.investigation_id);
        let mut spec = fixture.spec();
        if case == "permission" {
            spec.allowed_tools.clear();
            spec.permissions.clear();
        }
        let binding = admission.bind(spec).unwrap();
        let mut call = fixture.call();
        fixture.approve(&ledger, &call);
        let code = match case {
            "unknown" => {
                call.tool_id = catalog("unknown.tool");
                ErrorCode::UnknownTool
            }
            "permission" => ErrorCode::PermissionDenied,
            "units" => {
                call.requested.units = wire(11);
                ErrorCode::BudgetExhausted
            }
            "bytes" => {
                call.requested.bytes = wire(65537);
                ErrorCode::BudgetExhausted
            }
            "cpu" => {
                call.requested.cpu_us = wire(100001);
                ErrorCode::BudgetExhausted
            }
            "elapsed" => {
                call.requested.elapsed_us = wire(1000001);
                ErrorCode::BudgetExhausted
            }
            _ => {
                ledger
                    .transaction(|tx| tx.reserve_budget(fixture.budget_id, wire(18), wire(0)))
                    .unwrap();
                ErrorCode::BudgetExhausted
            }
        };
        assert_denial(
            &ledger,
            &call,
            admission.reserve(&binding, &call).unwrap_err(),
            code,
            InvocationState::Rejected,
        );
        assert_balance(
            &ledger,
            fixture.budget_id,
            if case == "budget" { 18 } else { 0 },
            0,
        );
    }
}

#[test]
fn unknown_tool_rejection_records_dispatcher_digest_without_registering_a_provider() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let binding = admission.bind(fixture.spec()).unwrap();
    let mut call = fixture.call();
    call.tool_id = catalog("absent.provider");
    let rejected = admission
        .record_rejection(
            &binding,
            &call,
            ProofError::new(
                ErrorCode::UnknownTool,
                "Tool is not in the reviewed catalog",
            ),
        )
        .unwrap();
    assert_eq!(rejected.state, InvocationState::Rejected);
    assert_eq!(rejected.provider_digest, fixture.tool.provider_digest);
    assert_eq!(
        rejected.error.as_ref().unwrap().invocation_id,
        Some(call.invocation_id)
    );
    assert!(rejected.grant_id.is_none());
    assert!(ledger.read_tool(&call.tool_id).is_err());
    assert_persisted(&ledger, &rejected, 0);
    assert_balance(&ledger, fixture.budget_id, 0, 0);
}

fn child_spec(fixture: &Fixture, child: EntityId) -> BindingSpec {
    let mut spec = fixture.spec();
    spec.budget_id = child;
    spec
}

fn child_scope(fixture: &Fixture) -> ScopePolicy {
    let mut restriction = fixture.scope.clone();
    restriction.scope_policy_id = EntityId::new();
    restriction.allowed_destinations[0].path.value = "/owned/public/".to_owned();
    restriction
}

fn check_destination(
    admission: &HostAdmission,
    binding: &TrustedBinding,
    permit: &razen_engine::application::admission::EffectPermit,
    url: &str,
    address: &str,
    authority: &str,
) -> Result<(), ProofError> {
    let destination = Destination::parse(url).unwrap();
    let address: IpAddr = address.parse().unwrap();
    admission.authorize_destination(
        binding,
        permit,
        &DestinationCheck {
            destination: &destination,
            resolved_addresses: &[address],
            chosen_address: address,
            connect_authority: Some(authority),
            server_name: Some("fixture.invalid"),
            request_authority: Some("fixture.invalid:443"),
        },
    )
}

#[test]
fn child_uses_real_parent_escrow_and_root_epoch_grant_with_narrowed_destination_overlay() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let parent = admission.bind(fixture.spec()).unwrap();
    let child_id = EntityId::new();
    ledger
        .transaction(|tx| tx.allocate_child(fixture.budget_id, child_id, wire(6), wire(0)))
        .unwrap();
    let child = admission
        .bind_child(
            &parent,
            child_spec(&fixture, child_id),
            child_scope(&fixture),
        )
        .unwrap();
    assert_eq!(child.scope_revision(), parent.scope_revision());
    let call = fixture.call();
    fixture.approve(&ledger, &call);
    admission.reserve(&child, &call).unwrap();
    assert_balance(&ledger, fixture.budget_id, 6, 0);
    assert_balance(&ledger, child_id, 4, 0);
    let permit = admission.begin_effect(&child, call.invocation_id).unwrap();
    check_destination(
        &admission,
        &child,
        &permit,
        "https://fixture.invalid/owned/public/item",
        "192.0.2.7",
        "fixture.invalid:443",
    )
    .unwrap();
    for (url, address, authority) in [
        (
            "https://fixture.invalid/owned/other",
            "192.0.2.7",
            "fixture.invalid:443",
        ),
        (
            "https://fixture.invalid/owned/private/item",
            "192.0.2.7",
            "fixture.invalid:443",
        ),
        (
            "https://fixture.invalid/owned/public/item",
            "192.0.2.8",
            "fixture.invalid:443",
        ),
        (
            "https://fixture.invalid/owned/public/item",
            "192.0.2.7",
            "other.invalid:443",
        ),
    ] {
        assert!(check_destination(&admission, &child, &permit, url, address, authority).is_err());
    }
    admission.complete(&child, permit, usage(2), None).unwrap();
    assert_balance(&ledger, child_id, 0, 2);
    assert_balance(&ledger, fixture.budget_id, 4, 2);
}

#[test]
fn child_binding_rejects_unbacked_balances_scope_expansion_and_identity_or_tool_growth() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let parent = admission.bind(fixture.spec()).unwrap();
    let child = EntityId::new();
    ledger
        .transaction(|tx| tx.allocate_child(fixture.budget_id, child, wire(6), wire(0)))
        .unwrap();
    let unrelated = EntityId::new();
    ledger.insert_budget(&budget(unrelated, 6)).unwrap();
    assert!(
        admission
            .bind_child(
                &parent,
                child_spec(&fixture, unrelated),
                child_scope(&fixture)
            )
            .is_err()
    );
    for case in [
        "identity",
        "user",
        "session",
        "investigation",
        "provider",
        "tool",
        "permission",
        "scope",
        "exclusion",
        "epoch",
    ] {
        let mut spec = child_spec(&fixture, child);
        let mut restriction = child_scope(&fixture);
        match case {
            "identity" => spec.identity_id = EntityId::new(),
            "user" => spec.user_id = EntityId::new(),
            "session" => spec.session_id = EntityId::new(),
            "investigation" => spec.investigation_id = EntityId::new(),
            "provider" => spec.provider_digest = Digest::of(b"child cannot substitute provider"),
            "tool" => spec.allowed_tools.push(catalog("extra.tool")),
            "permission" => spec.permissions.push(catalog("extra.permission")),
            "scope" => restriction.allowed_destinations[0].path.value = "/".to_owned(),
            "exclusion" => {
                restriction.allowed_destinations = fixture.scope.allowed_destinations.clone();
                restriction.exclusions.clear();
            }
            _ => restriction.revision = wire(1),
        }
        assert!(
            admission.bind_child(&parent, spec, restriction).is_err(),
            "child cannot expand {case}"
        );
    }
    assert_balance(&ledger, fixture.budget_id, 6, 0);
    assert_balance(&ledger, child, 0, 0);
    assert!(ledger.invocations().unwrap().is_empty());
}

#[test]
fn child_overlay_cannot_survive_root_epoch_change_or_reset_actual_escrow() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let parent = admission.bind(fixture.spec()).unwrap();
    let child_id = EntityId::new();
    ledger
        .transaction(|tx| tx.allocate_child(fixture.budget_id, child_id, wire(6), wire(0)))
        .unwrap();
    let child = admission
        .bind_child(
            &parent,
            child_spec(&fixture, child_id),
            child_scope(&fixture),
        )
        .unwrap();
    let call = fixture.call();
    fixture.approve(&ledger, &call);
    admission.reserve(&child, &call).unwrap();
    let mut scope = fixture.scope.clone();
    scope.revision = wire(1);
    ledger.replace_scope(&scope, wire(0)).unwrap();
    assert!(admission.begin_effect(&child, call.invocation_id).is_err());
    assert_eq!(
        ledger
            .read_invocation(call.invocation_id)
            .unwrap()
            .invocation
            .state,
        InvocationState::Cancelled
    );
    assert_balance(&ledger, child_id, 0, 0);
    assert_balance(&ledger, fixture.budget_id, 6, 0);
    assert!(
        admission
            .bind_child(
                &parent,
                child_spec(&fixture, child_id),
                child_scope(&fixture)
            )
            .is_err()
    );
}

#[test]
fn changed_same_binding_call_metadata_is_invalid_input_not_a_second_invocation() {
    for case in [
        "tool",
        "digest",
        "input_revision",
        "control_revision",
        "requested",
    ] {
        let run = TestRun::new();
        let ledger = run.create();
        let fixture = Fixture::new();
        fixture.install(&ledger);
        let admission = run.admission(&ledger, fixture.control.investigation_id);
        let binding = admission.bind(fixture.spec()).unwrap();
        let original = fixture.call();
        fixture.approve(&ledger, &original);
        let reserved = admission.reserve(&binding, &original).unwrap();
        let mut changed = fixture.call();
        changed.call_id = original.call_id;
        changed.input_ref = original.input_ref;
        match case {
            "tool" => changed.tool_id = catalog("other.tool"),
            "digest" => changed.input_sha256 = Digest::of(b"changed bounded input"),
            "input_revision" => changed.input_revision = wire(1),
            "control_revision" => changed.source_control_revision = wire(1),
            _ => changed.requested = usage(5),
        }
        let error = admission.reserve(&binding, &changed).unwrap_err();
        assert_eq!(
            error.code,
            ErrorCode::InvalidInput,
            "changed {case} cannot replay prior authority"
        );
        assert_eq!(ledger.invocations().unwrap().len(), 1);
        assert_eq!(
            admission
                .existing_invocation(&binding, original.call_id)
                .unwrap()
                .unwrap()
                .invocation,
            reserved
        );
        assert_persisted(&ledger, &reserved, 4);
        assert_balance(&ledger, fixture.budget_id, 4, 0);
    }
}

#[test]
fn completed_duplicate_returns_historical_result_without_rechecking_or_resetting_quota() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let binding = admission.bind(fixture.spec()).unwrap();
    let call = fixture.call();
    let grant = fixture.approve(&ledger, &call);
    admission.reserve(&binding, &call).unwrap();
    let permit = admission
        .begin_effect(&binding, call.invocation_id)
        .unwrap();
    let completed = admission
        .complete(&binding, permit, usage(2), None)
        .unwrap();
    ledger.revoke_grant(grant.grant_id).unwrap();
    assert_eq!(admission.reserve(&binding, &call).unwrap(), completed);
    assert!(
        admission
            .begin_effect(&binding, call.invocation_id)
            .is_err()
    );
    assert_persisted(&ledger, &completed, 0);
    assert_balance(&ledger, fixture.budget_id, 0, 2);
}

#[test]
fn current_grant_is_checked_again_for_each_prospective_effect_not_only_initial_sending() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let binding = admission.bind(fixture.spec()).unwrap();
    let call = fixture.call();
    let grant = fixture.approve(&ledger, &call);
    admission.reserve(&binding, &call).unwrap();
    let permit = admission
        .begin_effect(&binding, call.invocation_id)
        .unwrap();
    admission.recheck_effect(&binding, &permit).unwrap();
    check_destination(
        &admission,
        &binding,
        &permit,
        "https://fixture.invalid/owned/public/item",
        "192.0.2.7",
        "fixture.invalid:443",
    )
    .unwrap();
    ledger.revoke_grant(grant.grant_id).unwrap();
    assert_eq!(
        admission
            .recheck_effect(&binding, &permit)
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    assert!(
        check_destination(
            &admission,
            &binding,
            &permit,
            "https://fixture.invalid/owned/public/item",
            "192.0.2.7",
            "fixture.invalid:443"
        )
        .is_err()
    );
    assert_eq!(
        ledger
            .read_invocation(call.invocation_id)
            .unwrap()
            .invocation
            .state,
        InvocationState::Sending
    );
    assert_balance(&ledger, fixture.budget_id, 4, 0);
    let finished = admission
        .complete(&binding, permit, usage(1), None)
        .unwrap();
    assert_eq!(finished.grant_id, Some(grant.grant_id));
    assert_balance(&ledger, fixture.budget_id, 0, 1);
}

#[test]
fn a_shorter_lived_equivalent_grant_cannot_shadow_a_longer_current_approval() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let binding = admission.bind(fixture.spec()).unwrap();
    let call = fixture.call();
    let mut shorter = fixture.grant(&call);
    shorter.grant_id = EntityId::parse("00000000-0000-4000-8000-000000000001").unwrap();
    shorter.expires_at = serde_json::from_value(json!("2098-01-01T00:00:00Z")).unwrap();
    let mut longer = fixture.grant(&call);
    longer.grant_id = EntityId::parse("00000000-0000-4000-8000-000000000002").unwrap();
    ledger.insert_grant(&shorter).unwrap();
    ledger.insert_grant(&longer).unwrap();

    admission.reserve(&binding, &call).unwrap();
    ledger.revoke_grant(shorter.grant_id).unwrap();
    let permit = admission
        .begin_effect(&binding, call.invocation_id)
        .unwrap();
    let completed = admission
        .complete(&binding, permit, usage(1), None)
        .unwrap();
    assert_eq!(completed.grant_id, Some(longer.grant_id));
    assert_eq!(completed.state, InvocationState::Completed);
    assert_persisted(&ledger, &completed, 0);
    assert_balance(&ledger, fixture.budget_id, 0, 1);
}

#[test]
fn concurrent_final_admissions_have_exactly_one_durable_sending_winner() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let binding = admission.bind(fixture.spec()).unwrap();
    let call = fixture.call();
    fixture.approve(&ledger, &call);
    admission.reserve(&binding, &call).unwrap();
    let barrier = std::sync::Barrier::new(2);
    let (one, two) = std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            admission.begin_effect(&binding, call.invocation_id)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            admission.begin_effect(&binding, call.invocation_id)
        });
        (first.join().unwrap(), second.join().unwrap())
    });
    assert_eq!(usize::from(one.is_ok()) + usize::from(two.is_ok()), 1);
    let permit = one.or(two).expect("one sending permit");
    assert_eq!(
        ledger
            .read_invocation(call.invocation_id)
            .unwrap()
            .invocation
            .state,
        InvocationState::Sending
    );
    assert_balance(&ledger, fixture.budget_id, 4, 0);
    let completed = admission
        .complete(&binding, permit, usage(1), None)
        .unwrap();
    assert_persisted(&ledger, &completed, 0);
    assert_balance(&ledger, fixture.budget_id, 0, 1);
}

#[test]
fn invalid_finish_usage_or_error_contract_does_not_publish_result_or_release_hold() {
    for case in [
        "usage",
        "known_as_unknown",
        "unknown_as_known",
        "foreign_error",
    ] {
        let run = TestRun::new();
        let ledger = run.create();
        let fixture = Fixture::new();
        fixture.install(&ledger);
        let admission = run.admission(&ledger, fixture.control.investigation_id);
        let binding = admission.bind(fixture.spec()).unwrap();
        let call = fixture.call();
        fixture.approve(&ledger, &call);
        admission.reserve(&binding, &call).unwrap();
        let permit = admission
            .begin_effect(&binding, call.invocation_id)
            .unwrap();
        let before = ledger
            .read_invocation(call.invocation_id)
            .unwrap()
            .invocation;
        let result = match case {
            "usage" => admission.complete(&binding, permit, usage(5), None),
            "known_as_unknown" => admission.outcome_unknown(
                &binding,
                permit,
                usage(1),
                ProofError::new(
                    ErrorCode::ProviderUnavailable,
                    "Known failure is not an unknown outcome",
                ),
            ),
            "unknown_as_known" => admission.fail(
                &binding,
                permit,
                usage(1),
                ProofError::new(
                    ErrorCode::OutcomeUnknown,
                    "Unknown result must retain its reservation",
                ),
            ),
            _ => admission.fail(
                &binding,
                permit,
                usage(1),
                ProofError::new(
                    ErrorCode::ProviderUnavailable,
                    "Error belongs to a different invocation",
                )
                .with_invocation(EntityId::new()),
            ),
        };
        assert!(result.is_err(), "invalid {case} cannot publish a result");
        assert_persisted(&ledger, &before, 4);
        assert_balance(&ledger, fixture.budget_id, 4, 0);
    }
}

#[test]
fn known_measured_non_unit_overrun_is_failed_budget_exhausted_not_lost_usage() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let binding = admission.bind(fixture.spec()).unwrap();
    let call = fixture.call();
    fixture.approve(&ledger, &call);
    admission.reserve(&binding, &call).unwrap();
    let permit = admission
        .begin_effect(&binding, call.invocation_id)
        .unwrap();
    let mut actual = usage(2);
    actual.bytes = wire(1); // Requested bytes were zero; these are trusted measured counters.
    let failed = admission
        .fail(
            &binding,
            permit,
            actual,
            ProofError::new(
                ErrorCode::BudgetExhausted,
                "Measured output exceeded its admitted bound",
            ),
        )
        .unwrap();
    assert_eq!(failed.state, InvocationState::Failed);
    assert_eq!(failed.usage, actual);
    assert_eq!(
        failed.error.as_ref().unwrap().code,
        ErrorCode::BudgetExhausted
    );
    assert!(failed.output_ref.is_none());
    assert_persisted(&ledger, &failed, 0);
    assert_balance(&ledger, fixture.budget_id, 0, 2);
}

#[test]
fn stale_source_revision_rejection_replays_identically_but_cannot_change_revision() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let binding = admission.bind(fixture.spec()).unwrap();
    let mut call = fixture.call();
    call.source_control_revision = wire(1);
    let rejected = assert_denial(
        &ledger,
        &call,
        admission.reserve(&binding, &call).unwrap_err(),
        ErrorCode::StaleSnapshot,
        InvocationState::Rejected,
    );
    assert_eq!(admission.reserve(&binding, &call).unwrap(), rejected);
    call.source_control_revision = wire(2);
    assert_eq!(
        admission.reserve(&binding, &call).unwrap_err().code,
        ErrorCode::InvalidInput
    );
    assert_eq!(ledger.invocations().unwrap().len(), 1);
    assert_balance(&ledger, fixture.budget_id, 0, 0);
}

#[test]
fn child_budget_identifier_cannot_bypass_delegation_through_a_root_binding() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let parent = admission.bind(fixture.spec()).unwrap();
    let child_id = EntityId::new();
    ledger
        .transaction(|tx| tx.allocate_child(fixture.budget_id, child_id, wire(6), wire(0)))
        .unwrap();
    assert!(admission.bind(child_spec(&fixture, child_id)).is_err());
    admission
        .bind_child(
            &parent,
            child_spec(&fixture, child_id),
            child_scope(&fixture),
        )
        .unwrap();
    assert_balance(&ledger, fixture.budget_id, 6, 0);
    assert_balance(&ledger, child_id, 0, 0);
}

#[test]
fn current_session_lookup_preserves_owner_and_does_not_upgrade_binding_authority() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let service = Arc::new(
        ControlService::new(
            Arc::clone(&ledger),
            &run.profile,
            fixture.control.investigation_id,
        )
        .unwrap(),
    );
    let server = ControlServer::start(Arc::clone(&run.workspace), Arc::clone(&service)).unwrap();
    let client = ControlClient::new(&run.workspace).unwrap();
    let admission = HostAdmission::new(Arc::clone(&ledger), service);
    let binding = admission.bind(fixture.spec()).unwrap();
    let before = admission.session(&binding).unwrap();
    assert_eq!(before.project_id, fixture.project.project_id);
    assert_eq!(before.session, fixture.session);
    client
        .request(&fixture.command(0, ControlAction::Pause))
        .unwrap();
    let current = admission.session(&binding).unwrap();
    assert_eq!(current.session.control_revision, wire(1));
    assert_eq!(current.session.user_id, fixture.project.user_id);
    assert_eq!(binding.control_revision(), wire(0));
    assert!(admission.reserve(&binding, &fixture.call()).is_err());
    server.shutdown().unwrap();
}

#[test]
fn trusted_integrity_invalidation_closes_the_common_gate_without_new_ledger_mutations() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let admission = run.admission(&ledger, fixture.control.investigation_id);
    let binding = admission.bind(fixture.spec()).unwrap();
    let call = fixture.call();
    fixture.approve(&ledger, &call);
    admission.reserve(&binding, &call).unwrap();
    let before = ledger
        .read_invocation(call.invocation_id)
        .unwrap()
        .invocation;
    let events = ledger.outbox(256).unwrap().len();
    admission.check_integrity().unwrap();
    admission.invalidate_integrity();
    assert_eq!(
        admission.check_integrity().unwrap_err().code,
        ErrorCode::IntegrityError
    );
    assert!(admission.bind(fixture.spec()).is_err());
    assert!(
        admission
            .begin_effect(&binding, call.invocation_id)
            .is_err()
    );
    assert_eq!(
        admission
            .reserve(&binding, &fixture.call())
            .unwrap_err()
            .code,
        ErrorCode::IntegrityError
    );
    assert_eq!(
        admission.session(&binding).unwrap_err().code,
        ErrorCode::IntegrityError
    );
    assert_eq!(
        admission.invocation(call.invocation_id).unwrap_err().code,
        ErrorCode::IntegrityError
    );
    assert_eq!(
        admission
            .existing_invocation(&binding, call.call_id)
            .unwrap_err()
            .code,
        ErrorCode::IntegrityError
    );
    assert_eq!(
        ledger
            .read_invocation(call.invocation_id)
            .unwrap()
            .invocation,
        before
    );
    assert_eq!(ledger.outbox(256).unwrap().len(), events);
    assert_balance(&ledger, fixture.budget_id, 4, 0);
}
