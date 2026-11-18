use std::path::Path;

use razen_engine::adapters::ledger::{
    Ledger, LedgerTransaction, RegisteredSession, RegisteredTool, StoredInvocation,
};
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::profile::LoadedProfile;
use razen_engine::domain::authority::{
    ApprovalGrant, Budget, FixtureProject, IdentityProfile, ScopePolicy, ToolDescriptor,
};
use razen_engine::domain::execution::{Checkpoint, ControlMode, ControlState, Event};
use razen_engine::domain::invocation::{Invocation, InvocationHistory};
use razen_engine::domain::knowledge::InvestigationSession;
use razen_engine::domain::values::{
    AuditTime, CatalogId, Digest, EntityId, InvocationState, WireInt,
};
use razen_engine::protocol::error::{ErrorCode, ProofError, ProofResult};
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Value, json};

struct TestRun {
    workspace: OwnedDirectory,
    profile: LoadedProfile,
}

impl TestRun {
    fn new() -> Self {
        let run_id = EntityId::new();
        let workspace = OwnedDirectory::create(
            &std::env::temp_dir(),
            Path::new(&format!("razen-us1-catalog-{run_id}")),
            run_id,
        )
        .unwrap();
        let profile = LoadedProfile::load(
            &Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        Self { workspace, profile }
    }

    fn create(&self) -> Ledger {
        Ledger::create(&self.workspace, &self.profile).unwrap()
    }
    fn reopen(&self) -> Ledger {
        Ledger::open(&self.workspace, &self.profile).unwrap()
    }

    // Call only after dropping the canonical writer. Corruption never uses a concurrent writer.
    fn released_database(&self) -> Connection {
        let directory = self.workspace.path().canonicalize().unwrap();
        Connection::open_with_flags(
            directory.join("ledger.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .unwrap()
    }
}

impl Drop for TestRun {
    fn drop(&mut self) {
        let result = std::fs::remove_dir_all(self.workspace.path());
        if !std::thread::panicking() {
            result.expect("remove only this test's unique owned catalog directory");
        }
    }
}

fn wire(value: u64) -> WireInt {
    WireInt::new(value).unwrap()
}
fn catalog(value: &str) -> CatalogId {
    CatalogId::parse(value).unwrap()
}
fn abort() -> ProofError {
    ProofError::new(ErrorCode::Cancelled, "Deliberate catalog transaction abort")
}

struct Fixture {
    project: FixtureProject,
    scope: ScopePolicy,
    identity: IdentityProfile,
    tool: RegisteredTool,
    grant: ApprovalGrant,
    session: InvestigationSession,
    control: ControlState,
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
            "revision": 0, "allowed_destinations": [], "exclusions": []
        }))
        .unwrap();
        let identity: IdentityProfile = serde_json::from_value(json!({
            "identity_id": EntityId::new(), "project_id": project.project_id,
            "secret_ref_names": ["fixture.synthetic-credential"]
        }))
        .unwrap();
        let descriptor: ToolDescriptor = serde_json::from_value(json!({
            "tool_id": "http.send", "version": "0.1.0", "input_contract": "http.send.input",
            "output_contract": "http.send.output", "effect": "active_network",
            "permissions": ["fixture.http"],
            "limits": {"units": 10, "bytes": 65536, "cpu_us": 100000, "elapsed_us": 1000000},
            "retry_class": "non_retryable"
        }))
        .unwrap();
        let tool = RegisteredTool {
            descriptor,
            provider_digest: Digest::of(b"reviewed synthetic provider"),
        };
        let grant: ApprovalGrant = serde_json::from_value(json!({
            "grant_id": EntityId::new(), "project_id": project.project_id,
            "tool_id": tool.descriptor.tool_id, "tool_version": tool.descriptor.version,
            "provider_digest": tool.provider_digest, "scope_revision": 0,
            "identity_id": identity.identity_id, "bounded_input_sha256": Digest::of(b"bounded request"),
            "limits": tool.descriptor.limits, "expires_at": "2099-01-01T00:00:00Z", "revoked": false
        })).unwrap();
        let session: InvestigationSession = serde_json::from_value(json!({
            "investigation_id": EntityId::new(), "goal": "Inspect the owned synthetic fixture",
            "control_revision": 0, "session_id": EntityId::new(), "user_id": project.user_id,
            "branch_refs": [], "evidence_refs": []
        }))
        .unwrap();
        let control: ControlState = serde_json::from_value(json!({
            "investigation_id": session.investigation_id, "revision": 0,
            "mode": "running", "admission_open": true, "instruction_ref": EntityId::new()
        }))
        .unwrap();
        Self {
            project,
            scope,
            identity,
            tool,
            grant,
            session,
            control,
        }
    }

    fn insert_authority(&self, tx: &mut LedgerTransaction<'_>) -> ProofResult<()> {
        tx.insert_project(&self.project)?;
        tx.insert_scope(&self.scope)?;
        tx.insert_identity(&self.identity)?;
        tx.insert_tool(&self.tool)?;
        tx.insert_grant(&self.grant)
    }

    fn install(&self, ledger: &Ledger) {
        ledger.transaction(|tx| self.insert_authority(tx)).unwrap();
        ledger
            .insert_control(&self.control, self.project.project_id, self.scope.revision)
            .unwrap();
        ledger
            .insert_session(&self.session, self.project.project_id)
            .unwrap();
    }

    fn paused(&self) -> ControlState {
        let mut state = self.control.clone();
        state.revision = wire(1);
        state.mode = ControlMode::Paused;
        state.admission_open = false;
        state
    }

    fn registered_session(&self) -> Value {
        json!({"project_id": self.project.project_id, "session": self.session})
    }

    fn records(&self) -> Vec<Value> {
        vec![
            json!(self.project),
            json!(self.scope),
            json!(self.identity),
            json!(self.tool),
            json!(self.grant),
            self.registered_session(),
        ]
    }
}

fn assert_catalog(ledger: &Ledger, fixture: &Fixture) {
    assert_eq!(
        ledger.read_project(fixture.project.project_id).unwrap(),
        fixture.project
    );
    assert_eq!(
        ledger.read_scope(fixture.scope.scope_policy_id).unwrap(),
        fixture.scope
    );
    assert_eq!(
        ledger.read_identity(fixture.identity.identity_id).unwrap(),
        fixture.identity
    );
    assert_eq!(
        json!(ledger.read_tool(&fixture.tool.descriptor.tool_id).unwrap()),
        json!(fixture.tool)
    );
    assert_eq!(
        ledger.read_grant(fixture.grant.grant_id).unwrap(),
        fixture.grant
    );
    assert_eq!(
        json!(ledger.read_session(fixture.session.session_id).unwrap()),
        fixture.registered_session()
    );
}

fn event(project: EntityId) -> Event {
    serde_json::from_value(json!({
        "event_id": EntityId::new(), "schema_version": "0.1.0", "project_id": project,
        "aggregate_id": project, "aggregate_sequence": 1, "event_type": "catalog.installed",
        "timestamp": AuditTime::now(), "correlation_id": EntityId::new(),
        "causation_id": EntityId::new(), "control_revision": 0, "data_refs": [], "published": false
    }))
    .unwrap()
}

#[test]
fn canonical_catalog_records_round_trip_through_an_actual_ledger_restart() {
    let run = TestRun::new();
    let fixture = Fixture::new();
    {
        let ledger = run.create();
        fixture.install(&ledger);
        assert_catalog(&ledger, &fixture);
        assert!(
            Ledger::open(&run.workspace, &run.profile).is_err(),
            "catalog shares the sole writer"
        );
    }
    let reopened = run.reopen();
    assert_catalog(&reopened, &fixture);
    assert_eq!(reopened.grants().unwrap(), vec![fixture.grant.clone()]);
    reopened
        .transaction(|tx| {
            assert_eq!(
                tx.read_project(fixture.project.project_id)?,
                fixture.project
            );
            assert_eq!(tx.read_scope(fixture.scope.scope_policy_id)?, fixture.scope);
            assert_eq!(
                tx.read_identity(fixture.identity.identity_id)?,
                fixture.identity
            );
            assert_eq!(
                json!(tx.read_tool(&fixture.tool.descriptor.tool_id)?),
                json!(fixture.tool)
            );
            assert_eq!(tx.read_grant(fixture.grant.grant_id)?, fixture.grant);
            assert_eq!(tx.grants()?, vec![fixture.grant.clone()]);
            assert_eq!(
                json!(tx.read_session(fixture.session.session_id)?),
                fixture.registered_session()
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn revocation_survives_restart_and_live_fixture_reinsertion_cannot_unrevoke_it() {
    let run = TestRun::new();
    let fixture = Fixture::new();
    {
        let ledger = run.create();
        fixture.install(&ledger);
        ledger.revoke_grant(fixture.grant.grant_id).unwrap();
        ledger.revoke_grant(fixture.grant.grant_id).unwrap();
    }
    {
        let ledger = run.reopen();
        let mut revoked = fixture.grant.clone();
        revoked.revoked = true;
        assert_eq!(ledger.read_grant(revoked.grant_id).unwrap(), revoked);
        assert!(ledger.insert_grant(&fixture.grant).is_err());
        assert!(
            ledger.insert_grant(&revoked).is_err(),
            "even identical insertion is create-only"
        );
        assert_eq!(ledger.grants().unwrap(), vec![revoked]);
    }
    let ledger = run.reopen();
    assert!(ledger.read_grant(fixture.grant.grant_id).unwrap().revoked);
}

#[test]
fn duplicate_project_scope_identity_tool_and_session_records_are_never_upserts() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    assert!(
        ledger
            .transaction(|tx| tx.insert_project(&fixture.project))
            .is_err()
    );
    assert!(ledger.insert_scope(&fixture.scope).is_err());
    assert!(ledger.insert_identity(&fixture.identity).is_err());
    assert!(ledger.insert_tool(&fixture.tool).is_err());
    assert!(
        ledger
            .insert_session(&fixture.session, fixture.project.project_id)
            .is_err()
    );
    let mut project = fixture.project.clone();
    project.user_id = EntityId::new();
    assert!(
        ledger
            .transaction(|tx| tx.insert_project(&project))
            .is_err()
    );
    let mut identity = fixture.identity.clone();
    identity.secret_ref_names = vec![catalog("fixture.substitute-credential")];
    assert!(ledger.insert_identity(&identity).is_err());
    let mut session = fixture.session.clone();
    session.goal = "Replace canonical product state from a different runtime".to_owned();
    assert!(
        ledger
            .insert_session(&session, fixture.project.project_id)
            .is_err()
    );
    assert_catalog(&ledger, &fixture);
}

#[test]
fn provider_substitution_cannot_replace_a_reviewed_tool_or_create_a_matching_grant() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let substituted = RegisteredTool {
        descriptor: fixture.tool.descriptor.clone(),
        provider_digest: Digest::of(b"unreviewed substitute"),
    };
    assert!(ledger.insert_tool(&substituted).is_err());
    let mut grant = fixture.grant.clone();
    grant.grant_id = EntityId::new();
    grant.provider_digest = substituted.provider_digest;
    assert!(ledger.insert_grant(&grant).is_err());
    assert!(ledger.read_grant(grant.grant_id).is_err());
    assert_catalog(&ledger, &fixture);
}

#[test]
fn grant_requires_an_existing_project_its_own_identity_and_a_registered_tool() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let other = Fixture::new();
    ledger
        .transaction(|tx| {
            tx.insert_project(&other.project)?;
            tx.insert_scope(&other.scope)?;
            tx.insert_identity(&other.identity)
        })
        .unwrap();
    for dimension in [
        "project",
        "identity",
        "foreign_identity",
        "tool",
        "provider",
    ] {
        let mut grant = fixture.grant.clone();
        grant.grant_id = EntityId::new();
        match dimension {
            "project" => grant.project_id = EntityId::new(),
            "identity" => grant.identity_id = EntityId::new(),
            "foreign_identity" => grant.identity_id = other.identity.identity_id,
            "tool" => grant.tool_id = catalog("unregistered.tool"),
            "provider" => grant.provider_digest = Digest::of(b"foreign provider"),
            _ => unreachable!(),
        }
        assert!(
            ledger.insert_grant(&grant).is_err(),
            "accepted invalid {dimension}"
        );
        assert!(ledger.read_grant(grant.grant_id).is_err());
    }
    assert_eq!(ledger.grants().unwrap(), vec![fixture.grant]);
}

#[test]
fn child_scope_revision_is_not_incorrectly_compared_to_the_project_root_at_grant_insert() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let mut child = fixture.scope.clone();
    child.scope_policy_id = EntityId::new();
    child.revision = wire(7);
    ledger.insert_scope(&child).unwrap();
    let mut grant = fixture.grant.clone();
    grant.grant_id = EntityId::new();
    grant.scope_revision = child.revision;
    ledger.insert_grant(&grant).unwrap();
    drop(ledger);
    assert_eq!(run.reopen().read_grant(grant.grant_id).unwrap(), grant);
}

#[test]
fn scope_replacement_requires_same_owner_and_exactly_one_cas_revision_step() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    for dimension in ["no_step", "skip", "owner", "id"] {
        let mut scope = fixture.scope.clone();
        scope.revision = wire(1);
        match dimension {
            "no_step" => scope.revision = wire(0),
            "skip" => scope.revision = wire(2),
            "owner" => scope.project_id = EntityId::new(),
            "id" => scope.scope_policy_id = EntityId::new(),
            _ => unreachable!(),
        }
        assert!(
            ledger.replace_scope(&scope, wire(0)).is_err(),
            "accepted invalid {dimension}"
        );
        assert_eq!(
            ledger.read_scope(fixture.scope.scope_policy_id).unwrap(),
            fixture.scope
        );
    }
    let mut next = fixture.scope.clone();
    next.revision = wire(1);
    ledger.replace_scope(&next, wire(0)).unwrap();
    let mut stale = next.clone();
    stale.revision = wire(2);
    assert!(ledger.replace_scope(&stale, wire(0)).is_err());
    drop(ledger);
    let ledger = run.reopen();
    assert_eq!(ledger.read_scope(next.scope_policy_id).unwrap(), next);
    assert_eq!(
        ledger.read_grant(fixture.grant.grant_id).unwrap(),
        fixture.grant,
        "policy changes do not rewrite historical grant bindings"
    );
}

#[test]
fn missing_project_links_and_foreign_root_scope_links_abort_catalog_bootstrap() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    assert!(
        ledger
            .transaction(|tx| tx.insert_project(&fixture.project))
            .is_err(),
        "a dangling root must not commit"
    );
    assert!(ledger.read_project(fixture.project.project_id).is_err());
    assert!(ledger.insert_scope(&fixture.scope).is_err());
    assert!(ledger.insert_identity(&fixture.identity).is_err());
    let other = Fixture::new();
    let mut foreign = fixture.scope.clone();
    foreign.project_id = other.project.project_id;
    assert!(
        ledger
            .transaction(|tx| {
                tx.insert_project(&fixture.project)?;
                tx.insert_project(&other.project)?;
                tx.insert_scope(&other.scope)?;
                tx.insert_scope(&foreign)
            })
            .is_err()
    );
    assert!(ledger.read_project(fixture.project.project_id).is_err());
    assert!(ledger.read_project(other.project.project_id).is_err());
}

#[test]
fn session_owner_project_and_investigation_identity_cannot_be_substituted() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let other = Fixture::new();
    ledger
        .transaction(|tx| {
            tx.insert_project(&other.project)?;
            tx.insert_scope(&other.scope)
        })
        .unwrap();
    let mut foreign_user = fixture.session.clone();
    foreign_user.session_id = EntityId::new();
    foreign_user.investigation_id = EntityId::new();
    foreign_user.user_id = other.project.user_id;
    assert!(
        ledger
            .insert_session(&foreign_user, fixture.project.project_id)
            .is_err()
    );
    let mut second_session = fixture.session.clone();
    second_session.session_id = EntityId::new();
    assert!(
        ledger
            .insert_session(&second_session, fixture.project.project_id)
            .is_err(),
        "one investigation cannot acquire a second canonical session"
    );
    let mut changed_investigation = fixture.session.clone();
    changed_investigation.investigation_id = EntityId::new();
    assert!(
        ledger
            .insert_session(&changed_investigation, fixture.project.project_id)
            .is_err()
    );
    assert!(
        ledger
            .insert_session(&fixture.session, other.project.project_id)
            .is_err()
    );
    let mut absent_project = fixture.session.clone();
    absent_project.session_id = EntityId::new();
    absent_project.investigation_id = EntityId::new();
    assert!(
        ledger
            .insert_session(&absent_project, EntityId::new())
            .is_err()
    );
    assert_catalog(&ledger, &fixture);
}

#[test]
fn session_control_revision_matches_existing_control_and_advances_atomically_across_restart() {
    let run = TestRun::new();
    let fixture = Fixture::new();
    {
        let ledger = run.create();
        ledger
            .transaction(|tx| fixture.insert_authority(tx))
            .unwrap();
        ledger
            .insert_control(
                &fixture.control,
                fixture.project.project_id,
                fixture.scope.revision,
            )
            .unwrap();
        let mut stale_session = fixture.session.clone();
        stale_session.control_revision = wire(1);
        assert!(
            ledger
                .insert_session(&stale_session, fixture.project.project_id)
                .is_err()
        );
        ledger
            .insert_session(&fixture.session, fixture.project.project_id)
            .unwrap();
        ledger
            .transaction(|tx| {
                tx.apply_control(&fixture.paused(), wire(0))?;
                assert_eq!(
                    tx.read_session(fixture.session.session_id)?
                        .session
                        .control_revision,
                    wire(1)
                );
                Ok(())
            })
            .unwrap();
    }
    let ledger = run.reopen();
    let stored = ledger.read_session(fixture.session.session_id).unwrap();
    let mut expected = fixture.session.clone();
    expected.control_revision = wire(1);
    assert_eq!(stored.session, expected);
    assert_eq!(stored.project_id, fixture.project.project_id);
    assert_eq!(
        ledger
            .read_control(fixture.session.investigation_id)
            .unwrap(),
        fixture.paused()
    );
    assert_eq!(
        ledger
            .latest_checkpoint()
            .unwrap()
            .unwrap()
            .control_revision,
        wire(1)
    );
    assert!(
        ledger
            .insert_session(&fixture.session, fixture.project.project_id)
            .is_err()
    );
}

#[test]
fn minimal_legacy_control_without_a_catalog_session_still_commits() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    ledger
        .insert_control(
            &fixture.control,
            fixture.project.project_id,
            fixture.scope.revision,
        )
        .unwrap();
    ledger
        .transaction(|tx| tx.apply_control(&fixture.paused(), wire(0)))
        .unwrap();
    drop(ledger);
    assert_eq!(
        run.reopen()
            .read_control(fixture.control.investigation_id)
            .unwrap(),
        fixture.paused()
    );
}

#[test]
fn catalog_inserts_budget_outbox_and_checkpoint_rollback_and_commit_as_one_transaction() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    let budget: Budget = serde_json::from_value(json!({
        "budget_id": EntityId::new(), "limit": 10, "consumed": 0, "reserved": 0, "revision": 0
    }))
    .unwrap();
    ledger.insert_budget(&budget).unwrap();
    let event = event(fixture.project.project_id);
    let checkpoint: Checkpoint = serde_json::from_value(json!({
        "checkpoint_id": EntityId::new(), "run_id": run.workspace.run_id(), "schema_version": "0.1.0",
        "control_revision": 0, "scope_revision": 0, "budget_refs": [budget.budget_id],
        "invocation_refs": [], "lease_refs": [], "event_cursors": {}, "created_at": AuditTime::now()
    })).unwrap();
    let write = |tx: &mut LedgerTransaction<'_>| {
        fixture.insert_authority(tx)?;
        tx.insert_session(&fixture.session, fixture.project.project_id)?;
        tx.reserve_budget(budget.budget_id, wire(3), wire(0))?;
        tx.append_event(&event)?;
        tx.write_checkpoint(&checkpoint)
    };
    assert_eq!(
        ledger
            .transaction(|tx| {
                write(tx)?;
                Err::<(), _>(abort())
            })
            .unwrap_err()
            .code,
        ErrorCode::Cancelled
    );
    assert!(ledger.read_project(fixture.project.project_id).is_err());
    assert!(ledger.read_scope(fixture.scope.scope_policy_id).is_err());
    assert!(ledger.read_identity(fixture.identity.identity_id).is_err());
    assert!(ledger.read_tool(&fixture.tool.descriptor.tool_id).is_err());
    assert!(ledger.read_grant(fixture.grant.grant_id).is_err());
    assert!(ledger.read_session(fixture.session.session_id).is_err());
    assert!(ledger.grants().unwrap().is_empty());
    assert_eq!(ledger.read_budget(budget.budget_id).unwrap(), budget);
    assert!(ledger.outbox(256).unwrap().is_empty());
    assert!(ledger.latest_checkpoint().unwrap().is_none());
    ledger.transaction(write).unwrap();
    drop(ledger);
    let ledger = run.reopen();
    assert_catalog(&ledger, &fixture);
    assert_eq!(
        ledger.read_budget(budget.budget_id).unwrap().reserved,
        wire(3)
    );
    assert_eq!(ledger.outbox(256).unwrap(), vec![event]);
    assert_eq!(ledger.latest_checkpoint().unwrap().unwrap(), checkpoint);
}

#[test]
fn aborted_revocation_scope_and_control_leave_no_partial_session_or_outbox_changes() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let mut scope = fixture.scope.clone();
    scope.revision = wire(1);
    let error = ledger
        .transaction(|tx| {
            tx.revoke_grant(fixture.grant.grant_id)?;
            tx.replace_scope(&scope, wire(0))?;
            tx.apply_control(&fixture.paused(), wire(0))?;
            assert!(tx.read_grant(fixture.grant.grant_id)?.revoked);
            assert_eq!(
                tx.read_session(fixture.session.session_id)?
                    .session
                    .control_revision,
                wire(1)
            );
            Err::<(), _>(abort())
        })
        .unwrap_err();
    assert_eq!(error.code, ErrorCode::Cancelled);
    drop(ledger);
    let ledger = run.reopen();
    assert_catalog(&ledger, &fixture);
    assert_eq!(
        ledger
            .read_control(fixture.control.investigation_id)
            .unwrap(),
        fixture.control
    );
    assert!(ledger.outbox(256).unwrap().is_empty());
    assert!(ledger.latest_checkpoint().unwrap().is_none());
}

#[test]
fn rejected_catalog_operation_can_be_caught_without_replacing_preexisting_authority() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let event = event(fixture.project.project_id);
    ledger
        .transaction(|tx| {
            tx.revoke_grant(fixture.grant.grant_id)?;
            assert!(tx.insert_grant(&fixture.grant).is_err());
            assert!(tx.read_grant(fixture.grant.grant_id)?.revoked);
            let mut scope = fixture.scope.clone();
            scope.revision = wire(2);
            assert!(tx.replace_scope(&scope, wire(0)).is_err());
            assert_eq!(tx.read_scope(scope.scope_policy_id)?, fixture.scope);
            tx.append_event(&event)
        })
        .unwrap();
    drop(ledger);
    let ledger = run.reopen();
    assert!(ledger.read_grant(fixture.grant.grant_id).unwrap().revoked);
    assert_eq!(ledger.outbox(256).unwrap(), vec![event]);
}

// Locate the persisted JSON by its semantic value, not by imposing a particular table layout.
// The production catalog may use separate tables or a closed generic typed catalog table.
fn replace_persisted_record(run: &TestRun, expected: &Value, replacement: &[u8]) {
    let connection = run.released_database();
    let tables: Vec<String> = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT GLOB 'sqlite_*'")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    let mut found = Vec::new();
    for table in tables {
        let table_name = quote_identifier(&table);
        let columns: Vec<String> = connection
            .prepare(&format!("PRAGMA table_info({table_name})"))
            .unwrap()
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        for column in columns {
            let column_name = quote_identifier(&column);
            let mut statement = connection
                .prepare(&format!("SELECT rowid,{column_name} FROM {table_name}"))
                .unwrap();
            let mut rows = statement.query([]).unwrap();
            while let Some(row) = rows.next().unwrap() {
                let bytes = match row.get_ref(1).unwrap() {
                    rusqlite::types::ValueRef::Blob(bytes)
                    | rusqlite::types::ValueRef::Text(bytes) => bytes,
                    _ => continue,
                };
                if serde_json::from_slice::<Value>(bytes).ok().as_ref() == Some(expected) {
                    found.push((table.clone(), column.clone(), row.get::<_, i64>(0).unwrap()));
                }
            }
        }
    }
    assert_eq!(
        found.len(),
        1,
        "locate exactly one canonical persisted catalog record"
    );
    let (table, column, rowid) = &found[0];
    connection
        .execute_batch("PRAGMA ignore_check_constraints=ON")
        .unwrap();
    assert_eq!(
        connection
            .execute(
                &format!(
                    "UPDATE {} SET {}=?1 WHERE rowid=?2",
                    quote_identifier(table),
                    quote_identifier(column)
                ),
                params![replacement, rowid]
            )
            .unwrap(),
        1
    );
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn assert_corrupt_reopen_preserves_bytes(run: &TestRun) {
    let path = run.workspace.path().join("ledger.sqlite");
    let before = std::fs::read(&path).unwrap();
    let error = Ledger::open(&run.workspace, &run.profile)
        .err()
        .expect("corrupt catalog must fail closed");
    assert_eq!(error.code, ErrorCode::IntegrityError);
    assert_eq!(
        std::fs::read(path).unwrap(),
        before,
        "opening rejected metadata must not mutate it"
    );
}

#[test]
fn every_catalog_record_rejects_unknown_duplicate_truncated_and_oversize_persisted_json() {
    for record_index in 0..6 {
        for corruption in ["unknown", "duplicate", "truncated", "oversize"] {
            let run = TestRun::new();
            let fixture = Fixture::new();
            let ledger = run.create();
            fixture.install(&ledger);
            drop(ledger);
            let original = fixture.records().remove(record_index);
            let mut value = original.clone();
            let replacement = match corruption {
                "unknown" => {
                    value["unrecognized_host_authority"] = json!(true);
                    serde_json::to_vec(&value).unwrap()
                }
                "duplicate" => {
                    let (name, field) = original.as_object().unwrap().iter().next().unwrap();
                    let mut bytes = serde_json::to_vec(&original).unwrap();
                    bytes.pop();
                    bytes.extend_from_slice(
                        format!(",{}:{field}}}", serde_json::to_string(name).unwrap()).as_bytes(),
                    );
                    bytes
                }
                "truncated" => b"{\"project_id\":".to_vec(),
                "oversize" => {
                    // Even valid JSON followed by legal whitespace must hit the raw 1 MiB bound.
                    let mut bytes = serde_json::to_vec(&original).unwrap();
                    bytes.resize(1_048_577, b' ');
                    bytes
                }
                _ => unreachable!(),
            };
            replace_persisted_record(&run, &original, &replacement);
            assert_corrupt_reopen_preserves_bytes(&run);
        }
    }
}

#[test]
fn stored_provider_versions_and_exact_wire_numbers_are_revalidated_on_reopen() {
    for corruption in [
        "tool_version",
        "grant_version",
        "fraction",
        "overflow",
        "negative",
        "coerced",
        "time",
        "digest",
    ] {
        let run = TestRun::new();
        let fixture = Fixture::new();
        let ledger = run.create();
        fixture.install(&ledger);
        drop(ledger);
        let original = if corruption == "tool_version" {
            json!(fixture.tool)
        } else {
            json!(fixture.grant)
        };
        let mut changed = original.clone();
        match corruption {
            "tool_version" => changed["descriptor"]["version"] = json!("0.2.0"),
            "grant_version" => changed["tool_version"] = json!("0.2.0"),
            "fraction" => changed["scope_revision"] = json!(0.5),
            "overflow" => changed["scope_revision"] = json!(9_007_199_254_740_992_u64),
            "negative" => changed["scope_revision"] = json!(-1),
            "coerced" => changed["scope_revision"] = json!("0"),
            "time" => changed["expires_at"] = json!("2099-01-01T01:00:00+01:00"),
            "digest" => changed["provider_digest"] = json!("A".repeat(64)),
            _ => unreachable!(),
        }
        replace_persisted_record(&run, &original, &serde_json::to_vec(&changed).unwrap());
        assert_corrupt_reopen_preserves_bytes(&run);
    }
}

#[test]
fn validly_typed_foreign_owners_and_record_id_substitution_in_sqlite_fail_closed() {
    for corruption in [
        "project_root",
        "scope_project",
        "identity_project",
        "grant_identity",
        "grant_provider",
        "session_project",
        "session_user",
        "session_investigation",
        "session_revision",
        "project_id",
    ] {
        let run = TestRun::new();
        let fixture = Fixture::new();
        let ledger = run.create();
        fixture.install(&ledger);
        drop(ledger);
        let index = match corruption {
            "project_root" | "project_id" => 0,
            "scope_project" => 1,
            "identity_project" => 2,
            "grant_identity" | "grant_provider" => 4,
            _ => 5,
        };
        let original = fixture.records().remove(index);
        let mut changed = original.clone();
        match corruption {
            "project_root" => changed["scope_policy_id"] = json!(EntityId::new()),
            "scope_project" | "identity_project" | "session_project" => {
                changed["project_id"] = json!(EntityId::new())
            }
            "grant_identity" => changed["identity_id"] = json!(EntityId::new()),
            "grant_provider" => {
                changed["provider_digest"] = json!(Digest::of(b"substituted provider"))
            }
            "session_user" => changed["session"]["user_id"] = json!(EntityId::new()),
            "session_investigation" => {
                changed["session"]["investigation_id"] = json!(EntityId::new())
            }
            "session_revision" => changed["session"]["control_revision"] = json!(1),
            "project_id" => changed["project_id"] = json!(EntityId::new()),
            _ => unreachable!(),
        }
        replace_persisted_record(&run, &original, &serde_json::to_vec(&changed).unwrap());
        assert_corrupt_reopen_preserves_bytes(&run);
    }
}

#[test]
fn public_host_structs_still_pass_domain_collection_and_session_size_limits_before_storage() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let mut identity = fixture.identity.clone();
    identity.identity_id = EntityId::new();
    identity.secret_ref_names = vec![catalog("synthetic.reference"); 257];
    assert!(ledger.insert_identity(&identity).is_err());
    assert!(ledger.read_identity(identity.identity_id).is_err());
    let mut session = fixture.session.clone();
    session.session_id = EntityId::new();
    session.investigation_id = EntityId::new();
    session.goal = "x".repeat(4097);
    assert!(
        ledger
            .insert_session(&session, fixture.project.project_id)
            .is_err()
    );
    assert!(ledger.read_session(session.session_id).is_err());
    let mut tool = RegisteredTool {
        descriptor: fixture.tool.descriptor.clone(),
        provider_digest: fixture.tool.provider_digest,
    };
    tool.descriptor.tool_id = catalog("oversize.tool");
    tool.descriptor.permissions = vec![catalog("fixture.permission"); 257];
    assert!(ledger.insert_tool(&tool).is_err());
    assert!(ledger.read_tool(&tool.descriptor.tool_id).is_err());
    assert_catalog(&ledger, &fixture);
}

#[test]
fn registered_wrapper_wire_records_reject_unknown_fields_without_changing_domain_models() {
    let fixture = Fixture::new();
    let mut tool = json!(fixture.tool);
    tool["secret_value"] = json!("never accepted as authority metadata");
    assert!(serde_json::from_value::<RegisteredTool>(tool).is_err());
    let mut session = fixture.registered_session();
    session["runtime_conversation"] = json!([]);
    assert!(serde_json::from_value::<RegisteredSession>(session).is_err());
}

fn invocation_budget() -> Budget {
    serde_json::from_value(json!({
        "budget_id": EntityId::new(), "limit": 10, "consumed": 0, "reserved": 0, "revision": 0
    }))
    .unwrap()
}

fn reserved_invocation(
    run: &TestRun,
    fixture: &Fixture,
    budget: &Budget,
    grant: &ApprovalGrant,
    control_revision: WireInt,
) -> StoredInvocation {
    let proposed: Invocation = serde_json::from_value(json!({
        "invocation_id": EntityId::new(), "run_id": run.workspace.run_id(),
        "project_id": fixture.project.project_id, "investigation_id": fixture.session.investigation_id,
        "session_id": fixture.session.session_id, "actor_ref": fixture.project.user_id,
        "tool_id": grant.tool_id, "tool_version": grant.tool_version, "provider_digest": grant.provider_digest,
        "input_ref": EntityId::new(), "input_sha256": grant.bounded_input_sha256, "input_revision": 0,
        "control_revision": control_revision, "scope_revision": grant.scope_revision,
        "identity_id": grant.identity_id, "budget_id": budget.budget_id, "attempt": 1,
        "causation_id": EntityId::new(), "deduplication_key": format!("effect.{}", EntityId::new()),
        "state": "proposed", "usage": {"units": 0, "bytes": 0, "cpu_us": 0, "elapsed_us": 0}
    })).unwrap();
    let mut history = InvocationHistory::start(&proposed).unwrap();
    let mut invocation = proposed;
    invocation.state = InvocationState::Reserved;
    invocation.grant_id = Some(grant.grant_id);
    history
        .record(&invocation, Some(grant), AuditTime::now())
        .unwrap();
    StoredInvocation {
        invocation,
        history,
        reserved_units: wire(1),
        requested: serde_json::from_value(
            json!({"units": 1, "bytes": 0, "cpu_us": 0, "elapsed_us": 0}),
        )
        .unwrap(),
        source_control_revision: control_revision,
    }
}

fn record_sending(stored: &mut StoredInvocation, grant: &ApprovalGrant) {
    stored.invocation.state = InvocationState::Sending;
    stored
        .history
        .record(&stored.invocation, Some(grant), AuditTime::now())
        .unwrap();
}

#[test]
fn scope_replacement_preserves_old_terminal_and_pending_provenance_without_readmitting_it() {
    let run = TestRun::new();
    let fixture = Fixture::new();
    let ledger = run.create();
    fixture.install(&ledger);
    let mut retained = Vec::new();
    for state in [
        InvocationState::Completed,
        InvocationState::Failed,
        InvocationState::Cancelled,
        InvocationState::Reserved,
    ] {
        let budget = invocation_budget();
        ledger.insert_budget(&budget).unwrap();
        let mut stored = reserved_invocation(&run, &fixture, &budget, &fixture.grant, wire(0));
        ledger
            .transaction(|tx| {
                tx.reserve_budget(budget.budget_id, wire(1), wire(0))?;
                tx.insert_invocation(&stored)
            })
            .unwrap();
        if state != InvocationState::Reserved {
            if state != InvocationState::Cancelled {
                record_sending(&mut stored, &fixture.grant);
                ledger
                    .transaction(|tx| tx.update_invocation(&stored, InvocationState::Reserved))
                    .unwrap();
            }
            let previous = stored.invocation.state;
            stored.invocation.state = state;
            stored
                .history
                .record(&stored.invocation, None, AuditTime::now())
                .unwrap();
            stored.reserved_units = wire(0);
            ledger
                .transaction(|tx| {
                    tx.settle_budget(budget.budget_id, wire(1), wire(0), wire(1))?;
                    tx.update_invocation(&stored, previous)
                })
                .unwrap();
        }
        retained.push((budget, stored));
    }
    let mut scope = fixture.scope.clone();
    scope.revision = wire(1);
    ledger.replace_scope(&scope, wire(0)).unwrap();
    drop(ledger);
    let ledger = run.reopen();
    for (_, expected) in &retained {
        let actual = ledger
            .read_invocation(expected.invocation.invocation_id)
            .unwrap();
        assert_eq!(actual.invocation, expected.invocation);
        assert_eq!(
            actual.history.export_json().unwrap(),
            expected.history.export_json().unwrap()
        );
        assert_eq!(actual.reserved_units, expected.reserved_units);
    }
    let (pending_budget, pending) = retained.last().unwrap();
    assert_eq!(
        ledger
            .read_budget(pending_budget.budget_id)
            .unwrap()
            .reserved,
        wire(1)
    );
    let mut attempted_send = pending.clone();
    record_sending(&mut attempted_send, &fixture.grant);
    assert!(
        ledger
            .transaction(|tx| tx.update_invocation(&attempted_send, InvocationState::Reserved))
            .is_err(),
        "restoring an old reservation does not admit its effect in a newer policy epoch"
    );
    assert_eq!(
        ledger
            .read_invocation(pending.invocation.invocation_id)
            .unwrap()
            .invocation
            .state,
        InvocationState::Reserved,
        "stale pending work requires explicit reconciliation, not replay"
    );
    ledger
        .transaction(|tx| tx.apply_control(&fixture.paused(), wire(0)))
        .unwrap();
    assert_eq!(
        ledger
            .read_invocation(pending.invocation.invocation_id)
            .unwrap()
            .invocation
            .state,
        InvocationState::Cancelled
    );
    assert_eq!(
        ledger
            .read_budget(pending_budget.budget_id)
            .unwrap()
            .reserved,
        wire(0)
    );
    assert_eq!(
        ledger.latest_checkpoint().unwrap().unwrap().scope_revision,
        wire(1),
        "root scope replacement must atomically advance the existing control's scope context"
    );
    drop(ledger);
    let ledger = run.reopen();
    assert_eq!(ledger.invocations().unwrap().len(), retained.len());
    for (_, expected) in retained.iter().take(3) {
        assert_eq!(
            ledger
                .read_invocation(expected.invocation.invocation_id)
                .unwrap()
                .invocation,
            expected.invocation,
            "later control changes preserve terminal origin revisions"
        );
    }
}

#[test]
fn new_reservations_require_exact_current_scope_and_control_not_merely_nonfuture_revisions() {
    let run = TestRun::new();
    let fixture = Fixture::new();
    let ledger = run.create();
    fixture.install(&ledger);
    let mut next_scope = fixture.scope.clone();
    next_scope.revision = wire(1);
    ledger.replace_scope(&next_scope, wire(0)).unwrap();
    for scope_revision in [0, 2] {
        let budget = invocation_budget();
        ledger.insert_budget(&budget).unwrap();
        let mut grant = fixture.grant.clone();
        if scope_revision != 0 {
            grant.grant_id = EntityId::new();
            grant.scope_revision = wire(scope_revision);
            ledger.insert_grant(&grant).unwrap();
        }
        let stored = reserved_invocation(&run, &fixture, &budget, &grant, wire(0));
        assert!(
            ledger
                .transaction(|tx| {
                    tx.reserve_budget(budget.budget_id, wire(1), wire(0))?;
                    tx.insert_invocation(&stored)
                })
                .is_err(),
            "scope {scope_revision} is not the current root epoch"
        );
        assert_eq!(ledger.read_budget(budget.budget_id).unwrap(), budget);
        assert!(
            ledger
                .read_invocation(stored.invocation.invocation_id)
                .is_err()
        );
    }
    let mut current_grant = fixture.grant.clone();
    current_grant.grant_id = EntityId::new();
    current_grant.scope_revision = wire(1);
    ledger.insert_grant(&current_grant).unwrap();
    let budget = invocation_budget();
    ledger.insert_budget(&budget).unwrap();
    let mut current = reserved_invocation(&run, &fixture, &budget, &current_grant, wire(0));
    ledger
        .transaction(|tx| {
            tx.reserve_budget(budget.budget_id, wire(1), wire(0))?;
            tx.insert_invocation(&current)
        })
        .unwrap();
    record_sending(&mut current, &current_grant);
    ledger
        .transaction(|tx| tx.update_invocation(&current, InvocationState::Reserved))
        .unwrap();
    ledger
        .transaction(|tx| tx.apply_control(&fixture.paused(), wire(0)))
        .unwrap();
    let mut resumed = fixture.control.clone();
    resumed.revision = wire(2);
    ledger
        .transaction(|tx| tx.apply_control(&resumed, wire(1)))
        .unwrap();
    for control_revision in [0, 3] {
        let budget = invocation_budget();
        ledger.insert_budget(&budget).unwrap();
        let stored = reserved_invocation(
            &run,
            &fixture,
            &budget,
            &current_grant,
            wire(control_revision),
        );
        assert!(
            ledger
                .transaction(|tx| {
                    tx.reserve_budget(budget.budget_id, wire(1), wire(0))?;
                    tx.insert_invocation(&stored)
                })
                .is_err(),
            "control {control_revision} is not the current admission epoch"
        );
        assert_eq!(ledger.read_budget(budget.budget_id).unwrap(), budget);
    }
    drop(ledger);
    let ledger = run.reopen();
    assert_eq!(
        ledger
            .read_invocation(current.invocation.invocation_id)
            .unwrap()
            .invocation,
        current.invocation,
        "an already-dispatched old-control effect is retained, not replayed or invalidated"
    );
}

#[test]
fn grant_capacity_is_finite_and_exhaustion_never_truncates_or_publishes_a_failed_insert() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let mut expected_ids = std::collections::BTreeSet::from([fixture.grant.grant_id]);
    let mut rejected_id = None;
    ledger
        .transaction(|tx| {
            for _ in 0..4096 {
                let mut grant = fixture.grant.clone();
                grant.grant_id = EntityId::new();
                match tx.insert_grant(&grant) {
                    Ok(()) => {
                        expected_ids.insert(grant.grant_id);
                    }
                    Err(error) => {
                        assert_eq!(error.code, ErrorCode::BudgetExhausted);
                        assert!(tx.read_grant(grant.grant_id).is_err());
                        rejected_id = Some(grant.grant_id);
                        break;
                    }
                }
            }
            assert!(
                rejected_id.is_some(),
                "canonical grants must have a finite ceiling no greater than 4096"
            );
            assert_eq!(
                tx.grants()?.len(),
                expected_ids.len(),
                "listing must never silently truncate"
            );
            Ok(())
        })
        .unwrap();
    drop(ledger);
    let ledger = run.reopen();
    let actual = ledger.grants().unwrap();
    assert_eq!(
        actual
            .iter()
            .map(|grant| grant.grant_id)
            .collect::<std::collections::BTreeSet<_>>(),
        expected_ids
    );
    for grant in actual {
        let mut expected = fixture.grant.clone();
        expected.grant_id = grant.grant_id;
        assert_eq!(grant, expected);
    }
    assert!(ledger.read_grant(rejected_id.unwrap()).is_err());
    let unknown_id = EntityId::new();
    assert!(
        ledger.revoke_grant(unknown_id).is_err(),
        "revocation cannot create authority"
    );
    assert!(ledger.read_grant(unknown_id).is_err());
}

#[test]
fn session_and_control_require_matching_project_even_when_each_id_and_user_is_valid() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let other = Fixture::new();
    ledger
        .transaction(|tx| {
            tx.insert_project(&other.project)?;
            tx.insert_scope(&other.scope)
        })
        .unwrap();
    ledger
        .insert_control(
            &other.control,
            other.project.project_id,
            other.scope.revision,
        )
        .unwrap();
    let mut cross_project = fixture.session.clone();
    cross_project.session_id = EntityId::new();
    cross_project.investigation_id = other.control.investigation_id;
    assert!(
        ledger
            .insert_session(&cross_project, fixture.project.project_id)
            .is_err(),
        "a legitimate owner cannot link a session to another project's control"
    );
    assert!(ledger.read_session(cross_project.session_id).is_err());
    let mut standalone = fixture.session.clone();
    standalone.session_id = EntityId::new();
    standalone.investigation_id = EntityId::new();
    ledger
        .insert_session(&standalone, fixture.project.project_id)
        .unwrap();
    let mut control = fixture.control.clone();
    control.investigation_id = standalone.investigation_id;
    assert!(
        ledger
            .insert_control(&control, other.project.project_id, other.scope.revision)
            .is_err(),
        "late control registration cannot contradict an existing canonical session owner"
    );
    assert!(ledger.read_control(control.investigation_id).is_err());
    ledger
        .insert_control(&control, fixture.project.project_id, fixture.scope.revision)
        .unwrap();
    drop(ledger);
    let ledger = run.reopen();
    assert_eq!(
        ledger.read_session(standalone.session_id).unwrap().session,
        standalone
    );
    assert_eq!(
        ledger.read_control(control.investigation_id).unwrap(),
        control
    );
}

#[test]
fn matching_grants_filters_the_exact_binding_without_treating_a_match_as_authorization() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let mut second = fixture.grant.clone();
    second.grant_id = EntityId::new();
    let mut unrelated_input = fixture.grant.clone();
    unrelated_input.grant_id = EntityId::new();
    unrelated_input.bounded_input_sha256 = Digest::of(b"a different bounded request");
    ledger
        .transaction(|tx| {
            tx.insert_grant(&second)?;
            tx.insert_grant(&unrelated_input)
        })
        .unwrap();
    let budget = invocation_budget();
    let invocation =
        reserved_invocation(&run, &fixture, &budget, &fixture.grant, wire(0)).invocation;
    let expected_ids = std::collections::BTreeSet::from([fixture.grant.grant_id, second.grant_id]);
    let matching = ledger.matching_grants(&invocation).unwrap();
    assert_eq!(
        matching
            .iter()
            .map(|grant| grant.grant_id)
            .collect::<std::collections::BTreeSet<_>>(),
        expected_ids,
        "lookup considers the bound input, not just tool/project or the supplied grant ID"
    );
    ledger
        .transaction(|tx| {
            let matches = tx.matching_grants(&invocation)?;
            assert_eq!(
                matches
                    .iter()
                    .map(|grant| grant.grant_id)
                    .collect::<std::collections::BTreeSet<_>>(),
                expected_ids
            );
            for grant in matches {
                assert_eq!(grant, tx.read_grant(grant.grant_id)?);
            }
            Ok(())
        })
        .unwrap();
    for dimension in ["project", "tool", "provider", "scope", "identity", "input"] {
        let mut foreign = invocation.clone();
        match dimension {
            "project" => foreign.project_id = EntityId::new(),
            "tool" => foreign.tool_id = catalog("foreign.tool"),
            "provider" => foreign.provider_digest = Digest::of(b"foreign implementation"),
            "scope" => foreign.scope_revision = wire(1),
            "identity" => foreign.identity_id = EntityId::new(),
            "input" => foreign.input_sha256 = Digest::of(b"unregistered input"),
            _ => unreachable!(),
        }
        assert!(
            ledger.matching_grants(&foreign).unwrap().is_empty(),
            "lookup ignored the bound {dimension}"
        );
        ledger
            .transaction(|tx| {
                assert!(
                    tx.matching_grants(&foreign)?.is_empty(),
                    "transaction lookup ignored {dimension}"
                );
                Ok(())
            })
            .unwrap();
    }
    let mut excessive = invocation.usage;
    excessive.units = wire(11);
    assert!(
        fixture
            .grant
            .validate_current(&invocation, &excessive, AuditTime::now())
            .is_err(),
        "lookup cannot substitute for the requested Usage check"
    );
    assert_eq!(ledger.matching_grants(&invocation).unwrap().len(), 2);
    ledger
        .transaction(|tx| {
            tx.revoke_grant(fixture.grant.grant_id)?;
            assert!(
                tx.read_grant(fixture.grant.grant_id)?
                    .validate_current(&invocation, &invocation.usage, AuditTime::now())
                    .is_err()
            );
            for grant in tx.matching_grants(&invocation)? {
                assert_eq!(
                    grant,
                    tx.read_grant(grant.grant_id)?,
                    "lookup must observe this transaction's revocation"
                );
            }
            Ok(())
        })
        .unwrap();
    drop(ledger);
    let ledger = run.reopen();
    for grant in ledger.matching_grants(&invocation).unwrap() {
        assert_eq!(grant, ledger.read_grant(grant.grant_id).unwrap());
    }
    assert!(ledger.read_grant(fixture.grant.grant_id).unwrap().revoked);
}

#[test]
fn owned_run_dedup_lookup_observes_transaction_commit_rollback_and_restart() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    assert_eq!(ledger.run_id(), run.workspace.run_id());
    let budget = invocation_budget();
    ledger.insert_budget(&budget).unwrap();
    let stored = reserved_invocation(&run, &fixture, &budget, &fixture.grant, wire(0));
    let key = &stored.invocation.deduplication_key;
    assert!(ledger.invocation_for_dedup(key).unwrap().is_none());
    let write = |tx: &mut LedgerTransaction<'_>| {
        assert!(tx.invocation_for_dedup(key)?.is_none());
        tx.reserve_budget(budget.budget_id, wire(1), wire(0))?;
        tx.insert_invocation(&stored)?;
        let found = tx
            .invocation_for_dedup(key)?
            .expect("own pending insert is visible");
        assert_eq!(found.invocation, stored.invocation);
        assert_eq!(found.history.export_json()?, stored.history.export_json()?);
        Ok(())
    };
    assert_eq!(
        ledger
            .transaction(|tx| {
                write(tx)?;
                Err::<(), _>(abort())
            })
            .unwrap_err()
            .code,
        ErrorCode::Cancelled
    );
    assert!(ledger.invocation_for_dedup(key).unwrap().is_none());
    ledger.transaction(write).unwrap();
    assert_eq!(
        ledger
            .invocation_for_dedup(key)
            .unwrap()
            .unwrap()
            .invocation,
        stored.invocation
    );
    assert!(
        ledger
            .invocation_for_dedup(&format!("other-binding.{key}"))
            .unwrap()
            .is_none()
    );
    for key in [
        String::new(),
        "x".repeat(257),
        "é".repeat(129),
        "binding\nkey".to_owned(),
    ] {
        assert_eq!(
            ledger.invocation_for_dedup(&key).unwrap_err().code,
            ErrorCode::InvalidInput
        );
        ledger
            .transaction(|tx| {
                assert_eq!(
                    tx.invocation_for_dedup(&key).unwrap_err().code,
                    ErrorCode::InvalidInput
                );
                Ok(())
            })
            .unwrap();
    }
    assert!(
        ledger
            .invocation_for_dedup(&"é".repeat(128))
            .unwrap()
            .is_none(),
        "the 256-byte limit is exact UTF-8 bytes, not character count"
    );
    drop(ledger);
    let ledger = run.reopen();
    assert_eq!(ledger.run_id(), run.workspace.run_id());
    assert_eq!(
        ledger
            .invocation_for_dedup(key)
            .unwrap()
            .unwrap()
            .invocation,
        stored.invocation
    );
}

#[test]
fn optional_tool_lookup_distinguishes_absence_from_a_corrupted_existing_provider() {
    let run = TestRun::new();
    let ledger = run.create();
    let fixture = Fixture::new();
    fixture.install(&ledger);
    let id = &fixture.grant.tool_id;
    let expected = ledger.read_tool(id).unwrap();
    let missing = CatalogId::parse("missing.provider").unwrap();
    assert_eq!(ledger.find_tool(&missing).unwrap(), None);
    assert_eq!(ledger.find_tool(id).unwrap(), Some(expected.clone()));
    ledger
        .transaction(|tx| {
            assert_eq!(tx.find_tool(&missing)?, None);
            assert_eq!(tx.find_tool(id)?, Some(expected));
            Ok(())
        })
        .unwrap();
    let path = run
        .workspace
        .path()
        .canonicalize()
        .unwrap()
        .join("ledger.sqlite");
    let probe = rusqlite::Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .unwrap();
    probe
        .execute(
            "UPDATE tools SET provider_digest=?1 WHERE tool_id=?2",
            rusqlite::params![
                Digest::of(b"corrupted indexed provider").to_string(),
                id.as_str()
            ],
        )
        .unwrap();
    drop(probe);
    assert_eq!(
        ledger.find_tool(id).unwrap_err().code,
        ErrorCode::IntegrityError
    );
    ledger
        .transaction(|tx| {
            assert_eq!(
                tx.find_tool(id).unwrap_err().code,
                ErrorCode::IntegrityError
            );
            Ok(())
        })
        .unwrap();
}
