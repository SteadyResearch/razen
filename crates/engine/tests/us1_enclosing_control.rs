//! Canonical policy-state checks; these are not operational provider/binary proofs.
use std::path::Path;
use std::sync::Arc;

use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::admission::{BindingSpec, TrustedBinding};
use razen_engine::application::control::{ControlAction, ControlCommand};
use razen_engine::application::control_owner::OwnedControl;
use razen_engine::application::profile::LoadedProfile;
use razen_engine::application::proof_host::ProofHost;
use razen_engine::application::registry::PreparedInvocation;
use razen_engine::domain::execution::ControlMode;
use razen_engine::domain::values::{
    CatalogId, ContractVersion, Digest, EntityId, InvocationState, WireInt,
};
use razen_engine::protocol::contracts::CanonicalFixtures;
use razen_engine::protocol::error::ErrorCode;
use razen_engine::protocol::messages::ToolRequest;
use serde_json::value::RawValue;

#[path = "support/private_root.rs"]
mod private_root;

struct Fixture {
    owner: OwnedControl,
    host: ProofHost,
    _root: private_root::PrivateRoot,
}

impl Fixture {
    fn new() -> Self {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = LoadedProfile::load(
            &repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let bytes = std::fs::read(repository.join("fixtures/scenarios/contracts.json")).unwrap();
        let root = private_root::PrivateRoot::new();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        let host = ProofHost::create(
            workspace.clone(),
            &profile,
            CanonicalFixtures::from_bytes(&bytes).unwrap(),
            Digest::of(&bytes),
            Digest::of(b"canonical policy-state fixture, not an operational provider identity"),
        )
        .unwrap();
        let owner = OwnedControl::start(workspace, host.control.clone()).unwrap();
        host.install_control_client(owner.client().unwrap())
            .unwrap();
        Self {
            owner,
            host,
            _root: root,
        }
    }

    fn child_spec(&self) -> BindingSpec {
        self.host.fork_session().unwrap().local_spec()
    }

    fn control(&self, action: ControlAction) {
        let state = self
            .host
            .ledger
            .read_control(self.host.session.investigation_id)
            .unwrap();
        self.owner
            .client()
            .unwrap()
            .request(&ControlCommand {
                request_id: EntityId::new(),
                investigation_id: state.investigation_id,
                expected_revision: state.revision,
                action,
            })
            .unwrap();
    }

    fn prepare(&self, binding: &Arc<TrustedBinding>) -> PreparedInvocation {
        let snapshot = self
            .host
            .evidence
            .snapshots()
            .unwrap()
            .into_iter()
            .find(|snapshot| snapshot.project_id == binding.project_id() && !snapshot.truncated)
            .unwrap();
        let input = RawValue::from_string(
            serde_json::json!({"snapshot_id":snapshot.snapshot_id,
            "revision":snapshot.revision,"offset":0,"max_bytes":1})
            .to_string(),
        )
        .unwrap();
        self.host
            .registry
            .prepare(
                binding,
                &ToolRequest {
                    call_id: EntityId::new(),
                    tool_id: CatalogId::parse("traffic.snapshot.read").unwrap(),
                    tool_version: ContractVersion::V0_1_0,
                    input: &input,
                    source_control_revision: binding.control_revision(),
                },
            )
            .unwrap()
    }
}

#[test]
fn review_enclosing_cancel_blocks_existing_and_new_child_investigations_and_releases_unsent_hold() {
    let fixture = Fixture::new();
    let spec = fixture.child_spec();
    let binding = Arc::new(fixture.host.admission.bind(spec.clone()).unwrap());
    let prepared = fixture.prepare(&binding);
    fixture.host.approve(&binding, prepared.call()).unwrap();
    let before = fixture
        .host
        .ledger
        .read_budget(binding.budget_id())
        .unwrap();
    fixture
        .host
        .admission
        .reserve(&binding, prepared.call())
        .unwrap();
    fixture.control(ControlAction::Cancel);

    let denied = fixture
        .host
        .admission
        .bind(spec)
        .err()
        .expect("run cancellation must prevent a new child binding");
    assert_eq!(denied.code, ErrorCode::Cancelled);
    let later = fixture.child_spec();
    assert_eq!(
        fixture
            .host
            .admission
            .bind(later)
            .err()
            .expect("late registration cannot escape cancellation")
            .code,
        ErrorCode::Cancelled
    );
    let error = fixture
        .host
        .admission
        .begin_effect(&binding, prepared.call().invocation_id)
        .err()
        .expect("already reserved child must not enter Sending after the enclosing ACK");
    assert_eq!(error.code, ErrorCode::Cancelled);
    let stored = fixture
        .host
        .ledger
        .read_invocation(prepared.call().invocation_id)
        .unwrap();
    assert_eq!(stored.invocation.state, InvocationState::Cancelled);
    assert_eq!(stored.reserved_units, WireInt::ZERO);
    let after = fixture
        .host
        .ledger
        .read_budget(binding.budget_id())
        .unwrap();
    assert_eq!(after.consumed, before.consumed);
    assert_eq!(after.reserved, before.reserved);
    assert_eq!(stored.history.last(), &stored.invocation);
}

#[test]
fn review_enclosing_resume_does_not_renew_an_old_child_binding_but_a_fresh_binding_can_reserve() {
    let fixture = Fixture::new();
    let spec = fixture.child_spec();
    let old = Arc::new(fixture.host.admission.bind(spec.clone()).unwrap());
    let prepared = fixture.prepare(&old);
    fixture.host.approve(&old, prepared.call()).unwrap();
    fixture.control(ControlAction::Pause);
    fixture.control(ControlAction::Resume);

    let error = fixture
        .host
        .admission
        .reserve(&old, prepared.call())
        .expect_err("enclosing resume cannot renew a pre-pause child binding");
    assert_eq!(error.code, ErrorCode::StaleSnapshot);
    let rejected = fixture
        .host
        .ledger
        .read_invocation(prepared.call().invocation_id)
        .unwrap();
    assert_eq!(rejected.invocation.state, InvocationState::Rejected);
    assert_eq!(rejected.reserved_units, WireInt::ZERO);
    let fresh = Arc::new(fixture.host.admission.bind(spec).unwrap());
    assert_ne!(fresh.binding_id(), old.binding_id());
    let current = fixture.prepare(&fresh);
    fixture.host.approve(&fresh, current.call()).unwrap();
    assert_eq!(
        fixture
            .host
            .admission
            .reserve(&fresh, current.call())
            .unwrap()
            .state,
        InvocationState::Reserved
    );
}

#[test]
fn fixture_session_control_preserves_case_authority_and_shared_budget_but_not_root_cancel() {
    let fixture = Fixture::new();
    let outer = fixture.host.bind_local().unwrap();
    let outer_prepared = fixture.prepare(&outer);
    fixture.host.approve(&outer, outer_prepared.call()).unwrap();
    let outer_units = outer_prepared.call().requested.units;
    let before = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    let child = fixture.host.fork_session().unwrap();
    let old_child = child.bind_local().unwrap();
    let child_prepared = fixture.prepare(&old_child);
    child.approve(&old_child, child_prepared.call()).unwrap();
    assert_ne!(
        child.session.investigation_id,
        fixture.host.session.investigation_id
    );
    assert_ne!(child.session.session_id, fixture.host.session.session_id);
    assert_eq!(child.budget_id, fixture.host.budget_id);
    let client = child.control_client().unwrap();
    let paused = client
        .request(&ControlCommand {
            request_id: EntityId::new(),
            investigation_id: old_child.investigation_id(),
            expected_revision: old_child.control_revision(),
            action: ControlAction::Pause,
        })
        .unwrap();
    assert_eq!(
        child
            .admission
            .reserve(&old_child, child_prepared.call())
            .unwrap_err()
            .code,
        ErrorCode::StaleSnapshot
    );
    let completed = fixture
        .host
        .registry
        .execute_prepared(&outer, outer_prepared)
        .unwrap();
    assert_eq!(completed.state, InvocationState::Completed);
    let after = fixture
        .host
        .ledger
        .read_budget(fixture.host.budget_id)
        .unwrap();
    assert_eq!(after.limit, before.limit);
    assert_eq!(after.reserved, before.reserved);
    assert_eq!(
        after.consumed.get(),
        before
            .consumed
            .get()
            .checked_add(outer_units.get())
            .unwrap()
    );
    let root_control = fixture
        .host
        .ledger
        .read_control(fixture.host.session.investigation_id)
        .unwrap();
    assert_eq!(root_control.mode, ControlMode::Running);
    assert_eq!(root_control.revision, outer.control_revision());
    client
        .request(&ControlCommand {
            request_id: EntityId::new(),
            investigation_id: child.session.investigation_id,
            expected_revision: paused.state.revision,
            action: ControlAction::Resume,
        })
        .unwrap();
    let fresh = child.bind_local().unwrap();
    assert!(fresh.control_revision() > old_child.control_revision());
    let later = fixture.prepare(&fresh);
    child.approve(&fresh, later.call()).unwrap();
    assert_eq!(child.ledger.read_budget(child.budget_id).unwrap(), after);
    fixture.control(ControlAction::Cancel);
    assert_eq!(
        child
            .admission
            .reserve(&fresh, later.call())
            .unwrap_err()
            .code,
        ErrorCode::Cancelled
    );
    assert_eq!(child.ledger.read_budget(child.budget_id).unwrap(), after);
}
