use std::path::Path;
use std::sync::Arc;

use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::control::{ControlAction, ControlCommand};
use razen_engine::application::control_owner::OwnedControl;
use razen_engine::application::profile::LoadedProfile;
use razen_engine::application::proof_host::ProofHost;
use razen_engine::domain::values::{Digest, EntityId, WireInt};
use razen_engine::protocol::contracts::CanonicalFixtures;
use razen_engine::protocol::error::ErrorCode;

#[path = "support/private_root.rs"]
mod private_root;

fn host(root: &private_root::PrivateRoot) -> ProofHost {
    let workspace = Arc::new(
        OwnedDirectory::create(
            root.path(),
            Path::new("proof-run-with-an-output-name-longer-than-a-unix-socket-path"),
            EntityId::new(),
        )
        .unwrap(),
    );
    let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let profile =
        LoadedProfile::load(&repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"))
            .unwrap();
    let bytes = std::fs::read(repo.join("fixtures/scenarios/contracts.json")).unwrap();
    ProofHost::create(
        workspace,
        &profile,
        CanonicalFixtures::from_bytes(&bytes).unwrap(),
        Digest::of(&bytes),
        Digest::of(b"long-path control policy-test provider metadata"),
    )
    .unwrap()
}

#[test]
fn long_evidence_paths_do_not_disable_the_actual_durable_private_control_channel() {
    let root = private_root::PrivateRoot::new();
    let host = host(&root);
    assert!(
        host.workspace
            .path()
            .join("ephemeral/control.sock")
            .as_os_str()
            .as_encoded_bytes()
            .len()
            >= 104
    );
    let owner =
        OwnedControl::start(Arc::clone(&host.workspace), Arc::clone(&host.control)).unwrap();
    let auxiliary = owner.workspace_path().to_owned();
    assert!(
        !auxiliary.starts_with(root.path()),
        "control uses its explicitly owned short resource workspace"
    );
    let client = owner.client().unwrap();
    let ack = client
        .request(&ControlCommand {
            request_id: EntityId::new(),
            investigation_id: host.session.investigation_id,
            expected_revision: WireInt::ZERO,
            action: ControlAction::Pause,
        })
        .unwrap();
    assert_eq!(
        ack.state,
        host.ledger
            .read_control(host.session.investigation_id)
            .unwrap()
    );
    assert!(!ack.state.admission_open);
    assert!(ack.measurement.ack_elapsed_us().unwrap().get() <= 1_000_000);
    assert!(host.bind_local().is_err());
    owner.shutdown().unwrap();
    assert!(
        !auxiliary.exists(),
        "owned control socket/token/marker/directory are removed after worker join"
    );
    assert!(
        client
            .request(&ControlCommand {
                request_id: EntityId::new(),
                investigation_id: host.session.investigation_id,
                expected_revision: ack.state.revision,
                action: ControlAction::Resume
            })
            .is_err()
    );
    assert_eq!(
        host.ledger
            .read_control(host.session.investigation_id)
            .unwrap(),
        ack.state
    );
}

#[test]
fn control_cleanup_refuses_unexpected_files_instead_of_recursively_deleting_them() {
    let root = private_root::PrivateRoot::new();
    let host = host(&root);
    let owner =
        OwnedControl::start(Arc::clone(&host.workspace), Arc::clone(&host.control)).unwrap();
    let auxiliary = owner.workspace_path().to_owned();
    let unowned = auxiliary.join("unrelated-user-file");
    std::fs::write(&unowned, b"keep this unrelated file").unwrap();
    let error = owner.shutdown().unwrap_err();
    assert_eq!(error.code, ErrorCode::PermissionDenied);
    assert_eq!(
        std::fs::read(&unowned).unwrap(),
        b"keep this unrelated file"
    );
    assert!(auxiliary.join(".razen-run.json").exists());
    // This test created and captured this unique auxiliary directory and file;
    // remove its own negative-test residue after proving production refused it.
    std::fs::remove_dir_all(auxiliary).unwrap();
}
