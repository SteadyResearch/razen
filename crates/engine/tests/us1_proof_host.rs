use std::path::Path;
use std::sync::Arc;

use razen_engine::adapters::evidence_store::EvidenceStore;
use razen_engine::adapters::ledger::Ledger;
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::profile::LoadedProfile;
use razen_engine::application::proof_host::ProofHost;
use razen_engine::domain::values::{CatalogId, Digest, EntityId, InvocationState, WireInt};
use razen_engine::protocol::contracts::{CanonicalFixtures, ContractRecord};
use razen_engine::protocol::error::ErrorCode;

#[path = "support/private_root.rs"]
mod private_root;

fn inputs() -> (LoadedProfile, Vec<u8>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    (
        LoadedProfile::load(&root.join("specs/001-r0-feasibility/contracts/pilot-profile.json"))
            .unwrap(),
        std::fs::read(root.join("fixtures/scenarios/contracts.json")).unwrap(),
    )
}

#[test]
fn bootstrap_imports_real_public_bytes_with_a_durable_origin_but_never_imports_fixture_authority() {
    let root = private_root::PrivateRoot::new();
    let workspace =
        Arc::new(OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap());
    let (profile, bytes) = inputs();
    let examples = CanonicalFixtures::from_bytes(&bytes).unwrap();
    let old_grants: Vec<_> = examples
        .records()
        .iter()
        .filter_map(|document| match &document.record {
            ContractRecord::ApprovalGrant(grant) => Some(grant.grant_id),
            _ => None,
        })
        .collect();
    let public_bytes: u64 = examples
        .records()
        .iter()
        .filter_map(|document| match &document.record {
            ContractRecord::Artifact(artifact) => Some(artifact.length_bytes.get()),
            _ => None,
        })
        .sum();
    // Policy/storage test: the operational engine supplies its measured executable digest.
    let provider = Digest::of(b"bootstrap policy-test provider metadata");
    let host = ProofHost::create(
        Arc::clone(&workspace),
        &profile,
        examples,
        Digest::of(&bytes),
        provider,
    )
    .unwrap();
    let imported = host
        .ledger
        .read_invocation(host.bootstrap_invocation_id)
        .unwrap();
    assert_eq!(imported.invocation.state, InvocationState::Completed);
    assert_eq!(imported.invocation.tool_id.as_str(), "proof.fixture.import");
    assert!(imported.invocation.grant_id.is_some());
    assert_eq!(imported.invocation.provider_digest, provider);
    assert_eq!(imported.invocation.usage.units.get(), 1);
    assert!(imported.invocation.usage.bytes.get() >= public_bytes);
    assert!(imported.invocation.usage.cpu_us.get() > 0);
    assert!(imported.invocation.usage.elapsed_us.get() > 0);
    assert_eq!(imported.reserved_units, WireInt::ZERO);
    imported
        .invocation
        .validate(Some(&imported.history))
        .unwrap();
    assert_eq!(
        host.ledger
            .read_budget(host.budget_id)
            .unwrap()
            .consumed
            .get(),
        1
    );
    for old_grant in old_grants {
        assert!(
            host.ledger.read_grant(old_grant).is_err(),
            "schema examples are not live approvals"
        );
    }
    let artifacts = host.evidence.artifacts().unwrap();
    for artifact in &artifacts {
        assert_eq!(
            artifact.origin_invocation_id,
            imported.invocation.invocation_id
        );
        host.evidence
            .verify_artifact(host.project.project_id, artifact.artifact_id)
            .unwrap();
    }
    for snapshot in host.evidence.snapshots().unwrap() {
        let reader = host
            .evidence
            .snapshot_reader(
                host.project.project_id,
                snapshot.snapshot_id,
                snapshot.revision,
            )
            .unwrap();
        let body = reader.read(WireInt::ZERO, snapshot.length_bytes).unwrap();
        assert_eq!(Digest::of(&body), snapshot.sha256);
    }
    let binding = host.bind_local().unwrap();
    assert!(
        !binding
            .allowed_tools()
            .iter()
            .any(|tool| tool.as_str() == "proof.fixture.import")
    );
    assert!(
        !binding
            .allowed_tools()
            .iter()
            .any(|tool| tool.as_str() == "http.send")
    );
    let instruction = host
        .ledger
        .read_control(host.session.investigation_id)
        .unwrap()
        .instruction_ref;
    host.evidence
        .verify_artifact(host.project.project_id, instruction)
        .unwrap();
    let project = host.project.project_id;
    let invocation_id = host.bootstrap_invocation_id;
    let budget_id = host.budget_id;
    drop(host);
    let ledger = Ledger::open(&workspace, &profile).unwrap();
    assert_eq!(
        ledger.read_invocation(invocation_id).unwrap().invocation,
        imported.invocation
    );
    assert_eq!(ledger.read_budget(budget_id).unwrap().consumed.get(), 1);
    let evidence = EvidenceStore::open(workspace).unwrap();
    for artifact in artifacts {
        evidence
            .verify_artifact(project, artifact.artifact_id)
            .unwrap();
    }
}

#[test]
fn a_second_bootstrap_cannot_replace_authority_reset_quota_or_reinitialize_a_live_run() {
    let root = private_root::PrivateRoot::new();
    let workspace =
        Arc::new(OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap());
    let (profile, bytes) = inputs();
    let provider = Digest::of(b"bootstrap policy-test provider metadata");
    let host = ProofHost::create(
        Arc::clone(&workspace),
        &profile,
        CanonicalFixtures::from_bytes(&bytes).unwrap(),
        Digest::of(&bytes),
        provider,
    )
    .unwrap();
    let before = host.ledger.read_budget(host.budget_id).unwrap();
    let second = ProofHost::create(
        workspace,
        &profile,
        CanonicalFixtures::from_bytes(&bytes).unwrap(),
        Digest::of(&bytes),
        Digest::of(b"different provider"),
    );
    let error = match second {
        Ok(_) => panic!("Existing run was reinitialized"),
        Err(error) => error,
    };
    assert_eq!(error.code, ErrorCode::IntegrityError);
    assert_eq!(host.ledger.read_budget(host.budget_id).unwrap(), before);
    let imported = host
        .ledger
        .read_invocation(host.bootstrap_invocation_id)
        .unwrap();
    assert_eq!(imported.invocation.state, InvocationState::Completed);
    assert_eq!(
        host.ledger
            .read_tool(&CatalogId::parse("proof.fixture.import").unwrap())
            .unwrap()
            .provider_digest,
        provider
    );
}
