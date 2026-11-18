use razen_engine::adapters::components::supervisor::ApprovedComponents;
use razen_engine::domain::values::CatalogId;
use razen_engine::protocol::error::ErrorCode;
#[path = "support/component_fixture.rs"]
mod component_fixture;
use component_fixture::{Fixture, assert_reaped_successors};

#[test]
fn public_wit_component_reads_real_chunks_and_proposes_only_unchanged_snapshot_ranges() {
    let fixture = Fixture::new();
    let before = fixture.host.evidence.snapshots().unwrap();
    let observation = fixture.execute("CMP-01");
    assert_reaped_successors(&observation.report);
    let run = &observation.report["runs"][0];
    assert_eq!(run["outcome"], "completed");
    assert!(
        run["reads"]
            .as_array()
            .unwrap()
            .iter()
            .any(|read| read["bytes"].as_u64().unwrap() > 0)
    );
    assert!(!run["observations"].as_array().unwrap().is_empty());
    for snapshot in before {
        fixture
            .host
            .evidence
            .snapshot_reader(snapshot.project_id, snapshot.snapshot_id, snapshot.revision)
            .unwrap();
    }
    assert_eq!(
        observation.report["input_before_sha256"],
        observation.report["input_after_sha256"]
    );
}

#[test]
fn built_manifest_contains_six_distinct_verified_native_components_and_rejects_missing_artifacts() {
    let fixture = Fixture::new();
    let approved = ApprovedComponents::load(&fixture.repository, &fixture.profile).unwrap();
    assert_eq!(approved.variants().len(), 6);
    let hashes: std::collections::BTreeSet<_> = approved
        .variants()
        .iter()
        .map(|entry| entry.sha256)
        .collect();
    assert_eq!(hashes.len(), 6);
    let missing = ApprovedComponents::load(fixture.host.workspace.path(), &fixture.profile);
    assert!(
        missing.is_err(),
        "missing prebuilt fixtures cannot satisfy a proof"
    );
}

#[test]
fn actual_broker_denies_foreign_stale_hash_overflow_chunk_and_cumulative_reads_and_invalid_output()
{
    let fixture = Fixture::new();
    let observation = fixture.execute("CMP-04");
    assert_reaped_successors(&observation.report);
    let denials = observation.report["denials"].as_array().unwrap();
    for name in [
        "foreign_project",
        "stale_revision",
        "wrong_hash",
        "overflow_range",
        "chunk_limit",
        "cumulative_limit",
        "invalid_output",
    ] {
        let denial = denials
            .iter()
            .find(|denial| denial["attempt"] == name)
            .expect(name);
        assert!(denial["error"].is_object());
        assert_eq!(denial["bytes_copied"], 0);
    }
    assert!(
        observation.report["runs"]
            .as_array()
            .unwrap()
            .iter()
            .any(|run| run["variant"] == "fixture-output" && run["outcome"] != "completed")
    );
}

#[test]
fn guest_actually_attempts_filesystem_socket_environment_and_credentials_without_disclosure() {
    let fixture = Fixture::new();
    let observation = fixture.execute("CMP-06");
    assert_reaped_successors(&observation.report);
    let attempts = observation.report["access_attempts"].as_array().unwrap();
    for resource in ["filesystem", "socket", "environment", "credential"] {
        let attempt = attempts
            .iter()
            .find(|attempt| attempt["resource"] == resource)
            .expect(resource);
        assert_eq!(attempt["denied"], true);
    }
    let serialized = serde_json::to_vec(&observation.report).unwrap();
    assert!(
        !String::from_utf8(serialized)
            .unwrap()
            .contains("RAZEN_FIXTURE_CREDENTIAL_DO_NOT_EXPORT_20261116")
    );
}

#[test]
fn unknown_component_case_has_no_spawn_or_ledger_effect() {
    let fixture = Fixture::new();
    let before = fixture.host.ledger.invocations().unwrap().len();
    let error = razen_engine::application::suites::components::execute(
        &fixture.host,
        &fixture.profile,
        &fixture.repository,
        &CatalogId::parse("CMP-99").unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert_eq!(before, fixture.host.ledger.invocations().unwrap().len());
}
