use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::{Arc, atomic::AtomicBool, mpsc};

use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::cli::Suite;
use razen_engine::application::engine;
use razen_engine::application::harness::{
    BOOTSTRAP_PATH, CaseSelection, CommandStatus, EXAMPLES_PATH, EngineBootstrap, EngineOutcome,
    ReviewStatus, ScenarioManifest,
};
use razen_engine::application::packet::{publish, verify};
use razen_engine::domain::values::{AuditTime, CatalogId, ContractVersion, Digest, EntityId};
use serde_json::Value;

#[path = "support/private_root.rs"]
mod private_root;

struct Fixture {
    workspace: Arc<OwnedDirectory>,
    bootstrap: EngineBootstrap,
    selection: CaseSelection,
    outcome: EngineOutcome,
    _root: private_root::PrivateRoot,
}

impl Fixture {
    fn new(all_contracts: bool) -> Self {
        Self::with_cancellation(all_contracts, false)
    }

    fn with_cancellation(all_contracts: bool, cancelled: bool) -> Self {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let profile =
            fs::read(repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"))
                .unwrap();
        let manifest = fs::read(repository.join("fixtures/scenarios/manifest.json")).unwrap();
        let examples = fs::read(repository.join("fixtures/scenarios/contracts.json")).unwrap();
        let case = CatalogId::parse("CON-01").unwrap();
        let selection = serde_json::from_slice::<ScenarioManifest>(&manifest)
            .unwrap()
            .select(
                Suite::Contracts,
                if all_contracts { None } else { Some(&case) },
                Digest::of(&manifest),
            )
            .unwrap();
        let root = private_root::PrivateRoot::new();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        let bootstrap = EngineBootstrap {
            schema_version: ContractVersion::V0_1_0,
            run_id: workspace.run_id(),
            started_at: AuditTime::now(),
            profile_sha256: Digest::of(&profile),
            fixture_manifest_sha256: Digest::of(&manifest),
            contract_examples_sha256: Digest::of(&examples),
            // A test-only host observation, never used as operational proof of a binary.
            orchestrator_sha256: Digest::of(b"packet behavior-test host"),
        };
        for (name, bytes) in [
            ("profile.json", profile),
            ("fixture-manifest.json", manifest),
            ("cases.json", serde_json::to_vec(&selection).unwrap()),
            (EXAMPLES_PATH, examples),
            (BOOTSTRAP_PATH, serde_json::to_vec(&bootstrap).unwrap()),
        ] {
            workspace.write_new(Path::new(name), &bytes).unwrap();
        }
        let (send, receive) = mpsc::sync_channel(1);
        let outcome = engine::execute(
            workspace.clone(),
            &repository,
            Arc::new(AtomicBool::new(cancelled)),
            send,
        )
        .unwrap();
        // The worker has joined its control server. Release the last controller before publication.
        drop(receive);
        Self {
            workspace,
            bootstrap,
            selection,
            outcome,
            _root: root,
        }
    }

    fn publish(&self) {
        publish(
            &self.workspace,
            &self.bootstrap,
            &self.selection,
            &self.outcome,
        )
        .unwrap();
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.workspace.path().join(relative)
    }

    fn json(&self, relative: &str) -> Value {
        serde_json::from_slice(&fs::read(self.path(relative)).unwrap()).unwrap()
    }

    fn reseal_json(&self, relative: &str, value: &Value) {
        self.reseal_bytes(relative, &serde_json::to_vec(value).unwrap());
    }

    fn reseal_bytes(&self, relative: &str, bytes: &[u8]) {
        fs::write(self.path(relative), bytes).unwrap();
        let mut manifest = self.json("manifest.json");
        let entry = manifest["files"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|entry| entry["path"] == relative)
            .unwrap();
        entry["sha256"] = serde_json::to_value(Digest::of(bytes)).unwrap();
        entry["length_bytes"] = Value::from(bytes.len() as u64);
        fs::write(
            self.path("manifest.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
    }
}

// Includes bytes, inode, mode and timestamps affected by writes, but not read access time.
fn durable_snapshot(root: &Path) -> BTreeMap<PathBuf, (Vec<u8>, u64, u32, i64, i64)> {
    fn visit(
        root: &Path,
        path: &Path,
        result: &mut BTreeMap<PathBuf, (Vec<u8>, u64, u32, i64, i64)>,
    ) {
        for entry in fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let metadata = fs::symlink_metadata(entry.path()).unwrap();
            if metadata.is_dir() {
                visit(root, &entry.path(), result);
                continue;
            }
            let bytes = if metadata.is_symlink() {
                fs::read_link(entry.path())
                    .unwrap()
                    .as_os_str()
                    .as_encoded_bytes()
                    .to_vec()
            } else {
                fs::read(entry.path()).unwrap()
            };
            result.insert(
                entry.path().strip_prefix(root).unwrap().to_owned(),
                (
                    bytes,
                    metadata.ino(),
                    metadata.mode(),
                    metadata.mtime(),
                    metadata.mtime_nsec(),
                ),
            );
        }
    }
    let mut result = BTreeMap::new();
    visit(root, root, &mut result);
    result
}

#[test]
fn selected_five_passes_are_immutable_full_inventory_incomplete_and_never_human_reviewed() {
    let fixture = Fixture::new(true);
    let profile = fs::read(fixture.path("profile.json")).unwrap();
    let cases = fs::read(fixture.path("cases.json")).unwrap();
    let verdict = publish(
        &fixture.workspace,
        &fixture.bootstrap,
        &fixture.selection,
        &fixture.outcome,
    )
    .unwrap();
    assert_eq!(verdict.counts.total.get(), 35);
    assert_eq!(verdict.counts.passed.get(), 5);
    assert_eq!(verdict.counts.unexecuted.get(), 30);
    assert_eq!(verdict.selected_status, CommandStatus::Passed);
    assert_eq!(verdict.full_status, CommandStatus::Incomplete);
    assert_eq!(verdict.review_status, ReviewStatus::Unreviewed);
    assert!(!verdict.r0_exit_ready);
    assert_eq!(fs::read(fixture.path("profile.json")).unwrap(), profile);
    assert_eq!(fs::read(fixture.path("cases.json")).unwrap(), cases);
    let manifest = fixture.json("manifest.json");
    let paths: Vec<_> = manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .map(|file| file["path"].as_str().unwrap())
        .collect();
    for required in [
        ".razen-run.json",
        "profile.json",
        "fixture-manifest.json",
        "run.json",
        "versions.json",
        "cases.json",
        "results.json",
        "trace.jsonl",
        "exit.json",
        "ledger.sqlite",
        "evidence/store.json",
    ] {
        assert!(paths.contains(&required), "manifest must cover {required}");
    }
    assert!(
        paths
            .iter()
            .any(|path| path.starts_with("evidence/bodies/"))
    );
    assert!(
        paths
            .iter()
            .any(|path| path.starts_with("evidence/catalog/"))
    );
    assert!(
        paths
            .iter()
            .any(|path| path.starts_with("contract-campaigns-")),
        "original replay sources are proof bytes"
    );
    assert!(!paths.iter().any(|path| path.starts_with("ephemeral/")));
    let before = durable_snapshot(fixture.workspace.path());
    let verified = verify(&fixture.workspace).unwrap();
    assert_eq!(verified.full_status, CommandStatus::Incomplete);
    assert_eq!(verified.selected_status, CommandStatus::Passed);
    assert!(!verified.r0_exit_ready);
    assert!(
        publish(
            &fixture.workspace,
            &fixture.bootstrap,
            &fixture.selection,
            &fixture.outcome
        )
        .is_err()
    );
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
    fixture.workspace.cleanup_ephemeral().unwrap();
    assert_eq!(
        verify(&fixture.workspace).unwrap().full_status,
        CommandStatus::Incomplete
    );
    let campaign = paths
        .iter()
        .find(|path| path.ends_with("/framing-seed-replays.json"))
        .unwrap();
    fs::remove_file(fixture.path(campaign)).unwrap();
    let damaged = durable_snapshot(fixture.workspace.path());
    assert!(verify(&fixture.workspace).is_err());
    assert_eq!(durable_snapshot(fixture.workspace.path()), damaged);
}

#[test]
fn review_cancellation_without_a_failed_proof_is_incomplete_on_publication_and_readonly_verification()
 {
    let fixture = Fixture::with_cancellation(true, true);
    let verdict = publish(
        &fixture.workspace,
        &fixture.bootstrap,
        &fixture.selection,
        &fixture.outcome,
    )
    .unwrap();
    assert_eq!(verdict.counts.total.get(), 35);
    assert_eq!(verdict.counts.failed.get(), 0);
    assert_eq!(verdict.counts.unexecuted.get(), 35);
    assert_eq!(verdict.selected_status, CommandStatus::Incomplete);
    assert_eq!(verdict.full_status, CommandStatus::Incomplete);
    assert_eq!(verdict.review_status, ReviewStatus::Unreviewed);
    assert!(!verdict.r0_exit_ready);
    let before = durable_snapshot(fixture.workspace.path());
    let verified = verify(&fixture.workspace).unwrap();
    assert_eq!(verified.selected_status, CommandStatus::Incomplete);
    assert_eq!(verified.full_status, CommandStatus::Incomplete);
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn artifact_tamper_fails_readonly_without_repair_or_provider_execution() {
    let fixture = Fixture::new(false);
    fixture.publish();
    let body = fs::read_dir(fixture.path("evidence/bodies"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut bytes = fs::read(&body).unwrap();
    bytes.push(0);
    fs::write(body, bytes).unwrap();
    let before = durable_snapshot(fixture.workspace.path());
    assert!(verify(&fixture.workspace).is_err());
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn missing_evidence_layout_is_not_recreated_by_verify() {
    let fixture = Fixture::new(false);
    fixture.publish();
    fs::rename(
        fixture.path("evidence"),
        fixture._root.path().join("saved-evidence"),
    )
    .unwrap();
    let before = durable_snapshot(fixture.workspace.path());
    assert!(verify(&fixture.workspace).is_err());
    assert!(!fixture.path("evidence").exists());
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn added_unindexed_regular_file_or_unsafe_link_cannot_hide_from_manifest() {
    let fixture = Fixture::new(false);
    fixture.publish();
    fixture
        .workspace
        .write_new(Path::new("evidence/added.bin"), b"unindexed")
        .unwrap();
    assert!(verify(&fixture.workspace).is_err());
    fs::remove_file(fixture.path("evidence/added.bin")).unwrap();
    fs::hard_link(fixture.path("profile.json"), fixture.path("hard-link")).unwrap();
    assert!(verify(&fixture.workspace).is_err());
    fs::remove_file(fixture.path("hard-link")).unwrap();
    fs::create_dir(fixture.path("added-empty-directory")).unwrap();
    fs::set_permissions(
        fixture.path("added-empty-directory"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert!(verify(&fixture.workspace).is_err());
    fs::remove_dir(fixture.path("added-empty-directory")).unwrap();
    symlink(fixture.path("profile.json"), fixture.path("foreign-link")).unwrap();
    let before = durable_snapshot(fixture.workspace.path());
    assert!(verify(&fixture.workspace).is_err());
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn metadata_permission_change_is_not_valid_packet_even_with_unchanged_bytes() {
    let fixture = Fixture::new(false);
    fixture.publish();
    fs::set_permissions(
        fixture.path("results.json"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let before = durable_snapshot(fixture.workspace.path());
    assert!(verify(&fixture.workspace).is_err());
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn rehashed_out_of_range_or_foreign_result_reference_is_not_evidence() {
    let fixture = Fixture::new(false);
    fixture.publish();
    let original = fixture.json("results.json");
    let mut changed = original.clone();
    changed[0]["evidence_refs"][0]["range_start"] = Value::from(0);
    changed[0]["evidence_refs"][0]["range_end"] = Value::from(9007199254740991u64);
    fixture.reseal_json("results.json", &changed);
    assert!(verify(&fixture.workspace).is_err());
    let mut changed = original;
    changed[0]["evidence_refs"][0]["artifact_id"] = serde_json::to_value(EntityId::new()).unwrap();
    fixture.reseal_json("results.json", &changed);
    let before = durable_snapshot(fixture.workspace.path());
    assert!(verify(&fixture.workspace).is_err());
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn rehashed_duplicate_results_or_fabricated_usage_never_validate_against_real_ledger() {
    let fixture = Fixture::new(false);
    fixture.publish();
    let original = fixture.json("results.json");
    let mut changed = original.clone();
    changed[1] = changed[0].clone();
    fixture.reseal_json("results.json", &changed);
    assert!(verify(&fixture.workspace).is_err());
    let mut changed = original;
    changed[0]["usage"]["units"] = Value::from(0);
    fixture.reseal_json("results.json", &changed);
    assert!(verify(&fixture.workspace).is_err());
}

#[test]
fn rehashed_trace_truncation_or_fabricated_versions_cannot_claim_observed_provenance() {
    let fixture = Fixture::new(false);
    fixture.publish();
    let original = fixture.json("versions.json");
    let mut versions = original.clone();
    versions["observed"]["lockfile_sha256"] =
        serde_json::to_value(Digest::of(b"foreign lock")).unwrap();
    fixture.reseal_json("versions.json", &versions);
    assert!(verify(&fixture.workspace).is_err());
    fixture.reseal_json("versions.json", &original);
    let trace = fs::read(fixture.path("trace.jsonl")).unwrap();
    let first_line = trace.iter().position(|byte| *byte == b'\n').unwrap() + 1;
    fixture.reseal_bytes("trace.jsonl", &trace[..first_line]);
    let before = durable_snapshot(fixture.workspace.path());
    assert!(verify(&fixture.workspace).is_err());
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn review_file_is_not_an_implicit_approval_mechanism() {
    let fixture = Fixture::new(false);
    fixture.publish();
    fixture
        .workspace
        .write_new(Path::new("review.json"), br#"{"status":"approved"}"#)
        .unwrap();
    let before = durable_snapshot(fixture.workspace.path());
    assert!(verify(&fixture.workspace).is_err());
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn exact_owned_review_is_live_while_technical_exit_and_manifest_stay_immutable() {
    let fixture = Fixture::new(false);
    fixture.publish();
    let manifest = fs::read(fixture.path("manifest.json")).unwrap();
    let exit = fs::read(fixture.path("exit.json")).unwrap();
    let mut references = vec![serde_json::json!({"kind":"run_manifest",
        "run_id":fixture.workspace.run_id(),"sha256":Digest::of(&manifest)})];
    for result in &fixture.outcome.results {
        if let Some(reference) = result.evidence_refs.first() {
            references.push(serde_json::json!({"kind":"evidence","reference":reference}));
        }
    }
    let decision = serde_json::json!({"decision_id":"EXIT-REVIEW","subject":"Packet behavior policy test",
        "decision":"Approve exactly these immutable test bytes","rationale":"Controlled policy test, not operational R0 approval",
        "alternatives":["Reject"],"evidence_refs":references,"status":"approved",
        "reviewer":"packet-policy-test-owner","reviewed_at":AuditTime::now()});
    fixture
        .workspace
        .write_new(
            Path::new("review.json"),
            &serde_json::to_vec(&decision).unwrap(),
        )
        .unwrap();
    let before = durable_snapshot(fixture.workspace.path());
    let verdict = verify(&fixture.workspace).unwrap();
    assert_eq!(verdict.review_status, ReviewStatus::Approved);
    assert_eq!(verdict.full_status, CommandStatus::Incomplete);
    assert!(!verdict.r0_exit_ready);
    assert_eq!(fs::read(fixture.path("manifest.json")).unwrap(), manifest);
    assert_eq!(fs::read(fixture.path("exit.json")).unwrap(), exit);
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
    assert!(
        !fixture.json("manifest.json")["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["path"] == "review.json")
    );
    let mut tampered = decision.clone();
    tampered["evidence_refs"][1]["reference"]["sha256"] =
        serde_json::json!(Digest::of(b"foreign evidence bytes"));
    fs::write(
        fixture.path("review.json"),
        serde_json::to_vec(&tampered).unwrap(),
    )
    .unwrap();
    let stale = verify(&fixture.workspace).unwrap();
    assert_eq!(stale.review_status, ReviewStatus::Unreviewed);
    assert!(!stale.r0_exit_ready);
    assert_eq!(fs::read(fixture.path("manifest.json")).unwrap(), manifest);
    assert_eq!(fs::read(fixture.path("exit.json")).unwrap(), exit);
}

#[test]
fn publication_rejects_changed_raw_scenario_identity_instead_of_repinning_it() {
    let fixture = Fixture::new(false);
    let mut source = fs::read(fixture.path("fixture-manifest.json")).unwrap();
    source.push(b'\n');
    fs::write(fixture.path("fixture-manifest.json"), source).unwrap();
    let before = durable_snapshot(fixture.workspace.path());
    assert!(
        publish(
            &fixture.workspace,
            &fixture.bootstrap,
            &fixture.selection,
            &fixture.outcome
        )
        .is_err()
    );
    assert!(!fixture.path("manifest.json").exists());
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn deeply_nested_proof_data_exceeds_finite_traversal_bound_without_partial_publication() {
    let fixture = Fixture::new(false);
    let relative = format!("{}body.bin", "nested/".repeat(33));
    fixture
        .workspace
        .write_new(Path::new(&relative), b"bounded")
        .unwrap();
    let before = durable_snapshot(fixture.workspace.path());
    let error = publish(
        &fixture.workspace,
        &fixture.bootstrap,
        &fixture.selection,
        &fixture.outcome,
    )
    .unwrap_err();
    assert_eq!(
        error.code,
        razen_engine::protocol::error::ErrorCode::BudgetExhausted
    );
    assert!(!fixture.path("manifest.json").exists());
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn rehashed_observations_cannot_contradict_the_actual_immutable_case_report() {
    let fixture = Fixture::new(false);
    fixture.publish();
    let profile = razen_engine::application::profile::LoadedProfile::from_bytes(
        &fs::read(fixture.path("profile.json")).unwrap(),
    )
    .unwrap();
    let ledger =
        razen_engine::adapters::ledger::Ledger::open_readonly(&fixture.workspace, &profile)
            .unwrap();
    let invocation = ledger
        .invocations()
        .unwrap()
        .into_iter()
        .find(|stored| stored.invocation.tool_id.as_str() == "proof.case.execute")
        .unwrap()
        .invocation;
    drop(ledger);
    let mut changed = fixture.json("results.json");
    changed[0]["status"] = Value::from("failed");
    changed[0]["observed"]["round_trip"] = Value::from(false);
    changed[0]["error"] = serde_json::to_value(
        razen_engine::protocol::error::ProofError::new(
            razen_engine::protocol::error::ErrorCode::OutputInvalid,
            "Forged contradictory observation",
        )
        .with_invocation(invocation.invocation_id),
    )
    .unwrap();
    fixture.reseal_json("results.json", &changed);
    let before = durable_snapshot(fixture.workspace.path());
    assert!(verify(&fixture.workspace).is_err());
    assert_eq!(durable_snapshot(fixture.workspace.path()), before);
}

#[test]
fn full_run_sized_packet_retains_every_seal_and_rejects_changed_late_history() {
    let fixture = Fixture::new(false);
    const BODY: &[u8] = b"retained proof history";
    for index in 0..8_193 {
        fixture
            .workspace
            .write_new(Path::new(&format!("retained-{index:05}.bin")), BODY)
            .unwrap();
    }
    fixture.publish();
    let manifest = fixture.json("manifest.json");
    let expected_sha256 = serde_json::to_value(Digest::of(BODY)).unwrap();
    let mut retained_files = 0;
    for entry in manifest["files"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["path"].as_str().unwrap().starts_with("retained-"))
    {
        assert_eq!(
            entry["path"],
            Value::from(format!("retained-{retained_files:05}.bin"))
        );
        assert_eq!(entry["sha256"], expected_sha256);
        assert_eq!(entry["length_bytes"], Value::from(BODY.len()));
        retained_files += 1;
    }
    assert_eq!(retained_files, 8_193);
    let verdict = verify(&fixture.workspace).unwrap();
    assert_eq!(verdict.counts.passed.get(), 1);
    assert_eq!(verdict.full_status, CommandStatus::Incomplete);
    assert!(!verdict.r0_exit_ready);
    fs::write(fixture.path("retained-08192.bin"), b"changed history").unwrap();
    assert_eq!(
        verify(&fixture.workspace).unwrap_err().code,
        razen_engine::protocol::error::ErrorCode::IntegrityError
    );
}
