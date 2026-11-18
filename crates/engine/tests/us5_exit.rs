use razen_engine::{
    application::{
        harness::{CommandStatus, ReviewStatus},
        inventory,
        review::{self, ReviewContext},
    },
    domain::{
        decisions::DecisionRecord,
        evidence::EvidenceRef,
        proofs::CaseStatus,
        values::{AuditTime, Digest, EntityId},
    },
};
use serde_json::json;
#[path = "support/exit_fixtures.rs"]
mod fixture;
#[path = "support/private_root.rs"]
mod private_root;
fn now() -> AuditTime {
    AuditTime::parse("2026-11-16T12:03:00Z").unwrap()
}
#[test]
fn complete_controlled_record_gate_is_not_approval_and_partial_selection_is_not_full_pass() {
    let run = fixture::run();
    let profile = fixture::profile();
    let mut selection = fixture::selection();
    let mut results = fixture::results(&run);
    let gate = inventory::evaluate(&selection, &run, &results, &profile).unwrap();
    assert_eq!(gate.counts.total.get(), 35);
    assert_eq!(gate.full_status, CommandStatus::Passed);
    let digest = Digest::of(b"actual immutable manifest bytes");
    let required: Vec<EvidenceRef> = vec![serde_json::from_value(fixture::evidence()).unwrap()];
    let context = ReviewContext {
        run: &run,
        manifest_sha256: digest,
        profile: &profile,
        gate: &gate,
        required_evidence: &required,
        now: now(),
    };
    let assessment = review::assess(&context, None).unwrap();
    assert_eq!(assessment.review_status, ReviewStatus::Unreviewed);
    assert!(!assessment.r0_exit_ready);
    selection
        .selected_case_ids
        .retain(|id| id.as_str().starts_with("CON-"));
    for result in &mut results {
        if !result.case_id.as_str().starts_with("CON-") {
            result.status = CaseStatus::Unexecuted;
            result.observed = serde_json::from_value(json!({})).unwrap();
            result.evidence_refs.clear();
        }
    }
    let partial = inventory::evaluate(&selection, &run, &results, &profile).unwrap();
    assert_eq!(partial.selected_status, CommandStatus::Passed);
    assert_eq!(partial.full_status, CommandStatus::Incomplete);
    assert_eq!(partial.counts.unexecuted.get(), 30);
}
#[test]
fn exact_review_cannot_override_failed_partial_or_unprepared_run() {
    let mut run = fixture::run();
    let profile = fixture::profile();
    let selection = fixture::selection();
    let mut results = fixture::results(&run);
    let digest = Digest::of(b"immutable manifest");
    let decision: DecisionRecord = serde_json::from_value(fixture::decision(&run, digest)).unwrap();
    let required = vec![serde_json::from_value(fixture::evidence()).unwrap()];
    for status in [
        CaseStatus::Passed,
        CaseStatus::Failed,
        CaseStatus::Blocked,
        CaseStatus::Unexecuted,
    ] {
        results[7].status = status;
        let gate = inventory::evaluate(&selection, &run, &results, &profile).unwrap();
        let context = ReviewContext {
            run: &run,
            manifest_sha256: digest,
            profile: &profile,
            gate: &gate,
            required_evidence: &required,
            now: now(),
        };
        let actual = review::assess(&context, Some(&decision)).unwrap();
        assert_eq!(actual.r0_exit_ready, status == CaseStatus::Passed);
    }
    results[7].status = CaseStatus::Passed;
    run.environment.isolation_status = razen_engine::domain::proofs::IsolationStatus::NotRequired;
    run.environment.guest_package_manifest_sha256 = None;
    run.environment.provisioning_sha256 = None;
    run.environment.effective_config_sha256 = None;
    run.environment.seccomp_sha256 = None;
    let gate = inventory::evaluate(&selection, &run, &results, &profile).unwrap();
    let context = ReviewContext {
        run: &run,
        manifest_sha256: digest,
        profile: &profile,
        gate: &gate,
        required_evidence: &required,
        now: now(),
    };
    assert!(
        !review::assess(&context, Some(&decision))
            .unwrap()
            .r0_exit_ready
    );
}
#[test]
fn wrong_manifest_wrong_run_missing_refs_pending_stale_and_rejection_never_authorize() {
    let run = fixture::run();
    let profile = fixture::profile();
    let selection = fixture::selection();
    let results = fixture::results(&run);
    let gate = inventory::evaluate(&selection, &run, &results, &profile).unwrap();
    let digest = Digest::of(b"immutable manifest");
    let required = vec![serde_json::from_value(fixture::evidence()).unwrap()];
    let context = ReviewContext {
        run: &run,
        manifest_sha256: digest,
        profile: &profile,
        gate: &gate,
        required_evidence: &required,
        now: now(),
    };
    for kind in [
        "manifest", "run", "refs", "pending", "blocked", "time", "future", "rejected",
    ] {
        let mut value = fixture::decision(&run, digest);
        match kind {
            "manifest" => value["evidence_refs"][0]["sha256"] = json!(Digest::of(b"other")),
            "run" => value["evidence_refs"][0]["run_id"] = json!(EntityId::new()),
            "refs" => {
                value["evidence_refs"].as_array_mut().unwrap().pop();
            }
            "time" => value["reviewed_at"] = json!("2026-11-16T12:00:30Z"),
            "future" => value["reviewed_at"] = json!("2026-11-17T12:00:00Z"),
            other => value["status"] = json!(other),
        };
        let decision: DecisionRecord = serde_json::from_value(value).unwrap();
        let assessment = review::assess(&context, Some(&decision)).unwrap();
        assert!(!assessment.r0_exit_ready, "authorized {kind}");
        assert_eq!(
            assessment.review_status,
            if kind == "rejected" {
                ReviewStatus::Rejected
            } else {
                ReviewStatus::Unreviewed
            }
        );
    }
}
#[test]
fn inventory_rejects_mixed_runs_profiles_duplicate_cases_and_unsupported_happy_path() {
    let mut run = fixture::run();
    let profile = fixture::profile();
    let selection = fixture::selection();
    let mut results = fixture::results(&run);
    results[1].run_id = EntityId::new();
    assert!(inventory::evaluate(&selection, &run, &results, &profile).is_err());
    results[1].run_id = run.run_id;
    results[1].case_id = results[0].case_id.clone();
    assert!(inventory::evaluate(&selection, &run, &results, &profile).is_err());
    results = fixture::results(&run);
    results[8].observed=serde_json::from_value(json!({"forwarded":false,"h2_both_legs":false,"concurrent_streams":false,"body_exact":false})).unwrap();
    assert!(inventory::evaluate(&selection, &run, &results, &profile).is_err());
    results = fixture::results(&run);
    run.profile_sha256 = Digest::of(b"changed profile");
    assert!(inventory::evaluate(&selection, &run, &results, &profile).is_err());
}
#[test]
fn package_order_borrows_dependencies_before_dependents_even_when_manifest_reversed() {
    let selection = fixture::selection();
    let value = serde_json::to_value(selection.inventory).unwrap();
    let mut packages: Vec<razen_engine::domain::proofs::WorkPackage> =
        serde_json::from_value(value["packages"].clone()).unwrap();
    packages.reverse();
    let cases = serde_json::from_value(value["cases"].clone()).unwrap();
    let inventory = razen_engine::domain::proofs::ProofInventory::new(packages, cases).unwrap();
    let ordered = inventory::topological_packages(&inventory).unwrap();
    let ids: Vec<_> = ordered.iter().map(|p| p.package_id.as_str()).collect();
    assert_eq!(ids, vec!["R0-01", "R0-02", "R0-03", "R0-04", "R0-05"]);
    for package in ordered {
        assert!(
            inventory
                .packages()
                .iter()
                .any(|original| std::ptr::eq(original, package))
        );
    }
}
#[test]
fn review_reader_is_readonly_and_rejects_symlinks_world_readable_or_malformed_decisions() {
    use razen_engine::adapters::workspace::OwnedDirectory;
    use std::{
        os::unix::fs::{PermissionsExt, symlink},
        path::Path,
    };
    let root = private_root::PrivateRoot::new();
    let run = fixture::run();
    let workspace = OwnedDirectory::create(root.path(), Path::new("run"), run.run_id).unwrap();
    let profile = fixture::profile();
    let selection = fixture::selection();
    let results = fixture::results(&run);
    let gate = inventory::evaluate(&selection, &run, &results, &profile).unwrap();
    let digest = Digest::of(b"immutable manifest");
    let required = vec![serde_json::from_value(fixture::evidence()).unwrap()];
    let context = ReviewContext {
        run: &run,
        manifest_sha256: digest,
        profile: &profile,
        gate: &gate,
        required_evidence: &required,
        now: now(),
    };
    assert_eq!(
        review::read_and_assess(&workspace, &context)
            .unwrap()
            .review_status,
        ReviewStatus::Unreviewed
    );
    let bytes = serde_json::to_vec(&fixture::decision(&run, digest)).unwrap();
    workspace
        .write_new(Path::new("review.json"), &bytes)
        .unwrap();
    let before = std::fs::metadata(workspace.path().join("review.json")).unwrap();
    assert!(
        review::read_and_assess(&workspace, &context)
            .unwrap()
            .r0_exit_ready
    );
    assert_eq!(
        workspace.read(Path::new("review.json"), 65536).unwrap(),
        bytes
    );
    assert_eq!(
        std::fs::metadata(workspace.path().join("review.json"))
            .unwrap()
            .modified()
            .unwrap(),
        before.modified().unwrap()
    );
    std::fs::set_permissions(
        workspace.path().join("review.json"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    assert!(review::read_and_assess(&workspace, &context).is_err());
    std::fs::remove_file(workspace.path().join("review.json")).unwrap();
    let outside = root.path().join("outside.json");
    std::fs::write(&outside, &bytes).unwrap();
    symlink(&outside, workspace.path().join("review.json")).unwrap();
    assert!(review::read_and_assess(&workspace, &context).is_err());
    std::fs::remove_file(workspace.path().join("review.json")).unwrap();
    workspace
        .write_new(
            Path::new("review.json"),
            br#"{"status":"approved","reviewer":"invented"}"#,
        )
        .unwrap();
    assert!(review::read_and_assess(&workspace, &context).is_err());
}
#[test]
fn controlled_exit_driver_rejects_changed_manifest_and_fabricated_happy_path_records() {
    use razen_engine::application::suites::exit::{
        controlled_fixture, evaluate_controlled_fixture,
    };
    use razen_engine::domain::proofs::CheckName;
    let run = fixture::run();
    let profile = fixture::profile();
    let mut controlled = controlled_fixture(&run, fixture::selection(), &profile).unwrap();
    let facts = evaluate_controlled_fixture(&controlled, &profile).unwrap();
    for name in [
        CheckName::CompleteInventory,
        CheckName::PacketIntegrity,
        CheckName::FailureBlocksExit,
        CheckName::ApprovalRequired,
        CheckName::R0Only,
    ] {
        assert_eq!(facts.get(name), Some(true));
    }
    controlled.manifest_sha256 = Digest::of(b"changed manifest");
    assert!(evaluate_controlled_fixture(&controlled, &profile).is_err());
    let mut controlled = controlled_fixture(&run, fixture::selection(), &profile).unwrap();
    let index = controlled
        .results
        .iter()
        .position(|result| result.case_id.as_str() == "NET-04")
        .unwrap();
    controlled.results[index].observed=serde_json::from_value(json!({"forwarded":false,"h2_both_legs":false,"concurrent_streams":false,"body_exact":false})).unwrap();
    assert!(evaluate_controlled_fixture(&controlled, &profile).is_err());
    let mut controlled = controlled_fixture(&run, fixture::selection(), &profile).unwrap();
    controlled.artifact_bytes.push(0);
    assert!(evaluate_controlled_fixture(&controlled, &profile).is_err());
}
#[test]
fn controlled_exit_integrity_checks_handle_zero_length_artifacts() {
    use razen_engine::application::suites::exit::{
        controlled_fixture, evaluate_controlled_fixture,
    };
    use razen_engine::domain::{
        decisions::DecisionEvidence, evidence::EvidenceRef, proofs::CheckName, values::WireInt,
    };

    let run = fixture::run();
    let profile = fixture::profile();
    let mut controlled = controlled_fixture(&run, fixture::selection(), &profile).unwrap();
    controlled.artifact_bytes.clear();
    controlled.artifact.sha256 = Digest::of(b"");
    controlled.artifact.length_bytes = WireInt::ZERO;
    let reference = EvidenceRef::Artifact {
        artifact_id: controlled.artifact.artifact_id,
        sha256: controlled.artifact.sha256,
        range: None,
    };
    for result in &mut controlled.results {
        result.evidence_refs.fill(reference);
    }
    let mut manifest: serde_json::Value =
        serde_json::from_slice(&controlled.manifest_bytes).unwrap();
    manifest["results_sha256"] = json!(Digest::of(
        &serde_json::to_vec(&controlled.results).unwrap()
    ));
    controlled.manifest_bytes.clear();
    serde_json::to_writer(&mut controlled.manifest_bytes, &manifest).unwrap();
    controlled.manifest_sha256 = Digest::of(&controlled.manifest_bytes);
    for evidence in &mut controlled.review.evidence_refs {
        match evidence {
            DecisionEvidence::RunManifest { sha256, .. } => {
                *sha256 = controlled.manifest_sha256;
            }
            DecisionEvidence::Evidence {
                reference: reviewed,
            } => {
                *reviewed = reference;
            }
            DecisionEvidence::DependencySelection { .. } => {
                panic!("controlled gate fixture unexpectedly contains a dependency selection");
            }
        }
    }
    let observed = evaluate_controlled_fixture(&controlled, &profile).unwrap();
    for name in [
        CheckName::CompleteInventory,
        CheckName::PacketIntegrity,
        CheckName::FailureBlocksExit,
        CheckName::ApprovalRequired,
        CheckName::R0Only,
    ] {
        assert_eq!(observed.get(name), Some(true));
    }
}
#[test]
fn inventory_rejects_measured_version_and_backend_mismatches_even_with_matching_profile_hash() {
    let mut run = fixture::run();
    let profile = fixture::profile();
    let selection = fixture::selection();
    let results = fixture::results(&run);
    run.environment.dependency_versions.insert(
        razen_engine::domain::values::CatalogId::parse("rust").unwrap(),
        razen_engine::domain::proofs::VersionPin::parse("1.93.1").unwrap(),
    );
    assert!(inventory::evaluate(&selection, &run, &results, &profile).is_err());
    let mut run = fixture::run();
    let results = fixture::results(&run);
    run.environment.backend = "unprepared-native-backend".into();
    assert!(inventory::evaluate(&selection, &run, &results, &profile).is_err());
}

#[test]
fn cancellation_only_case_is_incomplete_but_real_failure_keeps_precedence() {
    use razen_engine::protocol::error::{ErrorCode, ProofError};
    let run = fixture::run();
    let profile = fixture::profile();
    let selection = fixture::selection();
    let mut results = fixture::results(&run);
    results[0].status = CaseStatus::Failed;
    results[0].error = Some(ProofError::new(
        ErrorCode::Cancelled,
        "Controlled cancellation policy input",
    ));
    let gate = inventory::evaluate(&selection, &run, &results, &profile).unwrap();
    assert_eq!(gate.full_status, CommandStatus::Incomplete);
    assert_eq!(gate.selected_status, CommandStatus::Incomplete);
    results[1].status = CaseStatus::Failed;
    results[1].error = Some(ProofError::new(
        ErrorCode::IntegrityError,
        "Controlled genuine proof failure",
    ));
    let gate = inventory::evaluate(&selection, &run, &results, &profile).unwrap();
    assert_eq!(gate.full_status, CommandStatus::Failed);
    assert_eq!(gate.selected_status, CommandStatus::Failed);
    assert!(
        gate.package_statuses
            .iter()
            .all(|status| *status == razen_engine::domain::proofs::PackageStatus::Failed)
    );
}

#[test]
fn extra_foreign_evidence_cannot_extend_exit_approval() {
    let run = fixture::run();
    let profile = fixture::profile();
    let selection = fixture::selection();
    let results = fixture::results(&run);
    let gate = inventory::evaluate(&selection, &run, &results, &profile).unwrap();
    let digest = Digest::of(b"immutable manifest");
    let required = vec![serde_json::from_value(fixture::evidence()).unwrap()];
    let context = ReviewContext {
        run: &run,
        manifest_sha256: digest,
        profile: &profile,
        gate: &gate,
        required_evidence: &required,
        now: now(),
    };
    let mut value = fixture::decision(&run, digest);
    let mut foreign = fixture::evidence();
    foreign["artifact_id"] = json!(EntityId::new());
    value["evidence_refs"]
        .as_array_mut()
        .unwrap()
        .push(json!({"kind":"evidence","reference":foreign}));
    let decision: DecisionRecord = serde_json::from_value(value).unwrap();
    assert!(
        !review::assess(&context, Some(&decision))
            .unwrap()
            .r0_exit_ready
    );
}

#[test]
fn review_reader_rejects_hardlinks_oversized_and_unknown_fields() {
    use razen_engine::adapters::workspace::OwnedDirectory;
    use std::path::Path;
    let root = private_root::PrivateRoot::new();
    let run = fixture::run();
    let workspace = OwnedDirectory::create(root.path(), Path::new("run"), run.run_id).unwrap();
    let profile = fixture::profile();
    let selection = fixture::selection();
    let results = fixture::results(&run);
    let gate = inventory::evaluate(&selection, &run, &results, &profile).unwrap();
    let digest = Digest::of(b"immutable manifest");
    let required = vec![serde_json::from_value(fixture::evidence()).unwrap()];
    let context = ReviewContext {
        run: &run,
        manifest_sha256: digest,
        profile: &profile,
        gate: &gate,
        required_evidence: &required,
        now: now(),
    };
    let path = workspace.path().join("review.json");
    let mut value = fixture::decision(&run, digest);
    value["unknown"] = json!(true);
    workspace
        .write_new(
            Path::new("review.json"),
            &serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    assert!(review::read_and_assess(&workspace, &context).is_err());
    std::fs::remove_file(&path).unwrap();
    workspace
        .write_new(Path::new("review.json"), &vec![b' '; 256 * 1024 + 1])
        .unwrap();
    assert!(review::read_and_assess(&workspace, &context).is_err());
    std::fs::remove_file(&path).unwrap();
    workspace
        .write_new(
            Path::new("review.json"),
            &serde_json::to_vec(&fixture::decision(&run, digest)).unwrap(),
        )
        .unwrap();
    std::fs::hard_link(&path, root.path().join("review-alias.json")).unwrap();
    assert!(review::read_and_assess(&workspace, &context).is_err());
}

#[test]
fn frozen_backend_maps_reject_missing_substituted_and_extra_observer_keys() {
    // CONTROLLEDGATEFIXTURE: deterministic observer-shape policy, not measured native inputs.
    use razen_engine::{
        adapters::components::supervisor::{VARIANTS, WASMTIME_VERSION, WIT_BINDGEN_VERSION},
        application::{cli::Suite, harness::ScenarioManifest},
        domain::{
            proofs::{IsolationStatus, VersionPin},
            values::CatalogId,
        },
    };
    use std::collections::BTreeMap;
    let profile = fixture::profile();
    let bytes = include_bytes!("../../../fixtures/scenarios/manifest.json");
    let digest = Digest::of(b"CONTROLLEDGATEFIXTURE frozen observer shape");
    for id in ["CON-01", "NET-01", "CMP-01", "RUN-01", "REC-01", "EXIT-01"] {
        let selection = serde_json::from_slice::<ScenarioManifest>(bytes)
            .unwrap()
            .select(
                Suite::All,
                Some(&CatalogId::parse(id).unwrap()),
                Digest::of(bytes),
            )
            .unwrap();
        let has = |prefix: &str| {
            selection
                .selected_case_ids
                .iter()
                .any(|case| case.as_str().starts_with(prefix))
        };
        let mut run = fixture::run();
        let observed = &mut run.environment;
        observed.fixture_digests = BTreeMap::new();
        observed.binary_digests = BTreeMap::new();
        observed.dependency_versions = BTreeMap::new();
        for key in [
            "scenario-manifest",
            "contract-scenarios",
            "approved-fixtures",
            "parser-corpus-manifest",
            "pilot-profile",
        ] {
            observed
                .fixture_digests
                .insert(CatalogId::parse(key).unwrap(), digest);
        }
        for key in ["razen-proof", "razen-engine"] {
            observed
                .binary_digests
                .insert(CatalogId::parse(key).unwrap(), digest);
        }
        observed.dependency_versions.insert(
            CatalogId::parse("rust").unwrap(),
            VersionPin::parse(&profile.config().toolchain.rust).unwrap(),
        );
        if has("CMP-") {
            for key in ["components", "component-build-manifest"]
                .into_iter()
                .chain(VARIANTS.iter().copied())
            {
                observed
                    .fixture_digests
                    .insert(CatalogId::parse(key).unwrap(), digest);
            }
            observed
                .binary_digests
                .insert(CatalogId::parse("razen-component-runner").unwrap(), digest);
            for (key, pin) in [
                ("wasmtime", WASMTIME_VERSION),
                ("wit-bindgen", WIT_BINDGEN_VERSION),
            ] {
                observed.dependency_versions.insert(
                    CatalogId::parse(key).unwrap(),
                    VersionPin::parse(pin).unwrap(),
                );
            }
        }
        if has("NET-") {
            observed
                .fixture_digests
                .insert(CatalogId::parse("transport-scenarios").unwrap(), digest);
        }
        if has("NET-") || has("EXIT-") {
            observed.dependency_versions.insert(
                CatalogId::parse("rama").unwrap(),
                VersionPin::parse("0.4.0").unwrap(),
            );
        }
        if has("REC-") {
            observed
                .fixture_digests
                .insert(CatalogId::parse("recovery-scenarios").unwrap(), digest);
            observed
                .binary_digests
                .insert(CatalogId::parse("razen-fixture-receiver").unwrap(), digest);
        }
        if has("RUN-") || has("EXIT-") {
            observed.isolation_status = IsolationStatus::Prepared;
            for key in ["guest-source", "runtime"] {
                observed
                    .fixture_digests
                    .insert(CatalogId::parse(key).unwrap(), digest);
            }
            for key in ["guest-supervisor", "guest-adversary", "bubblewrap"] {
                observed
                    .binary_digests
                    .insert(CatalogId::parse(key).unwrap(), digest);
            }
            for (key, pin) in [
                (
                    "lima",
                    profile.config().external_runner.lima_version.as_str(),
                ),
                (
                    "bubblewrap",
                    profile.config().external_runner.bubblewrap_version.as_str(),
                ),
            ] {
                observed.dependency_versions.insert(
                    CatalogId::parse(key).unwrap(),
                    VersionPin::parse(pin).unwrap(),
                );
            }
        } else {
            observed.isolation_status = IsolationStatus::NotRequired;
            observed.guest_package_manifest_sha256 = None;
            observed.provisioning_sha256 = None;
            observed.effective_config_sha256 = None;
            observed.seccomp_sha256 = None;
        }
        inventory::validate_selected_environment(&selection, &run, &profile).unwrap();
        if has("NET-") || has("EXIT-") {
            let mut changed = run.clone();
            changed
                .environment
                .dependency_versions
                .remove(&CatalogId::parse("rama").unwrap());
            assert!(
                inventory::validate_selected_environment(&selection, &changed, &profile).is_err(),
                "{id}: missing Rama observation"
            );
            changed.environment.dependency_versions.insert(
                CatalogId::parse("rama").unwrap(),
                VersionPin::parse("0.4.1").unwrap(),
            );
            assert!(
                inventory::validate_selected_environment(&selection, &changed, &profile).is_err(),
                "{id}: wrong Rama pin"
            );
        }
        let mut changed = run.clone();
        changed
            .environment
            .fixture_digests
            .remove(&CatalogId::parse("approved-fixtures").unwrap());
        assert!(
            inventory::validate_selected_environment(&selection, &changed, &profile).is_err(),
            "{id}: missing"
        );
        changed
            .environment
            .fixture_digests
            .insert(CatalogId::parse("unreviewed-substitute").unwrap(), digest);
        assert!(
            inventory::validate_selected_environment(&selection, &changed, &profile).is_err(),
            "{id}: same-cardinality substitution"
        );
        let mut changed = run.clone();
        changed
            .environment
            .binary_digests
            .insert(CatalogId::parse("unreviewed-binary").unwrap(), digest);
        assert!(
            inventory::validate_selected_environment(&selection, &changed, &profile).is_err(),
            "{id}: extra binary"
        );
        let mut changed = run.clone();
        changed.environment.dependency_versions.insert(
            CatalogId::parse("unreviewed-version").unwrap(),
            VersionPin::parse("1.0.0").unwrap(),
        );
        assert!(
            inventory::validate_selected_environment(&selection, &changed, &profile).is_err(),
            "{id}: extra version"
        );
    }
}
