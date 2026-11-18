use razen_engine::domain::evidence::EvidenceRef;
use razen_engine::domain::proofs::{
    CheckName, IsolationStatus, PackageStatus, ProofCase, ProofInventory, ProofResult, Run,
    WorkPackage,
};
use razen_engine::domain::values::CatalogId;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

const MANIFEST: &str = include_str!("../../../fixtures/scenarios/manifest.json");
const RUN_ID: &str = "10000000-0000-4000-8000-000000000001";
const OTHER_RUN_ID: &str = "10000000-0000-4000-8000-000000000002";
const ARTIFACT_ID: &str = "10000000-0000-4000-8000-000000000003";
const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_DIGEST: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn manifest() -> Value {
    serde_json::from_str(MANIFEST).unwrap()
}

fn decode<T: DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}

fn rejects<T: DeserializeOwned>(value: Value) {
    assert!(
        serde_json::from_value::<T>(value.clone()).is_err(),
        "accepted {value}"
    );
}

fn case_value(case_id: &str) -> Value {
    manifest()["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|case| case["case_id"] == case_id)
        .unwrap()
        .clone()
}

fn inventory_from(value: Value) -> Result<ProofInventory, Box<dyn std::error::Error>> {
    let packages = serde_json::from_value(value["packages"].clone())?;
    let cases = serde_json::from_value(value["cases"].clone())?;
    Ok(ProofInventory::new(packages, cases)?)
}

fn inventory() -> ProofInventory {
    inventory_from(manifest()).unwrap()
}

// Synthetic record inputs only: these tests validate records, not fixture execution,
// evidence resolution, packet integrity, reviewer approval, or actual R0 readiness.
fn run_value() -> Value {
    json!({
        "run_id": RUN_ID,
        "contract_version": "0.1.0",
        "profile_id": "macos-arm64-proof",
        "profile_sha256": DIGEST,
        "clock_epoch_id": "10000000-0000-4000-8000-000000000004",
        "started_at": "2026-11-16T12:00:00Z",
        "environment": {
            "hardware_model": "synthetic-arm64-fixture",
            "logical_cpus": 8,
            "memory_mib": 16384,
            "os": "macOS",
            "os_version": "26.5.1",
            "arch": "arm64",
            "os_build": "synthetic-build",
            "kernel": "synthetic-kernel",
            "filesystem": "APFS",
            "storage": "synthetic-local-storage",
            "component_target": "wasm32-wasip2",
            "backend": "lima-vz-plain-bubblewrap-cgroup-v2",
            "isolation_status": "prepared",
            "guest_os": "Debian 13.7 arm64",
            "image_digest": format!("sha512:{}", "c".repeat(128)),
            "dependency_versions": {
                "rust": "1.100.0", "lima": "2.3.0", "bubblewrap": "0.13.1"
            },
            "fixture_digests": { "contracts": DIGEST, "transport": DIGEST },
            "binary_digests": { "engine": DIGEST, "supervisor": DIGEST },
            "lockfile_sha256": DIGEST,
            "component_lockfile_sha256": DIGEST,
            "guest_package_manifest_sha256": DIGEST,
            "provisioning_sha256": DIGEST,
            "effective_config_sha256": DIGEST,
            "seccomp_sha256": DIGEST,
            "wit_sha256": DIGEST
        },
        "dependency_record_refs": ["10000000-0000-4000-8000-000000000005"],
        "fixture_manifest_sha256": DIGEST
    })
}

fn run() -> Run {
    decode(run_value())
}

fn result_value(case_id: &str, status: &str, observed: Value) -> Value {
    json!({
        "run_id": RUN_ID,
        "case_id": case_id,
        "status": status,
        "expected": case_value(case_id)["expected"],
        "observed": observed,
        "evidence_refs": [{ "artifact_id": ARTIFACT_ID, "sha256": DIGEST }],
        "elapsed_us": 17,
        "usage": { "units": 1, "bytes": 32, "cpu_us": 3, "elapsed_us": 17 }
    })
}

fn matching_record(case_id: &str) -> ProofResult {
    decode(result_value(
        case_id,
        "passed",
        case_value(case_id)["expected"].clone(),
    ))
}

fn package_status(results: &[ProofResult], package: &str) -> PackageStatus {
    inventory()
        .package_status(&run(), results, &CatalogId::parse(package).unwrap())
        .unwrap()
}

#[test]
fn canonical_inventory_preserves_every_record_field() {
    let source = manifest();
    let packages: Vec<WorkPackage> = decode(source["packages"].clone());
    let cases: Vec<ProofCase> = decode(source["cases"].clone());
    assert_eq!(serde_json::to_value(&packages).unwrap(), source["packages"]);
    assert_eq!(serde_json::to_value(&cases).unwrap(), source["cases"]);
    ProofInventory::new(packages, cases).unwrap();
}

#[test]
fn fixed_catalog_checks_exact_case_package_requirements_success_and_assertions() {
    // An independent oracle, not a comparison of the manifest to itself.
    let expected = [
        (
            "CON-01",
            "R0-01",
            "FR-002,FR-017",
            "SC-001",
            "round_trip,stable_references,evidence_variants",
        ),
        (
            "CON-02",
            "R0-01",
            "FR-002,FR-004",
            "SC-001,SC-002",
            "invalid_rejected,framing_fuzz,typed_fuzz,complete_budget,replayable",
        ),
        (
            "CON-03",
            "R0-01",
            "FR-002,FR-004",
            "SC-002",
            "stale_rejected,foreign_rejected,original_unchanged",
        ),
        (
            "CON-04",
            "R0-01",
            "FR-004,FR-017",
            "SC-002",
            "consumer_equivalence,revocation_enforced,child_scope_bounded,aggregate_quota",
        ),
        (
            "CON-05",
            "R0-01",
            "FR-003",
            "SC-001,SC-002",
            "graphs_distinct,ownership_filtered,two_memory_levels,promotion_bounded",
        ),
        (
            "NET-01",
            "R0-02",
            "FR-005,FR-017",
            "SC-003",
            "forwarded,headers_preserved,body_exact,capture_referenced",
        ),
        (
            "NET-02",
            "R0-02",
            "FR-005,FR-006",
            "SC-003",
            "forwarded,body_exact,opaque_tunnel",
        ),
        (
            "NET-03",
            "R0-02",
            "FR-005,FR-006",
            "SC-002,SC-003",
            "forwarded,upstream_verified,isolated_trust,trust_unchanged",
        ),
        (
            "NET-04",
            "R0-02",
            "FR-005",
            "SC-003",
            "forwarded,h2_both_legs,concurrent_streams,body_exact",
        ),
        (
            "NET-05",
            "R0-02",
            "FR-004,FR-005",
            "SC-002,SC-003",
            "scope_rechecked,pivots_denied,healthy_observer,zero_forbidden_arrivals",
        ),
        (
            "NET-06",
            "R0-02",
            "FR-005,FR-006,FR-017",
            "SC-002,SC-003",
            "invalid_tls_rejected,authorities_match,trust_unchanged,secrets_absent",
        ),
        (
            "NET-07",
            "R0-02",
            "FR-005,FR-018",
            "SC-003",
            "body_bounded,representation_explicit,invalid_rejected,no_partial_replacement",
        ),
        (
            "NET-08",
            "R0-02",
            "FR-005,FR-014",
            "SC-003",
            "stream_reset,valid_stream_survives,errors_attributed",
        ),
        (
            "CMP-01",
            "R0-03",
            "FR-007,FR-017",
            "SC-001,SC-004",
            "public_wit,bounded_read,valid_proposal,original_unchanged",
        ),
        (
            "CMP-02",
            "R0-03",
            "FR-008",
            "SC-004",
            "execution_interrupted,deadline_met",
        ),
        (
            "CMP-03",
            "R0-03",
            "FR-008,FR-014",
            "SC-004",
            "memory_bounded,aggregate_invocations_bounded,control_ack,rss_observed",
        ),
        (
            "CMP-04",
            "R0-03",
            "FR-007,FR-008",
            "SC-002,SC-004",
            "invalid_rejected,stale_rejected,foreign_rejected,output_bounded",
        ),
        (
            "CMP-05",
            "R0-03",
            "FR-008",
            "SC-004",
            "host_call_deadline,aggregate_host_calls_bounded,control_ack",
        ),
        (
            "CMP-06",
            "R0-03",
            "FR-006,FR-007,FR-008",
            "SC-002,SC-004",
            "ungranted_access_denied,secrets_absent",
        ),
        (
            "CMP-07",
            "R0-03",
            "FR-008,FR-017",
            "SC-004",
            "all_variants_observed,slots_released,fresh_success,errors_attributed",
        ),
        (
            "RUN-01",
            "R0-04",
            "FR-009,FR-017",
            "SC-001,SC-002",
            "runtime_lifecycle,brokered_calls,model_separate,zero_model_egress",
        ),
        (
            "RUN-02",
            "R0-04",
            "FR-010,FR-018",
            "SC-002,SC-004",
            "effective_config_attested,mandatory_isolation,contamination_rejected,no_fallback",
        ),
        (
            "RUN-03",
            "R0-04",
            "FR-006,FR-010",
            "SC-002,SC-004",
            "actual_attempts,descendants_restricted,granted_read,secrets_absent",
        ),
        (
            "RUN-04",
            "R0-04",
            "FR-004,FR-010",
            "SC-002,SC-004",
            "actual_attempts,descendants_restricted,healthy_observer,zero_forbidden_arrivals,descriptors_closed",
        ),
        (
            "RUN-05",
            "R0-04",
            "FR-010,FR-014",
            "SC-004",
            "actual_attempts,descendants_restricted,resource_limits,fresh_success",
        ),
        (
            "RUN-06",
            "R0-04",
            "FR-011,FR-017",
            "SC-004,SC-005",
            "ten_control_samples,control_ack,no_stale_admissions,contained",
        ),
        (
            "RUN-07",
            "R0-04",
            "FR-004,FR-011,FR-012",
            "SC-002,SC-005",
            "events_deduplicated,causality_preserved,late_work_denied,aggregate_quota",
        ),
        (
            "RUN-08",
            "R0-04",
            "FR-010,FR-011,FR-012",
            "SC-004,SC-005",
            "host_transport_lost,lease_expired,descendants_terminated,contained",
        ),
        (
            "REC-01",
            "R0-04",
            "FR-012",
            "SC-005",
            "reservation_seams,consumption_preserved,reservation_reconciled,zero_resends",
        ),
        (
            "REC-02",
            "R0-04",
            "FR-012,FR-017",
            "SC-005",
            "sending_seams,unknown_restored,consumption_preserved,read_only_reconciliation,zero_resends",
        ),
        (
            "REC-03",
            "R0-04",
            "FR-012,FR-017",
            "SC-005",
            "completion_restored,events_deduplicated,consumption_preserved,zero_resends",
        ),
        (
            "REC-04",
            "R0-04",
            "FR-004,FR-011,FR-012",
            "SC-002,SC-005",
            "current_authority,current_versions,stale_work_denied",
        ),
        (
            "REC-05",
            "R0-04",
            "FR-012,FR-016,FR-018",
            "SC-005,SC-007",
            "storage_faults,admission_closed,partial_evidence,zero_resends",
        ),
        (
            "EXIT-01",
            "R0-05",
            "FR-013,FR-014,FR-015,FR-016",
            "SC-006",
            "stable_pins,provenance,licenses_recorded,decisions_recorded,raw_measurements",
        ),
        (
            "EXIT-02",
            "R0-05",
            "FR-001,FR-016,FR-018",
            "SC-001,SC-007",
            "complete_inventory,packet_integrity,failure_blocks_exit,approval_required,r0_only",
        ),
    ];
    for (id, package, requirements, successes, checks) in expected {
        let value = case_value(id);
        assert_eq!(value["package_id"], package);
        assert_eq!(
            value["requirement_ids"],
            json!(requirements.split(',').collect::<Vec<_>>())
        );
        assert_eq!(
            value["success_ids"],
            json!(successes.split(',').collect::<Vec<_>>())
        );
        assert_eq!(value["mandatory"], true);
        let expected_checks: Value = checks
            .split(',')
            .map(|name| (name.to_owned(), json!(true)))
            .collect::<serde_json::Map<_, _>>()
            .into();
        assert_eq!(value["expected"], expected_checks);
        let _: ProofCase = decode(value.clone());
        // Individually plausible catalog substitutions must fail typed parsing too.
        for field in [
            "package_id",
            "requirement_ids",
            "success_ids",
            "mandatory",
            "expected",
        ] {
            let mut changed = value.clone();
            changed[field] = match field {
                "package_id" => json!(if package == "R0-01" { "R0-02" } else { "R0-01" }),
                "requirement_ids" => json!(["FR-018"]),
                "success_ids" => json!(["SC-006"]),
                "mandatory" => json!(false),
                _ => json!({}),
            };
            if changed != value {
                rejects::<ProofCase>(changed);
            }
        }
    }
}

#[test]
fn package_dag_is_the_catalog_not_just_any_acyclic_graph() {
    let expected = [
        ("R0-01", json!([])),
        ("R0-02", json!(["R0-01"])),
        ("R0-03", json!(["R0-01"])),
        ("R0-04", json!(["R0-01"])),
        ("R0-05", json!(["R0-01", "R0-02", "R0-03", "R0-04"])),
    ];
    for (index, (id, requires)) in expected.into_iter().enumerate() {
        let source = manifest();
        assert_eq!(source["packages"][index]["package_id"], id);
        assert_eq!(source["packages"][index]["requires"], requires);
        for replacement in [json!([id]), json!(["R0-99"]), json!(["R0-05"])] {
            let mut changed = source.clone();
            changed["packages"][index]["requires"] = replacement;
            assert!(inventory_from(changed).is_err());
        }
        if id != "R0-01" {
            let mut changed = source;
            changed["packages"][index]["requires"] = json!([]);
            assert!(
                inventory_from(changed).is_err(),
                "accepted removed prerequisite for {id}"
            );
        }
    }
}

#[test]
fn inventory_rejects_missing_duplicate_and_reassigned_cases_or_requirements() {
    for field in ["packages", "cases"] {
        let mut missing = manifest();
        missing[field].as_array_mut().unwrap().pop();
        assert!(inventory_from(missing).is_err());
        let mut duplicate = manifest();
        let first = duplicate[field][0].clone();
        duplicate[field].as_array_mut().unwrap().push(first);
        assert!(inventory_from(duplicate).is_err());
    }
    let mut reassigned = manifest();
    reassigned["packages"][0]["case_ids"][0] = json!("NET-01");
    assert!(inventory_from(reassigned).is_err());
    let mut omitted = manifest();
    omitted["packages"][1]["case_ids"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(inventory_from(omitted).is_err());
    let mut weakened = manifest();
    weakened["packages"][3]["requirement_ids"] = json!(["FR-010"]);
    assert!(inventory_from(weakened).is_err());
    let mut duplicate_requirement = manifest();
    duplicate_requirement["packages"][0]["requirement_ids"] =
        json!(["FR-002", "FR-002", "FR-003", "FR-004", "FR-017"]);
    assert!(inventory_from(duplicate_requirement).is_err());
    let mut unknown = case_value("CON-01");
    unknown["case_id"] = json!("CON-99");
    rejects::<ProofCase>(unknown);
}

#[test]
fn assertion_keys_are_typed_case_specific_booleans_without_coercion() {
    assert_eq!(
        serde_json::to_value(CheckName::H2BothLegs).unwrap(),
        "h2_both_legs"
    );
    assert_eq!(
        decode::<CheckName>(json!("healthy_observer")),
        CheckName::HealthyObserver
    );
    rejects::<CheckName>(json!("arbitrary_model_claim"));
    for invalid in [json!("true"), json!(1), json!(null), json!({"claim": true})] {
        let mut value = result_value("NET-04", "passed", case_value("NET-04")["expected"].clone());
        value["observed"]["h2_both_legs"] = invalid;
        rejects::<ProofResult>(value);
    }
    let mut wrong_case = result_value("NET-04", "failed", json!({"healthy_observer": true}));
    rejects::<ProofResult>(wrong_case.clone());
    wrong_case["observed"] = json!({"arbitrary_model_claim": true});
    rejects::<ProofResult>(wrong_case);
    let mut substituted =
        result_value("NET-04", "passed", case_value("NET-04")["expected"].clone());
    substituted["expected"] = case_value("NET-05")["expected"].clone();
    rejects::<ProofResult>(substituted);
}

#[test]
fn every_required_observation_and_evidence_reference_is_needed_for_pass() {
    for case in manifest()["cases"].as_array().unwrap() {
        let id = case["case_id"].as_str().unwrap();
        let valid = result_value(id, "passed", case["expected"].clone());
        let record: ProofResult = decode(valid.clone());
        let _: &EvidenceRef = &record.evidence_refs[0];
        for check in case["expected"].as_object().unwrap().keys() {
            let mut missing = valid.clone();
            missing["observed"].as_object_mut().unwrap().remove(check);
            rejects::<ProofResult>(missing);
            let mut contradicted = valid.clone();
            contradicted["observed"][check] = json!(false);
            rejects::<ProofResult>(contradicted);
        }
        let mut absent_evidence = valid;
        absent_evidence["evidence_refs"] = json!([]);
        rejects::<ProofResult>(absent_evidence);
    }
}

#[test]
fn negative_case_cannot_pass_without_a_healthy_observer_and_observed_denial() {
    let observations = json!({
        "scope_rechecked": true, "pivots_denied": true,
        "healthy_observer": false, "zero_forbidden_arrivals": true
    });
    rejects::<ProofResult>(result_value("NET-05", "passed", observations.clone()));
    // An observed failure is preserved as a failed record, not rejected or upgraded.
    let failed: ProofResult = decode(result_value("NET-05", "failed", observations));
    assert_eq!(serde_json::to_value(failed).unwrap()["status"], "failed");
    let mut no_denial = case_value("NET-05")["expected"].clone();
    no_denial["pivots_denied"] = json!(false);
    rejects::<ProofResult>(result_value("NET-05", "passed", no_denial));
    for status in ["failed", "blocked", "unexecuted"] {
        let mut partial = result_value("NET-05", status, json!({}));
        partial["evidence_refs"] = json!([]);
        let record: ProofResult = decode(partial);
        assert_eq!(serde_json::to_value(record).unwrap()["status"], status);
    }
}

#[test]
fn result_records_have_strict_fields_numbers_statuses_and_shared_evidence_variants() {
    let valid = result_value("CON-01", "passed", case_value("CON-01")["expected"].clone());
    for field in [
        "run_id",
        "case_id",
        "status",
        "expected",
        "observed",
        "evidence_refs",
        "elapsed_us",
        "usage",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        rejects::<ProofResult>(missing);
    }
    for status in ["success", "incomplete", "PASSED", "skipped", ""] {
        let mut changed = valid.clone();
        changed["status"] = json!(status);
        rejects::<ProofResult>(changed);
    }
    for invalid in [
        json!(-1),
        json!(1.5),
        json!(9007199254740992_u64),
        json!("17"),
    ] {
        let mut changed = valid.clone();
        changed["elapsed_us"] = invalid;
        rejects::<ProofResult>(changed);
    }
    let mut unknown = valid.clone();
    unknown["approved"] = json!(true);
    rejects::<ProofResult>(unknown);
    let mut null_error = valid.clone();
    null_error["error"] = Value::Null;
    rejects::<ProofResult>(null_error);
    let mut artifact_revision = valid.clone();
    artifact_revision["evidence_refs"][0]["revision"] = json!(0);
    rejects::<ProofResult>(artifact_revision);
    let mut snapshot = valid.clone();
    snapshot["evidence_refs"] = json!([{
        "snapshot_id": ARTIFACT_ID, "revision": 0, "sha256": DIGEST,
        "range_start": 0, "range_end": 2
    }]);
    let _: ProofResult = decode(snapshot.clone());
    snapshot["evidence_refs"][0]
        .as_object_mut()
        .unwrap()
        .remove("revision");
    rejects::<ProofResult>(snapshot);
    let mut missing_usage = valid;
    missing_usage["usage"]
        .as_object_mut()
        .unwrap()
        .remove("cpu_us");
    rejects::<ProofResult>(missing_usage);
}

#[test]
fn duplicate_wire_fields_and_assertions_are_rejected_before_overwrite() {
    let valid = result_value("NET-04", "passed", case_value("NET-04")["expected"].clone());
    let document = serde_json::to_string(&valid).unwrap();
    let duplicate_case =
        document.replacen("\"case_id\":", "\"case_id\":\"CON-01\",\"case_id\":", 1);
    assert!(serde_json::from_str::<ProofResult>(&duplicate_case).is_err());
    let duplicate_check = document.replacen(
        "\"h2_both_legs\":true",
        "\"h2_both_legs\":false,\"h2_both_legs\":true",
        1,
    );
    assert!(serde_json::from_str::<ProofResult>(&duplicate_check).is_err());
    let observed_duplicate =
        document.replacen("\"observed\":{", "\"observed\":{\"body_exact\":false,", 1);
    assert!(serde_json::from_str::<ProofResult>(&observed_duplicate).is_err());
    let environment_duplicate = serde_json::to_string(&run_value()).unwrap().replacen(
        "\"rust\":\"1.100.0\"",
        "\"rust\":\"0.0.0\",\"rust\":\"1.100.0\"",
        1,
    );
    assert!(serde_json::from_str::<Run>(&environment_duplicate).is_err());
    let digest_duplicate = serde_json::to_string(&run_value()).unwrap().replacen(
        "\"fixture_digests\":{",
        &format!("\"fixture_digests\":{{\"contracts\":\"{OTHER_DIGEST}\","),
        1,
    );
    assert!(serde_json::from_str::<Run>(&digest_duplicate).is_err());
}

#[test]
fn unique_case_identity_is_scoped_to_one_run_without_last_writer_wins() {
    let first = matching_record("CON-01");
    let duplicate = matching_record("CON-01");
    assert!(
        inventory()
            .package_status(
                &run(),
                &[first, duplicate],
                &CatalogId::parse("R0-01").unwrap()
            )
            .is_err()
    );
    let foreign: ProofResult = {
        let mut value = result_value("CON-01", "passed", case_value("CON-01")["expected"].clone());
        value["run_id"] = json!(OTHER_RUN_ID);
        decode(value)
    };
    assert!(
        inventory()
            .package_status(
                &run(),
                &[matching_record("CON-01"), foreign],
                &CatalogId::parse("R0-01").unwrap()
            )
            .is_err()
    );
    assert!(
        inventory()
            .package_status(&run(), &[], &CatalogId::parse("R0-99").unwrap())
            .is_err()
    );
}

#[test]
fn complete_package_records_and_partial_selected_results_are_not_the_same_gate() {
    let mut records = vec![matching_record("CON-01")];
    assert_eq!(package_status(&records, "R0-01"), PackageStatus::Incomplete);
    for id in ["CON-02", "CON-03", "CON-04", "CON-05"] {
        records.push(matching_record(id));
    }
    assert_eq!(package_status(&records, "R0-01"), PackageStatus::Passed);
    assert_eq!(package_status(&records, "R0-05"), PackageStatus::Incomplete);
    records[0] = decode(result_value("CON-01", "blocked", json!({})));
    assert_eq!(package_status(&records, "R0-01"), PackageStatus::Blocked);
    records[0] = decode(result_value(
        "CON-01",
        "failed",
        json!({"round_trip": false}),
    ));
    assert_eq!(package_status(&records, "R0-01"), PackageStatus::Failed);
    records[0] = decode(result_value("CON-01", "unexecuted", json!({})));
    assert_eq!(package_status(&records, "R0-01"), PackageStatus::Incomplete);
}

#[test]
fn passing_package_records_cannot_bypass_missing_or_failed_prerequisites() {
    let mut transport = (1..=8)
        .map(|index| matching_record(&format!("NET-{index:02}")))
        .collect::<Vec<_>>();
    assert_eq!(
        package_status(&transport, "R0-02"),
        PackageStatus::Incomplete
    );
    transport.push(decode(result_value(
        "CON-01",
        "failed",
        json!({"round_trip": false}),
    )));
    assert_ne!(package_status(&transport, "R0-02"), PackageStatus::Passed);
    // Even an EXIT-02 assertion that calls itself complete cannot supply absent packages.
    assert_eq!(
        package_status(
            &[matching_record("EXIT-01"), matching_record("EXIT-02")],
            "R0-05"
        ),
        PackageStatus::Incomplete
    );
}

fn assert_run_round_trip(value: Value) -> Run {
    let record: Run = decode(value);
    let restored: Run = serde_json::from_slice(&serde_json::to_vec(&record).unwrap()).unwrap();
    assert_eq!(
        restored, record,
        "All typed provenance must survive serialization"
    );
    record
}

#[test]
fn run_round_trip_retains_all_provenance_and_omits_absent_finish_time() {
    let source = run_value();
    let record = assert_run_round_trip(source.clone());
    assert!(
        serde_json::to_value(&record)
            .unwrap()
            .get("finished_at")
            .is_none()
    );
    let mut finished = source.clone();
    finished["finished_at"] = json!("2026-11-16T12:00:01Z");
    let completed = assert_run_round_trip(finished);
    assert!(
        serde_json::to_value(completed)
            .unwrap()
            .get("finished_at")
            .is_some()
    );
    let _: Run = decode(source);
}

#[test]
fn required_run_metadata_cannot_be_omitted_null_untyped_or_unbounded() {
    let source = run_value();
    for field in source.as_object().unwrap().keys() {
        let mut missing = source.clone();
        missing.as_object_mut().unwrap().remove(field);
        rejects::<Run>(missing);
    }
    for field in source["environment"].as_object().unwrap().keys() {
        let mut missing = source.clone();
        missing["environment"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        rejects::<Run>(missing);
        let mut null = source.clone();
        null["environment"][field] = Value::Null;
        rejects::<Run>(null);
    }
    for field in ["logical_cpus", "memory_mib"] {
        for invalid in [
            json!(-1),
            json!(1.5),
            json!("8"),
            json!(9007199254740992_u64),
        ] {
            let mut changed = source.clone();
            changed["environment"][field] = invalid;
            rejects::<Run>(changed);
        }
    }
    for field in ["hardware_model", "storage", "kernel"] {
        let mut oversized = source.clone();
        oversized["environment"][field] = json!("é".repeat(1_048_577));
        rejects::<Run>(oversized);
    }
    for field in ["fixture_digests", "binary_digests", "dependency_versions"] {
        let mut oversized = source.clone();
        let value = if field == "dependency_versions" {
            json!("0.1.0")
        } else {
            json!(DIGEST)
        };
        oversized["environment"][field] = (0..4096)
            .map(|index| (format!("entry-{index}"), value.clone()))
            .collect::<serde_json::Map<_, _>>()
            .into();
        rejects::<Run>(oversized);
    }
    let mut untyped_digest = source.clone();
    untyped_digest["environment"]["fixture_digests"]["contracts"] = json!("not-a-digest");
    rejects::<Run>(untyped_digest);
    let mut floating_version = source.clone();
    floating_version["environment"]["dependency_versions"]["rust"] = json!("latest");
    rejects::<Run>(floating_version);
    let mut unbounded_version = source.clone();
    unbounded_version["environment"]["dependency_versions"]["rust"] = json!("1".repeat(1_048_577));
    rejects::<Run>(unbounded_version);
    let mut unknown = source.clone();
    unknown["environment"]["raw_secret"] = json!("must-not-be-accepted");
    rejects::<Run>(unknown);
    let mut unknown_root = source.clone();
    unknown_root["review_approved"] = json!(true);
    rejects::<Run>(unknown_root);
    let mut null_finish = source.clone();
    null_finish["finished_at"] = Value::Null;
    rejects::<Run>(null_finish);
    let mut backwards_finish = source;
    backwards_finish["finished_at"] = json!("2026-11-16T11:59:59Z");
    rejects::<Run>(backwards_finish);
}

#[test]
fn same_run_continuation_cannot_rebind_profile_fixtures_versions_or_clock() {
    let initial = run();
    initial.validate_continuation(&run()).unwrap();
    let mut finished = run_value();
    finished["finished_at"] = json!("2026-11-16T12:00:01Z");
    initial
        .validate_continuation(&decode(finished.clone()))
        .unwrap();
    for (field, replacement) in [
        ("run_id", json!(OTHER_RUN_ID)),
        ("profile_sha256", json!(OTHER_DIGEST)),
        ("fixture_manifest_sha256", json!(OTHER_DIGEST)),
        ("clock_epoch_id", json!(OTHER_RUN_ID)),
        ("started_at", json!("2026-11-16T12:00:02Z")),
        ("dependency_record_refs", json!([ARTIFACT_ID])),
    ] {
        let mut changed = run_value();
        changed[field] = replacement;
        assert!(
            initial.validate_continuation(&decode(changed)).is_err(),
            "rebound {field}"
        );
    }
    for (field, replacement) in [
        ("lockfile_sha256", json!(OTHER_DIGEST)),
        ("provisioning_sha256", json!(OTHER_DIGEST)),
        ("effective_config_sha256", json!(OTHER_DIGEST)),
        ("wit_sha256", json!(OTHER_DIGEST)),
        ("hardware_model", json!("a-different-machine")),
    ] {
        let mut changed = run_value();
        changed["environment"][field] = replacement;
        assert!(
            initial.validate_continuation(&decode(changed)).is_err(),
            "rebound {field}"
        );
    }
    for field in ["dependency_versions", "fixture_digests", "binary_digests"] {
        let mut changed = run_value();
        let first = changed["environment"][field]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        changed["environment"][field][first] = if field == "dependency_versions" {
            json!("2.0.0")
        } else {
            json!(OTHER_DIGEST)
        };
        assert!(initial.validate_continuation(&decode(changed)).is_err());
    }
    let completed: Run = decode(finished.clone());
    assert!(completed.validate_continuation(&run()).is_err());
    finished["finished_at"] = json!("2026-11-16T12:00:02Z");
    assert!(completed.validate_continuation(&decode(finished)).is_err());
}

#[test]
fn catalog_records_and_result_collections_are_bounded_and_strict() {
    let source = manifest();
    let package = source["packages"][0].clone();
    let case = case_value("CON-01");
    for field in package.as_object().unwrap().keys() {
        let mut missing = package.clone();
        missing.as_object_mut().unwrap().remove(field);
        rejects::<WorkPackage>(missing);
    }
    for field in case.as_object().unwrap().keys() {
        let mut missing = case.clone();
        missing.as_object_mut().unwrap().remove(field);
        rejects::<ProofCase>(missing);
    }
    let mut oversized_title = package.clone();
    oversized_title["title"] = json!("é".repeat(1_048_577));
    rejects::<WorkPackage>(oversized_title);
    let mut oversized_description = case.clone();
    oversized_description["description"] = json!("é".repeat(1_048_577));
    rejects::<ProofCase>(oversized_description);
    let mut unknown_package = package.clone();
    unknown_package["optional"] = json!(true);
    rejects::<WorkPackage>(unknown_package);
    let mut unknown_case = case.clone();
    unknown_case["optional"] = json!(true);
    rejects::<ProofCase>(unknown_case);
    let mut oversized_fixtures = case.clone();
    oversized_fixtures["fixture_refs"] = json!(vec!["fixtures/scenarios/contracts.json"; 4096]);
    rejects::<ProofCase>(oversized_fixtures);
    let mut duplicate_fixtures = case.clone();
    duplicate_fixtures["fixture_refs"] = json!([
        "fixtures/scenarios/contracts.json",
        "fixtures/scenarios/contracts.json"
    ]);
    rejects::<ProofCase>(duplicate_fixtures);
    let mut oversized_evidence = result_value("CON-01", "passed", case["expected"].clone());
    oversized_evidence["evidence_refs"] = json!(vec![
        json!({ "artifact_id": ARTIFACT_ID, "sha256": DIGEST });
        4096
    ]);
    rejects::<ProofResult>(oversized_evidence);
    let mut oversized_dependencies = run_value();
    oversized_dependencies["dependency_record_refs"] = json!(vec![ARTIFACT_ID; 4096]);
    rejects::<Run>(oversized_dependencies);
    let case_document = serde_json::to_string(&case).unwrap().replacen(
        "\"round_trip\":true",
        "\"round_trip\":false,\"round_trip\":true",
        1,
    );
    assert!(serde_json::from_str::<ProofCase>(&case_document).is_err());
    let package_document = serde_json::to_string(&package).unwrap().replacen(
        "\"package_id\":",
        "\"package_id\":\"R0-05\",\"package_id\":",
        1,
    );
    assert!(serde_json::from_str::<WorkPackage>(&package_document).is_err());
}

#[test]
fn unsupported_run_versions_profiles_and_invalid_digest_namespaces_are_rejected() {
    for (field, invalid) in [
        ("run_id", json!("R0-01")),
        ("clock_epoch_id", json!("clock-1")),
        ("profile_id", json!("unreviewed-profile")),
        ("contract_version", json!("0.2.0")),
        ("profile_sha256", json!("sha256:not-a-digest")),
        ("fixture_manifest_sha256", json!(DIGEST.to_uppercase())),
    ] {
        let mut changed = run_value();
        changed[field] = invalid;
        rejects::<Run>(changed);
    }
    let mut changed = run_value();
    changed["environment"]["image_digest"] = json!(DIGEST);
    rejects::<Run>(changed);
}

#[test]
fn each_package_membership_and_requirement_set_is_independently_validated() {
    let source = manifest();
    for (index, package) in source["packages"].as_array().unwrap().iter().enumerate() {
        for field in ["case_ids", "requirement_ids"] {
            let mut omitted = source.clone();
            omitted["packages"][index][field]
                .as_array_mut()
                .unwrap()
                .pop();
            assert!(
                inventory_from(omitted).is_err(),
                "accepted weakened {} {field}",
                package["package_id"]
            );
            let mut duplicate = source.clone();
            let first = duplicate["packages"][index][field][0].clone();
            duplicate["packages"][index][field]
                .as_array_mut()
                .unwrap()
                .push(first);
            assert!(
                inventory_from(duplicate).is_err(),
                "accepted duplicate {} {field}",
                package["package_id"]
            );
        }
    }
    for case in source["cases"].as_array().unwrap() {
        let mut wrong_fixture = case.clone();
        wrong_fixture["fixture_refs"] = json!(["fixtures/scenarios/unreviewed.json"]);
        rejects::<ProofCase>(wrong_fixture);
        let mut missing_expected = case.clone();
        let first = missing_expected["expected"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        missing_expected["expected"]
            .as_object_mut()
            .unwrap()
            .remove(&first);
        rejects::<ProofCase>(missing_expected);
        let mut weakened_expected = case.clone();
        weakened_expected["expected"][first] = json!(false);
        rejects::<ProofCase>(weakened_expected);
    }
}

#[test]
fn expected_denial_may_retain_its_structured_operation_error_without_becoming_failed() {
    let mut value = result_value("NET-05", "passed", case_value("NET-05")["expected"].clone());
    value["error"] = serde_json::to_value(razen_engine::protocol::error::ProofError::new(
        razen_engine::protocol::error::ErrorCode::OutOfScope,
        "Fixture operation denied by scope",
    ))
    .unwrap();
    let record: ProofResult = decode(value.clone());
    assert_eq!(serde_json::to_value(record).unwrap(), value);
}

const ISOLATION_OBSERVATIONS: [&str; 4] = [
    "guest_package_manifest_sha256",
    "provisioning_sha256",
    "effective_config_sha256",
    "seccomp_sha256",
];

fn contracts_run_value() -> Value {
    let mut value = run_value();
    value["environment"]["isolation_status"] = json!("not_required");
    value["environment"]["dependency_versions"] = json!({ "rust": "1.100.0" });
    value["environment"]["binary_digests"] = json!({ "engine": DIGEST });
    for field in ISOLATION_OBSERVATIONS {
        value["environment"].as_object_mut().unwrap().remove(field);
    }
    value
}

#[test]
fn vm_independent_contracts_run_preserves_provenance_without_guest_observations() {
    assert_eq!(
        serde_json::to_value(IsolationStatus::NotRequired).unwrap(),
        "not_required"
    );
    let value = contracts_run_value();
    let record = assert_run_round_trip(value.clone());
    assert_eq!(
        record.environment.isolation_status,
        IsolationStatus::NotRequired
    );
    let mut with_selected_versions = value;
    with_selected_versions["environment"]["dependency_versions"]["lima"] = json!("2.3.0");
    with_selected_versions["environment"]["dependency_versions"]["bubblewrap"] = json!("0.13.1");
    assert_run_round_trip(with_selected_versions);
}

#[test]
fn isolation_state_distinguishes_unavailable_from_prepared_without_fabricated_hashes() {
    for status in ["not_required", "unavailable"] {
        let mut value = contracts_run_value();
        value["environment"]["isolation_status"] = json!(status);
        assert_run_round_trip(value.clone());
        for field in ISOLATION_OBSERVATIONS {
            let mut fabricated_observation = value.clone();
            fabricated_observation["environment"][field] = json!(DIGEST);
            rejects::<Run>(fabricated_observation);
            let mut null_observation = value.clone();
            null_observation["environment"][field] = Value::Null;
            rejects::<Run>(null_observation);
        }
        value["environment"]["dependency_versions"]
            .as_object_mut()
            .unwrap()
            .remove("rust");
        rejects::<Run>(value);
    }
    for field in ISOLATION_OBSERVATIONS {
        let mut missing = run_value();
        missing["environment"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        rejects::<Run>(missing);
        let mut null = run_value();
        null["environment"][field] = Value::Null;
        rejects::<Run>(null);
    }
    for dependency in ["rust", "lima", "bubblewrap"] {
        let mut missing = run_value();
        missing["environment"]["dependency_versions"]
            .as_object_mut()
            .unwrap()
            .remove(dependency);
        rejects::<Run>(missing);
    }
}

#[test]
fn changing_isolation_observations_or_status_requires_a_new_run() {
    let contracts: Run = decode(contracts_run_value());
    let prepared: Run = decode(run_value());
    assert!(contracts.validate_continuation(&prepared).is_err());
    assert!(prepared.validate_continuation(&contracts).is_err());
    let mut unavailable = contracts_run_value();
    unavailable["environment"]["isolation_status"] = json!("unavailable");
    assert!(
        contracts
            .validate_continuation(&decode(unavailable))
            .is_err()
    );
}
