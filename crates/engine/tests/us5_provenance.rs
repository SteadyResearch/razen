use razen_engine::{
    application::provenance,
    domain::{
        decisions::{DecisionRecord, DependencyRecord},
        values::Digest,
    },
};
use serde_json::{Value, json};
#[path = "support/exit_fixtures.rs"]
mod fixture;
#[path = "support/private_root.rs"]
mod private_root;
fn source() -> Value {
    json!({"name":"serde","checked_at":"2026-11-16T19:02:49Z","source_url":"https://crates.io/api/v1/crates/serde","latest_stable_observed":"1.0.229","selected_version":"1.0.229","checksum":Digest::of(b"actual downloaded crate bytes"),"license_expression":"MIT OR Apache-2.0","minimum_rust":{"kind":"declared","version":"1.56"},"yanked":false,"prerelease":false})
}
fn record() -> Value {
    json!({"name":"serde","source_url":"https://crates.io/api/v1/crates/serde","checked_at":"2026-11-16T19:02:49Z","latest_stable_observed":"1.0.229","selected_version":"1.0.229","artifact_digest":{"kind":"published_observed","algorithm":"sha256","digest":Digest::of(b"actual downloaded crate bytes")},"license_expression":"MIT OR Apache-2.0","minimum_rust":{"kind":"declared","version":"1.56"},"compatibility_evidence_refs":[fixture::evidence()]})
}
#[test]
fn published_checksum_does_not_become_download_verified_without_hashing_actual_bytes() {
    for expression in [
        "MIT OR Apache-2.0",
        "Apache-2.0 / MIT",
        "Upstream freeform license claim",
        "NOASSERTION",
    ] {
        let mut record_value = record();
        record_value["license_expression"] = json!(expression);
        let record: DependencyRecord = serde_json::from_value(record_value).unwrap();
        let mut source_value = source();
        source_value["license_expression"] = json!(expression);
        let source = serde_json::to_vec(&source_value).unwrap();
        provenance::verify_dependency_source(&record, &source).unwrap();
        assert_eq!(record.license_expression, expression);
        assert_eq!(
            serde_json::to_value(&record).unwrap()["license_expression"],
            expression
        );
        assert!(!record.artifact_digest.downloaded_verified());
        assert!(provenance::verify_download(&record, b"changed downloaded crate bytes").is_err());
        assert!(!record.artifact_digest.downloaded_verified());
        let verified =
            provenance::verify_download(&record, b"actual downloaded crate bytes").unwrap();
        assert!(verified.artifact_digest.downloaded_verified());
        assert_eq!(verified.license_expression, expression);
        let mut forged = record.clone();
        forged.artifact_digest = verified.artifact_digest;
        assert!(provenance::verify_dependency_source(&forged, &source).is_err());
        source_value["license_expression"] = json!("Apache-2.0 OR MIT");
        assert!(
            provenance::verify_dependency_source(
                &record,
                &serde_json::to_vec(&source_value).unwrap()
            )
            .is_err()
        );
    }
}
#[test]
fn source_validation_rejects_unobserved_latest_changed_license_msrv_and_silent_downgrade() {
    let record: DependencyRecord = serde_json::from_value(record()).unwrap();
    for field in [
        "latest_stable_observed",
        "license_expression",
        "minimum_rust",
        "yanked",
        "prerelease",
    ] {
        let mut source = source();
        source[field] = match field {
            "minimum_rust" => json!({"kind":"declared","version":"1.99"}),
            "yanked" | "prerelease" => json!(true),
            _ => json!("different"),
        };
        assert!(
            provenance::verify_dependency_source(&record, &serde_json::to_vec(&source).unwrap())
                .is_err(),
            "accepted changed {field}"
        );
    }
    let mut downgraded = serde_json::to_value(&record).unwrap();
    downgraded["selected_version"] = json!("1.0.228");
    let downgraded: DependencyRecord = serde_json::from_value(downgraded).unwrap();
    let mut selected_source = source();
    selected_source["selected_version"] = json!("1.0.228");
    assert!(
        provenance::verify_dependency_source(
            &downgraded,
            &serde_json::to_vec(&selected_source).unwrap()
        )
        .is_err()
    );
}
#[test]
fn records_reject_unknown_null_zero_digest_secret_and_private_path_metadata() {
    for (field, value) in [
        (
            "artifact_digest",
            json!({"kind":"published_observed","algorithm":"sha256","digest":"0".repeat(64)}),
        ),
        ("approved_exception_ref", Value::Null),
        (
            "source_url",
            json!("https://user:token@crates.io/api/v1/crates/serde"),
        ),
        ("license_expression", json!("/Users/owner/private/license")),
        ("name", json!("-----BEGIN PRIVATE KEY-----")),
        ("unknown", json!(true)),
    ] {
        let mut value_record = record();
        value_record[field] = value;
        assert!(
            serde_json::from_value::<DependencyRecord>(value_record).is_err(),
            "accepted {field}"
        );
    }
    let run = fixture::run();
    let digest = Digest::of(b"manifest");
    for field in ["reviewer", "rationale"] {
        let mut value = fixture::decision(&run, digest);
        value[field] = json!("/Users/owner/.ssh/id_ed25519");
        assert!(serde_json::from_value::<DecisionRecord>(value).is_err());
    }
    let mut decision = fixture::decision(&run, digest);
    decision["evidence_refs"][0] = json!({"kind":"manifest","text":"approved any manifest"});
    assert!(serde_json::from_value::<DecisionRecord>(decision).is_err());
}
#[test]
fn non_rust_dependency_never_invents_msrv_or_single_permissive_debian_image_license() {
    let mut value = record();
    value["name"] = json!("debian-image");
    value["source_url"] =
        json!("https://cloud.debian.org/images/cloud/trixie/20261111-2659/SHA512SUMS");
    value["selected_version"] = json!("13.7");
    value["latest_stable_observed"] = json!("13.7");
    value["minimum_rust"] = json!({"kind":"not_applicable"});
    value["license_expression"] = json!("NOASSERTION");
    let image: DependencyRecord = serde_json::from_value(value).unwrap();
    image.validate().unwrap();
}
#[test]
fn raw_measurement_consumer_rejects_missing_samples_recomputed_summaries_and_non_arrivals() {
    use razen_engine::{
        application::measurements::{Measurements, Sample},
        domain::values::EntityId,
    };
    let profile = fixture::profile();
    let config = &profile.config().measurement;
    let samples = |count: u64, base: u64| -> Vec<Sample> {
        (0..count)
            .map(|i| Sample {
                invocation_id: EntityId::new(),
                result_artifact_id: EntityId::new(),
                elapsed_us: i + 1,
                receiver_sequence: base + 2 * i + 1,
                body_bytes: config.sample_body_bytes.get(),
                body_sha256: Digest::of(b"CONTROLLEDGATEFIXTURE body"),
                receiver_before: base + 2 * i,
                receiver_after: base + 2 * i + 1,
            })
            .collect()
    };
    let warmup = config.latency_warmup_exchanges.get();
    let count = config.latency_sample_exchanges.get();
    let direct_samples = samples(count, 2 * warmup);
    let proxy_samples = samples(count, 2 * warmup + 1);
    let times: Vec<_> = (1..=count).collect();
    let value = Measurements {
        profile_sha256: profile.sha256(),
        fixture_sha256: Digest::of(b"fixture"),
        context_source: "run.environment".into(),
        method: "CONTROLLEDGATEFIXTURE raw sample policy inputs only".into(),
        warmup_exchanges: warmup,
        sample_body_bytes: config.sample_body_bytes.get(),
        direct_warmup: samples(warmup, 0),
        proxy_warmup: samples(warmup, 1),
        direct_samples,
        proxy_samples,
        direct_us: times.clone(),
        proxy_us: times.clone(),
        direct_p50_us: razen_engine::application::measurements::percentile(&times, 50).unwrap(),
        direct_p95_us: razen_engine::application::measurements::percentile(&times, 95).unwrap(),
        proxy_p50_us: razen_engine::application::measurements::percentile(&times, 50).unwrap(),
        proxy_p95_us: razen_engine::application::measurements::percentile(&times, 95).unwrap(),
        direct_receiver_count: warmup + count,
        proxy_receiver_count: warmup + count,
        rss_kib_before: 1,
        rss_kib_after: 2,
        max_sampled_rss_kib: 2,
    };
    provenance::validate_measurements(&value, &profile).unwrap();
    let mut corrupt = value.clone();
    corrupt.direct_samples.pop();
    assert!(provenance::validate_measurements(&corrupt, &profile).is_err());
    let mut corrupt = value.clone();
    corrupt.proxy_p95_us = 0;
    assert!(provenance::validate_measurements(&corrupt, &profile).is_err());
    let mut corrupt = value.clone();
    corrupt.direct_samples[0].receiver_after = corrupt.direct_samples[0].receiver_before;
    assert!(provenance::validate_measurements(&corrupt, &profile).is_err());
    let mut corrupt = value.clone();
    corrupt.proxy_samples[0].receiver_before += 1;
    corrupt.proxy_samples[0].receiver_after += 1;
    corrupt.proxy_samples[0].receiver_sequence += 1;
    assert!(provenance::validate_measurements(&corrupt, &profile).is_err());
    let mut corrupt = value.clone();
    corrupt.rss_kib_before = u64::MAX;
    corrupt.max_sampled_rss_kib = u64::MAX;
    assert!(provenance::validate_measurements(&corrupt, &profile).is_err());
    let mut corrupt = value;
    corrupt.proxy_us[0] += 1;
    assert!(provenance::validate_measurements(&corrupt, &profile).is_err());
}
#[test]
fn readonly_graph_consumer_rederives_directness_instead_of_trusting_a_transitive_label() {
    use razen_engine::application::provenance::{DependencyEntry, DependencyKind, Workspace};
    let mut value = record();
    value["selected_version"] = json!("1.0.228");
    let record: DependencyRecord = serde_json::from_value(value).unwrap();
    let mut entry = DependencyEntry {
        workspace: Some(Workspace::Host),
        kind: DependencyKind::Transitive,
        record,
    };
    let graph = json!({"workspace":"host","lockfile_sha256":Digest::of(b"lock"),"members":[{"name":"razen-engine","version":"0.1.0","features":[],"feature_definitions":{},"dependencies":[["serde","1.0.228"]],"resolved":[{"alias":"serde","package":["serde","1.0.228"],"dep_kinds":[{"kind":null,"target":null}]}],"requirements":[{"name":"serde","req":"=1.0.228","kind":null,"rename":null,"optional":false,"target":null}]}],"packages":[{"name":"serde","version":"1.0.228","checksum":Digest::of(b"actual downloaded crate bytes"),"direct":true,"features":[],"feature_definitions":{},"dependencies":[],"resolved":[],"requirements":[],"license_expression":"MIT OR Apache-2.0","minimum_rust":{"kind":"declared","version":"1.56"}}]});
    let mut graph = graph;
    graph["packages"][0]["library_name"] = json!("serde");
    graph["members"][0]["requirements"][0]["features"] = json!([]);
    graph["members"][0]["requirements"][0]["uses_default_features"] = json!(true);
    assert!(
        provenance::verify_graph_selection(&entry, &serde_json::to_vec(&graph).unwrap()).is_err()
    );
    entry.kind = DependencyKind::Direct;
    assert!(
        provenance::verify_graph_selection(&entry, &serde_json::to_vec(&graph).unwrap()).is_err()
    );
    entry.record.selected_version = serde_json::from_value(json!("1.0.229")).unwrap();
    let mut current = graph;
    current["members"][0]["dependencies"][0][1] = json!("1.0.229");
    current["members"][0]["resolved"][0]["package"][1] = json!("1.0.229");
    current["members"][0]["requirements"][0]["req"] = json!("=1.0.229");
    current["packages"][0]["version"] = json!("1.0.229");
    provenance::verify_graph_selection(&entry, &serde_json::to_vec(&current).unwrap()).unwrap();
    let mut changed = current.clone();
    changed["packages"][0]["minimum_rust"] = json!({"kind":"declared","version":"1.99"});
    assert!(
        provenance::verify_graph_selection(&entry, &serde_json::to_vec(&changed).unwrap()).is_err()
    );
    let mut changed = current;
    changed["packages"][0]["license_expression"] = json!("different upstream license");
    assert!(
        provenance::verify_graph_selection(&entry, &serde_json::to_vec(&changed).unwrap()).is_err()
    );
}
#[test]
fn actual_capture_reader_rejects_changed_bytes_traversal_symlinks_and_unsafe_permissions() {
    use razen_engine::application::provenance::SourceFile;
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    let root = private_root::PrivateRoot::new();
    let bytes = b"actual private metadata capture";
    fs::write(root.path().join("capture.json"), bytes).unwrap();
    let mut source = SourceFile {
        path: "capture.json".into(),
        sha256: Digest::of(bytes),
    };
    assert_eq!(
        provenance::read_capture(root.path(), &source).unwrap(),
        bytes
    );
    fs::write(root.path().join("capture.json"), b"changed bytes").unwrap();
    assert!(provenance::read_capture(root.path(), &source).is_err());
    source.path = "../capture.json".into();
    assert!(provenance::read_capture(root.path(), &source).is_err());
    source.path = "link.json".into();
    symlink("capture.json", root.path().join("link.json")).unwrap();
    assert!(provenance::read_capture(root.path(), &source).is_err());
    source.path = "capture.json".into();
    source.sha256 = Digest::of(b"changed bytes");
    fs::set_permissions(
        root.path().join("capture.json"),
        fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert!(provenance::read_capture(root.path(), &source).is_err());
    assert_eq!(
        fs::read(root.path().join("capture.json")).unwrap(),
        b"changed bytes"
    );
}
#[test]
fn declared_prepared_environment_without_actual_sources_cannot_create_provenance_or_invocations() {
    use razen_engine::{
        adapters::workspace::OwnedDirectory,
        application::proof_host::ProofHost,
        domain::values::EntityId,
        protocol::{contracts::CanonicalFixtures, error::ErrorCode},
    };
    use std::{path::Path, sync::Arc};
    let root = private_root::PrivateRoot::new();
    let profile = fixture::profile();
    let workspace =
        Arc::new(OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap());
    let examples = include_bytes!("../../../fixtures/scenarios/contracts.json");
    let host = ProofHost::create(
        workspace,
        &profile,
        CanonicalFixtures::from_bytes(examples).unwrap(),
        Digest::of(examples),
        Digest::of(b"CONTROLLEDGATEFIXTURE provenance consumer"),
    )
    .unwrap();
    let mut run = fixture::run();
    run.run_id = host.workspace.run_id();
    let before = host.ledger.invocations().unwrap().len();
    let error = provenance::collect(&host, &profile, root.path(), &run).unwrap_err();
    assert_eq!(error.code, ErrorCode::ProviderUnavailable);
    assert_eq!(host.ledger.invocations().unwrap().len(), before);
    let error = provenance::preflight(root.path(), &run.environment, &profile).unwrap_err();
    assert_eq!(error.code, ErrorCode::ProviderUnavailable);
    assert_eq!(host.ledger.invocations().unwrap().len(), before);
    assert!(
        !root
            .path()
            .join("target/r0-evidence/preparation/provenance/inputs.json")
            .exists()
    );
}
#[test]
fn debian_package_names_epochs_and_revisions_remain_exact_without_inventing_rust_msrv() {
    let mut package = record();
    package["name"] = json!("libstdc++6");
    package["selected_version"] = json!("1:14.2.0-19");
    package["latest_stable_observed"] = json!("1:14.2.0-19");
    package["minimum_rust"] = json!({"kind":"not_applicable"});
    package["license_expression"] = json!("NOASSERTION");
    let package: DependencyRecord = serde_json::from_value(package).unwrap();
    package.validate().unwrap();
    assert_eq!(package.name.as_str(), "libstdc++6");
    assert_eq!(package.selected_version.as_str(), "1:14.2.0-19");
}
#[test]
fn approved_exception_is_bound_to_exact_source_selection_without_self_referential_artifact_hashes()
{
    use razen_engine::domain::{decisions::DependencySelection, values::AuditTime};
    let selection = json!({"name":"serde","selected_version":"1.0.228","latest_stable_observed":"1.0.229","selected_source_sha256":Digest::of(b"CONTROLLEDGATEFIXTURE selected source"),"latest_source_sha256":Digest::of(b"CONTROLLEDGATEFIXTURE latest source")});
    let binding: DependencySelection = serde_json::from_value(selection.clone()).unwrap();
    let run = fixture::run();
    let mut value = fixture::decision(&run, Digest::of(b"manifest"));
    value["decision_id"] = json!("DEP-SERDE");
    value["evidence_refs"] = json!([{"kind":"dependency_selection","selection":selection}]);
    value["rationale"] = json!(
        "Recorded the [official stable manifest](https://static.rust-lang.org/dist/channel-rust-stable.toml)(verified?) without changing the selected source binding."
    );
    let decision: DecisionRecord = serde_json::from_value(value.clone()).unwrap();
    let before = AuditTime::parse("2026-11-16T12:03:00Z").unwrap();
    provenance::verify_exception_binding(&decision, &binding, before).unwrap();
    for status in ["recorded", "pending", "blocked", "rejected"] {
        let mut value = value.clone();
        value["status"] = json!(status);
        let decision: DecisionRecord = serde_json::from_value(value).unwrap();
        assert!(provenance::verify_exception_binding(&decision, &binding, before).is_err());
    }
    value["evidence_refs"][0]["selection"]["selected_source_sha256"] =
        json!(Digest::of(b"other source"));
    let changed: DecisionRecord = serde_json::from_value(value).unwrap();
    assert!(provenance::verify_exception_binding(&changed, &binding, before).is_err());
}
#[test]
fn every_absolute_private_directory_is_rejected_in_public_dependency_and_decision_fields() {
    for path in [
        "/var/folders/person/cache",
        "/tmp/private",
        "/Volumes/Private/source",
        "/opt/internal/project",
        "C:\\private\\source",
        "https://public.example/release(/tmp/private)",
        "Source=/tmp/private(https://public.example/release)",
        "[public](https://public.example)/opt/internal",
        "https://alice'private:secret@public.example/license",
        "https://public.example/license'part?token=secret",
        "[license](https://alice'private:secret@public.example/license)",
        "[license](https://public.example/license'part?token=secret)",
        "https://alice(private:secret@public.example/license)",
        "https://public.example/license'part#secret",
        "[license](HTTPS://alice'private:secret@public.example/license)",
        "/",
        "Apache-2.0 / MIT / /opt/internal",
        "Apache-2.0 / MIT (https://public.example/release)(/tmp/private)",
        "Apache-2.0 / MIT password=private",
        "UnknownLicense / MIT",
        "Apache 2 / MIT",
    ] {
        let mut dependency = record();
        dependency["license_expression"] = json!(path);
        assert!(serde_json::from_value::<DependencyRecord>(dependency).is_err());
        let run = fixture::run();
        let mut decision = fixture::decision(&run, Digest::of(b"manifest"));
        decision["rationale"] = json!(format!("Built from {path}"));
        assert!(serde_json::from_value::<DecisionRecord>(decision).is_err());
    }
}
