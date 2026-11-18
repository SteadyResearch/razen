use std::fmt::Write as _;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use razen_engine::application::profile::{LoadedProfile, PilotProfile};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

const CANONICAL: &[u8] =
    include_bytes!("../../../specs/001-r0-feasibility/contracts/pilot-profile.json");
const PROFILE_BYTE_LIMIT: usize = 1024 * 1024;

fn sha256_hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(64);
    for byte in Sha256::digest(bytes) {
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn sample() -> Value {
    serde_json::from_slice(CANONICAL).expect("canonical profile is JSON")
}

fn changed(pointer: &str, replacement: Value) -> Vec<u8> {
    let mut profile = sample();
    *profile
        .pointer_mut(pointer)
        .expect("existing profile field") = replacement;
    serde_json::to_vec(&profile).expect("serialize owned profile sample")
}

fn rejects(bytes: &[u8], case: &str) {
    assert!(LoadedProfile::from_bytes(bytes).is_err(), "accepted {case}");
}

fn rejects_change(pointer: &str, replacement: Value) {
    let case = format!("{pointer} = {replacement}");
    rejects(&changed(pointer, replacement), &case);
}

fn object_paths(value: &Value, path: &str, output: &mut Vec<String>) {
    if let Value::Object(object) = value {
        output.push(path.to_owned());
        for (key, child) in object {
            object_paths(child, &format!("{path}/{key}"), output);
        }
    }
}

fn leaf_paths(value: &Value, path: &str, output: &mut Vec<String>) {
    if let Value::Object(object) = value {
        for (key, child) in object {
            leaf_paths(child, &format!("{path}/{key}"), output);
        }
    } else {
        output.push(path.to_owned());
    }
}

#[test]
fn profile_identity_hashes_exact_input_bytes_not_a_reserialized_config() {
    let original = LoadedProfile::from_bytes(CANONICAL).expect("approved profile");
    original
        .config()
        .validate()
        .expect("validated configuration");
    let mut spaced = b" \n\t".to_vec();
    spaced.extend_from_slice(CANONICAL);
    spaced.extend_from_slice(b"\r\n ");
    let reformatted = LoadedProfile::from_bytes(&spaced).expect("legal JSON whitespace");

    assert_eq!(original.sha256().to_string(), sha256_hex(CANONICAL));
    assert_eq!(reformatted.sha256().to_string(), sha256_hex(&spaced));
    assert_ne!(original.sha256(), reformatted.sha256());
    assert_eq!(
        serde_json::to_value(original.config()).expect("serialize config"),
        serde_json::to_value(reformatted.config()).expect("serialize config")
    );
}

#[test]
fn coherent_stricter_budgets_are_retained_without_defaulting_or_reusing_the_hash() {
    let mut stricter = sample();
    for (pointer, value) in [
        ("/transport/requests_per_case", 8),
        ("/transport/redirect_limit", 1),
        ("/transport/request_timeout_ms", 1000),
        ("/transport/body_limit_bytes", 524288),
        ("/transport/chunk_limit_bytes", 32768),
        ("/control/ack_deadline_ms", 500),
        ("/parser_fuzz/max_inputs", 128),
        ("/parser_fuzz/max_input_bytes", 32768),
        ("/parser_fuzz/deadline_ms", 15000),
        ("/component/linear_memory_bytes", 33554432),
        ("/component/table_elements", 8192),
        ("/component/fuel_per_invocation", 5000000),
        ("/component/epoch_interval_ms", 5),
        ("/component/invocation_deadline_ms", 2500),
        ("/component/host_call_deadline_ms", 125),
        ("/component/runner_rss_monitor_threshold_mib", 128),
        ("/component/rss_sampling_ms", 5),
        ("/external_runner/guest_cpus", 1),
        ("/external_runner/guest_memory_mib", 1024),
        ("/external_runner/memory_max_bytes", 134217728),
        ("/external_runner/pids_max", 32),
        ("/external_runner/tmpfs_max_bytes", 8388608),
        ("/external_runner/file_descriptors_max", 32),
        ("/external_runner/wall_deadline_ms", 2500),
        ("/external_runner/termination_grace_ms", 100),
        ("/external_runner/empty_cgroup_observation_deadline_ms", 500),
        ("/external_runner/orphan_lease_ms", 1000),
        ("/protocol/message_limit_bytes", 524288),
        ("/protocol/invocation_output_limit_bytes", 1048576),
        ("/protocol/admission_queue_capacity", 32),
        ("/protocol/event_queue_capacity", 128),
        ("/ledger/busy_timeout_ms", 125),
        ("/measurement/latency_warmup_exchanges", 10),
        ("/measurement/latency_sample_exchanges", 50),
        ("/measurement/sample_body_bytes", 2048),
    ] {
        *stricter.pointer_mut(pointer).unwrap() = json!(value);
    }
    stricter["external_runner"]["cpu_max"] = json!("50000 100000");
    let bytes = serde_json::to_vec(&stricter).unwrap();
    let loaded = LoadedProfile::from_bytes(&bytes).expect("coherent stricter limits");
    loaded
        .config()
        .validate()
        .expect("custom configuration is valid");
    assert_eq!(serde_json::to_value(loaded.config()).unwrap(), stricter);
    assert_eq!(loaded.sha256().to_string(), sha256_hex(&bytes));
    assert_ne!(
        loaded.sha256(),
        LoadedProfile::from_bytes(CANONICAL).unwrap().sha256()
    );
}

#[test]
fn typed_policy_validation_rejects_unsafe_configuration_outside_the_loader() {
    let mut config: PilotProfile = serde_json::from_slice(CANONICAL).unwrap();
    config.transport.upstream_tls_verification = false;
    assert!(
        config.validate().is_err(),
        "typed validation allowed TLS bypass"
    );

    let mut config: PilotProfile = serde_json::from_slice(CANONICAL).unwrap();
    config.external_runner.direct_network = true;
    assert!(
        config.validate().is_err(),
        "typed validation allowed direct networking"
    );
}

#[test]
fn every_object_rejects_unknown_and_duplicate_fields() {
    let canonical = sample();
    let mut paths = Vec::new();
    object_paths(&canonical, "", &mut paths);
    for path in paths {
        let mut unknown = canonical.clone();
        unknown
            .pointer_mut(&path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(
                "unreviewed_capability".to_owned(),
                json!("secret-profile-value-must-not-leak"),
            );
        let bytes = serde_json::to_vec(&unknown).unwrap();
        let error = LoadedProfile::from_bytes(&bytes)
            .err()
            .unwrap_or_else(|| panic!("accepted unknown field in {path}"));
        assert!(!error.message.contains("secret-profile-value-must-not-leak"));
        assert!(
            !error
                .to_string()
                .contains("secret-profile-value-must-not-leak")
        );

        let object = canonical.pointer(&path).unwrap().as_object().unwrap();
        let fragment = serde_json::to_string(object).unwrap();
        let compact = serde_json::to_string(&canonical).unwrap();
        for (key, value) in object {
            let duplicate = format!(
                "{{{}:{},{}",
                serde_json::to_string(key).unwrap(),
                serde_json::to_string(value).unwrap(),
                &fragment[1..]
            );
            let bytes = compact.replacen(&fragment, &duplicate, 1);
            rejects(bytes.as_bytes(), &format!("duplicate {path}/{key}"));
        }
    }
}

#[test]
fn every_declared_field_is_required_without_permissive_defaults() {
    let canonical = sample();
    let mut paths = Vec::new();
    object_paths(&canonical, "", &mut paths);
    for path in paths {
        for key in canonical
            .pointer(&path)
            .unwrap()
            .as_object()
            .unwrap()
            .keys()
        {
            let mut missing = canonical.clone();
            missing
                .pointer_mut(&path)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(key);
            rejects(
                &serde_json::to_vec(&missing).unwrap(),
                &format!("missing {path}/{key}"),
            );
        }
    }
}

#[test]
fn typed_fields_never_coerce_strings_numbers_booleans_arrays_or_null() {
    let canonical = sample();
    let mut paths = Vec::new();
    leaf_paths(&canonical, "", &mut paths);
    for path in paths {
        let value = canonical.pointer(&path).unwrap();
        let wrong_type = match value {
            Value::String(_) => json!(1),
            Value::Number(_) => json!("1"),
            Value::Bool(_) => json!("false"),
            Value::Array(_) => json!("http1_forward"),
            _ => panic!("unexpected canonical leaf {path}"),
        };
        rejects_change(&path, wrong_type);
        rejects_change(&path, Value::Null);
        if value.is_number() {
            for invalid in [
                json!(-1),
                json!(1.5),
                json!(9007199254740992_u64),
                json!(u64::MAX),
            ] {
                rejects_change(&path, invalid);
            }
            let overflow = changed(&path, json!("overflow-placeholder"));
            let overflow = String::from_utf8(overflow)
                .unwrap()
                .replace("\"overflow-placeholder\"", "18446744073709551616");
            rejects(overflow.as_bytes(), &format!("u64 overflow in {path}"));
        }
    }
}

#[test]
fn units_are_not_interchangeable_or_inferred_from_strings() {
    for (pointer, wrong_units) in [
        ("/transport/request_timeout_ms", json!("2s")),
        ("/transport/body_limit_bytes", json!("1MiB")),
        ("/component/linear_memory_bytes", json!("64MiB")),
        (
            "/component/runner_rss_monitor_threshold_mib",
            json!("268435456 bytes"),
        ),
        ("/external_runner/guest_memory_mib", json!("2GiB")),
        ("/parser_fuzz/deadline_ms", json!("30s")),
    ] {
        rejects_change(pointer, wrong_units);
    }
    let mut wrong_field = sample();
    let transport = wrong_field["transport"].as_object_mut().unwrap();
    let timeout = transport.remove("request_timeout_ms").unwrap();
    transport.insert("request_timeout_seconds".to_owned(), timeout);
    rejects(
        &serde_json::to_vec(&wrong_field).unwrap(),
        "renamed time unit",
    );
}

#[test]
fn unsupported_contract_pilot_toolchain_world_backend_and_image_pins_are_denied() {
    for (pointer, replacement) in [
        ("/profile_version", "0.3.0"),
        ("/profile_version", "v0.1.0"),
        ("/profile_id", "unreviewed-pilot"),
        ("/host/os", "Linux"),
        ("/host/os_version", "26.5.2"),
        ("/host/arch", "x86_64"),
        ("/toolchain/rust", "stable"),
        ("/toolchain/rust", "1.99.0"),
        ("/toolchain/component_target", "wasm32-wasip1"),
        ("/parser_fuzz/mutation_version", "0.2.0"),
        (
            "/component/world",
            "razen:component-proof/passive-proof@0.2.0",
        ),
        ("/external_runner/backend", "native-host"),
        ("/external_runner/lima_version", "2.3.1"),
        ("/external_runner/bubblewrap_version", "0.13.0"),
        ("/external_runner/guest_os", "Debian unstable arm64"),
        (
            "/external_runner/image_url",
            "http://cloud.debian.org/untrusted.raw",
        ),
        (
            "/external_runner/image_url",
            "https://example.invalid/replacement.raw",
        ),
        ("/external_runner/image_url", "file:///tmp/guest.raw"),
        (
            "/external_runner/image_digest",
            "sha512:00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
        (
            "/external_runner/image_digest",
            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ),
        ("/protocol/version", "razen.proof/0.2.0"),
    ] {
        rejects_change(pointer, json!(replacement));
    }
    let approved = sample()["external_runner"]["image_digest"]
        .as_str()
        .unwrap()
        .to_owned();
    rejects_change(
        "/external_runner/image_digest",
        json!(approved.to_uppercase()),
    );
}

#[test]
fn all_required_transport_modes_and_run_metadata_are_present_exactly_once() {
    for pointer in ["/transport/required_modes", "/host/required_run_metadata"] {
        let canonical = sample();
        let required = canonical.pointer(pointer).unwrap().as_array().unwrap();
        rejects_change(pointer, json!([]));
        for index in 0..required.len() {
            let mut missing = required.clone();
            missing.remove(index);
            rejects_change(pointer, json!(missing));
            let mut duplicated = required.clone();
            duplicated.push(required[index].clone());
            rejects_change(pointer, json!(duplicated));
        }
        let mut unknown = required.clone();
        unknown.push(json!("unreviewed-mode-or-metadata"));
        rejects_change(pointer, json!(unknown));
    }
}

#[test]
fn tls_verification_and_fixture_scoping_cannot_be_weakened() {
    for (pointer, replacement) in [
        ("/transport/upstream_tls_verification", json!(false)),
        ("/transport/client_trust", json!("os-trust-store")),
        ("/transport/client_trust", json!("install-system-ca")),
        ("/transport/client_trust", json!("trust-all")),
        ("/transport/bind", json!("0.0.0.0")),
        ("/transport/fixture_scope", json!("all-private-addresses")),
        ("/control/stale_admissions_after_barrier", json!(1)),
    ] {
        rejects_change(pointer, replacement);
    }
}

#[test]
fn runners_cannot_gain_network_mount_socket_or_agent_authority() {
    for pointer in [
        "/external_runner/direct_network",
        "/external_runner/host_mounts",
        "/external_runner/agent_or_manager_socket_forwarding",
    ] {
        rejects_change(pointer, json!(true));
    }
    for capability in [
        "inherit_network",
        "mounts",
        "inherited_sockets",
        "ssh_agent_forwarding",
        "manager_socket",
        "host_agent",
        "docker_socket",
    ] {
        let mut profile = sample();
        profile["external_runner"][capability] = json!(true);
        rejects(&serde_json::to_vec(&profile).unwrap(), capability);
    }
    rejects_change("/external_runner/memory_swap_max_bytes", json!(1));
}

#[test]
fn positive_finite_budgets_cannot_be_disabled_with_zero_or_unbounded_values() {
    let canonical = sample();
    let mut paths = Vec::new();
    leaf_paths(&canonical, "", &mut paths);
    for path in paths {
        if !canonical.pointer(&path).unwrap().is_number()
            || matches!(
                path.as_str(),
                "/parser_fuzz/seed"
                    | "/control/stale_admissions_after_barrier"
                    | "/external_runner/memory_swap_max_bytes"
            )
        {
            continue;
        }
        for value in [json!(0), json!("unbounded"), json!("infinity")] {
            rejects_change(&path, value);
        }
    }
}

#[test]
fn aggregate_caps_and_hard_ack_deadline_cannot_be_expanded() {
    for pointer in [
        "/component/max_concurrent_invocations",
        "/component/max_concurrent_host_calls",
        "/external_runner/max_concurrent_invocations",
    ] {
        rejects_change(pointer, json!(2));
    }
    rejects_change("/control/ack_deadline_ms", json!(1001));
}

#[test]
fn resource_limits_must_be_internally_consistent() {
    let canonical = sample();
    for (pointer, too_large) in [
        (
            "/transport/chunk_limit_bytes",
            canonical["transport"]["body_limit_bytes"].as_u64().unwrap() + 1,
        ),
        (
            "/component/host_call_deadline_ms",
            canonical["component"]["invocation_deadline_ms"]
                .as_u64()
                .unwrap()
                + 1,
        ),
        (
            "/component/epoch_interval_ms",
            canonical["component"]["invocation_deadline_ms"]
                .as_u64()
                .unwrap()
                + 1,
        ),
        (
            "/external_runner/tmpfs_max_bytes",
            canonical["external_runner"]["memory_max_bytes"]
                .as_u64()
                .unwrap()
                + 1,
        ),
        (
            "/external_runner/memory_max_bytes",
            canonical["external_runner"]["guest_memory_mib"]
                .as_u64()
                .unwrap()
                * 1024
                * 1024
                + 1,
        ),
        (
            "/external_runner/termination_grace_ms",
            canonical["external_runner"]["empty_cgroup_observation_deadline_ms"]
                .as_u64()
                .unwrap()
                + 1,
        ),
        (
            "/measurement/sample_body_bytes",
            canonical["transport"]["body_limit_bytes"].as_u64().unwrap() + 1,
        ),
    ] {
        rejects_change(pointer, json!(too_large));
    }
    for invalid in [
        "max 100000",
        "0 100000",
        "100000 0",
        "-1 100000",
        "100000",
        "100000 100000 100000",
        "18446744073709551616 100000",
    ] {
        rejects_change("/external_runner/cpu_max", json!(invalid));
    }
}

#[test]
fn ledger_durability_and_honest_measurement_policy_cannot_be_disabled() {
    for (pointer, replacement) in [
        ("/ledger/journal_mode", json!("OFF")),
        ("/ledger/synchronous", json!("OFF")),
        ("/ledger/fullfsync", json!(false)),
        ("/ledger/foreign_keys", json!(false)),
        (
            "/measurement/product_performance_thresholds_are_r0_gates",
            json!(true),
        ),
        (
            "/measurement/provision_or_compile_during_timing",
            json!(true),
        ),
    ] {
        rejects_change(pointer, replacement);
    }
}

struct ProfileDirectory(PathBuf);

impl ProfileDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("razen-profile-{}", Uuid::new_v4()));
        fs::create_dir(&path).expect("create unique profile test directory");
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for ProfileDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove only this test's profile directory");
    }
}

fn write_profile(path: &Path, bytes: &[u8]) {
    let mut file = File::create_new(path).expect("create unique profile file");
    file.write_all(bytes).expect("write profile sample");
}

#[test]
fn file_and_memory_loaders_enforce_the_exact_one_mib_input_boundary() {
    let directory = ProfileDirectory::new();
    let path = directory.path("boundary.json");
    let mut bytes = CANONICAL.to_vec();
    bytes.resize(PROFILE_BYTE_LIMIT, b' ');
    write_profile(&path, &bytes);
    let loaded = LoadedProfile::load(&path).expect("exactly one MiB is allowed");
    assert_eq!(loaded.sha256().to_string(), sha256_hex(&bytes));
    assert_eq!(
        LoadedProfile::from_bytes(&bytes)
            .expect("same in-memory byte limit")
            .sha256(),
        loaded.sha256()
    );
    bytes.push(b' ');
    rejects(&bytes, "one byte beyond in-memory profile limit");
    let oversized = directory.path("oversized.json");
    write_profile(&oversized, &bytes);
    assert!(
        LoadedProfile::load(&oversized).is_err(),
        "accepted oversized file"
    );
}

#[test]
fn large_valid_json_file_is_rejected_by_the_input_byte_budget() {
    let directory = ProfileDirectory::new();
    let path = directory.path("large.json");
    let mut file = File::create_new(&path).expect("create bounded oversized sample");
    file.write_all(CANONICAL).expect("write JSON prefix");
    for _ in 0..1024 {
        file.write_all(&[b' '; 8192])
            .expect("append valid JSON whitespace");
    }
    drop(file);
    assert!(
        LoadedProfile::load(&path).is_err(),
        "accepted oversized valid JSON file"
    );
}

#[test]
fn malformed_or_multiple_documents_never_become_a_profile() {
    for invalid in [b"".as_slice(), b"null", b"[]", b"{}", b"{", b"\xff\xfe"] {
        rejects(invalid, "malformed or non-object profile");
    }
    let mut trailing_document = CANONICAL.to_vec();
    trailing_document.extend_from_slice(CANONICAL);
    rejects(&trailing_document, "multiple JSON documents");
}

#[test]
fn missing_profile_file_is_a_safe_typed_error() {
    let directory = ProfileDirectory::new();
    let secret_path = directory.path("secret-location-not-for-diagnostics.json");
    let error = LoadedProfile::load(&secret_path).expect_err("missing file fails");
    assert!(
        !error
            .message
            .contains("secret-location-not-for-diagnostics")
    );
    assert!(
        !error
            .to_string()
            .contains("secret-location-not-for-diagnostics")
    );
}

#[test]
fn required_string_lists_reject_non_string_entries_instead_of_coercing_them() {
    for pointer in ["/transport/required_modes", "/host/required_run_metadata"] {
        for wrong_entry in [Value::Null, json!(true), json!(7), json!({}), json!([])] {
            let canonical = sample();
            let mut entries = canonical
                .pointer(pointer)
                .unwrap()
                .as_array()
                .unwrap()
                .clone();
            entries[0] = wrong_entry;
            rejects_change(pointer, json!(entries));
        }
    }
}

#[test]
fn lowered_limits_reject_inconsistency_even_when_every_value_is_within_reviewed_maxima() {
    for changes in [
        vec![("/transport/body_limit_bytes", 32768)],
        vec![("/component/invocation_deadline_ms", 100)],
        vec![
            ("/component/invocation_deadline_ms", 5),
            ("/component/host_call_deadline_ms", 1),
            ("/component/rss_sampling_ms", 1),
        ],
        vec![("/external_runner/memory_max_bytes", 8388608)],
        vec![("/external_runner/guest_memory_mib", 128)],
        vec![("/external_runner/empty_cgroup_observation_deadline_ms", 100)],
        vec![
            ("/transport/body_limit_bytes", 2048),
            ("/transport/chunk_limit_bytes", 1024),
        ],
        vec![("/protocol/message_limit_bytes", 1024)],
        vec![("/control/ack_deadline_ms", 100)],
    ] {
        let mut profile = sample();
        for (pointer, value) in &changes {
            *profile.pointer_mut(pointer).unwrap() = json!(value);
        }
        rejects(
            &serde_json::to_vec(&profile).unwrap(),
            &format!("inconsistent lower budgets: {changes:?}"),
        );
    }
}

#[test]
fn archived_profile_policy_cannot_acquire_the_new_component_caps() {
    let mut legacy = sample();
    legacy["profile_version"] = json!("0.1.0");
    legacy["component"]["instances"] = json!(1);
    legacy["component"]["tables"] = json!(1);
    let loaded = LoadedProfile::from_bytes(&serde_json::to_vec(&legacy).unwrap()).unwrap();
    let mut changed = loaded.config().clone();
    changed.component.instances = razen_engine::domain::values::WireInt::new(3).unwrap();
    assert_eq!(
        changed.validate().unwrap_err().code,
        razen_engine::protocol::error::ErrorCode::InvalidInput
    );
    changed.component.instances = razen_engine::domain::values::WireInt::new(1).unwrap();
    changed.component.tables = razen_engine::domain::values::WireInt::new(2).unwrap();
    assert_eq!(
        changed.validate().unwrap_err().code,
        razen_engine::protocol::error::ErrorCode::InvalidInput
    );
}
