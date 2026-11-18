#[path = "support/owned_child.rs"]
mod owned_child;
#[path = "support/private_root.rs"]
mod private_root;

use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use owned_child::OwnedChild;
use private_root::PrivateRoot;
use razen_engine::adapters::command::{CommandLimits, capture};
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::environment::observe;
use razen_engine::application::profile::LoadedProfile;
use razen_engine::domain::values::{CatalogId, Digest, EntityId};
use razen_engine::protocol::error::ErrorCode;
use sha2::{Digest as _, Sha256};

fn limits() -> CommandLimits {
    CommandLimits {
        stdin_bytes: 256 * 1024,
        stdout_bytes: 256 * 1024,
        stderr_bytes: 4096,
        timeout: Duration::from_secs(3),
    }
}

fn fixture(
    name: &str,
    input: Option<&[u8]>,
    limits: CommandLimits,
) -> razen_engine::protocol::error::ProofResult<razen_engine::adapters::command::CommandOutput> {
    capture(
        Path::new(env!("CARGO_BIN_EXE_razen-command-fixture")),
        &[OsStr::new(name)],
        input,
        limits,
    )
}

#[test]
fn command_preserves_literal_native_arguments_without_a_shell() {
    let literal = "$(touch /not-a-command) $HOME ; * 'quoted'";
    let output = capture(
        Path::new("/usr/bin/printf"),
        &[OsStr::new("%s"), OsStr::new(literal)],
        None,
        limits(),
    )
    .unwrap();
    assert_eq!(output.stdout, literal.as_bytes());
    assert!(output.stderr.is_empty());
}

#[test]
fn command_round_trips_binary_stdin_and_closes_it_at_eof() {
    let input: Vec<u8> = (0..=255).cycle().take(128 * 1024).collect();
    let output = capture(Path::new("/bin/cat"), &[], Some(&input), limits()).unwrap();
    assert_eq!(output.stdout, input);
    assert!(output.stderr.is_empty());
    assert!(
        capture(Path::new("/bin/cat"), &[], None, limits())
            .unwrap()
            .stdout
            .is_empty()
    );
}

#[test]
fn command_accepts_exact_output_cap_but_never_returns_truncated_success() {
    let mut cap = limits();
    cap.stdout_bytes = 4;
    let exact = capture(
        Path::new("/usr/bin/printf"),
        &[OsStr::new("1234")],
        None,
        cap,
    )
    .unwrap();
    assert_eq!(exact.stdout, b"1234");
    let mut cap = limits();
    cap.stdout_bytes = 4;
    let error = capture(
        Path::new("/usr/bin/printf"),
        &[OsStr::new("12345")],
        None,
        cap,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::OutputInvalid);
}

#[test]
fn command_bounds_each_stream_independently_without_pipe_deadlock() {
    let mut cap = limits();
    cap.stderr_bytes = 64;
    let started = Instant::now();
    let error = fixture("flood-stderr", None, cap).unwrap_err();
    assert_eq!(error.code, ErrorCode::OutputInvalid);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(!error.to_string().contains("PRIVATE-STDERR-MARKER"));
    let mut cap = limits();
    cap.stdout_bytes = 64;
    let error = fixture("flood-stdout", None, cap).unwrap_err();
    assert_eq!(error.code, ErrorCode::OutputInvalid);
}

#[test]
fn command_rejects_oversized_stdin_before_starting_the_executable() {
    let root = PrivateRoot::new();
    let marker = root.path().join("started");
    let input = marker.as_os_str().as_encoded_bytes();
    let mut cap = limits();
    cap.stdin_bytes = input.len() - 1;
    let error = fixture("pid-then-sleep", Some(input), cap).unwrap_err();
    assert_eq!(error.code, ErrorCode::InvalidInput);
    assert!(!marker.exists());
}

#[test]
fn command_deadline_includes_blocked_stdin_and_terminates_only_owned_child() {
    let mut unrelated = OwnedChild::sleep();
    let input = vec![b'x'; 256 * 1024];
    let mut cap = limits();
    cap.timeout = Duration::from_millis(100);
    let started = Instant::now();
    let error = capture(
        Path::new("/bin/sleep"),
        &[OsStr::new("30")],
        Some(&input),
        cap,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(2));
    unrelated.assert_running();
    unrelated.kill_and_wait();
}

#[test]
fn command_timeout_reaps_the_owned_process_before_returning() {
    let root = PrivateRoot::new();
    let marker = root.path().join("owned-pid");
    let mut cap = limits();
    cap.timeout = Duration::from_millis(750);
    let error = fixture(
        "pid-then-sleep",
        Some(marker.as_os_str().as_encoded_bytes()),
        cap,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::Timeout);
    let pid = fs::read_to_string(marker).expect("fixture actually started before deadline");
    let status = Command::new("/bin/kill")
        .args(["-0", pid.trim()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(
        !status.success(),
        "owned process remains alive or unreaped after timeout"
    );
}

#[test]
fn command_deadline_still_applies_when_exited_child_leaves_inherited_pipes_open() {
    let mut unrelated = OwnedChild::sleep();
    let mut cap = limits();
    cap.timeout = Duration::from_millis(100);
    let started = Instant::now();
    let error = fixture("inherited-pipes", None, cap).unwrap_err();
    assert_eq!(error.code, ErrorCode::Timeout);
    assert!(started.elapsed() < Duration::from_secs(1));
    unrelated.assert_running();
    unrelated.kill_and_wait();
}

#[test]
fn command_nonzero_exit_is_failure_without_private_stderr_in_diagnostics() {
    let error = fixture("exit", None, limits()).unwrap_err();
    assert_eq!(error.code, ErrorCode::ProviderUnavailable);
    assert!(!error.to_string().contains("PRIVATE-STDERR-MARKER"));
}

#[test]
fn command_missing_executable_and_zero_deadline_fail_explicitly() {
    let error = capture(
        Path::new("/nonexistent/razen-native-tool"),
        &[],
        None,
        limits(),
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::ProviderUnavailable);
    let mut cap = limits();
    cap.timeout = Duration::ZERO;
    assert_eq!(
        capture(Path::new("/bin/cat"), &[], None, cap)
            .unwrap_err()
            .code,
        ErrorCode::InvalidInput
    );
}

fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn profile() -> LoadedProfile {
    LoadedProfile::load(&repo().join("specs/001-r0-feasibility/contracts/pilot-profile.json"))
        .unwrap()
}

fn hash_file(path: &Path) -> Digest {
    let mut file = File::open(path).unwrap();
    let mut hash = Sha256::new();
    let mut buffer = [0; 16 * 1024];
    loop {
        let count = file.read(&mut buffer).unwrap();
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Digest::from_sha256(hash.finalize().into())
}

fn binaries() -> BTreeMap<CatalogId, Digest> {
    BTreeMap::from([(
        CatalogId::parse("test-harness").unwrap(),
        hash_file(&std::env::current_exe().unwrap()),
    )])
}

fn workspace(root: &PrivateRoot) -> OwnedDirectory {
    OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap()
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn native_text(program: &str, args: &[&str]) -> String {
    let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
    String::from_utf8(
        capture(Path::new(program), &args, None, limits())
            .unwrap()
            .stdout,
    )
    .unwrap()
    .trim()
    .to_owned()
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn environment_records_real_host_and_files_without_claiming_prepared_isolation() {
    use razen_engine::domain::proofs::IsolationStatus;
    let root = PrivateRoot::new();
    let owned = workspace(&root);
    let profile = profile();
    let measured_binaries = binaries();
    let before: Vec<_> = fs::read_dir(owned.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    let environment = observe(
        &repo(),
        &owned,
        &profile,
        measured_binaries.clone(),
        &[CatalogId::parse("CON-01").unwrap()],
    )
    .unwrap();
    environment.validate().unwrap();
    assert_eq!(
        environment.hardware_model,
        native_text("/usr/sbin/sysctl", &["-n", "hw.model"])
    );
    assert_eq!(
        environment.logical_cpus.get(),
        native_text("/usr/sbin/sysctl", &["-n", "hw.logicalcpu"])
            .parse::<u64>()
            .unwrap()
    );
    assert_eq!(
        environment.memory_mib.get(),
        native_text("/usr/sbin/sysctl", &["-n", "hw.memsize"])
            .parse::<u64>()
            .unwrap()
            / (1024 * 1024)
    );
    assert_eq!(
        environment.os_version,
        native_text("/usr/bin/sw_vers", &["-productVersion"])
    );
    assert_eq!(
        environment.os_build,
        native_text("/usr/bin/sw_vers", &["-buildVersion"])
    );
    assert!(
        environment
            .kernel
            .contains(&native_text("/usr/bin/uname", &["-r"]))
    );
    let volume = capture(
        Path::new("/bin/df"),
        &[OsStr::new("-P"), owned.path().as_os_str()],
        None,
        limits(),
    )
    .unwrap();
    let volume = String::from_utf8(volume.stdout).unwrap();
    let device = volume
        .lines()
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap();
    assert!(device.starts_with("/dev/disk"));
    let disk_plist = capture(
        Path::new("/usr/sbin/diskutil"),
        &[OsStr::new("info"), OsStr::new("-plist"), OsStr::new(device)],
        None,
        limits(),
    )
    .unwrap();
    let disk_json = capture(
        Path::new("/usr/bin/plutil"),
        &[
            OsStr::new("-convert"),
            OsStr::new("json"),
            OsStr::new("-o"),
            OsStr::new("-"),
            OsStr::new("--"),
            OsStr::new("-"),
        ],
        Some(&disk_plist.stdout),
        limits(),
    )
    .unwrap();
    let disk: serde_json::Value = serde_json::from_slice(&disk_json.stdout).unwrap();
    assert_eq!(
        environment.filesystem,
        disk["FilesystemType"].as_str().unwrap()
    );
    assert_eq!(
        environment.storage,
        format!(
            "solid_state={}; capacity_bytes={}; block_bytes={}",
            disk["SolidState"].as_bool().unwrap(),
            disk["TotalSize"].as_u64().unwrap(),
            disk["DeviceBlockSize"].as_u64().unwrap()
        )
    );
    assert_eq!(environment.os, "macOS");
    assert_eq!(environment.arch, "arm64");
    assert_eq!(environment.isolation_status, IsolationStatus::NotRequired);
    assert_eq!(environment.binary_digests, measured_binaries);
    assert_eq!(
        environment.backend,
        profile.config().external_runner.backend
    );
    assert_eq!(
        environment.guest_os,
        profile.config().external_runner.guest_os
    );
    assert_eq!(
        environment.image_digest.as_str(),
        profile.config().external_runner.image_digest
    );
    assert_eq!(
        environment.component_target,
        profile.config().toolchain.component_target
    );
    let rust = &environment.dependency_versions[&CatalogId::parse("rust").unwrap()];
    let compiled = env!("RAZEN_BUILD_RUSTC").split_whitespace().nth(1).unwrap();
    assert_eq!(rust.as_str(), compiled);
    assert_eq!(rust.as_str(), profile.config().toolchain.rust);
    assert_eq!(
        environment.dependency_versions.len(),
        1,
        "unobserved Lima/bubblewrap cannot be claimed installed"
    );
    assert_eq!(
        environment.lockfile_sha256,
        hash_file(&repo().join("Cargo.lock"))
    );
    assert_eq!(
        environment.component_lockfile_sha256,
        hash_file(&repo().join("fixtures/components/Cargo.lock"))
    );
    assert_eq!(
        environment.wit_sha256,
        hash_file(&repo().join("specs/001-r0-feasibility/contracts/plugin-sdk.wit"))
    );
    for (id, path) in [
        ("scenario-manifest", "fixtures/scenarios/manifest.json"),
        ("contract-scenarios", "fixtures/scenarios/contracts.json"),
        (
            "approved-fixtures",
            "fixtures/scenarios/approved-fixtures.json",
        ),
        (
            "parser-corpus-manifest",
            "fixtures/scenarios/parser-corpus/manifest.json",
        ),
    ] {
        assert_eq!(
            environment.fixture_digests[&CatalogId::parse(id).unwrap()],
            hash_file(&repo().join(path))
        );
    }
    let encoded = serde_json::to_value(&environment).unwrap();
    for field in [
        "guest_package_manifest_sha256",
        "provisioning_sha256",
        "effective_config_sha256",
        "seccomp_sha256",
    ] {
        assert!(
            encoded.get(field).is_none(),
            "unobserved field {field} must be omitted"
        );
    }
    assert!(!encoded.to_string().contains(root.path().to_str().unwrap()));
    assert!(!["unknown", "default", "unavailable"].contains(&environment.filesystem.as_str()));
    assert!(!["unknown", "default", "unavailable"].contains(&environment.storage.as_str()));
    let after: Vec<_> = fs::read_dir(owned.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(
        before, after,
        "observation cannot provision or write into the owned run"
    );
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn environment_missing_reviewed_files_is_error_and_never_executes_repo_tools() {
    use std::os::unix::fs::PermissionsExt;
    let root = PrivateRoot::new();
    let owned = workspace(&root);
    let fake_repo = root.path().join("untrusted-repo");
    fs::create_dir(&fake_repo).unwrap();
    let marker = root.path().join("executed");
    for name in ["rustc", "sysctl", "diskutil", "sw_vers", "lima"] {
        let path = fake_repo.join(name);
        fs::write(&path, format!("#!/bin/sh\ntouch '{}'\n", marker.display())).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    assert!(
        observe(
            &fake_repo,
            &owned,
            &profile(),
            binaries(),
            &[CatalogId::parse("CON-01").unwrap()]
        )
        .is_err()
    );
    assert!(!marker.exists());
    assert!(
        observe(
            &repo(),
            &owned,
            &profile(),
            BTreeMap::new(),
            &[CatalogId::parse("CON-01").unwrap()]
        )
        .is_err()
    );
}

#[test]
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn environment_unsupported_target_never_fabricates_macos_observations() {
    let root = PrivateRoot::new();
    let error = observe(
        &repo(),
        &workspace(&root),
        &profile(),
        binaries(),
        &[CatalogId::parse("CON-01").unwrap()],
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::UnsupportedProtocol);
}

#[test]
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn transport_observation_records_reviewed_source_and_compiled_rama_without_guest_pins() {
    let root = PrivateRoot::new();
    let owned = workspace(&root);
    let observed = observe(
        &repo(),
        &owned,
        &profile(),
        binaries(),
        &[CatalogId::parse("NET-01").unwrap()],
    )
    .unwrap();
    assert_eq!(
        observed.fixture_digests[&CatalogId::parse("transport-scenarios").unwrap()],
        hash_file(&repo().join("fixtures/scenarios/transport.json"))
    );
    assert_eq!(
        observed.dependency_versions[&CatalogId::parse("rama").unwrap()].as_str(),
        razen_engine::adapters::transport::RAMA_VERSION
    );
    assert_eq!(
        observed.isolation_status,
        razen_engine::domain::proofs::IsolationStatus::NotRequired
    );
    assert_eq!(observed.dependency_versions.len(), 2);
    assert!(observed.guest_package_manifest_sha256.is_none());
}
