#[path = "support/owned_child.rs"]
mod owned_child;
#[path = "support/private_root.rs"]
mod private_root;

#[path = "support/processes.rs"]
mod processes;

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Stdio};

use owned_child::OwnedChild;
use private_root::PrivateRoot;
use processes::{ReceiverFixture, read_file};
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::domain::values::{Digest, EntityId};
use serde_json::{Value, json};

fn workspace(root: &PrivateRoot) -> OwnedDirectory {
    OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new())
        .expect("create an owned run")
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("inspect actual permissions")
        .permissions()
        .mode()
        & 0o7777
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("create unrelated private fixture file");
    file.write_all(bytes).expect("write fixture file");
    file.sync_all().expect("sync fixture file");
}

fn private_dir(path: &Path) {
    DirBuilder::new()
        .mode(0o700)
        .create(path)
        .expect("create private fixture directory");
}

fn receiver() -> ReceiverFixture {
    ReceiverFixture::start(Path::new(env!("CARGO_BIN_EXE_razen-fixture-receiver")))
}

#[test]
fn created_run_marker_directories_and_artifacts_are_actually_private() {
    let root = PrivateRoot::new();
    let run_id = EntityId::new();
    let owned = OwnedDirectory::create(root.path(), Path::new("runs/one"), run_id)
        .expect("create nested owned run");
    assert_eq!(owned.path(), root.path().join("runs/one"));
    assert_eq!(owned.run_id(), run_id);
    assert_eq!(mode(&root.path().join("runs")), 0o700);
    assert_eq!(mode(owned.path()), 0o700);
    let marker_path = owned.path().join(".razen-run.json");
    assert_eq!(mode(&marker_path), 0o600);
    let marker: Value =
        serde_json::from_slice(&read_file(&marker_path)).expect("ownership marker JSON");
    assert_eq!(
        marker,
        json!({
            "version": "0.1.0",
            "run_id": run_id.to_string(),
            "uid": fs::metadata(owned.path()).expect("run metadata").uid(),
        })
    );

    let bytes = b"private\0evidence\xff";
    assert_eq!(
        owned
            .write_new(Path::new("evidence/blobs/raw.bin"), bytes)
            .unwrap(),
        Digest::of(bytes)
    );
    assert_eq!(mode(&owned.path().join("evidence")), 0o700);
    assert_eq!(mode(&owned.path().join("evidence/blobs")), 0o700);
    assert_eq!(mode(&owned.path().join("evidence/blobs/raw.bin")), 0o600);
    let reopened = OwnedDirectory::open(root.path(), Path::new("runs/one")).unwrap();
    assert_eq!(reopened.run_id(), run_id);
    assert_eq!(
        reopened
            .read(Path::new("evidence/blobs/raw.bin"), bytes.len())
            .unwrap(),
        bytes
    );
}

#[test]
fn create_new_is_immutable_and_successful_writes_are_visible_to_reopened_readers() {
    let root = PrivateRoot::new();
    let owned = workspace(&root);
    let artifact = Path::new("evidence/immutable.bin");
    let original = b"first committed artifact";
    assert_eq!(
        owned.write_new(artifact, original).unwrap(),
        Digest::of(original)
    );
    assert!(owned.write_new(artifact, b"replacement").is_err());
    assert!(owned.atomic_write(artifact, b"replacement").is_err());
    assert_eq!(read_file(&owned.path().join(artifact)), original);

    let state = Path::new("ephemeral/state.json");
    assert_eq!(
        owned.atomic_write(state, b"{\"step\":1}").unwrap(),
        Digest::of(b"{\"step\":1}")
    );
    assert_eq!(
        owned.atomic_write(state, b"{\"step\":2}").unwrap(),
        Digest::of(b"{\"step\":2}")
    );
    let reopened = OwnedDirectory::open(root.path(), Path::new("run")).unwrap();
    assert_eq!(reopened.read(state, 10).unwrap(), b"{\"step\":2}");
    assert_eq!(read_file(&owned.path().join(state)), b"{\"step\":2}");
    assert_eq!(mode(&owned.path().join(state)), 0o600);
    assert_eq!(
        fs::read_dir(owned.path().join("ephemeral"))
            .unwrap()
            .count(),
        1,
        "atomic replacement leaves no staging file"
    );
}

#[test]
fn bounded_reads_reject_over_limit_files_without_truncating_or_mutating_them() {
    let root = PrivateRoot::new();
    let owned = workspace(&root);
    let bytes = [0_u8, 255, 17, 42];
    owned
        .write_new(Path::new("evidence/bytes"), &bytes)
        .unwrap();
    assert!(owned.read(Path::new("evidence/bytes"), 3).is_err());
    assert!(owned.read(Path::new("evidence/bytes"), 0).is_err());
    assert_eq!(owned.read(Path::new("evidence/bytes"), 4).unwrap(), bytes);
    assert_eq!(owned.read(Path::new("evidence/bytes"), 100).unwrap(), bytes);
    assert_eq!(read_file(&owned.path().join("evidence/bytes")), bytes);
    assert_eq!(
        owned.write_new(Path::new("evidence/empty"), b"").unwrap(),
        Digest::of(b"")
    );
    assert!(
        owned
            .read(Path::new("evidence/empty"), 0)
            .unwrap()
            .is_empty()
    );
    assert!(owned.read(Path::new("evidence"), 100).is_err());
}

#[test]
fn absolute_traversal_dot_and_empty_components_are_rejected_at_every_entry_point() {
    let root = PrivateRoot::new();
    let owned = workspace(&root);
    private_file(&root.path().join("outside"), b"outside must survive");
    let absolute = root.path().join("outside");
    let invalid = [
        Path::new(""),
        Path::new("."),
        Path::new(".."),
        Path::new("../outside"),
        Path::new("nested/../outside"),
        Path::new("nested/./output"),
        Path::new("nested//output"),
        Path::new("nested/"),
        absolute.as_path(),
    ];
    for relative in invalid {
        assert!(
            OwnedDirectory::create(root.path(), relative, EntityId::new()).is_err(),
            "create accepted unsafe path {relative:?}"
        );
        assert!(
            OwnedDirectory::open(root.path(), relative).is_err(),
            "open accepted unsafe path {relative:?}"
        );
        assert!(
            owned.write_new(relative, b"overwrite").is_err(),
            "write_new accepted unsafe path {relative:?}"
        );
        assert!(
            owned.atomic_write(relative, b"overwrite").is_err(),
            "atomic_write accepted unsafe path {relative:?}"
        );
        assert!(
            owned.read(relative, 1024).is_err(),
            "read accepted unsafe path {relative:?}"
        );
    }
    assert_eq!(
        read_file(&root.path().join("outside")),
        b"outside must survive"
    );
    assert!(!root.path().join("nested").exists());
}

#[test]
fn unmarked_existing_outputs_and_other_runs_cannot_be_claimed_or_overwritten() {
    let root = PrivateRoot::new();
    private_dir(&root.path().join("unrelated"));
    private_file(
        &root.path().join("unrelated/user-data"),
        b"unrelated directory contents",
    );
    private_file(&root.path().join("file-output"), b"unrelated file");
    for relative in ["unrelated", "file-output"] {
        assert!(OwnedDirectory::create(root.path(), Path::new(relative), EntityId::new()).is_err());
        assert!(OwnedDirectory::open(root.path(), Path::new(relative)).is_err());
    }
    let owned = workspace(&root);
    let marker = read_file(&owned.path().join(".razen-run.json"));
    assert!(OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).is_err());
    assert_eq!(read_file(&owned.path().join(".razen-run.json")), marker);
    assert_eq!(
        read_file(&root.path().join("unrelated/user-data")),
        b"unrelated directory contents"
    );
    assert_eq!(
        read_file(&root.path().join("file-output")),
        b"unrelated file"
    );
    assert!(!root.path().join("unrelated/.razen-run.json").exists());
}

#[test]
fn owned_run_open_rejects_unsafe_modes_foreign_uid_and_non_strict_markers() {
    for unsafe_part in ["directory", "marker"] {
        let root = PrivateRoot::new();
        let owned = workspace(&root);
        let path = if unsafe_part == "directory" {
            owned.path().to_path_buf()
        } else {
            owned.path().join(".razen-run.json")
        };
        let unsafe_mode = if unsafe_part == "directory" {
            0o755
        } else {
            0o644
        };
        fs::set_permissions(&path, fs::Permissions::from_mode(unsafe_mode)).unwrap();
        assert!(OwnedDirectory::open(root.path(), Path::new("run")).is_err());
    }

    for malformed in [
        "foreign_uid",
        "version",
        "unknown_field",
        "duplicate_field",
        "invalid_json",
    ] {
        let root = PrivateRoot::new();
        let owned = workspace(&root);
        let marker_path = owned.path().join(".razen-run.json");
        let mut marker: Value = serde_json::from_slice(&read_file(&marker_path)).unwrap();
        let bytes = match malformed {
            "foreign_uid" => {
                marker["uid"] = json!(u64::from(fs::metadata(owned.path()).unwrap().uid()) + 1);
                serde_json::to_vec(&marker).unwrap()
            }
            "version" => {
                marker["version"] = json!("0.2.0");
                serde_json::to_vec(&marker).unwrap()
            }
            "unknown_field" => {
                marker["untrusted"] = json!(true);
                serde_json::to_vec(&marker).unwrap()
            }
            "duplicate_field" => {
                let original = serde_json::to_string(&marker).unwrap();
                format!("{{\"version\":\"0.1.0\",{}", &original[1..]).into_bytes()
            }
            "invalid_json" => b"not JSON".to_vec(),
            _ => unreachable!(),
        };
        fs::write(&marker_path, &bytes).unwrap();
        assert!(
            OwnedDirectory::open(root.path(), Path::new("run")).is_err(),
            "accepted marker with {malformed}"
        );
        assert!(
            owned.cleanup_ephemeral().is_err(),
            "cleanup trusted changed marker with {malformed}"
        );
        assert_eq!(
            read_file(&marker_path),
            bytes,
            "rejected marker must not be repaired or overwritten"
        );
    }
}

#[test]
fn symlinked_run_components_and_file_components_never_expose_or_change_the_target() {
    let root = PrivateRoot::new();
    private_dir(&root.path().join("outside"));
    private_file(&root.path().join("outside/secret"), b"outside secret");
    symlink(root.path().join("outside"), root.path().join("alias")).unwrap();
    for relative in ["alias", "alias/child"] {
        assert!(OwnedDirectory::create(root.path(), Path::new(relative), EntityId::new()).is_err());
        assert!(OwnedDirectory::open(root.path(), Path::new(relative)).is_err());
    }
    let owned = workspace(&root);
    symlink(root.path().join("outside"), owned.path().join("linked-dir")).unwrap();
    symlink(
        root.path().join("outside/secret"),
        owned.path().join("linked-file"),
    )
    .unwrap();
    symlink(
        root.path().join("does-not-exist"),
        owned.path().join("dangling"),
    )
    .unwrap();
    private_dir(&owned.path().join("ephemeral"));
    symlink(
        root.path().join("outside/secret"),
        owned.path().join("ephemeral/state.json"),
    )
    .unwrap();
    for relative in [
        "linked-dir/secret",
        "linked-file",
        "dangling",
        "ephemeral/state.json",
    ] {
        let path = Path::new(relative);
        assert!(owned.read(path, 1024).is_err(), "read followed {relative}");
        assert!(
            owned.write_new(path, b"changed").is_err(),
            "write_new followed {relative}"
        );
        assert!(
            owned.atomic_write(path, b"changed").is_err(),
            "atomic_write followed {relative}"
        );
    }
    assert_eq!(
        read_file(&root.path().join("outside/secret")),
        b"outside secret"
    );
    assert!(!root.path().join("outside/child").exists());
    assert!(!root.path().join("does-not-exist").exists());
    assert!(
        fs::symlink_metadata(owned.path().join("ephemeral/state.json"))
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn an_existing_handle_cannot_clean_a_run_whose_recorded_identity_changed() {
    let root = PrivateRoot::new();
    let owned = workspace(&root);
    owned
        .write_new(
            Path::new("ephemeral/keep"),
            b"not the original owner's data",
        )
        .unwrap();
    let marker_path = owned.path().join(".razen-run.json");
    let mut marker: Value = serde_json::from_slice(&read_file(&marker_path)).unwrap();
    let replacement_id = EntityId::new();
    marker["run_id"] = json!(replacement_id.to_string());
    fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
    assert!(
        owned.cleanup_ephemeral().is_err(),
        "cleanup must revalidate the recorded run identity"
    );
    assert_eq!(
        read_file(&owned.path().join("ephemeral/keep")),
        b"not the original owner's data"
    );
    assert_eq!(
        OwnedDirectory::open(root.path(), Path::new("run"))
            .unwrap()
            .run_id(),
        replacement_id
    );
}

#[test]
fn marker_symlinks_and_mutable_output_directories_are_not_replaced() {
    let root = PrivateRoot::new();
    let owned = workspace(&root);
    let marker = owned.path().join(".razen-run.json");
    let saved_marker = root.path().join("saved-marker");
    fs::rename(&marker, &saved_marker).unwrap();
    symlink(&saved_marker, &marker).unwrap();
    assert!(OwnedDirectory::open(root.path(), Path::new("run")).is_err());
    assert!(owned.cleanup_ephemeral().is_err());
    assert!(
        owned
            .atomic_write(Path::new(".razen-run.json"), b"replacement")
            .is_err()
    );
    assert!(
        fs::symlink_metadata(&marker)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let second = OwnedDirectory::create(root.path(), Path::new("second"), EntityId::new()).unwrap();
    private_dir(&second.path().join("run.json"));
    private_file(
        &second.path().join("run.json/user-data"),
        b"unrelated nested data",
    );
    assert!(
        second
            .atomic_write(Path::new("run.json"), b"replacement")
            .is_err()
    );
    assert_eq!(
        read_file(&second.path().join("run.json/user-data")),
        b"unrelated nested data"
    );
}

#[test]
fn atomic_replacement_is_limited_to_explicit_mutable_metadata_classes() {
    let root = PrivateRoot::new();
    let owned = workspace(&root);
    for relative in [
        "run.json",
        "results.json",
        "exit.json",
        "review.json",
        "ephemeral/state.json",
    ] {
        let path = Path::new(relative);
        owned.atomic_write(path, b"first").unwrap();
        assert_eq!(
            owned.atomic_write(path, b"second").unwrap(),
            Digest::of(b"second")
        );
        assert_eq!(owned.read(path, 6).unwrap(), b"second");
        assert_eq!(mode(&owned.path().join(path)), 0o600);
    }
    let marker_before = read_file(&owned.path().join(".razen-run.json"));
    assert!(
        owned
            .atomic_write(Path::new(".razen-run.json"), b"changed")
            .is_err()
    );
    assert_eq!(
        read_file(&owned.path().join(".razen-run.json")),
        marker_before
    );
    for relative in [
        "evidence/raw",
        "profile.json",
        "versions.json",
        "cases.json",
        "trace.jsonl",
        "ledger.sqlite",
        "ledger.sqlite-wal",
        "ledger.sqlite-shm",
        "other.json",
    ] {
        let path = Path::new(relative);
        assert!(owned.atomic_write(path, b"unapproved creation").is_err());
        owned.write_new(path, b"immutable original").unwrap();
        assert!(owned.atomic_write(path, b"unapproved replacement").is_err());
        assert_eq!(read_file(&owned.path().join(path)), b"immutable original");
    }
}

#[test]
fn cleanup_removes_only_owned_ephemeral_data_and_preserves_evidence_ledger_and_other_runs() {
    let root = PrivateRoot::new();
    let owned = workspace(&root);
    let other =
        OwnedDirectory::create(root.path(), Path::new("other-run"), EntityId::new()).unwrap();
    other
        .write_new(Path::new("ephemeral/keep"), b"other run")
        .unwrap();
    private_file(&root.path().join("unrelated"), b"outside run");
    for relative in [
        "evidence/raw",
        "ledger.sqlite",
        "ledger.sqlite-wal",
        "run.json",
        "trace.jsonl",
    ] {
        owned
            .write_new(Path::new(relative), relative.as_bytes())
            .unwrap();
    }
    let marker = read_file(&owned.path().join(".razen-run.json"));
    owned
        .write_new(Path::new("ephemeral/nested/work"), b"throwaway")
        .unwrap();
    owned.cleanup_ephemeral().unwrap();
    assert!(!owned.path().join("ephemeral/nested/work").exists());
    if owned.path().join("ephemeral").exists() {
        assert_eq!(
            fs::read_dir(owned.path().join("ephemeral"))
                .unwrap()
                .count(),
            0
        );
    }
    owned.cleanup_ephemeral().unwrap();
    for relative in [
        "evidence/raw",
        "ledger.sqlite",
        "ledger.sqlite-wal",
        "run.json",
        "trace.jsonl",
    ] {
        assert_eq!(read_file(&owned.path().join(relative)), relative.as_bytes());
    }
    assert_eq!(read_file(&owned.path().join(".razen-run.json")), marker);
    assert_eq!(
        other.read(Path::new("ephemeral/keep"), 9).unwrap(),
        b"other run"
    );
    assert_eq!(read_file(&root.path().join("unrelated")), b"outside run");
    OwnedDirectory::open(root.path(), Path::new("run")).unwrap();
}

#[test]
fn cleanup_refuses_symlink_escape_and_never_deletes_external_data() {
    for nested in [false, true] {
        let root = PrivateRoot::new();
        let owned = workspace(&root);
        private_dir(&root.path().join("outside"));
        private_file(&root.path().join("outside/keep"), b"external data");
        owned
            .write_new(Path::new("evidence/keep"), b"evidence")
            .unwrap();
        let link = if nested {
            private_dir(&owned.path().join("ephemeral"));
            owned.path().join("ephemeral/escape")
        } else {
            owned.path().join("ephemeral")
        };
        symlink(root.path().join("outside"), &link).unwrap();
        assert!(
            owned.cleanup_ephemeral().is_err(),
            "cleanup must reject unsafe symlink resolution"
        );
        assert_eq!(
            read_file(&root.path().join("outside/keep")),
            b"external data"
        );
        assert_eq!(
            owned.read(Path::new("evidence/keep"), 8).unwrap(),
            b"evidence"
        );
    }
}

#[test]
fn authenticated_receiver_counts_every_post_including_duplicates() {
    let mut receiver = receiver();
    let action = EntityId::new().to_string();
    let other = EntityId::new().to_string();
    let count_route = format!("/count/{action}");
    let effect_route = format!("/effect/{action}");
    assert_eq!(receiver.authorized("GET", &count_route).count(&action), 0);
    assert_eq!(receiver.authorized("POST", &effect_route).count(&action), 1);
    assert_eq!(receiver.authorized("POST", &effect_route).count(&action), 2);
    assert_eq!(
        receiver.authorized("GET", &count_route).count(&action),
        2,
        "an independent GET must observe both duplicate POST effects"
    );
    assert_eq!(
        receiver
            .authorized("GET", &format!("/count/{other}"))
            .count(&other),
        0
    );
    assert_eq!(mode(receiver.root()), 0o700);
    assert_eq!(mode(&receiver.root().join("token")), 0o600);
    assert!(
        receiver.state_path().is_file(),
        "counts must have an actual independent state database"
    );
    let database = fs::read(receiver.state_path()).unwrap();
    assert!(
        database.starts_with(b"SQLite format 3\0"),
        "receiver state is SQLite, not a JSON stand-in"
    );
    receiver.assert_running();
}

#[test]
fn unauthorized_and_invalid_receiver_requests_have_no_effect_on_a_healthy_counter() {
    let mut receiver = receiver();
    let action = EntityId::new().to_string();
    let effect_route = format!("/effect/{action}");
    let count_route = format!("/count/{action}");
    assert_eq!(receiver.authorized("POST", &effect_route).count(&action), 1);
    let wrong = format!("Bearer wrong-{}", EntityId::new());
    let wrong_scheme = format!("Basic {}", receiver.token());
    for authorization in [
        None,
        Some(wrong.as_str()),
        Some(wrong_scheme.as_str()),
        Some("Bearer"),
    ] {
        assert_eq!(
            receiver
                .request("POST", &effect_route, authorization)
                .status,
            401
        );
        assert_eq!(
            receiver.request("GET", &count_route, authorization).status,
            401
        );
        assert_eq!(
            receiver.authorized("GET", &count_route).count(&action),
            1,
            "denied requests must not increment an otherwise reachable receiver"
        );
    }
    assert_eq!(
        receiver.authorized("POST", "/effect/not-a-uuid").status,
        400
    );
    assert_eq!(receiver.authorized("GET", "/count/not-a-uuid").status, 400);
    assert_eq!(receiver.authorized("GET", &count_route).count(&action), 1);
    assert_eq!(
        receiver.authorized("POST", &effect_route).count(&action),
        2,
        "receiver remains functional after every denial"
    );
    receiver.assert_running();
}

#[test]
fn receiver_remains_healthy_when_a_separately_owned_sleep_child_is_sigkilled() {
    let mut receiver = receiver();
    let mut unrelated_child = OwnedChild::sleep();
    unrelated_child.assert_running();
    let action = EntityId::new().to_string();
    let effect_route = format!("/effect/{action}");
    let count_route = format!("/count/{action}");
    assert_eq!(receiver.authorized("POST", &effect_route).count(&action), 1);
    let status = unrelated_child.kill_and_wait();
    assert_eq!(
        status.signal(),
        Some(9),
        "the separate owned child really received SIGKILL"
    );
    receiver.assert_running();
    assert_eq!(receiver.authorized("GET", &count_route).count(&action), 1);
    assert_eq!(receiver.authorized("POST", &effect_route).count(&action), 2);
    assert_eq!(receiver.authorized("GET", &count_route).count(&action), 2);
    receiver.assert_running();
}

#[test]
fn receiver_counter_is_committed_to_its_own_state_database() {
    let mut receiver = receiver();
    let action = EntityId::new().to_string();
    let effect_route = format!("/effect/{action}");
    let count_route = format!("/count/{action}");
    assert_eq!(receiver.authorized("POST", &effect_route).count(&action), 1);
    assert_eq!(receiver.authorized("POST", &effect_route).count(&action), 2);
    receiver.restart();
    assert_eq!(receiver.authorized("GET", &count_route).count(&action), 2);
    assert_eq!(receiver.authorized("POST", &effect_route).count(&action), 3);
    receiver.assert_running();
}

#[test]
fn receiver_refuses_non_loopback_binding_and_public_token_files() {
    for (bind, token_mode) in [("0.0.0.0:0", 0o600), ("127.0.0.1:0", 0o644)] {
        let root = PrivateRoot::new();
        let token_path = root.path().join("token");
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        private_file(&token_path, token.as_bytes());
        fs::set_permissions(&token_path, fs::Permissions::from_mode(token_mode)).unwrap();
        let mut child = OwnedChild::spawn(
            Command::new(env!("CARGO_BIN_EXE_razen-fixture-receiver"))
                .args(["--bind", bind, "--token-file"])
                .arg(&token_path)
                .arg("--state")
                .arg(root.path().join("counter.sqlite3"))
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null()),
        );
        assert!(
            !child.wait_for_exit().success(),
            "receiver accepted unsafe startup configuration"
        );
    }
}
