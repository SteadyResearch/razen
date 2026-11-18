#[path = "support/private_root.rs"]
mod private_root;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use private_root::PrivateRoot;
use razen_engine::adapters::evidence_store::{EvidenceStore, SnapshotReader};
use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::domain::evidence::{
    Artifact, EvidenceRange, EvidenceRef, Header, ObservationProposal, ObservationStatus,
    RedactionStatus, Representation, Snapshot,
};
use razen_engine::domain::values::{CatalogId, Digest, EntityId, MAX_WIRE_INT, WireInt};
use razen_engine::protocol::contracts::{CanonicalFixtures, ContractRecord};
use razen_engine::protocol::error::ErrorCode;
use serde_json::Value;

const BODY: &[u8] = &[0, 0xff, b'a', b'\r', b'\n', 0x80];
const ARTIFACT_LIMIT: usize = 32 * 1_048_576;

fn id(n: u64) -> EntityId {
    EntityId::parse(&format!("00000000-0000-4000-8000-{n:012x}")).unwrap()
}

fn int(n: u64) -> WireInt {
    WireInt::new(n).unwrap()
}

fn workspace(root: &PrivateRoot) -> Arc<OwnedDirectory> {
    Arc::new(OwnedDirectory::create(root.path(), Path::new("run"), id(1)).unwrap())
}

fn reopen(root: &PrivateRoot) -> EvidenceStore {
    EvidenceStore::open(Arc::new(
        OwnedDirectory::open(root.path(), Path::new("run")).unwrap(),
    ))
    .unwrap()
}

fn write_artifact(store: &EvidenceStore, bytes: &[u8]) -> Arc<Artifact> {
    store
        .write_artifact(
            id(2),
            CatalogId::parse("fixture_body").unwrap(),
            id(3),
            bytes,
            RedactionStatus::Original,
        )
        .unwrap()
}

fn snapshot_for(artifact: &Artifact) -> Snapshot {
    Snapshot {
        snapshot_id: id(4),
        project_id: artifact.project_id,
        revision: int(3),
        sha256: artifact.sha256,
        length_bytes: artifact.length_bytes,
        body_ref: artifact.artifact_id,
        representation: Representation::Http1Body,
        headers: vec![
            Header {
                name: "x-fixture".into(),
                value: "first".into(),
            },
            Header {
                name: "x-fixture".into(),
                value: "second".into(),
            },
        ],
        truncated: false,
        derived_from: None,
    }
}

fn reference(snapshot: &Snapshot) -> EvidenceRef {
    EvidenceRef::Snapshot {
        snapshot_id: snapshot.snapshot_id,
        revision: snapshot.revision,
        sha256: snapshot.sha256,
        range: Some(EvidenceRange::new(int(1), int(4)).unwrap()),
    }
}

fn proposal(snapshot: &Snapshot) -> ObservationProposal {
    ObservationProposal {
        proposal_id: id(5),
        project_id: snapshot.project_id,
        rule_id: CatalogId::parse("rule:binary-fixture").unwrap(),
        title: "Binary fixture observation".into(),
        evidence_refs: vec![reference(snapshot)],
        actor_ref: id(6),
        status: ObservationStatus::Proposed,
    }
}

fn installed(store: &EvidenceStore, bytes: &[u8]) -> (Arc<Artifact>, Arc<Snapshot>) {
    let artifact = write_artifact(store, bytes);
    let snapshot = store.install_snapshot(snapshot_for(&artifact)).unwrap();
    (artifact, snapshot)
}

fn private_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

fn files_below(path: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for entry in fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let metadata = fs::symlink_metadata(entry.path()).unwrap();
        if metadata.is_dir() {
            files.extend(files_below(&entry.path()));
        } else {
            assert!(metadata.is_file(), "unexpected non-regular generated entry");
            files.push(entry.path());
        }
    }
    files.sort();
    files
}

fn metadata_for(workspace: &OwnedDirectory, artifact: &Artifact) -> PathBuf {
    // Discover persisted JSON by record contents, not a filename-as-authority convention.
    let needle = artifact.artifact_id.to_string();
    let body_path = workspace.path().join(&artifact.relative_path);
    files_below(workspace.path())
        .into_iter()
        .find(|path| {
            if *path == body_path {
                return false;
            }
            let bytes = fs::read(path).unwrap();
            serde_json::from_slice::<Value>(&bytes).is_ok()
                && bytes
                    .windows(needle.len())
                    .any(|window| window == needle.as_bytes())
                && bytes
                    .windows(b"\"relative_path\"".len())
                    .any(|window| window == b"\"relative_path\"")
        })
        .expect("artifact has actual persistent JSON metadata")
}

fn replace_field(value: &mut Value, field: &str, replacement: &Value) -> usize {
    match value {
        Value::Object(object) => {
            let mut count = 0;
            if let Some(current) = object.get_mut(field) {
                *current = replacement.clone();
                count += 1;
            }
            count
                + object
                    .values_mut()
                    .map(|value| replace_field(value, field, replacement))
                    .sum::<usize>()
        }
        Value::Array(values) => values
            .iter_mut()
            .map(|value| replace_field(value, field, replacement))
            .sum(),
        _ => 0,
    }
}

fn fixture_pack() -> CanonicalFixtures {
    CanonicalFixtures::load(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/scenarios/contracts.json"),
    )
    .unwrap()
}

#[test]
fn owned_store_is_send_sync_and_a_truly_empty_run_reopens_without_evidence() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<EvidenceStore>();
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let store = EvidenceStore::open(workspace).unwrap();
    assert!(store.artifacts().unwrap().is_empty());
    assert!(store.snapshots().unwrap().is_empty());
    assert!(store.proposals(id(2)).unwrap().is_empty());
    drop(store);
    let store = reopen(&root);
    assert!(store.artifacts().unwrap().is_empty());
    assert!(store.snapshots().unwrap().is_empty());
    assert!(store.proposals(id(2)).unwrap().is_empty());
}

#[test]
fn binary_artifacts_snapshots_and_proposals_survive_actual_close_and_reopen() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let store = EvidenceStore::open(workspace.clone()).unwrap();
    let (artifact, snapshot) = installed(&store, BODY);
    let proposed = store.record_proposal(proposal(&snapshot)).unwrap();
    assert_eq!(
        fs::read(workspace.path().join(&artifact.relative_path)).unwrap(),
        BODY
    );
    assert_eq!(artifact.origin_invocation_id, id(3));
    assert_eq!(artifact.sha256, Digest::of(BODY));
    assert_eq!(artifact.length_bytes, int(BODY.len() as u64));
    assert_eq!(proposed.status, ObservationStatus::Proposed);
    drop(store);
    drop(workspace);
    let store = reopen(&root);
    assert_eq!(
        store.artifact(id(2), artifact.artifact_id).unwrap(),
        artifact
    );
    assert_eq!(store.snapshot(id(2), id(4), int(3)).unwrap(), snapshot);
    assert_eq!(store.proposal(id(2), id(5)).unwrap(), proposed);
    assert_eq!(store.proposals(id(2)).unwrap(), vec![proposed]);
    assert_eq!(
        store
            .read_artifact(id(2), artifact.artifact_id, BODY.len())
            .unwrap(),
        BODY
    );
    store.verify_artifact(id(2), artifact.artifact_id).unwrap();
    assert_eq!(
        store
            .snapshot_reader(id(2), id(4), int(3))
            .unwrap()
            .read(int(1), int(4))
            .unwrap(),
        &BODY[1..5]
    );
}

#[test]
fn all_generated_evidence_and_metadata_have_private_modes_and_single_links() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let store = EvidenceStore::open(workspace.clone()).unwrap();
    let (_, snapshot) = installed(&store, BODY);
    store.record_proposal(proposal(&snapshot)).unwrap();
    fn check(path: &Path) {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert_eq!(metadata.uid(), rustix::process::geteuid().as_raw());
        assert_eq!(
            metadata.permissions().mode() & 0o7777,
            if metadata.is_dir() { 0o700 } else { 0o600 }
        );
        if metadata.is_dir() {
            for child in fs::read_dir(path).unwrap() {
                check(&child.unwrap().path());
            }
        } else {
            assert!(metadata.is_file());
            assert_eq!(metadata.nlink(), 1);
        }
    }
    check(workspace.path());
}

#[test]
fn fixture_import_installs_only_public_bytes_with_the_trusted_host_origin() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let store = EvidenceStore::open(workspace.clone()).unwrap();
    let fixtures = fixture_pack();
    store.import_fixtures(&fixtures, id(900)).unwrap();
    let mut artifacts = 0;
    let mut snapshots = 0;
    for document in fixtures.records() {
        match &document.record {
            ContractRecord::Artifact(source) => {
                artifacts += 1;
                let actual = store
                    .artifact(source.project_id, source.artifact_id)
                    .unwrap();
                assert_eq!(actual.origin_invocation_id, id(900));
                assert_eq!(actual.sha256, source.sha256);
                assert_eq!(actual.length_bytes, source.length_bytes);
                assert_eq!(actual.kind, source.kind);
                assert_eq!(actual.redaction_status, source.redaction_status);
                assert_eq!(
                    store
                        .read_artifact(source.project_id, source.artifact_id, ARTIFACT_LIMIT)
                        .unwrap(),
                    fixtures.body(source.artifact_id).unwrap()
                );
                assert_eq!(
                    fs::read(workspace.path().join(&actual.relative_path)).unwrap(),
                    fixtures.body(source.artifact_id).unwrap()
                );
            }
            ContractRecord::Snapshot(source) => {
                snapshots += 1;
                let actual = store
                    .snapshot(source.project_id, source.snapshot_id, source.revision)
                    .unwrap();
                assert_eq!(actual.as_ref(), source);
                assert_eq!(
                    store
                        .snapshot_reader(source.project_id, source.snapshot_id, source.revision)
                        .unwrap()
                        .read(int(0), int(65_536))
                        .unwrap(),
                    fixtures.body(source.body_ref).unwrap()
                );
            }
            ContractRecord::ObservationProposal(source) => {
                assert!(
                    store
                        .proposal(source.project_id, source.proposal_id)
                        .is_err()
                );
                assert!(store.proposals(source.project_id).unwrap().is_empty());
            }
            _ => {}
        }
    }
    assert!(artifacts > 0 && snapshots > 0);
    let previous = store.artifacts().unwrap();
    let previous_snapshots = store.snapshots().unwrap();
    let _duplicate = store.import_fixtures(&fixtures, id(901));
    assert_eq!(store.artifacts().unwrap(), previous);
    assert_eq!(store.snapshots().unwrap(), previous_snapshots);
    drop(store);
    let store = reopen(&root);
    assert_eq!(store.artifacts().unwrap(), previous);
    assert_eq!(store.snapshots().unwrap(), previous_snapshots);
    for artifact in previous {
        assert_eq!(artifact.origin_invocation_id, id(900));
    }
}

#[test]
fn chunk_reads_are_positional_binary_exact_and_bounded_including_eof_and_overflow() {
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    let bytes: Vec<u8> = (0..196_619).map(|index| (index % 256) as u8).collect();
    let (_, snapshot) = installed(&store, &bytes);
    let reader: SnapshotReader = store
        .snapshot_reader(id(2), snapshot.snapshot_id, int(3))
        .unwrap();
    assert_eq!(reader.metadata(), snapshot.as_ref());
    for (offset, count) in [
        (65_536, 65_536),
        (0, 65_536),
        (196_600, 65_536),
        (1, 5),
        (2, 0),
    ] {
        let end = (offset + count).min(bytes.len() as u64) as usize;
        assert_eq!(
            reader.read(int(offset), int(count)).unwrap(),
            bytes[offset as usize..end]
        );
    }
    assert!(
        reader
            .read(int(bytes.len() as u64), int(1))
            .unwrap()
            .is_empty()
    );
    assert!(
        reader
            .read(int(bytes.len() as u64), int(0))
            .unwrap()
            .is_empty()
    );
    for (offset, count) in [
        (0, 65_537),
        (196_620, 1),
        (MAX_WIRE_INT, 1),
        (1, MAX_WIRE_INT),
    ] {
        assert!(
            reader.read(int(offset), int(count)).is_err(),
            "accepted {offset}+{count}"
        );
    }
}

#[test]
fn reader_references_require_the_exact_snapshot_revision_hash_and_half_open_range() {
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    let (artifact, snapshot) = installed(&store, BODY);
    let reader = store.snapshot_reader(id(2), id(4), int(3)).unwrap();
    let range = reader.validate_reference(&reference(&snapshot)).unwrap();
    assert_eq!((range.start(), range.end()), (int(1), int(4)));
    let whole = EvidenceRef::Snapshot {
        snapshot_id: id(4),
        revision: int(3),
        sha256: snapshot.sha256,
        range: None,
    };
    assert_eq!(
        reader.validate_reference(&whole).unwrap().len(),
        int(BODY.len() as u64)
    );
    let empty = EvidenceRef::Snapshot {
        snapshot_id: id(4),
        revision: int(3),
        sha256: snapshot.sha256,
        range: Some(EvidenceRange::new(int(6), int(6)).unwrap()),
    };
    assert!(reader.validate_reference(&empty).unwrap().is_empty());
    for invalid in [
        EvidenceRef::Snapshot {
            snapshot_id: id(99),
            revision: int(3),
            sha256: snapshot.sha256,
            range: None,
        },
        EvidenceRef::Snapshot {
            snapshot_id: id(4),
            revision: int(2),
            sha256: snapshot.sha256,
            range: None,
        },
        EvidenceRef::Snapshot {
            snapshot_id: id(4),
            revision: int(3),
            sha256: Digest::of(b"other"),
            range: None,
        },
        EvidenceRef::Snapshot {
            snapshot_id: id(4),
            revision: int(3),
            sha256: snapshot.sha256,
            range: Some(EvidenceRange {
                range_start: int(4),
                range_end: int(3),
            }),
        },
        EvidenceRef::Snapshot {
            snapshot_id: id(4),
            revision: int(3),
            sha256: snapshot.sha256,
            range: Some(EvidenceRange::new(int(0), int(7)).unwrap()),
        },
        EvidenceRef::Artifact {
            artifact_id: artifact.artifact_id,
            sha256: artifact.sha256,
            range: None,
        },
    ] {
        assert!(reader.validate_reference(&invalid).is_err());
    }
}

#[test]
fn foreign_owners_and_stale_revisions_fail_before_a_reader_or_proposal_is_published() {
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    let (artifact, snapshot) = installed(&store, BODY);
    assert_eq!(
        store
            .artifact(id(99), artifact.artifact_id)
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    assert!(
        store
            .read_artifact(id(99), artifact.artifact_id, BODY.len())
            .is_err()
    );
    assert!(store.verify_artifact(id(99), artifact.artifact_id).is_err());
    assert!(store.snapshot(id(99), id(4), int(3)).is_err());
    assert!(store.snapshot_reader(id(99), id(4), int(3)).is_err());
    assert_eq!(
        store.snapshot(id(2), id(4), int(2)).unwrap_err().code,
        ErrorCode::StaleSnapshot
    );
    assert!(store.snapshot_reader(id(2), id(4), int(4)).is_err());
    let mut foreign = proposal(&snapshot);
    foreign.project_id = id(99);
    assert!(store.record_proposal(foreign).is_err());
    assert!(store.proposals(id(2)).unwrap().is_empty());
    assert!(store.proposals(id(99)).unwrap().is_empty());
    store.record_proposal(proposal(&snapshot)).unwrap();
    assert!(store.proposal(id(99), id(5)).is_err());
    drop(store);
    let store = reopen(&root);
    assert_eq!(store.proposals(id(2)).unwrap().len(), 1);
    assert!(store.proposals(id(99)).unwrap().is_empty());
}

#[test]
fn artifact_read_budgets_never_return_truncation_or_empty_success_for_a_large_body() {
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    let artifact = write_artifact(&store, BODY);
    for max in [0, BODY.len() - 1] {
        assert!(
            store
                .read_artifact(id(2), artifact.artifact_id, max)
                .is_err()
        );
    }
    assert_eq!(
        store
            .read_artifact(id(2), artifact.artifact_id, BODY.len())
            .unwrap(),
        BODY
    );
    let empty = write_artifact(&store, b"");
    assert!(
        store
            .read_artifact(id(2), empty.artifact_id, 0)
            .unwrap()
            .is_empty()
    );
    let before = store.artifacts().unwrap();
    assert!(
        store
            .write_artifact(
                id(2),
                CatalogId::parse("fixture_body").unwrap(),
                id(3),
                &vec![0; ARTIFACT_LIMIT + 1],
                RedactionStatus::Original
            )
            .is_err()
    );
    assert_eq!(store.artifacts().unwrap(), before);
    drop(store);
    assert_eq!(reopen(&root).artifacts().unwrap(), before);
}

#[test]
fn identical_and_changed_artifact_bytes_always_get_new_immutable_host_identities() {
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    let first = write_artifact(&store, BODY);
    let same = write_artifact(&store, BODY);
    let changed = write_artifact(&store, b"changed");
    assert_ne!(first.artifact_id, same.artifact_id);
    assert_ne!(first.relative_path, same.relative_path);
    assert_ne!(first.artifact_id, changed.artifact_id);
    assert_ne!(first.sha256, changed.sha256);
    drop(store);
    let store = reopen(&root);
    assert_eq!(store.artifacts().unwrap().len(), 3);
    assert_eq!(
        store
            .read_artifact(id(2), first.artifact_id, BODY.len())
            .unwrap(),
        BODY
    );
    assert_eq!(
        store.read_artifact(id(2), changed.artifact_id, 7).unwrap(),
        b"changed"
    );
}

#[test]
fn snapshot_install_resolves_actual_owned_artifacts_and_never_rebinds_an_existing_id() {
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    let artifact = write_artifact(&store, BODY);
    let good = snapshot_for(&artifact);
    let mut missing = good.clone();
    missing.body_ref = id(99);
    assert!(store.install_snapshot(missing).is_err());
    let mut foreign = good.clone();
    foreign.project_id = id(99);
    assert!(store.install_snapshot(foreign).is_err());
    let mut wrong_hash = good.clone();
    wrong_hash.sha256 = Digest::of(b"other");
    assert!(store.install_snapshot(wrong_hash).is_err());
    let mut wrong_length = good.clone();
    wrong_length.length_bytes = int(5);
    assert!(store.install_snapshot(wrong_length).is_err());
    assert!(store.snapshots().unwrap().is_empty());
    let canonical = store.install_snapshot(good.clone()).unwrap();
    let second_body = write_artifact(&store, b"mutant");
    let mut replacement = snapshot_for(&second_body);
    replacement.revision = int(4);
    assert!(store.install_snapshot(replacement).is_err());
    let mut substituted_owner = good.clone();
    substituted_owner.project_id = id(99);
    assert!(store.install_snapshot(substituted_owner).is_err());
    let _duplicate = store.install_snapshot(good);
    assert_eq!(store.snapshots().unwrap(), vec![canonical.clone()]);
    drop(store);
    assert_eq!(
        reopen(&root).snapshot(id(2), id(4), int(3)).unwrap(),
        canonical
    );
}

#[test]
fn proposal_references_are_actually_resolved_and_immutable_across_reopen() {
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    let (artifact, snapshot) = installed(&store, BODY);
    for invalid_reference in [
        EvidenceRef::Snapshot {
            snapshot_id: id(99),
            revision: int(3),
            sha256: snapshot.sha256,
            range: None,
        },
        EvidenceRef::Snapshot {
            snapshot_id: id(4),
            revision: int(2),
            sha256: snapshot.sha256,
            range: None,
        },
        EvidenceRef::Snapshot {
            snapshot_id: id(4),
            revision: int(3),
            sha256: Digest::of(b"other"),
            range: None,
        },
        EvidenceRef::Snapshot {
            snapshot_id: id(4),
            revision: int(3),
            sha256: snapshot.sha256,
            range: Some(EvidenceRange::new(int(0), int(MAX_WIRE_INT)).unwrap()),
        },
        EvidenceRef::Artifact {
            artifact_id: id(99),
            sha256: artifact.sha256,
            range: None,
        },
        EvidenceRef::Artifact {
            artifact_id: artifact.artifact_id,
            sha256: Digest::of(b"other"),
            range: None,
        },
    ] {
        let mut invalid = proposal(&snapshot);
        invalid.evidence_refs = vec![invalid_reference];
        assert!(store.record_proposal(invalid).is_err());
        assert!(store.proposals(id(2)).unwrap().is_empty());
    }
    let canonical = store.record_proposal(proposal(&snapshot)).unwrap();
    let mut replacement = canonical.as_ref().clone();
    replacement.title = "replacement must not win".into();
    assert!(store.record_proposal(replacement).is_err());
    let mut foreign = canonical.as_ref().clone();
    foreign.project_id = id(99);
    assert!(store.record_proposal(foreign).is_err());
    drop(store);
    let store = reopen(&root);
    assert_eq!(store.proposal(id(2), id(5)).unwrap(), canonical);
    assert_eq!(store.proposals(id(2)).unwrap(), vec![canonical]);
    let artifact_proposal = ObservationProposal {
        proposal_id: id(7),
        evidence_refs: vec![EvidenceRef::Artifact {
            artifact_id: artifact.artifact_id,
            sha256: artifact.sha256,
            range: Some(EvidenceRange::new(int(0), int(2)).unwrap()),
        }],
        ..proposal(&snapshot)
    };
    store.record_proposal(artifact_proposal).unwrap();
    drop(store);
    assert_eq!(reopen(&root).proposals(id(2)).unwrap().len(), 2);
}

#[test]
fn opening_a_reader_hashes_the_entire_actual_file_not_only_the_requested_prefix() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let store = EvidenceStore::open(workspace.clone()).unwrap();
    let bytes = vec![0x80; 196_619];
    let (artifact, _) = installed(&store, &bytes);
    let file = OpenOptions::new()
        .write(true)
        .open(workspace.path().join(&artifact.relative_path))
        .unwrap();
    file.write_all_at(&[0x81], bytes.len() as u64 - 1).unwrap();
    file.sync_all().unwrap();
    assert!(store.snapshot_reader(id(2), id(4), int(3)).is_err());
    assert!(store.verify_artifact(id(2), artifact.artifact_id).is_err());
    assert!(
        store
            .read_artifact(id(2), artifact.artifact_id, bytes.len())
            .is_err()
    );
    assert!(
        store
            .record_proposal(proposal(&snapshot_for(&artifact)))
            .is_err()
    );
    drop(file);
    drop(store);
    assert!(EvidenceStore::open(workspace).is_err());
}

#[test]
fn an_open_reader_rejects_in_place_changes_even_outside_the_requested_range() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let store = EvidenceStore::open(workspace.clone()).unwrap();
    let (artifact, snapshot) = installed(&store, BODY);
    let reader = store.snapshot_reader(id(2), id(4), int(3)).unwrap();
    assert_eq!(reader.read(int(0), int(1)).unwrap(), &BODY[..1]);
    let file = OpenOptions::new()
        .write(true)
        .open(workspace.path().join(&artifact.relative_path))
        .unwrap();
    file.write_all_at(&[0x81], 5).unwrap();
    file.sync_all().unwrap();
    assert!(reader.read(int(0), int(1)).is_err());
    assert!(reader.validate_reference(&reference(&snapshot)).is_err());
    file.write_all_at(&BODY[5..], 5).unwrap();
    file.sync_all().unwrap();
    assert!(
        reader.read(int(0), int(1)).is_err(),
        "restored bytes must not revive a changed reader"
    );
}

#[test]
fn open_readers_reject_truncation_and_same_byte_path_identity_replacement() {
    for truncate in [false, true] {
        let root = PrivateRoot::new();
        let workspace = workspace(&root);
        let store = EvidenceStore::open(workspace.clone()).unwrap();
        let (artifact, _) = installed(&store, BODY);
        let reader = store.snapshot_reader(id(2), id(4), int(3)).unwrap();
        let path = workspace.path().join(&artifact.relative_path);
        if truncate {
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(2)
                .unwrap();
        } else {
            fs::remove_file(&path).unwrap();
            private_file(&path, BODY);
        }
        assert!(reader.read(int(0), int(1)).is_err());
    }
}

#[test]
fn symlink_hardlink_and_public_mode_substitutions_never_expose_external_bytes() {
    for attack in ["symlink", "hardlink", "public"] {
        let root = PrivateRoot::new();
        let workspace = workspace(&root);
        let store = EvidenceStore::open(workspace.clone()).unwrap();
        let (artifact, _) = installed(&store, BODY);
        let outside = root.path().join("unrelated.bin");
        private_file(&outside, BODY);
        let path = workspace.path().join(&artifact.relative_path);
        match attack {
            "symlink" => {
                fs::remove_file(&path).unwrap();
                symlink(&outside, &path).unwrap();
            }
            "hardlink" => {
                fs::remove_file(&path).unwrap();
                fs::hard_link(&outside, &path).unwrap();
            }
            "public" => fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            store.verify_artifact(id(2), artifact.artifact_id).is_err(),
            "accepted {attack}"
        );
        assert!(
            store
                .read_artifact(id(2), artifact.artifact_id, BODY.len())
                .is_err()
        );
        assert!(store.snapshot_reader(id(2), id(4), int(3)).is_err());
        drop(store);
        assert!(EvidenceStore::open(workspace).is_err());
        assert_eq!(fs::read(&outside).unwrap(), BODY);
    }
}

#[test]
fn symlinked_body_parent_is_rejected_without_traversing_or_modifying_its_target() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let store = EvidenceStore::open(workspace.clone()).unwrap();
    let (artifact, _) = installed(&store, BODY);
    let body_path = workspace.path().join(&artifact.relative_path);
    let parent = body_path.parent().unwrap();
    let relocated = root.path().join("unrelated-tree");
    fs::rename(parent, &relocated).unwrap();
    symlink(&relocated, parent).unwrap();
    assert!(store.verify_artifact(id(2), artifact.artifact_id).is_err());
    assert!(store.snapshot_reader(id(2), id(4), int(3)).is_err());
    assert_eq!(
        fs::read(relocated.join(body_path.file_name().unwrap())).unwrap(),
        BODY
    );
    drop(store);
    assert!(EvidenceStore::open(workspace).is_err());
}

#[test]
fn traversal_absolute_and_identity_substitution_in_persisted_metadata_fail_reopen() {
    for (field, replacement) in [
        ("relative_path", Value::String("../unrelated.bin".into())),
        ("relative_path", Value::String("/tmp/unrelated.bin".into())),
        (
            "relative_path",
            Value::String("bodies/../unrelated.bin".into()),
        ),
        ("project_id", serde_json::to_value(id(99)).unwrap()),
        ("artifact_id", serde_json::to_value(id(99)).unwrap()),
        (
            "sha256",
            serde_json::to_value(Digest::of(b"other")).unwrap(),
        ),
        ("length_bytes", Value::from(5)),
    ] {
        let root = PrivateRoot::new();
        let workspace = workspace(&root);
        let store = EvidenceStore::open(workspace.clone()).unwrap();
        let (artifact, _) = installed(&store, BODY);
        let metadata_path = metadata_for(&workspace, &artifact);
        let mut metadata: Value =
            serde_json::from_slice(&fs::read(&metadata_path).unwrap()).unwrap();
        assert!(replace_field(&mut metadata, field, &replacement) > 0);
        drop(store);
        fs::write(&metadata_path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        assert!(
            EvidenceStore::open(workspace).is_err(),
            "accepted substituted {field}"
        );
    }
}

#[test]
fn corrupt_oversized_or_missing_persisted_metadata_never_reopens_as_an_empty_store() {
    for attack in ["malformed", "oversized", "missing"] {
        let root = PrivateRoot::new();
        let workspace = workspace(&root);
        let store = EvidenceStore::open(workspace.clone()).unwrap();
        let (artifact, _) = installed(&store, BODY);
        let metadata_path = metadata_for(&workspace, &artifact);
        drop(store);
        match attack {
            "malformed" => fs::write(&metadata_path, b"{broken").unwrap(),
            "oversized" => fs::write(&metadata_path, vec![b' '; 16 * 1_048_576]).unwrap(),
            "missing" => fs::remove_file(&metadata_path).unwrap(),
            _ => unreachable!(),
        }
        assert!(
            EvidenceStore::open(workspace).is_err(),
            "accepted {attack} metadata"
        );
    }
}

#[test]
fn failed_writes_never_publish_artifact_snapshot_or_proposal_success_in_memory_or_on_disk() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let store = EvidenceStore::open(workspace.clone()).unwrap();
    let (artifact, snapshot) = installed(&store, BODY);
    let previous_artifacts = store.artifacts().unwrap();
    let previous_snapshots = store.snapshots().unwrap();
    fs::set_permissions(workspace.path(), fs::Permissions::from_mode(0o500)).unwrap();
    assert!(
        store
            .write_artifact(
                id(2),
                CatalogId::parse("fixture_body").unwrap(),
                id(3),
                b"not committed",
                RedactionStatus::Original
            )
            .is_err()
    );
    let mut next = snapshot_for(&artifact);
    next.snapshot_id = id(8);
    assert!(store.install_snapshot(next).is_err());
    assert!(store.record_proposal(proposal(&snapshot)).is_err());
    fs::set_permissions(workspace.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(store.artifacts().unwrap(), previous_artifacts);
    assert_eq!(store.snapshots().unwrap(), previous_snapshots);
    assert!(store.proposal(id(2), id(5)).is_err());
    assert!(store.proposals(id(2)).unwrap().is_empty());
    assert!(store.snapshot(id(2), id(8), int(3)).is_err());
    drop(store);
    let store = reopen(&root);
    assert_eq!(store.artifacts().unwrap(), previous_artifacts);
    assert_eq!(store.snapshots().unwrap(), previous_snapshots);
    assert!(store.proposals(id(2)).unwrap().is_empty());
    assert_eq!(
        store
            .read_artifact(id(2), artifact.artifact_id, BODY.len())
            .unwrap(),
        BODY
    );
}

#[test]
fn immutable_snapshot_catalog_is_finitely_bounded_and_rejects_the_next_record_without_publication()
{
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    let artifact = write_artifact(&store, BODY);
    let mut accepted = 0;
    for index in 0..=4096 {
        let mut snapshot = snapshot_for(&artifact);
        snapshot.snapshot_id = id(10_000 + index);
        match store.install_snapshot(snapshot) {
            Ok(_) => {
                accepted += 1;
                assert!(accepted <= 4096, "catalog exceeded its finite record limit");
            }
            Err(error) => {
                assert_eq!(error.code, ErrorCode::BudgetExhausted);
                break;
            }
        }
    }
    assert!(accepted > 0 && accepted <= 4096);
    assert_eq!(store.snapshots().unwrap().len(), accepted);
    drop(store);
    assert_eq!(reopen(&root).snapshots().unwrap().len(), accepted);
}

#[test]
fn full_run_artifact_history_survives_reopen_without_dropping_original_bytes() {
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    let artifacts: Vec<_> = (0..4_097).map(|_| write_artifact(&store, BODY)).collect();
    drop(store);
    let store = reopen(&root);
    for artifact in artifacts {
        assert_eq!(
            store.artifact(id(2), artifact.artifact_id).unwrap(),
            artifact
        );
        assert_eq!(
            store
                .read_artifact(id(2), artifact.artifact_id, BODY.len())
                .unwrap(),
            BODY
        );
    }
}

#[test]
fn a_reader_owns_its_handle_without_holding_the_directory_lock_or_store_alive() {
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    installed(&store, BODY);
    let reader = store.snapshot_reader(id(2), id(4), int(3)).unwrap();
    let second = write_artifact(&store, b"written while a reader is live");
    assert_ne!(second.artifact_id, reader.metadata().body_ref);
    drop(store);
    assert_eq!(reader.read(int(0), int(6)).unwrap(), BODY);
    drop(reader);
    assert_eq!(reopen(&root).artifacts().unwrap().len(), 2);
}

#[test]
fn metadata_symlinks_hardlinks_and_public_modes_are_rejected_before_catalog_loading() {
    for attack in ["symlink", "hardlink", "public"] {
        let root = PrivateRoot::new();
        let workspace = workspace(&root);
        let store = EvidenceStore::open(workspace.clone()).unwrap();
        let artifact = write_artifact(&store, BODY);
        let metadata_path = metadata_for(&workspace, &artifact);
        let original = fs::read(&metadata_path).unwrap();
        let outside = root.path().join("unrelated-metadata.json");
        private_file(&outside, &original);
        drop(store);
        match attack {
            "symlink" => {
                fs::remove_file(&metadata_path).unwrap();
                symlink(&outside, &metadata_path).unwrap();
            }
            "hardlink" => {
                fs::remove_file(&metadata_path).unwrap();
                fs::hard_link(&outside, &metadata_path).unwrap();
            }
            "public" => {
                fs::set_permissions(&metadata_path, fs::Permissions::from_mode(0o644)).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(
            EvidenceStore::open(workspace).is_err(),
            "accepted {attack} metadata"
        );
        assert_eq!(fs::read(&outside).unwrap(), original);
    }
}

#[test]
fn missing_actual_bytes_are_integrity_failures_not_a_successful_empty_export() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let store = EvidenceStore::open(workspace.clone()).unwrap();
    let (artifact, snapshot) = installed(&store, BODY);
    fs::remove_file(workspace.path().join(&artifact.relative_path)).unwrap();
    assert!(
        store
            .read_artifact(id(2), artifact.artifact_id, BODY.len())
            .is_err()
    );
    assert!(store.verify_artifact(id(2), artifact.artifact_id).is_err());
    assert!(store.snapshot_reader(id(2), id(4), int(3)).is_err());
    assert!(store.record_proposal(proposal(&snapshot)).is_err());
    assert!(store.proposals(id(2)).unwrap().is_empty());
    drop(store);
    assert!(EvidenceStore::open(workspace).is_err());
}

#[test]
fn reopened_records_cannot_be_rebound_by_duplicate_snapshot_or_proposal_writes() {
    let root = PrivateRoot::new();
    let store = EvidenceStore::open(workspace(&root)).unwrap();
    let (_, snapshot) = installed(&store, BODY);
    let canonical = store.record_proposal(proposal(&snapshot)).unwrap();
    drop(store);
    let store = reopen(&root);
    let mut revised = snapshot.as_ref().clone();
    revised.revision = int(4);
    assert!(store.install_snapshot(revised).is_err());
    let mut replaced = canonical.as_ref().clone();
    replaced.actor_ref = id(99);
    assert!(store.record_proposal(replaced).is_err());
    assert_eq!(store.snapshot(id(2), id(4), int(3)).unwrap(), snapshot);
    assert_eq!(store.proposal(id(2), id(5)).unwrap(), canonical);
    drop(store);
    let store = reopen(&root);
    assert_eq!(store.snapshots().unwrap(), vec![snapshot]);
    assert_eq!(store.proposals(id(2)).unwrap(), vec![canonical]);
}

fn readonly_state(workspace: &OwnedDirectory) -> Vec<(PathBuf, Vec<u8>, u64, u32, i64, i64)> {
    files_below(workspace.path())
        .into_iter()
        .map(|path| {
            let bytes = fs::read(&path).unwrap();
            let metadata = fs::metadata(&path).unwrap();
            (
                path,
                bytes,
                metadata.ino(),
                metadata.mode(),
                metadata.mtime(),
                metadata.mtime_nsec(),
            )
        })
        .collect()
}

#[test]
fn readonly_open_never_creates_missing_evidence_or_repairs_missing_layout() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let before = readonly_state(&workspace);
    assert!(EvidenceStore::open_readonly(workspace.clone()).is_err());
    assert!(!workspace.path().join("evidence").exists());
    assert_eq!(readonly_state(&workspace), before);
    let store = EvidenceStore::open(workspace.clone()).unwrap();
    drop(store);
    fs::remove_dir(workspace.path().join("evidence/catalog")).unwrap();
    let before = readonly_state(&workspace);
    assert!(EvidenceStore::open_readonly(workspace.clone()).is_err());
    assert!(!workspace.path().join("evidence/catalog").exists());
    assert_eq!(readonly_state(&workspace), before);
}

#[test]
fn readonly_catalog_reads_real_bytes_and_denies_every_mutator_without_filesystem_changes() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let writer = EvidenceStore::open(workspace.clone()).unwrap();
    let (artifact, snapshot) = installed(&writer, BODY);
    let proposed = writer.record_proposal(proposal(&snapshot)).unwrap();
    drop(writer);
    let before = readonly_state(&workspace);
    let reader = EvidenceStore::open_readonly(workspace.clone()).unwrap();
    assert_eq!(
        reader
            .read_artifact(id(2), artifact.artifact_id, BODY.len())
            .unwrap(),
        BODY
    );
    assert_eq!(reader.snapshots().unwrap(), vec![snapshot.clone()]);
    assert_eq!(reader.proposals(id(2)).unwrap(), vec![proposed]);
    assert_eq!(
        reader
            .snapshot_reader(id(2), id(4), int(3))
            .unwrap()
            .read(int(1), int(4))
            .unwrap(),
        &BODY[1..5]
    );
    assert_eq!(
        reader
            .write_artifact(
                id(2),
                CatalogId::parse("denied").unwrap(),
                id(3),
                b"no",
                RedactionStatus::Original
            )
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        reader
            .install_snapshot(snapshot.as_ref().clone())
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        reader
            .record_proposal(proposal(&snapshot))
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        reader
            .import_fixtures(&fixture_pack(), id(3))
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(readonly_state(&workspace), before);
}

#[test]
fn readonly_shared_leases_exclude_writers_even_after_reads_failed_mutations_and_store_drop() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let writer = EvidenceStore::open(workspace.clone()).unwrap();
    installed(&writer, BODY);
    assert!(
        EvidenceStore::open_readonly(workspace.clone()).is_err(),
        "a live writer is not quiescent"
    );
    drop(writer);
    let first = EvidenceStore::open_readonly(workspace.clone()).unwrap();
    let second = EvidenceStore::open_readonly(workspace.clone()).unwrap();
    let body_reader = first.snapshot_reader(id(2), id(4), int(3)).unwrap();
    assert!(
        first
            .write_artifact(
                id(2),
                CatalogId::parse("denied").unwrap(),
                id(3),
                b"no",
                RedactionStatus::Original
            )
            .is_err()
    );
    assert!(EvidenceStore::open(workspace.clone()).is_err());
    drop(first);
    assert_eq!(
        body_reader.read(int(0), int(BODY.len() as u64)).unwrap(),
        BODY
    );
    assert!(
        EvidenceStore::open(workspace.clone()).is_err(),
        "the second inspector still owns a shared lease"
    );
    drop(second);
    assert!(
        EvidenceStore::open(workspace.clone()).is_err(),
        "a native readonly body reader retains its lease"
    );
    drop(body_reader);
    assert!(EvidenceStore::open(workspace).is_ok());
}

#[test]
fn readonly_open_detects_real_body_tamper_without_rewriting_catalog_or_ledger() {
    let root = PrivateRoot::new();
    let workspace = workspace(&root);
    let writer = EvidenceStore::open(workspace.clone()).unwrap();
    let artifact = write_artifact(&writer, BODY);
    drop(writer);
    fs::write(workspace.path().join(&artifact.relative_path), b"tampered").unwrap();
    let before = readonly_state(&workspace);
    assert!(EvidenceStore::open_readonly(workspace.clone()).is_err());
    assert_eq!(readonly_state(&workspace), before);
}
