use std::borrow::Cow;

use razen_engine::domain::evidence::{Artifact, EvidenceRef, ObservationProposal, Patch, Snapshot};
use razen_engine::domain::values::{Digest, EntityId, MAX_WIRE_INT, WireInt};
use razen_engine::protocol::error::ErrorCode;
use serde::{Serialize, de::DeserializeOwned};
use serde_json::{Value, json};

const BODY: &[u8] = &[0x00, 0xff, b'a', b'\r', b'\n', 0x80];

fn id(n: u64) -> EntityId {
    EntityId::parse(&format!("00000000-0000-4000-8000-{n:012x}")).unwrap()
}

fn int(n: u64) -> WireInt {
    WireInt::new(n).unwrap()
}

fn snapshot_json() -> Value {
    json!({
        "snapshot_id": id(1), "project_id": id(2), "revision": 3,
        "sha256": Digest::of(BODY), "length_bytes": BODY.len(), "body_ref": id(3),
        "representation": "http1_body",
        "headers": [
            {"name": "content-type", "value": "application/octet-stream"},
            {"name": "x-fixture", "value": "first"},
            {"name": "x-fixture", "value": "second"}
        ],
        "truncated": false
    })
}

fn snapshot() -> Snapshot {
    serde_json::from_value(snapshot_json()).unwrap()
}

fn artifact_json() -> Value {
    json!({
        "artifact_id": id(4), "project_id": id(2), "kind": "fixture_body",
        "relative_path": "bodies/binary.bin", "sha256": Digest::of(BODY),
        "length_bytes": BODY.len(), "origin_invocation_id": id(5),
        "redaction_status": "original"
    })
}

fn patch_json(operations: Value) -> Value {
    json!({
        "patch_id": id(6), "project_id": id(2), "base_snapshot_id": id(1),
        "base_revision": 3, "base_sha256": Digest::of(BODY),
        "operations": operations, "actor_ref": id(7)
    })
}

fn proposal_json() -> Value {
    json!({
        "proposal_id": id(8), "project_id": id(2), "rule_id": "rule:binary-fixture",
        "title": "Binary fixture observation", "evidence_refs": [{
            "snapshot_id": id(1), "revision": 3, "sha256": Digest::of(BODY),
            "range_start": 0, "range_end": 2
        }], "actor_ref": id(7), "status": "proposed"
    })
}

fn strict_record<T: DeserializeOwned + Serialize>(document: Value, required: &[&str]) {
    let parsed: T = serde_json::from_value(document.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), document);
    for field in required {
        let mut missing = document.clone();
        missing.as_object_mut().unwrap().remove(*field);
        assert!(
            serde_json::from_value::<T>(missing).is_err(),
            "missing {field}"
        );
    }
    let mut extra = document.clone();
    extra["unreviewed_extension"] = json!(true);
    assert!(serde_json::from_value::<T>(extra).is_err());
    let first = required[0];
    let encoded = serde_json::to_string(&document).unwrap();
    let duplicated = format!("{{\"{first}\":{},{}", document[first], &encoded[1..]);
    assert!(
        serde_json::from_str::<T>(&duplicated).is_err(),
        "duplicate {first}"
    );
}

#[test]
fn canonical_evidence_records_round_trip_without_defaulting_required_fields() {
    strict_record::<Snapshot>(
        snapshot_json(),
        &[
            "snapshot_id",
            "project_id",
            "revision",
            "sha256",
            "length_bytes",
            "body_ref",
            "representation",
            "headers",
            "truncated",
        ],
    );
    strict_record::<Artifact>(
        artifact_json(),
        &[
            "artifact_id",
            "project_id",
            "kind",
            "relative_path",
            "sha256",
            "length_bytes",
            "origin_invocation_id",
            "redaction_status",
        ],
    );
    strict_record::<Patch>(
        patch_json(json!([])),
        &[
            "patch_id",
            "project_id",
            "base_snapshot_id",
            "base_revision",
            "base_sha256",
            "operations",
            "actor_ref",
        ],
    );
    strict_record::<ObservationProposal>(
        proposal_json(),
        &[
            "proposal_id",
            "project_id",
            "rule_id",
            "title",
            "evidence_refs",
            "actor_ref",
            "status",
        ],
    );
}

#[test]
fn evidence_variants_require_exact_discriminating_fields_and_paired_non_null_ranges() {
    for document in [
        json!({"snapshot_id": id(1), "revision": 3, "sha256": Digest::of(BODY)}),
        json!({"snapshot_id": id(1), "revision": 3, "sha256": Digest::of(BODY), "range_start": 0, "range_end": 6}),
        json!({"artifact_id": id(4), "sha256": Digest::of(BODY)}),
        json!({"artifact_id": id(4), "sha256": Digest::of(BODY), "range_start": 6, "range_end": 6}),
    ] {
        let parsed: EvidenceRef = serde_json::from_value(document.clone()).unwrap();
        assert_eq!(serde_json::to_value(parsed).unwrap(), document);
        for field in ["range_start", "range_end"] {
            let mut nullable = document.clone();
            nullable[field] = Value::Null;
            assert!(serde_json::from_value::<EvidenceRef>(nullable).is_err());
        }
    }
    for document in [
        json!({"snapshot_id": id(1), "sha256": Digest::of(BODY)}),
        json!({"artifact_id": id(4), "revision": 0, "sha256": Digest::of(BODY)}),
        json!({"artifact_id": id(4), "snapshot_id": id(1), "revision": 3, "sha256": Digest::of(BODY)}),
        json!({"snapshot_id": id(1), "revision": 3, "sha256": Digest::of(BODY), "range_start": 0}),
        json!({"artifact_id": id(4), "sha256": Digest::of(BODY), "range_end": 1}),
        json!({"snapshot_id": id(1), "revision": null, "sha256": Digest::of(BODY)}),
        json!({"artifact_id": id(4), "sha256": Digest::of(BODY), "range_start": 2, "range_end": 1}),
        json!({"artifact_id": id(4), "sha256": Digest::of(BODY), "range_start": -1, "range_end": 1}),
        json!({"artifact_id": id(4), "sha256": Digest::of(BODY), "range_start": 0, "range_end": 9007199254740992_u64}),
        json!({"artifact_id": id(4), "sha256": Digest::of(BODY), "authority": "owner"}),
    ] {
        assert!(
            serde_json::from_value::<EvidenceRef>(document.clone()).is_err(),
            "accepted {document}"
        );
    }
    let duplicate = format!(
        "{{\"artifact_id\":\"{}\",\"sha256\":\"{}\",\"sha256\":\"{}\"}}",
        id(4),
        Digest::of(BODY),
        Digest::of(b"other")
    );
    assert!(serde_json::from_str::<EvidenceRef>(&duplicate).is_err());
}

#[test]
fn references_resolve_only_against_owned_current_canonical_records_and_actual_bytes() {
    let canonical = snapshot();
    let reference: EvidenceRef = serde_json::from_value(json!({
        "snapshot_id": id(1), "revision": 3, "sha256": Digest::of(BODY),
        "range_start": 1, "range_end": 4
    }))
    .unwrap();
    let range = reference
        .validate_snapshot(id(2), int(3), &canonical, BODY)
        .unwrap();
    assert_eq!((range.start().get(), range.end().get()), (1, 4));
    assert_eq!(
        reference
            .validate_snapshot(id(99), int(3), &canonical, BODY)
            .unwrap_err()
            .code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        reference
            .validate_snapshot(id(2), int(4), &canonical, BODY)
            .unwrap_err()
            .code,
        ErrorCode::StaleSnapshot
    );
    assert_eq!(
        reference
            .validate_snapshot(id(2), int(3), &canonical, b"broken")
            .unwrap_err()
            .code,
        ErrorCode::IntegrityError
    );
    let mut foreign_record = snapshot_json();
    foreign_record["project_id"] = json!(id(99));
    let foreign: Snapshot = serde_json::from_value(foreign_record).unwrap();
    assert!(
        reference
            .validate_snapshot(id(2), int(3), &foreign, BODY)
            .is_err()
    );
    for (field, replacement) in [
        ("snapshot_id", json!(id(99))),
        ("revision", json!(2)),
        ("sha256", json!(Digest::of(b"other"))),
        ("range_end", json!(7)),
    ] {
        let mut invalid = serde_json::to_value(reference).unwrap();
        invalid[field] = replacement;
        let invalid: EvidenceRef = serde_json::from_value(invalid).unwrap();
        assert!(
            invalid
                .validate_snapshot(id(2), int(3), &canonical, BODY)
                .is_err(),
            "accepted {field}"
        );
    }
    let artifact: Artifact = serde_json::from_value(artifact_json()).unwrap();
    assert!(reference.validate_artifact(id(2), &artifact, BODY).is_err());
    let artifact_ref: EvidenceRef = serde_json::from_value(json!({
        "artifact_id": id(4), "sha256": Digest::of(BODY)
    }))
    .unwrap();
    assert_eq!(
        artifact_ref
            .validate_artifact(id(2), &artifact, BODY)
            .unwrap()
            .len()
            .get(),
        6
    );
    assert!(
        artifact_ref
            .validate_artifact(id(99), &artifact, BODY)
            .is_err()
    );
    assert!(
        artifact_ref
            .validate_artifact(id(2), &artifact, b"mutant")
            .is_err()
    );
    assert!(
        artifact_ref
            .validate_snapshot(id(2), int(3), &canonical, BODY)
            .is_err()
    );
    let mut substituted = artifact_json();
    substituted["artifact_id"] = json!(id(99));
    assert!(
        artifact_ref
            .validate_artifact(id(2), &serde_json::from_value(substituted).unwrap(), BODY)
            .is_err()
    );
}

#[test]
fn body_reads_preserve_binary_bytes_and_check_count_offset_and_chunk_limits() {
    let canonical = snapshot();
    canonical.validate_bytes(id(2), int(3), BODY).unwrap();
    let read = canonical
        .read_bytes(id(2), int(3), BODY, int(1), int(4))
        .unwrap();
    assert_eq!(read, &[0xff, b'a', b'\r', b'\n']);
    assert_eq!(read.as_ptr(), BODY[1..].as_ptr());
    assert!(
        canonical
            .read_bytes(id(2), int(3), BODY, int(6), int(1))
            .unwrap()
            .is_empty()
    );
    assert!(
        canonical
            .read_bytes(id(2), int(3), BODY, int(7), int(1))
            .is_err()
    );
    assert!(
        canonical
            .read_bytes(id(2), int(3), BODY, int(1), int(MAX_WIRE_INT))
            .is_err()
    );
    assert!(
        canonical
            .read_bytes(id(2), int(3), BODY, int(MAX_WIRE_INT), int(1))
            .is_err()
    );
    assert!(
        canonical
            .read_bytes(id(2), int(3), BODY, int(0), int(65_537))
            .is_err()
    );
    assert!(
        canonical
            .read_bytes(id(99), int(3), BODY, int(0), int(1))
            .is_err()
    );
    assert!(
        canonical
            .read_bytes(id(2), int(4), BODY, int(0), int(1))
            .is_err()
    );
    assert!(
        canonical
            .read_bytes(id(2), int(3), b"broken", int(0), int(1))
            .is_err()
    );
}

#[test]
fn header_only_and_empty_patches_borrow_original_bytes_but_create_new_snapshot_identity() {
    let original = snapshot();
    let before = serde_json::to_value(&original).unwrap();
    for operations in [
        json!([]),
        json!([{
            "op": "replace_headers", "headers": [
                {"name": "x-fixture", "value": "first"},
                {"name": "x-fixture", "value": "second"},
                {"name": "x-review", "value": "checked"}
            ]
        }]),
    ] {
        let patch: Patch = serde_json::from_value(patch_json(operations.clone())).unwrap();
        let derived = patch
            .apply(id(2), int(3), &original, BODY, id(10), id(11))
            .unwrap();
        assert!(matches!(derived.body, Cow::Borrowed(_)));
        assert_eq!(derived.body.as_ref(), BODY);
        let encoded = serde_json::to_value(&derived.snapshot).unwrap();
        assert_eq!(encoded["snapshot_id"], json!(id(10)));
        assert_eq!(encoded["revision"], 4);
        assert_eq!(encoded["derived_from"], json!(id(1)));
        assert_eq!(encoded["body_ref"], json!(id(3)));
        assert_eq!(encoded["sha256"], json!(Digest::of(BODY)));
        if !operations.as_array().unwrap().is_empty() {
            assert_eq!(encoded["headers"], operations[0]["headers"]);
        } else {
            assert_eq!(encoded["headers"], before["headers"]);
        }
        assert_eq!(serde_json::to_value(&original).unwrap(), before);
    }
}

#[test]
fn binary_replacement_creates_owned_derived_content_and_cannot_reuse_original_identity() {
    let original = snapshot();
    let patch: Patch = serde_json::from_value(patch_json(json!([{
        "op": "replace_body", "range_start": 1, "range_end": 3, "bytes_base64": "gAE="
    }])))
    .unwrap();
    let derived = patch
        .apply(id(2), int(3), &original, BODY, id(10), id(11))
        .unwrap();
    let expected = [0x00, 0x80, 0x01, b'\r', b'\n', 0x80];
    assert_eq!(derived.body.as_ref(), expected);
    assert!(matches!(derived.body, Cow::Owned(_)));
    let encoded = serde_json::to_value(&derived.snapshot).unwrap();
    assert_eq!(encoded["sha256"], json!(Digest::of(&expected)));
    assert_eq!(encoded["body_ref"], json!(id(11)));
    assert_eq!(encoded["representation"], "http1_body");
    assert_eq!(encoded["headers"], snapshot_json()["headers"]);
    derived
        .snapshot
        .validate_bytes(id(2), int(4), derived.body.as_ref())
        .unwrap();
    assert!(
        patch
            .apply(id(2), int(3), &original, BODY, id(1), id(11))
            .is_err()
    );
    assert!(
        patch
            .apply(id(2), int(3), &original, BODY, id(10), id(3))
            .is_err()
    );
    original.validate_bytes(id(2), int(3), BODY).unwrap();
}

#[test]
fn stale_foreign_hash_mismatched_overflowed_or_incomplete_patches_never_change_the_base() {
    let original = snapshot();
    let before = serde_json::to_value(&original).unwrap();
    let valid = patch_json(json!([]));
    for (field, replacement) in [
        ("project_id", json!(id(99))),
        ("base_snapshot_id", json!(id(99))),
        ("base_revision", json!(2)),
        ("base_sha256", json!(Digest::of(b"other"))),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = replacement;
        let patch: Patch = serde_json::from_value(invalid).unwrap();
        assert!(
            patch
                .apply(id(2), int(3), &original, BODY, id(10), id(11))
                .is_err(),
            "accepted {field}"
        );
    }
    let patch: Patch = serde_json::from_value(valid).unwrap();
    assert!(
        patch
            .apply(id(99), int(3), &original, BODY, id(10), id(11))
            .is_err()
    );
    assert!(
        patch
            .apply(id(2), int(4), &original, BODY, id(10), id(11))
            .is_err()
    );
    assert!(
        patch
            .apply(id(2), int(3), &original, b"broken", id(10), id(11))
            .is_err()
    );
    let mut overflowed = snapshot_json();
    overflowed["revision"] = json!(MAX_WIRE_INT);
    let overflowed: Snapshot = serde_json::from_value(overflowed).unwrap();
    let mut overflow_patch = patch_json(json!([]));
    overflow_patch["base_revision"] = json!(MAX_WIRE_INT);
    let overflow_patch: Patch = serde_json::from_value(overflow_patch).unwrap();
    assert!(
        overflow_patch
            .apply(id(2), int(MAX_WIRE_INT), &overflowed, BODY, id(10), id(11))
            .is_err()
    );
    let mut truncated = snapshot_json();
    truncated["truncated"] = json!(true);
    let truncated: Snapshot = serde_json::from_value(truncated).unwrap();
    let edit: Patch = serde_json::from_value(patch_json(json!([{
        "op": "replace_body", "range_start": 0, "range_end": 1, "bytes_base64": "AQ=="
    }])))
    .unwrap();
    assert!(
        edit.apply(id(2), int(3), &truncated, BODY, id(10), id(11))
            .is_err()
    );
    assert_eq!(serde_json::to_value(&original).unwrap(), before);
    assert_eq!(BODY, &[0x00, 0xff, b'a', b'\r', b'\n', 0x80]);
}

#[test]
fn patch_operations_reject_invalid_ranges_base64_unknown_fields_and_ambiguous_framing() {
    for operation in [
        json!({"op": "replace_body", "range_start": 2, "range_end": 1, "bytes_base64": "AQ=="}),
        json!({"op": "replace_body", "range_start": 0, "range_end": 9007199254740992_u64, "bytes_base64": "AQ=="}),
        json!({"op": "replace_body", "range_start": 0, "range_end": 1, "bytes_base64": "%%%"}),
        json!({"op": "replace_body", "range_start": 0, "range_end": 1, "bytes_base64": "AQ==", "scope": "all"}),
        json!({"op": "send_request"}),
        json!({"op": "replace_headers", "headers": [{"name": "x-fixture", "value": "ok\r\ninjected: yes"}]}),
    ] {
        assert!(serde_json::from_value::<Patch>(patch_json(json!([operation]))).is_err());
    }
    let original = snapshot();
    for operations in [
        json!([{"op": "replace_body", "range_start": 0, "range_end": 7, "bytes_base64": "AQ=="}]),
        json!([{"op": "replace_headers", "headers": [
            {"name": "content-length", "value": "6"}, {"name": "transfer-encoding", "value": "chunked"}
        ]}]),
        json!([{"op": "replace_headers", "headers": [
            {"name": "content-length", "value": "6"}, {"name": "content-length", "value": "7"}
        ]}]),
        json!([{"op": "replace_headers", "headers": [{"name": "content-length", "value": "5"}]}]),
    ] {
        let patch: Patch = serde_json::from_value(patch_json(operations)).unwrap();
        assert!(
            patch
                .apply(id(2), int(3), &original, BODY, id(10), id(11))
                .is_err()
        );
    }
}

#[test]
fn h2_snapshots_are_explicit_semantic_representations_and_derived_views_keep_separate_offsets() {
    let mut h2 = snapshot_json();
    h2["representation"] = json!("http2_semantic_body");
    let h2: Snapshot = serde_json::from_value(h2).unwrap();
    assert_eq!(
        serde_json::to_value(&h2).unwrap()["representation"],
        "http2_semantic_body"
    );
    h2.validate_bytes(id(2), int(3), BODY).unwrap();
    let patch: Patch = serde_json::from_value(patch_json(json!([{
        "op": "replace_headers", "headers": [{"name": "transfer-encoding", "value": "chunked"}]
    }])))
    .unwrap();
    assert!(
        patch
            .apply(id(2), int(3), &h2, BODY, id(10), id(11))
            .is_err()
    );
    let decoded = b"decoded synthetic body";
    let mut view = artifact_json();
    view["artifact_id"] = json!(id(20));
    view["kind"] = json!("decoded_body");
    view["sha256"] = json!(Digest::of(decoded));
    view["length_bytes"] = json!(decoded.len());
    let view: Artifact = serde_json::from_value(view).unwrap();
    let view_ref: EvidenceRef = serde_json::from_value(json!({
        "artifact_id": id(20), "sha256": Digest::of(decoded), "range_start": 8, "range_end": 17
    }))
    .unwrap();
    assert_eq!(
        view_ref
            .validate_artifact(id(2), &view, decoded)
            .unwrap()
            .len()
            .get(),
        9
    );
    let original: Artifact = serde_json::from_value(artifact_json()).unwrap();
    assert!(view_ref.validate_artifact(id(2), &original, BODY).is_err());
}

#[test]
fn artifacts_validate_actual_hash_and_length_and_forbid_non_owned_relative_paths() {
    let artifact: Artifact = serde_json::from_value(artifact_json()).unwrap();
    artifact.validate_bytes(id(2), BODY).unwrap();
    assert_eq!(
        artifact.validate_bytes(id(99), BODY).unwrap_err().code,
        ErrorCode::PermissionDenied
    );
    assert_eq!(
        artifact.validate_bytes(id(2), b"mutant").unwrap_err().code,
        ErrorCode::IntegrityError
    );
    assert!(artifact.validate_bytes(id(2), &BODY[..5]).is_err());
    for path in [
        "",
        "/tmp/foreign.bin",
        "../foreign.bin",
        "body/../../foreign.bin",
        "body/./x",
        "body//x",
        "body\\foreign.bin",
        "body/\u{0000}x",
    ] {
        let mut invalid = artifact_json();
        invalid["relative_path"] = json!(path);
        assert!(
            serde_json::from_value::<Artifact>(invalid).is_err(),
            "accepted {path:?}"
        );
    }
    let mut wrong_length = artifact_json();
    wrong_length["length_bytes"] = json!(5);
    let wrong_length: Artifact = serde_json::from_value(wrong_length).unwrap();
    assert!(wrong_length.validate_bytes(id(2), BODY).is_err());
}

#[test]
fn metadata_is_bounded_strict_and_observations_can_only_be_proposed() {
    for status in ["confirmed", "accepted", "failed", ""] {
        let mut invalid = proposal_json();
        invalid["status"] = json!(status);
        assert!(serde_json::from_value::<ObservationProposal>(invalid).is_err());
    }
    for (field, value) in [
        ("title", json!("é".repeat(129))),
        ("rule_id", json!("a".repeat(129))),
        ("evidence_refs", json!([])),
        ("actor_ref", json!("not-a-uuid")),
    ] {
        let mut invalid = proposal_json();
        invalid[field] = value;
        assert!(serde_json::from_value::<ObservationProposal>(invalid).is_err());
    }
    let mut nullable = snapshot_json();
    nullable["derived_from"] = Value::Null;
    assert!(serde_json::from_value::<Snapshot>(nullable).is_err());
    let mut self_derived = snapshot_json();
    self_derived["derived_from"] = json!(id(1));
    assert!(serde_json::from_value::<Snapshot>(self_derived).is_err());
    let mut many_headers = snapshot_json();
    many_headers["headers"] = json!(vec![json!({"name": "x-fixture", "value": "ok"}); 65_537]);
    assert!(serde_json::from_value::<Snapshot>(many_headers).is_err());
    let mut unknown_representation = snapshot_json();
    unknown_representation["representation"] = json!("original_tls_frames");
    assert!(serde_json::from_value::<Snapshot>(unknown_representation).is_err());
    let mut nested_unknown = snapshot_json();
    nested_unknown["headers"][0]["authorization"] = json!(true);
    assert!(serde_json::from_value::<Snapshot>(nested_unknown).is_err());
    let duplicate_header_field = serde_json::to_string(&snapshot_json()).unwrap().replace(
        "\"name\":\"content-type\"",
        "\"name\":\"content-type\",\"name\":\"x-forged\"",
    );
    assert!(serde_json::from_str::<Snapshot>(&duplicate_header_field).is_err());
}
