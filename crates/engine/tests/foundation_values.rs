use razen_engine::domain::values::{
    AuditTime, ByteRange, CatalogId, ContractVersion, Digest, EntityId, WireInt,
};
use razen_engine::protocol::error::{ErrorCode, ProofError, Retryability};

#[test]
fn entity_ids_require_canonical_v4_without_confusing_catalog_handles() {
    let issued = EntityId::new();
    assert_eq!(EntityId::parse(&issued.to_string()).unwrap(), issued);
    for value in [
        "project-1",
        "00000000-0000-0000-0000-000000000000",
        "a13be608-16ac-1ab4-ae10-248b266318a1",
        "A13BE608-16AC-4AB4-AE10-248B266318A1",
        "{a13be608-16ac-4ab4-ae10-248b266318a1}",
    ] {
        assert!(EntityId::parse(value).is_err(), "accepted noncanonical ID");
        assert!(serde_json::from_str::<EntityId>(&format!("{value:?}")).is_err());
    }
    for handle in [
        "R0-01",
        "CON-01",
        "macos-arm64-proof",
        "http.send",
        "rule:fixture",
    ] {
        assert_eq!(CatalogId::parse(handle).unwrap().as_str(), handle);
    }
    for handle in ["", "has space", "../escape", "\u{00e9}", "has\nnewline"] {
        assert!(CatalogId::parse(handle).is_err());
    }
    assert!(CatalogId::parse(&"a".repeat(129)).is_err());
}

#[test]
fn wire_integers_reject_lossy_json_and_checked_arithmetic_overflow() {
    let max = WireInt::new(9_007_199_254_740_991).unwrap();
    let one = WireInt::new(1).unwrap();
    assert!(WireInt::new(9_007_199_254_740_992).is_err());
    assert!(max.checked_add(one).is_err());
    assert!(WireInt::ZERO.checked_sub(one).is_err());
    assert_eq!(one.checked_add(one).unwrap().get(), 2);
    for document in [
        "-1",
        "1.0",
        "1e0",
        "9007199254740992",
        "\"1\"",
        "null",
        "true",
    ] {
        assert!(
            serde_json::from_str::<WireInt>(document).is_err(),
            "accepted {document}"
        );
    }
    let encoded = serde_json::to_string(&max).unwrap();
    assert_eq!(serde_json::from_str::<WireInt>(&encoded).unwrap(), max);
}

#[test]
fn digests_are_sha256_not_arbitrary_case_or_length_strings() {
    let digest = Digest::of(b"abc");
    assert_eq!(
        digest.to_string(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(Digest::parse(&digest.to_string()).unwrap(), digest);
    assert!(Digest::parse(&digest.to_string().to_uppercase()).is_err());
    assert!(Digest::parse(&"0".repeat(63)).is_err());
    assert!(Digest::parse(&"g".repeat(64)).is_err());
    assert!(Digest::parse(&"0".repeat(128)).is_err());
    let encoded = serde_json::to_string(&digest).unwrap();
    assert_eq!(serde_json::from_str::<Digest>(&encoded).unwrap(), digest);
}

#[test]
fn ranges_are_half_open_checked_and_do_not_wrap() {
    let length = WireInt::new(10).unwrap();
    let range = ByteRange::new(WireInt::new(2).unwrap(), length, length).unwrap();
    assert_eq!(range.start().get(), 2);
    assert_eq!(range.end().get(), 10);
    assert_eq!(range.len().get(), 8);
    assert_eq!(
        ByteRange::new(length, length, length).unwrap().len(),
        WireInt::ZERO
    );
    assert!(ByteRange::new(length, WireInt::new(2).unwrap(), length).is_err());
    assert!(ByteRange::new(WireInt::ZERO, WireInt::new(11).unwrap(), length).is_err());
}

#[test]
fn versions_are_exact_and_audit_timestamps_are_utc_not_local_deadlines() {
    assert_eq!(
        ContractVersion::parse("0.1.0").unwrap(),
        ContractVersion::V0_1_0
    );
    for version in ["0.1", "0.2.0", "v0.1.0", "0.1.0-beta", "latest"] {
        assert!(ContractVersion::parse(version).is_err());
    }
    let timestamp = AuditTime::parse("2026-11-16T12:34:56.123456Z").unwrap();
    let encoded = serde_json::to_string(&timestamp).unwrap();
    assert_eq!(
        serde_json::from_str::<AuditTime>(&encoded).unwrap(),
        timestamp
    );
    for value in [
        "2026-11-16T12:34:56+01:00",
        "2026-13-16T12:34:56Z",
        "2026-11-16 12:34:56",
        "123456",
    ] {
        assert!(AuditTime::parse(value).is_err());
    }
}

#[test]
fn audit_timestamps_preserve_utc_normalization_fraction_groups_and_ordering() {
    for (input, expected) in [
        ("2026-11-16T12:34:56Z", "2026-11-16T12:34:56+00:00"),
        ("2026-11-16t12:34:56z", "2026-11-16T12:34:56+00:00"),
        ("2026-11-16 12:34:56+00:00", "2026-11-16T12:34:56+00:00"),
        ("2026-11-16T12:34:56.1Z", "2026-11-16T12:34:56.100+00:00"),
        (
            "2026-11-16T12:34:56.1234Z",
            "2026-11-16T12:34:56.123400+00:00",
        ),
        (
            "2026-11-16T12:34:56.1234567Z",
            "2026-11-16T12:34:56.123456700+00:00",
        ),
        (
            "2026-11-16T12:34:56.000000000Z",
            "2026-11-16T12:34:56+00:00",
        ),
        (
            "2026-11-16T12:34:56.123456789123Z",
            "2026-11-16T12:34:56.123456789+00:00",
        ),
        ("9999-12-31T23:59:59Z", "9999-12-31T23:59:59+00:00"),
    ] {
        let time = AuditTime::parse(input).unwrap();
        assert_eq!(time.to_string(), expected);
        assert_eq!(AuditTime::parse(expected).unwrap(), time);
    }
    let before = AuditTime::parse("2026-11-16T12:34:56.999999999Z").unwrap();
    let after = AuditTime::parse("2026-11-16T12:34:57Z").unwrap();
    assert!(before < after);
    assert_eq!(
        before
            .checked_add(std::time::Duration::from_nanos(1))
            .unwrap(),
        after
    );
    assert!(before.checked_add(std::time::Duration::MAX).is_err());
    let maximum = AuditTime::parse("9999-12-31T23:59:59.999999999Z").unwrap();
    assert!(
        maximum
            .checked_add(std::time::Duration::from_nanos(1))
            .is_err()
    );
}

#[test]
fn audit_timestamps_reject_non_rfc3339_extensions_and_unknown_offsets() {
    for input in [
        "2026-11-16T12:34:56-00:00",
        "2026-11-16T12:34Z",
        "2026-11-16T12Z",
        "20261116T123456Z",
        "2026-11-16T12:34:56+00",
        "2026-11-16T12:34:56+0000",
        "2026-11-16T12:34:56+00:00:00",
        "2026-11-16T12:34:56,123Z",
        "2026-11-16T12:34:56Z[UTC]",
        "2026-11-16T12:34:56Z[u-ca=iso8601]",
        "2026-1-16T12:34:56Z",
        "2026-11-16T1:34:56Z",
        "2026-11-16T12:34:56Z ",
        "+002026-11-16T12:34:56Z",
    ] {
        assert!(AuditTime::parse(input).is_err(), "{input}");
    }
}

#[test]
fn audit_timestamp_consumers_reject_leap_seconds_without_normalizing_them() {
    for input in [
        "2016-12-31T23:59:59Z",
        "2016-12-31T23:59:59.999999999+00:00",
    ] {
        let parsed = AuditTime::parse(input).unwrap();
        let document = serde_json::to_string(input).unwrap();
        assert_eq!(
            serde_json::from_str::<AuditTime>(&document).unwrap(),
            parsed
        );
    }
    for input in [
        "2016-12-31T23:59:60Z",
        "2016-12-31t23:59:60z",
        "2016-12-31 23:59:60+00:00",
        "2016-12-31T23:59:60.123456789123Z",
    ] {
        assert!(AuditTime::parse(input).is_err(), "{input}");
        let document = serde_json::to_string(input).unwrap();
        assert!(
            serde_json::from_str::<AuditTime>(&document).is_err(),
            "{input}"
        );
    }
}

#[test]
fn unknown_active_effects_never_advertise_retryable_success() {
    let error = ProofError::new(
        ErrorCode::OutcomeUnknown,
        "Effect outcome requires reconciliation",
    );
    assert_eq!(error.retryability, Retryability::Reconcile);
    let encoded = serde_json::to_value(&error).unwrap();
    assert_eq!(encoded["code"], "outcome_unknown");
    assert_eq!(encoded["retryability"], "reconcile");
    assert!(encoded.get("invocation_id").is_none());
    assert_eq!(
        serde_json::from_value::<ProofError>(encoded.clone())
            .unwrap()
            .code,
        ErrorCode::OutcomeUnknown
    );
    let mut unsafe_retry = encoded.clone();
    unsafe_retry["retryability"] = serde_json::json!("safe_read");
    assert!(serde_json::from_value::<ProofError>(unsafe_retry).is_err());
    let mut null_invocation = encoded.clone();
    null_invocation["invocation_id"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<ProofError>(null_invocation).is_err());
    let mut unknown_field = encoded.clone();
    unknown_field["grant_id"] = serde_json::json!("forged");
    assert!(serde_json::from_value::<ProofError>(unknown_field).is_err());
    let mut oversized_message = encoded;
    oversized_message["message"] = serde_json::json!("x".repeat(257));
    assert!(serde_json::from_value::<ProofError>(oversized_message).is_err());
}
