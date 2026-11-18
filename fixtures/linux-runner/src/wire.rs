use crate::{Result, fail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;
pub const PROTOCOL: &str = "razen.proof/0.1.0";
pub const FRAME: usize = 1_048_576;
pub const CHUNK: usize = 65_536;
pub const SAFE: u64 = 9_007_199_254_740_991;
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct Launch {
    pub binding_id: String,
    pub invocation_id: String,
    pub run_id: String,
    pub attestation_id: String,
    pub profile_sha256: String,
    pub approved_fixture_id: String,
    pub input_artifact_refs: Vec<ArtifactRef>,
    pub lease_id: String,
    pub control_revision: u64,
}
#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct ArtifactRef {
    pub artifact_id: String,
    pub sha256: String,
    pub range_start: Option<u64>,
    pub range_end: Option<u64>,
}
#[derive(Debug)]
pub struct Envelope {
    pub message_id: String,
    pub correlation_id: Option<String>,
    pub kind: String,
    pub payload: Value,
}
#[derive(Clone, Copy)]
pub enum Role {
    Supervisor,
    Runtime,
}
#[derive(Clone, Copy)]
pub enum Direction {
    HostToPeer,
    PeerToHost,
}
struct Unique(Value);
impl<'de> Deserialize<'de> for Unique {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Unique;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("bounded JSON with unique object fields")
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Bool(v)))
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::Null))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Unique, E> {
                if v > SAFE {
                    return Err(E::custom("unsafe integer"));
                }
                Ok(Unique(Value::from(v)))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Unique, E> {
                if v.unsigned_abs() > SAFE {
                    return Err(E::custom("unsafe integer"));
                }
                Ok(Unique(Value::from(v)))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Unique, E> {
                if v.fract() == 0.0 && v.abs() > SAFE as f64 {
                    return Err(E::custom("unsafe integer"));
                }
                serde_json::Number::from_f64(v)
                    .map(|n| Unique(Value::Number(n)))
                    .ok_or_else(|| E::custom("invalid number"))
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Unique, E> {
                Ok(Unique(Value::String(v.to_owned())))
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut m = serde_json::Map::new();
                while let Some(k) = a.next_key::<String>()? {
                    if m.contains_key(&k) {
                        return Err(de::Error::custom("duplicate field"));
                    }
                    m.insert(k, a.next_value::<Unique>()?.0);
                }
                Ok(Unique(Value::Object(m)))
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut a: A,
            ) -> std::result::Result<Unique, A::Error> {
                let mut v = Vec::new();
                while let Some(x) = a.next_element::<Unique>()? {
                    if v.len() == 65536 {
                        return Err(de::Error::custom("sequence bound"));
                    }
                    v.push(x.0);
                }
                Ok(Unique(Value::Array(v)))
            }
        }
        d.deserialize_any(V)
    }
}
pub fn unique(bytes: &[u8]) -> Result<Value> {
    if bytes.len() > FRAME {
        return Err(fail("JSON bound exceeded"));
    }
    Ok(serde_json::from_slice::<Unique>(bytes)?.0)
}
pub fn fields(v: &Value, required: &[&str], optional: &[&str]) -> Result<()> {
    let object = v.as_object().ok_or_else(|| fail("object required"))?;
    if required.iter().any(|k| !object.contains_key(*k))
        || object
            .keys()
            .any(|k| !required.contains(&k.as_str()) && !optional.contains(&k.as_str()))
        || object.values().any(Value::is_null)
    {
        return Err(fail("strict object fields mismatch"));
    }
    Ok(())
}
pub fn uuid(v: &str) -> bool {
    let b = v.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                *c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(c)
            }
        })
        && b[14] == b'4'
        && matches!(b[19], b'8' | b'9' | b'a' | b'b')
}
pub fn digest(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
pub fn catalog(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 128
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-:/@".contains(&b))
}
pub fn id(v: &Value) -> Result<&str> {
    let s = v.as_str().ok_or_else(|| fail("UUID string required"))?;
    if !uuid(s) {
        return Err(fail("canonical UUID v4 required"));
    }
    Ok(s)
}
pub fn number(v: &Value) -> Result<u64> {
    v.as_u64()
        .filter(|n| *n <= SAFE)
        .ok_or_else(|| fail("nonnegative safe wire integer required"))
}
fn refs(v: &Value) -> Result<()> {
    let a = v
        .as_array()
        .ok_or_else(|| fail("reference array required"))?;
    if a.len() > 256 {
        return Err(fail("reference bound"));
    }
    for x in a {
        id(x)?;
    }
    Ok(())
}
fn usage(v: &Value) -> Result<()> {
    fields(v, &["units", "bytes", "cpu_us", "elapsed_us"], &[])?;
    for x in v.as_object().unwrap().values() {
        number(x)?;
    }
    Ok(())
}
fn error(v: &Value) -> Result<()> {
    fields(
        v,
        &["code", "message", "retryability", "diagnostic_refs"],
        &["invocation_id"],
    )?;
    let codes = [
        "invalid_input",
        "unsupported_version",
        "unknown_tool",
        "permission_denied",
        "out_of_scope",
        "approval_required",
        "budget_exhausted",
        "stale_snapshot",
        "unsupported_protocol",
        "timeout",
        "cancelled",
        "plugin_trap",
        "output_invalid",
        "provider_unavailable",
        "outcome_unknown",
        "integrity_error",
        "isolation_unavailable",
    ];
    if !codes.contains(&v["code"].as_str().unwrap_or(""))
        || !matches!(
            v["retryability"].as_str(),
            Some("safe_read" | "reconcile" | "never")
        )
        || v["message"]
            .as_str()
            .is_none_or(|s| s.is_empty() || s.len() > 256)
    {
        return Err(fail("structured error mismatch"));
    }
    refs(&v["diagnostic_refs"])?;
    if v["diagnostic_refs"]
        .as_array()
        .is_none_or(|refs| refs.len() > 32)
    {
        return Err(fail("diagnostic reference bound"));
    }
    if let Some(i) = v.get("invocation_id") {
        id(i)?;
    }
    Ok(())
}
pub fn decode(bytes: &[u8], role: Role, direction: Direction) -> Result<Envelope> {
    if bytes.len() > FRAME || !bytes.ends_with(b"\n") || bytes[..bytes.len() - 1].contains(&b'\n') {
        return Err(fail("invalid bounded JSONL frame"));
    }
    let v = unique(&bytes[..bytes.len() - 1])?;
    fields(
        &v,
        &["protocol", "message_id", "kind", "payload"],
        &["correlation_id"],
    )?;
    if v["protocol"] != PROTOCOL {
        return Err(fail("unsupported protocol"));
    }
    id(&v["message_id"])?;
    if let Some(c) = v.get("correlation_id") {
        id(c)?;
    }
    let kind = v["kind"].as_str().ok_or_else(|| fail("kind required"))?;
    let p = &v["payload"];
    use Direction::*;
    use Role::*;
    let (required, optional): (&[&str], &[&str]) = match (role, direction, kind) {
        (Supervisor, HostToPeer, "launch") => (
            &[
                "binding_id",
                "invocation_id",
                "run_id",
                "attestation_id",
                "profile_sha256",
                "approved_fixture_id",
                "input_artifact_refs",
                "lease_id",
                "control_revision",
            ],
            &[],
        ),
        (Supervisor, PeerToHost, "ready") => (&["invocation_id", "attestation"], &[]),
        (Supervisor, PeerToHost, "started") => (&["invocation_id"], &[]),
        (Supervisor, PeerToHost, "output") => (
            &["invocation_id", "stream", "sequence", "bytes_base64"],
            &[],
        ),
        (Supervisor, PeerToHost, "usage") => (
            &[
                "invocation_id",
                "cpu_time_us",
                "memory_peak_bytes",
                "pids_peak",
                "tmpfs_peak_bytes",
                "output_bytes",
            ],
            &[],
        ),
        (Supervisor, PeerToHost, "terminated") => (
            &["invocation_id", "outcome", "empty_cgroup"],
            &["exit_code", "signal"],
        ),
        (Supervisor, PeerToHost, "error") => (&["invocation_id", "error"], &[]),
        (Supervisor, HostToPeer, "lease_refresh") => (
            &[
                "binding_id",
                "invocation_id",
                "lease_id",
                "control_revision",
            ],
            &[],
        ),
        (Supervisor, HostToPeer, "cancel" | "close") => (
            &[
                "binding_id",
                "invocation_id",
                "lease_id",
                "control_revision",
                "reason",
            ],
            &[],
        ),
        (Runtime, HostToPeer, "start") => (
            &[
                "binding_id",
                "contract_version",
                "context_refs",
                "tool_ids",
                "budget_summary",
            ],
            &[],
        ),
        (Runtime, PeerToHost, "started") => (&["capabilities"], &[]),
        (Runtime, PeerToHost, "tool_request") => (
            &[
                "call_id",
                "tool_id",
                "tool_version",
                "input",
                "source_control_revision",
            ],
            &[],
        ),
        (Runtime, HostToPeer, "tool_result") => (
            &["call_id", "invocation_id", "state", "usage"],
            &["output_ref", "error"],
        ),
        (Runtime, PeerToHost, "event") => (
            &[
                "event_type",
                "source_control_revision",
                "sequence",
                "data_refs",
            ],
            &[],
        ),
        (Runtime, HostToPeer, "steer") => (&["control_revision", "instruction_ref"], &[]),
        (Runtime, HostToPeer, "cancel") => (&["control_revision", "reason"], &[]),
        (Runtime, PeerToHost, "result") => (
            &["state", "source_control_revision", "proposal_refs", "usage"],
            &["error"],
        ),
        (Runtime, HostToPeer, "close") => (&["reason"], &[]),
        (Runtime, PeerToHost, "closed") => (&[], &[]),
        _ => return Err(fail("kind forbidden on authenticated role/direction")),
    };
    fields(p, required, optional)?;
    for (k, v) in p.as_object().unwrap() {
        if k.ends_with("_id") && k != "tool_id" && k != "approved_fixture_id" {
            id(v)?;
        }
        if [
            "control_revision",
            "source_control_revision",
            "sequence",
            "cpu_time_us",
            "memory_peak_bytes",
            "pids_peak",
            "tmpfs_peak_bytes",
            "output_bytes",
            "exit_code",
            "signal",
        ]
        .contains(&k.as_str())
        {
            number(v)?;
        }
        if ["tool_id", "approved_fixture_id", "event_type"].contains(&k.as_str())
            && !v.as_str().is_some_and(catalog)
        {
            return Err(fail("catalog ID invalid"));
        }
        if ["contract_version", "tool_version"].contains(&k.as_str()) && v != "0.1.0" {
            return Err(fail("unsupported contract version"));
        }
        if ["context_refs", "data_refs", "proposal_refs"].contains(&k.as_str()) {
            refs(v)?;
        }
        if k == "usage" {
            usage(v)?;
        }
        if k == "error" {
            error(v)?;
        }
        if k == "reason" && v.as_str().is_none_or(|s| s.is_empty() || s.len() > 256) {
            return Err(fail("reason bound"));
        }
    }
    if let Some(output) = p.get("output_ref") {
        id(output)?;
    }
    if let Some(instruction) = p.get("instruction_ref") {
        id(instruction)?;
    }
    if matches!(kind, "result" | "terminated")
        && !matches!(
            p.get(if kind == "result" { "state" } else { "outcome" })
                .and_then(Value::as_str),
            Some("completed" | "failed" | "cancelled" | "budget_exhausted")
        )
    {
        return Err(fail("completion state mismatch"));
    }
    if kind == "tool_result"
        && !matches!(
            p["state"].as_str(),
            Some(
                "proposed"
                    | "rejected"
                    | "waiting_approval"
                    | "reserved"
                    | "sending"
                    | "completed"
                    | "failed"
                    | "outcome_unknown"
                    | "cancelled"
            )
        )
    {
        return Err(fail("invocation state mismatch"));
    }
    if matches!(kind, "tool_result" | "result")
        && p["state"] == "completed"
        && p.get("error").is_some()
    {
        return Err(fail("successful result cannot carry error"));
    }
    if kind == "tool_result"
        && p["state"] == "outcome_unknown"
        && (p["error"]["code"] != "outcome_unknown" || p["error"]["retryability"] != "reconcile")
    {
        return Err(fail("unknown effect requires conservative reconciliation"));
    }
    if kind == "ready" {
        let a = &p["attestation"];
        fields(
            a,
            &[
                "attestation_id",
                "run_id",
                "backend",
                "manager_version",
                "image_digest",
                "kernel_version",
                "effective_config_sha256",
                "provisioning_sha256",
                "binary_digests",
                "seccomp_sha256",
                "namespace_checks",
                "controller_checks",
                "mount_checks",
                "socket_checks",
                "uid_checks",
                "observed_limits",
                "created_at",
            ],
            &[],
        )?;
        id(&a["attestation_id"])?;
        id(&a["run_id"])?;
        if !a["backend"].as_str().is_some_and(catalog) {
            return Err(fail("attestation backend invalid"));
        }
        for name in ["manager_version", "kernel_version"] {
            if a[name]
                .as_str()
                .is_none_or(|v| v.is_empty() || v.len() > 256)
            {
                return Err(fail("attestation text bound"));
            }
        }
        for name in [
            "effective_config_sha256",
            "provisioning_sha256",
            "seccomp_sha256",
        ] {
            if !a[name].as_str().is_some_and(digest) {
                return Err(fail("attestation digest invalid"));
            }
        }
        let image = a["image_digest"]
            .as_str()
            .ok_or_else(|| fail("image digest required"))?;
        if image.len() != 135
            || !image.starts_with("sha512:")
            || !image[7..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(fail("image digest invalid"));
        }
        let timestamp = a["created_at"]
            .as_str()
            .ok_or_else(|| fail("attestation UTC timestamp required"))?;
        let civil = timestamp
            .strip_suffix('Z')
            .or_else(|| timestamp.strip_suffix('z'))
            .or_else(|| timestamp.strip_suffix("+00:00"))
            .ok_or_else(|| fail("attestation must be UTC"))?;
        let bytes = civil.as_bytes();
        // Restrict Jiff's broader Temporal syntax to the RFC3339 wire boundary.
        if bytes.len() < 19
            || !bytes[..4].iter().all(u8::is_ascii_digit)
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || !matches!(bytes[10], b'T' | b't' | b' ')
            || bytes[13] != b':'
            || bytes[16] != b':'
            || (bytes.len() > 19
                && (bytes[19] != b'.'
                    || bytes.len() == 20
                    || !bytes[20..].iter().all(u8::is_ascii_digit)))
        {
            return Err(fail("attestation RFC3339 timestamp required"));
        }
        // R0 rejects leap seconds rather than allowing Jiff to clamp 60 to 59.
        if &bytes[17..19] == b"60" {
            return Err(fail("attestation leap second unsupported"));
        }
        let _: jiff::civil::DateTime = civil[..civil.len().min(29)].parse()?;
        for name in [
            "binary_digests",
            "namespace_checks",
            "controller_checks",
            "mount_checks",
            "socket_checks",
            "uid_checks",
            "observed_limits",
        ] {
            let map = a[name]
                .as_object()
                .ok_or_else(|| fail("attestation map required"))?;
            if map.len() > 128 {
                return Err(fail("attestation map bound"));
            }
            for (key, value) in map {
                if !catalog(key) {
                    return Err(fail("attestation catalog key invalid"));
                }
                if name == "binary_digests" {
                    if !value.as_str().is_some_and(digest) {
                        return Err(fail("binary digest invalid"));
                    }
                } else if name == "observed_limits" {
                    number(value)?;
                } else if value.as_bool().is_none() {
                    return Err(fail("attestation boolean required"));
                }
            }
        }
    }
    if kind == "launch" {
        let references = p["input_artifact_refs"]
            .as_array()
            .ok_or_else(|| fail("artifact references required"))?;
        if references.len() > 256 {
            return Err(fail("artifact reference bound"));
        }
        for reference in references {
            fields(
                reference,
                &["artifact_id", "sha256"],
                &["range_start", "range_end"],
            )?;
            id(&reference["artifact_id"])?;
            if !reference["sha256"].as_str().is_some_and(digest) {
                return Err(fail("artifact digest invalid"));
            }
            match (reference.get("range_start"), reference.get("range_end")) {
                (None, None) => {}
                (Some(start), Some(end)) if number(start)? <= number(end)? => {}
                _ => return Err(fail("artifact range mismatch")),
            }
        }
        if !p["profile_sha256"].as_str().is_some_and(digest) {
            return Err(fail("launch profile digest invalid"));
        }
    }
    if kind == "output" {
        if !matches!(p["stream"].as_str(), Some("stdout" | "stderr")) {
            return Err(fail("output stream mismatch"));
        }
        let s = p["bytes_base64"]
            .as_str()
            .ok_or_else(|| fail("base64 required"))?;
        if s.len() > CHUNK.div_ceil(3) * 4 || STANDARD.decode(s)?.len() > CHUNK {
            return Err(fail("output chunk bound"));
        }
    }
    if kind == "terminated"
        && (p["empty_cgroup"].as_bool().is_none()
            || p.get("exit_code").is_some() && p.get("signal").is_some()
            || p.get("exit_code")
                .is_some_and(|v| v.as_u64().is_none_or(|n| n > 255))
            || p.get("signal")
                .is_some_and(|v| v.as_u64().is_none_or(|n| !(1..=64).contains(&n))))
    {
        return Err(fail("termination schema mismatch"));
    }
    if kind == "tool_result" && p.get("output_ref").is_some() && p.get("error").is_some() {
        return Err(fail("mutually exclusive result fields"));
    }
    if kind == "tool_request" {
        let mut nodes = 0;
        bounded_input(&p["input"], 0, &mut nodes)?;
    }
    if kind == "start" {
        fields(
            &p["budget_summary"],
            &["limit", "consumed", "reserved"],
            &[],
        )?;
        let b = &p["budget_summary"];
        if number(&b["consumed"])?
            .checked_add(number(&b["reserved"])?)
            .is_none_or(|n| n > number(&b["limit"]).unwrap_or(0))
        {
            return Err(fail("invalid budget summary"));
        }
        let t = p["tool_ids"]
            .as_array()
            .ok_or_else(|| fail("tool catalog required"))?;
        if t.len() > 256 || t.iter().any(|v| !v.as_str().is_some_and(catalog)) {
            return Err(fail("tool catalog bound"));
        }
    }
    if kind == "started" && matches!(role, Runtime) {
        let a = p["capabilities"]
            .as_array()
            .ok_or_else(|| fail("capabilities required"))?;
        let c = a
            .iter()
            .map(|v| v.as_str().unwrap_or(""))
            .collect::<BTreeSet<_>>();
        if c.len() != a.len()
            || c.len() > 8
            || [
                "brokered_calls",
                "events",
                "results",
                "usage",
                "cancellation",
                "closure",
            ]
            .iter()
            .any(|s| !c.contains(s))
            || c.iter().any(|s| {
                ![
                    "brokered_calls",
                    "events",
                    "results",
                    "usage",
                    "cancellation",
                    "closure",
                    "native_pause",
                    "native_steering",
                ]
                .contains(s)
            })
        {
            return Err(fail("capability set mismatch"));
        }
    }
    Ok(Envelope {
        message_id: v["message_id"].as_str().unwrap().into(),
        correlation_id: v
            .get("correlation_id")
            .and_then(Value::as_str)
            .map(str::to_owned),
        kind: kind.into(),
        payload: p.clone(),
    })
}
pub fn new_id() -> Result<String> {
    let mut bytes = [0u8; 16];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    bytes[6] = (bytes[6] & 15) | 64;
    bytes[8] = (bytes[8] & 63) | 128;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    ))
}
pub fn encode(
    kind: &str,
    payload: Value,
    correlation: Option<&str>,
    role: Role,
    direction: Direction,
) -> Result<Vec<u8>> {
    encode_with_id(&new_id()?, kind, payload, correlation, role, direction)
}
pub fn base64(bytes: &[u8]) -> String {
    STANDARD.encode(bytes)
}
pub fn encode_with_id(
    message_id: &str,
    kind: &str,
    payload: Value,
    correlation: Option<&str>,
    role: Role,
    direction: Direction,
) -> Result<Vec<u8>> {
    let mut v = json!({"protocol":PROTOCOL,"message_id":message_id,"kind":kind,"payload":payload});
    if let Some(c) = correlation {
        v["correlation_id"] = json!(c);
    }
    let mut bytes = serde_json::to_vec(&v)?;
    bytes.push(b'\n');
    decode(&bytes, role, direction)?;
    Ok(bytes)
}
fn bounded_input(value: &Value, depth: usize, nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    if depth > 64 || *nodes > 65536 {
        return Err(fail("tool input structural bound"));
    }
    match value {
        Value::Object(map) => {
            for value in map.values() {
                bounded_input(value, depth + 1, nodes)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                bounded_input(value, depth + 1, nodes)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod timestamp_tests {
    use super::{Direction, PROTOCOL, Role, decode};
    use serde_json::json;

    #[test]
    fn ready_timestamp_consumer_rejects_leap_seconds_before_normalization() {
        let id = "00000000-0000-4000-8000-000000000001";
        let mut ready = json!({
            "protocol": PROTOCOL,
            "message_id": id,
            "kind": "ready",
            "payload": {
                "invocation_id": id,
                "attestation": {
                    "attestation_id": id,
                    "run_id": id,
                    "backend": "lima-vz-plain-bubblewrap-cgroup-v2",
                    "manager_version": "2.3.0",
                    "image_digest": format!("sha512:{}", "a".repeat(128)),
                    "kernel_version": "6.12",
                    "effective_config_sha256": "a".repeat(64),
                    "provisioning_sha256": "a".repeat(64),
                    "binary_digests": {},
                    "seccomp_sha256": "a".repeat(64),
                    "namespace_checks": {},
                    "controller_checks": {},
                    "mount_checks": {},
                    "socket_checks": {},
                    "uid_checks": {},
                    "observed_limits": {},
                    "created_at": ""
                }
            }
        });
        for (timestamp, valid) in [
            ("2016-12-31T23:59:59Z", true),
            ("2016-12-31T23:59:59.123456+00:00", true),
            ("2016-12-31T23:59:59.123456789123Z", true),
            ("2016-12-31T23:59:60Z", false),
            ("2016-12-31t23:59:60z", false),
            ("2016-12-31 23:59:60+00:00", false),
            ("2016-12-31T23:59:60.123456789123Z", false),
            ("2016-12-31T23:59:59-00:00", false),
            ("2016-12-31T23:59:59Z[UTC]", false),
        ] {
            ready["payload"]["attestation"]["created_at"] = json!(timestamp);
            let mut frame = serde_json::to_vec(&ready).unwrap();
            frame.push(b'\n');
            assert_eq!(
                decode(&frame, Role::Supervisor, Direction::PeerToHost).is_ok(),
                valid,
                "{timestamp}"
            );
        }
    }
}
