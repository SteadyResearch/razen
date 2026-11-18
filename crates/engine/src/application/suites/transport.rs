//! Native operational NET proofs and quiescent, read-only fact verification.
use super::CaseObservation;
use crate::adapters::command::{CommandLimits, capture_status};
use crate::adapters::evidence_store::EvidenceStore;
use crate::adapters::ledger::{Ledger, RegisteredTool};
use crate::adapters::transport::{
    self, Limits, Mode, TransportConfig, capture,
    fixture::{Endpoint, ReceiverRecord},
    intercept::IsolatedAuthority,
    scope_connector::{FixtureZone, ResolutionFact, Resolver},
};
use crate::application::admission::{BindingSpec, PreparedCall, TrustedBinding};
use crate::application::effect_meter::EffectMeter;
use crate::application::http_send::{
    self, HttpSendInput, HttpSendOutput, HttpSendResult, HttpSendTiming, RequestSnapshot,
    SendRecord,
};
use crate::application::measurements::{self, Measurements, Route, Sample};
use crate::application::profile::LoadedProfile;
use crate::application::proof_host::ProofHost;
use crate::application::registry::Registry;
use crate::domain::authority::{
    DestinationRule, Effect, FixtureProject, IdentityProfile, PathKind, PathRule, RetryClass,
    Scheme, ScopePolicy, ToolDescriptor,
};
use crate::domain::evidence::{Header, RedactionStatus, Representation};
use crate::domain::execution::{ControlMode, ControlState};
use crate::domain::knowledge::InvestigationSession;
use crate::domain::proofs::{Assertions, CheckName, Run};
use crate::domain::values::{
    CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage, WireInt,
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use crate::protocol::messages::{ToolRequest, ToolResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_json::value::RawValue;
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

const HOST: &str = "target.razen.invalid";
const EXCLUDED: &str = "excluded.razen.invalid";
const PREPARE: &str = "proof.transport.fixture";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScenarioInput {
    schema_version: ContractVersion,
    fixture_only: bool,
    authority: String,
    excluded_authority: String,
    method: String,
    target: String,
    body: BodyPattern,
    headers: Vec<Header>,
    required_modes: Vec<Mode>,
    scope_variants: Vec<String>,
    tls_variants: Vec<String>,
    body_variants: Vec<String>,
    h2_max_concurrent_streams: u32,
    h2_reset_reason: String,
    encoding_policy: String,
    framing_policy: String,
    trust_policy: String,
    measurement_policy: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyPattern {
    pattern: String,
    length_from: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiverEvidence {
    endpoint_id: EntityId,
    port: u16,
    final_count: u64,
    accepted_connections: u64,
    records: Vec<ReceiverRecord>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExchangeFact {
    project_id: EntityId,
    invocation_id: EntityId,
    result_artifact_id: EntityId,
    receiver_endpoint_id: EntityId,
    receiver_sequence: u64,
    mode: Mode,
    inspection: String,
    request_snapshot_id: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_snapshot_id: Option<EntityId>,
    status: u16,
    receiver_method: String,
    receiver_target: String,
    receiver_headers: BTreeMap<String, Vec<String>>,
    receiver_body_sha256: Digest,
    request_body_sha256: Digest,
    response_body_sha256: Digest,
    connection_id: EntityId,
    stream_id: u32,
    receiver_started_us: u64,
    receiver_finished_us: u64,
    client_http_version: String,
    upstream_http_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_peer_certificate_sha256: Option<Digest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connect_authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connect_host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_server_name: Option<String>,
    request_authority: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tunnel_client_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tunnel_upstream_bytes: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptFact {
    variant: String,
    invocation_id: EntityId,
    attempt_artifact_id: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    result_artifact_id: Option<EntityId>,
    error_code: ErrorCode,
    observer_endpoint_id: EntityId,
    forbidden_before: u64,
    forbidden_after: u64,
    counter_kind: String,
    healthy_arrivals: u64,
    healthy_invocation_id: EntityId,
    captured_bytes: u64,
    representation: String,
    replacement_published: bool,
    redirects_observed: u64,
    resolution_count: u64,
    resolved_addresses: Vec<IpAddr>,
    #[serde(skip_serializing_if = "Option::is_none")]
    connection_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    stream_started_us: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reset_observed_us: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AttemptEvidence {
    variant: String,
    invocation_id: EntityId,
    observer_endpoint_id: EntityId,
    before: u64,
    after: u64,
    healthy_before: u64,
    healthy_after: u64,
    counter_kind: String,
    healthy_invocation_id: EntityId,
    resolutions: Vec<ResolutionFact>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustSnapshot {
    domains: Vec<TrustDomain>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustDomain {
    domain: String,
    exit_code: i32,
    stdout: String,
    stderr: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFact {
    before_sha256: Digest,
    after_sha256: Digest,
    before_artifact_id: EntityId,
    after_artifact_id: EntityId,
    public_root_artifact_id: EntityId,
    upstream_root_artifact_id: EntityId,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: ContractVersion,
    case_id: CatalogId,
    project_id: EntityId,
    profile_sha256: Digest,
    fixture_sha256: Digest,
    fixture_artifact_id: EntityId,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 512>")]
    provider_invocation_ids: Vec<EntityId>,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 512>")]
    provider_result_artifact_ids: Vec<EntityId>,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 32>")]
    receiver_artifact_ids: Vec<EntityId>,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 64>")]
    exchanges: Vec<ExchangeFact>,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 32>")]
    attempts: Vec<AttemptFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trust: Option<TrustFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    measurement: Option<Measurements>,
    #[serde(skip_serializing_if = "Option::is_none")]
    measurement_artifact_id: Option<EntityId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secrecy_artifact_id: Option<EntityId>,
}

struct Scenario {
    project: FixtureProject,
    binding: Arc<TrustedBinding>,
    snapshot_id: EntityId,
    identity_secret: Vec<u8>,
}
impl Scenario {
    fn create(
        host: &ProofHost,
        profile: &LoadedProfile,
        destinations: Vec<DestinationRule>,
        exclusions: Vec<DestinationRule>,
        body: &[u8],
        identity_secret: Vec<u8>,
    ) -> ProofResult<Self> {
        for tool in [
            http_send::registered_tool(host.provider_digest, profile)?,
            fixture_tool(host.provider_digest)?,
        ] {
            match host.ledger.find_tool(&tool.descriptor.tool_id)? {
                Some(existing) if existing != tool => return Err(invalid()),
                Some(_) => {}
                None => host.ledger.insert_tool(&tool)?,
            }
        }
        let project = FixtureProject {
            project_id: EntityId::new(),
            user_id: host.project.user_id,
            scope_policy_id: EntityId::new(),
            revision: WireInt::ZERO,
        };
        let scope = ScopePolicy {
            scope_policy_id: project.scope_policy_id,
            project_id: project.project_id,
            revision: WireInt::ZERO,
            allowed_destinations: destinations,
            exclusions,
        };
        host.ledger.transaction(|tx| {
            tx.insert_project(&project)?;
            tx.insert_scope(&scope)
        })?;
        let identity = IdentityProfile {
            identity_id: EntityId::new(),
            project_id: project.project_id,
            secret_ref_names: vec![CatalogId::parse("fixture-credential")?],
        };
        host.ledger.insert_identity(&identity)?;
        let origin = EntityId::new();
        let instruction = host.evidence.write_artifact(project.project_id, CatalogId::parse("transport-instruction")?, origin,
            b"Only the currently owned, explicitly scoped transport fixture endpoints are authorized.", RedactionStatus::Original)?;
        let session = InvestigationSession {
            investigation_id: EntityId::new(),
            session_id: EntityId::new(),
            user_id: project.user_id,
            goal: "Exercise reviewed owned transport fixtures without changing OS trust".to_owned(),
            control_revision: WireInt::ZERO,
            branch_refs: Vec::new(),
            evidence_refs: Vec::new(),
        };
        host.ledger.insert_control(
            &ControlState {
                investigation_id: session.investigation_id,
                revision: WireInt::ZERO,
                mode: ControlMode::Running,
                admission_open: true,
                instruction_ref: instruction.artifact_id,
            },
            project.project_id,
            scope.revision,
        )?;
        host.ledger.insert_session(&session, project.project_id)?;
        host.control.register_existing(session.investigation_id)?;
        let binding = Arc::new(host.admission.bind(BindingSpec {
            user_id: project.user_id,
            project_id: project.project_id,
            investigation_id: session.investigation_id,
            session_id: session.session_id,
            identity_id: identity.identity_id,
            budget_id: host.budget_id,
            provider_digest: host.provider_digest,
            allowed_tools: vec![CatalogId::parse(PREPARE)?, CatalogId::parse("http.send")?],
            permissions: vec![CatalogId::parse(PREPARE)?, CatalogId::parse("http.send")?],
        })?);
        let mut snapshot_id = None;
        write_owned(
            host,
            &binding,
            Some(origin),
            "transport-base",
            body,
            |invocation_id, bytes| {
                let id = capture::snapshot(
                    &host.evidence,
                    project.project_id,
                    invocation_id,
                    capture::SnapshotBody {
                        bytes,
                        headers: Vec::new(),
                        representation: Representation::RawBody,
                        truncated: false,
                        derived_from: None,
                    },
                )?;
                let original = host
                    .evidence
                    .snapshot(project.project_id, id, WireInt::ZERO)?;
                let derived = crate::domain::evidence::Snapshot {
                    snapshot_id: EntityId::new(),
                    representation: Representation::Http1Body,
                    derived_from: Some(id),
                    ..original.as_ref().clone()
                };
                snapshot_id = Some(host.evidence.install_snapshot(derived)?.snapshot_id);
                Ok(original.body_ref)
            },
        )?;
        Ok(Self {
            project,
            binding,
            snapshot_id: snapshot_id.ok_or_else(invalid)?,
            identity_secret,
        })
    }
    fn input(
        &self,
        host: &ProofHost,
        url: String,
        headers: &[Header],
        count: u64,
        reset: bool,
    ) -> ProofResult<HttpSendInput> {
        let parsed = url::Url::parse(&url).map_err(|_| invalid())?;
        let mut headers = headers.to_vec();
        if !headers
            .iter()
            .any(|header| header.name.eq_ignore_ascii_case("host"))
        {
            headers.push(Header {
                name: "host".to_owned(),
                value: parsed.authority().to_owned(),
            });
        }
        self.install_input(
            host,
            RequestSnapshot {
                body_snapshot_id: self.snapshot_id,
                body_revision: WireInt::ZERO,
                url,
                method: "POST".to_owned(),
                headers,
                request_count: wire(count)?,
                reset_first_stream: reset,
            },
        )
    }
    fn install_input(
        &self,
        host: &ProofHost,
        request: RequestSnapshot,
    ) -> ProofResult<HttpSendInput> {
        let bytes = encode(&request)?;
        ensure_identity_public(&self.identity_secret, &bytes)?;
        let mut input = None;
        let mut request = Some(request);
        write_owned(
            host,
            &self.binding,
            None,
            "transport-request",
            &bytes,
            |origin, _| {
                let installed = http_send::install_request(
                    &host.evidence,
                    &self.binding,
                    origin,
                    request.take().ok_or_else(invalid)?,
                )?;
                let snapshot = host.evidence.snapshot(
                    self.project.project_id,
                    installed.request_snapshot_id,
                    installed.base_revision,
                )?;
                input = Some(installed);
                Ok(snapshot.body_ref)
            },
        )?;
        input.ok_or_else(invalid)
    }
}
fn fixture_tool(provider_digest: Digest) -> ProofResult<RegisteredTool> {
    Ok(RegisteredTool {
        provider_digest,
        descriptor: ToolDescriptor {
            tool_id: CatalogId::parse(PREPARE)?,
            version: ContractVersion::V0_1_0,
            input_contract: CatalogId::parse("proof.transport.fixture.input")?,
            output_contract: CatalogId::parse("proof.transport.fixture.output")?,
            effect: Effect::LocalWrite,
            permissions: vec![CatalogId::parse(PREPARE)?],
            retry_class: RetryClass::NonRetryable,
            limits: Usage {
                units: wire(1)?,
                bytes: wire(8 * 1_048_576)?,
                cpu_us: wire(30_000_000)?,
                elapsed_us: wire(30_000_000)?,
            },
        },
    })
}
fn write_owned(
    host: &ProofHost,
    binding: &Arc<TrustedBinding>,
    origin: Option<EntityId>,
    kind: &str,
    bytes: &[u8],
    mut write: impl FnMut(EntityId, &[u8]) -> ProofResult<EntityId>,
) -> ProofResult<EntityId> {
    let id = origin.unwrap_or_default();
    let input = serde_json::to_vec(
        &serde_json::json!({"kind":kind,"length_bytes":bytes.len(),"sha256":Digest::of(bytes)}),
    )
    .map_err(|_| invalid())?;
    let artifact = host.evidence.write_artifact(
        binding.project_id(),
        CatalogId::parse("transport-fixture-input")?,
        id,
        &input,
        RedactionStatus::Original,
    )?;
    let call = PreparedCall {
        invocation_id: id,
        call_id: EntityId::new(),
        tool_id: CatalogId::parse(PREPARE)?,
        tool_version: ContractVersion::V0_1_0,
        input_ref: artifact.artifact_id,
        input_sha256: artifact.sha256,
        input_revision: WireInt::ZERO,
        source_control_revision: binding.control_revision(),
        requested: fixture_tool(host.provider_digest)?.descriptor.limits,
    };
    host.admission.propose(binding, &call)?;
    host.approve(binding, &call)?;
    host.admission.reserve(binding, &call)?;
    let permit = host.admission.begin_effect(binding, id)?;
    let mut meter = EffectMeter::start();
    meter.dispatched = true;
    host.admission.recheck_effect(binding, &permit)?;
    let result = write(id, bytes);
    meter.add_bytes(input.len())?;
    meter.add_bytes(bytes.len())?;
    match result {
        Ok(output) => {
            host.admission
                .complete(binding, permit, meter.usage()?, Some(output))?;
            Ok(output)
        }
        Err(error) => {
            if error.code == ErrorCode::OutputInvalid {
                let unknown = ProofError::new(
                    ErrorCode::OutcomeUnknown,
                    "Fixture evidence persistence requires reconciliation",
                );
                host.admission
                    .outcome_unknown(binding, permit, meter.usage()?, unknown.clone())?;
                return Err(unknown.with_invocation(id));
            } else {
                host.admission
                    .fail(binding, permit, meter.usage()?, error.clone())?;
            }
            Err(error)
        }
    }
}
fn publish(
    host: &ProofHost,
    scenario: &Scenario,
    kind: &str,
    bytes: &[u8],
) -> ProofResult<EntityId> {
    ensure_identity_public(&scenario.identity_secret, bytes)?;
    write_owned(
        host,
        &scenario.binding,
        None,
        kind,
        bytes,
        |origin, bytes| {
            Ok(host
                .evidence
                .write_artifact(
                    scenario.project.project_id,
                    CatalogId::parse(kind)?,
                    origin,
                    bytes,
                    RedactionStatus::Original,
                )?
                .artifact_id)
        },
    )
}
fn provider(
    host: &ProofHost,
    profile: &LoadedProfile,
    config: TransportConfig,
) -> ProofResult<Registry> {
    host.http_registry(profile, config)
}
fn send(
    host: &ProofHost,
    scenario: &Scenario,
    registry: &Registry,
    input: &HttpSendInput,
    direct: bool,
) -> ProofResult<HttpSendResult> {
    if direct {
        // The independent lower-level baseline is deliberately not an SDK route.
        let provider = registry.http_provider()?;
        let prepared = provider.prepare(Arc::clone(&scenario.binding), input)?;
        host.approve(&scenario.binding, prepared.call())?;
        return provider.execute_direct(prepared);
    }
    let raw = RawValue::from_string(serde_json::to_string(input).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let request = ToolRequest {
        call_id: EntityId::new(),
        tool_id: CatalogId::parse("http.send")?,
        tool_version: ContractVersion::V0_1_0,
        input: &raw,
        source_control_revision: scenario.binding.control_revision(),
    };
    let prepared = registry.prepare(&scenario.binding, &request)?;
    host.approve(&scenario.binding, prepared.call())?;
    send_result(
        host,
        scenario,
        registry.execute_prepared(&scenario.binding, prepared)?,
    )
}
fn send_result(
    host: &ProofHost,
    scenario: &Scenario,
    result: ToolResult,
) -> ProofResult<HttpSendResult> {
    let stored = host.admission.invocation(result.invocation_id)?;
    let limit = usize::try_from(stored.requested.bytes.get()).map_err(|_| invalid())?;
    let invocation = stored.invocation;
    let record_artifact_id = match result.output_ref {
        Some(id) => {
            let bytes = host
                .evidence
                .read_artifact(scenario.project.project_id, id, limit)?;
            let output: HttpSendOutput = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            output.exchange_ref
        }
        None => {
            // Failed/uncertain invocations do not advertise success output. The
            // lower-level measured record remains immutable evidence, not a retry.
            let artifacts = host.evidence.artifacts()?;
            let mut records = artifacts.iter().filter(|artifact| {
                artifact.project_id == scenario.project.project_id
                    && artifact.origin_invocation_id == result.invocation_id
                    && artifact.kind.as_str() == "http-send-failure"
            });
            let id = records
                .next()
                .ok_or_else(|| result.error.clone().unwrap_or_else(invalid))?
                .artifact_id;
            if records.next().is_some() {
                return Err(invalid());
            }
            id
        }
    };
    let bytes =
        host.evidence
            .read_artifact(scenario.project.project_id, record_artifact_id, limit)?;
    let record: SendRecord = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if record.invocation_id != invocation.invocation_id
        || record.project_id != invocation.project_id
    {
        return Err(invalid());
    }
    Ok(HttpSendResult {
        invocation,
        record,
        record_artifact_id,
    })
}
fn rule(tls: bool, host: &str, port: u16) -> DestinationRule {
    DestinationRule {
        scheme: if tls { Scheme::Https } else { Scheme::Http },
        host: host.to_owned(),
        port,
        path: PathRule {
            kind: PathKind::Prefix,
            value: "/".to_owned(),
        },
        resolved_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
    }
}
fn config(
    mode: Mode,
    port: u16,
    zone: Arc<FixtureZone>,
    ingress: &IsolatedAuthority,
    upstream: &IsolatedAuthority,
) -> ProofResult<TransportConfig> {
    Ok(TransportConfig {
        mode,
        resolver: Resolver::Fixture(zone),
        upstream_roots: Arc::clone(&upstream.roots),
        client_roots: if mode == Mode::HttpsConnectTunnel {
            Arc::clone(&upstream.roots)
        } else {
            Arc::clone(&ingress.roots)
        },
        ingress_tls: if mode.tls() {
            Some(ingress.server_config_names(
                vec![HOST.to_owned(), "upstream.razen.invalid".to_owned()],
                mode.alpn(),
            )?)
        } else {
            None
        },
        tls_server_name: mode.tls().then(|| HOST.to_owned()),
        connect_authority: mode.tls().then(|| format!("{HOST}:{port}")),
    })
}
fn successful(result: &HttpSendResult) -> ProofResult<()> {
    if result.invocation.state != InvocationState::Completed
        || result.record.exchanges.is_empty()
        || !result.record.stream_errors.is_empty()
        || result
            .record
            .exchanges
            .iter()
            .any(|e| e.status != 200 || e.request_body_sha256 != e.response_body_sha256)
    {
        return Err(invalid());
    }
    Ok(())
}
fn wire(value: u64) -> ProofResult<WireInt> {
    Ok(WireInt::new(value)?)
}
#[track_caller]
fn invalid() -> ProofError {
    let location = std::panic::Location::caller();
    let source = location.file().rsplit('/').next().unwrap();
    eprintln!(
        "{{\"component\":\"transport-proof\",\"source\":{:?},\"validation_line\":{}}}",
        source,
        location.line()
    );
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Transport immutable facts are missing, inconsistent or incomplete",
    )
}

pub fn execute(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo_root: &Path,
    case_id: &CatalogId,
) -> ProofResult<CaseObservation> {
    let bytes = std::fs::read(repo_root.join("fixtures/scenarios/transport.json"))
        .map_err(|_| invalid())?;
    if bytes.len() > 65_536 {
        return Err(invalid());
    }
    let input: ScenarioInput = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    validate_scenario(&input)?;
    let mode = match case_id.as_str() {
        "NET-01" | "NET-05" | "NET-07" => Mode::Http1Forward,
        "NET-02" => Mode::HttpsConnectTunnel,
        "NET-03" | "NET-06" => Mode::HttpsHttp1Intercept,
        "NET-04" | "NET-08" => Mode::HttpsHttp2Intercept,
        _ => return Err(invalid()),
    };
    let limits = Limits::from_profile(profile)?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| invalid())?;
    let ingress = IsolatedAuthority::create()?;
    let upstream = IsolatedAuthority::create()?;
    let invalid_upstream = IsolatedAuthority::create()?;
    let tls = if mode.tls() {
        Some(upstream.server_config(HOST, mode.alpn())?)
    } else {
        None
    };
    let primary = Endpoint::start(
        &runtime,
        tls,
        mode == Mode::HttpsHttp2Intercept,
        limits.clone(),
        None,
        case_id.as_str() == "NET-05",
    )?;
    let primary_id = EntityId::new();
    let forbidden = Endpoint::start(&runtime, None, false, limits.clone(), None, true)?;
    let forbidden_id = EntityId::new();
    let pivot = Endpoint::start(
        &runtime,
        None,
        false,
        limits.clone(),
        Some(forbidden.url(false, EXCLUDED, "/echo?fixture=binary")),
        false,
    )?;
    let pivot_id = EntityId::new();
    let redirect_loop = Endpoint::start(
        &runtime,
        None,
        false,
        limits.clone(),
        Some("/redirect".to_owned()),
        false,
    )?;
    let redirect_id = EntityId::new();
    let bad_certificate = Endpoint::start(
        &runtime,
        Some(invalid_upstream.server_config(HOST, b"http/1.1")?),
        false,
        limits.clone(),
        None,
        false,
    )?;
    let bad_id = EntityId::new();
    let mut faults = Vec::new();
    if case_id.as_str() == "NET-07" {
        for (variant, response) in fault_responses(&limits) {
            faults.push((
                variant,
                Endpoint::raw(&runtime, response, limits.clone())?,
                EntityId::new(),
            ));
        }
    }
    let zone = Arc::new(FixtureZone::default());
    for name in [HOST, EXCLUDED, "upstream.razen.invalid"] {
        zone.publish(name, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])?;
    }
    let mut rules = vec![
        rule(mode.tls(), HOST, primary.address.port()),
        rule(false, HOST, forbidden.address.port()),
        rule(false, HOST, pivot.address.port()),
        rule(false, HOST, redirect_loop.address.port()),
        rule(true, HOST, bad_certificate.address.port()),
    ];
    for (_, endpoint, _) in &faults {
        rules.push(rule(false, HOST, endpoint.address.port()));
    }
    if case_id.as_str() == "NET-05" {
        zone.publish(
            "upstream.razen.invalid",
            vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
        )?;
        for endpoint in [&primary, &forbidden] {
            let mut ipv6_control = rule(false, "upstream.razen.invalid", endpoint.address.port());
            ipv6_control.resolved_addresses = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];
            rules.push(ipv6_control);
        }
    }
    // Literal-address calls do not inherit a hostname's grant, even when they
    // would reach the very same healthy owned private-loopback listener.
    let body: Vec<u8> = (0..profile.config().measurement.sample_body_bytes.get())
        .map(|i| (i % 256) as u8)
        .collect();
    let identity_secret = fixture_secret(repo_root)?;
    let scenario = Scenario::create(
        host,
        profile,
        rules,
        vec![rule(false, EXCLUDED, forbidden.address.port())],
        &body,
        identity_secret,
    )?;
    let fixture_artifact_id = publish(host, &scenario, "transport-scenario", &bytes)?;
    let mut report = Report {
        schema_version: ContractVersion::V0_1_0,
        case_id: case_id.clone(),
        project_id: scenario.project.project_id,
        profile_sha256: profile.sha256(),
        fixture_sha256: Digest::of(&bytes),
        fixture_artifact_id,
        provider_invocation_ids: Vec::new(),
        provider_result_artifact_ids: Vec::new(),
        receiver_artifact_ids: Vec::new(),
        exchanges: Vec::new(),
        attempts: Vec::new(),
        trust: None,
        measurement: None,
        measurement_artifact_id: None,
        secrecy_artifact_id: None,
    };
    let mut attachment_paths = Vec::new();
    let trust_before = if mode.tls() {
        Some(trust_snapshot()?)
    } else {
        None
    };
    let main_config = config(
        mode,
        primary.address.port(),
        Arc::clone(&zone),
        &ingress,
        &upstream,
    )?;
    let main_provider = provider(host, profile, main_config.clone())?;
    let main_url = primary.url(mode.tls(), HOST, &input.target);
    let pair = mode == Mode::HttpsHttp2Intercept;
    let request_count = if pair { 2 } else { 1 };
    if !profile
        .config()
        .transport
        .requests_per_case
        .get()
        .is_multiple_of(request_count)
    {
        return Err(invalid());
    }
    for _ in 0..profile.config().transport.requests_per_case.get() / request_count {
        let before = primary.receiver.count();
        let request =
            scenario.input(host, main_url.clone(), &input.headers, request_count, false)?;
        let result = send(host, &scenario, &main_provider, &request, false)?;
        successful(&result)?;
        append_exchanges(&mut report, &result, &primary, primary_id, before)?;
    }
    match case_id.as_str() {
        "NET-01" => {
            let mut measurement_headers = input.headers.clone();
            measurement_headers.push(Header {
                name: "x-razen-framing".to_owned(),
                value: "content-length".to_owned(),
            });
            let measurement = measurements::measure(profile, report.fixture_sha256, |route| {
                let before = primary.receiver.count();
                let request =
                    scenario.input(host, main_url.clone(), &measurement_headers, 1, false)?;
                let result = send(
                    host,
                    &scenario,
                    &main_provider,
                    &request,
                    route == Route::Direct,
                )?;
                successful(&result)?;
                let records = primary.receiver.records()?;
                let receiver = records
                    .iter()
                    .find(|r| r.sequence == before + 1)
                    .ok_or_else(invalid)?;
                if primary.receiver.count() != before + 1
                    || receiver.body_bytes != body.len() as u64
                    || receiver.body_sha256 != Digest::of(&body)
                {
                    return Err(invalid());
                }
                report
                    .provider_invocation_ids
                    .push(result.invocation.invocation_id);
                report
                    .provider_result_artifact_ids
                    .push(result.record_artifact_id);
                Ok(Sample {
                    invocation_id: result.invocation.invocation_id,
                    result_artifact_id: result.record_artifact_id,
                    elapsed_us: result.record.network_elapsed_us,
                    receiver_sequence: receiver.sequence,
                    body_bytes: receiver.body_bytes,
                    body_sha256: receiver.body_sha256,
                    receiver_before: before,
                    receiver_after: primary.receiver.count(),
                })
            })?;
            let raw = encode(&measurement)?;
            ensure_identity_public(&scenario.identity_secret, &raw)?;
            let id = write_owned(
                host,
                &scenario.binding,
                None,
                "transport-measurements",
                &raw,
                |origin, bytes| {
                    attachment_paths.push(measurements::write_raw(&host.workspace, bytes)?);
                    Ok(host
                        .evidence
                        .write_artifact(
                            scenario.project.project_id,
                            CatalogId::parse("transport-measurements")?,
                            origin,
                            bytes,
                            RedactionStatus::Original,
                        )?
                        .artifact_id)
                },
            )?;
            report.measurement_artifact_id = Some(id);
            report.measurement = Some(measurement);
        }
        "NET-05" => {
            for variant in &input.scope_variants {
                let use_primary = matches!(
                    variant.as_str(),
                    "dns_change" | "dns_mixed_answers" | "ungranted_loopback_port"
                );
                let observer = if use_primary { &primary } else { &forbidden };
                let observer_id = if use_primary {
                    primary_id
                } else {
                    forbidden_id
                };
                let healthy_config = config(
                    Mode::Http1Forward,
                    observer.address.port(),
                    Arc::clone(&zone),
                    &ingress,
                    &upstream,
                )?;
                let healthy_provider = provider(host, profile, healthy_config)?;
                let healthy_host = if matches!(
                    variant.as_str(),
                    "dns_change" | "dns_mixed_answers" | "ipv6_zone"
                ) {
                    "upstream.razen.invalid"
                } else {
                    HOST
                };
                let healthy_input = scenario.input(
                    host,
                    observer.url(false, healthy_host, &input.target),
                    &input.headers,
                    1,
                    false,
                )?;
                let healthy_before = observer.receiver.count();
                let healthy = send(host, &scenario, &healthy_provider, &healthy_input, false)?;
                successful(&healthy)?;
                let healthy_after = observer.receiver.count();
                let lookup_before = zone.lookups()?.len();
                let mut attempted_config = config(
                    Mode::Http1Forward,
                    primary.address.port(),
                    Arc::clone(&zone),
                    &ingress,
                    &upstream,
                )?;
                let attempted_url = match variant.as_str() {
                    "excluded" => forbidden.url(false, EXCLUDED, &input.target),
                    "redirect_pivot" => pivot.url(false, HOST, "/pivot"),
                    "dns_change" => {
                        // This very authority just reached the dual-stack observer
                        // through IPv4; the next real resolution is now IPv6.
                        zone.publish(HOST, vec![IpAddr::V6(Ipv6Addr::LOCALHOST)])?;
                        primary.url(false, HOST, &input.target)
                    }
                    "dns_mixed_answers" => {
                        zone.publish(
                            HOST,
                            vec![
                                IpAddr::V4(Ipv4Addr::LOCALHOST),
                                IpAddr::V6(Ipv6Addr::LOCALHOST),
                            ],
                        )?;
                        primary.url(false, HOST, &input.target)
                    }
                    "ipv4_mapped_ipv6" => format!(
                        "http://[::ffff:127.0.0.1]:{}/echo",
                        forbidden.address.port()
                    ),
                    "ungranted_loopback_port" => {
                        format!("http://127.0.0.1:{}/echo", primary.address.port())
                    }
                    "ungranted_private_port" => {
                        format!("http://127.0.0.1:{}/echo", forbidden.address.port())
                    }
                    "userinfo" => format!("http://user@{HOST}:{}/echo", forbidden.address.port()),
                    "ambiguous_authority" => {
                        format!("http://127.1:{}/echo", forbidden.address.port())
                    }
                    "ipv6_zone" => format!("http://[::1%25lo0]:{}/echo", forbidden.address.port()),
                    _ => return Err(invalid()),
                };
                attempted_config.connect_authority = None;
                let attempted_provider = provider(host, profile, attempted_config)?;
                let before = observer.receiver.connections();
                let request = raw_input(host, &scenario, &attempted_url, &input.headers)?;
                let attempt = attempt_send(host, &scenario, &attempted_provider, request)?;
                let after = observer.receiver.connections();
                let mut resolutions = zone.lookups()?[lookup_before..].to_vec();
                if variant == "dns_change" {
                    // Include the real prior successful resolution in the same
                    // immutable evidence, not a configured or invented count.
                    let all = zone.lookups()?;
                    if let Some(prior) = all[..lookup_before].iter().rev().find(|r| r.host == HOST)
                    {
                        resolutions.insert(0, prior.clone());
                    }
                }
                zone.publish(HOST, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])?;
                push_attempt(
                    host,
                    &scenario,
                    &mut report,
                    variant,
                    attempt,
                    AttemptObservations {
                        endpoint: observer_id,
                        before,
                        after,
                        healthy_before,
                        healthy_after,
                        healthy_invocation_id: healthy.invocation.invocation_id,
                        resolutions,
                    },
                )?;
            }
        }
        "NET-06" => {
            for variant in &input.tls_variants {
                let observer = if variant == "invalid_upstream_certificate" {
                    &bad_certificate
                } else {
                    &primary
                };
                let mut healthy_config = main_config.clone();
                if variant == "invalid_upstream_certificate" {
                    healthy_config.upstream_roots = Arc::clone(&invalid_upstream.roots);
                    healthy_config.connect_authority =
                        Some(format!("{HOST}:{}", bad_certificate.address.port()));
                }
                let healthy_provider = provider(host, profile, healthy_config)?;
                let healthy_before = observer.receiver.count();
                let healthy = send(
                    host,
                    &scenario,
                    &healthy_provider,
                    &scenario.input(
                        host,
                        observer.url(true, HOST, &input.target),
                        &input.headers,
                        1,
                        false,
                    )?,
                    false,
                )?;
                successful(&healthy)?;
                let healthy_after = observer.receiver.count();
                let mut attempted_config = main_config.clone();
                let attempted_url = if variant == "invalid_upstream_certificate" {
                    attempted_config.connect_authority =
                        Some(format!("{HOST}:{}", bad_certificate.address.port()));
                    bad_certificate.url(true, HOST, &input.target)
                } else {
                    main_url.clone()
                };
                if variant == "connect_sni_mismatch" {
                    attempted_config.tls_server_name = Some("upstream.razen.invalid".to_owned());
                }
                if variant == "client_root_removed" {
                    attempted_config.client_roots = Arc::new(rustls::RootCertStore::empty());
                }
                let attempted_provider = provider(host, profile, attempted_config)?;
                let mut attempted_headers = input.headers.clone();
                if variant == "decrypted_authority_mismatch" {
                    attempted_headers.push(Header {
                        name: "host".to_owned(),
                        value: format!("{EXCLUDED}:{}", primary.address.port()),
                    });
                }
                let request = scenario.input(host, attempted_url, &attempted_headers, 1, false)?;
                let before = if variant == "invalid_upstream_certificate" {
                    bad_certificate.receiver.count()
                } else {
                    primary.receiver.count()
                };
                let attempt = attempt_send(host, &scenario, &attempted_provider, request)?;
                let after = if variant == "invalid_upstream_certificate" {
                    bad_certificate.receiver.count()
                } else {
                    primary.receiver.count()
                };
                push_attempt(
                    host,
                    &scenario,
                    &mut report,
                    variant,
                    attempt,
                    AttemptObservations {
                        endpoint: if variant == "invalid_upstream_certificate" {
                            bad_id
                        } else {
                            primary_id
                        },
                        before,
                        after,
                        healthy_before,
                        healthy_after,
                        healthy_invocation_id: healthy.invocation.invocation_id,
                        resolutions: Vec::new(),
                    },
                )?;
            }
        }
        "NET-07" => {
            for variant in &input.body_variants {
                let healthy_before = primary.receiver.count();
                let healthy = send(
                    host,
                    &scenario,
                    &main_provider,
                    &scenario.input(host, main_url.clone(), &input.headers, 1, false)?,
                    false,
                )?;
                successful(&healthy)?;
                let healthy_after = primary.receiver.count();
                let (endpoint, endpoint_id) = if variant == "redirect_limit" {
                    (&redirect_loop, redirect_id)
                } else {
                    let (_, endpoint, id) = faults
                        .iter()
                        .find(|(name, _, _)| name == variant)
                        .ok_or_else(invalid)?;
                    (endpoint, *id)
                };
                let attempted_provider = provider(
                    host,
                    profile,
                    config(
                        Mode::Http1Forward,
                        endpoint.address.port(),
                        Arc::clone(&zone),
                        &ingress,
                        &upstream,
                    )?,
                )?;
                let before = endpoint.receiver.count();
                let attempt = attempt_send(
                    host,
                    &scenario,
                    &attempted_provider,
                    scenario.input(
                        host,
                        endpoint.url(false, HOST, "/fault"),
                        &input.headers,
                        1,
                        false,
                    )?,
                )?;
                let after = endpoint.receiver.count();
                push_attempt(
                    host,
                    &scenario,
                    &mut report,
                    variant,
                    attempt,
                    AttemptObservations {
                        endpoint: endpoint_id,
                        before,
                        after,
                        healthy_before,
                        healthy_after,
                        healthy_invocation_id: healthy.invocation.invocation_id,
                        resolutions: Vec::new(),
                    },
                )?;
            }
        }
        "NET-08" => {
            let before = primary.receiver.count();
            let request = scenario.input(host, main_url.clone(), &input.headers, 3, true)?;
            let result = send(host, &scenario, &main_provider, &request, false)?;
            if result.record.stream_errors.is_empty() || result.record.exchanges.len() != 2 {
                return Err(invalid());
            }
            report.exchanges.clear();
            append_exchanges(&mut report, &result, &primary, primary_id, before)?;
            let reset = result.record.stream_errors.first().ok_or_else(invalid)?;
            let upstream = upstream_stream_id(&result.record, reset.stream_id)?;
            let records = primary.receiver.records()?;
            let failed = records
                .iter()
                .find(|r| r.sequence > before && r.stream_id == upstream && r.error.is_some())
                .ok_or_else(invalid)?;
            let evidence = AttemptEvidence {
                variant: "h2_stream_reset".to_owned(),
                invocation_id: result.invocation.invocation_id,
                observer_endpoint_id: primary_id,
                before,
                after: primary.receiver.count(),
                healthy_before: failed.sequence,
                counter_kind: "request_observed".to_owned(),
                healthy_after: primary.receiver.count(),
                healthy_invocation_id: result.invocation.invocation_id,
                resolutions: Vec::new(),
            };
            let artifact_id = publish(host, &scenario, "transport-attempt", &encode(&evidence)?)?;
            report.attempts.push(AttemptFact {
                variant: evidence.variant,
                invocation_id: result.invocation.invocation_id,
                attempt_artifact_id: artifact_id,
                result_artifact_id: Some(result.record_artifact_id),
                error_code: reset.error.code,
                observer_endpoint_id: primary_id,
                forbidden_before: before,
                forbidden_after: primary.receiver.count(),
                counter_kind: "request_observed".to_owned(),
                healthy_arrivals: primary
                    .receiver
                    .count()
                    .checked_sub(failed.sequence)
                    .ok_or_else(invalid)?,
                healthy_invocation_id: result.invocation.invocation_id,
                captured_bytes: 0,
                representation: "rejected".to_owned(),
                replacement_published: false,
                redirects_observed: 0,
                resolution_count: 0,
                resolved_addresses: Vec::new(),
                connection_id: Some(reset.connection_id),
                stream_id: Some(reset.stream_id),
                stream_started_us: Some(failed.started_us),
                reset_observed_us: Some(reset.observed_us),
            });
        }
        _ => {}
    }
    if let Some(before) = trust_before {
        let after = trust_snapshot()?;
        let before_bytes = encode(&before)?;
        let after_bytes = encode(&after)?;
        report.trust = Some(TrustFact {
            before_sha256: Digest::of(&before_bytes),
            after_sha256: Digest::of(&after_bytes),
            before_artifact_id: publish(host, &scenario, "transport-trust", &before_bytes)?,
            after_artifact_id: publish(host, &scenario, "transport-trust", &after_bytes)?,
            public_root_artifact_id: publish(
                host,
                &scenario,
                "transport-client-root",
                &ingress.public_der,
            )?,
            upstream_root_artifact_id: publish(
                host,
                &scenario,
                "transport-upstream-root",
                &upstream.public_der,
            )?,
        });
    }
    for (endpoint, endpoint_id) in [
        (&primary, primary_id),
        (&forbidden, forbidden_id),
        (&pivot, pivot_id),
        (&redirect_loop, redirect_id),
        (&bad_certificate, bad_id),
    ]
    .into_iter()
    .chain(faults.iter().map(|(_, endpoint, id)| (endpoint, *id)))
    {
        let evidence = ReceiverEvidence {
            endpoint_id,
            port: endpoint.address.port(),
            final_count: endpoint.receiver.count(),
            accepted_connections: endpoint.receiver.connections(),
            records: endpoint.receiver.records()?,
        };
        report.receiver_artifact_ids.push(publish(
            host,
            &scenario,
            "transport-receiver",
            &encode(&evidence)?,
        )?);
    }
    let pre_scan_report = encode(&report)?;
    let mut scanned = Vec::new();
    for artifact in host
        .evidence
        .artifacts()?
        .into_iter()
        .filter(|a| a.project_id == scenario.project.project_id)
    {
        let bytes = host.evidence.read_artifact(
            scenario.project.project_id,
            artifact.artifact_id,
            8 * 1_048_576,
        )?;
        ensure_identity_public(&scenario.identity_secret, &bytes)?;
        for authority in [&ingress, &upstream, &invalid_upstream] {
            authority.ensure_public(&bytes)?;
        }
        scanned.push(ScannedArtifact {
            artifact_id: artifact.artifact_id,
            sha256: artifact.sha256,
            length_bytes: artifact.length_bytes.get(),
        });
    }
    ensure_identity_public(&scenario.identity_secret, &pre_scan_report)?;
    for authority in [&ingress, &upstream, &invalid_upstream] {
        authority.ensure_public(&pre_scan_report)?;
    }
    let scan = SecrecyEvidence {
        project_id: scenario.project.project_id,
        identity_id: scenario.binding.identity_id(),
        protected_identity_values: u64::from(!scenario.identity_secret.is_empty()),
        protected_key_values: (ingress.protected_key_count()?
            + upstream.protected_key_count()?
            + invalid_upstream.protected_key_count()?) as u64,
        report_sha256: Digest::of(&pre_scan_report),
        scanned,
    };
    report.secrecy_artifact_id = Some(publish(
        host,
        &scenario,
        "transport-secrecy",
        &encode(&scan)?,
    )?);
    let report_value = serde_json::to_value(&report).map_err(|_| invalid())?;
    prohibited(&encode(&report)?)?;
    let observed = derive(
        &report,
        host.project.project_id,
        profile,
        &host.evidence,
        &host.ledger,
    )?;
    // Owned listeners and runtime tasks are torn down before the immutable report
    // is returned. Read-only verification never resurrects them.
    drop(main_provider);
    drop(faults);
    drop(bad_certificate);
    drop(redirect_loop);
    drop(pivot);
    drop(forbidden);
    drop(primary);
    drop(runtime);
    Ok(CaseObservation {
        case_id: case_id.clone(),
        observed,
        report: report_value,
        attachment_paths,
    })
}

fn validate_scenario(input: &ScenarioInput) -> ProofResult<()> {
    if input.schema_version != ContractVersion::V0_1_0
        || !input.fixture_only
        || input.authority != HOST
        || input.excluded_authority != EXCLUDED
        || input.method != "POST"
        || input.target != "/echo?fixture=binary"
        || input.body.pattern != "ascending-octets"
        || input.body.length_from != "measurement.sample_body_bytes"
        || input.h2_max_concurrent_streams != 2
        || input.h2_reset_reason != "CANCEL"
        || input.required_modes
            != [
                Mode::Http1Forward,
                Mode::HttpsConnectTunnel,
                Mode::HttpsHttp1Intercept,
                Mode::HttpsHttp2Intercept,
            ]
        || input.scope_variants != SCOPE_VARIANTS
        || input.tls_variants != TLS_VARIANTS
        || input.body_variants != BODY_VARIANTS
    {
        return Err(invalid());
    }
    Ok(())
}
const SCOPE_VARIANTS: &[&str] = &[
    "excluded",
    "redirect_pivot",
    "dns_change",
    "dns_mixed_answers",
    "ipv4_mapped_ipv6",
    "ungranted_loopback_port",
    "ungranted_private_port",
    "userinfo",
    "ambiguous_authority",
    "ipv6_zone",
];
const TLS_VARIANTS: &[&str] = &[
    "invalid_upstream_certificate",
    "connect_sni_mismatch",
    "decrypted_authority_mismatch",
    "client_root_removed",
];
const BODY_VARIANTS: &[&str] = &[
    "oversized_body",
    "truncated_content_length",
    "truncated_chunked",
    "conflicting_framing",
    "unsupported_encoding",
    "unsupported_protocol",
    "redirect_limit",
];

fn raw_input(
    host: &ProofHost,
    scenario: &Scenario,
    url: &str,
    headers: &[Header],
) -> ProofResult<HttpSendInput> {
    let mut headers = headers.to_vec();
    if let Ok(parsed) = url::Url::parse(url) {
        headers.push(Header {
            name: "host".to_owned(),
            value: parsed.authority().to_owned(),
        });
    }
    scenario.install_input(
        host,
        RequestSnapshot {
            body_snapshot_id: scenario.snapshot_id,
            body_revision: WireInt::ZERO,
            url: url.to_owned(),
            method: "POST".to_owned(),
            headers,
            request_count: wire(1)?,
            reset_first_stream: false,
        },
    )
}
fn attempt_send(
    host: &ProofHost,
    scenario: &Scenario,
    registry: &Registry,
    input: HttpSendInput,
) -> ProofResult<Result<HttpSendResult, (EntityId, ProofError)>> {
    let raw = RawValue::from_string(serde_json::to_string(&input).map_err(|_| invalid())?)
        .map_err(|_| invalid())?;
    let request = ToolRequest {
        call_id: EntityId::new(),
        tool_id: CatalogId::parse("http.send")?,
        tool_version: ContractVersion::V0_1_0,
        input: &raw,
        source_control_revision: scenario.binding.control_revision(),
    };
    match registry.prepare(&scenario.binding, &request) {
        Ok(prepared) => {
            host.approve(&scenario.binding, prepared.call())?;
            let result = send_result(
                host,
                scenario,
                registry.execute_prepared(&scenario.binding, prepared)?,
            )?;
            if result.record.stream_errors.is_empty() {
                return Err(invalid());
            }
            Ok(Ok(result))
        }
        Err(error) => {
            let origin = EntityId::new();
            let bytes = encode(&input)?;
            let artifact = host.evidence.write_artifact(
                scenario.project.project_id,
                CatalogId::parse("http-rejected-input")?,
                origin,
                &bytes,
                RedactionStatus::Original,
            )?;
            let call = PreparedCall {
                invocation_id: origin,
                call_id: EntityId::new(),
                tool_id: CatalogId::parse("http.send")?,
                tool_version: ContractVersion::V0_1_0,
                input_ref: artifact.artifact_id,
                input_sha256: artifact.sha256,
                input_revision: WireInt::ZERO,
                source_control_revision: scenario.binding.control_revision(),
                requested: Usage::default(),
            };
            host.admission
                .record_rejection(&scenario.binding, &call, error.clone())?;
            Ok(Err((origin, error)))
        }
    }
}
struct AttemptObservations {
    endpoint: EntityId,
    before: u64,
    after: u64,
    healthy_before: u64,
    healthy_after: u64,
    healthy_invocation_id: EntityId,
    resolutions: Vec<ResolutionFact>,
}

fn push_attempt(
    host: &ProofHost,
    scenario: &Scenario,
    report: &mut Report,
    variant: &str,
    result: Result<HttpSendResult, (EntityId, ProofError)>,
    observations: AttemptObservations,
) -> ProofResult<()> {
    let AttemptObservations {
        endpoint,
        before,
        after,
        healthy_before,
        healthy_after,
        healthy_invocation_id,
        resolutions,
    } = observations;
    let (invocation_id, result_artifact_id, error_code, redirects, captured_bytes) = match result {
        Ok(result) => {
            let error = result
                .record
                .stream_errors
                .first()
                .ok_or_else(invalid)?
                .error
                .code;
            report
                .provider_invocation_ids
                .push(result.invocation.invocation_id);
            report
                .provider_result_artifact_ids
                .push(result.record_artifact_id);
            let captured = result
                .record
                .partial_captures
                .iter()
                .try_fold(0_u64, |sum, partial| {
                    sum.checked_add(partial.capture.length_bytes)
                })
                .ok_or_else(invalid)?;
            (
                result.invocation.invocation_id,
                Some(result.record_artifact_id),
                error,
                result.record.redirects_observed,
                captured,
            )
        }
        Err((id, error)) => (id, None, error.code, 0, 0),
    };
    let counter_kind = if SCOPE_VARIANTS.contains(&variant) {
        "tcp_accept"
    } else {
        "request_observed"
    };
    let addresses = resolutions
        .iter()
        .flat_map(|resolution| resolution.addresses.iter().copied())
        .collect();
    let resolution_count = resolutions.len() as u64;
    let evidence = AttemptEvidence {
        variant: variant.to_owned(),
        invocation_id,
        observer_endpoint_id: endpoint,
        before,
        after,
        healthy_before,
        healthy_after,
        healthy_invocation_id,
        resolutions,
        counter_kind: counter_kind.to_owned(),
    };
    let artifact_id = publish(host, scenario, "transport-attempt", &encode(&evidence)?)?;
    report.attempts.push(AttemptFact {
        variant: variant.to_owned(),
        invocation_id,
        attempt_artifact_id: artifact_id,
        result_artifact_id,
        error_code,
        observer_endpoint_id: endpoint,
        forbidden_before: before,
        forbidden_after: after,
        counter_kind: counter_kind.to_owned(),
        healthy_arrivals: healthy_after
            .checked_sub(healthy_before)
            .ok_or_else(invalid)?,
        healthy_invocation_id,
        captured_bytes,
        representation: if captured_bytes > 0 {
            "truncated"
        } else {
            "rejected"
        }
        .to_owned(),
        replacement_published: false,
        redirects_observed: redirects,
        resolution_count,
        resolved_addresses: addresses,
        connection_id: None,
        stream_id: None,
        stream_started_us: None,
        reset_observed_us: None,
    });
    Ok(())
}
fn upstream_stream_id(record: &SendRecord, downstream: u32) -> ProofResult<u32> {
    if record.mode == Mode::HttpsHttp2Intercept {
        return record
            .stream_links
            .iter()
            .find(|link| link.downstream_stream_id == downstream)
            .map(|link| link.upstream_stream_id)
            .ok_or_else(invalid);
    }
    if downstream != 0 {
        return Err(invalid());
    }
    Ok(0)
}

fn append_exchanges(
    report: &mut Report,
    result: &HttpSendResult,
    receiver: &Endpoint,
    endpoint_id: EntityId,
    before: u64,
) -> ProofResult<()> {
    report
        .provider_invocation_ids
        .push(result.invocation.invocation_id);
    report
        .provider_result_artifact_ids
        .push(result.record_artifact_id);
    let records = receiver.receiver.records()?;
    for exchange in &result.record.exchanges {
        let upstream = upstream_stream_id(&result.record, exchange.stream_id)?;
        let received = records
            .iter()
            .find(|r| r.sequence > before && r.stream_id == upstream && r.error.is_none())
            .ok_or_else(invalid)?;
        report.exchanges.push(exchange_fact(
            &result.record,
            result.record_artifact_id,
            exchange,
            received,
            endpoint_id,
        ));
    }
    Ok(())
}
fn exchange_fact(
    record: &SendRecord,
    artifact: EntityId,
    exchange: &http_send::ExchangeOutput,
    receiver: &ReceiverRecord,
    endpoint_id: EntityId,
) -> ExchangeFact {
    let connect_authority = record.connect_authority.clone();
    let server_name = record.tls_server_name.clone();
    let authority = receiver.authority.clone();
    ExchangeFact {
        project_id: record.project_id,
        invocation_id: record.invocation_id,
        result_artifact_id: artifact,
        receiver_endpoint_id: endpoint_id,
        receiver_sequence: receiver.sequence,
        mode: record.mode,
        inspection: if record.mode == Mode::HttpsConnectTunnel {
            "opaque"
        } else {
            "inspected"
        }
        .to_owned(),
        request_snapshot_id: record.input_snapshot_id,
        response_snapshot_id: exchange.response_snapshot_id,
        status: exchange.status,
        receiver_method: receiver.method.clone(),
        receiver_target: receiver.target.clone(),
        receiver_headers: receiver.headers.clone(),
        receiver_body_sha256: receiver.body_sha256,
        request_body_sha256: exchange.request_body_sha256,
        response_body_sha256: exchange.response_body_sha256,
        connection_id: exchange.connection_id,
        stream_id: exchange.stream_id,
        receiver_started_us: receiver.started_us,
        receiver_finished_us: receiver.finished_us,
        client_http_version: exchange.client_http_version.clone(),
        upstream_http_version: receiver.http_version.clone(),
        client_alpn: exchange.client_alpn.clone(),
        upstream_alpn: exchange.upstream_alpn.clone(),
        upstream_peer_certificate_sha256: exchange.upstream_peer_certificate_sha256,
        connect_host: connect_authority
            .as_ref()
            .and_then(|a| url::Url::parse(&format!("https://{a}/")).ok())
            .and_then(|url| url.host_str().map(str::to_owned)),
        connect_authority,
        tls_server_name: server_name,
        request_authority: authority,
        tunnel_client_bytes: record.tunnel_bytes.map(|b| b.0),
        tunnel_upstream_bytes: record.tunnel_bytes.map(|b| b.1),
    }
}
fn fault_responses(limits: &Limits) -> Vec<(String, Vec<u8>)> {
    let mut oversized = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
        limits.body_bytes + 1
    )
    .into_bytes();
    oversized.resize(oversized.len() + limits.body_bytes + 1, b'X');
    vec![
        ("oversized_body".to_owned(), oversized),
        (
            "truncated_content_length".to_owned(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort".to_vec(),
        ),
        (
            "truncated_chunked".to_owned(),
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10\r\nshort".to_vec(),
        ),
        (
            "conflicting_framing".to_owned(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nshort!".to_vec(),
        ),
        (
            "unsupported_encoding".to_owned(),
            b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 5\r\n\r\nshort".to_vec(),
        ),
        (
            "unsupported_protocol".to_owned(),
            b"HTTP/3.0 200 OK\r\nContent-Length: 5\r\n\r\nshort".to_vec(),
        ),
    ]
}
fn trust_snapshot() -> ProofResult<TrustSnapshot> {
    let mut domains = Vec::new();
    for (domain, args) in [
        ("user", vec!["dump-trust-settings"]),
        ("admin", vec!["dump-trust-settings", "-d"]),
        ("system", vec!["dump-trust-settings", "-s"]),
    ] {
        let args: Vec<_> = args.iter().map(OsStr::new).collect();
        let output = capture_status(
            Path::new("/usr/bin/security"),
            &args,
            None,
            CommandLimits {
                stdin_bytes: 0,
                stdout_bytes: 1_048_576,
                stderr_bytes: 65_536,
                timeout: Duration::from_secs(2),
            },
        )?;
        prohibited(&output.stdout)?;
        prohibited(&output.stderr)?;
        let stdout = String::from_utf8(output.stdout).map_err(|_| invalid())?;
        let stderr = String::from_utf8(output.stderr).map_err(|_| invalid())?;
        if output.exit_code != 0
            && !(output.exit_code == 1
                && format!("{stdout}{stderr}").contains("No Trust Settings were found"))
        {
            return Err(invalid());
        }
        domains.push(TrustDomain {
            domain: domain.to_owned(),
            exit_code: output.exit_code,
            stdout,
            stderr,
        });
    }
    Ok(TrustSnapshot { domains })
}
fn prohibited(bytes: &[u8]) -> ProofResult<()> {
    for marker in [
        b"PRIVATE KEY".as_slice(),
        b"CLIENT_RANDOM",
        b"SSLKEYLOGFILE",
        b"RAZEN_FIXTURE_CREDENTIAL_DO_NOT_EXPORT_20261116",
        b"RAZEN_FIXTURE_HOST_CANARY_20261116",
        b"RAZEN_FIXTURE_MANAGEMENT_CANARY_20261116",
        b"RAZEN_FIXTURE_OTHER_INVOCATION_CANARY_20261116",
        b"/Users/",
        b"/home/",
    ] {
        if bytes.windows(marker.len()).any(|window| window == marker) {
            return Err(invalid());
        }
    }
    Ok(())
}
fn encode(value: &impl Serialize) -> ProofResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| invalid())
}

pub fn verify_report(
    result: &crate::domain::proofs::ProofResult,
    report: &Value,
    project: EntityId,
    run: &Run,
    profile: &LoadedProfile,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<Assertions> {
    validate_wire_value(report, 0)?;
    let bytes = serde_json::to_vec(report).map_err(|_| invalid())?;
    if bytes.len()
        > profile
            .config()
            .protocol
            .invocation_output_limit_bytes
            .get() as usize
        || result.run_id != run.run_id
        || run.run_id != ledger.run_id()
        || run.profile_sha256 != profile.sha256()
    {
        return Err(invalid());
    }
    let report: Report = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if report.case_id != result.case_id
        || run
            .environment
            .fixture_digests
            .get(&CatalogId::parse("transport-scenarios")?)
            != Some(&report.fixture_sha256)
    {
        return Err(invalid());
    }
    if let Some(id) = report.measurement_artifact_id {
        let actual = evidence.artifact(report.project_id, id)?;
        let matching: Vec<_> = result
            .evidence_refs
            .iter()
            .filter_map(|reference| match reference {
                crate::domain::evidence::EvidenceRef::Artifact {
                    artifact_id,
                    sha256,
                    range,
                } if *sha256 == actual.sha256 && range.is_none() => Some(*artifact_id),
                _ => None,
            })
            .collect();
        if matching.len() != 1 {
            return Err(invalid());
        }
        let raw = owned_artifact(
            evidence,
            ledger,
            project,
            matching[0],
            "case-execution-attachment",
        )?;
        if Digest::of(&raw) != actual.sha256 {
            return Err(invalid());
        }
    }
    derive(&report, project, profile, evidence, ledger)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparedRecord {
    input: HttpSendInput,
    request: RequestSnapshot,
    request_snapshot_sha256: Digest,
    body_snapshot_sha256: Digest,
    mode: Mode,
    provider_configuration_id: EntityId,
    #[serde(default)]
    connect_authority: Option<String>,
    #[serde(default)]
    tls_server_name: Option<String>,
}
struct VerifiedSend {
    record: SendRecord,
    input: PreparedRecord,
}
fn owned_artifact(
    evidence: &EvidenceStore,
    ledger: &Ledger,
    project: EntityId,
    id: EntityId,
    kind: &str,
) -> ProofResult<Vec<u8>> {
    let artifact = evidence.artifact(project, id)?;
    if artifact.kind.as_str() != kind {
        return Err(invalid());
    }
    let invocation = ledger.read_invocation(artifact.origin_invocation_id)?;
    if invocation.invocation.project_id != project
        || !matches!(
            invocation.invocation.state,
            InvocationState::Completed
                | InvocationState::Failed
                | InvocationState::OutcomeUnknown
                | InvocationState::Rejected
        )
    {
        return Err(invalid());
    }
    invocation.invocation.validate(Some(&invocation.history))?;
    let bytes = evidence.read_artifact(project, id, 8 * 1_048_576)?;
    // Roots are DER rather than textual secret-bearing configuration. Their
    // content is still checked by the immutable artifact hash above.
    if !kind.ends_with("-root") {
        prohibited(&bytes)?;
    }
    Ok(bytes)
}
fn success_output(
    project: EntityId,
    invocation: &crate::domain::invocation::Invocation,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<(HttpSendOutput, Vec<u8>)> {
    let id = invocation.output_ref.ok_or_else(invalid)?;
    let bytes = owned_artifact(evidence, ledger, project, id, "http-send-output")?;
    if evidence.artifact(project, id)?.origin_invocation_id != invocation.invocation_id {
        return Err(invalid());
    }
    let output: HttpSendOutput = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    Ok((output, bytes))
}
fn verified_send(
    project: EntityId,
    id: EntityId,
    evidence: &EvidenceStore,
    ledger: &Ledger,
    profile: &LoadedProfile,
) -> ProofResult<VerifiedSend> {
    let artifact = evidence.artifact(project, id)?;
    let kind = &artifact.kind;
    if !["http-send-result", "http-send-failure"].contains(&kind.as_str()) {
        return Err(invalid());
    }
    let bytes = owned_artifact(evidence, ledger, project, id, kind.as_str())?;
    let record: SendRecord = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if record.schema_version != ContractVersion::V0_1_0
        || record.project_id != project
        || record.exchanges.len() > 3
        || record.stream_errors.len() > 4
        || record.stream_links.len() > 3
        || (record.mode != Mode::HttpsHttp2Intercept && !record.stream_links.is_empty())
    {
        return Err(invalid());
    }
    for (index, link) in record.stream_links.iter().enumerate() {
        if link.downstream_stream_id == 0
            || link.downstream_stream_id > i32::MAX as u32
            || link.downstream_stream_id.is_multiple_of(2)
            || link.upstream_stream_id == 0
            || link.upstream_stream_id > i32::MAX as u32
            || link.upstream_stream_id.is_multiple_of(2)
            || record.stream_links[..index].iter().any(|previous| {
                previous.downstream_stream_id == link.downstream_stream_id
                    || previous.upstream_stream_id == link.upstream_stream_id
            })
        {
            return Err(invalid());
        }
    }
    let stored = ledger.read_invocation(record.invocation_id)?;
    let invocation = &stored.invocation;
    if evidence.artifact(project, id)?.origin_invocation_id != invocation.invocation_id
        || invocation.tool_id.as_str() != "http.send"
        || invocation.provider_digest
            != ledger
                .read_tool(&CatalogId::parse("http.send")?)?
                .provider_digest
        || invocation.project_id != project
        || invocation.grant_id.is_none()
    {
        return Err(invalid());
    }
    let grant = ledger.read_grant(invocation.grant_id.ok_or_else(invalid)?)?;
    if grant.project_id != project
        || grant.bounded_input_sha256 != invocation.input_sha256
        || grant.identity_id != invocation.identity_id
        || grant.provider_digest != invocation.provider_digest
        || grant.tool_id != invocation.tool_id
        || grant.tool_version != invocation.tool_version
        || grant.scope_revision != invocation.scope_revision
        || stored.requested.units > grant.limits.units
        || stored.requested.bytes > grant.limits.bytes
        || stored.requested.cpu_us > grant.limits.cpu_us
        || stored.requested.elapsed_us > grant.limits.elapsed_us
    {
        return Err(invalid());
    }
    let input_artifact = evidence.artifact(project, invocation.input_ref)?;
    if input_artifact.origin_invocation_id != invocation.invocation_id
        || input_artifact.sha256 != invocation.input_sha256
    {
        return Err(invalid());
    }
    let input_bytes = owned_artifact(
        evidence,
        ledger,
        project,
        invocation.input_ref,
        "http-send-input",
    )?;
    let input: PreparedRecord = serde_json::from_slice(&input_bytes).map_err(|_| invalid())?;
    if record.provider_configuration_id != input.provider_configuration_id {
        return Err(invalid());
    }
    if input.mode != record.mode
        || input.input.identity_id != invocation.identity_id
        || input.request.body_snapshot_id != record.input_snapshot_id
        || input.request.body_revision != record.input_revision
        || input.request.request_count.get() == 0
        || input.request.request_count.get() > 3
    {
        return Err(invalid());
    }
    let limits = Limits::from_profile(profile)?;
    let descriptor = evidence.snapshot(
        project,
        input.input.request_snapshot_id,
        input.input.base_revision,
    )?;
    if descriptor.truncated
        || descriptor.representation != Representation::RawBody
        || descriptor.derived_from != Some(input.request.body_snapshot_id)
        || descriptor.sha256 != input.request_snapshot_sha256
        || descriptor.headers
            != vec![Header {
                name: "content-type".to_owned(),
                value: "application/vnd.razen.http-request+json".to_owned(),
            }]
        || descriptor.length_bytes.get() > 524_288
    {
        return Err(invalid());
    }
    let descriptor_origin = evidence
        .artifact(project, descriptor.body_ref)?
        .origin_invocation_id;
    let publisher = ledger.read_invocation(descriptor_origin)?;
    if publisher.invocation.state != InvocationState::Completed
        || publisher.invocation.tool_id.as_str() != PREPARE
        || publisher.invocation.project_id != project
        || publisher.invocation.output_ref != Some(descriptor.body_ref)
        || publisher.invocation.identity_id != invocation.identity_id
        || publisher.invocation.grant_id.is_none()
        || publisher.reserved_units != WireInt::ZERO
    {
        return Err(invalid());
    }
    let publisher_grant = ledger.read_grant(publisher.invocation.grant_id.ok_or_else(invalid)?)?;
    if publisher_grant.project_id != project
        || publisher_grant.identity_id != invocation.identity_id
        || publisher_grant.bounded_input_sha256 != publisher.invocation.input_sha256
        || publisher_grant.tool_id.as_str() != PREPARE
        || publisher_grant.provider_digest != publisher.invocation.provider_digest
        || publisher.requested.units > publisher_grant.limits.units
        || publisher.requested.bytes > publisher_grant.limits.bytes
        || publisher.requested.cpu_us > publisher_grant.limits.cpu_us
        || publisher.requested.elapsed_us > publisher_grant.limits.elapsed_us
    {
        return Err(invalid());
    }
    publisher.invocation.validate(Some(&publisher.history))?;
    let descriptor_bytes = capture::read_complete(
        evidence,
        project,
        input.input.request_snapshot_id,
        input.input.base_revision,
        &limits,
    )?;
    let resolved: RequestSnapshot =
        serde_json::from_slice(&descriptor_bytes).map_err(|_| invalid())?;
    let canonical_descriptor = encode(&resolved)?;
    if canonical_descriptor != descriptor_bytes || canonical_descriptor != encode(&input.request)? {
        return Err(invalid());
    }
    let scope = ledger.read_scope(ledger.read_project(project)?.scope_policy_id)?;
    if scope.revision != invocation.scope_revision
        || record.connections.len() > 32
        || record.redirect_chain.len() > limits.redirects + 1
        || record.redirects_observed != record.redirect_chain.len() as u64
        || (!record.exchanges.is_empty() && record.connections.is_empty())
    {
        return Err(invalid());
    }
    let mut redirect_origin = input.request.url.as_str();
    for redirect in &record.redirect_chain {
        if redirect.from_url != redirect_origin
            || ![301, 302, 303, 307, 308].contains(&redirect.status)
        {
            return Err(invalid());
        }
        if redirect.capture.truncated
            || redirect.capture.length_bytes > profile.config().transport.body_limit_bytes.get()
            || redirect
                .capture
                .chunks
                .iter()
                .try_fold(0_u64, |sum, n| sum.checked_add(*n))
                .ok_or_else(invalid)?
                != redirect.capture.length_bytes
            || redirect
                .capture
                .chunks
                .iter()
                .any(|n| *n == 0 || *n > profile.config().transport.chunk_limit_bytes.get())
        {
            return Err(invalid());
        }
        transport::scope_connector::normalize(&redirect.to_url)?;
        redirect_origin = &redirect.to_url;
    }
    for connection in &record.connections {
        let destination = transport::scope_connector::normalize(&connection.url)?;
        if destination.port() != connection.connected_peer.port()
            || connection.resolved_addresses.is_empty()
            || connection.resolved_addresses.len() > 16
            || (connection.url != input.request.url
                && !record
                    .redirect_chain
                    .iter()
                    .any(|r| r.to_url == connection.url))
        {
            return Err(invalid());
        }
        scope.authorize(&crate::domain::authority::DestinationCheck {
            destination: &destination,
            resolved_addresses: &connection.resolved_addresses,
            chosen_address: connection.connected_peer.ip(),
            connect_authority: connection.connect_authority.as_deref(),
            server_name: connection.declared_server_name.as_deref(),
            request_authority: connection.request_authority.as_deref(),
        })?;
    }
    if !record.exchanges.is_empty() && record.mode.tls() {
        if record.connect_authority != input.connect_authority {
            return Err(invalid());
        }
        if record.mode != Mode::HttpsConnectTunnel
            && record.tls_server_name != input.tls_server_name
        {
            return Err(invalid());
        }
        let expected_alpn = std::str::from_utf8(record.mode.alpn()).map_err(|_| invalid())?;
        if record.exchanges.iter().any(|e| {
            e.client_alpn.as_deref() != Some(expected_alpn)
                || e.upstream_alpn.as_deref() != Some(expected_alpn)
                || e.upstream_peer_certificate_sha256.is_none()
        }) {
            return Err(invalid());
        }
    }
    let source = evidence.snapshot(project, record.input_snapshot_id, record.input_revision)?;
    let body = capture::read_complete(
        evidence,
        project,
        record.input_snapshot_id,
        record.input_revision,
        &limits,
    )?;
    let expected_body = Digest::of(&body);
    let mut accounted = (body.len() as u64)
        .checked_add(record.io.attempted_request_body_bytes)
        .and_then(|n| n.checked_add(record.io.captured_response_body_bytes))
        .ok_or_else(invalid)?;
    let mut captured_response_bytes = record
        .redirect_chain
        .iter()
        .try_fold(0_u64, |sum, r| sum.checked_add(r.capture.length_bytes))
        .ok_or_else(invalid)?;
    if !record.exchanges.is_empty() {
        let dispatches = if record.mode == Mode::HttpsHttp2Intercept {
            input.request.request_count.get()
        } else {
            record.connections.len() as u64
        };
        if record.io.attempted_request_body_bytes
            != (body.len() as u64)
                .checked_mul(dispatches)
                .ok_or_else(invalid)?
        {
            return Err(invalid());
        }
    }
    for exchange in &record.exchanges {
        if exchange.request_body_sha256 != expected_body
            || exchange.response_capture.length_bytes > limits.body_bytes as u64
            || exchange.response_capture.sha256 != exchange.response_body_sha256
            || exchange.response_capture.truncated
            || exchange.response_capture.chunks.len() > limits.body_bytes
            || exchange
                .response_capture
                .chunks
                .iter()
                .any(|n| *n == 0 || *n > limits.chunk_bytes as u64)
            || exchange
                .response_capture
                .chunks
                .iter()
                .try_fold(0_u64, |sum, n| sum.checked_add(*n))
                .ok_or_else(invalid)?
                != exchange.response_capture.length_bytes
        {
            return Err(invalid());
        }
        captured_response_bytes = captured_response_bytes
            .checked_add(exchange.response_capture.length_bytes)
            .ok_or_else(invalid)?;
        if record.mode == Mode::HttpsConnectTunnel {
            if exchange.response_snapshot_id.is_some()
                || record.tunnel_bytes.is_none_or(|b| b.0 == 0 || b.1 == 0)
            {
                return Err(invalid());
            }
        } else {
            let id = exchange.response_snapshot_id.ok_or_else(invalid)?;
            let snapshot = evidence.snapshot(project, id, WireInt::ZERO)?;
            accounted = accounted
                .checked_add(snapshot.length_bytes.get())
                .ok_or_else(invalid)?;
            if snapshot.truncated
                || snapshot.sha256 != exchange.response_body_sha256
                || snapshot.length_bytes.get() != exchange.response_capture.length_bytes
                || snapshot.headers != exchange.response_headers
                || evidence
                    .artifact(project, snapshot.body_ref)?
                    .origin_invocation_id
                    != invocation.invocation_id
                || snapshot.derived_from.is_some()
                || snapshot.representation
                    != if record.mode == Mode::HttpsHttp2Intercept {
                        Representation::Http2SemanticBody
                    } else {
                        Representation::Http1Body
                    }
            {
                return Err(invalid());
            }
            let bytes = capture::read_complete(evidence, project, id, WireInt::ZERO, &limits)?;
            if Digest::of(&bytes) != exchange.response_body_sha256 {
                return Err(invalid());
            }
        }
    }
    if record.partial_captures.len() > 4 {
        return Err(invalid());
    }
    for partial in &record.partial_captures {
        let snapshot = evidence.snapshot(project, partial.snapshot_id, WireInt::ZERO)?;
        accounted = accounted
            .checked_add(snapshot.length_bytes.get())
            .ok_or_else(invalid)?;
        if !snapshot.truncated
            || !partial.capture.truncated
            || snapshot.sha256 != partial.capture.sha256
            || snapshot.length_bytes.get() != partial.capture.length_bytes
            || snapshot.length_bytes.get() > limits.body_bytes as u64
            || snapshot.representation
                != if record.mode == Mode::HttpsHttp2Intercept {
                    Representation::Http2SemanticBody
                } else {
                    Representation::Http1Body
                }
            || snapshot.derived_from.is_some()
            || partial
                .capture
                .chunks
                .iter()
                .any(|n| *n == 0 || *n > limits.chunk_bytes as u64)
            || partial
                .capture
                .chunks
                .iter()
                .try_fold(0_u64, |sum, n| sum.checked_add(*n))
                .ok_or_else(invalid)?
                != partial.capture.length_bytes
            || evidence
                .artifact(project, snapshot.body_ref)?
                .origin_invocation_id
                != invocation.invocation_id
            || !record
                .stream_errors
                .iter()
                .any(|e| e.error.code == partial.error.code)
        {
            return Err(invalid());
        }
        evidence.verify_artifact(project, snapshot.body_ref)?;
        captured_response_bytes = captured_response_bytes
            .checked_add(partial.capture.length_bytes)
            .ok_or_else(invalid)?;
    }
    if captured_response_bytes != record.io.captured_response_body_bytes {
        return Err(invalid());
    }
    let success = if record.stream_errors.is_empty() {
        Some(success_output(project, invocation, evidence, ledger)?)
    } else {
        None
    };
    let timing_id = if let Some((output, _)) = &success {
        output.timing_ref
    } else {
        let timing_artifacts = evidence.artifacts()?;
        let mut timings = timing_artifacts.iter().filter(|artifact| {
            artifact.project_id == project
                && artifact.origin_invocation_id == invocation.invocation_id
                && artifact.kind.as_str() == "http-send-timing"
        });
        let id = timings.next().ok_or_else(invalid)?.artifact_id;
        if timings.next().is_some() {
            return Err(invalid());
        }
        id
    };
    let timing_bytes = owned_artifact(evidence, ledger, project, timing_id, "http-send-timing")?;
    let timing: HttpSendTiming = serde_json::from_slice(&timing_bytes).map_err(|_| invalid())?;
    if evidence.artifact(project, timing_id)?.origin_invocation_id != invocation.invocation_id
        || timing.finished_us < timing.started_us
        || timing.network_elapsed_us != record.network_elapsed_us
        || timing.finished_us - timing.started_us < timing.network_elapsed_us
    {
        return Err(invalid());
    }
    accounted = accounted
        .checked_add(timing_bytes.len() as u64)
        .ok_or_else(invalid)?;
    if record.stream_errors.is_empty() {
        if invocation.state != InvocationState::Completed
            || record.exchanges.is_empty()
            || stored.reserved_units != WireInt::ZERO
            || kind.as_str() != "http-send-result"
        {
            return Err(invalid());
        }
        let (output, output_bytes) = success.ok_or_else(invalid)?;
        if output.exchange_ref != id
            || output.response_snapshot_ref
                != record
                    .exchanges
                    .last()
                    .and_then(|exchange| exchange.response_snapshot_id)
            || output.response_snapshot_ref.is_none() != (record.mode == Mode::HttpsConnectTunnel)
            || output.timing_ref != timing_id
        {
            return Err(invalid());
        }
        accounted = accounted
            .checked_add(output_bytes.len() as u64)
            .ok_or_else(invalid)?;
    } else {
        if !matches!(
            invocation.state,
            InvocationState::Failed | InvocationState::OutcomeUnknown
        ) || invocation.output_ref.is_some()
            || kind.as_str() != "http-send-failure"
        {
            return Err(invalid());
        }
        let ambiguous = record.stream_errors.iter().any(|error| {
            matches!(
                error.error.code,
                ErrorCode::ProviderUnavailable | ErrorCode::Timeout | ErrorCode::OutcomeUnknown
            )
        });
        if ambiguous
            && (invocation.state != InvocationState::OutcomeUnknown
                || stored.reserved_units.get() == 0
                || invocation.error.as_ref().map(|error| error.code)
                    != Some(ErrorCode::OutcomeUnknown))
        {
            return Err(invalid());
        }
    }
    if source.truncated
        || source.sha256 != expected_body
        || source.sha256 != input.body_snapshot_sha256
        || accounted
            .checked_add(bytes.len() as u64)
            .ok_or_else(invalid)?
            != invocation.usage.bytes.get()
        || invocation.usage.units.get() != 1
        || invocation.usage.cpu_us.get() == 0
        || invocation.usage.elapsed_us.get() == 0
        || record.network_elapsed_us > invocation.usage.elapsed_us.get()
        || invocation.usage.bytes > stored.requested.bytes
        || invocation.usage.elapsed_us > stored.requested.elapsed_us
        || invocation.usage.cpu_us > stored.requested.cpu_us
    {
        return Err(invalid());
    }
    Ok(VerifiedSend { record, input })
}

fn derive(
    report: &Report,
    root_project: EntityId,
    profile: &LoadedProfile,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<Assertions> {
    let owner = ledger.read_project(root_project)?.user_id;
    let project = ledger.read_project(report.project_id)?;
    if project.user_id != owner
        || report.schema_version != ContractVersion::V0_1_0
        || report.profile_sha256 != profile.sha256()
        || report.provider_invocation_ids.len() != report.provider_result_artifact_ids.len()
        || report.provider_invocation_ids.len() > 512
        || report.receiver_artifact_ids.len() > 32
        || report.exchanges.len() > 64
        || report.attempts.len() > 32
    {
        return Err(invalid());
    }
    if report.exchanges.len()
        != if report.case_id.as_str() == "NET-08" {
            2
        } else {
            profile.config().transport.requests_per_case.get() as usize
        }
    {
        return Err(invalid());
    }
    let fixture_bytes = owned_artifact(
        evidence,
        ledger,
        report.project_id,
        report.fixture_artifact_id,
        "transport-scenario",
    )?;
    if Digest::of(&fixture_bytes) != report.fixture_sha256 {
        return Err(invalid());
    }
    let fixture: ScenarioInput = serde_json::from_slice(&fixture_bytes).map_err(|_| invalid())?;
    validate_scenario(&fixture)?;
    let mut receivers = BTreeMap::new();
    for id in &report.receiver_artifact_ids {
        let bytes = owned_artifact(
            evidence,
            ledger,
            report.project_id,
            *id,
            "transport-receiver",
        )?;
        let receiver: ReceiverEvidence = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if receiver.final_count > 4096
            || receiver.accepted_connections > 4096
            || receiver.records.len() > 4096
            || receivers.contains_key(&receiver.endpoint_id)
        {
            return Err(invalid());
        }
        if report.case_id.as_str() == "NET-05"
            && receiver.accepted_connections != receiver.final_count
        {
            return Err(invalid());
        }
        let mut sequences = BTreeSet::new();
        for record in &receiver.records {
            WireInt::new(record.started_us)?;
            WireInt::new(record.finished_us)?;
            if record.sequence == 0
                || record.sequence > receiver.final_count
                || !sequences.insert(record.sequence)
                || record.started_us > record.finished_us
                || record.headers.len() > 256
                || record.body_bytes > profile.config().transport.body_limit_bytes.get()
                || record.method.len() > 32
                || record.target.len() > 8192
            {
                return Err(invalid());
            }
        }
        receivers.insert(receiver.endpoint_id, receiver);
    }
    let mut sends = BTreeMap::new();
    for (id, artifact) in report
        .provider_invocation_ids
        .iter()
        .zip(&report.provider_result_artifact_ids)
    {
        let send = verified_send(report.project_id, *artifact, evidence, ledger, profile)?;
        if send.record.invocation_id != *id || sends.insert(*id, send).is_some() {
            return Err(invalid());
        }
    }
    let mut referenced_streams = BTreeSet::new();
    for fact in &report.exchanges {
        let send = sends.get(&fact.invocation_id).ok_or_else(invalid)?;
        if !referenced_streams.insert((fact.invocation_id, fact.stream_id))
            || fact.project_id != report.project_id
        {
            return Err(invalid());
        }
        let exchange = send
            .record
            .exchanges
            .iter()
            .find(|e| e.connection_id == fact.connection_id && e.stream_id == fact.stream_id)
            .ok_or_else(invalid)?;
        let receiver = receivers
            .get(&fact.receiver_endpoint_id)
            .ok_or_else(invalid)?;
        if !send
            .record
            .connections
            .iter()
            .any(|connection| connection.connected_peer.port() == receiver.port)
        {
            return Err(invalid());
        }
        let upstream = upstream_stream_id(&send.record, fact.stream_id)?;
        let record = receiver
            .records
            .iter()
            .find(|r| {
                r.sequence == fact.receiver_sequence && r.stream_id == upstream && r.error.is_none()
            })
            .ok_or_else(invalid)?;
        let reconstructed = exchange_fact(
            &send.record,
            fact.result_artifact_id,
            exchange,
            record,
            fact.receiver_endpoint_id,
        );
        if encode(fact)? != encode(&reconstructed)?
            || evidence
                .artifact(report.project_id, fact.result_artifact_id)?
                .origin_invocation_id
                != fact.invocation_id
            || fact.receiver_body_sha256 != fact.request_body_sha256
            || fact.response_body_sha256 != fact.request_body_sha256
            || fact.status != 200
            || fact.receiver_method != fixture.method
            || fact.receiver_target != fixture.target
        {
            return Err(invalid());
        }
        let source = evidence.snapshot(
            report.project_id,
            fact.request_snapshot_id,
            send.record.input_revision,
        )?;
        if source.sha256 != fact.request_body_sha256
            || source.length_bytes.get() != profile.config().measurement.sample_body_bytes.get()
        {
            return Err(invalid());
        }
        if fact.mode == Mode::HttpsHttp2Intercept
            && (record.http_version != "HTTP/2.0"
                || fact.client_http_version != "HTTP/2.0"
                || fact.client_alpn.as_deref() != Some("h2")
                || fact.upstream_alpn.as_deref() != Some("h2")
                || fact.stream_id == 0)
        {
            return Err(invalid());
        }
    }
    let mut variants = BTreeSet::new();
    for (attempt_index, fact) in report.attempts.iter().enumerate() {
        let expected_error = adverse_error(&fact.variant);
        if expected_error != Some(fact.error_code) {
            eprintln!(
                "{{\"component\":\"transport-proof\",\"attempt_index\":{},\"actual_error\":\"{:?}\",\"expected_error\":\"{:?}\"}}",
                attempt_index, fact.error_code, expected_error
            );
            return Err(invalid());
        }
        if BODY_VARIANTS.contains(&fact.variant.as_str())
            && fact.forbidden_after <= fact.forbidden_before
        {
            return Err(invalid());
        }
        if fact.variant == "redirect_limit"
            && (fact.redirects_observed != profile.config().transport.redirect_limit.get() + 1
                || fact.forbidden_after - fact.forbidden_before != fact.redirects_observed)
        {
            return Err(invalid());
        }
        if !variants.insert(fact.variant.as_str()) {
            return Err(invalid());
        }
        let bytes = owned_artifact(
            evidence,
            ledger,
            report.project_id,
            fact.attempt_artifact_id,
            "transport-attempt",
        )?;
        let observed: AttemptEvidence = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        let invocation = ledger.read_invocation(fact.invocation_id)?;
        if observed.variant != fact.variant
            || observed.invocation_id != fact.invocation_id
            || observed.observer_endpoint_id != fact.observer_endpoint_id
            || observed.before != fact.forbidden_before
            || observed.after != fact.forbidden_after
            || observed.healthy_invocation_id != fact.healthy_invocation_id
            || fact.healthy_arrivals
                != observed
                    .healthy_after
                    .checked_sub(observed.healthy_before)
                    .ok_or_else(invalid)?
            || fact.healthy_arrivals == 0
            || fact.captured_bytes > profile.config().transport.body_limit_bytes.get()
            || fact.replacement_published
            || !["rejected", "truncated"].contains(&fact.representation.as_str())
            || observed.resolutions.len() > 4096
            || fact.resolution_count != observed.resolutions.len() as u64
            || fact.resolved_addresses
                != observed
                    .resolutions
                    .iter()
                    .flat_map(|r| r.addresses.iter().copied())
                    .collect::<Vec<_>>()
            || invocation.invocation.project_id != report.project_id
            || invocation.invocation.tool_id.as_str() != "http.send"
        {
            return Err(invalid());
        }
        let receiver = receivers
            .get(&fact.observer_endpoint_id)
            .ok_or_else(invalid)?;
        let expected_counter = if SCOPE_VARIANTS.contains(&fact.variant.as_str()) {
            "tcp_accept"
        } else {
            "request_observed"
        };
        if fact.counter_kind != expected_counter || observed.counter_kind != expected_counter {
            return Err(invalid());
        }
        let final_count = if expected_counter == "tcp_accept" {
            receiver.accepted_connections
        } else {
            receiver.final_count
        };
        if final_count < fact.forbidden_after || fact.forbidden_before > fact.forbidden_after {
            return Err(invalid());
        }
        if let Some(result_id) = fact.result_artifact_id {
            let send = sends.get(&fact.invocation_id).ok_or_else(invalid)?;
            let captured_bytes = send
                .record
                .partial_captures
                .iter()
                .try_fold(0_u64, |sum, partial| {
                    sum.checked_add(partial.capture.length_bytes)
                })
                .ok_or_else(invalid)?;
            if fact.captured_bytes != captured_bytes
                || fact.representation
                    != if captured_bytes > 0 {
                        "truncated"
                    } else {
                        "rejected"
                    }
            {
                return Err(invalid());
            }
            if evidence
                .artifact(report.project_id, result_id)?
                .origin_invocation_id
                != fact.invocation_id
                || send.record.redirects_observed != fact.redirects_observed
                || !send
                    .record
                    .stream_errors
                    .iter()
                    .any(|e| e.error.code == fact.error_code)
            {
                return Err(invalid());
            }
            if fact.variant == "h2_stream_reset" {
                let reset = send
                    .record
                    .stream_errors
                    .iter()
                    .find(|e| {
                        Some(e.stream_id) == fact.stream_id
                            && Some(e.connection_id) == fact.connection_id
                    })
                    .ok_or_else(invalid)?;
                let upstream = upstream_stream_id(&send.record, reset.stream_id)?;
                let failed = receiver
                    .records
                    .iter()
                    .find(|r| {
                        r.stream_id == upstream && r.sequence > observed.before && r.error.is_some()
                    })
                    .ok_or_else(invalid)?;
                if fact.stream_started_us != Some(failed.started_us)
                    || fact.reset_observed_us != Some(reset.observed_us)
                    || reset.observed_us <= failed.started_us
                    || !failed
                        .error
                        .as_ref()
                        .is_some_and(|e| e.starts_with("reset:"))
                {
                    return Err(invalid());
                }
            } else if !send.record.exchanges.is_empty() {
                return Err(invalid());
            }
        } else if invocation.invocation.state != InvocationState::Rejected
            || invocation.invocation.error.as_ref().map(|e| e.code) != Some(fact.error_code)
        {
            return Err(invalid());
        }
        let healthy = ledger.read_invocation(fact.healthy_invocation_id)?;
        if fact.variant != "h2_stream_reset" {
            if healthy.invocation.state != InvocationState::Completed
                || healthy.invocation.project_id != report.project_id
                || healthy.invocation.tool_id.as_str() != "http.send"
            {
                return Err(invalid());
            }
            let (output, _) =
                success_output(report.project_id, &healthy.invocation, evidence, ledger)?;
            let healthy = verified_send(
                report.project_id,
                output.exchange_ref,
                evidence,
                ledger,
                profile,
            )?;
            let healthy_port =
                transport::scope_connector::normalize(&healthy.input.request.url)?.port();
            let controls: Vec<_> = receivers
                .values()
                .filter(|r| r.port == healthy_port)
                .collect();
            if healthy.record.exchanges.len() != 1
                || controls.len() != 1
                || (report.case_id.as_str() != "NET-07" && healthy_port != receiver.port)
                || !controls[0].records.iter().any(|r| {
                    r.sequence > observed.healthy_before
                        && r.sequence <= observed.healthy_after
                        && r.body_sha256 == healthy.record.exchanges[0].response_body_sha256
                })
            {
                return Err(invalid());
            }
        }
    }
    if let Some(trust) = &report.trust {
        verify_trust(trust, report.project_id, evidence, ledger)?;
    }
    verify_secrecy(report, evidence, ledger)?;
    verify_raw_measurement(report, evidence, ledger)?;
    if let Some(measurement) = &report.measurement {
        verify_measurements(measurement, report, &sends, &receivers, profile)?;
    }
    let expected_count = profile.config().transport.requests_per_case.get() as usize;
    let positive_count = report.exchanges.len() == expected_count;
    let forwarded = positive_count && report.exchanges.iter().all(|e| e.status == 200);
    let exact = report.exchanges.iter().all(|e| {
        e.receiver_body_sha256 == e.request_body_sha256
            && e.request_body_sha256 == e.response_body_sha256
    });
    let headers = report.exchanges.iter().all(|e| {
        e.receiver_headers.get("x-razen-duplicate")
            == Some(&vec!["first".to_owned(), "second".to_owned()])
    });
    let tls = report.exchanges.iter().all(|e| {
        e.upstream_peer_certificate_sha256.is_some()
            && e.upstream_alpn.as_deref() == Some("http/1.1")
            && e.client_alpn.as_deref() == Some("http/1.1")
    });
    let authorities = report.exchanges.iter().all(|e| {
        e.connect_host.as_deref() == e.tls_server_name.as_deref()
            && e.connect_authority.as_deref() == Some(e.request_authority.as_str())
    });
    let trust = report
        .trust
        .as_ref()
        .is_some_and(|t| t.before_sha256 == t.after_sha256);
    let zero = report
        .attempts
        .iter()
        .all(|a| a.forbidden_before == a.forbidden_after);
    let healthy =
        !report.attempts.is_empty() && report.attempts.iter().all(|a| a.healthy_arrivals > 0);
    let complete_variants = |required: &[&str]| {
        report.attempts.len() == required.len()
            && required.iter().all(|variant| variants.contains(variant))
    };
    use CheckName::*;
    let checks: Vec<_> = match report.case_id.as_str() {
        "NET-01" => vec![
            (Forwarded, forwarded && report.measurement.is_some()),
            (HeadersPreserved, headers),
            (BodyExact, exact),
            (
                CaptureReferenced,
                report
                    .exchanges
                    .iter()
                    .all(|e| e.response_snapshot_id.is_some()),
            ),
        ],
        "NET-02" => vec![
            (Forwarded, forwarded),
            (BodyExact, exact),
            (
                OpaqueTunnel,
                report.exchanges.iter().all(|e| {
                    e.inspection == "opaque"
                        && e.response_snapshot_id.is_none()
                        && e.tunnel_client_bytes.is_some_and(|n| n > 0)
                        && e.tunnel_upstream_bytes.is_some_and(|n| n > 0)
                }),
            ),
        ],
        "NET-03" => vec![
            (Forwarded, forwarded),
            (UpstreamVerified, tls),
            (IsolatedTrust, tls && trust),
            (TrustUnchanged, trust),
        ],
        "NET-04" => vec![
            (Forwarded, forwarded),
            (
                H2BothLegs,
                report.exchanges.iter().all(|e| {
                    e.client_alpn.as_deref() == Some("h2")
                        && e.upstream_alpn.as_deref() == Some("h2")
                }),
            ),
            (ConcurrentStreams, overlap(&report.exchanges)),
            (BodyExact, exact && headers),
        ],
        "NET-05" => vec![
            (
                ScopeRechecked,
                complete_variants(SCOPE_VARIANTS)
                    && report.attempts.iter().all(|a| {
                        matches!(
                            a.error_code,
                            ErrorCode::OutOfScope
                                | ErrorCode::InvalidInput
                                | ErrorCode::PermissionDenied
                        )
                    }),
            ),
            (
                PivotsDenied,
                complete_variants(SCOPE_VARIANTS)
                    && report
                        .attempts
                        .iter()
                        .any(|a| a.variant == "redirect_pivot" && a.redirects_observed > 0)
                    && report
                        .attempts
                        .iter()
                        .any(|a| a.variant == "dns_change" && a.resolution_count >= 2)
                    && report.attempts.iter().any(|a| {
                        a.variant == "dns_mixed_answers" && a.resolved_addresses.len() >= 2
                    }),
            ),
            (HealthyObserver, healthy),
            (ZeroForbiddenArrivals, zero),
        ],
        "NET-06" => vec![
            (
                InvalidTlsRejected,
                complete_variants(TLS_VARIANTS)
                    && report.attempts.iter().any(|a| {
                        a.variant == "invalid_upstream_certificate"
                            && a.error_code == ErrorCode::PermissionDenied
                    }),
            ),
            (
                AuthoritiesMatch,
                authorities && complete_variants(TLS_VARIANTS) && zero && healthy,
            ),
            (TrustUnchanged, trust),
            (SecretsAbsent, report.secrecy_artifact_id.is_some() && trust),
        ],
        "NET-07" => vec![
            (
                BodyBounded,
                complete_variants(BODY_VARIANTS)
                    && report.attempts.iter().all(|a| {
                        a.captured_bytes <= profile.config().transport.body_limit_bytes.get()
                    }),
            ),
            (
                RepresentationExplicit,
                complete_variants(BODY_VARIANTS)
                    && report
                        .attempts
                        .iter()
                        .all(|a| ["rejected", "truncated"].contains(&a.representation.as_str())),
            ),
            (InvalidRejected, healthy && complete_variants(BODY_VARIANTS)),
            (
                NoPartialReplacement,
                report.attempts.iter().all(|a| !a.replacement_published)
                    && exact
                    && !report.exchanges.is_empty(),
            ),
        ],
        "NET-08" => {
            let reset = report
                .attempts
                .iter()
                .find(|a| a.variant == "h2_stream_reset");
            let attributable = reset.is_some_and(|a| {
                a.stream_id.is_some_and(|id| id > 0) && a.reset_observed_us > a.stream_started_us
            });
            let survives = reset.is_some_and(|a| {
                report.exchanges.iter().any(|e| {
                    Some(e.connection_id) == a.connection_id
                        && Some(e.stream_id) != a.stream_id
                        && Some(e.receiver_started_us) < a.reset_observed_us
                        && Some(e.receiver_finished_us) > a.stream_started_us
                }) && report.exchanges.iter().any(|e| {
                    Some(e.connection_id) == a.connection_id
                        && Some(e.receiver_started_us) > a.reset_observed_us
                })
            });
            vec![
                (StreamReset, attributable),
                (ValidStreamSurvives, survives && exact),
                (
                    ErrorsAttributed,
                    attributable && report.exchanges.len() >= 2,
                ),
            ]
        }
        _ => return Err(invalid()),
    };
    Assertions::new(checks)
}
fn overlap(exchanges: &[ExchangeFact]) -> bool {
    exchanges.iter().enumerate().any(|(i, left)| {
        exchanges[i + 1..].iter().any(|right| {
            left.connection_id == right.connection_id
                && left.stream_id != right.stream_id
                && left.receiver_started_us < right.receiver_finished_us
                && right.receiver_started_us < left.receiver_finished_us
        })
    })
}
fn verify_trust(
    trust: &TrustFact,
    project: EntityId,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<()> {
    for (id, digest) in [
        (trust.before_artifact_id, trust.before_sha256),
        (trust.after_artifact_id, trust.after_sha256),
    ] {
        let bytes = owned_artifact(evidence, ledger, project, id, "transport-trust")?;
        if Digest::of(&bytes) != digest {
            return Err(invalid());
        }
        let snapshot: TrustSnapshot = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if snapshot.domains.len() != 3
            || snapshot
                .domains
                .iter()
                .map(|d| d.domain.as_str())
                .collect::<Vec<_>>()
                != ["user", "admin", "system"]
        {
            return Err(invalid());
        }
        for domain in snapshot.domains {
            if domain.stdout.len() > 1_048_576
                || domain.stderr.len() > 65_536
                || (domain.exit_code != 0
                    && !(domain.exit_code == 1
                        && format!("{}{}", domain.stdout, domain.stderr)
                            .contains("No Trust Settings were found")))
            {
                return Err(invalid());
            }
        }
    }
    for (id, kind) in [
        (trust.public_root_artifact_id, "transport-client-root"),
        (trust.upstream_root_artifact_id, "transport-upstream-root"),
    ] {
        let bytes = owned_artifact(evidence, ledger, project, id, kind)?;
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(bytes))
            .map_err(|_| invalid())?;
        if roots.len() != 1 {
            return Err(invalid());
        }
    }
    Ok(())
}
fn verify_measurements(
    measured: &Measurements,
    report: &Report,
    sends: &BTreeMap<EntityId, VerifiedSend>,
    receivers: &BTreeMap<EntityId, ReceiverEvidence>,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    let config = &profile.config().measurement;
    if measured.profile_sha256 != profile.sha256()
        || measured.fixture_sha256 != report.fixture_sha256
        || measured.context_source != "run.environment"
        || measured.warmup_exchanges != config.latency_warmup_exchanges.get()
        || measured.sample_body_bytes != config.sample_body_bytes.get()
        || measured.direct_warmup.len() != config.latency_warmup_exchanges.get() as usize
        || measured.proxy_warmup.len() != measured.direct_warmup.len()
        || measured.direct_samples.len() != config.latency_sample_exchanges.get() as usize
        || measured.proxy_samples.len() != measured.direct_samples.len()
        || measured.direct_us
            != measured
                .direct_samples
                .iter()
                .map(|s| s.elapsed_us)
                .collect::<Vec<_>>()
        || measured.proxy_us
            != measured
                .proxy_samples
                .iter()
                .map(|s| s.elapsed_us)
                .collect::<Vec<_>>()
        || measured.rss_kib_before == 0
        || measured.rss_kib_after == 0
        || measured.max_sampled_rss_kib != measured.rss_kib_before.max(measured.rss_kib_after)
        || measured.direct_p50_us != measurements::percentile(&measured.direct_us, 50)?
        || measured.direct_p95_us != measurements::percentile(&measured.direct_us, 95)?
        || measured.proxy_p50_us != measurements::percentile(&measured.proxy_us, 50)?
        || measured.proxy_p95_us != measurements::percentile(&measured.proxy_us, 95)?
    {
        return Err(invalid());
    }
    let mut invocations = BTreeSet::new();
    let mut receiver_sequences = BTreeSet::new();
    for (route, samples) in [
        (Route::Direct, &measured.direct_warmup),
        (Route::Proxy, &measured.proxy_warmup),
        (Route::Direct, &measured.direct_samples),
        (Route::Proxy, &measured.proxy_samples),
    ] {
        for sample in samples {
            let send = sends.get(&sample.invocation_id).ok_or_else(invalid)?;
            let matching: Vec<_> = receivers
                .values()
                .filter(|receiver| {
                    receiver.records.iter().any(|r| {
                        r.sequence == sample.receiver_sequence
                            && r.body_sha256 == sample.body_sha256
                            && r.body_bytes == sample.body_bytes
                    })
                })
                .collect();
            if sample.elapsed_us == 0
                || !invocations.insert(sample.invocation_id)
                || matching.len() != 1
                || !receiver_sequences.insert((matching[0].endpoint_id, sample.receiver_sequence))
                || sample.receiver_before.checked_add(1) != Some(sample.receiver_after)
                || sample.receiver_after != sample.receiver_sequence
                || sample.body_bytes != config.sample_body_bytes.get()
                || send.record.direct != (route == Route::Direct)
                || send.record.network_elapsed_us != sample.elapsed_us
                || send.record.exchanges.len() != 1
                || send.record.exchanges[0].response_body_sha256 != sample.body_sha256
                || sample.result_artifact_id
                    != report.provider_result_artifact_ids[report
                        .provider_invocation_ids
                        .iter()
                        .position(|id| *id == sample.invocation_id)
                        .ok_or_else(invalid)?]
            {
                return Err(invalid());
            }
        }
    }
    let expected_count =
        config.latency_warmup_exchanges.get() + config.latency_sample_exchanges.get();
    if measured.direct_receiver_count != expected_count
        || measured.proxy_receiver_count != expected_count
    {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScannedArtifact {
    artifact_id: EntityId,
    sha256: Digest,
    length_bytes: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SecrecyEvidence {
    project_id: EntityId,
    identity_id: EntityId,
    protected_identity_values: u64,
    protected_key_values: u64,
    report_sha256: Digest,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 4096>")]
    scanned: Vec<ScannedArtifact>,
}
fn fixture_secret(root: &Path) -> ProofResult<Vec<u8>> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(root.join("fixtures/scenarios/approved-fixtures.json"))
        .map_err(|_| invalid())?
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    if bytes.len() > 65_536 {
        return Err(invalid());
    }
    let fixture: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let value = fixture["synthetic_canaries"]["credential"]
        .as_str()
        .ok_or_else(invalid)?;
    if !value.starts_with("RAZEN_FIXTURE_") || value.len() > 512 {
        return Err(invalid());
    }
    Ok(value.as_bytes().to_vec())
}
fn ensure_identity_public(secret: &[u8], bytes: &[u8]) -> ProofResult<()> {
    prohibited(bytes)?;
    if secret.is_empty() || bytes.windows(secret.len()).any(|window| window == secret) {
        return Err(invalid());
    }
    Ok(())
}
fn verify_secrecy(report: &Report, evidence: &EvidenceStore, ledger: &Ledger) -> ProofResult<()> {
    let id = report.secrecy_artifact_id.ok_or_else(invalid)?;
    let bytes = owned_artifact(evidence, ledger, report.project_id, id, "transport-secrecy")?;
    let scan: SecrecyEvidence = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let identity = ledger.read_identity(scan.identity_id)?;
    let mut original_report = report.clone();
    original_report.secrecy_artifact_id = None;
    if scan.project_id != report.project_id
        || identity.project_id != report.project_id
        || !identity
            .secret_ref_names
            .iter()
            .any(|name| name.as_str() == "fixture-credential")
        || scan.protected_identity_values != 1
        || scan.protected_key_values < 3
        || scan.protected_key_values > 1536
        || scan.report_sha256 != Digest::of(&encode(&original_report)?)
        || scan.scanned.is_empty()
    {
        return Err(invalid());
    }
    let mut ids = BTreeSet::new();
    for item in scan.scanned {
        let artifact = evidence.artifact(report.project_id, item.artifact_id)?;
        if !ids.insert(item.artifact_id)
            || artifact.sha256 != item.sha256
            || artifact.length_bytes.get() != item.length_bytes
        {
            return Err(invalid());
        }
        evidence.verify_artifact(report.project_id, item.artifact_id)?;
    }
    if !ids.contains(&report.fixture_artifact_id)
        || report
            .provider_result_artifact_ids
            .iter()
            .chain(&report.receiver_artifact_ids)
            .any(|id| !ids.contains(id))
    {
        return Err(invalid());
    }
    let artifacts = evidence.artifacts()?;
    for invocation_id in report.provider_invocation_ids.iter().copied().chain(
        report
            .attempts
            .iter()
            .flat_map(|attempt| [attempt.invocation_id, attempt.healthy_invocation_id]),
    ) {
        let invocation = ledger.read_invocation(invocation_id)?.invocation;
        if !ids.contains(&invocation.input_ref) {
            return Err(invalid());
        }
        let input = if invocation.state == InvocationState::Rejected {
            let bytes = owned_artifact(
                evidence,
                ledger,
                report.project_id,
                invocation.input_ref,
                "http-rejected-input",
            )?;
            serde_json::from_slice::<HttpSendInput>(&bytes).map_err(|_| invalid())?
        } else {
            let bytes = owned_artifact(
                evidence,
                ledger,
                report.project_id,
                invocation.input_ref,
                "http-send-input",
            )?;
            serde_json::from_slice::<PreparedRecord>(&bytes)
                .map_err(|_| invalid())?
                .input
        };
        let descriptor = evidence.snapshot(
            report.project_id,
            input.request_snapshot_id,
            input.base_revision,
        )?;
        if !ids.contains(&descriptor.body_ref) {
            return Err(invalid());
        }
        if invocation.state == InvocationState::Completed {
            let (output, _) = success_output(report.project_id, &invocation, evidence, ledger)?;
            if !ids.contains(&invocation.output_ref.ok_or_else(invalid)?)
                || !ids.contains(&output.exchange_ref)
                || !ids.contains(&output.timing_ref)
            {
                return Err(invalid());
            }
        }
        for artifact in artifacts.iter().filter(|artifact| {
            artifact.project_id == report.project_id
                && artifact.origin_invocation_id == invocation_id
        }) {
            if !ids.contains(&artifact.artifact_id) {
                return Err(invalid());
            }
        }
    }
    for fact in &report.exchanges {
        let request =
            evidence.snapshot(report.project_id, fact.request_snapshot_id, WireInt::ZERO)?;
        if !ids.contains(&request.body_ref) {
            return Err(invalid());
        }
        if let Some(id) = fact.response_snapshot_id
            && !ids.contains(
                &evidence
                    .snapshot(report.project_id, id, WireInt::ZERO)?
                    .body_ref,
            )
        {
            return Err(invalid());
        }
    }
    Ok(())
}

fn validate_wire_value(value: &Value, depth: usize) -> ProofResult<()> {
    if depth > 32 {
        return Err(invalid());
    }
    match value {
        Value::Null => Err(invalid()),
        Value::Number(number) => {
            WireInt::new(number.as_u64().ok_or_else(invalid)?)?;
            Ok(())
        }
        Value::Array(values) => {
            if values.len() > 4096 {
                return Err(invalid());
            }
            for value in values {
                validate_wire_value(value, depth + 1)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            if values.len() > 256 {
                return Err(invalid());
            }
            for value in values.values() {
                validate_wire_value(value, depth + 1)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn verify_raw_measurement(
    report: &Report,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<()> {
    match (&report.measurement, report.measurement_artifact_id) {
        (Some(measurement), Some(id)) => {
            let bytes = owned_artifact(
                evidence,
                ledger,
                report.project_id,
                id,
                "transport-measurements",
            )?;
            if bytes != encode(measurement)? {
                return Err(invalid());
            }
            Ok(())
        }
        (None, None) => Ok(()),
        _ => Err(invalid()),
    }
}

fn adverse_error(variant: &str) -> Option<ErrorCode> {
    Some(match variant {
        "userinfo" | "ambiguous_authority" | "ipv6_zone" => ErrorCode::InvalidInput,
        "excluded"
        | "redirect_pivot"
        | "dns_change"
        | "dns_mixed_answers"
        | "ipv4_mapped_ipv6"
        | "ungranted_loopback_port"
        | "ungranted_private_port"
        | "decrypted_authority_mismatch" => ErrorCode::OutOfScope,
        "invalid_upstream_certificate" | "connect_sni_mismatch" | "client_root_removed" => {
            ErrorCode::PermissionDenied
        }
        "oversized_body" | "redirect_limit" => ErrorCode::BudgetExhausted,
        "truncated_content_length" | "truncated_chunked" => ErrorCode::ProviderUnavailable,
        "conflicting_framing"
        | "unsupported_encoding"
        | "unsupported_protocol"
        | "h2_stream_reset" => ErrorCode::UnsupportedProtocol,
        _ => return None,
    })
}

#[cfg(test)]
mod historical_grant_tests {
    use super::*;
    use crate::transport_test_fixtures::{Fixture, Reply, WireReceiver, configuration, runtime};

    fn larger(requested: Usage) -> Usage {
        Usage {
            units: WireInt::new(requested.units.get() + 1).unwrap(),
            bytes: WireInt::new(requested.bytes.get() + 1).unwrap(),
            cpu_us: WireInt::new(requested.cpu_us.get() + 1).unwrap(),
            elapsed_us: WireInt::new(requested.elapsed_us.get() + 1).unwrap(),
        }
    }

    #[test]
    fn real_send_and_historical_verification_accept_larger_grant_ceilings() {
        let runtime = runtime();
        let receiver = WireReceiver::start(&runtime, None, Reply::Echo);
        let fixture = Fixture::scoped(&[receiver.rule(false)]);
        let binding = fixture.http_binding();
        let registry = fixture
            .host
            .http_registry(
                &fixture.profile,
                configuration(
                    Mode::Http1Forward,
                    Arc::new(rama::tls::rustls::dep::rustls::RootCertStore::empty()),
                    receiver.address.port(),
                ),
            )
            .unwrap();
        let publisher_limits = fixture
            .host
            .ledger
            .read_tool(&CatalogId::parse(PREPARE).unwrap())
            .unwrap()
            .descriptor
            .limits;
        let body = b"real fixture request authorized below both grant ceilings";
        let input = fixture.request_with_grant_limits(
            &binding,
            &receiver.url(false),
            body,
            Vec::new(),
            Some(larger(publisher_limits)),
        );
        let raw = RawValue::from_string(serde_json::to_string(&input).unwrap()).unwrap();
        let prepare = || {
            registry
                .prepare(
                    &binding,
                    &ToolRequest {
                        call_id: EntityId::new(),
                        tool_id: CatalogId::parse("http.send").unwrap(),
                        tool_version: ContractVersion::V0_1_0,
                        input: &raw,
                        source_control_revision: binding.control_revision(),
                    },
                )
                .unwrap()
        };
        let denied = prepare();
        let mut insufficient = denied.call().requested;
        insufficient.bytes = WireInt::new(insufficient.bytes.get() - 1).unwrap();
        fixture.approve_with_limits(&binding, denied.call(), insufficient);
        let rejected = registry.execute_prepared(&binding, denied).unwrap();
        assert_eq!(rejected.error.unwrap().code, ErrorCode::BudgetExhausted);
        assert!(receiver.bodies().is_empty());

        let prepared = prepare();
        let ordinary = fixture.host.approve(&binding, prepared.call()).unwrap();
        let broader = fixture.approve_with_limits(
            &binding,
            prepared.call(),
            larger(prepared.call().requested),
        );
        let result = registry.execute_prepared(&binding, prepared).unwrap();
        assert_eq!(result.state, InvocationState::Completed);
        assert_eq!(receiver.bodies(), vec![body.to_vec()]);
        let stored = fixture
            .host
            .ledger
            .read_invocation(result.invocation_id)
            .unwrap();
        assert_eq!(stored.invocation.grant_id, Some(broader));
        assert_ne!(stored.invocation.grant_id, Some(ordinary));
        let output = fixture
            .host
            .evidence
            .read_artifact(binding.project_id(), result.output_ref.unwrap(), 65_536)
            .unwrap();
        let output: HttpSendOutput = serde_json::from_slice(&output).unwrap();
        let verified = verified_send(
            binding.project_id(),
            output.exchange_ref,
            &fixture.host.evidence,
            &fixture.host.ledger,
            &fixture.profile,
        )
        .unwrap();
        assert_eq!(verified.record.invocation_id, result.invocation_id);
        assert_eq!(verified.input.input.identity_id, binding.identity_id());
    }
}
