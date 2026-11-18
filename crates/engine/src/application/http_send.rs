//! Active network provider using canonical host admission, never guest approvals.
use super::admission::{HostAdmission, PreparedCall, TrustedBinding};
use super::effect_meter::EffectMeter;
use super::profile::LoadedProfile;
use crate::adapters::evidence_store::EvidenceStore;
use crate::adapters::ledger::RegisteredTool;
use crate::adapters::transport::scope_connector::{self, Authority};
use crate::adapters::transport::{self, Limits, Mode, TransportConfig, capture};
use crate::domain::authority::{Effect, RetryClass, ToolDescriptor};
use crate::domain::evidence::{Header, RedactionStatus, Representation};
use crate::domain::invocation::Invocation;
use crate::domain::values::{
    CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage, WireInt,
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use tokio::runtime::Runtime;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSendInput {
    pub request_snapshot_id: EntityId,
    pub base_revision: WireInt,
    pub identity_id: EntityId,
}

/// Host-published immutable request descriptor; the body remains a separate snapshot.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSnapshot {
    pub body_snapshot_id: EntityId,
    pub body_revision: WireInt,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_text::<_, 8192>")]
    pub url: String,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_text::<_, 32>")]
    pub method: String,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 256>")]
    pub headers: Vec<Header>,
    pub request_count: WireInt,
    pub reset_first_stream: bool,
}

const REQUEST_CONTENT_TYPE: &str = "application/vnd.razen.http-request+json";
const REQUEST_DESCRIPTOR_LIMIT: usize = 524_288;

fn descriptor_bytes_for(request: &RequestSnapshot) -> ProofResult<Vec<u8>> {
    if request.url.len() > 8192
        || request.method.len() > 32
        || request.headers.len() > 256
        || request.request_count.get() == 0
        || request.request_count.get() > 3
    {
        return Err(transport::invalid());
    }
    let total = request.headers.iter().try_fold(0_usize, |sum, header| {
        header.validate()?;
        sum.checked_add(header.name.len())
            .and_then(|n| n.checked_add(header.value.len()))
            .ok_or_else(transport::bounded)
    })?;
    if total > 65_536 {
        return Err(transport::bounded());
    }
    let bytes = serde_json::to_vec(request).map_err(|_| transport::invalid())?;
    if bytes.len() > REQUEST_DESCRIPTOR_LIMIT {
        return Err(transport::bounded());
    }
    Ok(bytes)
}

/// Publishes owned data only: no grant, scope approval, or network operation.
pub fn install_request(
    evidence: &EvidenceStore,
    binding: &TrustedBinding,
    owner_invocation_id: EntityId,
    request: RequestSnapshot,
) -> ProofResult<HttpSendInput> {
    if request.headers.iter().any(|header| {
        ["authorization", "cookie"]
            .iter()
            .any(|name| header.name.eq_ignore_ascii_case(name))
    }) {
        return Err(ProofError::new(
            ErrorCode::PermissionDenied,
            "Private request headers must be configured on the host provider",
        ));
    }
    let bytes = descriptor_bytes_for(&request)?;
    let body = evidence.snapshot(
        binding.project_id(),
        request.body_snapshot_id,
        request.body_revision,
    )?;
    if body.truncated || body.length_bytes.get() > crate::domain::evidence::MAX_BODY_BYTES as u64 {
        return Err(transport::invalid());
    }
    evidence.verify_artifact(binding.project_id(), body.body_ref)?;
    let request_snapshot_id = capture::snapshot(
        evidence,
        binding.project_id(),
        owner_invocation_id,
        capture::SnapshotBody {
            bytes: &bytes,
            headers: vec![Header {
                name: "content-type".into(),
                value: REQUEST_CONTENT_TYPE.into(),
            }],
            representation: Representation::RawBody,
            truncated: false,
            derived_from: Some(request.body_snapshot_id),
        },
    )?;
    Ok(HttpSendInput {
        request_snapshot_id,
        base_revision: WireInt::ZERO,
        identity_id: binding.identity_id(),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSendOutput {
    pub exchange_ref: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_snapshot_ref: Option<EntityId>,
    pub timing_ref: EntityId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSendTiming {
    pub started_us: u64,
    pub finished_us: u64,
    pub network_elapsed_us: u64,
}

pub struct PreparedHttpSend {
    binding: Arc<TrustedBinding>,
    call: PreparedCall,
    configuration_id: EntityId,
    operation: Option<HttpOperation>,
}
struct HttpOperation {
    input: HttpSendInput,
    request: RequestSnapshot,
    body: Vec<u8>,
}
impl PreparedHttpSend {
    pub fn call(&self) -> &PreparedCall {
        &self.call
    }
    pub(crate) fn binding(&self) -> &Arc<TrustedBinding> {
        &self.binding
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeOutput {
    pub connection_id: EntityId,
    pub stream_id: u32,
    pub started_us: u64,
    pub finished_us: u64,
    pub status: u16,
    pub response_headers: Vec<Header>,
    pub response_capture: capture::CaptureFact,
    pub response_body_sha256: Digest,
    pub request_body_sha256: Digest,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_snapshot_id: Option<EntityId>,
    pub client_http_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_alpn: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_peer_certificate_sha256: Option<Digest>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StreamError {
    pub connection_id: EntityId,
    pub stream_id: u32,
    pub started_us: u64,
    pub observed_us: u64,
    pub error: ProofError,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PartialCapture {
    pub snapshot_id: EntityId,
    pub capture: capture::CaptureFact,
    pub error: ProofError,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SendRecord {
    pub schema_version: ContractVersion,
    pub project_id: EntityId,
    pub invocation_id: EntityId,
    pub provider_configuration_id: EntityId,
    pub io: scope_connector::IoUsage,
    pub input_snapshot_id: EntityId,
    pub input_revision: WireInt,
    pub mode: Mode,
    pub direct: bool,
    pub network_elapsed_us: u64,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 3>")]
    pub exchanges: Vec<ExchangeOutput>,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 4>")]
    pub stream_errors: Vec<StreamError>,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 3>")]
    pub stream_links: Vec<transport::StreamLink>,
    pub redirects_observed: u64,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 4>")]
    pub partial_captures: Vec<PartialCapture>,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 32>")]
    pub connections: Vec<scope_connector::ConnectionFact>,
    #[serde(deserialize_with = "crate::domain::evidence::bounded_vec::<_, _, 4>")]
    pub redirect_chain: Vec<scope_connector::RedirectFact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tunnel_bytes: Option<(u64, u64)>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub connect_authority: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
}
pub struct HttpSendResult {
    pub invocation: Invocation,
    pub record: SendRecord,
    pub record_artifact_id: EntityId,
}

struct SendOutcome {
    invocation: Invocation,
    detail: Option<(SendRecord, EntityId)>,
}
impl SendOutcome {
    fn historical(invocation: Invocation) -> Self {
        Self {
            invocation,
            detail: None,
        }
    }
}

pub struct HttpSendProvider {
    admission: Arc<HostAdmission>,
    evidence: Arc<EvidenceStore>,
    limits: Limits,
    requested: Usage,
    config: TransportConfig,
    runtime: Runtime,
    configuration_id: EntityId,
    secret_headers: Option<(EntityId, Vec<Header>)>,
    preparation: Mutex<()>,
}

pub fn registered_tool(
    provider_digest: Digest,
    profile: &LoadedProfile,
) -> ProofResult<RegisteredTool> {
    let limits = requested(profile)?;
    Ok(RegisteredTool {
        provider_digest,
        descriptor: ToolDescriptor {
            tool_id: CatalogId::parse("http.send")?,
            version: ContractVersion::V0_1_0,
            input_contract: CatalogId::parse("http.send.input")?,
            output_contract: CatalogId::parse("http.send.output")?,
            effect: Effect::ActiveNetwork,
            permissions: vec![CatalogId::parse("http.send")?],
            limits,
            retry_class: RetryClass::NonRetryable,
        },
    })
}
fn requested(profile: &LoadedProfile) -> ProofResult<Usage> {
    // A batch is bounded to two real concurrent streams; all network/body/public
    // output bytes are charged, not the size of a tiny success marker.
    let hops = profile
        .config()
        .transport
        .redirect_limit
        .get()
        .checked_add(1)
        .ok_or_else(transport::bounded)?
        .max(3);
    let bodies = hops
        .checked_mul(3)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(transport::bounded)?;
    let bytes = profile
        .config()
        .transport
        .body_limit_bytes
        .get()
        .checked_mul(bodies)
        .and_then(|n| {
            n.checked_add(
                profile
                    .config()
                    .protocol
                    .invocation_output_limit_bytes
                    .get(),
            )
        })
        .ok_or_else(transport::bounded)?;
    let elapsed = profile
        .config()
        .transport
        .request_timeout_ms
        .get()
        .checked_mul(1000)
        .and_then(|v| v.checked_add(500_000))
        .ok_or_else(transport::bounded)?;
    Ok(Usage {
        units: WireInt::new(1)?,
        bytes: WireInt::new(bytes)?,
        cpu_us: WireInt::new(elapsed.checked_mul(4).ok_or_else(transport::bounded)?)?,
        elapsed_us: WireInt::new(elapsed)?,
    })
}
impl HttpSendProvider {
    pub fn new(
        admission: Arc<HostAdmission>,
        evidence: Arc<EvidenceStore>,
        profile: &LoadedProfile,
        config: TransportConfig,
    ) -> ProofResult<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|_| transport::network())?;
        Ok(Self {
            admission,
            evidence,
            limits: Limits::from_profile(profile)?,
            requested: requested(profile)?,
            config,
            runtime,
            configuration_id: EntityId::new(),
            secret_headers: None,
            preparation: Mutex::new(()),
        })
    }
    /// Host-only credentials are never part of prepared/public input or history.
    pub fn with_secret_headers(
        mut self,
        identity_id: EntityId,
        headers: Vec<Header>,
    ) -> ProofResult<Self> {
        if headers.is_empty() || headers.len() > 256 {
            return Err(transport::invalid());
        }
        let mut total = 0_usize;
        for (index, header) in headers.iter().enumerate() {
            header.validate()?;
            if header.value.is_empty()
                || !["authorization", "cookie"]
                    .iter()
                    .any(|name| header.name.eq_ignore_ascii_case(name))
                || headers[..index]
                    .iter()
                    .any(|other| other.name.eq_ignore_ascii_case(&header.name))
            {
                return Err(transport::invalid());
            }
            total = total
                .checked_add(header.name.len())
                .and_then(|n| n.checked_add(header.value.len()))
                .ok_or_else(transport::bounded)?;
        }
        if total > 65_536 {
            return Err(transport::bounded());
        }
        self.secret_headers = Some((identity_id, headers));
        self.configuration_id = EntityId::new();
        Ok(self)
    }

    fn public_bytes(&self, bytes: &[u8]) -> ProofResult<()> {
        if let Some((_, headers)) = &self.secret_headers {
            for header in headers {
                let contains = |secret: &[u8]| {
                    !secret.is_empty() && bytes.windows(secret.len()).any(|part| part == secret)
                };
                let credential_present = if header.name.eq_ignore_ascii_case("authorization") {
                    header
                        .value
                        .split_once(' ')
                        .is_some_and(|(_, token)| contains(token.trim().as_bytes()))
                } else {
                    header
                        .value
                        .split(';')
                        .filter_map(|cookie| cookie.split_once('='))
                        .any(|(_, value)| contains(value.trim().as_bytes()))
                };
                if contains(header.value.as_bytes()) || credential_present {
                    return Err(ProofError::new(
                        ErrorCode::PermissionDenied,
                        "HTTP evidence contains private configured credential material",
                    ));
                }
            }
        }
        Ok(())
    }

    fn public_headers(&self, headers: &[Header]) -> ProofResult<()> {
        for header in headers {
            self.public_bytes(header.name.as_bytes())?;
            self.public_bytes(header.value.as_bytes())?;
        }
        Ok(())
    }
    pub(crate) fn matches_host(
        &self,
        admission: &Arc<HostAdmission>,
        evidence: &Arc<EvidenceStore>,
    ) -> bool {
        Arc::ptr_eq(&self.admission, admission) && Arc::ptr_eq(&self.evidence, evidence)
    }
    pub(crate) fn configuration_id(&self) -> EntityId {
        self.configuration_id
    }
    pub fn prepare(
        &self,
        binding: Arc<TrustedBinding>,
        input: &HttpSendInput,
    ) -> ProofResult<PreparedHttpSend> {
        self.prepare_call(binding, EntityId::new(), input)
    }
    pub fn prepare_call(
        &self,
        binding: Arc<TrustedBinding>,
        call_id: EntityId,
        input: &HttpSendInput,
    ) -> ProofResult<PreparedHttpSend> {
        let revision = binding.control_revision();
        self.prepare_request(binding, call_id, ContractVersion::V0_1_0, revision, input)
    }
    pub(crate) fn prepare_request(
        &self,
        binding: Arc<TrustedBinding>,
        call_id: EntityId,
        tool_version: ContractVersion,
        source_control_revision: WireInt,
        input: &HttpSendInput,
    ) -> ProofResult<PreparedHttpSend> {
        let _guard = self.preparation.lock().map_err(|_| {
            self.admission.invalidate_integrity();
            ProofError::new(
                ErrorCode::IntegrityError,
                "HTTP preparation state failed integrity checks",
            )
        })?;
        if tool_version != ContractVersion::V0_1_0 {
            return Err(ProofError::new(
                ErrorCode::UnsupportedVersion,
                "HTTP tool version is not supported",
            ));
        }
        if input.identity_id != binding.identity_id()
            || self
                .secret_headers
                .as_ref()
                .is_some_and(|(identity, _)| *identity != binding.identity_id())
        {
            return Err(transport::tls_error());
        }
        let descriptor = self.evidence.snapshot(
            binding.project_id(),
            input.request_snapshot_id,
            input.base_revision,
        )?;
        if descriptor.representation != Representation::RawBody
            || descriptor.truncated
            || descriptor.length_bytes.get() > REQUEST_DESCRIPTOR_LIMIT as u64
            || descriptor.headers
                != [Header {
                    name: "content-type".into(),
                    value: REQUEST_CONTENT_TYPE.into(),
                }]
        {
            return Err(transport::invalid());
        }
        let descriptor_bytes = capture::read_complete(
            &self.evidence,
            binding.project_id(),
            input.request_snapshot_id,
            input.base_revision,
            &self.limits,
        )?;
        self.public_bytes(&descriptor_bytes)?;
        let request: RequestSnapshot =
            serde_json::from_slice(&descriptor_bytes).map_err(|_| transport::invalid())?;
        self.public_headers(&request.headers)?;
        if descriptor.derived_from != Some(request.body_snapshot_id)
            || descriptor_bytes != descriptor_bytes_for(&request)?
        {
            return Err(transport::invalid());
        }
        let snapshot = self.evidence.snapshot(
            binding.project_id(),
            request.body_snapshot_id,
            request.body_revision,
        )?;
        let bytes = serde_json::to_vec(&PreparedInput {
            input,
            request: &request,
            request_snapshot_sha256: descriptor.sha256,
            body_snapshot_sha256: snapshot.sha256,
            mode: self.config.mode,
            provider_configuration_id: self.configuration_id,
            connect_authority: self.config.connect_authority.as_deref(),
            tls_server_name: self.config.tls_server_name.as_deref(),
        })
        .map_err(|_| transport::invalid())?;
        if bytes.len() > crate::domain::evidence::MAX_BODY_BYTES {
            return Err(transport::bounded());
        }
        self.public_bytes(&bytes)?;
        let existing = self.admission.existing_invocation(&binding, call_id)?;
        let call = if let Some(stored) = existing {
            let invocation = stored.invocation;
            if invocation.tool_id.as_str() != "http.send"
                || invocation.tool_version != tool_version
                || invocation.input_sha256 != Digest::of(&bytes)
                || invocation.input_revision != input.base_revision
                || stored.source_control_revision != source_control_revision
                || stored.requested != self.requested
            {
                return Err(transport::invalid());
            }
            let call = PreparedCall {
                invocation_id: invocation.invocation_id,
                call_id,
                tool_id: invocation.tool_id,
                tool_version,
                input_ref: invocation.input_ref,
                input_sha256: invocation.input_sha256,
                input_revision: invocation.input_revision,
                source_control_revision,
                requested: stored.requested,
            };
            if !matches!(
                invocation.state,
                InvocationState::Proposed | InvocationState::WaitingApproval
            ) {
                return Ok(PreparedHttpSend {
                    binding,
                    call,
                    configuration_id: self.configuration_id,
                    operation: None,
                });
            }
            Some(call)
        } else {
            None
        };
        let body = capture::read_complete(
            &self.evidence,
            binding.project_id(),
            request.body_snapshot_id,
            request.body_revision,
            &self.limits,
        )?;
        self.public_bytes(&body)?;
        self.admission.session(&binding)?;
        if request.request_count.get() == 0
            || request.request_count.get() > 3
            || (request.request_count.get() != 1 && self.config.mode != Mode::HttpsHttp2Intercept)
            || (!request.reset_first_stream && request.request_count.get() > 2)
            || (request.reset_first_stream
                && (self.config.mode != Mode::HttpsHttp2Intercept
                    || request.request_count.get() != 3))
        {
            return Err(transport::invalid());
        }
        let destination = scope_connector::normalize(&request.url)?;
        if (destination.scheme() == "https") != self.config.mode.tls() {
            return Err(transport::protocol());
        }
        if request.method.is_empty() {
            return Err(transport::invalid());
        }
        if let Some((_, secret_headers)) = &self.secret_headers
            && (request.headers.len() + secret_headers.len() > 256
                || request
                    .headers
                    .iter()
                    .chain(secret_headers.iter())
                    .map(|h| h.name.len() + h.value.len())
                    .sum::<usize>()
                    > 65_536
                || request.headers.iter().any(|header| {
                    secret_headers
                        .iter()
                        .any(|secret| secret.name.eq_ignore_ascii_case(&header.name))
                }))
        {
            return Err(transport::invalid());
        }
        // Validate framing without cloning the body's original header collection.
        crate::domain::evidence::Snapshot {
            snapshot_id: snapshot.snapshot_id,
            project_id: snapshot.project_id,
            revision: snapshot.revision,
            sha256: snapshot.sha256,
            length_bytes: snapshot.length_bytes,
            body_ref: snapshot.body_ref,
            representation: snapshot.representation,
            headers: request.headers.clone(),
            truncated: false,
            derived_from: snapshot.derived_from,
        }
        .validate()?;
        let framing = transport::http1::request(
            &request.url,
            &request.method,
            &request.headers,
            Vec::new(),
            rama::http::Version::HTTP_11,
        )?;
        capture::encoding(framing.headers())?;
        let call = match call {
            Some(call) => call,
            None => {
                let invocation_id = EntityId::new();
                let artifact = self.evidence.write_artifact(
                    binding.project_id(),
                    CatalogId::parse("http-send-input")?,
                    invocation_id,
                    &bytes,
                    RedactionStatus::Original,
                )?;
                let call = PreparedCall {
                    invocation_id,
                    call_id,
                    tool_id: CatalogId::parse("http.send")?,
                    tool_version,
                    input_ref: artifact.artifact_id,
                    input_sha256: artifact.sha256,
                    input_revision: input.base_revision,
                    source_control_revision,
                    requested: self.requested,
                };
                self.admission.propose(&binding, &call)?;
                call
            }
        };
        Ok(PreparedHttpSend {
            binding,
            call,
            operation: Some(HttpOperation {
                input: input.clone(),
                request,
                body,
            }),
            configuration_id: self.configuration_id,
        })
    }
    pub fn execute(&self, prepared: PreparedHttpSend) -> ProofResult<HttpSendResult> {
        self.detailed(self.execute_route(prepared, false)?)
    }
    pub(crate) fn execute_direct(&self, prepared: PreparedHttpSend) -> ProofResult<HttpSendResult> {
        self.detailed(self.execute_route(prepared, true)?)
    }
    pub(crate) fn execute_invocation(&self, prepared: PreparedHttpSend) -> ProofResult<Invocation> {
        self.execute_route(prepared, false)
            .map(|outcome| outcome.invocation)
    }
    fn detailed(&self, outcome: SendOutcome) -> ProofResult<HttpSendResult> {
        let SendOutcome { invocation, detail } = outcome;
        let (record, record_artifact_id) = match detail {
            Some(detail) => detail,
            None => {
                let id = invocation.output_ref.ok_or_else(|| {
                    invocation.error.clone().unwrap_or_else(|| {
                        ProofError::new(
                            ErrorCode::OutcomeUnknown,
                            "HTTP call is already in progress; no replay is permitted",
                        )
                        .with_invocation(invocation.invocation_id)
                    })
                })?;
                let limit = usize::try_from(self.requested.bytes.get())
                    .map_err(|_| transport::bounded())?;
                let bytes = self
                    .evidence
                    .read_artifact(invocation.project_id, id, limit)?;
                let output: HttpSendOutput =
                    serde_json::from_slice(&bytes).map_err(|_| transport::invalid())?;
                let bytes = self.evidence.read_artifact(
                    invocation.project_id,
                    output.exchange_ref,
                    limit,
                )?;
                (
                    serde_json::from_slice(&bytes).map_err(|_| transport::invalid())?,
                    output.exchange_ref,
                )
            }
        };
        Ok(HttpSendResult {
            invocation,
            record,
            record_artifact_id,
        })
    }
    fn admission_result(
        &self,
        binding: &TrustedBinding,
        call: &PreparedCall,
        error: ProofError,
    ) -> ProofResult<SendOutcome> {
        if matches!(
            error.code,
            ErrorCode::IntegrityError | ErrorCode::OutputInvalid | ErrorCode::InvalidInput
        ) {
            return Err(error);
        }
        let stored = self
            .admission
            .existing_invocation(binding, call.call_id)?
            .ok_or_else(|| error.clone())?;
        if stored.invocation.invocation_id != call.invocation_id {
            return Err(transport::invalid());
        }
        if stored.invocation.error.is_none()
            && !matches!(
                stored.invocation.state,
                InvocationState::Reserved
                    | InvocationState::Sending
                    | InvocationState::Completed
                    | InvocationState::OutcomeUnknown
            )
        {
            return Err(error);
        }
        Ok(SendOutcome::historical(stored.invocation))
    }
    fn execute_route(&self, prepared: PreparedHttpSend, direct: bool) -> ProofResult<SendOutcome> {
        let PreparedHttpSend {
            binding,
            call,
            operation,
            configuration_id,
        } = prepared;
        if configuration_id != self.configuration_id {
            return Err(transport::tls_error());
        }
        if let Some(operation) = &operation {
            // Revalidate immutable storage before reservation, not only during preparation.
            self.evidence.snapshot_reader(
                binding.project_id(),
                operation.input.request_snapshot_id,
                operation.input.base_revision,
            )?;
            self.evidence.snapshot_reader(
                binding.project_id(),
                operation.request.body_snapshot_id,
                operation.request.body_revision,
            )?;
        }
        let reserved = match self.admission.reserve(&binding, &call) {
            Ok(invocation) => invocation,
            Err(error) => return self.admission_result(&binding, &call, error),
        };
        if reserved.state != InvocationState::Reserved {
            return Ok(SendOutcome::historical(reserved));
        }
        let Some(HttpOperation {
            input: _,
            mut request,
            body,
        }) = operation
        else {
            return Ok(SendOutcome::historical(reserved));
        };
        let permit = match self.admission.begin_effect(&binding, call.invocation_id) {
            Ok(permit) => permit,
            Err(error) => return self.admission_result(&binding, &call, error),
        };
        let authority = Arc::new(Authority::new(
            Arc::clone(&self.admission),
            Arc::clone(&binding),
            permit,
        ));
        let mut meter = EffectMeter::start();
        let started_us = transport::clock_us();
        let mut record = SendRecord {
            schema_version: ContractVersion::V0_1_0,
            project_id: binding.project_id(),
            invocation_id: call.invocation_id,
            provider_configuration_id: self.configuration_id,
            io: scope_connector::IoUsage::default(),
            input_snapshot_id: request.body_snapshot_id,
            input_revision: request.body_revision,
            mode: self.config.mode,
            exchanges: Vec::new(),
            stream_errors: Vec::new(),
            stream_links: Vec::new(),
            partial_captures: Vec::new(),
            connections: Vec::new(),
            redirect_chain: Vec::new(),
            redirects_observed: 0,
            tunnel_bytes: None,
            connect_authority: None,
            tls_server_name: None,
            direct,
            network_elapsed_us: 0,
        };
        let operation = (|| {
            authority.recheck()?;
            // Resolve private headers only at the actual network boundary.
            if let Some((identity, headers)) = &self.secret_headers {
                if *identity != binding.identity_id() {
                    return Err(transport::tls_error());
                }
                request.headers.extend(headers.iter().cloned());
            }
            meter.dispatched = true;
            let request_digest = Digest::of(&body);
            meter.add_bytes(body.len())?;
            let started = std::time::Instant::now();
            let outcome = if direct {
                self.runtime.block_on(transport::relay::direct(
                    Arc::clone(&authority),
                    self.config.clone(),
                    self.limits.clone(),
                    transport::RequestData {
                        url: request.url,
                        method: request.method,
                        headers: request.headers,
                        body,
                    },
                ))
            } else {
                self.runtime.block_on(transport::relay::run(
                    Arc::clone(&authority),
                    self.config.clone(),
                    self.limits.clone(),
                    transport::RequestData {
                        url: request.url,
                        method: request.method,
                        headers: request.headers,
                        body,
                    },
                    request.request_count.get() as usize,
                    request.reset_first_stream,
                ))
            };
            record.network_elapsed_us =
                u64::try_from(started.elapsed().as_micros()).map_err(|_| transport::bounded())?;
            let outcome = outcome?;
            record.tunnel_bytes = outcome.facts.tunnel_bytes;
            record.redirects_observed = outcome.facts.redirects as u64;
            record.connect_authority = outcome.facts.connect_authority;
            record.tls_server_name = outcome.facts.tls_server_name;
            record.redirect_chain = outcome.facts.redirect_chain;
            record.stream_links = outcome.facts.stream_links;
            for partial in outcome.facts.partials {
                let error = partial.error.ok_or_else(transport::invalid)?;
                self.public_bytes(&partial.bytes)?;
                let headers = capture::headers(&partial.headers)?;
                self.public_headers(&headers)?;
                authority.recheck()?;
                meter.add_bytes(partial.bytes.len())?;
                meter.write_pending = true;
                let snapshot_id = capture::snapshot(
                    &self.evidence,
                    binding.project_id(),
                    call.invocation_id,
                    capture::SnapshotBody {
                        bytes: &partial.bytes,
                        headers,
                        representation: if self.config.mode == Mode::HttpsHttp2Intercept {
                            Representation::Http2SemanticBody
                        } else {
                            Representation::Http1Body
                        },
                        truncated: true,
                        derived_from: None,
                    },
                )?;
                meter.write_pending = false;
                record.partial_captures.push(PartialCapture {
                    snapshot_id,
                    capture: partial.capture,
                    error,
                });
            }
            for exchange in outcome.exchanges {
                match exchange.received {
                    Ok(received) => {
                        // A successful status is not proof that the body completed.
                        self.public_bytes(&received.bytes)?;
                        let response_headers = capture::headers(&received.headers)?;
                        self.public_headers(&response_headers)?;
                        authority.recheck()?;
                        if let Some(error) = received.error {
                            if self.config.mode != Mode::HttpsConnectTunnel {
                                meter.add_bytes(received.bytes.len())?;
                                meter.write_pending = true;
                                let snapshot_id = capture::snapshot(
                                    &self.evidence,
                                    binding.project_id(),
                                    call.invocation_id,
                                    capture::SnapshotBody {
                                        bytes: &received.bytes,
                                        headers: response_headers,
                                        representation: if self.config.mode
                                            == Mode::HttpsHttp2Intercept
                                        {
                                            Representation::Http2SemanticBody
                                        } else {
                                            Representation::Http1Body
                                        },
                                        truncated: true,
                                        derived_from: None,
                                    },
                                )?;
                                meter.write_pending = false;
                                record.partial_captures.push(PartialCapture {
                                    snapshot_id,
                                    capture: received.capture,
                                    error: error.clone(),
                                });
                            }
                            record.stream_errors.push(StreamError {
                                connection_id: outcome.connection_id,
                                stream_id: exchange.stream_id,
                                started_us: exchange.started_us,
                                observed_us: exchange.finished_us,
                                error,
                            });
                            continue;
                        }
                        if received.capture.truncated {
                            return Err(transport::protocol());
                        }
                        let response_snapshot_id = if self.config.mode == Mode::HttpsConnectTunnel {
                            None
                        } else {
                            meter.add_bytes(received.bytes.len())?;
                            meter.write_pending = true;
                            let id = capture::snapshot(
                                &self.evidence,
                                binding.project_id(),
                                call.invocation_id,
                                capture::SnapshotBody {
                                    bytes: &received.bytes,
                                    headers: response_headers.clone(),
                                    representation: if self.config.mode == Mode::HttpsHttp2Intercept
                                    {
                                        Representation::Http2SemanticBody
                                    } else {
                                        Representation::Http1Body
                                    },
                                    truncated: false,
                                    derived_from: None,
                                },
                            )?;
                            meter.write_pending = false;
                            Some(id)
                        };
                        record.exchanges.push(ExchangeOutput {
                            connection_id: outcome.connection_id,
                            stream_id: exchange.stream_id,
                            started_us: exchange.started_us,
                            finished_us: exchange.finished_us,
                            status: received.status,
                            response_headers,
                            response_capture: received.capture,
                            response_body_sha256: Digest::of(&received.bytes),
                            request_body_sha256: request_digest,
                            response_snapshot_id,
                            client_http_version: received.version,
                            client_alpn: outcome.facts.ingress_tls.clone(),
                            upstream_alpn: received.upstream_alpn,
                            upstream_peer_certificate_sha256: received.certificate,
                        });
                    }
                    Err(error) => record.stream_errors.push(StreamError {
                        connection_id: outcome.connection_id,
                        stream_id: exchange.stream_id,
                        started_us: exchange.started_us,
                        observed_us: exchange.finished_us,
                        error,
                    }),
                }
            }
            for (stream_id, error) in outcome.facts.stream_errors {
                if let Some(client_error) = record
                    .stream_errors
                    .iter_mut()
                    .find(|e| e.stream_id == stream_id)
                {
                    // The relay may expose only RST_CANCEL after an upstream
                    // connection loss. Preserve upstream uncertainty and the
                    // actual client timing instead of downgrading it to framing.
                    if matches!(
                        error.code,
                        ErrorCode::ProviderUnavailable
                            | ErrorCode::Timeout
                            | ErrorCode::OutcomeUnknown
                    ) || !matches!(
                        client_error.error.code,
                        ErrorCode::ProviderUnavailable
                            | ErrorCode::Timeout
                            | ErrorCode::OutcomeUnknown
                    ) {
                        client_error.error = error;
                    }
                } else {
                    record.stream_errors.push(StreamError {
                        connection_id: outcome.connection_id,
                        stream_id,
                        started_us: 0,
                        observed_us: 0,
                        error,
                    });
                }
            }
            if let Some(error) = outcome.facts.errors.into_iter().next() {
                if record.stream_errors.is_empty() {
                    record.stream_errors.push(StreamError {
                        connection_id: outcome.connection_id,
                        stream_id: 0,
                        started_us: 0,
                        observed_us: 0,
                        error,
                    });
                } else if error.code == ErrorCode::PermissionDenied {
                    // An observed TLS authentication denial is authoritative;
                    // its connection close is not an uncertain target outcome.
                    let mut derivative = record.stream_errors.iter_mut().filter(|client| {
                        matches!(
                            client.error.code,
                            ErrorCode::ProviderUnavailable
                                | ErrorCode::Timeout
                                | ErrorCode::OutcomeUnknown
                        )
                    });
                    if let Some(first) = derivative.next() {
                        for remaining in derivative {
                            remaining.error = error.clone();
                        }
                        first.error = error;
                    }
                }
            }
            if record.stream_errors.is_empty()
                && let Some(partial) = record.partial_captures.first()
            {
                record.stream_errors.push(StreamError {
                    connection_id: outcome.connection_id,
                    stream_id: 0,
                    started_us: 0,
                    observed_us: 0,
                    error: partial.error.clone(),
                });
            }
            if record.exchanges.is_empty() && record.stream_errors.is_empty() {
                return Err(transport::network());
            }
            Ok(())
        })();
        if let Err(error) = operation {
            record.stream_errors.push(StreamError {
                connection_id: EntityId::new(),
                stream_id: 0,
                started_us: 0,
                observed_us: 0,
                error,
            });
        }
        let ambiguous_write = meter.write_pending;
        let publication = (|| {
            record.connections = authority.connection_facts()?;
            record.io = authority.io_usage()?;
            meter.add_bytes(
                usize::try_from(record.io.attempted_request_body_bytes)
                    .map_err(|_| transport::bounded())?,
            )?;
            meter.add_bytes(
                usize::try_from(record.io.captured_response_body_bytes)
                    .map_err(|_| transport::bounded())?,
            )?;
            let timing = HttpSendTiming {
                started_us,
                finished_us: transport::clock_us(),
                network_elapsed_us: record.network_elapsed_us,
            };
            let timing_bytes = serde_json::to_vec(&timing).map_err(|_| transport::invalid())?;
            let bytes = serde_json::to_vec(&record).map_err(|_| transport::invalid())?;
            self.public_bytes(&bytes)?;
            self.public_bytes(&timing_bytes)?;
            meter.add_bytes(timing_bytes.len())?;
            meter.write_pending = true;
            let timing_artifact = self.evidence.write_artifact(
                binding.project_id(),
                CatalogId::parse("http-send-timing")?,
                call.invocation_id,
                &timing_bytes,
                RedactionStatus::Original,
            )?;
            meter.add_bytes(bytes.len())?;
            let artifact = self.evidence.write_artifact(
                binding.project_id(),
                CatalogId::parse(if record.stream_errors.is_empty() {
                    "http-send-result"
                } else {
                    "http-send-failure"
                })?,
                call.invocation_id,
                &bytes,
                RedactionStatus::Original,
            )?;
            meter.write_pending = false;
            let output_ref = if record.stream_errors.is_empty() && !ambiguous_write {
                let response_snapshot_ref = record
                    .exchanges
                    .last()
                    .and_then(|exchange| exchange.response_snapshot_id);
                if self.config.mode != Mode::HttpsConnectTunnel && response_snapshot_ref.is_none() {
                    return Err(transport::invalid());
                }
                let bytes = serde_json::to_vec(&HttpSendOutput {
                    exchange_ref: artifact.artifact_id,
                    response_snapshot_ref,
                    timing_ref: timing_artifact.artifact_id,
                })
                .map_err(|_| transport::invalid())?;
                self.public_bytes(&bytes)?;
                meter.add_bytes(bytes.len())?;
                let usage = meter.usage()?;
                if usage.bytes > call.requested.bytes
                    || usage.cpu_us > call.requested.cpu_us
                    || usage.elapsed_us > call.requested.elapsed_us
                {
                    return Err(transport::bounded());
                }
                meter.write_pending = true;
                let output = self.evidence.write_artifact(
                    binding.project_id(),
                    CatalogId::parse("http-send-output")?,
                    call.invocation_id,
                    &bytes,
                    RedactionStatus::Original,
                )?;
                meter.write_pending = false;
                Some(output.artifact_id)
            } else {
                None
            };
            Ok((artifact.artifact_id, output_ref))
        })();
        let (record_artifact_id, output_ref) = match publication {
            Ok(result) => result,
            Err(error) => {
                let permit = authority.take_permit()?;
                let invocation = self.admission.outcome_unknown(&binding, permit, meter.usage()?,
                    ProofError::new(ErrorCode::OutcomeUnknown, if error.code == ErrorCode::PermissionDenied {
                        "HTTP evidence cannot be published without disclosing private credentials; reconciliation is required"
                    } else { "HTTP effect evidence persistence requires reconciliation" }))?;
                return Ok(SendOutcome::historical(invocation));
            }
        };
        let usage = meter.usage()?;
        let permit = authority.take_permit()?;
        let error = record.stream_errors.first().map(|e| e.error.clone());
        let uncertain = ambiguous_write
            || record.stream_errors.iter().any(|e| {
                matches!(
                    e.error.code,
                    ErrorCode::Timeout
                        | ErrorCode::ProviderUnavailable
                        | ErrorCode::OutcomeUnknown
                        | ErrorCode::OutputInvalid
                )
            });
        let invocation = if uncertain && meter.dispatched {
            self.admission.outcome_unknown(
                &binding,
                permit,
                usage,
                ProofError::new(
                    ErrorCode::OutcomeUnknown,
                    "HTTP dispatch requires read-only reconciliation; no retry is permitted",
                ),
            )?
        } else if usage.bytes > call.requested.bytes
            || usage.cpu_us > call.requested.cpu_us
            || usage.elapsed_us > call.requested.elapsed_us
        {
            self.admission
                .fail(&binding, permit, usage, transport::bounded())?
        } else if let Some(error) = error {
            self.admission.fail(&binding, permit, usage, error)?
        } else {
            self.admission
                .complete(&binding, permit, usage, output_ref)?
        };
        Ok(SendOutcome {
            invocation,
            detail: Some((record, record_artifact_id)),
        })
    }
}
#[derive(Serialize)]
struct PreparedInput<'a> {
    input: &'a HttpSendInput,
    request: &'a RequestSnapshot,
    request_snapshot_sha256: Digest,
    body_snapshot_sha256: Digest,
    mode: Mode,
    provider_configuration_id: EntityId,
    #[serde(skip_serializing_if = "Option::is_none")]
    connect_authority: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tls_server_name: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::workspace::OwnedDirectory;
    use crate::application::proof_host::ProofHost;
    use crate::domain::authority::{DestinationRule, PathKind, PathRule, Scheme};
    use crate::protocol::contracts::CanonicalFixtures;
    use std::io::{Read, Write};
    use std::net::{Ipv4Addr, TcpListener};
    use std::path::Path;
    use std::time::{Duration, Instant};

    mod private_root {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/private_root.rs"
        ));
    }

    #[test]
    fn direct_response_completion_controls_partial_capture_history_and_unknown_hold() {
        for partial_response in [true, false] {
            let root = private_root::PrivateRoot::new();
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            listener.set_nonblocking(true).unwrap();
            let receiver = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(
                                Instant::now() < deadline,
                                "direct provider did not reach the actual receiver"
                            );
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("actual receiver accept failed: {error}"),
                    }
                };
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                let (header_end, body_length) = loop {
                    let length = stream.read(&mut buffer).unwrap();
                    assert!(length > 0);
                    request.extend_from_slice(&buffer[..length]);
                    assert!(request.len() <= 1_114_112);
                    if let Some(end) = request.windows(4).position(|part| part == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).unwrap();
                        let length = headers
                            .lines()
                            .filter_map(|line| line.split_once(':'))
                            .find_map(|(name, value)| {
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().unwrap())
                            })
                            .unwrap();
                        break (end + 4, length);
                    }
                };
                while request.len() - header_end < body_length {
                    let length = stream.read(&mut buffer).unwrap();
                    assert!(length > 0);
                    request.extend_from_slice(&buffer[..length]);
                    assert!(request.len() <= 1_114_112);
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\nactual-partial-body",
                    if partial_response { 128 } else { 19 }
                );
                stream.write_all(response.as_bytes()).unwrap();
                stream.shutdown(std::net::Shutdown::Both).unwrap();
                request[header_end..].to_vec()
            });
            let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
            let profile = LoadedProfile::load(
                &repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
            )
            .unwrap();
            let fixtures = std::fs::read(repo.join("fixtures/scenarios/contracts.json")).unwrap();
            let workspace = Arc::new(
                OwnedDirectory::create(root.path(), Path::new("direct-partial"), EntityId::new())
                    .unwrap(),
            );
            let host = ProofHost::create(
                workspace,
                &profile,
                CanonicalFixtures::from_bytes(&fixtures).unwrap(),
                Digest::of(&fixtures),
                Digest::of(b"direct partial response provider"),
            )
            .unwrap();
            let mut scope = host
                .ledger
                .read_scope(host.project.scope_policy_id)
                .unwrap();
            let previous = scope.revision;
            scope.revision = previous.checked_add(WireInt::new(1).unwrap()).unwrap();
            scope.allowed_destinations = vec![DestinationRule {
                scheme: Scheme::Http,
                host: "direct.razen.invalid".into(),
                port: address.port(),
                path: PathRule {
                    kind: PathKind::Prefix,
                    value: "/".into(),
                },
                resolved_addresses: vec![address.ip()],
            }];
            scope.exclusions.clear();
            host.ledger.replace_scope(&scope, previous).unwrap();
            host.ledger
                .insert_tool(&registered_tool(host.provider_digest, &profile).unwrap())
                .unwrap();
            let mut spec = host.local_spec();
            spec.allowed_tools
                .push(CatalogId::parse("http.send").unwrap());
            spec.permissions
                .push(CatalogId::parse("http.send").unwrap());
            let binding = Arc::new(host.admission.bind(spec).unwrap());
            let body = host
                .evidence
                .snapshots()
                .unwrap()
                .into_iter()
                .find(|snapshot| !snapshot.truncated)
                .unwrap();
            let input = install_request(
                &host.evidence,
                &binding,
                EntityId::new(),
                RequestSnapshot {
                    body_snapshot_id: body.snapshot_id,
                    body_revision: body.revision,
                    url: format!("http://direct.razen.invalid:{}/partial", address.port()),
                    method: "POST".into(),
                    headers: vec![Header {
                        name: "host".into(),
                        value: format!("direct.razen.invalid:{}", address.port()),
                    }],
                    request_count: WireInt::new(1).unwrap(),
                    reset_first_stream: false,
                },
            )
            .unwrap();
            let zone = Arc::new(scope_connector::FixtureZone::default());
            zone.publish("direct.razen.invalid", vec![address.ip()])
                .unwrap();
            let roots = Arc::new(rustls::RootCertStore::empty());
            let provider = HttpSendProvider::new(
                Arc::clone(&host.admission),
                Arc::clone(&host.evidence),
                &profile,
                TransportConfig {
                    mode: Mode::Http1Forward,
                    resolver: scope_connector::Resolver::Fixture(zone),
                    upstream_roots: Arc::clone(&roots),
                    client_roots: roots,
                    ingress_tls: None,
                    tls_server_name: None,
                    connect_authority: None,
                },
            )
            .unwrap();
            let call_id = EntityId::new();
            let prepared = provider
                .prepare_call(Arc::clone(&binding), call_id, &input)
                .unwrap();
            host.approve(&binding, prepared.call()).unwrap();
            let result = provider.execute_direct(prepared).unwrap();
            let sent_body = receiver.join().unwrap();
            assert_eq!(Digest::of(&sent_body), body.sha256);
            let retained_bodies = result
                .record
                .exchanges
                .iter()
                .filter_map(|exchange| exchange.response_snapshot_id)
                .chain(
                    result
                        .record
                        .partial_captures
                        .iter()
                        .map(|partial| partial.snapshot_id),
                )
                .map(|id| {
                    host.evidence
                        .snapshot(binding.project_id(), id, WireInt::ZERO)
                        .unwrap()
                        .length_bytes
                        .get()
                })
                .sum::<u64>();
            let retained_artifacts = host
                .evidence
                .artifacts()
                .unwrap()
                .iter()
                .filter(|artifact| {
                    artifact.origin_invocation_id == result.invocation.invocation_id
                        && [
                            "http-send-result",
                            "http-send-failure",
                            "http-send-output",
                            "http-send-timing",
                        ]
                        .contains(&artifact.kind.as_str())
                })
                .map(|artifact| artifact.length_bytes.get())
                .sum::<u64>();
            assert_eq!(
                result.invocation.usage.bytes.get(),
                body.length_bytes.get()
                    + result.record.io.attempted_request_body_bytes
                    + result.record.io.captured_response_body_bytes
                    + retained_bodies
                    + retained_artifacts
            );
            if !partial_response {
                assert_eq!(result.invocation.state, InvocationState::Completed);
                let output: HttpSendOutput = serde_json::from_slice(
                    &host
                        .evidence
                        .read_artifact(
                            binding.project_id(),
                            result.invocation.output_ref.unwrap(),
                            1024,
                        )
                        .unwrap(),
                )
                .unwrap();
                assert_eq!(output.exchange_ref, result.record_artifact_id);
                assert_eq!(
                    output.response_snapshot_ref,
                    result.record.exchanges[0].response_snapshot_id
                );
                let before = host.ledger.read_budget(host.budget_id).unwrap();
                let duplicate = provider
                    .prepare_call(Arc::clone(&binding), call_id, &input)
                    .unwrap();
                let historical = provider.execute_direct(duplicate).unwrap();
                assert_eq!(historical.record_artifact_id, result.record_artifact_id);
                assert_eq!(
                    serde_json::to_value(&historical.record).unwrap(),
                    serde_json::to_value(&result.record).unwrap()
                );
                assert_eq!(host.ledger.read_budget(host.budget_id).unwrap(), before);
                continue;
            }
            assert_eq!(result.invocation.state, InvocationState::OutcomeUnknown);
            assert!(result.invocation.output_ref.is_none());
            assert!(result.record.exchanges.is_empty());
            assert_eq!(result.record.partial_captures.len(), 1);
            assert_eq!(result.record.stream_errors.len(), 1);
            assert_eq!(
                result.record.stream_errors[0].error.code,
                ErrorCode::ProviderUnavailable
            );
            let partial = &result.record.partial_captures[0];
            let reader = host
                .evidence
                .snapshot_reader(binding.project_id(), partial.snapshot_id, WireInt::ZERO)
                .unwrap();
            assert!(reader.metadata().truncated);
            assert_eq!(
                reader
                    .read(WireInt::ZERO, reader.metadata().length_bytes)
                    .unwrap(),
                b"actual-partial-body"
            );
            let held = host.ledger.read_budget(host.budget_id).unwrap();
            assert_eq!(
                host.ledger
                    .read_invocation(result.invocation.invocation_id)
                    .unwrap()
                    .reserved_units,
                WireInt::new(1).unwrap()
            );
            let duplicate = provider
                .prepare_call(Arc::clone(&binding), call_id, &input)
                .unwrap();
            assert_eq!(
                provider.execute_direct(duplicate).err().unwrap().code,
                ErrorCode::OutcomeUnknown
            );
            assert_eq!(host.ledger.read_budget(host.budget_id).unwrap(), held);
            assert!(!host.evidence.artifacts().unwrap().iter().any(|artifact| {
                artifact.origin_invocation_id == result.invocation.invocation_id
                    && artifact.kind.as_str() == "http-send-output"
            }));
        }
    }
}
