use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use razen_engine::adapters::ledger::RegisteredTool;
use razen_engine::adapters::transport::{
    Mode, TransportConfig,
    scope_connector::{FixtureZone, Resolver},
};
use razen_engine::application::admission::{PreparedCall, TrustedBinding};
use razen_engine::application::effect_meter::EffectMeter;
use razen_engine::application::http_send::{
    self, HttpSendInput, HttpSendOutput, RequestSnapshot, SendRecord,
};
use razen_engine::domain::authority::{
    DestinationRule, Effect, PathKind, PathRule, RetryClass, Scheme, ToolDescriptor,
};
use razen_engine::domain::evidence::{Header, RedactionStatus, Representation, Snapshot};
use razen_engine::domain::values::{ContractVersion, Usage};
use razen_engine::protocol::error::{ErrorCode, ProofError, ProofResult};
use razen_engine::protocol::messages::{ToolRequest, ToolResult};
use serde_json::value::RawValue;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::runtime::Runtime;

use super::transport_io as io;

use razen_engine::adapters::workspace::OwnedDirectory;
use razen_engine::application::profile::LoadedProfile;
use razen_engine::application::proof_host::ProofHost;
use razen_engine::application::suites::{CaseObservation, transport};
use razen_engine::domain::values::{CatalogId, Digest, EntityId, WireInt};
use razen_engine::protocol::contracts::CanonicalFixtures;

#[path = "private_root.rs"]
mod private_root;

pub struct Fixture {
    pub host: ProofHost,
    pub profile: LoadedProfile,
    pub repo: PathBuf,
    _root: private_root::PrivateRoot,
}

impl Default for Fixture {
    fn default() -> Self {
        Self::new()
    }
}

impl Fixture {
    pub fn new() -> Self {
        Self::create(None)
    }

    pub fn scoped(destinations: &[DestinationRule]) -> Self {
        Self::create(Some(destinations))
    }

    fn create(destinations: Option<&[DestinationRule]>) -> Self {
        let root = private_root::PrivateRoot::new();
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = LoadedProfile::load(
            &repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let mut bytes = std::fs::read(repo.join("fixtures/scenarios/contracts.json")).unwrap();
        if let Some(destinations) = destinations {
            let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            let scope = value["records"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|record| record["record"]["type"] == "scope_policy")
                .unwrap();
            scope["record"]["fields"]["allowed_destinations"] =
                serde_json::to_value(destinations).unwrap();
            bytes = serde_json::to_vec(&value).unwrap();
        }
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("transport"), EntityId::new()).unwrap(),
        );
        let host = ProofHost::create(
            workspace,
            &profile,
            CanonicalFixtures::from_bytes(&bytes).unwrap(),
            Digest::of(&bytes),
            Digest::of(b"US2 integration test host"),
        )
        .unwrap();
        Self {
            host,
            profile,
            repo,
            _root: root,
        }
    }

    pub fn execute(&self, case: &str) -> CaseObservation {
        transport::execute(
            &self.host,
            &self.profile,
            &self.repo,
            &CatalogId::parse(case).unwrap(),
        )
        .unwrap()
    }

    pub fn body(&self, exchange: &serde_json::Value, name: &str) -> Vec<u8> {
        let project: EntityId = serde_json::from_value(exchange["project_id"].clone()).unwrap();
        let snapshot: EntityId = serde_json::from_value(exchange[name].clone()).unwrap();
        let reader = self
            .host
            .evidence
            .snapshot_reader(project, snapshot, WireInt::ZERO)
            .unwrap();
        let metadata = self
            .host
            .evidence
            .snapshots()
            .unwrap()
            .into_iter()
            .find(|s| s.snapshot_id == snapshot)
            .unwrap();
        reader.read(WireInt::ZERO, metadata.length_bytes).unwrap()
    }

    pub fn http_binding(&self) -> Arc<TrustedBinding> {
        if self
            .host
            .ledger
            .find_tool(&catalog("http.send"))
            .unwrap()
            .is_none()
        {
            self.host
                .ledger
                .insert_tool(
                    &http_send::registered_tool(self.host.provider_digest, &self.profile).unwrap(),
                )
                .unwrap();
        }
        let tool = RegisteredTool {
            provider_digest: self.host.provider_digest,
            descriptor: ToolDescriptor {
                tool_id: catalog("proof.transport.fixture"),
                version: ContractVersion::V0_1_0,
                input_contract: catalog("proof.transport.fixture.input"),
                output_contract: catalog("proof.transport.fixture.output"),
                effect: Effect::LocalWrite,
                permissions: vec![catalog("proof.transport.fixture")],
                retry_class: RetryClass::NonRetryable,
                limits: Usage {
                    units: wire(1),
                    bytes: wire(8 * 1_048_576),
                    cpu_us: wire(30_000_000),
                    elapsed_us: wire(30_000_000),
                },
            },
        };
        self.host.ledger.insert_tool(&tool).unwrap();
        let mut spec = self.host.local_spec();
        spec.allowed_tools
            .extend([catalog("http.send"), tool.descriptor.tool_id.clone()]);
        spec.permissions
            .extend([catalog("http.send"), tool.descriptor.tool_id]);
        Arc::new(self.host.admission.bind(spec).unwrap())
    }

    pub fn request(
        &self,
        binding: &Arc<TrustedBinding>,
        url: &str,
        body: &[u8],
        headers: Vec<Header>,
    ) -> HttpSendInput {
        self.request_with_grant_limits(binding, url, body, headers, None)
    }

    pub fn request_with_grant_limits(
        &self,
        binding: &Arc<TrustedBinding>,
        url: &str,
        body: &[u8],
        mut headers: Vec<Header>,
        grant_limits: Option<Usage>,
    ) -> HttpSendInput {
        let origin = EntityId::new();
        let input = serde_json::to_vec(
            &serde_json::json!({"url":url,"body_sha256":Digest::of(body),"body_bytes":body.len()}),
        )
        .unwrap();
        let input_artifact = self
            .host
            .evidence
            .write_artifact(
                binding.project_id(),
                catalog("transport-fixture-input"),
                origin,
                &input,
                RedactionStatus::Original,
            )
            .unwrap();
        let call = PreparedCall {
            invocation_id: origin,
            call_id: EntityId::new(),
            tool_id: catalog("proof.transport.fixture"),
            tool_version: ContractVersion::V0_1_0,
            input_ref: input_artifact.artifact_id,
            input_sha256: input_artifact.sha256,
            input_revision: WireInt::ZERO,
            source_control_revision: binding.control_revision(),
            requested: self
                .host
                .ledger
                .read_tool(&catalog("proof.transport.fixture"))
                .unwrap()
                .descriptor
                .limits,
        };
        self.host.admission.propose(binding, &call).unwrap();
        if let Some(limits) = grant_limits {
            self.approve_with_limits(binding, &call, limits);
        } else {
            self.host.approve(binding, &call).unwrap();
        }
        self.host.admission.reserve(binding, &call).unwrap();
        let permit = self.host.admission.begin_effect(binding, origin).unwrap();
        let mut meter = EffectMeter::start();
        meter.dispatched = true;
        self.host
            .admission
            .recheck_effect(binding, &permit)
            .unwrap();
        let mut retained_bytes = input.len() + body.len();
        let result = (|| -> ProofResult<(HttpSendInput, EntityId)> {
            let artifact = self.host.evidence.write_artifact(
                binding.project_id(),
                catalog("http-body"),
                origin,
                body,
                RedactionStatus::Original,
            )?;
            let snapshot = self.host.evidence.install_snapshot(Snapshot {
                snapshot_id: EntityId::new(),
                project_id: binding.project_id(),
                revision: WireInt::ZERO,
                sha256: artifact.sha256,
                length_bytes: artifact.length_bytes,
                body_ref: artifact.artifact_id,
                representation: Representation::Http1Body,
                headers: Vec::new(),
                truncated: false,
                derived_from: None,
            })?;
            headers.push(Header {
                name: "host".into(),
                value: url::Url::parse(url).unwrap().authority().to_owned(),
            });
            headers.push(Header {
                name: "content-length".into(),
                value: body.len().to_string(),
            });
            let request = RequestSnapshot {
                body_snapshot_id: snapshot.snapshot_id,
                body_revision: snapshot.revision,
                url: url.to_owned(),
                method: "POST".into(),
                headers,
                request_count: wire(1),
                reset_first_stream: false,
            };
            retained_bytes += serde_json::to_vec(&request).unwrap().len();
            let input = http_send::install_request(&self.host.evidence, binding, origin, request)?;
            let descriptor = self.host.evidence.snapshot(
                binding.project_id(),
                input.request_snapshot_id,
                input.base_revision,
            )?;
            Ok((input, descriptor.body_ref))
        })();
        meter.add_bytes(retained_bytes).unwrap();
        match result {
            Ok((input, output)) => {
                self.host
                    .admission
                    .complete(binding, permit, meter.usage().unwrap(), Some(output))
                    .unwrap();
                input
            }
            Err(error) => {
                self.host
                    .admission
                    .outcome_unknown(
                        binding,
                        permit,
                        meter.usage().unwrap(),
                        ProofError::new(
                            ErrorCode::OutcomeUnknown,
                            "Owned transport fixture publication requires reconciliation",
                        ),
                    )
                    .unwrap();
                panic!("owned request publication failed: {error:?}");
            }
        }
    }

    pub fn approve_with_limits(
        &self,
        binding: &TrustedBinding,
        call: &PreparedCall,
        limits: Usage,
    ) -> EntityId {
        let grant_id = EntityId::new();
        self.host
            .ledger
            .insert_grant(&razen_engine::domain::authority::ApprovalGrant {
                grant_id,
                project_id: binding.project_id(),
                tool_id: call.tool_id.clone(),
                tool_version: call.tool_version,
                provider_digest: binding.provider_digest(),
                scope_revision: binding.scope_revision(),
                identity_id: binding.identity_id(),
                bounded_input_sha256: call.input_sha256,
                limits,
                expires_at: serde_json::from_value(serde_json::json!("2099-01-01T00:00:00Z"))
                    .unwrap(),
                revoked: false,
            })
            .unwrap();
        grant_id
    }

    pub fn send(
        &self,
        registry: &razen_engine::application::registry::Registry,
        binding: &Arc<TrustedBinding>,
        input: &HttpSendInput,
    ) -> ToolResult {
        let raw = RawValue::from_string(serde_json::to_string(input).unwrap()).unwrap();
        let request = ToolRequest {
            call_id: EntityId::new(),
            tool_id: catalog("http.send"),
            tool_version: ContractVersion::V0_1_0,
            input: &raw,
            source_control_revision: binding.control_revision(),
        };
        let prepared = registry.prepare(binding, &request).unwrap();
        self.host.approve(binding, prepared.call()).unwrap();
        registry.execute_prepared(binding, prepared).unwrap()
    }

    pub fn record(&self, result: &ToolResult) -> SendRecord {
        let id = if let Some(id) = result.output_ref {
            let bytes = self
                .host
                .evidence
                .read_artifact(self.host.project.project_id, id, 65_536)
                .unwrap();
            serde_json::from_slice::<HttpSendOutput>(&bytes)
                .unwrap()
                .exchange_ref
        } else {
            self.host
                .evidence
                .artifacts()
                .unwrap()
                .into_iter()
                .find(|artifact| {
                    artifact.origin_invocation_id == result.invocation_id
                        && artifact.kind.as_str() == "http-send-failure"
                })
                .unwrap()
                .artifact_id
        };
        serde_json::from_slice(
            &self
                .host
                .evidence
                .read_artifact(self.host.project.project_id, id, 2 * 1_048_576)
                .unwrap(),
        )
        .unwrap()
    }

    pub fn secret_registry(
        &self,
        config: TransportConfig,
        binding: &TrustedBinding,
        token: &str,
    ) -> razen_engine::application::registry::Registry {
        let provider = http_send::HttpSendProvider::new(
            Arc::clone(&self.host.admission),
            Arc::clone(&self.host.evidence),
            &self.profile,
            config,
        )
        .unwrap()
        .with_secret_headers(
            binding.identity_id(),
            vec![Header {
                name: "authorization".into(),
                value: format!("Bearer {token}"),
            }],
        )
        .unwrap();
        razen_engine::application::registry::Registry::with_http(
            Arc::clone(&self.host.admission),
            Arc::clone(&self.host.evidence),
            CanonicalFixtures::load(&self.repo.join("fixtures/scenarios/contracts.json")).unwrap(),
            &self.profile,
            provider,
        )
        .unwrap()
    }
}

pub fn exchanges(observation: &CaseObservation) -> &[serde_json::Value] {
    observation.report["exchanges"]
        .as_array()
        .expect("actual exchange facts")
}

pub fn attempts(observation: &CaseObservation) -> &[serde_json::Value] {
    observation.report["attempts"]
        .as_array()
        .expect("actual adversarial attempt facts")
}

pub fn attempt<'a>(observation: &'a CaseObservation, variant: &str) -> &'a serde_json::Value {
    attempts(observation)
        .iter()
        .find(|a| a["variant"] == variant)
        .expect("required real attempt")
}

pub fn assert_denied(attempt: &serde_json::Value) {
    assert!(
        attempt["error_code"].is_string(),
        "denial must be explicit: {attempt}"
    );
    assert_eq!(
        attempt["forbidden_before"], attempt["forbidden_after"],
        "forbidden receiver changed"
    );
    assert!(
        attempt["healthy_arrivals"].as_u64().unwrap() > 0,
        "unreachable observer is not denial evidence"
    );
    assert!(
        attempt["invocation_id"].is_string(),
        "attempt must have durable admission provenance"
    );
}

fn catalog(value: &str) -> CatalogId {
    CatalogId::parse(value).unwrap()
}
fn wire(value: u64) -> WireInt {
    WireInt::new(value).unwrap()
}
pub const HOST: &str = "target.razen.invalid";

pub fn runtime() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

pub struct TlsFixture {
    pub roots: Arc<rustls::RootCertStore>,
    pub server: Arc<rustls::ServerConfig>,
}
impl Default for TlsFixture {
    fn default() -> Self {
        Self::new()
    }
}

impl TlsFixture {
    pub fn new() -> Self {
        Self::with_alpn(b"http/1.1")
    }
    pub fn h2() -> Self {
        Self::with_alpn(b"h2")
    }
    fn with_alpn(alpn: &[u8]) -> Self {
        let mut params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        let issuer =
            rcgen::CertifiedIssuer::self_signed(params, rcgen::KeyPair::generate().unwrap())
                .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(issuer.der().clone()).unwrap();
        let key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec![HOST.to_owned()])
            .unwrap()
            .signed_by(&key, &issuer)
            .unwrap();
        let mut server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), issuer.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
        server.alpn_protocols = vec![alpn.to_vec()];
        Self {
            roots: Arc::new(roots),
            server: Arc::new(server),
        }
    }
}

#[derive(Clone)]
pub enum Reply {
    Echo,
    Redirect(String),
    Wire(Vec<u8>),
    Lost,
}
#[derive(Default)]
struct WireObservations {
    bodies: Mutex<Vec<Vec<u8>>>,
    authorization: Mutex<Vec<Option<String>>>,
    tls_accepted: AtomicU64,
    tls_rejected: AtomicU64,
    plaintext: AtomicU64,
}
pub struct WireReceiver {
    pub address: SocketAddr,
    observed: Arc<WireObservations>,
    task: tokio::task::JoinHandle<()>,
}
impl WireReceiver {
    pub fn start(runtime: &Runtime, tls: Option<Arc<rustls::ServerConfig>>, reply: Reply) -> Self {
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let address = listener.local_addr().unwrap();
        let observed = Arc::new(WireObservations::default());
        let accepted = Arc::clone(&observed);
        let task = runtime.spawn(async move {
            let mut children = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let observed = Arc::clone(&accepted);
                let tls = tls.clone();
                let reply = reply.clone();
                children.spawn(async move {
                    let result = async {
                        if let Some(tls) = tls {
                            let mut first = [0; 1];
                            if stream.peek(&mut first).await? == 1 && first[0].is_ascii_alphabetic()
                            {
                                observed.plaintext.fetch_add(1, Ordering::SeqCst);
                            }
                            match rama::tls::rustls::dep::tokio_rustls::TlsAcceptor::from(tls)
                                .accept(stream)
                                .await
                            {
                                Ok(stream) => {
                                    observed.tls_accepted.fetch_add(1, Ordering::SeqCst);
                                    serve_wire(stream, observed, reply).await
                                }
                                Err(error) => {
                                    observed.tls_rejected.fetch_add(1, Ordering::SeqCst);
                                    Err(error)
                                }
                            }
                        } else {
                            serve_wire(stream, observed, reply).await
                        }
                    };
                    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), result).await;
                });
                while children.try_join_next().is_some() {}
            }
        });
        Self {
            address,
            observed,
            task,
        }
    }
    pub fn url(&self, tls: bool) -> String {
        format!(
            "{}://{HOST}:{}/echo",
            if tls { "https" } else { "http" },
            self.address.port()
        )
    }
    pub fn bodies(&self) -> Vec<Vec<u8>> {
        self.observed.bodies.lock().unwrap().clone()
    }
    pub fn tls_accepted(&self) -> u64 {
        self.observed.tls_accepted.load(Ordering::SeqCst)
    }
    pub fn tls_rejected(&self) -> u64 {
        self.observed.tls_rejected.load(Ordering::SeqCst)
    }
    pub fn authorizations(&self) -> Vec<Option<String>> {
        self.observed.authorization.lock().unwrap().clone()
    }
    pub fn wait_tls_rejected(&self, expected: u64) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while self.tls_rejected() < expected {
            assert!(
                std::time::Instant::now() < deadline,
                "owned TLS receiver did not observe a rejected handshake"
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    pub fn plaintext(&self) -> u64 {
        self.observed.plaintext.load(Ordering::SeqCst)
    }
    pub fn rule(&self, tls: bool) -> DestinationRule {
        DestinationRule {
            scheme: if tls { Scheme::Https } else { Scheme::Http },
            host: HOST.to_owned(),
            port: self.address.port(),
            path: PathRule {
                kind: PathKind::Prefix,
                value: "/".into(),
            },
            resolved_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        }
    }
}
impl Drop for WireReceiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_wire<IO>(
    mut stream: IO,
    observed: Arc<WireObservations>,
    reply: Reply,
) -> std::io::Result<()>
where
    IO: AsyncRead + AsyncWrite + Unpin,
{
    // The owned receiver consumes the complete bounded POST before the selected
    // real wire response (or intentional response loss). It is not a provider.
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 65_536 {
            return Err(std::io::ErrorKind::InvalidData.into());
        }
        head.push(stream.read_u8().await?);
    }
    let head = std::str::from_utf8(&head).map_err(|_| std::io::ErrorKind::InvalidData)?;
    let length = head
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .ok_or(std::io::ErrorKind::InvalidData)?
        .1
        .trim()
        .parse::<usize>()
        .map_err(|_| std::io::ErrorKind::InvalidData)?;
    if length > 1_048_576 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    observed.bodies.lock().unwrap().push(body.clone());
    let authorization = head
        .split("\r\n")
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .map(|(_, value)| value.trim().to_owned());
    observed.authorization.lock().unwrap().push(authorization);
    match reply {
        Reply::Echo => {
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await?;
            stream.write_all(&body).await?;
        }
        Reply::Redirect(location) => {
            stream.write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).await?;
        }
        Reply::Wire(bytes) => stream.write_all(&bytes).await?,
        Reply::Lost => {}
    }
    stream.shutdown().await
}

pub fn configuration(mode: Mode, roots: Arc<rustls::RootCertStore>, port: u16) -> TransportConfig {
    let zone = Arc::new(FixtureZone::default());
    zone.publish(HOST, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
        .unwrap();
    TransportConfig {
        mode,
        resolver: Resolver::Fixture(zone),
        upstream_roots: Arc::clone(&roots),
        client_roots: roots,
        ingress_tls: None,
        tls_server_name: (mode != Mode::Http1Forward).then(|| HOST.to_owned()),
        connect_authority: (mode != Mode::Http1Forward).then(|| format!("{HOST}:{port}")),
    }
}

#[derive(Clone)]
pub enum H2Reply {
    Echo,
    Lost,
    Oversized(usize),
    DisconnectAfterPrefix(rama::bytes::Bytes),
}
pub struct H2Receiver {
    pub address: SocketAddr,
    bodies: Arc<Mutex<Vec<Vec<u8>>>>,
    task: tokio::task::JoinHandle<()>,
}
impl H2Receiver {
    pub fn start(runtime: &Runtime, tls: Arc<rustls::ServerConfig>, reply: H2Reply) -> Self {
        let listener = runtime
            .block_on(tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)))
            .unwrap();
        let address = listener.local_addr().unwrap();
        let bodies = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&bodies);
        let task = runtime.spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            while let Ok((stream, _)) = listener.accept().await {
                let tls = Arc::clone(&tls);
                let reply = reply.clone();
                let observed = Arc::clone(&observed);
                connections.spawn(async move {
                    let stream = rama::tls::rustls::dep::tokio_rustls::TlsAcceptor::from(tls)
                        .accept(stream)
                        .await
                        .unwrap();
                    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
                    let mut connection = rama::http::core::h2::server::Builder::new()
                        .with_max_concurrent_streams(2)
                        .with_max_header_list_size(65_536)
                        .handshake::<_, rama::bytes::Bytes>(io::RamaIo::new(stream))
                        .await
                        .unwrap();
                    let (request, mut respond) = connection.accept().await.unwrap().unwrap();
                    let driver = io::OwnedTask::new(tokio::spawn(async move {
                        if let Some(request) = connection.accept().await {
                            request.expect("valid owned HTTP/2 connection");
                            panic!("this fault receiver accepts one stream per actual connection");
                        }
                    }));
                    let mut received = request.into_body();
                    let mut body = Vec::new();
                    while let Some(data) = received.data().await {
                        let data = data.unwrap();
                        assert!(body.len() + data.len() <= 1_048_576);
                        body.extend_from_slice(&data);
                        received
                            .flow_control()
                            .release_capacity(data.len())
                            .unwrap();
                    }
                    observed.lock().unwrap().push(body.clone());
                    if matches!(reply, H2Reply::Lost) {
                        // The independent receiver consumed the complete POST.
                        // Destroy the actual connection without response headers.
                        driver.abort();
                        let _ = driver.await;
                        return;
                    }
                    let (bytes, complete) = match reply {
                        H2Reply::Echo => (rama::bytes::Bytes::from(body), true),
                        H2Reply::Oversized(length) => {
                            (rama::bytes::Bytes::from(vec![b'X'; length]), true)
                        }
                        H2Reply::DisconnectAfterPrefix(bytes) => (bytes, false),
                        H2Reply::Lost => unreachable!(),
                    };
                    let response = rama::http::Response::builder()
                        .status(200)
                        .version(rama::http::Version::HTTP_2)
                        .body(())
                        .unwrap();
                    let mut sending = respond.send_response(response, false).unwrap();
                    let mut offset = 0;
                    while offset < bytes.len() {
                        sending.reserve_capacity((bytes.len() - offset).min(16_384));
                        let capacity = std::future::poll_fn(|cx| sending.poll_capacity(cx))
                            .await
                            .unwrap()
                            .unwrap();
                        if capacity == 0 {
                            continue;
                        }
                        let end = (offset + capacity.min(16_384)).min(bytes.len());
                        sending
                            .send_data(bytes.slice(offset..end), complete && end == bytes.len())
                            .unwrap();
                        offset = end;
                    }
                    // This is an actual receiver hold, not a synthesized client
                    // result. Tests assert the exact prefix that really arrived.
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    driver.abort();
                    let _ = driver.await;
                    drop(sending);
                });
                while connections.try_join_next().is_some() {}
            }
        });
        Self {
            address,
            bodies,
            task,
        }
    }
    pub fn bodies(&self) -> Vec<Vec<u8>> {
        self.bodies.lock().unwrap().clone()
    }
    pub fn url(&self) -> String {
        format!("https://{HOST}:{}/echo", self.address.port())
    }
    pub fn rule(&self) -> DestinationRule {
        DestinationRule {
            scheme: Scheme::Https,
            host: HOST.to_owned(),
            port: self.address.port(),
            path: PathRule {
                kind: PathKind::Prefix,
                value: "/".into(),
            },
            resolved_addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        }
    }
}
impl Drop for H2Receiver {
    fn drop(&mut self) {
        self.task.abort();
    }
}
