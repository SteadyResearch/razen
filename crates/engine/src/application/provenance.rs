//! Prepared raw captures are read offline. This module never runs Cargo, a compiler, a VM, or a network client.
use crate::domain::decisions::DependencyName;
use crate::domain::decisions::DependencySelection;
use crate::{
    adapters::{
        evidence_store::EvidenceStore,
        ledger::{Ledger, RegisteredTool},
    },
    application::{
        admission::{PreparedCall, TrustedBinding},
        effect_meter::EffectMeter,
        measurements::{self, Measurements},
        profile::LoadedProfile,
        proof_host::ProofHost,
    },
    domain::{
        authority::{Effect, RetryClass, ToolDescriptor},
        decisions::{
            ArtifactDigest, ArtifactHash, DecisionEvidence, DecisionRecord, DecisionStatus,
            DependencyRecord, DependencyVersion, DigestAlgorithm, MinimumRust, nonzero,
            public_license_metadata, safe_text,
        },
        evidence::{EvidenceRef, MAX_BODY_BYTES, RedactionStatus},
        proofs::{IsolationStatus, Run, RunEnvironment, VersionPin},
        validation::{bounded_text, bounded_vec},
        values::{
            AuditTime, CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage,
            WireInt, non_null_optional,
        },
    },
    protocol::error::{ErrorCode, ProofError, ProofResult},
};
use rustix::fs::{self, OFlags};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256, Sha512};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::Read,
    os::unix::fs::MetadataExt,
    path::{Component, Path},
    sync::Arc,
};
const INPUTS: &str = "target/r0-evidence/preparation/provenance/inputs.json";
const TOOL: &str = "proof.provenance.capture";
const MAX_CAPTURE: usize = 16 * 1024 * 1024;
#[track_caller]
fn invalid() -> ProofError {
    eprintln!(
        "{{\"component\":\"provenance\",\"validation_line\":{}}}",
        std::panic::Location::caller().line()
    );
    ProofError::new(
        ErrorCode::IntegrityError,
        "Prepared dependency source, graph, measurement, or provenance binding is inconsistent",
    )
}
fn missing() -> ProofError {
    ProofError::new(
        ErrorCode::ProviderUnavailable,
        "Required prepared authoritative dependency or guest license capture is unavailable",
    )
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StableSourceObservation {
    pub name: DependencyName,
    #[serde(deserialize_with = "bounded_text")]
    pub source_url: String,
    pub checked_at: AuditTime,
    pub latest_stable_observed: DependencyVersion,
    pub selected_version: DependencyVersion,
    pub checksum: Digest,
    #[serde(deserialize_with = "crate::domain::validation::text_limit::<_,2048>")]
    pub license_expression: String,
    pub minimum_rust: MinimumRust,
    pub yanked: bool,
    pub prerelease: bool,
}
pub fn verify_dependency_source(record: &DependencyRecord, bytes: &[u8]) -> ProofResult<()> {
    if bytes.len() > 64 * 1024 {
        return Err(invalid());
    }
    record.validate()?;
    require_current_selection(record, DependencyKind::Direct)?;
    let source: StableSourceObservation = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let expected = ArtifactDigest::PublishedObserved {
        algorithm: DigestAlgorithm::Sha256,
        digest: ArtifactHash::Sha256(source.checksum),
    };
    if source.name != record.name
        || source.source_url != record.source_url
        || source.checked_at != record.checked_at
        || source.latest_stable_observed != record.latest_stable_observed
        || source.selected_version != record.selected_version
        || source.license_expression != record.license_expression
        || source.minimum_rust != record.minimum_rust
        || source.yanked
        || source.prerelease
        || record.artifact_digest != expected
    {
        return Err(invalid());
    }
    Ok(())
}
pub fn verify_download(record: &DependencyRecord, bytes: &[u8]) -> ProofResult<DependencyRecord> {
    record.validate()?;
    let (algorithm, digest) = record.artifact_digest.parts();
    let matches = match digest {
        ArtifactHash::Sha256(expected) => Digest::of(bytes) == *expected,
        ArtifactHash::Sha512(expected) => expected.matches_sha512(&Sha512::digest(bytes).into()),
    };
    if !matches {
        return Err(invalid());
    }
    let mut verified = record.clone();
    verified.artifact_digest = ArtifactDigest::DownloadedVerified {
        algorithm,
        digest: digest.clone(),
    };
    Ok(verified)
}
pub fn validate_measurements(value: &Measurements, profile: &LoadedProfile) -> ProofResult<()> {
    let config = &profile.config().measurement;
    for value in [
        value.warmup_exchanges,
        value.sample_body_bytes,
        value.direct_receiver_count,
        value.proxy_receiver_count,
        value.rss_kib_before,
        value.rss_kib_after,
        value.max_sampled_rss_kib,
    ] {
        WireInt::new(value)?;
    }
    if value.profile_sha256 != profile.sha256()
        || !nonzero(value.fixture_sha256)
        || value.context_source != "run.environment"
        || !safe_text(&value.method, 2048)
        || value.warmup_exchanges != config.latency_warmup_exchanges.get()
        || value.sample_body_bytes != config.sample_body_bytes.get()
        || value.direct_warmup.len() != config.latency_warmup_exchanges.get() as usize
        || value.proxy_warmup.len() != value.direct_warmup.len()
        || value.direct_samples.len() != config.latency_sample_exchanges.get() as usize
        || value.proxy_samples.len() != value.direct_samples.len()
        || value.direct_us.len() != value.direct_samples.len()
        || value.proxy_us.len() != value.proxy_samples.len()
        || value.rss_kib_before == 0
        || value.rss_kib_after == 0
        || value.max_sampled_rss_kib != value.rss_kib_before.max(value.rss_kib_after)
        || value.direct_p50_us != measurements::percentile(&value.direct_us, 50)?
        || value.direct_p95_us != measurements::percentile(&value.direct_us, 95)?
        || value.proxy_p50_us != measurements::percentile(&value.proxy_us, 50)?
        || value.proxy_p95_us != measurements::percentile(&value.proxy_us, 95)?
    {
        return Err(invalid());
    }
    let mut identities = BTreeSet::new();
    let mut prior = None;
    let mut body = None;
    for (direct, proxy) in value
        .direct_warmup
        .iter()
        .zip(&value.proxy_warmup)
        .chain(value.direct_samples.iter().zip(&value.proxy_samples))
    {
        for sample in [direct, proxy] {
            for value in [
                sample.body_bytes,
                sample.elapsed_us,
                sample.receiver_before,
                sample.receiver_after,
                sample.receiver_sequence,
            ] {
                WireInt::new(value)?;
            }
            if sample.body_bytes != value.sample_body_bytes
                || !nonzero(sample.body_sha256)
                || sample.receiver_after.checked_sub(sample.receiver_before) != Some(1)
                || sample.receiver_sequence != sample.receiver_after
                || prior.is_some_and(|v| v != sample.receiver_before)
                || body.is_some_and(|digest| digest != sample.body_sha256)
                || !identities.insert(sample.invocation_id)
                || !identities.insert(sample.result_artifact_id)
            {
                return Err(invalid());
            }
            prior = Some(sample.receiver_after);
            body = Some(sample.body_sha256);
        }
    }
    for (warm, samples, times, count) in [
        (
            &value.direct_warmup,
            &value.direct_samples,
            &value.direct_us,
            value.direct_receiver_count,
        ),
        (
            &value.proxy_warmup,
            &value.proxy_samples,
            &value.proxy_us,
            value.proxy_receiver_count,
        ),
    ] {
        if count != (warm.len() + samples.len()) as u64
            || samples
                .iter()
                .zip(times)
                .any(|(sample, time)| sample.elapsed_us != *time)
        {
            return Err(invalid());
        }
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    #[serde(deserialize_with = "bounded_text")]
    pub path: String,
    pub sha256: Digest,
}
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Workspace {
    Host,
    Components,
    Linux,
}
impl Workspace {
    fn lock(self) -> &'static str {
        match self {
            Self::Host => "Cargo.lock",
            Self::Components => "fixtures/components/Cargo.lock",
            Self::Linux => "fixtures/linux-runner/Cargo.lock",
        }
    }
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceCapture {
    workspace: Workspace,
    metadata: SourceFile,
    lockfile_sha256: Digest,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryCapture {
    name: CatalogId,
    selected_version: DependencyVersion,
    checked_at: AuditTime,
    #[serde(deserialize_with = "bounded_text")]
    crate_url: String,
    crate_capture: SourceFile,
    #[serde(default, deserialize_with = "non_null_optional")]
    archive: Option<SourceFile>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestPackageCapture {
    name: DependencyName,
    version: DependencyVersion,
    #[serde(deserialize_with = "bounded_text")]
    architecture: String,
    #[serde(deserialize_with = "bounded_text")]
    source_url: String,
    checked_at: AuditTime,
    latest_stable_observed: DependencyVersion,
    copyright: SourceFile,
    policy: SourceFile,
    metadata: SourceFile,
    facts: SourceFile,
    #[serde(default, deserialize_with = "non_null_optional")]
    archive: Option<SourceFile>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Inputs {
    schema_version: ContractVersion,
    checked_at: AuditTime,
    #[serde(deserialize_with = "bounded_vec")]
    workspaces: Vec<WorkspaceCapture>,
    #[serde(deserialize_with = "capture_vec")]
    registry_observations: Vec<RegistryCapture>,
    rust_observation: SourceFile,
    isolation_observation: SourceFile,
    guest_packages: SourceFile,
    #[serde(deserialize_with = "capture_vec")]
    guest_package_observations: Vec<GuestPackageCapture>,
    #[serde(deserialize_with = "bounded_vec")]
    decisions: Vec<DecisionRecord>,
    #[serde(deserialize_with = "bounded_vec")]
    approved_exceptions: Vec<SourceFile>,
}
fn capture_vec<'de, D: serde::Deserializer<'de>, T: Deserialize<'de>>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    crate::domain::evidence::bounded_vec::<D, T, 2048>(d)
}
#[derive(Debug, Deserialize)]
struct CargoMetadata {
    packages: Vec<CargoPackage>,
    workspace_members: Vec<String>,
    resolve: CargoResolve,
}
#[derive(Debug, Serialize, Deserialize)]
struct CargoPackage {
    id: String,
    name: String,
    version: String,
    license: Option<String>,
    rust_version: Option<String>,
    source: Option<String>,
    dependencies: Vec<CargoDependency>,
    features: BTreeMap<String, Vec<String>>,
    targets: Vec<CargoTarget>,
}
#[derive(Debug, Serialize, Deserialize)]
struct CargoTarget {
    name: String,
    kind: Vec<String>,
}
#[derive(Debug, Serialize, Deserialize)]
struct CargoDependency {
    name: String,
    req: String,
    kind: Option<String>,
    rename: Option<String>,
    #[serde(default)]
    optional: bool,
    target: Option<String>,
    #[serde(deserialize_with = "bounded_vec")]
    features: Vec<String>,
    uses_default_features: bool,
}
#[derive(Debug, Serialize, Deserialize)]
struct CargoResolve {
    nodes: Vec<CargoNode>,
}
#[derive(Debug, Serialize, Deserialize)]
struct CargoNode {
    id: String,
    dependencies: Vec<String>,
    features: Vec<String>,
    deps: Vec<CargoResolved>,
}
#[derive(Debug, Serialize, Deserialize)]
struct CargoResolved {
    name: String,
    pkg: String,
    dep_kinds: Vec<CargoDepKind>,
}
#[derive(Debug, Eq, PartialEq, Serialize, Deserialize)]
struct CargoDepKind {
    kind: Option<String>,
    target: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolvedEdge {
    alias: String,
    package: (CatalogId, VersionPin),
    dep_kinds: Vec<CargoDepKind>,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    Direct,
    Transitive,
    Tool,
    GuestImage,
    GuestPackage,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependencyEntry {
    #[serde(
        skip_serializing_if = "Option::is_none",
        default,
        deserialize_with = "non_null_optional"
    )]
    pub workspace: Option<Workspace>,
    pub kind: DependencyKind,
    pub record: DependencyRecord,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceEvidence {
    pub role: CatalogId,
    pub raw_sha256: Digest,
    pub public_sha256: Digest,
    pub public_length_bytes: WireInt,
    #[serde(deserialize_with = "bounded_vec")]
    pub evidence_refs: Vec<EvidenceRef>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementEvidence {
    pub project_id: EntityId,
    pub reference: EvidenceRef,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceReport {
    pub schema_version: ContractVersion,
    pub run_id: EntityId,
    pub profile_sha256: Digest,
    pub checked_at: AuditTime,
    pub environment: RunEnvironment,
    #[serde(deserialize_with = "capture_vec")]
    pub dependencies: Vec<DependencyEntry>,
    #[serde(deserialize_with = "capture_vec")]
    pub sources: Vec<SourceEvidence>,
    #[serde(deserialize_with = "bounded_vec")]
    pub decisions: Vec<DecisionRecord>,
    #[serde(deserialize_with = "bounded_vec")]
    pub measurements: Vec<MeasurementEvidence>,
    #[serde(deserialize_with = "bounded_vec")]
    pub findings: Vec<String>,
    pub research_sha256: Digest,
    pub rerun_sha256: Digest,
}
struct Reader {
    root: File,
}
impl Reader {
    fn new(repo: &Path) -> ProofResult<Self> {
        let fd = fs::open(
            repo,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            fs::Mode::empty(),
        )
        .map_err(|_| missing())?;
        Ok(Self {
            root: File::from(fd),
        })
    }
    fn open(&self, path: &str) -> ProofResult<File> {
        if path.len() > 256
            || path.is_empty()
            || Path::new(path)
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(invalid());
        }
        let mut directory = self.root.try_clone().map_err(|_| invalid())?;
        let mut parts = Path::new(path).components().peekable();
        while let Some(Component::Normal(name)) = parts.next() {
            let last = parts.peek().is_none();
            let flags = OFlags::RDONLY
                | OFlags::NOFOLLOW
                | OFlags::CLOEXEC
                | OFlags::NONBLOCK
                | if last {
                    OFlags::empty()
                } else {
                    OFlags::DIRECTORY
                };
            let fd =
                fs::openat(&directory, name, flags, fs::Mode::empty()).map_err(|_| missing())?;
            let file = File::from(fd);
            let meta = file.metadata().map_err(|_| invalid())?;
            if meta.mode() & 0o022 != 0
                || (meta.uid() != rustix::process::geteuid().as_raw() && meta.uid() != 0)
                || (!last && !meta.is_dir())
                || (last && (!meta.is_file() || meta.nlink() != 1))
            {
                return Err(invalid());
            }
            directory = file;
        }
        Ok(directory)
    }
    fn read(&self, path: &str, max: usize) -> ProofResult<Vec<u8>> {
        let mut file = self.open(path)?;
        let before = file.metadata().map_err(|_| invalid())?;
        if before.len() > max as u64 {
            return Err(invalid());
        }
        let mut bytes = Vec::with_capacity(before.len() as usize);
        Read::by_ref(&mut file)
            .take(max as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        let after = file.metadata().map_err(|_| invalid())?;
        let named = self.open(path)?.metadata().map_err(|_| invalid())?;
        if bytes.len() > max
            || !crate::adapters::native_files::same_file(&before, &after)
            || !crate::adapters::native_files::same_file(&before, &named)
        {
            return Err(invalid());
        }
        Ok(bytes)
    }
    fn capture(&self, source: &SourceFile) -> ProofResult<Vec<u8>> {
        if !nonzero(source.sha256) {
            return Err(invalid());
        }
        let bytes = self.read(&source.path, MAX_CAPTURE)?;
        if Digest::of(&bytes) != source.sha256 {
            return Err(invalid());
        }
        Ok(bytes)
    }
    fn hash(&self, path: &str, algorithm: DigestAlgorithm) -> ProofResult<ArtifactHash> {
        enum State {
            Sha256(Sha256),
            Sha512(Sha512),
        }
        let mut file = self.open(path)?;
        let before = file.metadata().map_err(|_| invalid())?;
        if before.len() > 4 * 1024 * 1024 * 1024 {
            return Err(invalid());
        }
        let mut state = match algorithm {
            DigestAlgorithm::Sha256 => State::Sha256(Sha256::new()),
            DigestAlgorithm::Sha512 => State::Sha512(Sha512::new()),
        };
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        let mut buffer = [0u8; 65536];
        let mut length = 0u64;
        loop {
            if std::time::Instant::now() >= deadline {
                return Err(ProofError::new(
                    ErrorCode::Timeout,
                    "Prepared source hashing exceeded its finite deadline",
                ));
            }
            let count = file.read(&mut buffer).map_err(|_| invalid())?;
            if count == 0 {
                break;
            }
            length = length.checked_add(count as u64).ok_or_else(invalid)?;
            if length > before.len() {
                return Err(invalid());
            }
            match &mut state {
                State::Sha256(hash) => hash.update(&buffer[..count]),
                State::Sha512(hash) => hash.update(&buffer[..count]),
            }
        }
        let after = file.metadata().map_err(|_| invalid())?;
        let named = self.open(path)?.metadata().map_err(|_| invalid())?;
        if length != before.len()
            || !crate::adapters::native_files::same_file(&before, &after)
            || !crate::adapters::native_files::same_file(&before, &named)
        {
            return Err(invalid());
        }
        Ok(match state {
            State::Sha256(hash) => {
                ArtifactHash::Sha256(Digest::from_sha256(hash.finalize().into()))
            }
            State::Sha512(hash) => ArtifactHash::Sha512(
                crate::domain::proofs::ImageDigest::from_sha512(hash.finalize().into()),
            ),
        })
    }
}

pub fn registered_tool(provider_digest: Digest) -> ProofResult<RegisteredTool> {
    Ok(RegisteredTool {
        provider_digest,
        descriptor: ToolDescriptor {
            tool_id: CatalogId::parse(TOOL)?,
            version: ContractVersion::V0_1_0,
            input_contract: CatalogId::parse("proof.provenance.input")?,
            output_contract: CatalogId::parse("proof.provenance.output")?,
            effect: Effect::LocalWrite,
            permissions: vec![CatalogId::parse(TOOL)?],
            retry_class: RetryClass::NonRetryable,
            limits: Usage {
                units: WireInt::new(1)?,
                bytes: WireInt::new(2 * MAX_BODY_BYTES as u64)?,
                cpu_us: WireInt::new(30_000_000)?,
                elapsed_us: WireInt::new(30_000_000)?,
            },
        },
    })
}
fn source_binding(host: &ProofHost) -> ProofResult<Arc<TrustedBinding>> {
    let tool = registered_tool(host.provider_digest)?;
    match host.ledger.find_tool(&tool.descriptor.tool_id)? {
        Some(existing) if existing != tool => return Err(invalid()),
        Some(_) => {}
        None => host.ledger.insert_tool(&tool)?,
    }
    let mut spec = host.local_spec();
    spec.allowed_tools = vec![CatalogId::parse(TOOL)?];
    spec.permissions = vec![CatalogId::parse(TOOL)?];
    Ok(Arc::new(host.admission.bind(spec)?))
}
fn store_chunk(
    host: &ProofHost,
    binding: &Arc<TrustedBinding>,
    bytes: &[u8],
) -> ProofResult<EvidenceRef> {
    let origin = EntityId::new();
    let input = serde_json::to_vec(&json!({"sha256":Digest::of(bytes),"length_bytes":bytes.len()}))
        .map_err(|_| invalid())?;
    let artifact = host.evidence.write_artifact(
        host.project.project_id,
        CatalogId::parse("provenance-source-input")?,
        origin,
        &input,
        RedactionStatus::Original,
    )?;
    let call = PreparedCall {
        invocation_id: origin,
        call_id: EntityId::new(),
        tool_id: CatalogId::parse(TOOL)?,
        tool_version: ContractVersion::V0_1_0,
        input_ref: artifact.artifact_id,
        input_sha256: artifact.sha256,
        input_revision: WireInt::ZERO,
        source_control_revision: binding.control_revision(),
        requested: registered_tool(host.provider_digest)?.descriptor.limits,
    };
    host.admission.propose(binding, &call)?;
    host.approve(binding, &call)?;
    host.admission.reserve(binding, &call)?;
    let permit = host.admission.begin_effect(binding, origin)?;
    let mut meter = EffectMeter::start();
    meter.dispatched = true;
    host.admission.recheck_effect(binding, &permit)?;
    let result = host.evidence.write_artifact(
        host.project.project_id,
        CatalogId::parse("provenance-source")?,
        origin,
        bytes,
        RedactionStatus::Redacted,
    );
    meter.add_bytes(input.len())?;
    meter.add_bytes(bytes.len())?;
    match result {
        Ok(output) => {
            host.admission
                .complete(binding, permit, meter.usage()?, Some(output.artifact_id))?;
            Ok(EvidenceRef::Artifact {
                artifact_id: output.artifact_id,
                sha256: output.sha256,
                range: None,
            })
        }
        Err(error) => {
            host.admission.outcome_unknown(
                binding,
                permit,
                meter.usage()?,
                ProofError::new(
                    ErrorCode::OutcomeUnknown,
                    "Provenance source publication requires reconciliation",
                ),
            )?;
            Err(error)
        }
    }
}
fn retain(
    host: &ProofHost,
    binding: &Arc<TrustedBinding>,
    role: &str,
    raw_sha256: Digest,
    public: &Value,
) -> ProofResult<SourceEvidence> {
    public_value(public, 0)?;
    let bytes = serde_json::to_vec(public).map_err(|_| invalid())?;
    retain_bytes(host, binding, role, raw_sha256, &bytes)
}
fn retain_bytes(
    host: &ProofHost,
    binding: &Arc<TrustedBinding>,
    role: &str,
    raw_sha256: Digest,
    bytes: &[u8],
) -> ProofResult<SourceEvidence> {
    if bytes.is_empty() || bytes.len() > MAX_CAPTURE {
        return Err(invalid());
    }
    let mut refs = Vec::with_capacity(bytes.len().div_ceil(MAX_BODY_BYTES));
    for chunk in bytes.chunks(MAX_BODY_BYTES) {
        refs.push(store_chunk(host, binding, chunk)?);
    }
    Ok(SourceEvidence {
        role: CatalogId::parse(role)?,
        raw_sha256,
        public_sha256: Digest::of(bytes),
        public_length_bytes: WireInt::new(bytes.len() as u64)?,
        evidence_refs: refs,
    })
}
fn text<'a>(value: &'a Value, key: &str) -> ProofResult<&'a str> {
    value.get(key).and_then(Value::as_str).ok_or_else(invalid)
}
fn time(value: &Value, key: &str) -> ProofResult<AuditTime> {
    Ok(AuditTime::parse(text(value, key)?)?)
}
fn msrv(value: Option<&Value>) -> ProofResult<MinimumRust> {
    match value {
        Some(Value::String(version)) => Ok(MinimumRust::Declared {
            version: VersionPin::parse(version)?,
        }),
        Some(Value::Null) => Ok(MinimumRust::Undeclared),
        _ => Err(invalid()),
    }
}
fn license(value: Option<&Value>) -> ProofResult<String> {
    match value {
        Some(Value::String(value)) if public_license_metadata(value, 2048) => Ok(value.clone()),
        Some(Value::Null) => Ok("NOASSERTION".to_owned()),
        _ => Err(invalid()),
    }
}
fn published(algorithm: DigestAlgorithm, digest: ArtifactHash) -> ArtifactDigest {
    ArtifactDigest::PublishedObserved { algorithm, digest }
}
fn before_run(time: AuditTime, run: &Run) -> ProofResult<()> {
    if time > run.started_at {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Debug)]
struct LockedPackage {
    name: CatalogId,
    version: VersionPin,
    checksum: Option<Digest>,
    registry: bool,
}
fn lock_packages(bytes: &[u8]) -> ProofResult<Vec<LockedPackage>> {
    let text = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    let document = toml_edit::Document::parse(text).map_err(|_| invalid())?;
    if !matches!(
        document
            .get("version")
            .and_then(toml_edit::Item::as_integer),
        Some(3 | 4)
    ) {
        return Err(invalid());
    }
    let packages = document
        .get("package")
        .and_then(toml_edit::Item::as_array_of_tables)
        .ok_or_else(invalid)?;
    if packages.is_empty() || packages.len() > 2048 {
        return Err(invalid());
    }
    let mut records = Vec::with_capacity(packages.len());
    for package in packages {
        let field = |key| {
            package
                .get(key)
                .and_then(toml_edit::Item::as_str)
                .ok_or_else(invalid)
        };
        let name = CatalogId::parse(field("name")?)?;
        let version = VersionPin::parse(field("version")?)?;
        let registry = match package.get("source") {
            None => false,
            Some(item)
                if item.as_str()
                    == Some("registry+https://github.com/rust-lang/crates.io-index") =>
            {
                true
            }
            _ => return Err(invalid()),
        };
        let checksum = package
            .get("checksum")
            .map(|item| -> ProofResult<Digest> {
                Ok(Digest::parse(item.as_str().ok_or_else(invalid)?)?)
            })
            .transpose()?;
        if registry != checksum.is_some() || checksum.is_some_and(|digest| !nonzero(digest)) {
            return Err(invalid());
        }
        records.push(LockedPackage {
            name,
            version,
            checksum,
            registry,
        });
    }
    {
        let mut keys = BTreeSet::new();
        for record in &records {
            if !keys.insert((record.name.as_str(), record.version.as_str())) {
                return Err(invalid());
            }
        }
    }
    Ok(records)
}
#[derive(Serialize)]
struct GraphPackage<'a> {
    name: &'a str,
    version: &'a str,
    library_name: Option<&'a str>,
    checksum: Digest,
    direct: bool,
    features: &'a [String],
    feature_definitions: &'a BTreeMap<String, Vec<String>>,
    dependencies: Vec<(&'a str, &'a str)>,
    resolved: Vec<ResolvedEdge>,
    requirements: &'a [CargoDependency],
    license_expression: &'a str,
    minimum_rust: MinimumRust,
}
fn graph<'a>(
    metadata: &'a CargoMetadata,
    locked: &[LockedPackage],
) -> ProofResult<Vec<GraphPackage<'a>>> {
    if metadata.packages.len() > 2048
        || metadata.workspace_members.is_empty()
        || metadata.workspace_members.len() > 32
        || metadata.resolve.nodes.len() > 2048
    {
        return Err(invalid());
    }
    let mut ids = BTreeMap::new();
    for package in &metadata.packages {
        if ids.insert(&package.id, package).is_some() {
            return Err(invalid());
        }
    }
    let mut direct = BTreeSet::new();
    let mut node_ids = BTreeSet::new();
    for node in &metadata.resolve.nodes {
        if !ids.contains_key(&node.id)
            || !node_ids.insert(&node.id)
            || node.features.len() > 256
            || node.dependencies.len() > 2048
        {
            return Err(invalid());
        }
        for id in &node.dependencies {
            if !ids.contains_key(id) {
                return Err(invalid());
            }
            if metadata.workspace_members.contains(&node.id) {
                direct.insert(id);
            }
        }
    }
    if metadata
        .workspace_members
        .iter()
        .any(|id| !ids.contains_key(id))
        || node_ids.len() != ids.len()
        || metadata
            .workspace_members
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != metadata.workspace_members.len()
    {
        return Err(invalid());
    }
    let mut result = Vec::new();
    for package in &metadata.packages {
        if metadata.workspace_members.contains(&package.id) {
            if package.source.is_some() {
                return Err(invalid());
            }
            continue;
        }
        if package.source.as_deref()
            != Some("registry+https://github.com/rust-lang/crates.io-index")
        {
            return Err(invalid());
        }
        let lock = locked
            .iter()
            .find(|record| {
                record.name.as_str() == package.name
                    && record.version.as_str() == package.version
                    && record.registry
            })
            .ok_or_else(invalid)?;
        let node = metadata
            .resolve
            .nodes
            .iter()
            .find(|node| node.id == package.id)
            .ok_or_else(invalid)?;
        if node.features.iter().any(|feature| !safe_text(feature, 256)) {
            return Err(invalid());
        }
        let dependencies = node
            .dependencies
            .iter()
            .map(|id| {
                let target = ids.get(id).ok_or_else(invalid)?;
                Ok((target.name.as_str(), target.version.as_str()))
            })
            .collect::<ProofResult<Vec<_>>>()?;
        let resolved = resolved_edges(metadata, node)?;
        let minimum_rust = match package.rust_version.as_deref() {
            Some(version) => MinimumRust::Declared {
                version: VersionPin::parse(version)?,
            },
            None => MinimumRust::Undeclared,
        };
        result.push(GraphPackage {
            name: &package.name,
            version: &package.version,
            library_name: library_name(package)?,
            checksum: lock.checksum.ok_or_else(invalid)?,
            direct: direct.contains(&package.id),
            features: &node.features,
            feature_definitions: &package.features,
            dependencies,
            resolved,
            requirements: &package.dependencies,
            license_expression: package.license.as_deref().unwrap_or("NOASSERTION"),
            minimum_rust,
        });
    }
    Ok(result)
}
fn resolved_edges(metadata: &CargoMetadata, node: &CargoNode) -> ProofResult<Vec<ResolvedEdge>> {
    let mut ids = BTreeSet::new();
    let mut edges = Vec::new();
    for edge in &node.deps {
        let target = metadata
            .packages
            .iter()
            .find(|p| p.id == edge.pkg)
            .ok_or_else(invalid)?;
        ids.insert(&edge.pkg);
        edges.push(ResolvedEdge {
            alias: edge.name.clone(),
            package: (
                CatalogId::parse(&target.name)?,
                VersionPin::parse(&target.version)?,
            ),
            dep_kinds: edge
                .dep_kinds
                .iter()
                .map(|kind| CargoDepKind {
                    kind: kind.kind.clone(),
                    target: kind.target.clone(),
                })
                .collect(),
        });
    }
    if ids != node.dependencies.iter().collect() {
        return Err(invalid());
    }
    Ok(edges)
}
fn library_name(package: &CargoPackage) -> ProofResult<Option<&str>> {
    let mut libraries = package.targets.iter().filter(|target| {
        target.kind.iter().any(|kind| {
            matches!(
                kind.as_str(),
                "lib" | "rlib" | "dylib" | "cdylib" | "staticlib" | "proc-macro"
            )
        })
    });
    let name = libraries.next().map(|target| target.name.as_str());
    if libraries.next().is_some() || name.is_some_and(|name| !cargo_feature_name(name)) {
        return Err(invalid());
    }
    Ok(name)
}
fn graph_value(
    metadata: &CargoMetadata,
    packages: &[GraphPackage<'_>],
    workspace: Workspace,
    lockfile_sha256: Digest,
) -> ProofResult<Value> {
    let members=metadata.workspace_members.iter().map(|id|{
  let package=metadata.packages.iter().find(|package|package.id==*id).ok_or_else(invalid)?;
  let node=metadata.resolve.nodes.iter().find(|node|node.id==*id).ok_or_else(invalid)?;
  let dependencies=node.dependencies.iter().map(|id|{let target=metadata.packages.iter().find(|package|package.id==*id).ok_or_else(invalid)?;Ok((&target.name,&target.version))}).collect::<ProofResult<Vec<_>>>()?;
  Ok(json!({"name":package.name,"version":package.version,"library_name":library_name(package)?,"dependencies":dependencies,"resolved":resolved_edges(metadata,node)?,"requirements":package.dependencies,"features":node.features,"feature_definitions":package.features}))
 }).collect::<ProofResult<Vec<_>>>()?;
    let value = json!({"workspace":workspace,"lockfile_sha256":lockfile_sha256,"packages":packages,"members":members});
    validate_graph(&serde_json::from_value(value.clone()).map_err(|_| invalid())?)?;
    Ok(value)
}
/// Read-only readiness for explicit doctor/prepare workflows. Normal proof
/// collection uses these same parsers; this never creates evidence or a Run.
pub fn preflight(
    repo: &Path,
    environment: &RunEnvironment,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    if environment.isolation_status != IsolationStatus::Prepared {
        return Err(missing());
    }
    let reader = Reader::new(repo)?;
    let inputs: Inputs =
        serde_json::from_slice(&reader.read(INPUTS, MAX_CAPTURE)?).map_err(|_| invalid())?;
    if inputs.checked_at > AuditTime::now() {
        return Err(invalid());
    }
    if inputs.schema_version != ContractVersion::V0_1_0
        || inputs.workspaces.len() != 3
        || inputs.registry_observations.is_empty()
        || inputs.guest_package_observations.is_empty()
    {
        return Err(missing());
    }
    let mut facts = BTreeMap::new();
    for capture in &inputs.registry_observations {
        if capture.checked_at > inputs.checked_at {
            return Err(invalid());
        }
        let source = registry_observation(capture, &reader.capture(&capture.crate_capture)?)?;
        if let Some(archive) = &capture.archive
            && (archive.sha256 != source.checksum
                || reader.hash(&archive.path, DigestAlgorithm::Sha256)?
                    != ArtifactHash::Sha256(source.checksum))
        {
            return Err(invalid());
        }
        if facts
            .insert(
                (
                    source.name.as_str().to_owned(),
                    source.selected_version.as_str().to_owned(),
                ),
                (source, capture),
            )
            .is_some()
        {
            return Err(invalid());
        }
    }
    let mut seen = BTreeSet::new();
    let mut resolved = BTreeSet::new();
    for capture in &inputs.workspaces {
        let lock = reader.read(capture.workspace.lock(), MAX_CAPTURE)?;
        let digest = Digest::of(&lock);
        if !seen.insert(capture.workspace) || digest != capture.lockfile_sha256 {
            return Err(invalid());
        }
        let expected = match capture.workspace {
            Workspace::Host => Some(environment.lockfile_sha256),
            Workspace::Components => Some(environment.component_lockfile_sha256),
            Workspace::Linux => None,
        };
        if expected.is_some_and(|expected| expected != digest) {
            return Err(invalid());
        }
        let metadata: CargoMetadata =
            serde_json::from_slice(&reader.capture(&capture.metadata)?).map_err(|_| invalid())?;
        let packages = graph(&metadata, &lock_packages(&lock)?)?;
        public_value(
            &graph_value(&metadata, &packages, capture.workspace, digest)?,
            0,
        )?;
        for package in packages {
            let (source, source_capture) = facts
                .get(&(package.name.to_owned(), package.version.to_owned()))
                .ok_or_else(missing)?;
            if source.checksum != package.checksum
                || source.license_expression != package.license_expression
                || !compatible_msrv_sources(&source.minimum_rust, &package.minimum_rust)
            {
                return Err(invalid());
            }
            if package.direct {
                preflight_selection(
                    &reader,
                    &inputs,
                    &dependency_selection(
                        package.name,
                        package.version,
                        source.latest_stable_observed.as_str(),
                        source_capture.crate_capture.sha256,
                        source_capture.crate_capture.sha256,
                    )?,
                )?;
            }
            resolved.insert((package.name.to_owned(), package.version.to_owned()));
        }
    }
    let build_bytes = reader.read("target/proof-components/build-manifest.json", 1024 * 1024)?;
    let build: Value = serde_json::from_slice(&build_bytes).map_err(|_| invalid())?;
    verify_component_environment(&build, environment, Digest::of(&build_bytes))?;
    verify_component_files(&reader, &build)?;
    public_value(&build, 0)?;
    for (name, key) in [("wasmtime", "wasmtime"), ("wit-bindgen", "wit_bindgen")] {
        if !resolved.contains(&(name.to_owned(), text(&build, key)?.to_owned())) {
            return Err(invalid());
        }
    }
    let prepared: Value =
        serde_json::from_slice(&reader.read("target/r0-guest/prepared.json", 1024 * 1024)?)
            .map_err(|_| invalid())?;
    verify_prepared_environment(&prepared, profile.sha256(), environment)?;
    verify_prepared_files(repo, &reader, &prepared)?;
    let manifest = reader.capture(&inputs.guest_packages)?;
    if Some(Digest::of(&manifest)) != environment.guest_package_manifest_sha256 {
        return Err(invalid());
    }
    let manifest = std::str::from_utf8(&manifest).map_err(|_| invalid())?;
    if manifest.lines().count() != inputs.guest_package_observations.len() {
        return Err(invalid());
    }
    let mut packages = BTreeSet::new();
    for line in manifest.lines() {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 3 || !packages.insert((fields[0], fields[1], fields[2])) {
            return Err(invalid());
        }
    }
    let mut captures = BTreeSet::new();
    for capture in &inputs.guest_package_observations {
        if !captures.insert((
            capture.name.as_str(),
            capture.version.as_str(),
            capture.architecture.as_str(),
        )) || !packages.contains(&(
            capture.name.as_str(),
            capture.version.as_str(),
            capture.architecture.as_str(),
        )) || capture.checked_at > inputs.checked_at
            || !debian_source_url(&capture.source_url)
        {
            return Err(invalid());
        }
        let copyright = reader.capture(&capture.copyright)?;
        let policy = reader.capture(&capture.policy)?;
        let metadata = reader.capture(&capture.metadata)?;
        for raw in [&copyright, &policy, &metadata] {
            let public = public_document(std::str::from_utf8(raw).map_err(|_| invalid())?);
            public_value(&json!(public), 0)?;
        }
        let fact: GuestPackageFacts =
            serde_json::from_slice(&reader.capture(&capture.facts)?).map_err(|_| invalid())?;
        fact.validate()?;
        if fact.checked_at != capture.checked_at
            || fact.name != capture.name
            || fact.version != capture.version
            || fact.architecture != capture.architecture
            || fact.candidate != capture.latest_stable_observed
            || fact.copyright_raw_sha256 != capture.copyright.sha256
            || fact.policy_raw_sha256 != capture.policy.sha256
            || fact.metadata_raw_sha256 != capture.metadata.sha256
            || !packages.iter().any(|(name, version, _)| {
                *name == "python3-apt" && *version == fact.parser_version.as_str()
            })
        {
            return Err(invalid());
        }
        if let Some(archive) = &capture.archive
            && (archive.sha256 != fact.sha256
                || reader.hash(&archive.path, DigestAlgorithm::Sha256)?
                    != ArtifactHash::Sha256(fact.sha256))
        {
            return Err(invalid());
        }
        preflight_selection(
            &reader,
            &inputs,
            &dependency_selection(
                capture.name.as_str(),
                capture.version.as_str(),
                capture.latest_stable_observed.as_str(),
                capture.metadata.sha256,
                capture.policy.sha256,
            )?,
        )?;
    }
    preflight_tools(&reader, &inputs, environment)?;
    let research = reader.read("specs/001-r0-feasibility/research.md", 256 * 1024)?;
    let research = std::str::from_utf8(&research).map_err(|_| invalid())?;
    if inputs.decisions.len() != 8 {
        return Err(invalid());
    }
    let mut decisions = BTreeSet::new();
    for decision in &inputs.decisions {
        decision.validate()?;
        verify_source_decision_fields(decision, research)?;
        if ![
            "D-01", "D-02", "D-03", "D-04", "D-05", "D-06", "D-07", "D-08",
        ]
        .contains(&decision.decision_id.as_str())
            || !decisions.insert(decision.decision_id.as_str())
            || decision.reviewed_at > inputs.checked_at
        {
            return Err(invalid());
        }
    }
    public_value(&json!({"content":research}), 0)?;
    let instructions = reader.read("specs/001-r0-feasibility/quickstart.md", 256 * 1024)?;
    public_value(
        &json!({"content":std::str::from_utf8(&instructions).map_err(|_|invalid())?}),
        0,
    )?;
    Ok(())
}
fn preflight_selection(
    reader: &Reader,
    inputs: &Inputs,
    selection: &DependencySelection,
) -> ProofResult<()> {
    if selection.selected_version == selection.latest_stable_observed {
        return Ok(());
    }
    let mut found = false;
    for capture in &inputs.approved_exceptions {
        let decision: DecisionRecord =
            serde_json::from_slice(&reader.capture(capture)?).map_err(|_| invalid())?;
        if decision
            .evidence_refs
            .contains(&DecisionEvidence::DependencySelection {
                selection: selection.clone(),
            })
        {
            verify_exception_binding(&decision, selection, inputs.checked_at)?;
            if found {
                return Err(invalid());
            }
            found = true;
        }
    }
    if !found {
        return Err(missing());
    }
    Ok(())
}
fn preflight_tools(
    reader: &Reader,
    inputs: &Inputs,
    environment: &RunEnvironment,
) -> ProofResult<()> {
    let raw: Value = serde_json::from_slice(&reader.capture(&inputs.rust_observation)?)
        .map_err(|_| invalid())?;
    let rust = &raw["rust"];
    let selected = text(rust, "selected_version")?;
    let latest = text(rust, "latest_stable_version")?;
    if time(rust, "checked_at")? > inputs.checked_at
        || environment
            .dependency_versions
            .get(&CatalogId::parse("rust")?)
            .map(VersionPin::as_str)
            != Some(selected)
    {
        return Err(invalid());
    }
    let source = rust["source_urls"]
        .as_array()
        .and_then(|urls| urls.first())
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    if !crate::domain::decisions::source_url(source)
        || !nonzero(Digest::parse(text(
            &rust["published_packages"]["rust"]["aarch64-apple-darwin"],
            "hash",
        )?)?)
        || !public_license_metadata(text(&rust["license"], "primary")?, 2048)
    {
        return Err(invalid());
    }
    text(rust, "manifest_date")?;
    preflight_selection(
        reader,
        inputs,
        &dependency_selection(
            "rust",
            selected,
            latest,
            inputs.rust_observation.sha256,
            inputs.rust_observation.sha256,
        )?,
    )?;
    let isolation: Value = serde_json::from_slice(&reader.capture(&inputs.isolation_observation)?)
        .map_err(|_| invalid())?;
    let date = jiff::civil::Date::strptime("%Y-%m-%d", text(&isolation, "observed_on")?)
        .map_err(|_| invalid())?;
    if date
        > jiff::civil::Date::strptime("%Y-%m-%d", &inputs.checked_at.to_string()[..10])
            .map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    for name in ["lima", "bubblewrap"] {
        let tool = &isolation[name];
        let observed = &tool["latest_stable_observation"];
        let selected = text(tool, "selected_version")?;
        let latest = text(observed, "tag_name")?
            .strip_prefix('v')
            .ok_or_else(invalid)?;
        if observed["prerelease"] != false
            || observed["draft"] != false
            || !crate::domain::decisions::source_url(text(observed, "source_url")?)
            || environment
                .dependency_versions
                .get(&CatalogId::parse(name)?)
                .map(VersionPin::as_str)
                != Some(selected)
        {
            return Err(invalid());
        }
        let checksum = Digest::parse(
            text(&tool["asset"], "published_digest")?
                .strip_prefix("sha256:")
                .ok_or_else(invalid)?,
        )?;
        let license = if name == "lima" {
            "license"
        } else {
            "source_spdx"
        };
        if !public_license_metadata(text(&tool["license_and_notices"], license)?, 2048)
            || !nonzero(checksum)
        {
            return Err(invalid());
        }
        notice_projection(&tool["license_and_notices"], 0)?;
        if name == "lima"
            && reader.hash(
                "target/r0-tools/lima-2.3.0-Darwin-arm64.tar.gz",
                DigestAlgorithm::Sha256,
            )? != ArtifactHash::Sha256(checksum)
        {
            return Err(invalid());
        }
        preflight_selection(
            reader,
            inputs,
            &dependency_selection(
                name,
                selected,
                latest,
                inputs.isolation_observation.sha256,
                inputs.isolation_observation.sha256,
            )?,
        )?;
    }
    let debian = &isolation["debian"];
    DependencyVersion::parse(text(&debian["stable_status"], "latest_point_release")?)?;
    if text(&debian["image"], "published_digest")? != environment.image_digest.as_str()
        || reader.hash("target/r0-guest/debian.raw", DigestAlgorithm::Sha512)?
            != ArtifactHash::Sha512(environment.image_digest.clone())
        || !crate::domain::decisions::source_url(text(&debian["image"], "url")?)
        || !crate::domain::decisions::source_url(text(
            &debian["published_manifest"],
            "checksums_url",
        )?)
    {
        return Err(invalid());
    }
    notice_projection(&debian["licenses_and_notices"], 0)?;
    Ok(())
}
struct RegistryFact {
    source: StableSourceObservation,
    evidence: Vec<EvidenceRef>,
    archive: Option<ArtifactHash>,
    selection: DependencySelection,
}
fn registry_observation(
    capture: &RegistryCapture,
    bytes: &[u8],
) -> ProofResult<StableSourceObservation> {
    let expected_url = format!("https://crates.io/api/v1/crates/{}", capture.name);
    if capture.crate_url != expected_url {
        return Err(invalid());
    }
    let value: Value = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    let package = value.get("crate").ok_or_else(invalid)?;
    let mut matches = value
        .get("versions")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?
        .iter()
        .filter(|version| {
            version.get("num").and_then(Value::as_str) == Some(capture.selected_version.as_str())
        });
    let version = matches.next().ok_or_else(invalid)?;
    if matches.next().is_some()
        || text(package, "name")? != capture.name.as_str()
        || text(version, "crate")? != capture.name.as_str()
        || version.get("yanked").and_then(Value::as_bool) != Some(false)
    {
        return Err(invalid());
    }
    let latest = text(package, "max_stable_version")?;
    if !crate::domain::decisions::stable_version(latest)
        || !crate::domain::decisions::stable_version(capture.selected_version.as_str())
    {
        return Err(invalid());
    }
    let source = StableSourceObservation {
        name: DependencyName::parse(capture.name.as_str())?,
        source_url: capture.crate_url.clone(),
        checked_at: capture.checked_at,
        latest_stable_observed: DependencyVersion::parse(latest)?,
        selected_version: capture.selected_version.clone(),
        checksum: Digest::parse(text(version, "checksum")?)?,
        license_expression: license(version.get("license"))?,
        minimum_rust: msrv(version.get("rust_version"))?,
        yanked: false,
        prerelease: false,
    };
    if !nonzero(source.checksum) {
        return Err(invalid());
    }
    Ok(source)
}
fn registry_fact(
    reader: &Reader,
    capture: &RegistryCapture,
    host: &ProofHost,
    binding: &Arc<TrustedBinding>,
    run: &Run,
    sources: &mut Vec<SourceEvidence>,
) -> ProofResult<RegistryFact> {
    before_run(capture.checked_at, run)?;
    let bytes = reader.capture(&capture.crate_capture)?;
    let source = registry_observation(capture, &bytes)?;
    let archive = if let Some(archive) = &capture.archive {
        let actual = reader.hash(&archive.path, DigestAlgorithm::Sha256)?;
        if actual != ArtifactHash::Sha256(archive.sha256) || archive.sha256 != source.checksum {
            return Err(invalid());
        }
        Some(actual)
    } else {
        None
    };
    let mut public = json!({"observation":source,"crate_url":capture.crate_url,"source_raw_sha256":capture.crate_capture.sha256,
  "checked_at_basis":"immutable-source-file-capture-time"});
    if archive.is_some() {
        public.as_object_mut().ok_or_else(invalid)?.insert(
            "downloaded_archive_sha256".to_owned(),
            json!(source.checksum),
        );
    }
    let retained = retain(
        host,
        binding,
        "registry-observation",
        capture.crate_capture.sha256,
        &public,
    )?;
    let evidence = retained.evidence_refs.clone();
    sources.push(retained);
    let selection = DependencySelection {
        name: source.name.clone(),
        selected_version: source.selected_version.clone(),
        latest_stable_observed: source.latest_stable_observed.clone(),
        selected_source_sha256: capture.crate_capture.sha256,
        latest_source_sha256: capture.crate_capture.sha256,
    };
    Ok(RegistryFact {
        source,
        evidence,
        archive,
        selection,
    })
}
fn exception_for(
    reader: &Reader,
    inputs: &Inputs,
    host: &ProofHost,
    binding: &Arc<TrustedBinding>,
    selection: &DependencySelection,
    run: &Run,
) -> ProofResult<Option<EvidenceRef>> {
    let mut approved = None;
    for capture in &inputs.approved_exceptions {
        let bytes = reader.capture(capture)?;
        let decision: DecisionRecord = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if !decision
            .evidence_refs
            .contains(&DecisionEvidence::DependencySelection {
                selection: selection.clone(),
            })
        {
            continue;
        }
        verify_exception_binding(&decision, selection, run.started_at)?;
        if approved.is_some() {
            return Err(invalid());
        }
        approved = Some(store_chunk(host, binding, &bytes)?);
    }
    Ok(approved)
}

pub fn collect(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo: &Path,
    run: &Run,
) -> ProofResult<ProvenanceReport> {
    run.validate()?;
    crate::application::inventory::validate_environment(run, profile)?;
    if run.run_id != host.workspace.run_id()
        || run.profile_sha256 != profile.sha256()
        || run.environment.isolation_status != IsolationStatus::Prepared
    {
        return Err(missing());
    }
    let reader = Reader::new(repo)?;
    let raw = reader.read(INPUTS, MAX_CAPTURE)?;
    let inputs: Inputs = serde_json::from_slice(&raw).map_err(|_| invalid())?;
    before_run(inputs.checked_at, run)?;
    if inputs.workspaces.len() != 3
        || inputs.registry_observations.is_empty()
        || inputs.guest_package_observations.is_empty()
    {
        return Err(missing());
    }
    let binding = source_binding(host)?;
    let mut sources = Vec::new();
    let mut facts = BTreeMap::new();
    for capture in &inputs.registry_observations {
        let key = (
            capture.name.as_str().to_owned(),
            capture.selected_version.as_str().to_owned(),
        );
        if facts.contains_key(&key) {
            return Err(invalid());
        }
        facts.insert(
            key,
            registry_fact(&reader, capture, host, &binding, run, &mut sources)?,
        );
    }
    let mut dependencies = Vec::new();
    let mut findings=vec![
  "Source metadata, declared MSRV and license expressions are observations, not build compatibility, legal clearance or signature authentication.".to_owned(),
  "Guest image has mixed package-specific obligations; Debian is not assigned a single permissive license.".to_owned(),
  "Local owner review is an audit record, not cryptographically tamper-proof human attestation.".to_owned(),
 ];
    let mut seen = BTreeSet::new();
    for capture in &inputs.workspaces {
        if !seen.insert(capture.workspace) {
            return Err(invalid());
        }
        let lock = reader.read(capture.workspace.lock(), MAX_CAPTURE)?;
        let lock_sha = Digest::of(&lock);
        if lock_sha != capture.lockfile_sha256 {
            return Err(invalid());
        }
        match capture.workspace {
            Workspace::Host if lock_sha != run.environment.lockfile_sha256 => return Err(invalid()),
            Workspace::Components if lock_sha != run.environment.component_lockfile_sha256 => {
                return Err(invalid());
            }
            _ => {}
        }
        let locked = lock_packages(&lock)?;
        let metadata_bytes = reader.capture(&capture.metadata)?;
        let metadata: CargoMetadata =
            serde_json::from_slice(&metadata_bytes).map_err(|_| invalid())?;
        let graph = graph(&metadata, &locked)?;
        for member in metadata
            .packages
            .iter()
            .filter(|p| metadata.workspace_members.contains(&p.id))
        {
            if member.license.is_none() {
                findings.push(format!("Own workspace member {} has no declared publication license; distribution requires an explicit project-license decision.",member.name));
            }
        }
        let role = match capture.workspace {
            Workspace::Host => "host-graph",
            Workspace::Components => "component-graph",
            Workspace::Linux => "linux-graph",
        };
        let public_graph = graph_value(&metadata, &graph, capture.workspace, lock_sha)?;
        let retained = retain(host, &binding, role, capture.metadata.sha256, &public_graph)?;
        let graph_refs = retained.evidence_refs.clone();
        sources.push(retained);
        for package in graph {
            let fact = facts
                .get(&(package.name.to_owned(), package.version.to_owned()))
                .ok_or_else(missing)?;
            if fact.source.checksum != package.checksum {
                return Err(invalid());
            }
            if package.license_expression != fact.source.license_expression
                || !compatible_msrv_sources(&package.minimum_rust, &fact.source.minimum_rust)
            {
                return Err(invalid());
            }
            if matches!(fact.source.minimum_rust, MinimumRust::Undeclared)
                && matches!(package.minimum_rust, MinimumRust::Declared { .. })
            {
                findings.push(format!("{} {}: registry MSRV is explicitly undeclared; the distinct downloaded-manifest declaration is retained in the measured graph.",package.name,package.version));
            }
            let mut refs = fact.evidence.clone();
            refs.extend_from_slice(&graph_refs);
            let exception = if package.direct
                && fact.source.selected_version != fact.source.latest_stable_observed
            {
                exception_for(&reader, &inputs, host, &binding, &fact.selection, run)?
            } else {
                None
            };
            let record = DependencyRecord {
                name: fact.source.name.clone(),
                source_url: fact.source.source_url.clone(),
                checked_at: fact.source.checked_at,
                latest_stable_observed: fact.source.latest_stable_observed.clone(),
                selected_version: fact.source.selected_version.clone(),
                artifact_digest: match &fact.archive {
                    Some(digest) => ArtifactDigest::DownloadedVerified {
                        algorithm: DigestAlgorithm::Sha256,
                        digest: digest.clone(),
                    },
                    None => published(
                        DigestAlgorithm::Sha256,
                        ArtifactHash::Sha256(package.checksum),
                    ),
                },
                license_expression: fact.source.license_expression.clone(),
                minimum_rust: fact.source.minimum_rust.clone(),
                compatibility_evidence_refs: refs,
                approved_exception_ref: exception,
            };
            record.validate()?;
            require_current_selection(
                &record,
                if package.direct {
                    DependencyKind::Direct
                } else {
                    DependencyKind::Transitive
                },
            )?;
            if record.license_expression == "NOASSERTION" {
                findings.push(format!("{} {} has no upstream declared license expression; no permissive-license assumption is made.",record.name,record.selected_version.as_str()));
            }
            dependencies.push(DependencyEntry {
                workspace: Some(capture.workspace),
                kind: if package.direct {
                    DependencyKind::Direct
                } else {
                    DependencyKind::Transitive
                },
                record,
            });
        }
    }
    collect_tools(
        &reader,
        &inputs,
        host,
        &binding,
        run,
        &mut dependencies,
        &mut sources,
    )?;
    collect_guest_packages(
        &reader,
        &inputs,
        host,
        &binding,
        run,
        &mut dependencies,
        &mut sources,
    )?;
    collect_native_builds(
        &NativeBuildContext {
            repo,
            reader: &reader,
            inputs: &inputs,
        },
        host,
        &binding,
        run,
        &dependencies,
        &mut sources,
    )?;
    let research = reader.read("specs/001-r0-feasibility/research.md", 256 * 1024)?;
    let research_sha256 = Digest::of(&research);
    let research_text = std::str::from_utf8(&research).map_err(|_| invalid())?;
    let research_source = retain(
        host,
        &binding,
        "research-register",
        research_sha256,
        &json!({"source":"specs/001-r0-feasibility/research.md","sha256":research_sha256,"content":research_text}),
    )?;
    let research_refs = research_source.evidence_refs.clone();
    sources.push(research_source);
    let rerun = reader.read("specs/001-r0-feasibility/quickstart.md", 256 * 1024)?;
    let rerun_sha256 = Digest::of(&rerun);
    sources.push(retain(host,&binding,"rerun-instructions",rerun_sha256,&json!({"source":"specs/001-r0-feasibility/quickstart.md","sha256":rerun_sha256,"content":std::str::from_utf8(&rerun).map_err(|_|invalid())?}))?);
    let decisions = source_decisions(&inputs, research_text, &research_refs)?;
    let mut measured = Vec::new();
    for artifact in host.evidence.artifacts()? {
        if artifact.kind.as_str() != "transport-measurements" {
            continue;
        }
        if host.ledger.read_project(artifact.project_id)?.user_id != host.project.user_id {
            return Err(invalid());
        }
        let bytes = host.evidence.read_artifact(
            artifact.project_id,
            artifact.artifact_id,
            MAX_BODY_BYTES,
        )?;
        let value: Measurements = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        validate_measurements(&value, profile)?;
        let origin = host.ledger.read_invocation(artifact.origin_invocation_id)?;
        if origin.invocation.run_id != run.run_id
            || origin.invocation.state != InvocationState::Completed
            || origin.invocation.output_ref != Some(artifact.artifact_id)
        {
            return Err(invalid());
        }
        verify_measurement_origins(
            &value,
            &host.ledger,
            &host.evidence,
            run,
            artifact.project_id,
        )?;
        measured.push(MeasurementEvidence {
            project_id: artifact.project_id,
            reference: EvidenceRef::Artifact {
                artifact_id: artifact.artifact_id,
                sha256: artifact.sha256,
                range: None,
            },
        });
    }
    if measured.is_empty() {
        return Err(missing());
    }
    let constrained = dependencies
        .iter()
        .filter(|entry| {
            entry.kind == DependencyKind::Transitive
                && entry.record.selected_version != entry.record.latest_stable_observed
        })
        .count();
    if constrained > 0 {
        findings.push(format!("{constrained} resolved transitive records differ from observed global latest stable; exact upstream constraints and selected graph are retained, not relabeled as latest or approved direct exceptions."));
    }
    if dependencies.len() > 2048 || sources.len() > 2048 || findings.len() > 128 {
        return Err(invalid());
    }
    Ok(ProvenanceReport {
        schema_version: inputs.schema_version,
        run_id: run.run_id,
        profile_sha256: profile.sha256(),
        checked_at: inputs.checked_at,
        environment: run.environment.clone(),
        dependencies,
        sources,
        decisions,
        measurements: measured,
        findings,
        research_sha256,
        rerun_sha256,
    })
}
fn source_decisions(
    inputs: &Inputs,
    research: &str,
    references: &[EvidenceRef],
) -> ProofResult<Vec<DecisionRecord>> {
    let mut result = Vec::with_capacity(inputs.decisions.len());
    for id in [
        "D-01", "D-02", "D-03", "D-04", "D-05", "D-06", "D-07", "D-08",
    ] {
        let matches: Vec<_> = inputs
            .decisions
            .iter()
            .filter(|record| record.decision_id.as_str() == id)
            .collect();
        if matches.len() != 1 {
            return Err(missing());
        }
        let decision = matches[0];
        decision.validate()?;
        verify_source_decision_fields(decision, research)?;
        let mut record = decision.clone();
        if record.status == DecisionStatus::Recorded && record.evidence_refs.is_empty() {
            record.evidence_refs = references
                .iter()
                .map(|reference| DecisionEvidence::Evidence {
                    reference: *reference,
                })
                .collect();
        }
        if record.evidence_refs.is_empty() || record.reviewed_at > inputs.checked_at {
            return Err(invalid());
        }
        result.push(record);
    }
    if result.len() != inputs.decisions.len() {
        return Err(invalid());
    }
    Ok(result)
}

fn collect_tools(
    reader: &Reader,
    inputs: &Inputs,
    host: &ProofHost,
    binding: &Arc<TrustedBinding>,
    run: &Run,
    dependencies: &mut Vec<DependencyEntry>,
    sources: &mut Vec<SourceEvidence>,
) -> ProofResult<()> {
    let rust_raw = reader.capture(&inputs.rust_observation)?;
    let rust_value: Value = serde_json::from_slice(&rust_raw).map_err(|_| invalid())?;
    let rust = rust_value.get("rust").ok_or_else(invalid)?;
    let rust_time = time(rust, "checked_at")?;
    before_run(rust_time, run)?;
    let selected = text(rust, "selected_version")?;
    let latest = text(rust, "latest_stable_version")?;
    if run
        .environment
        .dependency_versions
        .get(&CatalogId::parse("rust")?)
        .map(VersionPin::as_str)
        != Some(selected)
    {
        return Err(invalid());
    }
    let rust_url = rust
        .get("source_urls")
        .and_then(Value::as_array)
        .and_then(|items| items.first())
        .and_then(Value::as_str)
        .ok_or_else(invalid)?;
    let rust_checksum = Digest::parse(text(
        &rust["published_packages"]["rust"]["aarch64-apple-darwin"],
        "hash",
    )?)?;
    let rust_license = text(&rust["license"], "primary")?;
    let retained = retain(
        host,
        binding,
        "rust-toolchain-observation",
        inputs.rust_observation.sha256,
        &json!({"name":"rust","source_url":rust_url,"checked_at":rust_time,"latest_stable_observed":latest,"selected_version":selected,"published_archive_sha256":rust_checksum,"license_expression":rust_license,"minimum_rust":{"kind":"not_applicable"},"manifest_date":text(rust,"manifest_date")?,"limitation":"Primary license observation is not a completed distribution notice or signature review."}),
    )?;
    let refs = retained.evidence_refs.clone();
    sources.push(retained);
    let rust_record = DependencyRecord {
        name: DependencyName::parse("rust")?,
        source_url: rust_url.to_owned(),
        checked_at: rust_time,
        latest_stable_observed: DependencyVersion::parse(latest)?,
        selected_version: DependencyVersion::parse(selected)?,
        artifact_digest: published(DigestAlgorithm::Sha256, ArtifactHash::Sha256(rust_checksum)),
        license_expression: rust_license.to_owned(),
        minimum_rust: MinimumRust::NotApplicable,
        approved_exception_ref: if latest != selected {
            exception_for(
                reader,
                inputs,
                host,
                binding,
                &dependency_selection(
                    "rust",
                    selected,
                    latest,
                    inputs.rust_observation.sha256,
                    inputs.rust_observation.sha256,
                )?,
                run,
            )?
        } else {
            None
        },
        compatibility_evidence_refs: refs,
    };
    rust_record.validate()?;
    require_current_selection(&rust_record, DependencyKind::Tool)?;
    dependencies.push(DependencyEntry {
        workspace: None,
        kind: DependencyKind::Tool,
        record: rust_record,
    });
    let isolation_raw = reader.capture(&inputs.isolation_observation)?;
    let isolation: Value = serde_json::from_slice(&isolation_raw).map_err(|_| invalid())?;
    let observed_on = text(&isolation, "observed_on")?;
    let source_date =
        jiff::civil::Date::strptime("%Y-%m-%d", observed_on).map_err(|_| invalid())?;
    let capture_date =
        jiff::civil::Date::strptime("%Y-%m-%d", &inputs.checked_at.to_string()[..10])
            .map_err(|_| invalid())?;
    if source_date > capture_date {
        return Err(invalid());
    }
    for name in ["lima", "bubblewrap"] {
        let value = &isolation[name];
        let latest = text(&value["latest_stable_observation"], "tag_name")?
            .strip_prefix('v')
            .ok_or_else(invalid)?;
        let selected = text(value, "selected_version")?;
        let url = text(&value["latest_stable_observation"], "source_url")?;
        if run
            .environment
            .dependency_versions
            .get(&CatalogId::parse(name)?)
            .map(VersionPin::as_str)
            != Some(selected)
            || value["latest_stable_observation"]["prerelease"] != false
            || value["latest_stable_observation"]["draft"] != false
        {
            return Err(invalid());
        }
        let digest = text(&value["asset"], "published_digest")?
            .strip_prefix("sha256:")
            .ok_or_else(invalid)?;
        let checksum = Digest::parse(digest)?;
        let expression = if name == "lima" {
            text(&value["license_and_notices"], "license")?
        } else {
            text(&value["license_and_notices"], "source_spdx")?
        };
        let artifact_digest = if name == "lima" {
            let actual = reader.hash(
                "target/r0-tools/lima-2.3.0-Darwin-arm64.tar.gz",
                DigestAlgorithm::Sha256,
            )?;
            if actual != ArtifactHash::Sha256(checksum) {
                return Err(invalid());
            }
            ArtifactDigest::DownloadedVerified {
                algorithm: DigestAlgorithm::Sha256,
                digest: actual,
            }
        } else {
            published(DigestAlgorithm::Sha256, ArtifactHash::Sha256(checksum))
        };
        let retained = retain(
            host,
            binding,
            "isolation-tool-observation",
            inputs.isolation_observation.sha256,
            &json!({"name":name,"source_url":url,"checked_at":inputs.checked_at,"original_observed_on":observed_on,"latest_stable_observed":latest,"selected_version":selected,"artifact_digest":artifact_digest,"license_expression":expression,"notices":notice_projection(&value["license_and_notices"],0)?,"minimum_rust":{"kind":"not_applicable"},"signatures_authenticated":false}),
        )?;
        let refs = retained.evidence_refs.clone();
        sources.push(retained);
        let record = DependencyRecord {
            name: DependencyName::parse(name)?,
            source_url: url.to_owned(),
            checked_at: inputs.checked_at,
            latest_stable_observed: DependencyVersion::parse(latest)?,
            selected_version: DependencyVersion::parse(selected)?,
            artifact_digest,
            license_expression: expression.to_owned(),
            minimum_rust: MinimumRust::NotApplicable,
            approved_exception_ref: if latest != selected {
                exception_for(
                    reader,
                    inputs,
                    host,
                    binding,
                    &dependency_selection(
                        name,
                        selected,
                        latest,
                        inputs.isolation_observation.sha256,
                        inputs.isolation_observation.sha256,
                    )?,
                    run,
                )?
            } else {
                None
            },
            compatibility_evidence_refs: refs,
        };
        record.validate()?;
        require_current_selection(&record, DependencyKind::Tool)?;
        dependencies.push(DependencyEntry {
            workspace: None,
            kind: DependencyKind::Tool,
            record,
        });
    }
    let debian = &isolation["debian"];
    let selected = text(&debian["stable_status"], "latest_point_release")?;
    let image = text(&debian["image"], "published_digest")?;
    if image != run.environment.image_digest.as_str() {
        return Err(invalid());
    }
    let actual = reader.hash("target/r0-guest/debian.raw", DigestAlgorithm::Sha512)?;
    let expected = ArtifactHash::Sha512(crate::domain::proofs::ImageDigest::parse(image)?);
    if actual != expected {
        return Err(invalid());
    }
    let url = text(&debian["published_manifest"], "checksums_url")?;
    let retained = retain(
        host,
        binding,
        "guest-image-observation",
        inputs.isolation_observation.sha256,
        &json!({"name":"debian-image","source_url":url,"checked_at":inputs.checked_at,"original_observed_on":observed_on,"latest_stable_observed":selected,"selected_version":selected,"artifact_digest":{"kind":"downloaded_verified","algorithm":"sha512","digest":run.environment.image_digest},"license_expression":"NOASSERTION","minimum_rust":{"kind":"not_applicable"},"notices":notice_projection(&debian["licenses_and_notices"],0)?,"image_url":text(&debian["image"],"url")?,"signatures_authenticated":false}),
    )?;
    let refs = retained.evidence_refs.clone();
    sources.push(retained);
    let record = DependencyRecord {
        name: DependencyName::parse("debian-image")?,
        source_url: url.to_owned(),
        checked_at: inputs.checked_at,
        latest_stable_observed: DependencyVersion::parse(selected)?,
        selected_version: DependencyVersion::parse(selected)?,
        artifact_digest: ArtifactDigest::DownloadedVerified {
            algorithm: DigestAlgorithm::Sha512,
            digest: actual,
        },
        license_expression: "NOASSERTION".to_owned(),
        minimum_rust: MinimumRust::NotApplicable,
        compatibility_evidence_refs: refs,
        approved_exception_ref: None,
    };
    record.validate()?;
    dependencies.push(DependencyEntry {
        workspace: None,
        kind: DependencyKind::GuestImage,
        record,
    });
    Ok(())
}
fn collect_guest_packages(
    reader: &Reader,
    inputs: &Inputs,
    host: &ProofHost,
    binding: &Arc<TrustedBinding>,
    run: &Run,
    dependencies: &mut Vec<DependencyEntry>,
    sources: &mut Vec<SourceEvidence>,
) -> ProofResult<()> {
    let manifest = reader.capture(&inputs.guest_packages)?;
    if Some(Digest::of(&manifest)) != run.environment.guest_package_manifest_sha256 {
        return Err(invalid());
    }
    let packages = std::str::from_utf8(&manifest).map_err(|_| invalid())?;
    let lines: Vec<_> = packages.lines().collect();
    if lines.is_empty()
        || lines.len() != inputs.guest_package_observations.len()
        || lines.len() > 2048
    {
        return Err(invalid());
    }
    let retained = retain(
        host,
        binding,
        "guest-package-manifest",
        inputs.guest_packages.sha256,
        &json!({"sha256":inputs.guest_packages.sha256,"packages_tsv":packages}),
    )?;
    let manifest_refs = retained.evidence_refs.clone();
    sources.push(retained);
    let mut seen = BTreeSet::new();
    for line in lines {
        let columns: Vec<_> = line.split('\t').collect();
        if columns.len() != 3 || !seen.insert((columns[0], columns[2])) {
            return Err(invalid());
        }
        let matches: Vec<_> = inputs
            .guest_package_observations
            .iter()
            .filter(|entry| {
                entry.name.as_str() == columns[0]
                    && entry.version.as_str() == columns[1]
                    && entry.architecture == columns[2]
            })
            .collect();
        if matches.len() != 1 {
            return Err(missing());
        }
        let capture = matches[0];
        before_run(capture.checked_at, run)?;
        if !debian_source_url(&capture.source_url)
            || !matches!(capture.architecture.as_str(), "arm64" | "all")
        {
            return Err(invalid());
        }
        let copyright = reader.capture(&capture.copyright)?;
        let copyright = std::str::from_utf8(&copyright).map_err(|_| invalid())?;
        let policy = reader.capture(&capture.policy)?;
        let policy = std::str::from_utf8(&policy).map_err(|_| invalid())?;
        let metadata = reader.capture(&capture.metadata)?;
        let metadata = std::str::from_utf8(&metadata).map_err(|_| invalid())?;
        let facts_bytes = reader.capture(&capture.facts)?;
        let facts: GuestPackageFacts =
            serde_json::from_slice(&facts_bytes).map_err(|_| invalid())?;
        facts.validate()?;
        if facts.checked_at != capture.checked_at
            || facts.name != capture.name
            || facts.version != capture.version
            || facts.architecture != capture.architecture
            || facts.candidate != capture.latest_stable_observed
            || facts.copyright_raw_sha256 != capture.copyright.sha256
            || facts.policy_raw_sha256 != capture.policy.sha256
            || facts.metadata_raw_sha256 != capture.metadata.sha256
            || !packages.lines().any(|line| {
                let mut fields = line.split('\t');
                fields.next() == Some("python3-apt")
                    && fields.next() == Some(facts.parser_version.as_str())
            })
        {
            return Err(invalid());
        }
        let checksum = facts.sha256;
        let expression = "NOASSERTION".to_owned();
        let artifact_digest = if let Some(archive) = &capture.archive {
            let actual = reader.hash(&archive.path, DigestAlgorithm::Sha256)?;
            if actual != ArtifactHash::Sha256(checksum) || archive.sha256 != checksum {
                return Err(invalid());
            }
            ArtifactDigest::DownloadedVerified {
                algorithm: DigestAlgorithm::Sha256,
                digest: actual,
            }
        } else {
            published(DigestAlgorithm::Sha256, ArtifactHash::Sha256(checksum))
        };
        let mut observation = json!({"name":capture.name,"source_url":capture.source_url,"checked_at":capture.checked_at,"latest_stable_observed":capture.latest_stable_observed,"selected_version":capture.version,"architecture":capture.architecture,"published_deb_sha256":checksum,"artifact_digest":artifact_digest,"copyright_raw_sha256":capture.copyright.sha256,"policy_raw_sha256":capture.policy.sha256,"metadata_raw_sha256":capture.metadata.sha256,"facts_raw_sha256":capture.facts.sha256,"parser_facts":facts,"license_expression":expression,"copyright":public_document(copyright),"policy":public_document(policy),"package_metadata":public_document(metadata),"limitation":"NOASSERTION: freeform original copyright is an explicit license reference, not parsed SPDX or legal clearance. Public legal text preserves notices with private paths and sensitive text redacted; original unmodified captures remain private under separate raw digests."});
        for (field, key) in [
            ("copyright", "copyright_public_sha256"),
            ("policy", "policy_public_sha256"),
            ("package_metadata", "metadata_public_sha256"),
        ] {
            let digest = Digest::of(text(&observation, field)?.as_bytes());
            observation
                .as_object_mut()
                .ok_or_else(invalid)?
                .insert(key.to_owned(), json!(digest));
        }
        if capture.archive.is_some() {
            observation
                .as_object_mut()
                .ok_or_else(invalid)?
                .insert("downloaded_deb_sha256".to_owned(), json!(checksum));
        }
        let retained = retain(
            host,
            binding,
            "guest-package-observation",
            capture.metadata.sha256,
            &observation,
        )?;
        let mut refs = retained.evidence_refs.clone();
        sources.push(retained);
        refs.extend_from_slice(&manifest_refs);
        let record = DependencyRecord {
            name: capture.name.clone(),
            source_url: capture.source_url.clone(),
            checked_at: capture.checked_at,
            latest_stable_observed: capture.latest_stable_observed.clone(),
            selected_version: capture.version.clone(),
            artifact_digest,
            license_expression: expression,
            minimum_rust: MinimumRust::NotApplicable,
            approved_exception_ref: if capture.version != capture.latest_stable_observed {
                exception_for(
                    reader,
                    inputs,
                    host,
                    binding,
                    &dependency_selection(
                        capture.name.as_str(),
                        capture.version.as_str(),
                        capture.latest_stable_observed.as_str(),
                        capture.metadata.sha256,
                        capture.policy.sha256,
                    )?,
                    run,
                )?
            } else {
                None
            },
            compatibility_evidence_refs: refs,
        };
        record.validate()?;
        require_current_selection(&record, DependencyKind::GuestPackage)?;
        dependencies.push(DependencyEntry {
            workspace: None,
            kind: DependencyKind::GuestPackage,
            record,
        });
    }
    Ok(())
}
fn require_current_selection(record: &DependencyRecord, kind: DependencyKind) -> ProofResult<()> {
    if kind != DependencyKind::Transitive
        && record.selected_version != record.latest_stable_observed
        && record.approved_exception_ref.is_none()
    {
        return Err(ProofError::new(
            ErrorCode::ProviderUnavailable,
            "A non-current direct or tooling selection requires its explicit source-bound approved exception",
        ));
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedGraph {
    workspace: Workspace,
    lockfile_sha256: Digest,
    #[serde(deserialize_with = "capture_vec")]
    packages: Vec<RecordedPackage>,
    #[serde(deserialize_with = "bounded_vec")]
    members: Vec<RecordedMember>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedPackage {
    name: CatalogId,
    version: VersionPin,
    library_name: Option<String>,
    checksum: Digest,
    direct: bool,
    #[serde(deserialize_with = "bounded_vec")]
    features: Vec<String>,
    feature_definitions: BTreeMap<String, Vec<String>>,
    #[serde(deserialize_with = "capture_vec")]
    dependencies: Vec<(CatalogId, VersionPin)>,
    #[serde(deserialize_with = "capture_vec")]
    resolved: Vec<ResolvedEdge>,
    #[serde(deserialize_with = "capture_vec")]
    requirements: Vec<CargoDependency>,
    #[serde(deserialize_with = "crate::domain::validation::text_limit::<_,2048>")]
    license_expression: String,
    minimum_rust: MinimumRust,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordedMember {
    name: CatalogId,
    version: VersionPin,
    library_name: Option<String>,
    #[serde(deserialize_with = "bounded_vec")]
    features: Vec<String>,
    feature_definitions: BTreeMap<String, Vec<String>>,
    #[serde(deserialize_with = "capture_vec")]
    dependencies: Vec<(CatalogId, VersionPin)>,
    #[serde(deserialize_with = "capture_vec")]
    resolved: Vec<ResolvedEdge>,
    #[serde(deserialize_with = "capture_vec")]
    requirements: Vec<CargoDependency>,
}
struct GraphNodeFeatures<'a> {
    library_name: Option<&'a str>,
    selected: &'a [String],
    definitions: &'a BTreeMap<String, Vec<String>>,
}
fn validate_graph(graph: &RecordedGraph) -> ProofResult<()> {
    if !nonzero(graph.lockfile_sha256) || graph.members.is_empty() || graph.packages.is_empty() {
        return Err(invalid());
    }
    let mut keys = BTreeMap::new();
    for member in &graph.members {
        if keys.contains_key(&(member.name.as_str(), member.version.as_str()))
            || member
                .library_name
                .as_ref()
                .is_some_and(|name| !cargo_feature_name(name))
        {
            return Err(invalid());
        }
        keys.insert(
            (member.name.as_str(), member.version.as_str()),
            GraphNodeFeatures {
                library_name: member.library_name.as_deref(),
                selected: &member.features,
                definitions: &member.feature_definitions,
            },
        );
    }
    for package in &graph.packages {
        if keys.contains_key(&(package.name.as_str(), package.version.as_str()))
            || !nonzero(package.checksum)
            || package
                .library_name
                .as_ref()
                .is_some_and(|name| !cargo_feature_name(name))
            || !public_license_metadata(&package.license_expression, 2048)
        {
            return Err(invalid());
        }
        keys.insert(
            (package.name.as_str(), package.version.as_str()),
            GraphNodeFeatures {
                library_name: package.library_name.as_deref(),
                selected: &package.features,
                definitions: &package.feature_definitions,
            },
        );
        let direct = graph.members.iter().any(|member| {
            member
                .dependencies
                .iter()
                .any(|(name, version)| name == &package.name && version == &package.version)
        });
        if direct != package.direct {
            return Err(invalid());
        }
    }
    for member in &graph.members {
        validate_edges(
            &member.requirements,
            &member.features,
            &member.feature_definitions,
            &member.dependencies,
            &member.resolved,
            true,
            &keys,
        )?;
    }
    for package in &graph.packages {
        validate_edges(
            &package.requirements,
            &package.features,
            &package.feature_definitions,
            &package.dependencies,
            &package.resolved,
            false,
            &keys,
        )?;
    }
    let mut reachable: BTreeSet<_> = graph
        .members
        .iter()
        .map(|member| (member.name.as_str(), member.version.as_str()))
        .collect();
    loop {
        let before = reachable.len();
        for member in &graph.members {
            if reachable.contains(&(member.name.as_str(), member.version.as_str())) {
                reachable.extend(
                    member
                        .dependencies
                        .iter()
                        .map(|(name, version)| (name.as_str(), version.as_str())),
                );
            }
        }
        for package in &graph.packages {
            if reachable.contains(&(package.name.as_str(), package.version.as_str())) {
                reachable.extend(
                    package
                        .dependencies
                        .iter()
                        .map(|(name, version)| (name.as_str(), version.as_str())),
                );
            }
        }
        if reachable.len() == before {
            break;
        }
    }
    if reachable.len() != keys.len() {
        return Err(invalid());
    }
    Ok(())
}
fn validate_edges(
    requirements: &[CargoDependency],
    features: &[String],
    definitions: &BTreeMap<String, Vec<String>>,
    dependencies: &[(CatalogId, VersionPin)],
    resolved: &[ResolvedEdge],
    member: bool,
    known: &BTreeMap<(&str, &str), GraphNodeFeatures<'_>>,
) -> ProofResult<()> {
    if definitions.len() > 2048
        || features.len() > 256
        || features
            .iter()
            .any(|feature| !safe_text(feature, 256) || !definitions.contains_key(feature))
    {
        return Err(invalid());
    }
    // Captures use Cargo's default workspace feature selection and all platforms,
    // never --no-default-features or --filter-platform. Nested feature closure is
    // checked too: dropping an activated feature must not hide an optional edge.
    if member
        && definitions.contains_key("default")
        && !features.iter().any(|feature| feature == "default")
    {
        return Err(invalid());
    }
    for (name, values) in definitions {
        if !cargo_feature_name(name) || values.len() > 2048 {
            return Err(invalid());
        }
        for value in values {
            let valid = if let Some(alias) = value.strip_prefix("dep:") {
                cargo_feature_name(alias)
            } else if let Some((alias, feature)) = value.split_once('/') {
                cargo_feature_name(alias.strip_suffix('?').unwrap_or(alias))
                    && cargo_feature_name(feature)
            } else {
                cargo_feature_name(value) && definitions.contains_key(value)
            };
            if !valid {
                return Err(invalid());
            }
        }
    }
    let mut activated = BTreeSet::new();
    for feature in features {
        let values = definitions.get(feature).ok_or_else(invalid)?;
        if values.len() > 2048 {
            return Err(invalid());
        }
        for value in values {
            if !safe_text(value, 512) {
                return Err(invalid());
            }
            if let Some(alias) = value.strip_prefix("dep:") {
                activated.insert(alias);
            } else if let Some((alias, _)) = value.split_once('/') {
                if !alias.ends_with('?') {
                    activated.insert(alias);
                }
            } else if !features.iter().any(|feature| feature == value) {
                return Err(invalid());
            }
        }
    }
    let applicable = |r: &CargoDependency| {
        (member || r.kind.as_deref() != Some("dev"))
            && (!r.optional || activated.contains(r.rename.as_deref().unwrap_or(&r.name)))
    };
    let parsed_requirements = requirements
        .iter()
        .map(|requirement| semver::VersionReq::parse(&requirement.req).map_err(|_| invalid()))
        .collect::<ProofResult<Vec<_>>>()?;
    let versions = resolved
        .iter()
        .map(|edge| semver::Version::parse(edge.package.1.as_str()).map_err(|_| invalid()))
        .collect::<ProofResult<Vec<_>>>()?;
    let matches = |requirement: usize, edge: usize, kind: &CargoDepKind| {
        let r = &requirements[requirement];
        let target = &resolved[edge];
        let library = known
            .get(&(target.package.0.as_str(), target.package.1.as_str()))
            .and_then(|node| node.library_name);
        r.name == target.package.0.as_str()
            && r.rename
                .as_deref()
                .or(library)
                .is_some_and(|alias| cargo_alias_eq(alias, &target.alias))
            && r.kind == kind.kind
            && r.target == kind.target
            && parsed_requirements[requirement].matches(&versions[edge])
    };
    let mut edge_keys = BTreeSet::new();
    let mut actual = BTreeSet::new();
    for (index, edge) in resolved.iter().enumerate() {
        if !safe_text(&edge.alias, 256)
            || edge.dep_kinds.is_empty()
            || !known.contains_key(&(edge.package.0.as_str(), edge.package.1.as_str()))
        {
            return Err(invalid());
        }
        actual.insert((edge.package.0.as_str(), edge.package.1.as_str()));
        for kind in &edge.dep_kinds {
            if !edge_keys.insert((
                &edge.alias,
                edge.package.0.as_str(),
                edge.package.1.as_str(),
                &kind.kind,
                &kind.target,
            )) {
                return Err(invalid());
            }
            // Cargo's resolve graph may retain disabled optional dependencies.
            // Authenticate their declarations without claiming feature activation.
            let mut matched = false;
            for (requirement, _) in requirements
                .iter()
                .enumerate()
                .filter(|(_, r)| member || r.kind.as_deref() != Some("dev"))
            {
                if matches(requirement, index, kind) {
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err(invalid());
            }
        }
    }
    let declared: BTreeSet<_> = dependencies
        .iter()
        .map(|(name, version)| (name.as_str(), version.as_str()))
        .collect();
    if declared.len() != dependencies.len() || actual != declared {
        return Err(invalid());
    }
    for (index, requirement) in requirements.iter().enumerate() {
        CatalogId::parse(&requirement.name)?;
        if requirement
            .features
            .iter()
            .any(|feature| !cargo_feature_name(feature))
            || !matches!(requirement.kind.as_deref(), None | Some("dev" | "build"))
            || requirement.target.as_ref().is_some_and(|target| {
                !safe_text(target, 2048)
                    || target
                        .split_whitespace()
                        .any(crate::domain::decisions::filesystem_token)
            })
        {
            return Err(invalid());
        }
        if applicable(requirement) {
            let mut count = 0;
            for (edge, target) in resolved.iter().enumerate() {
                for kind in &target.dep_kinds {
                    if matches(index, edge, kind) {
                        count += 1;
                        validate_dependency_features(
                            requirement,
                            known
                                .get(&(target.package.0.as_str(), target.package.1.as_str()))
                                .ok_or_else(invalid)?,
                            features,
                            definitions,
                        )?;
                    }
                }
            }
            if count != 1 {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn validate_dependency_features(
    requirement: &CargoDependency,
    target: &GraphNodeFeatures<'_>,
    source_features: &[String],
    source_definitions: &BTreeMap<String, Vec<String>>,
) -> ProofResult<()> {
    let selected = |feature: &str| target.selected.iter().any(|value| value == feature);
    if requirement
        .features
        .iter()
        .any(|feature| !selected(feature))
        || requirement.uses_default_features
            && target.definitions.contains_key("default")
            && !selected("default")
    {
        return Err(invalid());
    }
    let alias = requirement.rename.as_deref().unwrap_or(&requirement.name);
    for feature in source_features {
        for value in source_definitions.get(feature).ok_or_else(invalid)? {
            let Some((dependency, forwarded)) = value.split_once('/') else {
                continue;
            };
            // Weak forwarding does not activate an optional dependency. This check is
            // reached only for an enabled, matched edge with its actual kind/target.
            if dependency.strip_suffix('?').unwrap_or(dependency) == alias && !selected(forwarded) {
                return Err(invalid());
            }
        }
    }
    Ok(())
}
fn cargo_feature_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 256
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'+' | b'.'))
}
fn cargo_alias_eq(requirement: &str, resolved: &str) -> bool {
    requirement.len() == resolved.len()
        && requirement
            .bytes()
            .map(|byte| if byte == b'-' { b'_' } else { byte })
            .eq(resolved.bytes())
}
/// The caller-supplied kind cannot turn a directly selected downgrade into a constrained transitive pin.
pub fn verify_graph_selection(entry: &DependencyEntry, bytes: &[u8]) -> ProofResult<()> {
    if bytes.len() > MAX_CAPTURE {
        return Err(invalid());
    }
    let graph: RecordedGraph = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    validate_graph(&graph)?;
    verify_graph_entry(entry, &graph)
}
fn verify_graph_entry(entry: &DependencyEntry, graph: &RecordedGraph) -> ProofResult<()> {
    if entry.workspace != Some(graph.workspace) {
        return Err(invalid());
    }
    let record = &entry.record;
    record.validate()?;
    let package = graph
        .packages
        .iter()
        .find(|p| {
            p.name.as_str() == record.name.as_str()
                && p.version.as_str() == record.selected_version.as_str()
        })
        .ok_or_else(invalid)?;
    let direct = graph.members.iter().any(|m| {
        m.dependencies.iter().any(|(name, version)| {
            name.as_str() == record.name.as_str()
                && version.as_str() == record.selected_version.as_str()
        })
    });
    let kind = if direct {
        DependencyKind::Direct
    } else {
        DependencyKind::Transitive
    };
    if entry.kind != kind
        || record.artifact_digest.parts().1 != &ArtifactHash::Sha256(package.checksum)
        || record.license_expression != package.license_expression
        || !compatible_msrv_sources(&record.minimum_rust, &package.minimum_rust)
    {
        return Err(invalid());
    }
    require_current_selection(record, kind)
}
fn artifact_reference(reference: &EvidenceRef) -> ProofResult<(EntityId, Digest)> {
    match reference {
        EvidenceRef::Artifact {
            artifact_id,
            sha256,
            range: None,
        } if nonzero(*sha256) => Ok((*artifact_id, *sha256)),
        _ => Err(invalid()),
    }
}
fn owned_artifact(
    evidence: &EvidenceStore,
    ledger: &Ledger,
    owner: EntityId,
    artifact_project: EntityId,
    run: &Run,
    reference: &EvidenceRef,
) -> ProofResult<Vec<u8>> {
    let (id, digest) = artifact_reference(reference)?;
    let artifact = evidence.artifact(artifact_project, id)?;
    if artifact.sha256 != digest
        || ledger.read_project(artifact.project_id)?.user_id != ledger.read_project(owner)?.user_id
    {
        return Err(invalid());
    }
    let origin = ledger.read_invocation(artifact.origin_invocation_id)?;
    if origin.invocation.run_id != run.run_id
        || origin.invocation.project_id != artifact.project_id
        || origin.invocation.state != InvocationState::Completed
        || origin.invocation.output_ref != Some(id)
    {
        return Err(invalid());
    }
    let bytes = evidence.read_artifact(artifact.project_id, id, MAX_BODY_BYTES)?;
    reference.validate_artifact(artifact.project_id, &artifact, &bytes)?;
    Ok(bytes)
}
fn source_bytes(
    source: &SourceEvidence,
    evidence: &EvidenceStore,
    ledger: &Ledger,
    project: EntityId,
    run: &Run,
) -> ProofResult<Vec<u8>> {
    if !nonzero(source.raw_sha256)
        || !nonzero(source.public_sha256)
        || source.public_length_bytes.get() == 0
        || source.public_length_bytes.get() > MAX_CAPTURE as u64
        || source.evidence_refs.is_empty()
        || source.evidence_refs.len() > 16
    {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(source.public_length_bytes.get() as usize);
    for reference in &source.evidence_refs {
        let (id, _) = artifact_reference(reference)?;
        let artifact = evidence.artifact(project, id)?;
        let origin = ledger.read_invocation(artifact.origin_invocation_id)?;
        if artifact.kind.as_str() != "provenance-source"
            || artifact.redaction_status != RedactionStatus::Redacted
            || origin.invocation.tool_id.as_str() != TOOL
        {
            return Err(invalid());
        }
        let chunk = owned_artifact(evidence, ledger, project, project, run, reference)?;
        if bytes.len() + chunk.len() > MAX_CAPTURE {
            return Err(invalid());
        }
        bytes.extend_from_slice(&chunk);
    }
    if bytes.len() as u64 != source.public_length_bytes.get()
        || Digest::of(&bytes) != source.public_sha256
    {
        return Err(invalid());
    }
    Ok(bytes)
}
fn public_value(value: &Value, depth: usize) -> ProofResult<()> {
    if depth > 32 {
        return Err(invalid());
    }
    match value {
        Value::String(text) => {
            if text.len() > MAX_CAPTURE
                || text
                    .split(['\n', '\r', '\t'])
                    .any(|part| !part.is_empty() && !safe_text(part, MAX_CAPTURE))
            {
                return Err(invalid());
            }
        }
        Value::Array(items) => {
            if items.len() > 2048 {
                return Err(invalid());
            }
            for item in items {
                public_value(item, depth + 1)?;
            }
        }
        Value::Object(fields) => {
            // Cargo feature tables share the 2048-item source collection bound.
            if fields.len() > 2048 {
                return Err(invalid());
            }
            for (key, item) in fields {
                if !safe_text(key, 256) {
                    return Err(invalid());
                }
                if key == "notices" {
                    validate_public_notices(item, depth + 1)?;
                } else {
                    public_value(item, depth + 1)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}
fn notice_projection(value: &Value, depth: usize) -> ProofResult<Value> {
    if depth > 32 {
        return Err(invalid());
    }
    let projected = match value {
        Value::String(text) => {
            if text.len() > MAX_CAPTURE {
                return Err(invalid());
            }
            Value::String(public_document(text))
        }
        Value::Array(items) => {
            if items.len() > 2048 {
                return Err(invalid());
            }
            Value::Array(
                items
                    .iter()
                    .map(|item| notice_projection(item, depth + 1))
                    .collect::<ProofResult<Vec<_>>>()?,
            )
        }
        Value::Object(fields) => {
            if fields.len() > 256 {
                return Err(invalid());
            }
            let mut public = serde_json::Map::new();
            for (key, item) in fields {
                if !crate::domain::decisions::public_metadata(key, 256) {
                    return Err(invalid());
                }
                public.insert(key.clone(), notice_projection(item, depth + 1)?);
            }
            Value::Object(public)
        }
        _ => value.clone(),
    };
    Ok(projected)
}
fn validate_public_notices(value: &Value, depth: usize) -> ProofResult<()> {
    if depth > 32 {
        return Err(invalid());
    }
    match value {
        Value::String(text) => {
            if text.len() > MAX_CAPTURE || public_document(text) != *text {
                return Err(invalid());
            }
        }
        Value::Array(items) => {
            if items.len() > 2048 {
                return Err(invalid());
            }
            for item in items {
                validate_public_notices(item, depth + 1)?;
            }
        }
        Value::Object(fields) => {
            if fields.len() > 256 {
                return Err(invalid());
            }
            for (key, item) in fields {
                if !crate::domain::decisions::public_metadata(key, 256) {
                    return Err(invalid());
                }
                validate_public_notices(item, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
pub fn verify_report_sources(
    report: &ProvenanceReport,
    run: &Run,
    profile: &LoadedProfile,
    evidence: &EvidenceStore,
    ledger: &Ledger,
    project: EntityId,
) -> ProofResult<()> {
    run.validate()?;
    crate::application::inventory::validate_environment(run, profile)?;
    if report.run_id != run.run_id
        || report.profile_sha256 != profile.sha256()
        || run.profile_sha256 != profile.sha256()
        || report.environment != run.environment
        || report.environment.isolation_status != IsolationStatus::Prepared
        || report.checked_at > run.started_at
        || report.dependencies.is_empty()
        || report.dependencies.len() > 2048
        || report.sources.is_empty()
        || report.sources.len() > 2048
        || report.findings.is_empty()
        || report.findings.len() > 256
        || report
            .findings
            .iter()
            .any(|finding| !safe_text(finding, 4096))
        || report.measurements.is_empty()
    {
        return Err(invalid());
    }
    let mut values = Vec::with_capacity(report.sources.len());
    let mut graph_indexes = BTreeMap::new();
    let mut refs = BTreeMap::new();
    let mut research = None;
    let mut rerun = None;
    let mut guest_packages = None;
    let mut component_build = None;
    let mut prepared_guest = None;
    for (index, source) in report.sources.iter().enumerate() {
        let bytes = source_bytes(source, evidence, ledger, project, run)?;
        let mut value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        public_value(&value, 0)?;
        for reference in &source.evidence_refs {
            if refs.insert(artifact_reference(reference)?, index).is_some() {
                return Err(invalid());
            }
        }
        match source.role.as_str() {
            "host-graph" | "component-graph" | "linux-graph" => {
                let graph: RecordedGraph = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
                validate_graph(&graph)?;
                if graph_indexes
                    .insert(graph.workspace, (index, graph))
                    .is_some()
                {
                    return Err(invalid());
                }
            }
            "research-register" => {
                if research
                    .replace(text(&value, "content")?.to_owned())
                    .is_some()
                    || text(&value, "sha256")? != report.research_sha256.to_string()
                    || Digest::of(text(&value, "content")?.as_bytes()) != report.research_sha256
                    || source.raw_sha256 != report.research_sha256
                {
                    return Err(invalid());
                }
            }
            "rerun-instructions" => {
                if rerun.replace(()).is_some()
                    || Digest::of(text(&value, "content")?.as_bytes()) != report.rerun_sha256
                    || source.raw_sha256 != report.rerun_sha256
                {
                    return Err(invalid());
                }
            }
            "guest-package-manifest" => {
                if guest_packages
                    .replace(text(&value, "packages_tsv")?.to_owned())
                    .is_some()
                    || Some(source.raw_sha256) != run.environment.guest_package_manifest_sha256
                    || Digest::of(text(&value, "packages_tsv")?.as_bytes()) != source.raw_sha256
                {
                    return Err(invalid());
                }
            }
            "component-build-observation" => {
                if component_build.replace(index).is_some()
                    || source.raw_sha256 != Digest::of(&bytes)
                {
                    return Err(invalid());
                }
                verify_component_build(&value, run, &report.dependencies, source.raw_sha256)?;
            }
            "prepared-guest-observation" => {
                if prepared_guest.replace(index).is_some() {
                    return Err(invalid());
                }
                verify_prepared_guest(&value, run)?;
            }
            "guest-package-observation" => {
                if source.raw_sha256 != Digest::parse(text(&value, "metadata_raw_sha256")?)? {
                    return Err(invalid());
                }
                verify_guest_observation(&value)?;
            }
            "registry-observation"
            | "rust-toolchain-observation"
            | "isolation-tool-observation"
            | "guest-image-observation" => {}
            _ => return Err(invalid()),
        }
        if let Some(object) = value.as_object_mut() {
            for key in [
                "copyright",
                "policy",
                "package_metadata",
                "content",
                "packages_tsv",
            ] {
                object.remove(key);
            }
        }
        values.push(value);
    }
    if graph_indexes.len() != 3 || rerun.is_none() {
        return Err(invalid());
    }
    for (workspace, (_, graph)) in &graph_indexes {
        let expected = match workspace {
            Workspace::Host => Some(run.environment.lockfile_sha256),
            Workspace::Components => Some(run.environment.component_lockfile_sha256),
            Workspace::Linux => None,
        };
        if expected.is_some_and(|digest| digest != graph.lockfile_sha256)
            || report
                .dependencies
                .iter()
                .filter(|entry| entry.workspace == Some(*workspace))
                .count()
                != graph.packages.len()
        {
            return Err(invalid());
        }
    }
    let mut keys = BTreeSet::new();
    let mut tool_count = 0;
    let mut image_count = 0;
    let mut guest_count = 0;
    for entry in &report.dependencies {
        let record = &entry.record;
        record.validate()?;
        before_run(record.checked_at, run)?;
        if !keys.insert((
            entry.workspace,
            record.name.as_str(),
            record.selected_version.as_str(),
        )) {
            return Err(invalid());
        }
        let indexes = record
            .compatibility_evidence_refs
            .iter()
            .map(|reference| {
                refs.get(&artifact_reference(reference)?)
                    .copied()
                    .ok_or_else(invalid)
            })
            .collect::<ProofResult<BTreeSet<_>>>()?;
        if let Some(workspace) = entry.workspace {
            let (index, graph) = graph_indexes.get(&workspace).ok_or_else(invalid)?;
            if !indexes.contains(index) {
                return Err(invalid());
            }
            verify_graph_entry(entry, graph)?;
            let mut observed = None;
            for index in &indexes {
                if report.sources[*index].role.as_str() == "registry-observation" {
                    let source: StableSourceObservation = serde_json::from_value(
                        values[*index]
                            .get("observation")
                            .ok_or_else(invalid)?
                            .clone(),
                    )
                    .map_err(|_| invalid())?;
                    let downloaded = values[*index]
                        .get("downloaded_archive_sha256")
                        .map(|value| {
                            serde_json::from_value::<Digest>(value.clone()).map_err(|_| invalid())
                        })
                        .transpose()?;
                    if observed.replace((source, downloaded)).is_some() {
                        return Err(invalid());
                    }
                }
            }
            let (source, downloaded) = observed.ok_or_else(invalid)?;
            if record.artifact_digest.downloaded_verified() != downloaded.is_some()
                || downloaded.is_some_and(|digest| digest != source.checksum)
            {
                return Err(invalid());
            }
            if source.name != record.name
                || source.source_url != record.source_url
                || source.checked_at != record.checked_at
                || source.latest_stable_observed != record.latest_stable_observed
                || source.selected_version != record.selected_version
                || source.license_expression != record.license_expression
                || source.minimum_rust != record.minimum_rust
                || source.yanked
                || source.prerelease
                || record.artifact_digest.parts().1 != &ArtifactHash::Sha256(source.checksum)
            {
                return Err(invalid());
            }
        } else {
            require_current_selection(record, entry.kind)?;
            let role = match entry.kind {
                DependencyKind::Tool => {
                    tool_count += 1;
                    if record.name.as_str() == "rust" {
                        "rust-toolchain-observation"
                    } else {
                        "isolation-tool-observation"
                    }
                }
                DependencyKind::GuestImage => {
                    image_count += 1;
                    "guest-image-observation"
                }
                DependencyKind::GuestPackage => {
                    guest_count += 1;
                    "guest-package-observation"
                }
                _ => return Err(invalid()),
            };
            let source = indexes
                .iter()
                .find(|index| report.sources[**index].role.as_str() == role)
                .ok_or_else(invalid)?;
            verify_non_registry_record(record, &values[*source], entry.kind)?;
        }
        if let Some(reference) = &record.approved_exception_ref {
            let bytes = owned_artifact(evidence, ledger, project, project, run, reference)?;
            let decision: DecisionRecord = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
            let selection = exception_selection(record, &indexes, &report.sources, &values)?;
            verify_exception_binding(&decision, &selection, run.started_at)?;
        }
    }
    if component_build.is_none() || prepared_guest.is_none() {
        return Err(invalid());
    }
    let prepared_index = prepared_guest.ok_or_else(invalid)?;
    if graph_indexes
        .get(&Workspace::Linux)
        .map(|(_, graph)| graph.lockfile_sha256)
        != Some(Digest::parse(text(
            &values[prepared_index],
            "linux_lockfile_sha256",
        )?)?)
    {
        return Err(invalid());
    }
    if tool_count != 3 || image_count != 1 || guest_count == 0 {
        return Err(invalid());
    }
    let packages = guest_packages.ok_or_else(invalid)?;
    if packages.lines().count() != guest_count {
        return Err(invalid());
    }
    let research = research.ok_or_else(invalid)?;
    verify_decisions(&report.decisions, &research, report.checked_at)?;
    let research_source = report
        .sources
        .iter()
        .find(|source| source.role.as_str() == "research-register")
        .ok_or_else(invalid)?;
    for decision in &report.decisions {
        if research_source.evidence_refs.iter().any(|reference| {
            !decision
                .evidence_refs
                .contains(&DecisionEvidence::Evidence {
                    reference: *reference,
                })
        }) {
            return Err(invalid());
        }
        for reference in &decision.evidence_refs {
            match reference {
                DecisionEvidence::Evidence { reference } => {
                    if !refs.contains_key(&artifact_reference(reference)?) {
                        owned_artifact(evidence, ledger, project, project, run, reference)?;
                    }
                }
                DecisionEvidence::RunManifest { .. }
                | DecisionEvidence::DependencySelection { .. } => return Err(invalid()),
            }
        }
    }
    for measured in &report.measurements {
        let bytes = owned_artifact(
            evidence,
            ledger,
            project,
            measured.project_id,
            run,
            &measured.reference,
        )?;
        let (id, _) = artifact_reference(&measured.reference)?;
        if evidence.artifact(measured.project_id, id)?.kind.as_str() != "transport-measurements" {
            return Err(invalid());
        }
        let value: Measurements = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        validate_measurements(&value, profile)?;
        verify_measurement_origins(&value, ledger, evidence, run, measured.project_id)?;
    }
    Ok(())
}

fn verify_non_registry_record(
    record: &DependencyRecord,
    value: &Value,
    kind: DependencyKind,
) -> ProofResult<()> {
    if text(value, "name")? != record.name.as_str()
        || text(value, "source_url")? != record.source_url
        || time(value, "checked_at")? != record.checked_at
        || text(value, "latest_stable_observed")? != record.latest_stable_observed.as_str()
        || text(value, "selected_version")? != record.selected_version.as_str()
        || text(value, "license_expression")? != record.license_expression
        || record.minimum_rust != MinimumRust::NotApplicable
    {
        return Err(invalid());
    }
    let expected = if record.name.as_str() == "rust" {
        published(
            DigestAlgorithm::Sha256,
            ArtifactHash::Sha256(Digest::parse(text(value, "published_archive_sha256")?)?),
        )
    } else {
        ArtifactDigest::deserialize(value.get("artifact_digest").ok_or_else(invalid)?)
            .map_err(|_| invalid())?
    };
    if kind == DependencyKind::GuestPackage {
        let checksum = Digest::parse(text(value, "published_deb_sha256")?)?;
        let downloaded = value
            .get("downloaded_deb_sha256")
            .map(|value| Digest::deserialize(value).map_err(|_| invalid()))
            .transpose()?;
        if expected.parts().1 != &ArtifactHash::Sha256(checksum)
            || expected.downloaded_verified() != downloaded.is_some()
            || downloaded.is_some_and(|digest| digest != checksum)
        {
            return Err(invalid());
        }
    }
    if record.artifact_digest != expected {
        return Err(invalid());
    }
    Ok(())
}
fn verify_decisions(
    decisions: &[DecisionRecord],
    research: &str,
    checked_at: AuditTime,
) -> ProofResult<()> {
    if decisions.len() != 8 {
        return Err(invalid());
    }
    for id in [
        "D-01", "D-02", "D-03", "D-04", "D-05", "D-06", "D-07", "D-08",
    ] {
        let mut matches = decisions
            .iter()
            .filter(|record| record.decision_id.as_str() == id);
        let record = matches.next().ok_or_else(invalid)?;
        if matches.next().is_some() {
            return Err(invalid());
        }
        record.validate()?;
        if record.reviewed_at > checked_at
            || !matches!(
                record.status,
                DecisionStatus::Recorded | DecisionStatus::Approved
            )
            || record.evidence_refs.is_empty()
        {
            return Err(invalid());
        }
        verify_source_decision_fields(record, research)?;
    }
    Ok(())
}

fn verify_measurement_origins(
    value: &Measurements,
    ledger: &Ledger,
    evidence: &EvidenceStore,
    run: &Run,
    project: EntityId,
) -> ProofResult<()> {
    if !run
        .environment
        .fixture_digests
        .values()
        .any(|digest| *digest == value.fixture_sha256)
    {
        return Err(invalid());
    }
    for sample in value
        .direct_warmup
        .iter()
        .chain(&value.proxy_warmup)
        .chain(&value.direct_samples)
        .chain(&value.proxy_samples)
    {
        let stored = ledger.read_invocation(sample.invocation_id)?;
        let invocation = &stored.invocation;
        if invocation.run_id != run.run_id
            || invocation.project_id != project
            || invocation.tool_id.as_str() != "http.send"
            || invocation.state != InvocationState::Completed
        {
            return Err(invalid());
        }
        let output_id = invocation.output_ref.ok_or_else(invalid)?;
        let output_artifact = evidence.artifact(project, output_id)?;
        let result_artifact = evidence.artifact(project, sample.result_artifact_id)?;
        if output_artifact.kind.as_str() != "http-send-output"
            || output_artifact.origin_invocation_id != invocation.invocation_id
            || result_artifact.kind.as_str() != "http-send-result"
            || result_artifact.origin_invocation_id != invocation.invocation_id
        {
            return Err(invalid());
        }
        let output: crate::application::http_send::HttpSendOutput =
            serde_json::from_slice(&evidence.read_artifact(project, output_id, MAX_BODY_BYTES)?)
                .map_err(|_| invalid())?;
        if output.exchange_ref != sample.result_artifact_id {
            return Err(invalid());
        }
        evidence.verify_artifact(project, sample.result_artifact_id)?;
    }
    Ok(())
}
/// Source-only canonical artifacts, not an alternate packet writer.
pub fn publish_register(
    host: &ProofHost,
    report: &ProvenanceReport,
) -> ProofResult<SourceEvidence> {
    let value = serde_json::to_value(report).map_err(|_| invalid())?;
    public_value(&value, 0)?;
    let bytes = serde_json::to_vec(&value).map_err(|_| invalid())?;
    retain_bytes(
        host,
        &source_binding(host)?,
        "provenance-register",
        Digest::of(&bytes),
        &bytes,
    )
}
pub fn read_register(
    reference: &SourceEvidence,
    run: &Run,
    evidence: &EvidenceStore,
    ledger: &Ledger,
    project: EntityId,
) -> ProofResult<ProvenanceReport> {
    if reference.role.as_str() != "provenance-register"
        || reference.raw_sha256 != reference.public_sha256
    {
        return Err(invalid());
    }
    let bytes = source_bytes(reference, evidence, ledger, project, run)?;
    serde_json::from_slice(&bytes).map_err(|_| invalid())
}

struct NativeBuildContext<'a> {
    repo: &'a Path,
    reader: &'a Reader,
    inputs: &'a Inputs,
}

fn collect_native_builds(
    context: &NativeBuildContext<'_>,
    host: &ProofHost,
    binding: &Arc<TrustedBinding>,
    run: &Run,
    dependencies: &[DependencyEntry],
    sources: &mut Vec<SourceEvidence>,
) -> ProofResult<()> {
    let &NativeBuildContext {
        repo,
        reader,
        inputs,
    } = context;
    let bytes = reader.read("target/proof-components/build-manifest.json", 1024 * 1024)?;
    let value: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    verify_component_build(&value, run, dependencies, Digest::of(&bytes))?;
    verify_component_files(reader, &value)?;
    public_value(&value, 0)?;
    sources.push(retain_bytes(
        host,
        binding,
        "component-build-observation",
        Digest::of(&bytes),
        &bytes,
    )?);
    let bytes = reader.read("target/r0-guest/prepared.json", 1024 * 1024)?;
    let record: Value = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let linux = inputs
        .workspaces
        .iter()
        .find(|capture| capture.workspace == Workspace::Linux)
        .ok_or_else(invalid)?;
    let value = json!({"profile_sha256":record["profile_sha256"],"manager_sha256":record["manager_sha256"],"source_sha256":record["source_sha256"],"provisioning_sha256":record["provisioning_sha256"],"configuration_sha256":record["configuration_sha256"],"image_sha512":record["image_sha512"],"guest_manifest":record["guest_manifest"],"linux_lockfile_sha256":linux.lockfile_sha256});
    verify_prepared_guest(&value, run)?;
    verify_prepared_files(repo, reader, &value)?;
    sources.push(retain(
        host,
        binding,
        "prepared-guest-observation",
        Digest::of(&bytes),
        &value,
    )?);
    Ok(())
}
fn verify_component_files(reader: &Reader, value: &Value) -> ProofResult<()> {
    for (field, path) in [
        ("guest_manifest_sha256", "fixtures/components/Cargo.toml"),
        ("guest_source_sha256", "fixtures/components/src/lib.rs"),
        ("bindings_sha256", "fixtures/components/src/bindings.rs"),
        ("helper_sha256", "scripts/proofs/build-components.sh"),
        ("runner_sha256", "target/debug/razen-component-runner"),
    ] {
        if reader.hash(path, DigestAlgorithm::Sha256)?
            != ArtifactHash::Sha256(Digest::parse(text(value, field)?)?)
        {
            return Err(invalid());
        }
    }
    for variant in value["variants"].as_array().ok_or_else(invalid)? {
        let file = text(variant, "file")?;
        if file.contains(['/', '\\']) || !file.ends_with(".wasm") {
            return Err(invalid());
        }
        if reader.hash(
            &format!("target/proof-components/{file}"),
            DigestAlgorithm::Sha256,
        )? != ArtifactHash::Sha256(Digest::parse(text(variant, "sha256")?)?)
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn verify_prepared_files(repo: &Path, reader: &Reader, value: &Value) -> ProofResult<()> {
    if reader.hash(
        "target/r0-tools/lima/2.3.0/bin/limactl",
        DigestAlgorithm::Sha256,
    )? != ArtifactHash::Sha256(Digest::parse(text(value, "manager_sha256")?)?)
        || reader.hash("scripts/proofs/provision-guest.sh", DigestAlgorithm::Sha256)?
            != ArtifactHash::Sha256(Digest::parse(text(value, "provisioning_sha256")?)?)
        || crate::adapters::guest::preflight::source_digest(repo)?
            != Digest::parse(text(value, "source_sha256")?)?
    {
        return Err(invalid());
    }
    Ok(())
}
fn verify_component_build(
    value: &Value,
    run: &Run,
    dependencies: &[DependencyEntry],
    manifest_sha256: Digest,
) -> ProofResult<()> {
    verify_component_environment(value, &run.environment, manifest_sha256)?;
    for (name, key) in [("wit-bindgen", "wit_bindgen"), ("wasmtime", "wasmtime")] {
        if !dependencies.iter().any(|entry| {
            entry.record.name.as_str() == name
                && entry.record.selected_version.as_str() == value[key].as_str().unwrap_or("")
        }) {
            return Err(invalid());
        }
    }
    Ok(())
}
fn verify_component_environment(
    value: &Value,
    environment: &RunEnvironment,
    manifest_sha256: Digest,
) -> ProofResult<()> {
    if environment
        .fixture_digests
        .get(&CatalogId::parse("component-build-manifest")?)
        != Some(&manifest_sha256)
        || environment
            .binary_digests
            .get(&CatalogId::parse("razen-component-runner")?)
            != Some(&Digest::parse(text(value, "runner_sha256")?)?)
        || text(value, "rust")?
            != environment
                .dependency_versions
                .get(&CatalogId::parse("rust")?)
                .ok_or_else(invalid)?
                .as_str()
        || Digest::parse(text(value, "lock_sha256")?)? != environment.component_lockfile_sha256
        || Digest::parse(text(value, "wit_sha256")?)? != environment.wit_sha256
        || text(value, "target")? != environment.component_target
    {
        return Err(invalid());
    }
    for (name, key) in [("wit-bindgen", "wit_bindgen"), ("wasmtime", "wasmtime")] {
        if text(value, key)?
            != environment
                .dependency_versions
                .get(&CatalogId::parse(name)?)
                .ok_or_else(invalid)?
                .as_str()
        {
            return Err(invalid());
        }
    }
    let variants = value["variants"].as_array().ok_or_else(invalid)?;
    if variants.len() != 6 {
        return Err(invalid());
    }
    for name in [
        "fixture-valid",
        "fixture-loop",
        "fixture-grow",
        "fixture-output",
        "fixture-host-call",
        "fixture-denied-access",
    ] {
        let mut matching = variants.iter().filter(|variant| variant["variant"] == name);
        let variant = matching.next().ok_or_else(invalid)?;
        if matching.next().is_some()
            || environment.fixture_digests.get(&CatalogId::parse(name)?)
                != Some(&Digest::parse(text(variant, "sha256")?)?)
        {
            return Err(invalid());
        }
    }
    Ok(())
}
fn verify_prepared_guest(value: &Value, run: &Run) -> ProofResult<()> {
    verify_prepared_environment(value, run.profile_sha256, &run.environment)
}
fn verify_prepared_environment(
    value: &Value,
    profile_sha256: Digest,
    environment: &RunEnvironment,
) -> ProofResult<()> {
    let guest = &value["guest_manifest"];
    if Digest::parse(text(value, "profile_sha256")?)? != profile_sha256
        || guest["available"] != true
        || Some(Digest::parse(text(value, "provisioning_sha256")?)?)
            != environment.provisioning_sha256
        || Some(Digest::parse(text(value, "configuration_sha256")?)?)
            != environment.effective_config_sha256
        || Some(Digest::parse(text(guest, "package_manifest_sha256")?)?)
            != environment.guest_package_manifest_sha256
        || Some(Digest::parse(text(guest, "seccomp_sha256")?)?) != environment.seccomp_sha256
        || format!("sha512:{}", text(value, "image_sha512")?) != environment.image_digest.as_str()
    {
        return Err(invalid());
    }
    for (native, global) in [
        ("supervisor", "guest-supervisor"),
        ("adversary", "guest-adversary"),
        ("bubblewrap", "bubblewrap"),
    ] {
        let digest = Digest::parse(text(&guest["binary_digests"], native)?)?;
        if environment.binary_digests.get(&CatalogId::parse(global)?) != Some(&digest) {
            return Err(invalid());
        }
    }
    let source = Digest::parse(text(&guest["binary_digests"], "source")?)?;
    if environment
        .fixture_digests
        .get(&CatalogId::parse("guest-source")?)
        != Some(&source)
    {
        return Err(invalid());
    }
    Ok(())
}
pub fn read_capture(repo: &Path, source: &SourceFile) -> ProofResult<Vec<u8>> {
    Reader::new(repo)?.capture(source)
}

fn research_section<'a>(research: &'a str, id: &str) -> ProofResult<&'a str> {
    let heading = format!("## {id} ");
    let mut positions = research.match_indices(&heading);
    let (start, _) = positions.next().ok_or_else(invalid)?;
    if positions.next().is_some() {
        return Err(invalid());
    }
    let rest = &research[start..];
    let end = rest.find("\n## ").unwrap_or(rest.len());
    Ok(&rest[..end])
}
fn research_paragraph(section: &str, label: &str) -> ProofResult<String> {
    let (_, body) = section.split_once(label).ok_or_else(invalid)?;
    let body = body.trim_start();
    let end = body.find("\n\n").unwrap_or(body.len());
    let paragraph = body[..end].split_whitespace().collect::<Vec<_>>().join(" ");
    if !safe_text(&paragraph, 4096) {
        return Err(invalid());
    }
    Ok(paragraph)
}
fn verify_source_decision_fields(record: &DecisionRecord, research: &str) -> ProofResult<()> {
    let section = research_section(research, record.decision_id.as_str())?;
    let title = section
        .lines()
        .next()
        .and_then(|line| line.split_once('—'))
        .map(|(_, title)| title.trim())
        .ok_or_else(invalid)?;
    if record.subject != title
        || record.decision != research_paragraph(section, "**Decision**:")?
        || record.rationale != research_paragraph(section, "**Rationale**:")?
        || record.alternatives.len() != 1
        || record.alternatives[0] != research_paragraph(section, "**Alternatives considered**:")?
    {
        return Err(invalid());
    }
    Ok(())
}
/// Honest technical source observations only. The supplied observer/time are never converted to human approval.
pub fn recorded_research_decisions(
    research: &str,
    observer: &str,
    observed_at: AuditTime,
) -> ProofResult<Vec<DecisionRecord>> {
    if !safe_text(observer, 256) {
        return Err(invalid());
    }
    let mut records = Vec::with_capacity(8);
    for id in [
        "D-01", "D-02", "D-03", "D-04", "D-05", "D-06", "D-07", "D-08",
    ] {
        let section = research_section(research, id)?;
        let subject = section
            .lines()
            .next()
            .and_then(|line| line.split_once('—'))
            .map(|(_, title)| title.trim())
            .ok_or_else(invalid)?;
        let record = DecisionRecord {
            decision_id: CatalogId::parse(id)?,
            subject: subject.to_owned(),
            decision: research_paragraph(section, "**Decision**:")?,
            rationale: research_paragraph(section, "**Rationale**:")?,
            alternatives: vec![research_paragraph(section, "**Alternatives considered**:")?],
            evidence_refs: Vec::new(),
            status: DecisionStatus::Recorded,
            reviewer: observer.to_owned(),
            reviewed_at: observed_at,
        };
        record.validate()?;
        records.push(record);
    }
    Ok(records)
}

pub(crate) fn read_repository_file(
    repo: &Path,
    path: &str,
    maximum: usize,
) -> ProofResult<Vec<u8>> {
    Reader::new(repo)?.read(path, maximum)
}

fn rust_release(value: &str) -> Option<[u64; 3]> {
    let mut release = [0; 3];
    let mut count = 0;
    for part in value.split('.') {
        if count == 3 {
            return None;
        }
        release[count] = part.parse().ok()?;
        count += 1;
    }
    if count < 2 {
        return None;
    }
    Some(release)
}
fn compatible_msrv_sources(left: &MinimumRust, right: &MinimumRust) -> bool {
    match (left, right) {
        (MinimumRust::Declared { version: left }, MinimumRust::Declared { version: right }) => {
            rust_release(left.as_str())
                .zip(rust_release(right.as_str()))
                .is_some_and(|(left, right)| left == right)
        }
        (MinimumRust::NotApplicable, _) | (_, MinimumRust::NotApplicable) => false,
        _ => true,
    }
}

pub fn verify_exception_binding(
    decision: &DecisionRecord,
    selection: &DependencySelection,
    before: AuditTime,
) -> ProofResult<()> {
    decision.validate()?;
    selection.validate()?;
    if decision.status != DecisionStatus::Approved
        || decision.reviewed_at > before
        || decision.evidence_refs.len() != 1
        || decision.evidence_refs[0]
            != (DecisionEvidence::DependencySelection {
                selection: selection.clone(),
            })
    {
        return Err(invalid());
    }
    Ok(())
}

fn dependency_selection(
    name: &str,
    selected: &str,
    latest: &str,
    selected_source_sha256: Digest,
    latest_source_sha256: Digest,
) -> ProofResult<DependencySelection> {
    let selection = DependencySelection {
        name: DependencyName::parse(name)?,
        selected_version: DependencyVersion::parse(selected)?,
        latest_stable_observed: DependencyVersion::parse(latest)?,
        selected_source_sha256,
        latest_source_sha256,
    };
    selection.validate()?;
    Ok(selection)
}
fn exception_selection(
    record: &DependencyRecord,
    indexes: &BTreeSet<usize>,
    sources: &[SourceEvidence],
    values: &[Value],
) -> ProofResult<DependencySelection> {
    let mut selection = None;
    for index in indexes {
        let source = &sources[*index];
        let value = &values[*index];
        let hashes = match source.role.as_str() {
            "registry-observation" => {
                let raw = Digest::parse(text(value, "source_raw_sha256")?)?;
                if raw != source.raw_sha256 {
                    return Err(invalid());
                }
                (raw, raw)
            }
            "guest-package-observation" => (
                source.raw_sha256,
                Digest::parse(text(value, "policy_raw_sha256")?)?,
            ),
            "rust-toolchain-observation"
            | "isolation-tool-observation"
            | "guest-image-observation" => (source.raw_sha256, source.raw_sha256),
            _ => continue,
        };
        if selection
            .replace(dependency_selection(
                record.name.as_str(),
                record.selected_version.as_str(),
                record.latest_stable_observed.as_str(),
                hashes.0,
                hashes.1,
            )?)
            .is_some()
        {
            return Err(invalid());
        }
    }
    selection.ok_or_else(invalid)
}

fn debian_source_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| {
        url.scheme() == "https"
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() != "/"
            && matches!(
                url.host_str(),
                Some(
                    "snapshot.debian.org"
                        | "sources.debian.org"
                        | "deb.debian.org"
                        | "security.debian.org"
                )
            )
    })
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestOrigin {
    origin: String,
    archive: String,
    site: String,
    trusted: bool,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GuestPackageFacts {
    parser: String,
    parser_version: DependencyVersion,
    checked_at: AuditTime,
    name: DependencyName,
    version: DependencyVersion,
    architecture: String,
    installed: DependencyVersion,
    candidate: DependencyVersion,
    #[serde(deserialize_with = "bounded_vec")]
    candidate_origins: Vec<GuestOrigin>,
    filename: String,
    sha256: Digest,
    copyright_raw_sha256: Digest,
    policy_raw_sha256: Digest,
    metadata_raw_sha256: Digest,
    license_expression: String,
    license_reference: String,
}
impl GuestPackageFacts {
    fn validate(&self) -> ProofResult<()> {
        if self.parser != "python3-apt"
            || self.installed != self.version
            || !matches!(self.architecture.as_str(), "arm64" | "all")
            || self.license_expression != "NOASSERTION"
            || self.license_reference != "original-installed-package-copyright"
            || self.filename.starts_with('/')
            || !self.filename.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'/' | b'+' | b'-' | b'.' | b'_' | b'~' | b':' | b'%')
            })
            || self
                .filename
                .split('/')
                .any(|part| part.is_empty() || part == ".." || part == "." || part.len() > 256)
            || !self.filename.ends_with(".deb")
            || [
                self.sha256,
                self.copyright_raw_sha256,
                self.policy_raw_sha256,
                self.metadata_raw_sha256,
            ]
            .into_iter()
            .any(|digest| !nonzero(digest))
            || self.candidate_origins.iter().any(|origin| {
                (!origin.origin.is_empty()
                    && !crate::domain::decisions::public_metadata(&origin.origin, 128))
                    || (!origin.archive.is_empty()
                        && !crate::domain::decisions::public_metadata(&origin.archive, 128))
                    || (!origin.site.is_empty()
                        && (origin.site.len() > 256 || url::Host::parse(&origin.site).is_err()))
            })
            || !self.candidate_origins.iter().any(|origin| {
                origin.trusted
                    && origin.origin == "Debian"
                    && matches!(
                        origin.archive.as_str(),
                        "trixie"
                            | "trixie-security"
                            | "trixie-updates"
                            | "stable"
                            | "stable-security"
                            | "stable-updates"
                    )
                    && matches!(
                        origin.site.as_str(),
                        "snapshot.debian.org" | "deb.debian.org" | "security.debian.org"
                    )
            })
        {
            return Err(invalid());
        }
        Ok(())
    }
}
/// Field-specific public projection: never publish raw legal/control/policy text
/// under a Redacted label. URLs and legal prose survive; filesystem tokens do not.
fn public_document(raw: &str) -> String {
    let mut public = String::with_capacity(raw.len());
    let mut private_key = false;
    for line in raw.split_inclusive('\n') {
        if line.contains("-----BEGIN ") && line.contains("PRIVATE KEY-----") {
            private_key = true;
            public.push_str("[REDACTED PRIVATE KEY]\n");
        }
        if private_key {
            if line.contains("-----END ") && line.contains("PRIVATE KEY-----") {
                private_key = false;
            }
            continue;
        }
        let start = public.len();
        for token in line.split_inclusive(char::is_whitespace) {
            let word = token.trim_end_matches(char::is_whitespace);
            let suffix = &token[word.len()..];
            if word.is_empty() {
                public.push_str(suffix);
                continue;
            }
            let legal = word
                .trim_matches(['(', ')', '[', ']', '<', '>', '"', '\'', ',', ';'])
                .strip_prefix("/usr/share/common-licenses/")
                .filter(|name| cargo_feature_name(name));
            if let Some(name) = legal {
                public.push_str("debian-common-license-reference:");
                public.push_str(name);
            } else if crate::domain::decisions::filesystem_token(word)
                || !safe_text(word, MAX_CAPTURE)
            {
                public.push_str("[REDACTED]");
            } else {
                public.push_str(word);
            }
            public.push_str(suffix);
        }
        if public[start..]
            .split(['\n', '\r', '\t'])
            .any(|part| !part.is_empty() && !safe_text(part, MAX_CAPTURE))
        {
            public.truncate(start);
            public.push_str("[REDACTED SENSITIVE TEXT]");
            if line.ends_with('\n') {
                public.push('\n');
            }
        }
    }
    public
}
fn verify_guest_observation(value: &Value) -> ProofResult<()> {
    let facts: GuestPackageFacts =
        serde_json::from_value(value.get("parser_facts").ok_or_else(invalid)?.clone())
            .map_err(|_| invalid())?;
    facts.validate()?;
    if !debian_source_url(text(value, "source_url")?)
        || facts.checked_at != time(value, "checked_at")?
        || facts.name.as_str() != text(value, "name")?
        || facts.version.as_str() != text(value, "selected_version")?
        || facts.candidate.as_str() != text(value, "latest_stable_observed")?
        || facts.architecture != text(value, "architecture")?
        || facts.sha256 != Digest::parse(text(value, "published_deb_sha256")?)?
        || facts.copyright_raw_sha256 != Digest::parse(text(value, "copyright_raw_sha256")?)?
        || facts.policy_raw_sha256 != Digest::parse(text(value, "policy_raw_sha256")?)?
        || facts.metadata_raw_sha256 != Digest::parse(text(value, "metadata_raw_sha256")?)?
        || text(value, "license_expression")? != "NOASSERTION"
        || !nonzero(Digest::parse(text(value, "facts_raw_sha256")?)?)
    {
        return Err(invalid());
    }
    for (field, digest) in [
        ("copyright", "copyright_public_sha256"),
        ("policy", "policy_public_sha256"),
        ("package_metadata", "metadata_public_sha256"),
    ] {
        let public = text(value, field)?;
        if public_document(public) != public
            || Digest::of(public.as_bytes()) != Digest::parse(text(value, digest)?)?
        {
            return Err(invalid());
        }
    }
    Ok(())
}

#[cfg(test)]
mod registry_source_tests {
    use super::*;
    fn fixture() -> (RegistryCapture, Value) {
        let selected = Digest::of(b"selected older archive fixture");
        let latest = Digest::of(b"latest archive fixture");
        let value = json!({"crate":{"name":"example-crate","max_stable_version":"1.1.0"},"versions":[
   {"crate":"example-crate","num":"1.0.0","yanked":false,"checksum":selected,"license":"MIT","rust_version":"1.99.0"},
   {"crate":"example-crate","num":"1.1.0","yanked":false,"checksum":latest,"license":"Apache-2.0","rust_version":"1.100.0"}]});
        let capture = RegistryCapture {
            name: CatalogId::parse("example-crate").unwrap(),
            selected_version: DependencyVersion::parse("1.0.0").unwrap(),
            checked_at: AuditTime::parse("2026-11-16T12:00:00Z").unwrap(),
            crate_url: "https://crates.io/api/v1/crates/example-crate".to_owned(),
            crate_capture: SourceFile {
                path: "raw-registry-fixture.json".to_owned(),
                sha256: Digest::of(&serde_json::to_vec(&value).unwrap()),
            },
            archive: None,
        };
        (capture, value)
    }
    #[test]
    fn exact_selected_archive_license_and_msrv_come_from_one_atomic_response_not_its_latest_entry()
    {
        let (capture, value) = fixture();
        let source = registry_observation(&capture, &serde_json::to_vec(&value).unwrap()).unwrap();
        assert_eq!(source.selected_version.as_str(), "1.0.0");
        assert_eq!(source.latest_stable_observed.as_str(), "1.1.0");
        assert_eq!(
            source.checksum,
            Digest::of(b"selected older archive fixture")
        );
        assert_eq!(source.license_expression, "MIT");
        assert_eq!(
            source.minimum_rust,
            MinimumRust::Declared {
                version: VersionPin::parse("1.99.0").unwrap()
            }
        );
    }
    #[test]
    fn missing_duplicate_foreign_yanked_or_wrong_source_selection_never_falls_back_to_latest() {
        for scenario in ["missing", "duplicate", "foreign", "yanked", "wrong-source"] {
            let (mut capture, mut value) = fixture();
            match scenario {
                "missing" => {
                    value["versions"].as_array_mut().unwrap().remove(0);
                }
                "duplicate" => {
                    let duplicate = value["versions"][0].clone();
                    value["versions"].as_array_mut().unwrap().push(duplicate);
                }
                "foreign" => value["versions"][0]["crate"] = json!("another-crate"),
                "yanked" => value["versions"][0]["yanked"] = json!(true),
                "wrong-source" => {
                    capture.crate_url = "https://crates.io/api/v1/crates/another-crate".to_owned()
                }
                _ => unreachable!(),
            }
            assert_eq!(
                registry_observation(&capture, &serde_json::to_vec(&value).unwrap())
                    .unwrap_err()
                    .code,
                ErrorCode::IntegrityError,
                "{scenario}"
            );
        }
    }
    #[test]
    fn lockfile_uses_real_toml_strings_comments_and_duplicate_key_rejection() {
        let bytes=b"version = 4\n[[package]]\nname='serde' # comment\nversion='1.0.0'\nsource='registry+https://github.com/rust-lang/crates.io-index'\nchecksum='aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n";
        assert_eq!(lock_packages(bytes).unwrap()[0].name.as_str(), "serde");
        assert!(
            lock_packages(b"[[package]]\nname='serde'\nname='other'\nversion='1.0.0'\n").is_err()
        );
    }
    #[test]
    fn public_legal_projection_redacts_arbitrary_private_paths_without_erasing_legal_facts() {
        let raw = "Copyright 2026 Example Authors\nLicense: GPL-2+\nSee /usr/share/common-licenses/GPL-2\nBuild /var/folders/person/cache /tmp/private /Volumes/Secret /opt/internal C:\\private\\build\n";
        let public = public_document(raw);
        assert!(public.contains("Copyright 2026 Example Authors"));
        assert!(public.contains("License: GPL-2+"));
        assert!(public.contains("debian-common-license-reference:GPL-2"));
        assert_eq!(public_document(&public), public);
        for private in [
            "/var/folders",
            "/tmp/private",
            "/Volumes/Secret",
            "/opt/internal",
            "C:\\private",
        ] {
            assert!(!public.contains(private));
        }
        assert_ne!(Digest::of(raw.as_bytes()), Digest::of(public.as_bytes()));
    }
}

#[cfg(test)]
mod provenance_policy_tests {
    use super::*;
    // Deterministic source-policy fixtures, not operational full35 evidence.
    fn graph_fixture() -> Value {
        json!({"workspace":"host","lockfile_sha256":Digest::of(b"lock"),
   "members":[{"name":"workspace","version":"0.1.0","features":[],"feature_definitions":{},"dependencies":[["example","1.0.0"]],
    "resolved":[{"alias":"example","package":["example","1.0.0"],"dep_kinds":[{"kind":null,"target":null}]}],
    "requirements":[{"name":"example","req":"^1","kind":null,"rename":null,"optional":false,"target":null,"features":[],"uses_default_features":true}]}],
   "packages":[{"name":"example","version":"1.0.0","library_name":"example","checksum":Digest::of(b"archive"),"direct":true,"features":[],"feature_definitions":{},"dependencies":[],"resolved":[],"requirements":[],"license_expression":"MIT","minimum_rust":{"kind":"undeclared"}}]})
    }
    fn valid_graph(value: Value) -> bool {
        validate_graph(&serde_json::from_value(value).unwrap()).is_ok()
    }
    #[test]
    fn incoming_requested_features_and_defaults_cannot_drop_an_optional_subtree() {
        let mut value = graph_fixture();
        value["members"][0]["requirements"][0]["features"] = json!(["derive"]);
        value["packages"][0]["features"] = json!(["default", "derive"]);
        value["packages"][0]["feature_definitions"] =
            json!({"default":[],"derive":["dep:derive-helper"]});
        value["packages"][0]["requirements"] = json!([{"name":"derive-helper","req":"^1","kind":null,"rename":null,"optional":true,"target":null,"features":[],"uses_default_features":true}]);
        value["packages"][0]["dependencies"] = json!([["derive-helper", "1.0.0"]]);
        value["packages"][0]["resolved"] = json!([{"alias":"derive_helper","package":["derive-helper","1.0.0"],"dep_kinds":[{"kind":null,"target":null}]}]);
        let mut helper = graph_fixture()["packages"][0].clone();
        helper["name"] = json!("derive-helper");
        helper["library_name"] = json!("derive_helper");
        helper["direct"] = json!(false);
        value["packages"].as_array_mut().unwrap().push(helper);
        assert!(valid_graph(value.clone()));
        let mut dropped = value.clone();
        dropped["packages"][0]["features"] = json!(["default"]);
        dropped["packages"][0]["dependencies"] = json!([]);
        dropped["packages"][0]["resolved"] = json!([]);
        dropped["packages"].as_array_mut().unwrap().pop();
        assert!(!valid_graph(dropped));
        let mut dropped = value;
        dropped["packages"][0]["features"] = json!(["derive"]);
        assert!(!valid_graph(dropped));
    }
    #[test]
    fn strong_and_weak_feature_forwarding_require_features_only_on_enabled_dependencies() {
        for forwarding in ["example/forwarded", "example?/forwarded"] {
            let mut value = graph_fixture();
            value["members"][0]["features"] = json!(["selected"]);
            value["members"][0]["feature_definitions"] = json!({"selected":[forwarding]});
            value["packages"][0]["features"] = json!(["forwarded"]);
            value["packages"][0]["feature_definitions"] = json!({"forwarded":[]});
            assert!(valid_graph(value.clone()));
            value["packages"][0]["features"] = json!([]);
            assert!(!valid_graph(value));
        }
        let mut value = graph_fixture();
        value["members"][0]["requirements"][0]["optional"] = json!(true);
        value["members"][0]["requirements"][0]["features"] = json!(["derive"]);
        value["members"][0]["features"] = json!(["std"]);
        value["members"][0]["feature_definitions"] =
            json!({"std":["example?/forwarded"],"enabled":["dep:example"]});
        value["packages"][0]["feature_definitions"] =
            json!({"default":[],"derive":[],"forwarded":[]});
        // A retained inactive edge does not activate requested/default/weak features.
        assert!(valid_graph(value.clone()));
        let mut undeclared = value.clone();
        undeclared["members"][0]["requirements"][0]["name"] = json!("unrelated");
        assert!(!valid_graph(undeclared));
        let mut alias = value.clone();
        alias["members"][0]["resolved"][0]["alias"] = json!("unrelated");
        assert!(!valid_graph(alias));
        value["members"][0]["features"] = json!(["std", "enabled"]);
        assert!(!valid_graph(value.clone()));
        value["packages"][0]["features"] = json!(["default", "derive", "forwarded"]);
        assert!(valid_graph(value));
    }
    #[test]
    fn large_cargo_feature_maps_remain_publishable_but_invalid_names_are_rejected() {
        let mut graph = graph_fixture();
        let definitions = graph["packages"][0]["feature_definitions"]
            .as_object_mut()
            .unwrap();
        // The captured winapi 0.3.9 graph contains 399 feature definitions.
        for index in 0..399 {
            definitions.insert(format!("platform_{index}"), json!([]));
        }
        assert!(valid_graph(graph.clone()));
        public_value(&graph, 0).unwrap();
        graph["packages"][0]["feature_definitions"]
            .as_object_mut()
            .unwrap()
            .insert("/var/folders/person/cache".into(), json!([]));
        assert_eq!(
            validate_graph(&serde_json::from_value(graph).unwrap())
                .unwrap_err()
                .code,
            ErrorCode::IntegrityError
        );
    }
    #[test]
    fn public_notice_projection_preserves_negative_and_legal_facts_but_never_private_paths() {
        let original = json!({"legal":"Copyright Example Authors; see /usr/share/common-licenses/GPL-2","unavailable":false,"nested":[{"observation":"Build failed at /var/folders/person/cache and /opt/internal/project"}]});
        assert!(public_value(&json!({"notices":original}), 0).is_err());
        let projected = notice_projection(&original, 0).unwrap();
        public_value(&json!({"notices":projected}), 0).unwrap();
        assert_eq!(projected["unavailable"], json!(false));
        assert!(
            projected["legal"]
                .as_str()
                .unwrap()
                .contains("debian-common-license-reference:GPL-2")
        );
        let public = serde_json::to_string(&projected).unwrap();
        for path in ["/var/folders/person/cache", "/opt/internal/project"] {
            assert!(!public.contains(path));
        }
    }
    #[test]
    fn missing_required_edges_unreachable_packages_and_inconsistent_requirements_are_rejected() {
        let original = graph_fixture();
        assert!(valid_graph(original.clone()));
        let mut omitted = original.clone();
        omitted["members"][0]["dependencies"] = json!([]);
        omitted["members"][0]["resolved"] = json!([]);
        omitted["packages"][0]["direct"] = json!(false);
        assert!(!valid_graph(omitted));
        let mut unreachable = original.clone();
        let mut orphan = unreachable["packages"][0].clone();
        orphan["name"] = json!("orphan");
        orphan["direct"] = json!(false);
        unreachable["packages"].as_array_mut().unwrap().push(orphan);
        assert!(!valid_graph(unreachable));
        let mut inconsistent = original.clone();
        inconsistent["members"][0]["requirements"][0]["req"] = json!("^2");
        assert!(!valid_graph(inconsistent));
        let mut inconsistent = original;
        inconsistent["members"][0]["resolved"][0]["dep_kinds"][0]["target"] = json!("cfg(windows)");
        assert!(!valid_graph(inconsistent));
    }
    #[test]
    fn renamed_optional_and_target_dependencies_follow_actual_features_not_caller_kind() {
        let mut value = graph_fixture();
        value["packages"][0]["library_name"] = json!("different_library_name");
        value["members"][0]["resolved"][0]["alias"] = json!("different_library_name");
        assert!(valid_graph(value.clone()));
        value["members"][0]["requirements"][0]["optional"] = json!(true);
        value["members"][0]["requirements"][0]["rename"] = json!("renamed-example");
        value["members"][0]["requirements"][0]["target"] = json!("cfg(windows)");
        value["members"][0]["resolved"][0]["alias"] = json!("renamed_example");
        value["members"][0]["resolved"][0]["dep_kinds"][0]["target"] = json!("cfg(windows)");
        value["members"][0]["features"] = json!(["selected"]);
        value["members"][0]["feature_definitions"] = json!({"selected":["dep:renamed-example"]});
        assert!(valid_graph(value.clone()));
        let mut nested = value.clone();
        nested["members"][0]["feature_definitions"]["default"] = json!(["selected"]);
        nested["members"][0]["features"] = json!(["default", "selected"]);
        assert!(valid_graph(nested.clone()));
        nested["members"][0]["features"] = json!(["default"]);
        assert!(!valid_graph(nested));
        value["members"][0]["features"] = json!([]);
        assert!(valid_graph(value.clone()));
        let mut wrong_target = value.clone();
        wrong_target["members"][0]["requirements"][0]["target"] = json!("cfg(unix)");
        assert!(!valid_graph(wrong_target));
        // An inactive optional dependency is not required to appear in resolve.
        let mut value = graph_fixture();
        value["members"][0]["requirements"].as_array_mut().unwrap().push(json!({"name":"inactive","req":"^4","kind":null,"rename":"unused","optional":true,"target":"cfg(unix)","features":["std"],"uses_default_features":true}));
        value["members"][0]["feature_definitions"] =
            json!({"enable-unused":["dep:unused"],"weak":["unused?/std"]});
        value["members"][0]["features"] = json!(["weak"]);
        assert!(valid_graph(value.clone()));
        value["members"][0]["features"] = json!(["enable-unused"]);
        assert!(!valid_graph(value));
    }
    fn build_fixture() -> (Value, RunEnvironment, Digest) {
        let digest = Digest::of(b"CONTROLLEDGATEFIXTURE frozen build");
        let variants: Vec<_> = [
            "fixture-valid",
            "fixture-loop",
            "fixture-grow",
            "fixture-output",
            "fixture-host-call",
            "fixture-denied-access",
        ]
        .into_iter()
        .map(|name| json!({"variant":name,"file":format!("{name}.wasm"),"sha256":digest}))
        .collect();
        let build = json!({"rust":"1.100.0","target":"wasm32-wasip2","wasmtime":"50.0.1","wit_bindgen":"0.63.0","lock_sha256":digest,"wit_sha256":digest,"runner_sha256":digest,"variants":variants});
        let manifest = Digest::of(&serde_json::to_vec(&build).unwrap());
        let mut environment:RunEnvironment=serde_json::from_value(json!({"hardware_model":"CONTROLLEDGATEFIXTURE","logical_cpus":8,"memory_mib":16384,"os":"macOS","os_version":"26.5.1","arch":"arm64","os_build":"fixture","kernel":"fixture","filesystem":"APFS","storage":"fixture","component_target":"wasm32-wasip2","backend":"lima-vz-plain-bubblewrap-cgroup-v2","isolation_status":"prepared","guest_os":"Debian 13.7 arm64","image_digest":format!("sha512:{}","a".repeat(128)),"dependency_versions":{"rust":"1.100.0","wasmtime":"50.0.1","wit-bindgen":"0.63.0","lima":"2.3.0","bubblewrap":"0.13.1"},"fixture_digests":{"component-build-manifest":manifest},"binary_digests":{"razen-component-runner":digest},"lockfile_sha256":digest,"component_lockfile_sha256":digest,"guest_package_manifest_sha256":digest,"provisioning_sha256":digest,"effective_config_sha256":digest,"seccomp_sha256":digest,"wit_sha256":digest})).unwrap();
        for name in [
            "fixture-valid",
            "fixture-loop",
            "fixture-grow",
            "fixture-output",
            "fixture-host-call",
            "fixture-denied-access",
        ] {
            environment
                .fixture_digests
                .insert(CatalogId::parse(name).unwrap(), digest);
        }
        (build, environment, manifest)
    }
    #[test]
    fn replacement_manifest_runner_every_variant_and_tool_pins_cannot_replace_frozen_run_build() {
        let (build, environment, manifest) = build_fixture();
        verify_component_environment(&build, &environment, manifest).unwrap();
        assert!(
            verify_component_environment(&build, &environment, Digest::of(b"rebuilt manifest"))
                .is_err()
        );
        for field in ["runner_sha256", "rust", "wasmtime", "wit_bindgen"] {
            let mut changed = build.clone();
            changed[field] = if field == "runner_sha256" {
                json!(Digest::of(b"replacement binary"))
            } else {
                json!("99.0.0")
            };
            assert!(verify_component_environment(&changed, &environment, manifest).is_err());
        }
        for index in 0..6 {
            let mut changed = build.clone();
            changed["variants"][index]["sha256"] = json!(Digest::of(b"replacement wasm"));
            assert!(verify_component_environment(&changed, &environment, manifest).is_err());
        }
    }
    #[test]
    fn apt_api_facts_preserve_exact_debian_identity_without_invented_license_or_repository_trust() {
        let digest = Digest::of(b"CONTROLLEDGATEFIXTURE original");
        let facts = json!({"parser":"python3-apt","parser_version":"3.0.0","name":"libstdc++6","version":"1:14.2.0-19","architecture":"arm64","installed":"1:14.2.0-19","candidate":"1:14.2.0-19","candidate_origins":[{"origin":"Debian","archive":"trixie","site":"snapshot.debian.org","trusted":true}],"filename":"pool/main/g/gcc-14/libstdc++6_14.2.0-19_arm64.deb","sha256":digest,"copyright_raw_sha256":digest,"policy_raw_sha256":digest,"metadata_raw_sha256":digest,"license_expression":"NOASSERTION","license_reference":"original-installed-package-copyright"});
        let mut facts = facts;
        facts["checked_at"] = json!("2026-11-16T12:00:00Z");
        serde_json::from_value::<GuestPackageFacts>(facts.clone())
            .unwrap()
            .validate()
            .unwrap();
        let mut local = facts.clone();
        local["candidate_origins"]
            .as_array_mut()
            .unwrap()
            .push(json!({"origin":"","archive":"now","site":"","trusted":false}));
        serde_json::from_value::<GuestPackageFacts>(local)
            .unwrap()
            .validate()
            .unwrap();
        let mut observation = json!({"parser_facts":facts,"name":"libstdc++6","source_url":"https://snapshot.debian.org/archive/debian/20261112T000000Z/","checked_at":"2026-11-16T12:00:00Z","selected_version":"1:14.2.0-19","latest_stable_observed":"1:14.2.0-19","architecture":"arm64","published_deb_sha256":digest,"copyright_raw_sha256":digest,"policy_raw_sha256":digest,"metadata_raw_sha256":digest,"facts_raw_sha256":digest,"license_expression":"NOASSERTION","copyright":"Copyright Example Authors; License: GPL-2+","policy":"Candidate source unavailable in this controlled policy fixture","package_metadata":"Package: libstdc++6\nDescription: a folded\n control field remains original private capture\n"});
        for (field, key) in [
            ("copyright", "copyright_public_sha256"),
            ("policy", "policy_public_sha256"),
            ("package_metadata", "metadata_public_sha256"),
        ] {
            observation[key] = json!(Digest::of(text(&observation, field).unwrap().as_bytes()));
        }
        verify_guest_observation(&observation).unwrap();
        for (field, key) in [
            ("copyright", "copyright_public_sha256"),
            ("policy", "policy_public_sha256"),
            ("package_metadata", "metadata_public_sha256"),
        ] {
            let mut leaked = observation.clone();
            leaked[field] = json!("Private build at /var/folders/person/cache");
            leaked[key] = json!(Digest::of(text(&leaked, field).unwrap().as_bytes()));
            assert!(verify_guest_observation(&leaked).is_err());
        }
        for field in ["filename", "license_expression", "installed"] {
            let mut changed = facts.clone();
            changed[field] = match field {
                "filename" => json!("../private.deb"),
                "license_expression" => json!("MIT"),
                _ => json!("1:14.2.0-18"),
            };
            assert!(
                serde_json::from_value::<GuestPackageFacts>(changed)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
        let mut changed = facts;
        changed["candidate_origins"][0]["trusted"] = json!(false);
        assert!(
            serde_json::from_value::<GuestPackageFacts>(changed)
                .unwrap()
                .validate()
                .is_err()
        );
    }

    #[test]
    fn real_measurements_follow_canonical_http_output_to_the_exact_result_artifact() {
        let fixture = crate::transport_test_fixtures::Fixture::new();
        fixture.execute("NET-01");
        let artifact = fixture
            .host
            .evidence
            .artifacts()
            .unwrap()
            .into_iter()
            .find(|artifact| artifact.kind.as_str() == "transport-measurements")
            .unwrap();
        let mut measured: Measurements = serde_json::from_slice(
            &fixture
                .host
                .evidence
                .read_artifact(artifact.project_id, artifact.artifact_id, MAX_BODY_BYTES)
                .unwrap(),
        )
        .unwrap();
        // Only the identity context is controlled; all samples, invocations and artifacts
        // above came from actual receiver exchanges, never fabricated runtime observations.
        let digest = Digest::of(b"controlled measurement-consumer context");
        let run = Run {
            run_id: fixture.host.workspace.run_id(),
            contract_version: ContractVersion::V0_1_0,
            profile_id: fixture.profile.config().profile_id.clone(),
            profile_sha256: fixture.profile.sha256(),
            clock_epoch_id: EntityId::new(),
            started_at: AuditTime::now(),
            finished_at: None,
            environment: RunEnvironment {
                hardware_model: "controlled consumer context".to_owned(),
                logical_cpus: WireInt::new(1).unwrap(),
                memory_mib: WireInt::new(1).unwrap(),
                os: "macOS".to_owned(),
                os_version: "controlled".to_owned(),
                arch: "arm64".to_owned(),
                os_build: "controlled".to_owned(),
                kernel: "controlled".to_owned(),
                filesystem: "controlled".to_owned(),
                storage: "controlled".to_owned(),
                component_target: "wasm32-wasip2".to_owned(),
                backend: "controlled".to_owned(),
                isolation_status: IsolationStatus::NotRequired,
                guest_os: "controlled".to_owned(),
                image_digest: crate::domain::proofs::ImageDigest::parse(
                    &fixture.profile.config().external_runner.image_digest,
                )
                .unwrap(),
                dependency_versions: BTreeMap::from([(
                    CatalogId::parse("rust").unwrap(),
                    VersionPin::parse("1.100.0").unwrap(),
                )]),
                fixture_digests: BTreeMap::from([(
                    CatalogId::parse("transport").unwrap(),
                    measured.fixture_sha256,
                )]),
                binary_digests: BTreeMap::from([(
                    CatalogId::parse("razen-engine").unwrap(),
                    fixture.host.provider_digest,
                )]),
                lockfile_sha256: digest,
                component_lockfile_sha256: digest,
                guest_package_manifest_sha256: None,
                provisioning_sha256: None,
                effective_config_sha256: None,
                seccomp_sha256: None,
                wit_sha256: digest,
            },
            dependency_record_refs: Vec::new(),
            fixture_manifest_sha256: digest,
        };
        let check = |measured: &Measurements| {
            verify_measurement_origins(
                measured,
                &fixture.host.ledger,
                &fixture.host.evidence,
                &run,
                artifact.project_id,
            )
        };
        check(&measured).unwrap();
        assert_eq!(
            verify_measurement_origins(
                &measured,
                &fixture.host.ledger,
                &fixture.host.evidence,
                &run,
                EntityId::new(),
            )
            .unwrap_err()
            .code,
            ErrorCode::IntegrityError
        );
        let sample = measured.direct_samples[0].clone();
        let invocation = fixture
            .host
            .ledger
            .read_invocation(sample.invocation_id)
            .unwrap()
            .invocation;
        let output_id = invocation.output_ref.unwrap();
        assert_ne!(output_id, sample.result_artifact_id);
        measured.direct_samples[0].result_artifact_id = output_id;
        assert_eq!(
            check(&measured).unwrap_err().code,
            ErrorCode::IntegrityError
        );
        let original = fixture
            .host
            .evidence
            .read_artifact(
                artifact.project_id,
                sample.result_artifact_id,
                MAX_BODY_BYTES,
            )
            .unwrap();
        let alias = fixture
            .host
            .evidence
            .write_artifact(
                artifact.project_id,
                CatalogId::parse("http-send-result").unwrap(),
                sample.invocation_id,
                &original,
                RedactionStatus::Original,
            )
            .unwrap();
        measured.direct_samples[0].result_artifact_id = alias.artifact_id;
        assert_eq!(
            check(&measured).unwrap_err().code,
            ErrorCode::IntegrityError
        );
    }
}
