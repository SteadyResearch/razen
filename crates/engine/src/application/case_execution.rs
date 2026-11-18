//! Trusted fixture-harness execution, never a guest-callable or auto-approved provider.
use std::collections::BTreeSet;
use std::fs::Metadata;
use std::io::{self, Read, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};
use std::time::Duration;

use serde::Serialize;

use super::admission::{EffectPermit, PreparedCall, TrustedBinding};
use super::effect_meter::EffectMeter;
use super::profile::LoadedProfile;
use super::proof_host::ProofHost;
use super::suites::{CaseObservation, contracts};
use crate::adapters::ledger::RegisteredTool;
use crate::domain::authority::{ApprovalGrant, Effect, RetryClass, ToolDescriptor};
use crate::domain::evidence::{EvidenceRef, RedactionStatus};
use crate::domain::proofs::{CaseStatus, ProofCase, ProofResult as CaseResult};
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, Usage, WireInt,
};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult, Retryability};

const TOOL: &str = "proof.case.execute";
const MAX_EVIDENCE_REFS: usize = 128;

#[derive(Serialize)]
struct CaseInput<'a> {
    schema_version: ContractVersion,
    case_id: &'a CatalogId,
    profile_id: &'a CatalogId,
    profile_sha256: Digest,
    fixture_manifest_sha256: Digest,
    invocation_id: EntityId,
    actor_ref: EntityId,
    user_id: EntityId,
    project_id: EntityId,
    investigation_id: EntityId,
    session_id: EntityId,
    identity_id: EntityId,
    budget_id: EntityId,
    provider_digest: Digest,
    scope_revision: WireInt,
    control_revision: WireInt,
}

/// Execute completed fixture handlers under an explicit trusted harness approval.
/// Provider completion records actual execution; the returned proof verdict may fail.
pub fn execute(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo_root: &Path,
    case: &ProofCase,
    fixture_manifest_sha256: Digest,
) -> ProofResult<CaseResult> {
    let result = execute_inner(host, profile, repo_root, case, fixture_manifest_sha256);
    if result
        .as_ref()
        .is_err_and(|error| error.code == ErrorCode::IntegrityError)
    {
        host.admission.invalidate_integrity();
    }
    result
}

fn execute_inner(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo_root: &Path,
    case: &ProofCase,
    fixture_manifest_sha256: Digest,
) -> ProofResult<CaseResult> {
    // Validate the closed inventory before any run mutation or provider admission.
    case.validate()?;
    host.admission.check_integrity()?;
    let tool = register(host, profile)?;
    let mut spec = host.local_spec();
    spec.allowed_tools = vec![tool.descriptor.tool_id.clone()];
    spec.permissions = tool.descriptor.permissions.clone();
    let binding = host.admission.bind(spec)?;
    let invocation_id = EntityId::new();
    let call = prepare(
        host,
        profile,
        case,
        fixture_manifest_sha256,
        &binding,
        invocation_id,
        &tool,
    )?;
    approve(host, &binding, &call)?;
    host.admission.reserve(&binding, &call)?;
    let permit = host.admission.begin_effect(&binding, invocation_id)?;
    let mut meter = EffectMeter::start();
    let provided = provide(
        &ExecutionContext {
            host,
            profile,
            repo_root,
        },
        case,
        &binding,
        &permit,
        &call.requested,
        &mut meter,
    );
    let usage = match meter.usage() {
        Ok(usage) => usage,
        Err(error) => {
            // Unrepresentable accounting cannot justify releasing an uncertain hold.
            host.admission.invalidate_integrity();
            return Err(error.with_invocation(invocation_id));
        }
    };
    match provided {
        Err(error) => fail(host, &binding, permit, usage, meter.write_pending, error),
        Ok((observation, evidence_refs, output_ref)) => {
            if let Err(error) = within_limits(&usage, &call.requested) {
                return fail(host, &binding, permit, usage, false, error);
            }
            let passed = observation.observed.iter().all(|(_, value)| value);
            let error = (!passed).then(|| {
                ProofError::new(
                    ErrorCode::OutputInvalid,
                    "Executed proof observations do not satisfy every required assertion",
                )
                .with_invocation(invocation_id)
            });
            let result = CaseResult {
                run_id: host.workspace.run_id(),
                case_id: observation.case_id,
                status: if passed {
                    CaseStatus::Passed
                } else {
                    CaseStatus::Failed
                },
                expected: case.expected.clone(),
                observed: observation.observed,
                evidence_refs,
                elapsed_us: usage.elapsed_us,
                usage,
                error,
            };
            if let Err(error) = result.validate() {
                return fail(host, &binding, permit, usage, false, error);
            }
            host.admission
                .complete(&binding, permit, usage, Some(output_ref))?;
            Ok(result)
        }
    }
}

fn limits(profile: &LoadedProfile) -> ProofResult<Usage> {
    let config = profile.config();
    // Admission covers complete bounded campaigns, not a single guest/request.
    let elapsed_us: u64 = execution_deadline(profile)?
        .as_micros()
        .try_into()
        .map_err(|_| budget())?;
    // Process-wide CPU metering conservatively includes concurrent host work.
    let cpus = std::thread::available_parallelism().map_err(|_| {
        ProofError::new(
            ErrorCode::ProviderUnavailable,
            "Native CPU accounting capacity is unavailable",
        )
    })?;
    let cpu_us = elapsed_us
        .checked_mul(u64::try_from(cpus.get()).map_err(|_| budget())?)
        .ok_or_else(budget)?;
    Ok(Usage {
        units: WireInt::new(1)?,
        bytes: config.protocol.invocation_output_limit_bytes,
        cpu_us: WireInt::new(cpu_us)?,
        elapsed_us: WireInt::new(elapsed_us)?,
    })
}

pub(crate) fn execution_deadline(profile: &LoadedProfile) -> ProofResult<Duration> {
    let config = profile.config();
    let guest_ms = config
        .external_runner
        .wall_deadline_ms
        .get()
        .checked_add(30_000)
        .and_then(|value| value.checked_mul(64))
        .ok_or_else(budget)?;
    let exchanges = config
        .measurement
        .latency_warmup_exchanges
        .get()
        .checked_add(config.measurement.latency_sample_exchanges.get())
        .and_then(|value| value.checked_mul(2))
        .and_then(|value| value.checked_add(config.transport.requests_per_case.get()))
        .ok_or_else(budget)?;
    let transport_ms = exchanges
        .checked_mul(config.transport.request_timeout_ms.get())
        .ok_or_else(budget)?;
    let elapsed_ms = config
        .parser_fuzz
        .deadline_ms
        .get()
        .checked_mul(2)
        .and_then(|value| value.checked_add(guest_ms))
        .and_then(|value| value.checked_add(transport_ms))
        .and_then(|value| value.checked_add(config.control.ack_deadline_ms.get()))
        .ok_or_else(budget)?;
    Ok(Duration::from_millis(elapsed_ms))
}

fn register(host: &ProofHost, profile: &LoadedProfile) -> ProofResult<RegisteredTool> {
    let tool = RegisteredTool {
        provider_digest: host.provider_digest,
        descriptor: ToolDescriptor {
            tool_id: CatalogId::parse(TOOL)?,
            version: ContractVersion::V0_1_0,
            input_contract: CatalogId::parse("proof.case.execute.input")?,
            output_contract: CatalogId::parse("proof.case.execute.output")?,
            effect: Effect::LocalWrite,
            permissions: vec![CatalogId::parse(TOOL)?],
            limits: limits(profile)?,
            retry_class: RetryClass::NonRetryable,
        },
    };
    host.ledger
        .transaction(|tx| match tx.find_tool(&tool.descriptor.tool_id)? {
            Some(existing) if existing == tool => Ok(()),
            Some(_) => Err(integrity()),
            None => tx.insert_tool(&tool),
        })?;
    Ok(tool)
}

fn prepare(
    host: &ProofHost,
    profile: &LoadedProfile,
    case: &ProofCase,
    fixture_manifest_sha256: Digest,
    binding: &TrustedBinding,
    invocation_id: EntityId,
    tool: &RegisteredTool,
) -> ProofResult<PreparedCall> {
    let input = CaseInput {
        schema_version: ContractVersion::V0_1_0,
        case_id: &case.case_id,
        profile_id: &profile.config().profile_id,
        profile_sha256: profile.sha256(),
        fixture_manifest_sha256,
        invocation_id,
        actor_ref: binding.actor_ref(),
        user_id: binding.user_id(),
        project_id: binding.project_id(),
        investigation_id: binding.investigation_id(),
        session_id: binding.session_id(),
        identity_id: binding.identity_id(),
        budget_id: binding.budget_id(),
        provider_digest: binding.provider_digest(),
        scope_revision: binding.scope_revision(),
        control_revision: binding.control_revision(),
    };
    let bytes = encode(
        &input,
        usize::try_from(profile.config().protocol.message_limit_bytes.get())
            .map_err(|_| budget())?,
    )?;
    let artifact = host
        .evidence
        .write_artifact(
            binding.project_id(),
            CatalogId::parse("case-execution-input")?,
            invocation_id,
            &bytes,
            RedactionStatus::Original,
        )
        .map_err(|error| error.with_invocation(invocation_id))?;
    Ok(PreparedCall {
        invocation_id,
        call_id: EntityId::new(),
        tool_id: tool.descriptor.tool_id.clone(),
        tool_version: tool.descriptor.version,
        input_ref: artifact.artifact_id,
        input_sha256: artifact.sha256,
        input_revision: WireInt::ZERO,
        source_control_revision: binding.control_revision(),
        requested: tool.descriptor.limits,
    })
}

fn approve(host: &ProofHost, binding: &TrustedBinding, call: &PreparedCall) -> ProofResult<()> {
    // This entire entry point is an explicit trusted fixture-harness action, not
    // a Registry handler or an approval inferred from an untrusted tool request.
    host.admission.session(binding)?;
    let expiry = call
        .requested
        .elapsed_us
        .get()
        .checked_add(call.requested.elapsed_us.get())
        .ok_or_else(budget)?;
    host.ledger.insert_grant(&ApprovalGrant {
        grant_id: EntityId::new(),
        project_id: binding.project_id(),
        tool_id: call.tool_id.clone(),
        tool_version: call.tool_version,
        provider_digest: binding.provider_digest(),
        scope_revision: binding.scope_revision(),
        identity_id: binding.identity_id(),
        bounded_input_sha256: call.input_sha256,
        limits: call.requested,
        expires_at: AuditTime::now().checked_add(Duration::from_micros(expiry))?,
        revoked: false,
    })
}

pub(crate) struct ExecutionContext<'a> {
    pub host: &'a ProofHost,
    pub profile: &'a LoadedProfile,
    pub repo_root: &'a Path,
}

fn provide(
    context: &ExecutionContext<'_>,
    case: &ProofCase,
    binding: &TrustedBinding,
    permit: &EffectPermit,
    maximum: &Usage,
    meter: &mut EffectMeter,
) -> ProofResult<(CaseObservation, Vec<EvidenceRef>, EntityId)> {
    let &ExecutionContext {
        host,
        profile,
        repo_root,
    } = context;
    host.admission.recheck_effect(binding, permit)?;
    meter.dispatched = true;
    let executed = match case
        .case_id
        .as_str()
        .split_once('-')
        .map(|(prefix, _)| prefix)
    {
        Some("CON") => contracts::execute(host, profile, repo_root, &case.case_id),
        Some("NET") => super::suites::transport::execute(host, profile, repo_root, &case.case_id),
        Some("CMP") => super::suites::components::execute(host, profile, repo_root, &case.case_id),
        Some("RUN") => super::suites::runtime::execute(host, profile, repo_root, &case.case_id),
        Some("REC") => super::suites::recovery::execute(host, profile, repo_root, &case.case_id),
        Some("EXIT") => super::suites::exit::execute(host, profile, repo_root, &case.case_id),
        _ => return Err(invalid_output()),
    };
    let observation = match executed {
        Ok(observation) => observation,
        Err(error) => {
            // The parser handler persists its own replay files. Its filesystem
            // OutputInvalid cannot establish whether a write became durable.
            // No such ambiguity is inferred for a known parser/fixture denial.
            if case.case_id.as_str() == "CON-02" && error.code == ErrorCode::OutputInvalid {
                meter.write_pending = true;
            }
            return Err(error);
        }
    };
    validate_observation(case, &observation)?;
    within_limits(&meter.usage()?, maximum)?;
    let remaining = remaining_bytes(meter, maximum)?;
    let report = encode(&observation.report, remaining)?;
    let report_ref = publish(
        host,
        binding,
        permit,
        "case-execution-report",
        &report,
        maximum,
        meter,
    )?;
    let EvidenceRef::Artifact {
        artifact_id: output_ref,
        ..
    } = report_ref
    else {
        return Err(integrity());
    };
    let mut references = Vec::with_capacity(observation.attachment_paths.len() + 1);
    references.push(report_ref);
    for path in &observation.attachment_paths {
        within_limits(&meter.usage()?, maximum)?;
        host.admission.recheck_effect(binding, permit)?;
        let bytes = read_attachment(host, path, remaining_bytes(meter, maximum)?)?;
        references.push(publish(
            host,
            binding,
            permit,
            "case-execution-attachment",
            &bytes,
            maximum,
            meter,
        )?);
    }
    Ok((observation, references, output_ref))
}

fn validate_observation(case: &ProofCase, observation: &CaseObservation) -> ProofResult<()> {
    if observation.case_id != case.case_id
        || observation.observed.iter().count() != case.expected.iter().count()
        || observation
            .observed
            .iter()
            .any(|(name, _)| case.expected.get(name).is_none())
        || !observation.report.is_object()
        || observation.attachment_paths.len() >= MAX_EVIDENCE_REFS
    {
        return Err(invalid_output());
    }
    let mut paths = BTreeSet::new();
    for path in &observation.attachment_paths {
        if path.as_os_str().is_empty()
            || !path
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
            || !paths.insert(path)
        {
            return Err(invalid_output());
        }
    }
    Ok(())
}

fn publish(
    host: &ProofHost,
    binding: &TrustedBinding,
    permit: &EffectPermit,
    kind: &str,
    bytes: &[u8],
    maximum: &Usage,
    meter: &mut EffectMeter,
) -> ProofResult<EvidenceRef> {
    if bytes.len() > remaining_bytes(meter, maximum)? {
        return Err(budget());
    }
    within_limits(&meter.usage()?, maximum)?;
    host.admission.recheck_effect(binding, permit)?;
    let kind = CatalogId::parse(kind)?;
    // Count the bytes actually handed to evidence publication, including an
    // attempt whose durability subsequently becomes uncertain. Never drop them.
    meter.add_bytes(bytes.len())?;
    meter.write_pending = true;
    let artifact = host.evidence.write_artifact(
        binding.project_id(),
        kind,
        permit.invocation_id(),
        bytes,
        RedactionStatus::Original,
    )?;
    meter.write_pending = false;
    let reference = EvidenceRef::Artifact {
        artifact_id: artifact.artifact_id,
        sha256: artifact.sha256,
        range: None,
    };
    reference.validate_artifact(binding.project_id(), &artifact, bytes)?;
    host.evidence
        .verify_artifact(binding.project_id(), artifact.artifact_id)?;
    Ok(reference)
}

fn read_attachment(host: &ProofHost, path: &Path, limit: usize) -> ProofResult<Vec<u8>> {
    // Every component is opened through the owned directory descriptor with
    // O_NOFOLLOW; no path-based arbitrary host read is permitted here.
    let mut file = host.workspace.open_readonly(path)?;
    let before = file.metadata().map_err(|_| integrity())?;
    let length = usize::try_from(before.len()).map_err(|_| budget())?;
    if length > limit {
        return Err(budget());
    }
    let mut bytes = vec![0; length];
    file.read_exact(&mut bytes).map_err(|_| integrity())?;
    let mut extra = [0];
    if file.read(&mut extra).map_err(|_| integrity())? != 0 {
        return Err(integrity());
    }
    let after = file.metadata().map_err(|_| integrity())?;
    let named = host
        .workspace
        .open_readonly(path)?
        .metadata()
        .map_err(|_| integrity())?;
    if !same_file(&before, &after) || !same_file(&before, &named) {
        return Err(integrity());
    }
    Ok(bytes)
}

fn same_file(first: &Metadata, second: &Metadata) -> bool {
    first.dev() == second.dev()
        && first.ino() == second.ino()
        && first.len() == second.len()
        && first.uid() == second.uid()
        && first.mode() == second.mode()
        && first.nlink() == second.nlink()
        && first.mtime() == second.mtime()
        && first.mtime_nsec() == second.mtime_nsec()
        && first.ctime() == second.ctime()
        && first.ctime_nsec() == second.ctime_nsec()
}

fn remaining_bytes(meter: &EffectMeter, maximum: &Usage) -> ProofResult<usize> {
    usize::try_from(
        maximum
            .bytes
            .get()
            .checked_sub(meter.bytes)
            .ok_or_else(budget)?,
    )
    .map_err(|_| budget())
}

fn within_limits(actual: &Usage, maximum: &Usage) -> ProofResult<()> {
    if actual.units > maximum.units
        || actual.bytes > maximum.bytes
        || actual.cpu_us > maximum.cpu_us
        || actual.elapsed_us > maximum.elapsed_us
    {
        return Err(budget());
    }
    Ok(())
}

fn fail(
    host: &ProofHost,
    binding: &TrustedBinding,
    permit: EffectPermit,
    usage: Usage,
    write_pending: bool,
    error: ProofError,
) -> ProofResult<CaseResult> {
    let invocation_id = permit.invocation_id();
    if error.code == ErrorCode::IntegrityError {
        host.admission.invalidate_integrity();
        return Err(error.with_invocation(invocation_id));
    }
    let nested_unknown = match error.invocation_id.filter(|id| *id != invocation_id) {
        Some(id) => {
            host.ledger.read_invocation(id)?.invocation.state
                == crate::domain::values::InvocationState::OutcomeUnknown
        }
        None => false,
    };
    if (write_pending && error.code == ErrorCode::OutputInvalid)
        || error.code == ErrorCode::OutcomeUnknown
        || error.retryability == Retryability::Reconcile
        || nested_unknown
    {
        let unknown = ProofError::new(
            ErrorCode::OutcomeUnknown,
            "Case evidence durability requires reconciliation",
        )
        .with_invocation(invocation_id);
        host.admission
            .outcome_unknown(binding, permit, usage, unknown.clone())?;
        return Err(unknown);
    }
    let invocation = host.admission.fail(binding, permit, usage, error)?;
    Err(invocation.error.ok_or_else(integrity)?)
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("bounded case JSON output exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn encode(value: &impl Serialize, limit: usize) -> ProofResult<Vec<u8>> {
    let mut buffer = BoundedBuffer {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut buffer, value).map_err(|_| budget())?;
    Ok(buffer.bytes)
}

fn invalid_output() -> ProofError {
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Case provider returned mismatched observations or unsafe attachment paths",
    )
}

fn budget() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Case execution exceeds its admitted finite resources",
    )
}

fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Case execution provider or immutable evidence failed integrity checks",
    )
}
