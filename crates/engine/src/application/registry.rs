//! Host-configured providers share one persistent admission boundary. Decoded
//! IDs select records; they never confer grant or transport configuration authority.
use std::io::{self, Write};
use std::sync::{Arc, Mutex, MutexGuard};

use base64::display::Base64Display;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize, Serializer};

use super::admission::{EffectPermit, HostAdmission, PreparedCall, TrustedBinding};
use super::effect_meter::EffectMeter;
use super::http_send::{HttpSendInput, HttpSendProvider, PreparedHttpSend};
use super::profile::LoadedProfile;
use crate::adapters::evidence_store::{EvidenceStore, SnapshotReader};
use crate::adapters::ledger::{RegisteredTool, StoredInvocation};
use crate::adapters::transport::TransportConfig;
use crate::domain::authority::{Effect, RetryClass, ToolDescriptor};
use crate::domain::evidence::{
    EvidenceRange, EvidenceRef, ObservationProposal, ObservationStatus, RedactionStatus,
    bounded_text,
};
use crate::domain::invocation::Invocation;
use crate::domain::knowledge::{MemoryItem, MemoryLevel};
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage, WireInt,
};
use crate::protocol::contracts::{CanonicalFixtures, ContractRecord};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use crate::protocol::messages::{ToolRequest, ToolResult};

const VERSION: ContractVersion = ContractVersion::V0_1_0;
const SNAPSHOT_READ: &str = "traffic.snapshot.read";
const OBSERVATION_PROPOSE: &str = "observation.propose";
const CONTEXT_READ: &str = "context.read";

#[derive(Clone, Copy)]
struct Limits {
    input: usize,
    output: usize,
    chunk: WireInt,
    requested: Usage,
}

impl Limits {
    fn from_profile(profile: &LoadedProfile) -> ProofResult<Self> {
        let config = profile.config();
        let time_us = config
            .component
            .invocation_deadline_ms
            .get()
            .checked_mul(1000)
            .ok_or_else(budget)?;
        Ok(Self {
            input: usize::try_from(config.protocol.message_limit_bytes.get())
                .map_err(|_| budget())?,
            output: usize::try_from(config.protocol.invocation_output_limit_bytes.get())
                .map_err(|_| budget())?,
            chunk: config.transport.chunk_limit_bytes,
            requested: Usage {
                units: WireInt::new(1)?,
                bytes: config.protocol.invocation_output_limit_bytes,
                cpu_us: WireInt::new(time_us)?,
                elapsed_us: WireInt::new(time_us)?,
            },
        })
    }
}

/// Host-only preparation. In particular neither its binding nor its verified FD
/// can be supplied by a deserialized runtime message or cloned for redispatch.
pub struct PreparedInvocation(PreparedKind);

enum PreparedKind {
    Local {
        binding: Arc<TrustedBinding>,
        call: PreparedCall,
        operation: PreparedOperation,
    },
    Http(PreparedHttpSend),
}

impl PreparedInvocation {
    pub fn call(&self) -> &PreparedCall {
        match &self.0 {
            PreparedKind::Local { call, .. } => call,
            PreparedKind::Http(http) => http.call(),
        }
    }
}

enum PreparedOperation {
    Duplicate,
    Snapshot {
        input: SnapshotInput,
        reader: SnapshotReader,
    },
    Observation {
        input: ObservationInput,
        reader: SnapshotReader,
        reference: EvidenceRef,
    },
    Context(ContextInput),
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotInput {
    snapshot_id: EntityId,
    revision: WireInt,
    offset: WireInt,
    max_bytes: WireInt,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObservationInput {
    rule_id: CatalogId,
    #[serde(deserialize_with = "bounded_text::<_, 256>")]
    title: String,
    snapshot_id: EntityId,
    revision: WireInt,
    range_start: WireInt,
    range_end: WireInt,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ContextKind {
    Investigation,
    MemoryExamples,
    AssetExamples,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ContextInput {
    kind: ContextKind,
    record_id: EntityId,
}

enum Input {
    Snapshot(SnapshotInput),
    Observation(ObservationInput),
    Context(ContextInput),
}

impl Input {
    fn parse(request: &ToolRequest<'_>, limits: Limits) -> ProofResult<Self> {
        if request.input.get().len() > limits.input {
            return Err(invalid());
        }
        let bytes = request.input.get().as_bytes();
        match request.tool_id.as_str() {
            SNAPSHOT_READ => serde_json::from_slice(bytes)
                .map(Self::Snapshot)
                .map_err(|_| invalid()),
            OBSERVATION_PROPOSE => serde_json::from_slice(bytes)
                .map(Self::Observation)
                .map_err(|_| invalid()),
            CONTEXT_READ => serde_json::from_slice(bytes)
                .map(Self::Context)
                .map_err(|_| invalid()),
            _ => Err(ProofError::new(
                ErrorCode::UnknownTool,
                "The tool is not in the reviewed local catalog",
            )),
        }
    }

    fn canonical(&self, limit: usize) -> ProofResult<Vec<u8>> {
        match self {
            Self::Snapshot(input) => encode(input, limit),
            Self::Observation(input) => encode(input, limit),
            Self::Context(input) => encode(input, limit),
        }
    }

    fn revision(&self, binding: &TrustedBinding) -> WireInt {
        match self {
            Self::Snapshot(input) => input.revision,
            Self::Observation(input) => input.revision,
            Self::Context(_) => binding.control_revision(),
        }
    }
}

pub struct Registry {
    admission: Arc<HostAdmission>,
    evidence: Arc<EvidenceStore>,
    fixtures: Arc<CanonicalFixtures>,
    limits: Limits,
    preparation: Mutex<()>,
    http: Option<HttpSendProvider>,
}

impl Registry {
    pub fn builtin_tools(
        provider_digest: Digest,
        profile: &LoadedProfile,
    ) -> ProofResult<Vec<RegisteredTool>> {
        let limits = Limits::from_profile(profile)?;
        [
            (
                SNAPSHOT_READ,
                "snapshot.read",
                "traffic.snapshot.read.input",
                "traffic.snapshot.read.output",
                Effect::LocalRead,
                RetryClass::SafeRead,
            ),
            (
                OBSERVATION_PROPOSE,
                "observation.propose",
                "observation.propose.input",
                "observation.propose.output",
                Effect::LocalWrite,
                RetryClass::Deduplicated,
            ),
            (
                CONTEXT_READ,
                "context.read",
                "context.read.input",
                "context.read.output",
                Effect::LocalRead,
                RetryClass::SafeRead,
            ),
        ]
        .into_iter()
        .map(
            |(id, permission, input_contract, output_contract, effect, retry_class)| {
                Ok(RegisteredTool {
                    provider_digest,
                    descriptor: ToolDescriptor {
                        tool_id: CatalogId::parse(id)?,
                        version: VERSION,
                        input_contract: CatalogId::parse(input_contract)?,
                        output_contract: CatalogId::parse(output_contract)?,
                        effect,
                        permissions: vec![CatalogId::parse(permission)?],
                        limits: limits.requested,
                        retry_class,
                    },
                })
            },
        )
        .collect()
    }

    pub fn new(
        admission: Arc<HostAdmission>,
        evidence: Arc<EvidenceStore>,
        fixtures: CanonicalFixtures,
        profile: &LoadedProfile,
    ) -> ProofResult<Self> {
        if fixtures
            .records()
            .iter()
            .filter(|d| matches!(&d.record, ContractRecord::MemoryItem(_)))
            .count()
            > 256
        {
            return Err(invalid());
        }
        Ok(Self {
            admission,
            evidence,
            fixtures: Arc::new(fixtures),
            limits: Limits::from_profile(profile)?,
            preparation: Mutex::new(()),
            http: None,
        })
    }

    /// A trusted host installs exactly one immutable network configuration.
    pub fn with_http(
        admission: Arc<HostAdmission>,
        evidence: Arc<EvidenceStore>,
        fixtures: CanonicalFixtures,
        profile: &LoadedProfile,
        provider: HttpSendProvider,
    ) -> ProofResult<Self> {
        if !provider.matches_host(&admission, &evidence) {
            return Err(denied());
        }
        let mut registry = Self::new(admission, evidence, fixtures, profile)?;
        registry.http = Some(provider);
        Ok(registry)
    }

    pub(crate) fn with_transport(
        &self,
        profile: &LoadedProfile,
        config: TransportConfig,
    ) -> ProofResult<Self> {
        Ok(Self {
            admission: Arc::clone(&self.admission),
            evidence: Arc::clone(&self.evidence),
            fixtures: Arc::clone(&self.fixtures),
            limits: self.limits,
            preparation: Mutex::new(()),
            http: Some(HttpSendProvider::new(
                Arc::clone(&self.admission),
                Arc::clone(&self.evidence),
                profile,
                config,
            )?),
        })
    }

    pub(crate) fn http_provider(&self) -> ProofResult<&HttpSendProvider> {
        self.http.as_ref().ok_or_else(|| {
            ProofError::new(
                ErrorCode::ProviderUnavailable,
                "The network provider is not configured by the host",
            )
        })
    }

    /// Schema examples only; no fixture grant or history is live authority.
    pub fn contract_examples(&self) -> &CanonicalFixtures {
        &self.fixtures
    }

    // Only input publication is serialized. No provider work or control wait holds this lock.
    fn preparation_guard(&self) -> ProofResult<MutexGuard<'_, ()>> {
        self.preparation.lock().map_err(|_| {
            self.admission.invalidate_integrity();
            integrity()
        })
    }

    pub fn prepare(
        &self,
        binding: &Arc<TrustedBinding>,
        request: &ToolRequest<'_>,
    ) -> ProofResult<PreparedInvocation> {
        let _guard = self.preparation_guard()?;
        self.observe(self.prepare_inner(binding, request))
    }

    fn prepare_inner(
        &self,
        binding: &Arc<TrustedBinding>,
        request: &ToolRequest<'_>,
    ) -> ProofResult<PreparedInvocation> {
        self.healthy()?;
        if request.tool_id.as_str() == "http.send" {
            let provider = self.http_provider()?;
            if let Some(stored) = self
                .admission
                .existing_invocation(binding, request.call_id)?
                && stored.invocation.state == InvocationState::Rejected
                && let Some(error) = &stored.invocation.error
            {
                let rejection = encode(&self.rejected_input(request, error.code), 1024)?;
                if same_request(&stored, request, Digest::of(&rejection)) {
                    return Err(error.clone());
                }
            }
            if request.input.get().len() > self.limits.input {
                return Err(invalid());
            }
            let input: HttpSendInput =
                serde_json::from_str(request.input.get()).map_err(|_| invalid())?;
            return provider
                .prepare_request(
                    Arc::clone(binding),
                    request.call_id,
                    request.tool_version,
                    request.source_control_revision,
                    &input,
                )
                .map(|http| PreparedInvocation(PreparedKind::Http(http)));
        }
        let existing = self
            .admission
            .existing_invocation(binding, request.call_id)?;
        let input = Input::parse(request, self.limits)?;
        let bytes = input.canonical(self.limits.input)?;
        let revision = input.revision(binding);
        if let Some(stored) = existing {
            let digest = Digest::of(&bytes);
            if !same_request(&stored, request, digest)
                || stored.invocation.input_revision != revision
            {
                if let Some(error) = &stored.invocation.error {
                    let metadata = self.rejected_input(request, error.code);
                    let rejection = encode(&metadata, 1024)?;
                    if stored.invocation.state == InvocationState::Rejected
                        && same_request(&stored, request, Digest::of(&rejection))
                    {
                        return Err(error.clone());
                    }
                }
                return Err(invalid());
            }
            let requested = stored.requested;
            let invocation = stored.invocation;
            let operation = if matches!(
                invocation.state,
                InvocationState::Proposed | InvocationState::WaitingApproval
            ) {
                self.validate_input(binding, input)?
            } else {
                PreparedOperation::Duplicate
            };
            return Ok(PreparedInvocation(PreparedKind::Local {
                binding: Arc::clone(binding),
                call: PreparedCall {
                    invocation_id: invocation.invocation_id,
                    call_id: request.call_id,
                    tool_id: request.tool_id.clone(),
                    tool_version: request.tool_version,
                    input_ref: invocation.input_ref,
                    input_sha256: digest,
                    input_revision: revision,
                    source_control_revision: request.source_control_revision,
                    requested,
                },
                operation,
            }));
        }
        let operation = self.validate_input(binding, input)?;
        let invocation_id = EntityId::new();
        let artifact = self.evidence.write_artifact(
            binding.project_id(),
            CatalogId::parse("tool-input")?,
            invocation_id,
            &bytes,
            RedactionStatus::Original,
        )?;
        let call = PreparedCall {
            invocation_id,
            call_id: request.call_id,
            tool_id: request.tool_id.clone(),
            tool_version: request.tool_version,
            input_ref: artifact.artifact_id,
            input_sha256: artifact.sha256,
            input_revision: revision,
            source_control_revision: request.source_control_revision,
            requested: self.limits.requested,
        };
        self.admission.propose(binding, &call)?;
        Ok(PreparedInvocation(PreparedKind::Local {
            binding: Arc::clone(binding),
            call,
            operation,
        }))
    }

    fn validate_input(
        &self,
        binding: &TrustedBinding,
        input: Input,
    ) -> ProofResult<PreparedOperation> {
        match input {
            Input::Snapshot(input) => {
                if input.max_bytes > self.limits.chunk {
                    return Err(invalid());
                }
                let reader = self.evidence.snapshot_reader(
                    binding.project_id(),
                    input.snapshot_id,
                    input.revision,
                )?;
                if input.offset > reader.metadata().length_bytes {
                    return Err(invalid());
                }
                input
                    .offset
                    .checked_add(input.max_bytes)
                    .map_err(|_| invalid())?;
                Ok(PreparedOperation::Snapshot { input, reader })
            }
            Input::Observation(input) => {
                let reader = self.evidence.snapshot_reader(
                    binding.project_id(),
                    input.snapshot_id,
                    input.revision,
                )?;
                let reference = EvidenceRef::Snapshot {
                    snapshot_id: input.snapshot_id,
                    revision: input.revision,
                    sha256: reader.metadata().sha256,
                    range: Some(EvidenceRange::new(input.range_start, input.range_end)?),
                };
                reader.validate_reference(&reference)?;
                Ok(PreparedOperation::Observation {
                    input,
                    reader,
                    reference,
                })
            }
            Input::Context(input) => {
                self.validate_context(binding, &input)?;
                Ok(PreparedOperation::Context(input))
            }
        }
    }

    fn validate_context(&self, binding: &TrustedBinding, input: &ContextInput) -> ProofResult<()> {
        match input.kind {
            ContextKind::Investigation => {
                if input.record_id != binding.investigation_id() {
                    return Err(denied());
                }
                self.admission.session(binding)?;
            }
            ContextKind::MemoryExamples => {
                if input.record_id != binding.session_id() {
                    return Err(denied());
                }
                self.admission.session(binding)?;
            }
            ContextKind::AssetExamples => {
                self.owned_graph(binding, input.record_id)?;
            }
        }
        Ok(())
    }

    fn owned_graph(
        &self,
        binding: &TrustedBinding,
        id: EntityId,
    ) -> ProofResult<&crate::domain::knowledge::AssetGraph> {
        self.fixtures
            .records()
            .iter()
            .find_map(|d| match &d.record {
                ContractRecord::AssetGraph(graph)
                    if graph.graph_id == id && graph.project_id == binding.project_id() =>
                {
                    Some(graph)
                }
                _ => None,
            })
            .ok_or_else(denied)
    }

    pub fn execute(
        &self,
        binding: &Arc<TrustedBinding>,
        request: &ToolRequest<'_>,
    ) -> ProofResult<ToolResult> {
        let guard = self.preparation_guard()?;
        let prepared = match self.prepare_inner(binding, request) {
            Ok(prepared) => prepared,
            Err(error) if business_error(error.code) => {
                return self.observe(self.reject(binding, request, error));
            }
            Err(error) => return self.observe(Err(error)),
        };
        drop(guard);
        self.execute_prepared(binding, prepared)
    }

    fn reject(
        &self,
        binding: &TrustedBinding,
        request: &ToolRequest<'_>,
        error: ProofError,
    ) -> ProofResult<ToolResult> {
        self.healthy()?;
        let metadata = self.rejected_input(request, error.code);
        let bytes = encode(&metadata, 1024)?;
        if let Some(stored) = self
            .admission
            .existing_invocation(binding, request.call_id)?
        {
            let digest = Digest::of(&bytes);
            if !same_request(&stored, request, digest) {
                return Err(invalid());
            }
            return Ok(result(request.call_id, stored.invocation));
        }
        let invocation_id = EntityId::new();
        let artifact = self.evidence.write_artifact(
            binding.project_id(),
            CatalogId::parse("rejected-input")?,
            invocation_id,
            &bytes,
            RedactionStatus::Original,
        )?;
        let call = PreparedCall {
            invocation_id,
            call_id: request.call_id,
            tool_id: request.tool_id.clone(),
            tool_version: request.tool_version,
            input_ref: artifact.artifact_id,
            input_sha256: artifact.sha256,
            input_revision: WireInt::ZERO,
            source_control_revision: request.source_control_revision,
            requested: Usage::default(),
        };
        let invocation = self.admission.record_rejection(binding, &call, error)?;
        Ok(result(request.call_id, invocation))
    }

    fn rejected_input(&self, request: &ToolRequest<'_>, code: ErrorCode) -> RejectedInput {
        RejectedInput {
            original_input_sha256: Digest::of(request.input.get().as_bytes()),
            code,
            provider_configuration_id: if request.tool_id.as_str() == "http.send" {
                self.http.as_ref().map(HttpSendProvider::configuration_id)
            } else {
                None
            },
        }
    }

    pub fn execute_prepared(
        &self,
        binding: &Arc<TrustedBinding>,
        prepared: PreparedInvocation,
    ) -> ProofResult<ToolResult> {
        self.observe(self.execute_inner(binding, prepared))
    }

    fn execute_inner(
        &self,
        binding: &Arc<TrustedBinding>,
        prepared: PreparedInvocation,
    ) -> ProofResult<ToolResult> {
        self.healthy()?;
        let (prepared_binding, call, operation) = match prepared.0 {
            PreparedKind::Local {
                binding,
                call,
                operation,
            } => (binding, call, operation),
            PreparedKind::Http(http) => {
                if !Arc::ptr_eq(binding, http.binding()) {
                    return Err(denied());
                }
                let call_id = http.call().call_id;
                return self
                    .http_provider()?
                    .execute_invocation(http)
                    .map(|invocation| result(call_id, invocation));
            }
        };
        if !Arc::ptr_eq(binding, &prepared_binding) {
            return Err(denied());
        }
        if matches!(operation, PreparedOperation::Duplicate) {
            return self.existing_result(binding, &call);
        }
        let reserved = match self.admission.reserve(binding, &call) {
            Ok(invocation) => invocation,
            Err(error) => return self.admission_denial(binding, &call, error),
        };
        if reserved.state != InvocationState::Reserved
            || reserved.invocation_id != call.invocation_id
        {
            return Ok(result(call.call_id, reserved));
        }
        let permit = match self.admission.begin_effect(binding, reserved.invocation_id) {
            Ok(permit) => permit,
            Err(error) => return self.admission_denial(binding, &call, error),
        };
        let mut meter = EffectMeter::start();
        let output = self.provide(binding, &permit, operation, &mut meter);
        let usage = meter.usage()?;
        let overrun = usage.bytes > call.requested.bytes
            || usage.cpu_us > call.requested.cpu_us
            || usage.elapsed_us > call.requested.elapsed_us;
        let output = match output {
            Ok(_) if overrun => Err(budget()),
            Err(error) if overrun && business_error(error.code) => Err(budget()),
            other => other,
        };
        match output {
            Ok(output_ref) => {
                let invocation =
                    self.admission
                        .complete(binding, permit, usage, Some(output_ref))?;
                Ok(result(call.call_id, invocation))
            }
            Err(error) => {
                let fatal = !business_error(error.code);
                let invocation = if error.code == ErrorCode::OutputInvalid && meter.write_pending {
                    // A filesystem failure can occur after a catalog entry was
                    // written but before durability was acknowledged. Do not
                    // release that hold or assume the local effect was absent.
                    self.admission.outcome_unknown(
                        binding,
                        permit,
                        usage,
                        ProofError::new(
                            ErrorCode::OutcomeUnknown,
                            "Local evidence persistence requires reconciliation",
                        ),
                    )?
                } else {
                    self.admission.fail(binding, permit, usage, error.clone())?
                };
                if fatal {
                    return Err(error.with_invocation(invocation.invocation_id));
                }
                Ok(result(call.call_id, invocation))
            }
        }
    }

    fn existing_result(
        &self,
        binding: &TrustedBinding,
        call: &PreparedCall,
    ) -> ProofResult<ToolResult> {
        let stored = self
            .admission
            .existing_invocation(binding, call.call_id)?
            .ok_or_else(integrity)?;
        if !same_call(&stored, call) {
            return Err(invalid());
        }
        Ok(result(call.call_id, stored.invocation))
    }

    fn admission_denial(
        &self,
        binding: &TrustedBinding,
        call: &PreparedCall,
        error: ProofError,
    ) -> ProofResult<ToolResult> {
        if !business_error(error.code) {
            return Err(error);
        }
        let Some(stored) = self.admission.existing_invocation(binding, call.call_id)? else {
            return Err(error);
        };
        if !same_call(&stored, call) {
            return Err(invalid());
        }
        let concurrent_duplicate = stored.invocation.invocation_id != call.invocation_id
            && stored.invocation.state == InvocationState::Reserved;
        if stored.invocation.error.is_none()
            && !concurrent_duplicate
            && !matches!(
                stored.invocation.state,
                InvocationState::Sending
                    | InvocationState::Completed
                    | InvocationState::OutcomeUnknown
            )
        {
            return Err(error);
        }
        Ok(result(call.call_id, stored.invocation))
    }

    fn provide(
        &self,
        binding: &TrustedBinding,
        permit: &EffectPermit,
        operation: PreparedOperation,
        meter: &mut EffectMeter,
    ) -> ProofResult<EntityId> {
        self.admission.recheck_effect(binding, permit)?;
        // One actual local dispatch consumes one logical work unit. Timing and
        // exposed bytes below are measured, never estimated resource samples.
        meter.dispatched = true;
        let bytes = match operation {
            PreparedOperation::Snapshot { input, reader } => {
                let end = input
                    .offset
                    .checked_add(input.max_bytes)?
                    .min(reader.metadata().length_bytes);
                let length = end.checked_sub(input.offset)?.get();
                let reference = EvidenceRef::Snapshot {
                    snapshot_id: input.snapshot_id,
                    revision: input.revision,
                    sha256: reader.metadata().sha256,
                    range: Some(EvidenceRange::new(input.offset, end)?),
                };
                // Count actual JSON framing and base64 expansion before copying the requested bytes.
                let overhead = serialized_length(&SnapshotOutput {
                    snapshot_ref: reference,
                    offset: input.offset,
                    bytes_base64: Base64Bytes(&[]),
                    eof: end == reader.metadata().length_bytes,
                })?;
                let anticipated = length
                    .checked_add(encoded_length(length)?)
                    .and_then(|n| n.checked_add(overhead as u64))
                    .ok_or_else(budget)?;
                if anticipated > self.limits.requested.bytes.get() {
                    return Err(budget());
                }
                self.admission.recheck_effect(binding, permit)?;
                let body = reader.read(input.offset, input.max_bytes)?;
                meter.add_bytes(body.len())?;
                let output = SnapshotOutput {
                    snapshot_ref: reference,
                    offset: input.offset,
                    bytes_base64: Base64Bytes(&body),
                    eof: end == reader.metadata().length_bytes,
                };
                encode(&output, self.remaining(meter)?)?
            }
            PreparedOperation::Observation {
                input,
                reader,
                reference,
            } => {
                reader.validate_reference(&reference)?;
                let proposal_id = EntityId::new();
                let output = encode(
                    &ProposalOutput {
                        proposal_id,
                        status: ObservationStatus::Proposed,
                    },
                    self.remaining(meter)?,
                )?;
                self.check_usage(meter, output.len())?;
                let proposal = ObservationProposal {
                    proposal_id,
                    project_id: binding.project_id(),
                    rule_id: input.rule_id,
                    title: input.title,
                    evidence_refs: vec![reference],
                    actor_ref: binding.actor_ref(),
                    status: ObservationStatus::Proposed,
                };
                proposal.validate()?;
                self.admission.recheck_effect(binding, permit)?;
                meter.write_pending = true;
                self.evidence.record_proposal(proposal)?;
                meter.write_pending = false;
                output
            }
            PreparedOperation::Context(input) => self.context(binding, permit, &input, meter)?,
            PreparedOperation::Duplicate => return Err(invalid()),
        };
        self.check_usage(meter, bytes.len())?;
        self.admission.recheck_effect(binding, permit)?;
        meter.write_pending = true;
        let output = self.evidence.write_artifact(
            binding.project_id(),
            CatalogId::parse("tool-result")?,
            permit.invocation_id(),
            &bytes,
            RedactionStatus::Original,
        )?;
        meter.write_pending = false;
        meter.add_bytes(bytes.len())?;
        Ok(output.artifact_id)
    }

    fn context(
        &self,
        binding: &TrustedBinding,
        permit: &EffectPermit,
        input: &ContextInput,
        meter: &mut EffectMeter,
    ) -> ProofResult<Vec<u8>> {
        self.validate_context(binding, input)?;
        let output_size = serialized_length(&ContextOutput {
            record_ref: binding.project_id(),
            schema_version: VERSION,
        })?;
        let limit = self
            .remaining(meter)?
            .checked_sub(output_size)
            .ok_or_else(budget)?;
        let bytes = match input.kind {
            ContextKind::Investigation => {
                let session = self.admission.session(binding)?;
                encode(
                    &ContextRecord {
                        schema_version: VERSION,
                        record: &session.session,
                    },
                    limit,
                )?
            }
            ContextKind::AssetExamples => encode(
                &ContextRecord {
                    schema_version: VERSION,
                    record: self.owned_graph(binding, input.record_id)?,
                },
                limit,
            )?,
            ContextKind::MemoryExamples => self.memory_context(binding, permit, meter, limit)?,
        };
        self.check_usage(
            meter,
            bytes.len().checked_add(output_size).ok_or_else(budget)?,
        )?;
        self.admission.recheck_effect(binding, permit)?;
        meter.write_pending = true;
        let artifact = self.evidence.write_artifact(
            binding.project_id(),
            CatalogId::parse("context-record")?,
            permit.invocation_id(),
            &bytes,
            RedactionStatus::Original,
        )?;
        meter.write_pending = false;
        meter.add_bytes(bytes.len())?;
        encode(
            &ContextOutput {
                record_ref: artifact.artifact_id,
                schema_version: VERSION,
            },
            self.remaining(meter)?,
        )
    }

    fn memory_context(
        &self,
        binding: &TrustedBinding,
        permit: &EffectPermit,
        meter: &mut EffectMeter,
        limit: usize,
    ) -> ProofResult<Vec<u8>> {
        let mut buffer = BoundedBuffer::new(limit);
        buffer
            .write_all(b"{\"schema_version\":\"0.1.0\",\"memory_examples\":[")
            .map_err(|_| budget())?;
        let initial_bytes = meter.bytes;
        let mut first = true;
        for document in self.fixtures.records() {
            let ContractRecord::MemoryItem(item) = &document.record else {
                continue;
            };
            let session = match item.level {
                MemoryLevel::Session => Some(binding.session_id()),
                MemoryLevel::User => None,
            };
            // All ownership, session, status and expiry checks precede even the
            // content metadata lookup. Rejected examples do not touch their body.
            if item
                .authorize_access(binding.user_id(), item.level, session, AuditTime::now())
                .is_err()
            {
                continue;
            }
            self.admission.recheck_effect(binding, permit)?;
            let artifact = self
                .evidence
                .artifact(binding.project_id(), item.content_ref)?;
            let length = artifact.length_bytes.get();
            let overhead = serialized_length(&MemoryExample {
                record: item,
                bytes_base64: Base64Bytes(&[]),
            })?;
            let exposed = meter.bytes.checked_sub(initial_bytes).ok_or_else(budget)?;
            let anticipated = exposed
                .checked_add(length)
                .and_then(|n| n.checked_add(encoded_length(length).ok()?))
                .and_then(|n| n.checked_add(overhead as u64))
                .and_then(|n| n.checked_add(buffer.bytes.len() as u64 + 3))
                .ok_or_else(budget)?;
            if anticipated > limit as u64 {
                return Err(budget());
            }
            let max_bytes = usize::try_from(length).map_err(|_| budget())?;
            self.admission.recheck_effect(binding, permit)?;
            let content =
                self.evidence
                    .read_artifact(binding.project_id(), item.content_ref, max_bytes)?;
            meter.add_bytes(content.len())?;
            if !first {
                buffer.write_all(b",").map_err(|_| budget())?;
            }
            first = false;
            buffer.limit = limit
                .checked_sub(usize::try_from(meter.bytes - initial_bytes).map_err(|_| budget())?)
                .ok_or_else(budget)?;
            serde_json::to_writer(
                &mut buffer,
                &MemoryExample {
                    record: item,
                    bytes_base64: Base64Bytes(&content),
                },
            )
            .map_err(|_| budget())?;
        }
        buffer.write_all(b"]}").map_err(|_| budget())?;
        Ok(buffer.bytes)
    }

    fn remaining(&self, meter: &EffectMeter) -> ProofResult<usize> {
        let remaining = self
            .limits
            .requested
            .bytes
            .get()
            .checked_sub(meter.bytes)
            .ok_or_else(budget)?;
        Ok(self
            .limits
            .output
            .min(usize::try_from(remaining).map_err(|_| budget())?))
    }

    fn check_usage(&self, meter: &EffectMeter, additional: usize) -> ProofResult<()> {
        if additional > self.remaining(meter)? {
            return Err(budget());
        }
        let usage = meter.usage()?;
        if usage.cpu_us > self.limits.requested.cpu_us
            || usage.elapsed_us > self.limits.requested.elapsed_us
        {
            return Err(budget());
        }
        Ok(())
    }

    fn healthy(&self) -> ProofResult<()> {
        self.admission.check_integrity()
    }

    fn observe<T>(&self, outcome: ProofResult<T>) -> ProofResult<T> {
        if outcome
            .as_ref()
            .is_err_and(|error| error.code == ErrorCode::IntegrityError)
        {
            self.admission.invalidate_integrity();
        }
        outcome
    }
}

#[derive(Serialize)]
struct RejectedInput {
    original_input_sha256: Digest,
    code: ErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider_configuration_id: Option<EntityId>,
}
#[derive(Serialize)]
struct SnapshotOutput<'a> {
    snapshot_ref: EvidenceRef,
    offset: WireInt,
    bytes_base64: Base64Bytes<'a>,
    eof: bool,
}
#[derive(Serialize)]
struct ProposalOutput {
    proposal_id: EntityId,
    status: ObservationStatus,
}
#[derive(Serialize)]
struct ContextOutput {
    record_ref: EntityId,
    schema_version: ContractVersion,
}
#[derive(Serialize)]
struct ContextRecord<'a, T> {
    schema_version: ContractVersion,
    record: &'a T,
}
#[derive(Serialize)]
struct MemoryExample<'a> {
    record: &'a MemoryItem,
    bytes_base64: Base64Bytes<'a>,
}

struct Base64Bytes<'a>(&'a [u8]);
impl Serialize for Base64Bytes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&Base64Display::new(self.0, &STANDARD))
    }
}

struct BoundedBuffer {
    bytes: Vec<u8>,
    limit: usize,
}
impl BoundedBuffer {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
        }
    }
}
impl Write for BoundedBuffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("bounded JSON output exceeded"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct CountBytes(usize);
impl Write for CountBytes {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("JSON length overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn serialized_length<T: Serialize>(value: &T) -> ProofResult<usize> {
    let mut counter = CountBytes(0);
    serde_json::to_writer(&mut counter, value).map_err(|_| budget())?;
    Ok(counter.0)
}
fn encode<T: Serialize>(value: &T, limit: usize) -> ProofResult<Vec<u8>> {
    let mut buffer = BoundedBuffer::new(limit);
    serde_json::to_writer(&mut buffer, value).map_err(|_| budget())?;
    Ok(buffer.bytes)
}
fn encoded_length(length: u64) -> ProofResult<u64> {
    length
        .checked_add(2)
        .and_then(|n| (n / 3).checked_mul(4))
        .ok_or_else(budget)
}
fn same_request(stored: &StoredInvocation, request: &ToolRequest<'_>, digest: Digest) -> bool {
    let invocation = &stored.invocation;
    invocation.tool_id == request.tool_id
        && invocation.tool_version == request.tool_version
        && invocation.input_sha256 == digest
        && stored.source_control_revision == request.source_control_revision
}
fn same_call(stored: &StoredInvocation, call: &PreparedCall) -> bool {
    let invocation = &stored.invocation;
    invocation.tool_id == call.tool_id
        && invocation.tool_version == call.tool_version
        && invocation.input_sha256 == call.input_sha256
        && invocation.input_revision == call.input_revision
        && stored.source_control_revision == call.source_control_revision
        && stored.requested == call.requested
}
fn result(call_id: EntityId, invocation: Invocation) -> ToolResult {
    ToolResult {
        call_id,
        invocation_id: invocation.invocation_id,
        state: invocation.state,
        output_ref: invocation.output_ref,
        error: invocation.error,
        usage: invocation.usage,
    }
}
fn business_error(code: ErrorCode) -> bool {
    matches!(
        code,
        ErrorCode::InvalidInput
            | ErrorCode::UnsupportedVersion
            | ErrorCode::UnknownTool
            | ErrorCode::PermissionDenied
            | ErrorCode::OutOfScope
            | ErrorCode::ApprovalRequired
            | ErrorCode::BudgetExhausted
            | ErrorCode::StaleSnapshot
            | ErrorCode::ProviderUnavailable
            | ErrorCode::UnsupportedProtocol
            | ErrorCode::Cancelled
            | ErrorCode::Timeout
    )
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Local tool input does not match its exact contract",
    )
}
fn denied() -> ProofError {
    ProofError::new(
        ErrorCode::PermissionDenied,
        "The requested context is not owned by this binding",
    )
}
fn budget() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Local provider data exceeds its admitted output budget",
    )
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Local provider integrity is unavailable",
    )
}
