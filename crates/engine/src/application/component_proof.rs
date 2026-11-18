//! Passive public component provider. Only the trusted caller grants a prepared call.
use super::{
    admission::{HostAdmission, PreparedCall, TrustedBinding},
    effect_meter::EffectMeter,
    profile::LoadedProfile,
};
use crate::adapters::{
    components::{
        ComponentCapacity,
        bindings::Observation,
        snapshot_reader::{BlockedRead, SnapshotBroker, validate_reference},
        supervisor::{ApprovedComponents, RunFact, Supervisor, VARIANTS},
    },
    evidence_store::EvidenceStore,
    ledger::{Ledger, RegisteredTool},
};
use crate::domain::{
    authority::{Effect, RetryClass, ToolDescriptor},
    evidence::{
        EvidenceRange, EvidenceRef, ObservationProposal, ObservationStatus, RedactionStatus,
        Snapshot,
    },
    invocation::Invocation,
    values::{CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage, WireInt},
};
use crate::protocol::{
    error::{ErrorCode, ProofError, ProofResult},
    messages::ToolRequest,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, atomic::AtomicBool};

pub const TOOL: &str = "component.passive.proof";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentInput {
    pub variant: String,
    pub snapshot_id: EntityId,
    pub revision: WireInt,
    pub sha256: Digest,
}
pub struct PreparedComponent {
    pub call: PreparedCall,
    pub input: ComponentInput,
    pub snapshot: Arc<Snapshot>,
    binding_id: EntityId,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentExecution {
    pub fact: RunFact,
    pub fact_artifact_id: EntityId,
    pub proposal_ids: Vec<EntityId>,
    pub invocation: Invocation,
}

pub fn registered_tool(
    provider_digest: Digest,
    profile: &LoadedProfile,
) -> ProofResult<RegisteredTool> {
    Ok(RegisteredTool {
        provider_digest,
        descriptor: ToolDescriptor {
            tool_id: CatalogId::parse(TOOL)?,
            version: ContractVersion::V0_1_0,
            input_contract: CatalogId::parse("component.passive.proof.input")?,
            output_contract: CatalogId::parse("component.passive.proof.output")?,
            effect: Effect::LocalWrite,
            permissions: vec![CatalogId::parse("component.passive")?],
            limits: requested(profile)?,
            retry_class: RetryClass::NonRetryable,
        },
    })
}
fn requested(profile: &LoadedProfile) -> ProofResult<Usage> {
    Ok(Usage {
        units: WireInt::new(1)?,
        bytes: WireInt::new(8 * 1024 * 1024)?,
        cpu_us: WireInt::new(60_000_000)?,
        elapsed_us: WireInt::new(
            (profile.config().component.invocation_deadline_ms.get() + 2000) * 1000,
        )?,
    })
}
pub fn prepare(
    admission: &HostAdmission,
    evidence: &EvidenceStore,
    binding: &TrustedBinding,
    request: &ToolRequest<'_>,
    profile: &LoadedProfile,
) -> ProofResult<PreparedComponent> {
    if request.tool_id.as_str() != TOOL || request.tool_version != ContractVersion::V0_1_0 {
        return Err(invalid());
    }
    let input: ComponentInput = serde_json::from_str(request.input.get()).map_err(|_| invalid())?;
    if !VARIANTS.contains(&input.variant.as_str()) {
        return Err(invalid());
    }
    let reader =
        evidence.snapshot_reader(binding.project_id(), input.snapshot_id, input.revision)?;
    if reader.metadata().sha256 != input.sha256 {
        return Err(ProofError::new(
            ErrorCode::StaleSnapshot,
            "Prepared component snapshot hash does not match immutable evidence",
        ));
    }
    let snapshot = Arc::new(reader.metadata().clone());
    let bytes = serde_json::to_vec(&input).map_err(|_| invalid())?;
    if let Some(stored) = admission.existing_invocation(binding, request.call_id)? {
        if stored.invocation.input_sha256 != Digest::of(&bytes)
            || stored.invocation.tool_id != request.tool_id
            || stored.invocation.control_revision != request.source_control_revision
        {
            return Err(invalid());
        }
        return Ok(PreparedComponent {
            call: PreparedCall {
                invocation_id: stored.invocation.invocation_id,
                call_id: request.call_id,
                tool_id: request.tool_id.clone(),
                tool_version: request.tool_version,
                input_ref: stored.invocation.input_ref,
                input_sha256: stored.invocation.input_sha256,
                input_revision: input.revision,
                source_control_revision: request.source_control_revision,
                requested: stored.requested,
            },
            input,
            snapshot,
            binding_id: binding.binding_id(),
        });
    }
    let invocation_id = EntityId::new();
    let artifact = evidence.write_artifact(
        binding.project_id(),
        CatalogId::parse("component-input")?,
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
        input_revision: input.revision,
        source_control_revision: request.source_control_revision,
        requested: requested(profile)?,
    };
    admission.propose(binding, &call)?;
    Ok(PreparedComponent {
        call,
        input,
        snapshot,
        binding_id: binding.binding_id(),
    })
}
#[allow(clippy::too_many_arguments)]
pub fn execute_prepared(
    admission: Arc<HostAdmission>,
    evidence: Arc<EvidenceStore>,
    binding: Arc<TrustedBinding>,
    prepared: PreparedComponent,
    approved: &ApprovedComponents,
    profile: &LoadedProfile,
    capacity: Arc<ComponentCapacity>,
    blocked: Option<Arc<BlockedRead>>,
    cancelled: Arc<AtomicBool>,
) -> ProofResult<ComponentExecution> {
    if binding.binding_id() != prepared.binding_id {
        return Err(invalid());
    }
    let reserved = admission.reserve(&binding, &prepared.call)?;
    if reserved.state != InvocationState::Reserved {
        return Err(ProofError::new(
            ErrorCode::InvalidInput,
            "A terminal component invocation cannot be dispatched again",
        ));
    }
    let permit = admission.begin_effect(&binding, reserved.invocation_id)?;
    let mut meter = EffectMeter::start();
    let provided = (|| -> ProofResult<(RunFact, EntityId, Vec<EntityId>)> {
        let mut broker = SnapshotBroker::new(
            Arc::clone(&evidence),
            Arc::clone(&admission),
            Arc::clone(&binding),
            &permit,
            Arc::clone(&prepared.snapshot),
            profile,
            Arc::clone(&capacity),
        )?;
        broker.blocked = blocked;
        broker.cancelled = Arc::clone(&cancelled);
        let run = Supervisor::new(capacity).run(
            approved,
            profile,
            &prepared.input.variant,
            &mut broker,
            cancelled,
        );
        let mut fact = {
            let fact = run?;
            meter.dispatched = true;
            fact
        };
        meter.add_bytes(broker.consumed() as usize)?;
        let mut proposal_ids = Vec::new();
        if fact.error.is_none()
            && let Err(cause) =
                validate_observations(&prepared.snapshot, &fact.observations, profile)
        {
            fact.error = Some(cause);
            fact.outcome = "failed".into();
        }
        if fact.error.is_none() && prepared.input.variant == "fixture-denied-access" {
            fact.error = Some(ProofError::new(
                ErrorCode::PermissionDenied,
                "Guest access attempts were denied by the closed WASI context",
            ));
            fact.outcome = "failed".into();
        }
        if fact.error.is_none() {
            for observation in &fact.observations {
                let proposal = ObservationProposal {
                    proposal_id: EntityId::new(),
                    project_id: binding.project_id(),
                    rule_id: CatalogId::parse(&observation.rule_id)?,
                    title: observation.title.clone(),
                    evidence_refs: vec![EvidenceRef::Snapshot {
                        snapshot_id: prepared.snapshot.snapshot_id,
                        revision: prepared.snapshot.revision,
                        sha256: prepared.snapshot.sha256,
                        range: Some(EvidenceRange::new(
                            WireInt::new(observation.range_start)?,
                            WireInt::new(observation.range_end)?,
                        )?),
                    }],
                    actor_ref: binding.actor_ref(),
                    status: ObservationStatus::Proposed,
                };
                admission.recheck_effect(&binding, &permit)?;
                meter.write_pending = true;
                let proposal_id = proposal.proposal_id;
                evidence.record_proposal(proposal)?;
                meter.write_pending = false;
                proposal_ids.push(proposal_id);
            }
        }
        let bytes = serde_json::to_vec(&fact).map_err(|_| invalid())?;
        meter.add_bytes(bytes.len())?;
        meter.write_pending = true;
        let artifact = evidence.write_artifact(
            binding.project_id(),
            CatalogId::parse("component-lifecycle")?,
            permit.invocation_id(),
            &bytes,
            RedactionStatus::Original,
        )?;
        meter.write_pending = false;
        Ok((fact, artifact.artifact_id, proposal_ids))
    })();
    let usage = meter.usage()?;
    let (fact, fact_artifact_id, proposal_ids) = match provided {
        Ok(output) => output,
        Err(cause) => {
            let terminal = if meter.write_pending {
                admission.outcome_unknown(
                    &binding,
                    permit,
                    usage,
                    ProofError::new(
                        ErrorCode::OutcomeUnknown,
                        "Component evidence persistence requires reconciliation",
                    ),
                )?
            } else {
                admission.fail(&binding, permit, usage, cause)?
            };
            return Err(terminal.error.ok_or_else(|| {
                ProofError::new(
                    ErrorCode::IntegrityError,
                    "Component terminal state is missing its attributed error",
                )
            })?);
        }
    };
    let invocation = match &fact.error {
        None => admission.complete(&binding, permit, usage, Some(fact_artifact_id))?,
        Some(cause) => admission.fail(&binding, permit, usage, cause.clone())?,
    };
    Ok(ComponentExecution {
        fact,
        fact_artifact_id,
        proposal_ids,
        invocation,
    })
}
pub fn validate_observations(
    snapshot: &Snapshot,
    observations: &[Observation],
    profile: &LoadedProfile,
) -> ProofResult<()> {
    if observations.is_empty() || observations.len() > 128 {
        return Err(output());
    }
    for observation in observations {
        validate_reference(snapshot, &observation.snapshot).map_err(|_| output())?;
        if CatalogId::parse(&observation.rule_id).is_err()
            || observation.title.is_empty()
            || observation.title.len() > 256
            || observation.title.chars().any(char::is_control)
            || observation.range_start > observation.range_end
            || observation.range_end > snapshot.length_bytes.get()
        {
            return Err(output());
        }
    }
    struct Size(usize);
    impl std::io::Write for Size {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("component output size overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut size = Size(0);
    serde_json::to_writer(&mut size, observations).map_err(|_| output())?;
    if size.0
        > profile
            .config()
            .protocol
            .invocation_output_limit_bytes
            .get() as usize
    {
        return Err(output());
    }
    Ok(())
}
pub fn verify_execution(
    execution: &ComponentExecution,
    project: EntityId,
    evidence: &EvidenceStore,
    ledger: &Ledger,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    let stored = ledger.read_invocation(execution.fact.invocation_id)?;
    if stored.invocation != execution.invocation
        || stored.invocation.project_id != project
        || stored.invocation.tool_id.as_str() != TOOL
        || stored.invocation.usage.units.get() != 1
        || stored.reserved_units != WireInt::ZERO
    {
        return Err(output());
    }
    let artifact = evidence.artifact(project, execution.fact_artifact_id)?;
    if artifact.origin_invocation_id != execution.fact.invocation_id {
        return Err(output());
    }
    let bytes = evidence.read_artifact(project, artifact.artifact_id, 2 * 1024 * 1024)?;
    let original: RunFact = serde_json::from_slice(&bytes).map_err(|_| output())?;
    if serde_json::to_vec(&original).map_err(|_| output())?
        != serde_json::to_vec(&execution.fact).map_err(|_| output())?
    {
        return Err(output());
    }
    if stored.invocation.usage.bytes.get()
        != bytes.len() as u64 + original.reads.iter().map(|read| read.bytes).sum::<u64>()
        || original.stdout_bytes
            > profile
                .config()
                .protocol
                .invocation_output_limit_bytes
                .get()
        || original.stderr_bytes > 16_384
        || !original.reaped
        || original.pid == 0
        || original.elapsed_us == 0
        || original.invocations_after != 0
        || original.host_calls_after != 0
        || original.rss_samples.is_empty()
    {
        return Err(output());
    }
    if original.error.is_none() != (stored.invocation.state == InvocationState::Completed) {
        return Err(output());
    }
    if original
        .error
        .as_ref()
        .map(|cause| (cause.code, cause.message.as_ref()))
        != stored
            .invocation
            .error
            .as_ref()
            .map(|cause| (cause.code, cause.message.as_ref()))
        || stored.invocation.usage.elapsed_us.get() < original.elapsed_us
    {
        return Err(output());
    }
    let expected_proposals = if original.error.is_none() {
        original.observations.len()
    } else {
        0
    };
    if execution.proposal_ids.len() != expected_proposals
        || execution
            .proposal_ids
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != execution.proposal_ids.len()
    {
        return Err(output());
    }
    for (id, observation) in execution.proposal_ids.iter().zip(&original.observations) {
        let proposal = evidence.proposal(project, *id)?;
        if proposal.actor_ref != stored.invocation.actor_ref
            || proposal.rule_id.as_str() != observation.rule_id
            || proposal.title != observation.title
            || proposal.evidence_refs.len() != 1
        {
            return Err(output());
        }
        let expected = EvidenceRef::Snapshot {
            snapshot_id: EntityId::parse(&observation.snapshot.snapshot_id)?,
            revision: WireInt::new(observation.snapshot.revision)?,
            sha256: Digest::parse(&observation.snapshot.sha256)?,
            range: Some(EvidenceRange::new(
                WireInt::new(observation.range_start)?,
                WireInt::new(observation.range_end)?,
            )?),
        };
        if proposal.evidence_refs[0] != expected {
            return Err(output());
        }
        for reference in &proposal.evidence_refs {
            let EvidenceRef::Snapshot {
                snapshot_id,
                revision,
                ..
            } = reference
            else {
                return Err(output());
            };
            evidence
                .snapshot_reader(project, *snapshot_id, *revision)?
                .validate_reference(reference)?;
        }
    }
    Ok(())
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Component input or host binding does not match its closed contract",
    )
}
fn output() -> ProofError {
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Component result is not a bounded valid proposed observation",
    )
}
