//! Executed CMP facts. Verification only reads immutable evidence and canonical state.
use super::CaseObservation;
use crate::adapters::{
    components::{
        bindings::Observation,
        snapshot_reader::{BlockedRead, ReadFact, SnapshotBroker, reference},
        supervisor::{ApprovedComponents, BuildManifest, RunFact, VARIANTS, WIT_SHA256},
    },
    evidence_store::EvidenceStore,
    ledger::Ledger,
};
use crate::application::{
    admission::TrustedBinding,
    component_proof::{self, ComponentExecution, ComponentInput, PreparedComponent},
    control::{ControlAction, ControlClient, ControlCommand},
    effect_meter::EffectMeter,
    profile::LoadedProfile,
    proof_host::ProofHost,
};
use crate::domain::{
    evidence::{RedactionStatus, Snapshot},
    execution::{ControlMeasurement, ControlMode, ControlState},
    knowledge::InvestigationSession,
    proofs::{Assertions, CheckName, Run},
    values::{CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage, WireInt},
};
use crate::protocol::{
    error::{ErrorCode, ProofError, ProofResult},
    messages::ToolRequest,
};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::path::Path;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Scenario {
    schema_version: String,
    world: String,
    wit_sha256: Digest,
    build_manifest: String,
    variants: Vec<String>,
    cases: Vec<String>,
    capabilities: Capabilities,
    rss_policy: String,
    proposal_status: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Capabilities {
    environment: bool,
    preopens: bool,
    network: bool,
    inherited_stdio: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExecutionRef {
    invocation_id: EntityId,
    fact_artifact_id: EntityId,
    proposal_ids: Vec<EntityId>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Denial {
    attempt: String,
    error: ProofError,
    bytes_copied: u64,
    trial_invocation_id: EntityId,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessAttempt {
    resource: String,
    denied: bool,
    invocation_id: EntityId,
    observation_index: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlSample {
    ticket_id: EntityId,
    investigation_id: EntityId,
    revision_before: WireInt,
    revision_after: WireInt,
    ack_elapsed_us: WireInt,
    measurement: ControlMeasurement,
    action: ControlAction,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Overlap {
    active_invocation_id: EntityId,
    rejected_invocation_id: EntityId,
    peak_admitted: usize,
    rejection: ProofError,
    rejection_elapsed_us: u64,
    extra_spawns: usize,
    extra_reads: usize,
    queued: usize,
    active_before: usize,
    active_after: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_error: Option<ProofError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    blocked_elapsed_us: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerTrial {
    invocation_id: EntityId,
    artifact_id: EntityId,
    reads: Vec<ReadFact>,
    consumed: u64,
    usage: Usage,
    #[serde(with = "crate::adapters::components::wit_number::observations")]
    invalid_observations: Vec<Observation>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerBody {
    invocation_id: EntityId,
    reads: Vec<ReadFact>,
    consumed: u64,
    #[serde(with = "crate::adapters::components::wit_number::observations")]
    invalid_observations: Vec<Observation>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: String,
    case_id: CatalogId,
    project_id: EntityId,
    session_id: EntityId,
    profile_sha256: Digest,
    scenario_sha256: Digest,
    manifest_sha256: Digest,
    build_manifest: BuildManifest,
    input_snapshot: Snapshot,
    input_before_sha256: Digest,
    input_after_sha256: Digest,
    runs: Vec<RunFact>,
    executions: Vec<ExecutionRef>,
    broker_trials: Vec<BrokerTrial>,
    denials: Vec<Denial>,
    foreign_fixtures: Vec<crate::adapters::components::fixture_import::ForeignFixture>,
    access_attempts: Vec<AccessAttempt>,
    control_measurements: Vec<ControlSample>,
    release_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    invocation_overlap: Option<Overlap>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host_call_overlap: Option<Overlap>,
}
struct Fixture<'a> {
    host: &'a ProofHost,
    profile: &'a LoadedProfile,
    approved: ApprovedComponents,
    session: InvestigationSession,
    snapshot: Arc<Snapshot>,
    control: Arc<ControlClient>,
}
impl<'a> Fixture<'a> {
    fn new(host: &'a ProofHost, profile: &'a LoadedProfile, repo: &Path) -> ProofResult<Self> {
        let approved = ApprovedComponents::load(repo, profile)?;
        let snapshot = host
            .evidence
            .snapshots()?
            .into_iter()
            .find(|item| {
                item.project_id == host.project.project_id
                    && item.length_bytes.get() > 0
                    && !item.truncated
            })
            .ok_or_else(invalid)?;
        let mut session = host.session.clone();
        session.session_id = EntityId::new();
        session.investigation_id = EntityId::new();
        session.control_revision = WireInt::ZERO;
        session.branch_refs.clear();
        host.ledger
            .insert_session(&session, host.project.project_id)?;
        let instruction_ref = host
            .ledger
            .read_control(host.session.investigation_id)?
            .instruction_ref;
        host.ledger.insert_control(
            &ControlState {
                investigation_id: session.investigation_id,
                revision: WireInt::ZERO,
                mode: ControlMode::Running,
                admission_open: true,
                instruction_ref,
            },
            host.project.project_id,
            host.scope.revision,
        )?;
        host.control.register_existing(session.investigation_id)?;
        let control = host.control_client()?;
        Ok(Self {
            host,
            profile,
            approved,
            session,
            snapshot,
            control,
        })
    }
    fn binding(&self) -> ProofResult<Arc<TrustedBinding>> {
        let mut spec = self.host.local_spec();
        spec.investigation_id = self.session.investigation_id;
        spec.session_id = self.session.session_id;
        spec.allowed_tools = vec![CatalogId::parse(component_proof::TOOL)?];
        spec.permissions = vec![CatalogId::parse("component.passive")?];
        Ok(Arc::new(self.host.admission.bind(spec)?))
    }
    fn prepare(&self, variant: &str) -> ProofResult<(Arc<TrustedBinding>, PreparedComponent)> {
        let binding = self.binding()?;
        let input = ComponentInput {
            variant: variant.into(),
            snapshot_id: self.snapshot.snapshot_id,
            revision: self.snapshot.revision,
            sha256: self.snapshot.sha256,
        };
        let raw = RawValue::from_string(serde_json::to_string(&input).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        let request = ToolRequest {
            call_id: EntityId::new(),
            tool_id: CatalogId::parse(component_proof::TOOL)?,
            tool_version: ContractVersion::V0_1_0,
            input: &raw,
            source_control_revision: binding.control_revision(),
        };
        let prepared = component_proof::prepare(
            &self.host.admission,
            &self.host.evidence,
            &binding,
            &request,
            self.profile,
        )?;
        self.host.approve(&binding, &prepared.call)?;
        Ok((binding, prepared))
    }
    fn run(
        &self,
        variant: &str,
        blocked: Option<Arc<BlockedRead>>,
        cancelled: Arc<AtomicBool>,
    ) -> ProofResult<ComponentExecution> {
        let (binding, prepared) = self.prepare(variant)?;
        component_proof::execute_prepared(
            Arc::clone(&self.host.admission),
            Arc::clone(&self.host.evidence),
            binding,
            prepared,
            &self.approved,
            self.profile,
            Arc::clone(&self.host.component_capacity),
            blocked,
            cancelled,
        )
    }
    fn fresh(&self, report: &mut Report) -> ProofResult<()> {
        let mut execution = self.run("fixture-valid", None, Arc::new(AtomicBool::new(false)))?;
        if let Some(cause) = execution.fact.error.take() {
            return Err(cause);
        }
        if execution.fact.observations.is_empty() {
            return Err(output());
        }
        push_execution(report, execution);
        Ok(())
    }
    fn adversary(&self, report: &mut Report, variant: &str) -> ProofResult<()> {
        let execution = self.run(variant, None, Arc::new(AtomicBool::new(false)))?;
        if execution.fact.error.is_none() {
            return Err(output());
        }
        push_execution(report, execution);
        self.barrier(report)?;
        self.fresh(report)
    }
    fn barrier(&self, report: &mut Report) -> ProofResult<()> {
        let client = &self.control;
        for action in [ControlAction::Pause, ControlAction::Resume] {
            let before = self
                .host
                .ledger
                .read_control(self.session.investigation_id)?;
            let command = ControlCommand {
                request_id: EntityId::new(),
                investigation_id: self.session.investigation_id,
                expected_revision: before.revision,
                action,
            };
            let ack = client.request(&command)?;
            let durable = self
                .host
                .ledger
                .read_control(self.session.investigation_id)?;
            if durable != ack.state {
                return Err(output());
            }
            report.control_measurements.push(ControlSample {
                ticket_id: ack.request_id,
                investigation_id: self.session.investigation_id,
                revision_before: before.revision,
                revision_after: ack.state.revision,
                ack_elapsed_us: ack.measurement.ack_elapsed_us()?,
                measurement: ack.measurement,
                action,
            });
        }
        Ok(())
    }
}
fn push_execution(report: &mut Report, execution: ComponentExecution) {
    report.executions.push(ExecutionRef {
        invocation_id: execution.fact.invocation_id,
        fact_artifact_id: execution.fact_artifact_id,
        proposal_ids: execution.proposal_ids,
    });
    report.runs.push(execution.fact);
}
pub fn execute(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo: &Path,
    case_id: &CatalogId,
) -> ProofResult<CaseObservation> {
    if !matches!(
        case_id.as_str(),
        "CMP-01" | "CMP-02" | "CMP-03" | "CMP-04" | "CMP-05" | "CMP-06" | "CMP-07"
    ) {
        return Err(invalid());
    }
    let scenario_bytes =
        std::fs::read(repo.join("fixtures/scenarios/components.json")).map_err(|_| invalid())?;
    if scenario_bytes.len() > 8192 {
        return Err(invalid());
    }
    let scenario: Scenario = serde_json::from_slice(&scenario_bytes).map_err(|_| invalid())?;
    if scenario.schema_version != "0.1.0"
        || scenario.world != profile.config().component.world
        || scenario.wit_sha256 != Digest::parse(WIT_SHA256)?
        || scenario.variants.iter().map(String::as_str).ne(VARIANTS)
        || scenario.cases
            != [
                "CMP-01", "CMP-02", "CMP-03", "CMP-04", "CMP-05", "CMP-06", "CMP-07",
            ]
        || scenario.build_manifest != "target/proof-components/build-manifest.json"
        || scenario.proposal_status != "proposed"
        || scenario.capabilities.environment
        || scenario.capabilities.preopens
        || scenario.capabilities.network
        || scenario.capabilities.inherited_stdio
    {
        return Err(invalid());
    }
    let fixture = Fixture::new(host, profile, repo)?;
    let reader = host.evidence.snapshot_reader(
        host.project.project_id,
        fixture.snapshot.snapshot_id,
        fixture.snapshot.revision,
    )?;
    let before = hash_snapshot(&reader)?;
    let mut report = Report {
        schema_version: "0.1.0".into(),
        case_id: case_id.clone(),
        project_id: host.project.project_id,
        session_id: fixture.session.session_id,
        profile_sha256: profile.sha256(),
        scenario_sha256: Digest::of(&scenario_bytes),
        manifest_sha256: fixture.approved.manifest_sha256,
        build_manifest: fixture.approved.manifest.clone(),
        input_snapshot: (*fixture.snapshot).clone(),
        input_before_sha256: before,
        input_after_sha256: before,
        runs: Vec::new(),
        executions: Vec::new(),
        broker_trials: Vec::new(),
        denials: Vec::new(),
        access_attempts: Vec::new(),
        foreign_fixtures: Vec::new(),
        control_measurements: Vec::new(),
        release_paths: Vec::new(),
        invocation_overlap: None,
        host_call_overlap: None,
    };
    match case_id.as_str() {
        "CMP-01" => fixture.fresh(&mut report)?,
        "CMP-02" => fixture.adversary(&mut report, "fixture-loop")?,
        "CMP-03" => {
            fixture.adversary(&mut report, "fixture-grow")?;
            invocation_overlap(&fixture, &mut report, false)?;
        }
        "CMP-04" => {
            broker_denials(&fixture, &mut report)?;
            fixture.adversary(&mut report, "fixture-output")?;
        }
        "CMP-05" => {
            blocked_guest(&fixture, &mut report)?;
            host_call_overlap(&fixture, &mut report)?;
        }
        "CMP-06" => {
            denied_access(&fixture, &mut report)?;
        }
        "CMP-07" => {
            fixture.fresh(&mut report)?;
            report.release_paths.push("success".into());
            fixture.adversary(&mut report, "fixture-loop")?;
            report.release_paths.push("trap".into());
            fixture.adversary(&mut report, "fixture-grow")?;
            broker_denials(&fixture, &mut report)?;
            fixture.adversary(&mut report, "fixture-output")?;
            blocked_guest(&fixture, &mut report)?;
            report.release_paths.push("timeout".into());
            denied_access(&fixture, &mut report)?;
            invocation_overlap(&fixture, &mut report, true)?;
            report.release_paths.push("cancelled".into());
            report.release_paths.push("invocation_saturation".into());
            host_call_overlap(&fixture, &mut report)?;
            report.release_paths.push("host_call_saturation".into());
        }
        _ => return Err(invalid()),
    }
    report.input_after_sha256 = hash_snapshot(&reader)?;
    let assertions = derive(&report, profile)?;
    Ok(CaseObservation {
        case_id: case_id.clone(),
        observed: assertions,
        report: serde_json::to_value(report).map_err(|_| output())?,
        attachment_paths: Vec::new(),
    })
}
fn hash_snapshot(reader: &crate::adapters::evidence_store::SnapshotReader) -> ProofResult<Digest> {
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < reader.metadata().length_bytes.get() {
        let count = (reader.metadata().length_bytes.get() - offset).min(65536);
        let bytes = reader.read(WireInt::new(offset)?, WireInt::new(count)?)?;
        hash.update(&bytes);
        offset += bytes.len() as u64;
    }
    Ok(Digest::from_sha256(hash.finalize().into()))
}
fn blocked_guest(fixture: &Fixture<'_>, report: &mut Report) -> ProofResult<()> {
    let (blocked, _writer) = BlockedRead::new()?;
    let execution = fixture.run(
        "fixture-host-call",
        Some(blocked),
        Arc::new(AtomicBool::new(false)),
    )?;
    if !execution.fact.reads.iter().any(|read| {
        read.error
            .as_ref()
            .is_some_and(|cause| cause.code == ErrorCode::Timeout)
    }) {
        return Err(output());
    }
    push_execution(report, execution);
    fixture.barrier(report)?;
    fixture.fresh(report)
}
fn denied_access(fixture: &Fixture<'_>, report: &mut Report) -> ProofResult<()> {
    let execution = fixture.run(
        "fixture-denied-access",
        None,
        Arc::new(AtomicBool::new(false)),
    )?;
    if execution
        .fact
        .error
        .as_ref()
        .is_none_or(|cause| cause.code != ErrorCode::PermissionDenied)
    {
        return Err(output());
    }
    for resource in ["filesystem", "socket", "environment", "credential"] {
        let (index, observation) = execution
            .fact
            .observations
            .iter()
            .enumerate()
            .find(|(_, observation)| observation.rule_id == format!("fixture.denied.{resource}"))
            .ok_or_else(output)?;
        report.access_attempts.push(AccessAttempt {
            resource: resource.into(),
            denied: observation.title == "access denied",
            invocation_id: execution.fact.invocation_id,
            observation_index: index,
        });
    }
    push_execution(report, execution);
    fixture.barrier(report)?;
    fixture.fresh(report)
}
fn invocation_overlap(fixture: &Fixture<'_>, report: &mut Report, cancel: bool) -> ProofResult<()> {
    let (blocked, _writer) = BlockedRead::new()?;
    let cancelled = Arc::new(AtomicBool::new(false));
    let (binding, prepared) = fixture.prepare("fixture-valid")?;
    let execution = std::thread::scope(|scope| -> ProofResult<ComponentExecution> {
        let pending = scope.spawn(|| {
            fixture.run(
                "fixture-host-call",
                Some(Arc::clone(&blocked)),
                Arc::clone(&cancelled),
            )
        });
        blocked.wait_entered(Duration::from_millis(
            fixture
                .profile
                .config()
                .component
                .invocation_deadline_ms
                .get(),
        ))?;
        let before = fixture.host.component_capacity.state();
        let rejected_id = prepared.call.invocation_id;
        let started = Instant::now();
        let attempted = component_proof::execute_prepared(
            Arc::clone(&fixture.host.admission),
            Arc::clone(&fixture.host.evidence),
            binding,
            prepared,
            &fixture.approved,
            fixture.profile,
            Arc::clone(&fixture.host.component_capacity),
            None,
            Arc::new(AtomicBool::new(false)),
        );
        let elapsed = started.elapsed().as_micros() as u64;
        let rejection = match attempted {
            Err(cause) if cause.code == ErrorCode::BudgetExhausted => cause,
            _ => return Err(output()),
        };
        let after = fixture.host.component_capacity.state();
        fixture.barrier(report)?;
        if cancel {
            cancelled.store(true, Ordering::SeqCst);
        }
        let execution = pending.join().map_err(|_| output())??;
        report.invocation_overlap = Some(Overlap {
            active_invocation_id: execution.fact.invocation_id,
            rejected_invocation_id: rejected_id,
            peak_admitted: after.invocation_peak,
            rejection,
            rejection_elapsed_us: elapsed,
            extra_spawns: after.spawns.checked_sub(before.spawns).ok_or_else(output)?,
            extra_reads: after.reads.checked_sub(before.reads).ok_or_else(output)?,
            queued: usize::from(matches!(
                fixture
                    .host
                    .ledger
                    .read_invocation(rejected_id)?
                    .invocation
                    .state,
                InvocationState::Reserved | InvocationState::Sending
            )),
            active_before: before.invocations,
            active_after: after.invocations,
            blocked_error: None,
            blocked_elapsed_us: None,
        });
        Ok(execution)
    })?;
    if cancel && execution.fact.outcome != "cancelled" {
        return Err(output());
    }
    if execution.fact.error.is_none() {
        return Err(output());
    }
    push_execution(report, execution);
    fixture.fresh(report)
}
struct TrialObservation {
    reads: Vec<ReadFact>,
    consumed: u64,
    failure: ProofError,
    invalid_observations: Vec<Observation>,
}

fn finish_trial(
    fixture: &Fixture<'_>,
    binding: &TrustedBinding,
    permit: crate::application::admission::EffectPermit,
    mut meter: EffectMeter,
    observation: TrialObservation,
) -> ProofResult<BrokerTrial> {
    let TrialObservation {
        reads,
        consumed,
        failure,
        invalid_observations,
    } = observation;
    let body = BrokerBody {
        invocation_id: permit.invocation_id(),
        reads,
        consumed,
        invalid_observations,
    };
    let bytes = serde_json::to_vec(&body).map_err(|_| output())?;
    let artifact = fixture.host.evidence.write_artifact(
        binding.project_id(),
        CatalogId::parse("component-broker-trial")?,
        permit.invocation_id(),
        &bytes,
        RedactionStatus::Original,
    )?;
    meter.add_bytes(bytes.len())?;
    meter.add_bytes(consumed as usize)?;
    let usage = meter.usage()?;
    let invocation = fixture
        .host
        .admission
        .fail(binding, permit, usage, failure)?;
    Ok(BrokerTrial {
        invocation_id: invocation.invocation_id,
        artifact_id: artifact.artifact_id,
        reads: body.reads,
        consumed,
        usage,
        invalid_observations: body.invalid_observations,
    })
}
fn broker_denials(fixture: &Fixture<'_>, report: &mut Report) -> ProofResult<()> {
    let foreign_fixture =
        crate::adapters::components::fixture_import::import(fixture.host, &fixture.snapshot)?;
    let foreign = reference(&foreign_fixture.snapshot);
    report.foreign_fixtures.push(foreign_fixture);
    let (binding, prepared) = fixture.prepare("fixture-valid")?;
    fixture.host.admission.reserve(&binding, &prepared.call)?;
    let permit = fixture
        .host
        .admission
        .begin_effect(&binding, prepared.call.invocation_id)?;
    let mut meter = EffectMeter::start();
    meter.dispatched = true;
    let mut broker = SnapshotBroker::new(
        Arc::clone(&fixture.host.evidence),
        Arc::clone(&fixture.host.admission),
        Arc::clone(&binding),
        &permit,
        Arc::clone(&fixture.snapshot),
        fixture.profile,
        Arc::clone(&fixture.host.component_capacity),
    )?;
    let original = reference(&fixture.snapshot);
    let mut stale = original.clone();
    stale.revision += 1;
    let mut wrong_hash = original.clone();
    wrong_hash.sha256 = Digest::of(b"substituted hash").to_string();
    for (attempt, supplied, offset, max_bytes, code) in [
        (
            "foreign_project",
            foreign,
            0,
            1,
            ErrorCode::PermissionDenied,
        ),
        ("stale_revision", stale, 0, 1, ErrorCode::StaleSnapshot),
        ("wrong_hash", wrong_hash, 0, 1, ErrorCode::StaleSnapshot),
        (
            "overflow_range",
            original.clone(),
            u64::MAX,
            2,
            ErrorCode::InvalidInput,
        ),
        (
            "chunk_limit",
            original.clone(),
            0,
            fixture.profile.config().transport.chunk_limit_bytes.get() as u32 + 1,
            ErrorCode::BudgetExhausted,
        ),
    ] {
        let outcome = broker.read(supplied, offset, max_bytes);
        let error = match outcome {
            Err(cause) if cause.code == code => cause,
            _ => return Err(output()),
        };
        report.denials.push(Denial {
            attempt: attempt.into(),
            error,
            bytes_copied: 0,
            trial_invocation_id: permit.invocation_id(),
        });
    }
    let mut remaining = fixture.snapshot.length_bytes.get();
    let mut offset = 0;
    while remaining > 0 {
        let count =
            remaining.min(fixture.profile.config().transport.chunk_limit_bytes.get()) as u32;
        let bytes = broker.read(original.clone(), offset, count)?;
        offset += bytes.len() as u64;
        remaining -= bytes.len() as u64;
    }
    let error = broker
        .read(original, 0, 1)
        .err()
        .filter(|cause| cause.code == ErrorCode::BudgetExhausted)
        .ok_or_else(output)?;
    report.denials.push(Denial {
        attempt: "cumulative_limit".into(),
        error: error.clone(),
        bytes_copied: 0,
        trial_invocation_id: permit.invocation_id(),
    });
    let reads = std::mem::take(&mut broker.reads);
    let consumed = broker.consumed();
    drop(broker);
    let mut invalid = Observation {
        rule_id: "fixture.invalid".into(),
        title: "invalid range".into(),
        snapshot: reference(&fixture.snapshot),
        range_start: u64::MAX,
        range_end: 0,
    };
    let mut invalid_observations = vec![invalid.clone()];
    invalid.range_start = 0;
    invalid.range_end = 0;
    invalid.snapshot.revision += 1;
    invalid_observations.push(invalid.clone());
    invalid.snapshot = reference(&report.foreign_fixtures.last().ok_or_else(output)?.snapshot);
    invalid_observations.push(invalid.clone());
    invalid.snapshot = reference(&fixture.snapshot);
    invalid.snapshot.sha256 = Digest::of(b"substituted output hash").to_string();
    invalid_observations.push(invalid);
    for observation in &invalid_observations {
        component_proof::validate_observations(
            &fixture.snapshot,
            std::slice::from_ref(observation),
            fixture.profile,
        )
        .err()
        .ok_or_else(output)?;
    }
    let error = component_proof::validate_observations(
        &fixture.snapshot,
        &invalid_observations[..1],
        fixture.profile,
    )
    .err()
    .ok_or_else(output)?;
    report.denials.push(Denial {
        attempt: "invalid_output".into(),
        error: error.clone(),
        bytes_copied: 0,
        trial_invocation_id: permit.invocation_id(),
    });
    report.broker_trials.push(finish_trial(
        fixture,
        &binding,
        permit,
        meter,
        TrialObservation {
            reads,
            consumed,
            failure: error,
            invalid_observations,
        },
    )?);
    fixture.barrier(report)?;
    fixture.fresh(report)
}
fn host_call_overlap(fixture: &Fixture<'_>, report: &mut Report) -> ProofResult<()> {
    let (binding, prepared) = fixture.prepare("fixture-host-call")?;
    let (other_binding, other_prepared) = fixture.prepare("fixture-host-call")?;
    fixture.host.admission.reserve(&binding, &prepared.call)?;
    fixture
        .host
        .admission
        .reserve(&other_binding, &other_prepared.call)?;
    let permit = fixture
        .host
        .admission
        .begin_effect(&binding, prepared.call.invocation_id)?;
    let other_permit = fixture
        .host
        .admission
        .begin_effect(&other_binding, other_prepared.call.invocation_id)?;
    let mut meter = EffectMeter::start();
    meter.dispatched = true;
    let other_meter = EffectMeter::start();
    let mut first = SnapshotBroker::new(
        Arc::clone(&fixture.host.evidence),
        Arc::clone(&fixture.host.admission),
        Arc::clone(&binding),
        &permit,
        Arc::clone(&fixture.snapshot),
        fixture.profile,
        Arc::clone(&fixture.host.component_capacity),
    )?;
    let mut second = SnapshotBroker::new(
        Arc::clone(&fixture.host.evidence),
        Arc::clone(&fixture.host.admission),
        Arc::clone(&other_binding),
        &other_permit,
        Arc::clone(&fixture.snapshot),
        fixture.profile,
        Arc::clone(&fixture.host.component_capacity),
    )?;
    let (blocked, _writer) = BlockedRead::new()?;
    first.blocked = Some(Arc::clone(&blocked));
    let supplied = reference(&fixture.snapshot);
    let (mut first, blocked_error, rejection) = std::thread::scope(|scope| -> ProofResult<_> {
        let first_reference = supplied.clone();
        let pending = scope.spawn(move || {
            let result = first.read(first_reference, 0, 1);
            (first, result)
        });
        blocked.wait_entered(Duration::from_millis(
            fixture
                .profile
                .config()
                .component
                .host_call_deadline_ms
                .get(),
        ))?;
        let before = fixture.host.component_capacity.state();
        let started = Instant::now();
        let rejection = second
            .read(supplied, 0, 1)
            .err()
            .filter(|cause| cause.code == ErrorCode::BudgetExhausted)
            .ok_or_else(output)?;
        let rejection_elapsed_us = started.elapsed().as_micros() as u64;
        let after = fixture.host.component_capacity.state();
        fixture.barrier(report)?;
        let (first, blocked_result) = pending.join().map_err(|_| output())?;
        let blocked_error = blocked_result
            .err()
            .filter(|cause| cause.code == ErrorCode::Timeout)
            .ok_or_else(output)?;
        let blocked_elapsed_us = first.reads.last().ok_or_else(output)?.elapsed_us;
        report.host_call_overlap = Some(Overlap {
            active_invocation_id: permit.invocation_id(),
            rejected_invocation_id: other_permit.invocation_id(),
            peak_admitted: after.host_call_peak,
            rejection: rejection.clone(),
            rejection_elapsed_us,
            extra_spawns: after.spawns.checked_sub(before.spawns).ok_or_else(output)?,
            extra_reads: after.reads.checked_sub(before.reads).ok_or_else(output)?,
            queued: usize::from(second.reads.is_empty()),
            active_before: before.host_calls,
            active_after: after.host_calls,
            blocked_error: Some(blocked_error.clone()),
            blocked_elapsed_us: Some(blocked_elapsed_us),
        });
        Ok((first, blocked_error, rejection))
    })?;
    let first_reads = std::mem::take(&mut first.reads);
    let second_reads = std::mem::take(&mut second.reads);
    let consumed = first.consumed();
    let other_consumed = second.consumed();
    drop(first);
    drop(second);
    report.broker_trials.push(finish_trial(
        fixture,
        &binding,
        permit,
        meter,
        TrialObservation {
            reads: first_reads,
            consumed,
            failure: blocked_error,
            invalid_observations: Vec::new(),
        },
    )?);
    report.broker_trials.push(finish_trial(
        fixture,
        &other_binding,
        other_permit,
        other_meter,
        TrialObservation {
            reads: second_reads,
            consumed: other_consumed,
            failure: rejection,
            invalid_observations: Vec::new(),
        },
    )?);
    fixture.fresh(report)
}
fn recovered(report: &Report) -> bool {
    !report.runs.is_empty()
        && report
            .runs
            .last()
            .is_some_and(|run| run.variant == "fixture-valid" && run.error.is_none())
        && report.runs.windows(2).all(|pair| {
            pair[0].variant == "fixture-valid"
                || (pair[1].variant == "fixture-valid"
                    && pair[1].error.is_none()
                    && pair[0].invocation_id != pair[1].invocation_id)
        })
}
fn overlap_valid(overlap: &Option<Overlap>) -> bool {
    overlap.as_ref().is_some_and(|fact| {
        fact.peak_admitted == 1
            && fact.active_before == 1
            && fact.active_after == 1
            && fact.rejection.code == ErrorCode::BudgetExhausted
            && fact.rejection_elapsed_us < 250_000
            && fact.extra_spawns == 0
            && fact.extra_reads == 0
            && fact.queued == 0
    })
}
fn controls_valid(report: &Report, profile: &LoadedProfile) -> bool {
    !report.control_measurements.is_empty()
        && report.control_measurements.iter().all(|sample| {
            sample
                .measurement
                .validate_barrier_deadline(
                    WireInt::new(profile.config().control.ack_deadline_ms.get() * 1000)
                        .expect("validated profile deadline"),
                )
                .is_ok()
                && sample.measurement.ack_elapsed_us().ok() == Some(sample.ack_elapsed_us)
                && sample.revision_after.get() == sample.revision_before.get() + 1
        })
}
fn derive(report: &Report, profile: &LoadedProfile) -> ProofResult<Assertions> {
    let fresh = recovered(report);
    let released = report
        .runs
        .iter()
        .all(|run| run.reaped && run.invocations_after == 0 && run.host_calls_after == 0);
    let failure = |variant: &str| {
        report
            .runs
            .iter()
            .find(|run| run.variant == variant && run.error.is_some())
    };
    let control = controls_valid(report, profile);
    let deadline = profile.config().component.invocation_deadline_ms.get() * 1000 + 1_000_000;
    let terminal_paths = report.runs.iter().any(|fact| fact.error.is_none())
        && report.runs.iter().any(|fact| {
            fact.store.memory_denied_bytes > 0
                || (fact.variant == "fixture-loop" && fact.store.fuel_remaining == 0)
        })
        && report.runs.iter().any(|fact| {
            fact.variant == "fixture-host-call"
                && fact
                    .error
                    .as_ref()
                    .is_some_and(|cause| cause.code == ErrorCode::Timeout)
                && fact.store.fuel_remaining > 0
                && fact.reads.iter().any(|read| {
                    read.error
                        .as_ref()
                        .is_some_and(|cause| cause.code == ErrorCode::Timeout)
                })
        })
        && report.runs.iter().any(|fact| {
            fact.outcome == "cancelled"
                && fact
                    .error
                    .as_ref()
                    .is_some_and(|cause| cause.code == ErrorCode::Cancelled)
        });
    let checks = match report.case_id.as_str() {
        "CMP-01" => {
            let valid = report.runs.first().ok_or_else(output)?;
            vec![
                (
                    CheckName::PublicWit,
                    report.build_manifest.wit_sha256.to_string() == WIT_SHA256 && valid.ready,
                ),
                (
                    CheckName::BoundedRead,
                    !valid.reads.is_empty()
                        && valid.reads.iter().all(|read| {
                            read.error.is_none()
                                && u64::from(read.max_bytes)
                                    <= profile.config().transport.chunk_limit_bytes.get()
                        })
                        && valid.reads.iter().map(|read| read.bytes).sum::<u64>()
                            == report.input_snapshot.length_bytes.get(),
                ),
                (
                    CheckName::ValidProposal,
                    valid.error.is_none()
                        && component_proof::validate_observations(
                            &report.input_snapshot,
                            &valid.observations,
                            profile,
                        )
                        .is_ok()
                        && report
                            .executions
                            .first()
                            .is_some_and(|execution| !execution.proposal_ids.is_empty()),
                ),
                (
                    CheckName::OriginalUnchanged,
                    report.input_before_sha256 == report.input_after_sha256
                        && report.input_after_sha256 == report.input_snapshot.sha256,
                ),
            ]
        }
        "CMP-02" => {
            let failed = failure("fixture-loop").ok_or_else(output)?;
            vec![
                (
                    CheckName::ExecutionInterrupted,
                    failed
                        .error
                        .as_ref()
                        .is_some_and(|cause| cause.code == ErrorCode::Timeout)
                        && fresh
                        && released,
                ),
                (CheckName::DeadlineMet, failed.elapsed_us <= deadline),
            ]
        }
        "CMP-03" => {
            let failed = failure("fixture-grow").ok_or_else(output)?;
            vec![
                (
                    CheckName::MemoryBounded,
                    failed.store.memory_denied_bytes as u64
                        > profile.config().component.linear_memory_bytes.get()
                        && failed.store.memory_peak_bytes as u64
                            <= profile.config().component.linear_memory_bytes.get()
                        && failed.store.resource_probes.len() == 5
                        && failed
                            .store
                            .resource_probes
                            .iter()
                            .all(|probe| probe.denied && probe.requested > probe.limit)
                        && fresh
                        && released,
                ),
                (
                    CheckName::AggregateInvocationsBounded,
                    overlap_valid(&report.invocation_overlap),
                ),
                (CheckName::ControlAck, control),
                // Retain zero lifecycle samples; require a measured positive resident footprint.
                (
                    CheckName::RssObserved,
                    report.runs.iter().all(|run| {
                        !run.rss_samples.is_empty() && run.rss_samples.iter().any(|rss| *rss > 0)
                    }),
                ),
            ]
        }
        "CMP-04" => {
            let denial = |attempt: &str, code| {
                report.denials.iter().any(|denial| {
                    denial.attempt == attempt
                        && denial.error.code == code
                        && denial.bytes_copied == 0
                })
            };
            vec![
                (
                    CheckName::InvalidRejected,
                    denial("overflow_range", ErrorCode::InvalidInput)
                        && denial("invalid_output", ErrorCode::OutputInvalid),
                ),
                (
                    CheckName::StaleRejected,
                    denial("stale_revision", ErrorCode::StaleSnapshot)
                        && denial("wrong_hash", ErrorCode::StaleSnapshot),
                ),
                (
                    CheckName::ForeignRejected,
                    denial("foreign_project", ErrorCode::PermissionDenied),
                ),
                (
                    CheckName::OutputBounded,
                    failure("fixture-output").is_some()
                        && denial("chunk_limit", ErrorCode::BudgetExhausted)
                        && denial("cumulative_limit", ErrorCode::BudgetExhausted)
                        && fresh
                        && released,
                ),
            ]
        }
        "CMP-05" => {
            let failed = failure("fixture-host-call").ok_or_else(output)?;
            vec![
                (
                    CheckName::HostCallDeadline,
                    failed.store.fuel_remaining > 0
                        && failed.reads.iter().any(|read| {
                            read.error
                                .as_ref()
                                .is_some_and(|cause| cause.code == ErrorCode::Timeout)
                                && read.elapsed_us
                                    >= profile.config().component.host_call_deadline_ms.get() * 1000
                                && read.elapsed_us
                                    <= profile.config().component.host_call_deadline_ms.get() * 1000
                                        + 100_000
                        })
                        && fresh
                        && released,
                ),
                (
                    CheckName::AggregateHostCallsBounded,
                    overlap_valid(&report.host_call_overlap),
                ),
                (CheckName::ControlAck, control),
            ]
        }
        "CMP-06" => vec![
            (
                CheckName::UngrantedAccessDenied,
                report.access_attempts.len() == 4
                    && report.access_attempts.iter().all(|attempt| attempt.denied)
                    && failure("fixture-denied-access").is_some()
                    && fresh
                    && released,
            ),
            (
                CheckName::SecretsAbsent,
                report
                    .runs
                    .iter()
                    .flat_map(|run| &run.observations)
                    .all(|observation| {
                        observation.title.len() <= 256
                            && !observation.title.contains("RAZEN_FIXTURE_")
                    }),
            ),
        ],
        "CMP-07" => vec![
            (
                CheckName::AllVariantsObserved,
                VARIANTS
                    .iter()
                    .all(|variant| report.runs.iter().any(|run| run.variant == *variant))
                    && overlap_valid(&report.invocation_overlap)
                    && overlap_valid(&report.host_call_overlap)
                    && controls_valid(report, profile)
                    && terminal_paths
                    && [
                        "success",
                        "trap",
                        "timeout",
                        "cancelled",
                        "invocation_saturation",
                        "host_call_saturation",
                    ]
                    .iter()
                    .all(|path| report.release_paths.iter().any(|actual| actual == path)),
            ),
            (CheckName::SlotsReleased, released),
            (CheckName::FreshSuccess, fresh),
            (
                CheckName::ErrorsAttributed,
                report
                    .runs
                    .iter()
                    .filter(|run| run.variant != "fixture-valid")
                    .all(|run| run.error.is_some()),
            ),
        ],
        _ => return Err(invalid()),
    };
    Assertions::new(checks)
}
pub fn verify_report(
    result: &crate::domain::proofs::ProofResult,
    value: &serde_json::Value,
    project: EntityId,
    run: &Run,
    profile: &LoadedProfile,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<Assertions> {
    use crate::adapters::components::supervisor::{WASMTIME_VERSION, WIT_BINDGEN_VERSION};
    let bytes = serde_json::to_vec(value).map_err(|_| output())?;
    if bytes.len() > 2 * 1024 * 1024 {
        return Err(output());
    }
    let report: Report = serde_json::from_slice(&bytes).map_err(|_| output())?;
    if report.schema_version != "0.1.0"
        || report.case_id != result.case_id
        || report.project_id != project
        || report.profile_sha256 != profile.sha256()
        || report.runs.len() > 64
        || report.executions.len() != report.runs.len()
        || report.broker_trials.len() > 8
        || report.denials.len() > 32
        || report.control_measurements.len() > 32
        || report.build_manifest.schema_version != "0.1.0"
        || report.build_manifest.rust != profile.config().toolchain.rust
        || report.build_manifest.target != profile.config().toolchain.component_target
        || report.build_manifest.wasmtime != WASMTIME_VERSION
        || report.build_manifest.wit_bindgen != WIT_BINDGEN_VERSION
        || report.build_manifest.wit_sha256.to_string() != WIT_SHA256
        || report.build_manifest.variants.len() != 6
    {
        return Err(output());
    }
    for (name, expected) in [
        ("wasmtime", report.build_manifest.wasmtime.as_str()),
        ("wit-bindgen", report.build_manifest.wit_bindgen.as_str()),
    ] {
        if !run
            .environment
            .dependency_versions
            .iter()
            .any(|(key, pin)| key.as_str() == name && pin.as_str() == expected)
        {
            return Err(output());
        }
    }
    if run
        .environment
        .fixture_digests
        .get(&CatalogId::parse("components")?)
        != Some(&report.scenario_sha256)
        || run
            .environment
            .fixture_digests
            .get(&CatalogId::parse("component-build-manifest")?)
            != Some(&report.manifest_sha256)
        || Digest::of(&serde_json::to_vec(&report.build_manifest).map_err(|_| output())?)
            != report.manifest_sha256
        || run.environment.wit_sha256 != report.build_manifest.wit_sha256
        || run.environment.component_lockfile_sha256 != report.build_manifest.lock_sha256
        || run
            .environment
            .binary_digests
            .get(&CatalogId::parse("razen-component-runner")?)
            != Some(&report.build_manifest.runner_sha256)
    {
        return Err(output());
    }
    let mut variants = std::collections::BTreeSet::new();
    for entry in &report.build_manifest.variants {
        if !VARIANTS.contains(&entry.variant.as_str())
            || !variants.insert(entry.variant.as_str())
            || entry.file != format!("{}.wasm", entry.variant)
            || entry.length_bytes == 0
            || entry.length_bytes > 16 * 1024 * 1024
            || run
                .environment
                .fixture_digests
                .get(&CatalogId::parse(&entry.variant)?)
                != Some(&entry.sha256)
        {
            return Err(output());
        }
    }
    let session = ledger.read_session(report.session_id)?;
    let owner = ledger.read_project(project)?;
    if session.project_id != project
        || session.session.user_id != owner.user_id
        || ledger.run_id() != run.run_id
    {
        return Err(output());
    }
    if report.foreign_fixtures.len() > 2 {
        return Err(output());
    }
    for foreign in &report.foreign_fixtures {
        let foreign_project = ledger.read_project(foreign.snapshot.project_id)?;
        let imported = ledger
            .read_invocation(foreign.import_invocation_id)?
            .invocation;
        if foreign_project.user_id != owner.user_id
            || foreign_project.project_id == project
            || imported.project_id != foreign_project.project_id
            || imported.tool_id.as_str() != "proof.fixture.import"
            || imported.state != InvocationState::Completed
            || imported.usage.units.get() != 1
        {
            return Err(output());
        }
        let foreign_reader = evidence.snapshot_reader(
            foreign.snapshot.project_id,
            foreign.snapshot.snapshot_id,
            foreign.snapshot.revision,
        )?;
        if foreign_reader.metadata() != &foreign.snapshot
            || hash_snapshot(&foreign_reader)? != foreign.snapshot.sha256
            || evidence
                .artifact(foreign.snapshot.project_id, foreign.snapshot.body_ref)?
                .origin_invocation_id
                != imported.invocation_id
        {
            return Err(output());
        }
    }
    let reader = evidence.snapshot_reader(
        project,
        report.input_snapshot.snapshot_id,
        report.input_snapshot.revision,
    )?;
    if reader.metadata() != &report.input_snapshot
        || hash_snapshot(&reader)? != report.input_after_sha256
        || report.input_before_sha256 != report.input_after_sha256
    {
        return Err(output());
    }
    for (fact, reference) in report.runs.iter().zip(&report.executions) {
        if fact.invocation_id != reference.invocation_id
            || !VARIANTS.contains(&fact.variant.as_str())
            || !report
                .build_manifest
                .variants
                .iter()
                .any(|entry| entry.variant == fact.variant && entry.sha256 == fact.component_sha256)
        {
            return Err(output());
        }
        let invocation = ledger.read_invocation(fact.invocation_id)?.invocation;
        if invocation.session_id != report.session_id
            || invocation.investigation_id != session.session.investigation_id
        {
            return Err(output());
        }
        let input = evidence.read_artifact(project, invocation.input_ref, 8192)?;
        let parsed: ComponentInput = serde_json::from_slice(&input).map_err(|_| output())?;
        if Digest::of(&input) != invocation.input_sha256
            || parsed.variant != fact.variant
            || parsed.snapshot_id != report.input_snapshot.snapshot_id
            || parsed.revision != report.input_snapshot.revision
            || parsed.sha256 != report.input_snapshot.sha256
        {
            return Err(output());
        }
        let execution = ComponentExecution {
            fact: fact.clone(),
            fact_artifact_id: reference.fact_artifact_id,
            proposal_ids: reference.proposal_ids.clone(),
            invocation,
        };
        component_proof::verify_execution(&execution, project, evidence, ledger, profile)?;
        validate_read_facts(&report, &fact.reads, evidence, project, profile, false)?;
        if fact.error.is_none() {
            component_proof::validate_observations(
                &report.input_snapshot,
                &fact.observations,
                profile,
            )?;
        }
    }
    for trial in &report.broker_trials {
        let invocation = ledger.read_invocation(trial.invocation_id)?.invocation;
        let artifact = evidence.artifact(project, trial.artifact_id)?;
        let body = evidence.read_artifact(project, trial.artifact_id, 1024 * 1024)?;
        let stored: BrokerBody = serde_json::from_slice(&body).map_err(|_| output())?;
        if invocation.project_id != project
            || invocation.session_id != report.session_id
            || invocation.usage != trial.usage
            || invocation.state != InvocationState::Failed
            || artifact.origin_invocation_id != invocation.invocation_id
            || stored.invocation_id != trial.invocation_id
            || stored.consumed != trial.consumed
            || serde_json::to_vec(&stored.reads).map_err(|_| output())?
                != serde_json::to_vec(&trial.reads).map_err(|_| output())?
            || serde_json::to_vec(&stored.invalid_observations).map_err(|_| output())?
                != serde_json::to_vec(&trial.invalid_observations).map_err(|_| output())?
            || invocation.usage.bytes.get() != body.len() as u64 + trial.consumed
        {
            return Err(output());
        }
        validate_read_facts(
            &report,
            &trial.reads,
            evidence,
            project,
            profile,
            report
                .host_call_overlap
                .as_ref()
                .is_some_and(|overlap| overlap.rejected_invocation_id == trial.invocation_id),
        )?;
        if trial.invalid_observations.len() > 16 {
            return Err(output());
        }
        for observation in &trial.invalid_observations {
            if component_proof::validate_observations(
                &report.input_snapshot,
                std::slice::from_ref(observation),
                profile,
            )
            .is_ok()
            {
                return Err(output());
            }
        }
    }
    for denial in &report.denials {
        if !report.broker_trials.iter().any(|trial| {
            trial.invocation_id == denial.trial_invocation_id
                && (trial
                    .reads
                    .iter()
                    .any(|read| read.error.as_ref() == Some(&denial.error))
                    || (denial.attempt == "invalid_output"
                        && denial.error.code == ErrorCode::OutputInvalid
                        && !trial.invalid_observations.is_empty()))
        }) {
            return Err(output());
        }
    }
    for attempt in &report.access_attempts {
        let fact = report
            .runs
            .iter()
            .find(|fact| {
                fact.invocation_id == attempt.invocation_id
                    && fact.variant == "fixture-denied-access"
            })
            .ok_or_else(output)?;
        let observation = fact
            .observations
            .get(attempt.observation_index)
            .ok_or_else(output)?;
        if observation.rule_id != format!("fixture.denied.{}", attempt.resource)
            || attempt.denied != (observation.title == "access denied")
        {
            return Err(output());
        }
    }
    let control_state = ledger.read_control(session.session.investigation_id)?;
    if control_state.mode != ControlMode::Running || !control_state.admission_open {
        return Err(output());
    }
    let mut control_events = std::collections::BTreeMap::new();
    let mut cursor = WireInt::ZERO;
    loop {
        let page = ledger.event_page(cursor, 256)?;
        if page.events.is_empty() {
            break;
        }
        for event in page.events {
            if event.aggregate_id == session.session.investigation_id
                && let Some(revision) = event.control_revision
            {
                control_events.insert(revision, event.event_type);
            }
        }
        cursor = page.last_position;
    }
    let mut revision = WireInt::ZERO;
    for sample in &report.control_measurements {
        if sample.investigation_id != session.session.investigation_id
            || sample.ticket_id != sample.measurement.request_id
            || sample.revision_before != revision
            || sample.revision_after.get() != revision.get() + 1
            || sample.measurement.affected_revision != sample.revision_after
            || sample.measurement.clock_epoch_id != run.clock_epoch_id
        {
            return Err(output());
        }
        sample.measurement.validate_barrier_deadline(WireInt::new(
            profile.config().control.ack_deadline_ms.get() * 1000,
        )?)?;
        let event_type = match sample.action {
            ControlAction::Pause => "control.paused",
            ControlAction::Resume => "control.resumed",
            ControlAction::Cancel => "control.cancelled",
        };
        if control_events
            .get(&sample.revision_after)
            .map(CatalogId::as_str)
            != Some(event_type)
        {
            return Err(output());
        }
        revision = sample.revision_after;
    }
    if control_state.revision != revision {
        return Err(output());
    }
    for pair in report
        .runs
        .windows(2)
        .filter(|pair| pair[0].error.is_some())
    {
        let failed = ledger.read_invocation(pair[0].invocation_id)?.invocation;
        let successor = ledger.read_invocation(pair[1].invocation_id)?.invocation;
        if successor.state != InvocationState::Completed
            || successor.control_revision <= failed.control_revision
            || !report.control_measurements.iter().any(|sample| {
                sample.revision_after > failed.control_revision
                    && sample.revision_after <= successor.control_revision
            })
        {
            return Err(output());
        }
    }
    for overlap in [&report.invocation_overlap, &report.host_call_overlap]
        .into_iter()
        .flatten()
    {
        let active = ledger.read_invocation(overlap.active_invocation_id)?;
        let rejected = ledger.read_invocation(overlap.rejected_invocation_id)?;
        if active.invocation.project_id != project || rejected.invocation.project_id != project {
            return Err(output());
        }
        if overlap.active_invocation_id != overlap.rejected_invocation_id
            && rejected
                .invocation
                .error
                .as_ref()
                .is_none_or(|cause| cause.code != ErrorCode::BudgetExhausted)
        {
            return Err(output());
        }
    }
    derive(&report, profile)
}
fn validate_read_facts(
    report: &Report,
    reads: &[ReadFact],
    evidence: &EvidenceStore,
    project: EntityId,
    profile: &LoadedProfile,
    allow_capacity_denial: bool,
) -> ProofResult<()> {
    if reads.len() > 4096 {
        return Err(output());
    }
    let snapshot = &report.input_snapshot;
    let reader = evidence.snapshot_reader(project, snapshot.snapshot_id, snapshot.revision)?;
    let mut cumulative = 0_u64;
    for read in reads {
        if read.bytes > u64::from(read.max_bytes)
            || read.elapsed_us > profile.config().component.invocation_deadline_ms.get() * 1000
        {
            return Err(output());
        }
        let reference_error = crate::adapters::components::snapshot_reader::validate_reference(
            snapshot,
            &read.snapshot,
        )
        .err()
        .map(|cause| cause.code);
        let expected = reference_error.or_else(|| {
            if u64::from(read.max_bytes) > profile.config().transport.chunk_limit_bytes.get() {
                return Some(ErrorCode::BudgetExhausted);
            }
            let end = read.offset.checked_add(u64::from(read.max_bytes));
            if read.max_bytes == 0 || end.is_none_or(|end| end > snapshot.length_bytes.get()) {
                return Some(ErrorCode::InvalidInput);
            }
            if cumulative + u64::from(read.max_bytes)
                > snapshot
                    .length_bytes
                    .get()
                    .min(profile.config().transport.body_limit_bytes.get())
            {
                return Some(ErrorCode::BudgetExhausted);
            }
            None
        });
        if let Some(cause) = &read.error {
            if read.bytes != 0 || read.sha256 != Digest::of(b"") {
                return Err(output());
            }
            if expected != Some(cause.code) {
                match cause.code {
                    ErrorCode::BudgetExhausted if allow_capacity_denial && expected.is_none() => {}
                    ErrorCode::Timeout
                        if expected.is_none()
                            && read.elapsed_us
                                >= profile.config().component.host_call_deadline_ms.get()
                                    * 1000
                            && read.elapsed_us
                                <= profile.config().component.host_call_deadline_ms.get()
                                    * 1000
                                    + 100_000 => {}
                    ErrorCode::Cancelled
                        if expected.is_none() && !report.control_measurements.is_empty() => {}
                    _ => return Err(output()),
                }
            }
            if cause.code == ErrorCode::PermissionDenied
                && !report.foreign_fixtures.iter().any(|foreign| {
                    foreign.snapshot.snapshot_id.to_string() == read.snapshot.snapshot_id
                })
            {
                return Err(output());
            }
            continue;
        }
        if expected.is_some() {
            return Err(output());
        }
        let bytes = reader.read(
            WireInt::new(read.offset)?,
            WireInt::new(u64::from(read.max_bytes))?,
        )?;
        if bytes.len() as u64 != read.bytes || Digest::of(&bytes) != read.sha256 {
            return Err(output());
        }
        cumulative += read.bytes;
    }
    Ok(())
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Component scenario or approved prerequisite does not match the closed fixture contract",
    )
}
fn output() -> ProofError {
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Component evidence is missing, inconsistent, or failed the required operation",
    )
}
