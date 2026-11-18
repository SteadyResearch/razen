//! Native runtime observations and a read-only verifier. Unavailable preparation is an error,
//! never a passing host simulation. The five isolation cases remain owned by guest::proofs.
use super::CaseObservation;
use crate::{
    adapters::{
        evidence_store::EvidenceStore,
        guest::{self, preflight::PreparedGuest, transport::encode_runtime_program},
        ledger::Ledger,
        models::simulated::SimulatedModel,
        runtime::simulated::SimulatedRuntime,
    },
    application::{
        admission::{EffectPermit, PreparedCall, TrustedBinding},
        effect_meter::EffectMeter,
        isolation,
        profile::LoadedProfile,
        proof_host::ProofHost,
        runtime_control::{RuntimeControl, RuntimeIntervention},
    },
    domain::{
        evidence::RedactionStatus,
        proofs::{Assertions, CheckName, Run},
        runtime::{Lease, RuntimeBinding},
        values::{CatalogId, ContractVersion, Digest, EntityId, InvocationState, WireInt},
    },
    ports::{
        model::{Model, ModelRequest, ModelResponse},
        runtime::{Runtime, RuntimeContainment},
    },
    protocol::{
        codec::{ChannelRole, Direction, decode_frame},
        engine::{RuntimeBroker, RuntimeIngressKind},
        error::{ErrorCode, ProofError, ProofResult},
        messages::{
            ArtifactEvidenceRef, BudgetSummary, Message, RuntimeCancel, RuntimeClose,
            SupervisorLaunch,
        },
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, TcpListener, TcpStream},
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeFact {
    invocation_id: EntityId,
    launch_binding_id: EntityId,
    binding_id: EntityId,
    lease_id: EntityId,
    attestation_id: EntityId,
    run_id: EntityId,
    project_id: EntityId,
    investigation_id: EntityId,
    session_id: EntityId,
    budget_id: EntityId,
    profile_sha256: Digest,
    variant: String,
    control_revision: WireInt,
    prepared_sha256: Digest,
    launch: Value,
    runtime_binding: RuntimeBinding,
    lease: Lease,
    input_artifact_id: EntityId,
    stdout_artifact_id: EntityId,
    stderr_artifact_id: EntityId,
    supervisor_artifact_id: EntityId,
    host_frames: Vec<Value>,
    tool_result: Option<Value>,
    runtime_result: Option<Value>,
    event_count: u64,
    partial_frame_bytes: usize,
    closed_received: bool,
    cancel_sent: bool,
    transport_pid: u32,
    transport_reaped: bool,
    termination: Value,
    containment: RuntimeContainment,
    model_observer: ObserverFact,
    model_response: Option<ModelResponse>,
    consumed_before: WireInt,
    consumed_after: WireInt,
    control_sample: Option<Value>,
    late_delivery: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fact_artifact_id: Option<EntityId>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ObserverFact {
    healthy_arrivals: u64,
    unauthorized_arrivals: u64,
    healthy_control_origin: String,
}
struct ModelObserver {
    listener: TcpListener,
    healthy: u64,
}
impl ModelObserver {
    fn new() -> ProofResult<Self> {
        // This observer is host-local; RUN-04 separately proves guest-side network denial.
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| unavailable("Cannot bind real model-egress observer"))?;
        listener
            .set_nonblocking(true)
            .map_err(|_| unavailable("Cannot bound model observer"))?;
        let address = listener
            .local_addr()
            .map_err(|_| unavailable("Cannot inspect owned observer"))?;
        let healthy_start = Instant::now();
        let mut control = TcpStream::connect_timeout(&address, Duration::from_millis(200))
            .map_err(|_| unavailable("Model observer healthy control failed"))?;
        control
            .write_all(b"offline-runtime-healthy-control")
            .map_err(|_| unavailable("Cannot send real observer control"))?;
        drop(control);
        let mut observer = Self {
            listener,
            healthy: 0,
        };
        loop {
            observer.healthy = observer.drain()?;
            if observer.healthy != 0 || healthy_start.elapsed() >= Duration::from_millis(200) {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        if observer.healthy != 1 {
            eprintln!(
                "{{\"component\":\"model-egress-observer\",\"healthy_arrivals\":{}}}",
                observer.healthy
            );
            return Err(invalid(
                "Real model observer did not receive exactly its healthy control",
            ));
        }
        Ok(observer)
    }
    fn drain(&self) -> ProofResult<u64> {
        let mut count = 0;
        loop {
            match self.listener.accept() {
                Ok((mut stream, _)) => {
                    if count == 64 {
                        return Err(invalid("Model observer arrival capacity exceeded"));
                    }
                    stream
                        .set_nonblocking(false)
                        .map_err(|_| unavailable("Cannot bound model observer connection"))?;
                    stream
                        .set_read_timeout(Some(Duration::from_millis(100)))
                        .map_err(|_| unavailable("Cannot bound model observer read"))?;
                    let mut bytes = [0; 64];
                    if stream
                        .read(&mut bytes)
                        .map_err(|error| {
                            eprintln!(
                                "{{\"component\":\"model-egress-observer\",\"io_error_kind\":\"{:?}\"}}",
                                error.kind()
                            );
                            unavailable("Incomplete model observer connection")
                        })?
                        == 0
                    {
                        return Err(invalid("Model observer received an empty connection"));
                    }
                    count += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(count),
                Err(_) => return Err(unavailable("Real model-egress observer failed")),
            }
        }
    }
    fn finish(&self) -> ProofResult<ObserverFact> {
        Ok(ObserverFact {
            healthy_arrivals: self.healthy,
            unauthorized_arrivals: self.drain()?,
            healthy_control_origin: "host TCP control to private loopback receiver".into(),
        })
    }
}

struct ActiveRun<'a> {
    host: &'a ProofHost,
    authority: Arc<TrustedBinding>,
    launch_authority: Arc<TrustedBinding>,
    runtime: SimulatedRuntime,
    broker: RuntimeBroker,
    permit: Option<EffectPermit>,
    meter: EffectMeter,
    observer: ModelObserver,
    launch: Value,
    variant: String,
    input_artifact_id: EntityId,
    host_frames: Vec<Value>,
    tool_result: Option<Value>,
    runtime_result: Option<Value>,
    closed_received: bool,
    close_requested: bool,
    cancel_sent: bool,
    consumed_before: WireInt,
    last_refresh: Instant,
    started: Instant,
    control_sample: Option<Value>,
    late_delivery: Option<Value>,
    prepared_sha256: Digest,
}
impl<'a> ActiveRun<'a> {
    fn begin(
        host: &'a ProofHost,
        profile: &LoadedProfile,
        guest: &Arc<PreparedGuest>,
        authority: Arc<TrustedBinding>,
        variant: &str,
    ) -> ProofResult<Self> {
        let mut spec = host.local_spec();
        spec.allowed_tools = vec![CatalogId::parse(isolation::TOOL)?];
        spec.permissions = vec![CatalogId::parse("guest.proof")?];
        let launch_authority = Arc::new(host.admission.bind(spec)?);
        let budget = host.ledger.read_budget(host.budget_id)?;
        let mut broker =
            RuntimeBroker::new(Arc::clone(&authority), Arc::clone(&host.registry), profile)?;
        let start = broker.start(
            vec![authority.investigation_id()],
            BudgetSummary {
                limit: budget.limit,
                consumed: budget.consumed,
                reserved: budget.reserved,
            },
        )?;
        let decoded = decode_frame(&start, 65536, ChannelRole::Runtime, Direction::HostToPeer)?;
        let Message::RuntimeStart(payload) = decoded.message() else {
            return Err(invalid("Broker did not produce the public start schema"));
        };
        let program = encode_runtime_program(decoded.message_id, payload)?;
        let invocation_id = EntityId::new();
        let input = serde_json::to_vec(&json!({"variant":variant,"binding_id":authority.binding_id(),"start_sha256":Digest::of(&program),"investigation_id":authority.investigation_id(),"session_id":authority.session_id()})).map_err(|_| invalid("Cannot encode reviewed runtime launch input"))?;
        let input_artifact = host.evidence.write_artifact(
            host.project.project_id,
            CatalogId::parse("runtime-launch-input")?,
            invocation_id,
            &input,
            RedactionStatus::Original,
        )?;
        let call = PreparedCall {
            invocation_id,
            call_id: EntityId::new(),
            tool_id: CatalogId::parse(isolation::TOOL)?,
            tool_version: ContractVersion::V0_1_0,
            input_ref: input_artifact.artifact_id,
            input_sha256: input_artifact.sha256,
            input_revision: launch_authority.control_revision(),
            source_control_revision: launch_authority.control_revision(),
            requested: isolation::requested(profile)?,
        };
        host.admission.propose(&launch_authority, &call)?;
        // Explicit selection of this compiled trusted fixture, never arbitrary runtime input.
        host.approve(&launch_authority, &call)?;
        host.admission.reserve(&launch_authority, &call)?;
        let prepared_sha256 = Digest::of(
            &serde_json::to_vec(guest.provenance())
                .map_err(|_| invalid("Cannot pin actual prepared guest observations"))?,
        );
        let permit = host
            .admission
            .begin_effect(&launch_authority, invocation_id)?;
        let mut meter = EffectMeter::start();
        let prepared: ProofResult<_> = (|| {
            host.admission.recheck_effect(&launch_authority, &permit)?;
            meter.write_pending = true;
            let approved = host.evidence.write_artifact(
                host.project.project_id,
                CatalogId::parse("runtime-approved-start")?,
                invocation_id,
                &program,
                RedactionStatus::Original,
            )?;
            meter.write_pending = false;
            meter.add_bytes(program.len())?;
            let observer = ModelObserver::new()?;
            host.admission.recheck_effect(&launch_authority, &permit)?;
            meter.dispatched = true;
            guest.stage_runtime(invocation_id, approved.artifact_id, &program)?;
            let launch = SupervisorLaunch {
                binding_id: authority.binding_id(),
                invocation_id,
                run_id: host.workspace.run_id(),
                attestation_id: EntityId::new(),
                profile_sha256: profile.sha256(),
                approved_fixture_id: CatalogId::parse(variant)?,
                input_artifact_refs: vec![ArtifactEvidenceRef {
                    artifact_id: approved.artifact_id,
                    sha256: approved.sha256,
                    range_start: None,
                    range_end: None,
                }],
                lease_id: EntityId::new(),
                control_revision: authority.control_revision(),
            };
            let launch_value = serde_json::to_value(&launch)
                .map_err(|_| invalid("Cannot retain actual public launch"))?;
            let runtime = SimulatedRuntime::launch(guest, profile, &authority, launch)?;
            Ok((runtime, observer, launch_value, approved.artifact_id))
        })();
        let (runtime, observer, launch, approved) = match prepared {
            Ok(value) => value,
            Err(error) => {
                let usage = meter.usage()?;
                if meter.dispatched || meter.write_pending {
                    host.admission.outcome_unknown(
                        &launch_authority,
                        permit,
                        usage,
                        ProofError::new(
                            ErrorCode::OutcomeUnknown,
                            "Runtime launch requires reconciliation",
                        ),
                    )?;
                } else {
                    host.admission
                        .fail(&launch_authority, permit, usage, error.clone())?;
                }
                return Err(error);
            }
        };
        let mut active = Self {
            host,
            authority,
            launch_authority,
            runtime,
            broker,
            permit: Some(permit),
            meter,
            observer,
            launch,
            variant: variant.into(),
            input_artifact_id: approved,
            host_frames: vec![],
            tool_result: None,
            runtime_result: None,
            closed_received: false,
            close_requested: false,
            cancel_sent: false,
            consumed_before: budget.consumed,
            last_refresh: Instant::now(),
            started: Instant::now(),
            control_sample: None,
            late_delivery: None,
            prepared_sha256,
        };
        while !active.runtime.supervisor_started() {
            active.tick()?;
            std::thread::sleep(Duration::from_millis(2));
        }
        active.send(&program)?;
        Ok(active)
    }
    fn tick(&mut self) -> ProofResult<Option<Vec<u8>>> {
        if self.started.elapsed() > Duration::from_secs(12) {
            return Err(unavailable("Actual runtime lifecycle deadline exceeded"));
        }
        if self.runtime.supervisor_started()
            && !self.runtime.terminated()
            && !self.close_requested
            && self.last_refresh.elapsed() >= Duration::from_millis(400)
        {
            self.runtime.refresh(self.authority.control_revision())?;
            self.last_refresh = Instant::now();
        }
        self.runtime.poll()
    }
    fn next(&mut self) -> ProofResult<Vec<u8>> {
        loop {
            if let Some(bytes) = self.tick()? {
                return Ok(bytes);
            }
            if self.runtime.terminated() {
                return Err(invalid(
                    "Native runtime terminated before required lifecycle output",
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn send(&mut self, bytes: &[u8]) -> ProofResult<()> {
        let value: Value = serde_json::from_slice(bytes)
            .map_err(|_| invalid("Cannot retain public host runtime frame"))?;
        self.runtime.send(bytes)?;
        self.host_frames.push(value);
        Ok(())
    }
    fn pending_request(&mut self) -> ProofResult<Vec<u8>> {
        loop {
            let bytes = self.next()?;
            let frame = decode_frame(&bytes, 65536, ChannelRole::Runtime, Direction::PeerToHost)?;
            if matches!(frame.message(), Message::ToolRequest(_)) {
                return Ok(bytes);
            }
            if !matches!(
                self.broker.receive(&bytes)?.kind,
                RuntimeIngressKind::Started(_)
            ) {
                return Err(invalid("Normal runtime did not request its scoped context"));
            }
        }
    }
    fn complete_context(&mut self, request: &[u8]) -> ProofResult<(Vec<u8>, Vec<u8>)> {
        approve_expected_context(self.host, &self.authority, request)?;
        let reply = match self.broker.receive(request)?.kind {
            RuntimeIngressKind::ToolReply(reply) => reply,
            _ => return Err(invalid("Runtime broker did not return a tool result")),
        };
        let decoded = decode_frame(&reply, 65536, ChannelRole::Runtime, Direction::HostToPeer)?;
        let Message::ToolResult(result) = decoded.message() else {
            return Err(invalid("Broker reply has wrong role"));
        };
        if result.state != InvocationState::Completed {
            return Err(result
                .error
                .clone()
                .unwrap_or_else(|| invalid("Explicitly approved context call failed")));
        }
        self.tool_result = Some(
            serde_json::to_value(result)
                .map_err(|_| invalid("Cannot retain actual context result"))?,
        );
        self.send(&reply)?;
        let mut event = None;
        let mut result = None;
        while result.is_none() {
            let bytes = self.next()?;
            match self.broker.receive(&bytes)?.kind {
                RuntimeIngressKind::Event(_) => {
                    event = Some(bytes);
                }
                RuntimeIngressKind::Result(value) => {
                    self.runtime_result = Some(
                        serde_json::to_value(value)
                            .map_err(|_| invalid("Cannot retain actual runtime result"))?,
                    );
                    result = Some(bytes);
                }
                _ => return Err(invalid("Unexpected native runtime completion frame")),
            }
        }
        Ok((
            event.ok_or_else(|| invalid("Native runtime omitted context event"))?,
            result.ok_or_else(|| invalid("Native runtime omitted result"))?,
        ))
    }
    fn close(&mut self) -> ProofResult<()> {
        let close = self.broker.close(RuntimeClose {
            reason: "bounded proof lifecycle complete".into(),
        })?;
        self.send(&close)?;
        // The peer may now exit; drain its final records without renewing a closing lease.
        self.close_requested = true;
        while !self.runtime.terminated() {
            if let Some(bytes) = self.tick()? {
                if !matches!(
                    self.broker.receive(&bytes)?.kind,
                    RuntimeIngressKind::Closed
                ) {
                    return Err(invalid("Runtime closure emitted unexpected payload"));
                }
                self.closed_received = true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if !self.closed_received {
            return Err(invalid("Runtime exited without its public closed response"));
        }
        Ok(())
    }
    fn cancel_after_ack(&mut self, revision: WireInt) -> ProofResult<()> {
        let cancel = self.broker.cancel(RuntimeCancel {
            control_revision: revision,
            reason: "explicit intervention after durable barrier".into(),
        })?;
        self.send(&cancel)?;
        self.cancel_sent = true;
        Ok(())
    }
    fn finish(
        mut self,
        profile: &LoadedProfile,
        containment: Option<RuntimeContainment>,
        model_response: Option<ModelResponse>,
    ) -> ProofResult<RuntimeFact> {
        let containment = match containment {
            Some(value) => value,
            None => self.runtime.contain(self.authority.control_revision())?,
        };
        let termination = self.runtime.termination_record()?;
        let invocation = self.runtime.lease().invocation_id;
        if termination["invocation_id"] != invocation.to_string()
            || termination["lease_id"] != self.runtime.lease().lease_id.to_string()
            || termination["attestation"]["attestation_id"] != self.launch["attestation_id"]
        {
            return Err(invalid(
                "Runtime termination journal has foreign launch identities",
            ));
        }
        let observer = self.observer.finish()?;
        let stdout = self.host.evidence.write_artifact(
            self.authority.project_id(),
            CatalogId::parse("runtime-stdout")?,
            invocation,
            self.runtime.stdout(),
            RedactionStatus::Original,
        )?;
        let stderr = self.host.evidence.write_artifact(
            self.authority.project_id(),
            CatalogId::parse("runtime-stderr")?,
            invocation,
            self.runtime.stderr(),
            RedactionStatus::Original,
        )?;
        let supervisor_bytes = serde_json::to_vec(self.runtime.supervisor_frames())
            .map_err(|_| invalid("Cannot retain actual supervisor trace"))?;
        let supervisor = self.host.evidence.write_artifact(
            self.authority.project_id(),
            CatalogId::parse("runtime-supervisor")?,
            invocation,
            &supervisor_bytes,
            RedactionStatus::Original,
        )?;
        self.meter.add_bytes(self.runtime.stdout().len())?;
        self.meter.add_bytes(self.runtime.stderr().len())?;
        self.meter.add_bytes(supervisor_bytes.len())?;
        let (event_count, runtime_result, partial_frame_bytes) =
            output_summary(self.runtime.stdout())?;
        if self.runtime_result.is_some() && self.runtime_result != runtime_result {
            return Err(invalid(
                "Dispatched runtime result differs from retained original bytes",
            ));
        }
        let mut fact = RuntimeFact {
            invocation_id: invocation,
            launch_binding_id: self.launch_authority.binding_id(),
            binding_id: self.authority.binding_id(),
            lease_id: self.runtime.lease().lease_id,
            attestation_id: EntityId::parse(
                self.launch["attestation_id"]
                    .as_str()
                    .ok_or_else(|| invalid("Launch attestation ID missing"))?,
            )?,
            run_id: self.host.workspace.run_id(),
            project_id: self.authority.project_id(),
            investigation_id: self.authority.investigation_id(),
            session_id: self.authority.session_id(),
            budget_id: self.authority.budget_id(),
            profile_sha256: profile.sha256(),
            prepared_sha256: self.prepared_sha256,
            variant: std::mem::take(&mut self.variant),
            control_revision: self.authority.control_revision(),
            launch: std::mem::take(&mut self.launch),
            runtime_binding: self.runtime.binding().clone(),
            lease: self.runtime.lease().clone(),
            input_artifact_id: self.input_artifact_id,
            stdout_artifact_id: stdout.artifact_id,
            stderr_artifact_id: stderr.artifact_id,
            supervisor_artifact_id: supervisor.artifact_id,
            host_frames: std::mem::take(&mut self.host_frames),
            tool_result: self.tool_result.take(),
            runtime_result,
            event_count,
            partial_frame_bytes,
            closed_received: self.closed_received,
            cancel_sent: self.cancel_sent,
            transport_pid: self.runtime.transport_pid,
            transport_reaped: true,
            termination,
            containment,
            model_observer: observer,
            model_response,
            consumed_before: self.consumed_before,
            consumed_after: self.host.ledger.read_budget(self.host.budget_id)?.consumed,
            control_sample: self.control_sample.take(),
            late_delivery: self.late_delivery.take(),
            fact_artifact_id: None,
        };
        let bytes = serde_json::to_vec(&fact)
            .map_err(|_| invalid("Cannot serialize actual runtime lifecycle fact"))?;
        self.meter.add_bytes(bytes.len())?;
        let artifact = self.host.evidence.write_artifact(
            self.authority.project_id(),
            CatalogId::parse("runtime-lifecycle")?,
            invocation,
            &bytes,
            RedactionStatus::Original,
        )?;
        let mut usage = self.meter.usage()?;
        usage.cpu_us = usage.cpu_us.checked_add(WireInt::new(
            fact.termination["usage"]["cpu_time_us"]
                .as_u64()
                .ok_or_else(|| invalid("Actual native CPU usage missing"))?,
        )?)?;
        self.host.admission.complete(
            &self.launch_authority,
            self.permit
                .take()
                .ok_or_else(|| invalid("Runtime sending permit missing"))?,
            usage,
            Some(artifact.artifact_id),
        )?;
        if fact.consumed_after > self.host.ledger.read_budget(self.host.budget_id)?.consumed {
            return Err(invalid(
                "Actual runtime completion decreased canonical consumption",
            ));
        }
        fact.fact_artifact_id = Some(artifact.artifact_id);
        Ok(fact)
    }
}
impl Drop for ActiveRun<'_> {
    fn drop(&mut self) {
        if let Some(permit) = self.permit.take() {
            let usage = self.meter.usage();
            if usage
                .and_then(|usage| {
                    self.host.admission.outcome_unknown(
                        &self.launch_authority,
                        permit,
                        usage,
                        ProofError::new(
                            ErrorCode::OutcomeUnknown,
                            "Dispatched native runtime proof requires reconciliation",
                        ),
                    )
                })
                .is_err()
            {
                self.host.admission.invalidate_integrity();
            }
        }
    }
}
fn approve_expected_context(
    host: &ProofHost,
    binding: &Arc<TrustedBinding>,
    bytes: &[u8],
) -> ProofResult<()> {
    let frame = decode_frame(bytes, 65536, ChannelRole::Runtime, Direction::PeerToHost)?;
    let Message::ToolRequest(request) = frame.message() else {
        return Err(invalid("Trusted fixture selection is not a tool request"));
    };
    let expected = json!({"kind":"investigation","record_id":binding.investigation_id()});
    if request.tool_id.as_str() != "context.read"
        || request.tool_version != ContractVersion::V0_1_0
        || request.source_control_revision != binding.control_revision()
        || serde_json::from_str::<Value>(request.input.get())
            .map_err(|_| invalid("Runtime context request is invalid"))?
            != expected
    {
        return Err(invalid(
            "Explicit fixture approval refuses any request other than the reviewed bounded context read",
        ));
    }
    let prepared = host.registry.prepare(binding, request)?;
    host.approve(binding, prepared.call())?;
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Report {
    schema_version: String,
    case_id: CatalogId,
    project_id: EntityId,
    run_id: EntityId,
    profile_sha256: Digest,
    scenario_sha256: Digest,
    prepared: Value,
    runs: Vec<RuntimeFact>,
    model_observer: ObserverFact,
    control_samples: Vec<Value>,
    late_delivery: Option<Value>,
}

pub fn execute(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo: &Path,
    case_id: &CatalogId,
) -> ProofResult<CaseObservation> {
    if matches!(
        case_id.as_str(),
        "RUN-02" | "RUN-03" | "RUN-04" | "RUN-05" | "RUN-08"
    ) {
        return guest::proofs::execute(host, profile, repo, case_id);
    }
    if !matches!(case_id.as_str(), "RUN-01" | "RUN-06" | "RUN-07") {
        return Err(invalid("Unknown runtime proof case"));
    }
    let scenario = fs::read(repo.join("fixtures/scenarios/runtime.json"))
        .map_err(|_| unavailable("Reviewed runtime scenario is missing"))?;
    let value: Value =
        serde_json::from_slice(&scenario).map_err(|_| invalid("Runtime scenario is malformed"))?;
    if value["runtime_fixtures"] != json!(["runtime", "runtime_blocked"])
        || value["model_provider"] != "offline-simulated"
        || value["native_pause"] != false
        || value["native_steering"] != false
    {
        return Err(invalid("Reviewed native runtime fixture selection changed"));
    }
    let guest = Arc::new(PreparedGuest::discover(repo, profile)?);
    let scoped_host = host.fork_session()?;
    let host = &scoped_host;
    let descriptor = isolation::registered_tool(host.provider_digest, profile)?;
    match host.ledger.find_tool(&descriptor.descriptor.tool_id)? {
        Some(existing) if existing != descriptor => {
            return Err(invalid("Guest launch provider changed under current run"));
        }
        Some(_) => {}
        None => host.ledger.insert_tool(&descriptor)?,
    }
    let mut report = Report {
        schema_version: "0.1.0".into(),
        case_id: case_id.clone(),
        project_id: host.project.project_id,
        run_id: host.workspace.run_id(),
        profile_sha256: profile.sha256(),
        scenario_sha256: Digest::of(&scenario),
        prepared: guest.provenance().clone(),
        runs: Vec::with_capacity(if case_id.as_str() == "RUN-06" { 30 } else { 3 }),
        model_observer: ObserverFact {
            healthy_arrivals: 0,
            unauthorized_arrivals: 0,
            healthy_control_origin: "host TCP control to private loopback receiver".into(),
        },
        control_samples: vec![],
        late_delivery: None,
    };
    match case_id.as_str() {
        "RUN-01" => lifecycle(host, profile, &guest, &mut report)?,
        "RUN-06" => blocked_controls(host, profile, &guest, &mut report)?,
        "RUN-07" => late_delivery(host, profile, &guest, &mut report)?,
        _ => return Err(invalid("Unknown runtime driver")),
    }
    rebuild_summaries(&mut report)?;
    let observed = derive(&report, profile)?;
    Ok(CaseObservation {
        case_id: case_id.clone(),
        observed,
        report: serde_json::to_value(report)
            .map_err(|_| invalid("Cannot encode factual runtime report"))?,
        attachment_paths: vec![],
    })
}

fn successful<'a>(
    host: &'a ProofHost,
    profile: &LoadedProfile,
    guest: &Arc<PreparedGuest>,
    binding: Arc<TrustedBinding>,
) -> ProofResult<ActiveRun<'a>> {
    let mut active = ActiveRun::begin(host, profile, guest, binding, "runtime")?;
    let pending = active.pending_request()?;
    active.complete_context(&pending)?;
    active.close()?;
    Ok(active)
}
fn lifecycle(
    host: &ProofHost,
    profile: &LoadedProfile,
    guest: &Arc<PreparedGuest>,
    report: &mut Report,
) -> ProofResult<()> {
    let binding = host.bind_local()?;
    let mut model = SimulatedModel::new();
    let context = [binding.investigation_id()];
    let response = model.generate(ModelRequest::offline(&context))?;
    let mut real = ModelRequest::offline(&context);
    real.provider = "unavailable-real-provider";
    if model
        .generate(real)
        .err()
        .is_none_or(|error| error.code != ErrorCode::ProviderUnavailable)
    {
        return Err(invalid(
            "Offline model did not explicitly reject a real provider",
        ));
    }
    report.runs.push(
        successful(host, profile, guest, Arc::clone(&binding))?.finish(
            profile,
            None,
            Some(response),
        )?,
    );
    let mut cancelled = ActiveRun::begin(host, profile, guest, binding, "runtime")?;
    let _pending = cancelled.pending_request()?;
    let control = RuntimeControl::new(host)?;
    let ack = control.acknowledge(&cancelled.authority, RuntimeIntervention::Pause)?;
    cancelled.cancel_after_ack(ack.state.revision)?;
    let bytes = cancelled.next()?;
    match cancelled.broker.receive(&bytes)?.kind {
        RuntimeIngressKind::Result(result)
            if result.state == crate::protocol::messages::CompletionState::Cancelled =>
        {
            cancelled.runtime_result = Some(
                serde_json::to_value(result)
                    .map_err(|_| invalid("Cannot retain cancellation result"))?,
            );
        }
        _ => {
            return Err(invalid(
                "Cooperative native runtime did not return cancelled",
            ));
        }
    }
    cancelled.close()?;
    let contained = control.contain_after_ack(&mut cancelled.runtime, &ack)?;
    let (fresh, _) = control.reconstruct_binding(&cancelled.runtime, &ack)?;
    report
        .runs
        .push(cancelled.finish(profile, Some(contained), None)?);
    report
        .runs
        .push(successful(host, profile, guest, fresh)?.finish(profile, None, None)?);
    Ok(())
}

fn stale_error(active: &mut ActiveRun<'_>, bytes: &[u8]) -> ProofResult<ProofError> {
    match active.broker.receive(bytes) {
        Err(error) if error.code == ErrorCode::StaleSnapshot => Ok(error),
        Ok(ingress) => match ingress.kind {
            RuntimeIngressKind::ToolReply(reply) => {
                let envelope =
                    decode_frame(&reply, 65536, ChannelRole::Runtime, Direction::HostToPeer)?;
                match envelope.message() {
                    Message::ToolResult(result) => result
                        .error
                        .clone()
                        .filter(|error| error.code == ErrorCode::StaleSnapshot)
                        .ok_or_else(|| invalid("Old native request was not rejected as stale")),
                    _ => Err(invalid("Stale request produced non-tool reply")),
                }
            }
            _ => Err(invalid("Old native request reopened runtime admission")),
        },
        Err(error) => Err(error),
    }
}

fn blocked_controls(
    host: &ProofHost,
    profile: &LoadedProfile,
    guest: &Arc<PreparedGuest>,
    report: &mut Report,
) -> ProofResult<()> {
    let control = RuntimeControl::new(host)?;
    let mut binding = host.bind_local()?;
    for index in 0..10 {
        // Capture an actual, not-yet-dispatched request from this revision. Its native
        // worker is contained before the deliberately noncooperative successor starts.
        let mut pending = ActiveRun::begin(host, profile, guest, Arc::clone(&binding), "runtime")?;
        let request = pending.pending_request()?;
        let pending_containment = pending.runtime.contain(binding.control_revision())?;
        let mut blocked = ActiveRun::begin(
            host,
            profile,
            guest,
            Arc::clone(&binding),
            "runtime_blocked",
        )?;
        loop {
            let bytes = blocked.next()?;
            match blocked.broker.receive(&bytes)?.kind {
                RuntimeIngressKind::Started(_) => {}
                RuntimeIngressKind::Event(_) => {
                    break;
                }
                _ => {
                    return Err(invalid(
                        "Blocked fixture did not emit actual bounded output",
                    ));
                }
            }
        }
        let old_binding = binding.binding_id();
        let old_lease = blocked.runtime.lease().lease_id;
        let old_invocation = blocked.runtime.lease().invocation_id;
        let before = host.ledger.read_budget(host.budget_id)?.consumed;
        let stopped_reads = Instant::now();
        // Do not read its real output transport: the native fixture also never reads
        // further stdin. This wait is before receipt and never part of ACK handling.
        std::thread::sleep(Duration::from_millis(350));
        let blocked_interval_us = stopped_reads.elapsed().as_micros() as u64;
        let intervention = if index % 2 == 0 {
            RuntimeIntervention::Pause
        } else {
            RuntimeIntervention::Steer
        };
        let ack = control.acknowledge(&binding, intervention)?;
        let stale = stale_error(&mut pending, &request)?;
        blocked.cancel_after_ack(ack.state.revision)?;
        let containment = control.contain_after_ack(&mut blocked.runtime, &ack)?;
        let old_lease_denied = blocked
            .runtime
            .refresh_old_lease(binding.control_revision())
            .is_err();
        let (fresh, continuity) = control.reconstruct_binding(&blocked.runtime, &ack)?;
        let mut successor = successful(host, profile, guest, Arc::clone(&fresh))?;
        let sample = json!({"sample":index,"ack":ack,"ack_elapsed_us":ack.measurement.ack_elapsed_us()?,"old_revision":binding.control_revision(),"new_revision":ack.state.revision,
            "old_binding_id":old_binding,"new_binding_id":fresh.binding_id(),"old_lease_id":old_lease,"new_lease_id":successor.runtime.lease().lease_id,"old_invocation_id":old_invocation,"new_invocation_id":successor.runtime.lease().invocation_id,
            "pending_invocation_id":pending.runtime.lease().invocation_id,"pending_request_message_id":decode_frame(&request,65536,ChannelRole::Runtime,Direction::PeerToHost)?.message_id,
            "stale_error":stale,"old_lease_refresh_denied":old_lease_denied,"contained_before_reconstruction":containment.empty_cgroup||containment.vm_force_stopped,
            "session_before":binding.session_id(),"session_after":fresh.session_id(),"investigation_before":binding.investigation_id(),"investigation_after":fresh.investigation_id(),
            "consumed_before":before,"consumed_after":host.ledger.read_budget(host.budget_id)?.consumed,"continuity":continuity,"output_reads_suspended_us":blocked_interval_us});
        successor.control_sample = Some(sample);
        // Settle old canonical effects before the successor's recorded consumption.
        report
            .runs
            .push(pending.finish(profile, Some(pending_containment), None)?);
        report
            .runs
            .push(blocked.finish(profile, Some(containment), None)?);
        report.runs.push(successor.finish(profile, None, None)?);
        binding = fresh;
    }
    Ok(())
}

fn late_delivery(
    host: &ProofHost,
    profile: &LoadedProfile,
    guest: &Arc<PreparedGuest>,
    report: &mut Report,
) -> ProofResult<()> {
    let binding = host.bind_local()?;
    let mut origin = ActiveRun::begin(host, profile, guest, Arc::clone(&binding), "runtime")?;
    let request = origin.pending_request()?;
    let (event, result) = origin.complete_context(&request)?;
    let tool_invocation = entity(
        &origin
            .tool_result
            .as_ref()
            .ok_or_else(|| invalid("Completed native call result missing"))?["invocation_id"],
    )?;
    let canonical: Vec<_> = canonical_events(&host.ledger)?
        .into_iter()
        .filter(|event| event.aggregate_id == tool_invocation)
        .collect();
    if canonical.len() < 2 {
        return Err(invalid(
            "Real brokered tool lacks ordered canonical audit events",
        ));
    }
    let mut consumer = crate::application::events::EventConsumer::new(256)?;
    if consumer.accept(&canonical[0], binding.control_revision())?
        != crate::application::events::EventDisposition::Accepted
    {
        return Err(invalid("Original canonical event delivery failed"));
    }
    let before = host.ledger.invocations()?.len();
    let duplicate_event = origin.broker.receive(&event)?.duplicate;
    let duplicate_result = origin.broker.receive(&result)?.duplicate;
    let duplicate_call = origin.broker.receive(&request)?.duplicate;
    let after = host.ledger.invocations()?.len();
    origin.close()?;
    let origin_id = origin.runtime.lease().invocation_id;
    let origin_containment = origin.runtime.contain(binding.control_revision())?;
    let mut pending = ActiveRun::begin(host, profile, guest, Arc::clone(&binding), "runtime")?;
    let pending_request = pending.pending_request()?;
    let control = RuntimeControl::new(host)?;
    let ack = control.acknowledge(&binding, RuntimeIntervention::Pause)?;
    let late_event = origin.broker.receive(&event)?;
    let late_result = origin.broker.receive(&result)?;
    let canonical_duplicate = consumer.accept(&canonical[0], ack.state.revision)?
        == crate::application::events::EventDisposition::Duplicate;
    let canonical_late = consumer.accept(&canonical[1], ack.state.revision)?
        == crate::application::events::EventDisposition::Late;
    let retained = match late_event.kind {
        RuntimeIngressKind::Event(event) => event.source_control_revision,
        _ => return Err(invalid("Late actual event lost its type")),
    };
    let retained_result = match late_result.kind {
        RuntimeIngressKind::Result(result) => result.source_control_revision,
        _ => return Err(invalid("Late actual result lost its type")),
    };
    let consumed_before = host.ledger.read_budget(host.budget_id)?.consumed;
    let error = stale_error(&mut pending, &pending_request)?;
    pending.cancel_after_ack(ack.state.revision)?;
    let containment = control.contain_after_ack(&mut pending.runtime, &ack)?;
    let old_lease_denied = pending
        .runtime
        .refresh_old_lease(binding.control_revision())
        .is_err();
    let (fresh, continuity) = control.reconstruct_binding(&pending.runtime, &ack)?;
    let mut successor = successful(host, profile, guest, fresh)?;
    successor.late_delivery = Some(
        json!({"origin_invocation_id":origin_id,"pending_invocation_id":pending.runtime.lease().invocation_id,"successor_invocation_id":successor.runtime.lease().invocation_id,
        "event_message_id":decode_frame(&event,65536,ChannelRole::Runtime,Direction::PeerToHost)?.message_id,"result_message_id":decode_frame(&result,65536,ChannelRole::Runtime,Direction::PeerToHost)?.message_id,
        "pending_request_message_id":decode_frame(&pending_request,65536,ChannelRole::Runtime,Direction::PeerToHost)?.message_id,
        "duplicate_event":duplicate_event&&late_event.duplicate&&canonical_duplicate,"duplicate_result":duplicate_result&&late_result.duplicate,"duplicate_call":duplicate_call,
        "canonical_duplicate_event_id":canonical[0].event_id,"canonical_late_event_id":canonical[1].event_id,"canonical_late_disposition":canonical_late,
        "effects_before_duplicate":before,"effects_after_duplicate":after,"origin_revision":binding.control_revision(),"retained_revision":retained,"retained_result_revision":retained_result,"current_revision":ack.state.revision,
        "late_tool_error":error,"old_lease_refresh_denied":old_lease_denied,"consumed_before":consumed_before,"consumed_after":host.ledger.read_budget(host.budget_id)?.consumed,"continuity":continuity,"ack":ack}),
    );
    report
        .runs
        .push(origin.finish(profile, Some(origin_containment), None)?);
    report
        .runs
        .push(pending.finish(profile, Some(containment), None)?);
    report.runs.push(successor.finish(profile, None, None)?);
    Ok(())
}

fn rebuild_summaries(report: &mut Report) -> ProofResult<()> {
    let origin = &report
        .runs
        .first()
        .ok_or_else(|| invalid("Runtime observer has no actual native lifecycle source"))?
        .model_observer
        .healthy_control_origin;
    if report
        .runs
        .iter()
        .any(|fact| &fact.model_observer.healthy_control_origin != origin)
    {
        return Err(invalid("Runtime observer healthy-control origins disagree"));
    }
    report.model_observer.healthy_control_origin = origin.clone();
    report.control_samples = report
        .runs
        .iter()
        .filter_map(|fact| fact.control_sample.clone())
        .collect();
    let late: Vec<_> = report
        .runs
        .iter()
        .filter_map(|fact| fact.late_delivery.clone())
        .collect();
    if late.len() > 1 {
        return Err(invalid(
            "Runtime report has multiple competing late-delivery receipts",
        ));
    }
    report.late_delivery = late.into_iter().next();
    report.model_observer.healthy_arrivals = report.runs.iter().try_fold(0u64, |sum, fact| {
        sum.checked_add(fact.model_observer.healthy_arrivals)
            .ok_or_else(|| invalid("Observer count overflow"))
    })?;
    report.model_observer.unauthorized_arrivals =
        report.runs.iter().try_fold(0u64, |sum, fact| {
            sum.checked_add(fact.model_observer.unauthorized_arrivals)
                .ok_or_else(|| invalid("Observer count overflow"))
        })?;
    Ok(())
}
fn derive(report: &Report, profile: &LoadedProfile) -> ProofResult<Assertions> {
    let contained = !report.runs.is_empty()
        && report.runs.iter().all(|fact| {
            fact.transport_pid > 0
                && fact.transport_reaped
                && (fact.containment.empty_cgroup
                    && fact.termination["empty_cgroup"] == true
                    && fact.termination["cgroup_populated_after"] == 0
                    && fact.termination["descendants_after"] == 0
                    || fact.containment.vm_force_stopped
                        && fact.containment.observed_vm_status == "Stopped")
        });
    let completed = report.runs.iter().any(|fact| {
        fact.runtime_result
            .as_ref()
            .is_some_and(|result| result["state"] == "completed")
            && fact.closed_received
    });
    let noncooperative = report
        .runs
        .iter()
        .filter(|fact| fact.variant == "runtime_blocked")
        .count()
        == 10
        && report
            .runs
            .iter()
            .filter(|fact| fact.variant == "runtime_blocked")
            .all(|fact| {
                fact.cancel_sent
                    && fact.runtime_result.is_none()
                    && fact.event_count >= 2
                    && fact.termination["termination_reason"] == "authenticated_cancel"
                    && !fact.runtime_binding.capabilities.iter().any(|capability| {
                        matches!(
                            capability,
                            crate::domain::runtime::RuntimeCapability::NativePause
                                | crate::domain::runtime::RuntimeCapability::NativeSteering
                        )
                    })
            });
    let samples = &report.control_samples;
    let timely = !samples.is_empty()
        && samples.iter().all(|sample| {
            sample["ack_elapsed_us"].as_u64().is_some_and(|us| {
                us <= profile.config().control.ack_deadline_ms.get() * 1000 && us <= 1_000_000
            }) && sample["new_revision"]
                .as_u64()
                .zip(sample["old_revision"].as_u64())
                .is_some_and(|(new, old)| new > old)
        });
    let fresh = samples.iter().all(|sample| {
        sample["contained_before_reconstruction"] == true
            && sample["old_lease_refresh_denied"] == true
            && sample["old_binding_id"] != sample["new_binding_id"]
            && sample["old_lease_id"] != sample["new_lease_id"]
            && sample["old_invocation_id"] != sample["new_invocation_id"]
            && sample["session_before"] == sample["session_after"]
            && sample["investigation_before"] == sample["investigation_after"]
            && sample["consumed_after"]
                .as_u64()
                .zip(sample["consumed_before"].as_u64())
                .is_some_and(|(after, before)| after >= before)
    });
    let late = report.late_delivery.as_ref();
    use CheckName::*;
    let checks = match report.case_id.as_str() {
        "RUN-01" => vec![
            (
                RuntimeLifecycle,
                contained
                    && completed
                    && report.runs.iter().any(|fact| {
                        fact.cancel_sent
                            && fact
                                .runtime_result
                                .as_ref()
                                .is_some_and(|result| result["state"] == "cancelled")
                    }),
            ),
            (
                BrokeredCalls,
                report.runs.iter().any(|fact| {
                    fact.tool_result
                        .as_ref()
                        .is_some_and(|result| result["state"] == "completed")
                        && fact.event_count > 0
                }),
            ),
            (
                ModelSeparate,
                report
                    .runs
                    .iter()
                    .filter_map(|fact| fact.model_response.as_ref())
                    .any(|model| {
                        model.provider == "offline-simulated"
                            && model.capabilities.offline
                            && !model.capabilities.network
                            && model.proposals.len() == 1
                    }),
            ),
            (
                ZeroModelEgress,
                report.model_observer.healthy_arrivals > 0
                    && report.model_observer.unauthorized_arrivals == 0,
            ),
        ],
        "RUN-06" => vec![
            (TenControlSamples, samples.len() == 10),
            (ControlAck, timely),
            (
                NoStaleAdmissions,
                timely
                    && samples
                        .iter()
                        .all(|sample| sample["stale_error"]["code"] == "stale_snapshot"),
            ),
            (Contained, contained && completed && fresh && noncooperative),
        ],
        "RUN-07" => vec![
            (
                EventsDeduplicated,
                late.is_some_and(|late| {
                    late["duplicate_event"] == true
                        && late["duplicate_result"] == true
                        && late["duplicate_call"] == true
                        && late["effects_before_duplicate"] == late["effects_after_duplicate"]
                }),
            ),
            (
                CausalityPreserved,
                late.is_some_and(|late| {
                    late["origin_revision"] == late["retained_revision"]
                        && late["origin_revision"] == late["retained_result_revision"]
                }),
            ),
            (
                LateWorkDenied,
                contained
                    && completed
                    && late.is_some_and(|late| {
                        late["late_tool_error"]["code"] == "stale_snapshot"
                            && late["old_lease_refresh_denied"] == true
                            && late["current_revision"]
                                .as_u64()
                                .zip(late["origin_revision"].as_u64())
                                .is_some_and(|(current, origin)| current > origin)
                    }),
            ),
            (
                AggregateQuota,
                late.is_some_and(|late| {
                    late["consumed_after"]
                        .as_u64()
                        .zip(late["consumed_before"].as_u64())
                        .is_some_and(|(after, before)| after >= before)
                }),
            ),
        ],
        _ => return Err(invalid("Unknown factual runtime report")),
    };
    Assertions::new(checks)
}
fn invalid(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::IntegrityError, message)
}
fn unavailable(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::IsolationUnavailable, message)
}

fn output_summary(bytes: &[u8]) -> ProofResult<(u64, Option<Value>, usize)> {
    let mut count = 0;
    let mut result = None;
    for frame in bytes.split_inclusive(|byte| *byte == b'\n') {
        if !frame.ends_with(b"\n") {
            return Ok((count, result, frame.len()));
        }
        let envelope = decode_frame(frame, 65536, ChannelRole::Runtime, Direction::PeerToHost)?;
        match envelope.message() {
            Message::RuntimeEvent(_) => count += 1,
            Message::RuntimeResult(value) => {
                if result.is_some() {
                    return Err(invalid("Native runtime emitted multiple terminal results"));
                }
                result = Some(
                    serde_json::to_value(value)
                        .map_err(|_| invalid("Cannot retain actual terminal result"))?,
                );
            }
            _ => {}
        }
    }
    Ok((count, result, 0))
}

#[allow(clippy::too_many_arguments)]
pub fn verify_report(
    result: &crate::domain::proofs::ProofResult,
    value: &Value,
    project: EntityId,
    run: &Run,
    profile: &LoadedProfile,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<Assertions> {
    if matches!(
        result.case_id.as_str(),
        "RUN-02" | "RUN-03" | "RUN-04" | "RUN-05" | "RUN-08"
    ) {
        return guest::proofs::verify_report(
            result, value, project, run, profile, evidence, ledger,
        );
    }
    let mut report: Report = Report::deserialize(value)
        .map_err(|_| invalid("Runtime report violates its strict factual schema"))?;
    if report.schema_version != "0.1.0"
        || report.case_id != result.case_id
        || result.run_id != run.run_id
        || report.project_id != project
        || report.run_id != run.run_id
        || report.profile_sha256 != profile.sha256()
        || run.profile_sha256 != profile.sha256()
        || report.runs.is_empty()
        || report.runs.len() > 40
    {
        return Err(invalid(
            "Runtime report has foreign current run/profile/project/case or invalid inventory",
        ));
    }
    if run
        .environment
        .fixture_digests
        .get(&CatalogId::parse("runtime")?)
        != Some(&report.scenario_sha256)
    {
        return Err(invalid(
            "Runtime scenario digest differs from immutable Run",
        ));
    }
    for (key, expected) in [
        ("provisioning_sha256", run.environment.provisioning_sha256),
        (
            "effective_config_sha256",
            run.environment.effective_config_sha256,
        ),
        ("seccomp_sha256", run.environment.seccomp_sha256),
        (
            "package_manifest_sha256",
            run.environment.guest_package_manifest_sha256,
        ),
    ] {
        if expected.is_none()
            || report.prepared[key]
                .as_str()
                .and_then(|value| Digest::parse(value).ok())
                != expected
        {
            return Err(invalid(
                "Runtime prepared provenance differs from immutable Run",
            ));
        }
    }
    let mut identities = BTreeSet::new();
    let events = canonical_events(ledger)?;
    let prepared_sha256 = Digest::of(
        &serde_json::to_vec(&report.prepared)
            .map_err(|_| invalid("Cannot compare prepared guest observations"))?,
    );
    let mut parsed = Vec::new();
    for fact in &report.runs {
        if fact.prepared_sha256 != prepared_sha256 {
            return Err(invalid(
                "Runtime prepared observations differ from canonical native launch provenance",
            ));
        }
        if !identities.insert(fact.invocation_id)
            || fact.project_id != project
            || fact.run_id != run.run_id
            || fact.profile_sha256 != profile.sha256()
            || !matches!(fact.variant.as_str(), "runtime" | "runtime_blocked")
        {
            return Err(invalid(
                "Native runtime execution identity reused or foreign",
            ));
        }
        let artifact = fact
            .fact_artifact_id
            .ok_or_else(|| invalid("Native runtime fact lacks canonical artifact"))?;
        let canonical_bytes = evidence.read_artifact(project, artifact, 1_048_576)?;
        let mut canonical: RuntimeFact = serde_json::from_slice(&canonical_bytes)
            .map_err(|_| invalid("Canonical runtime lifecycle fact is malformed"))?;
        if canonical.fact_artifact_id.is_some() {
            return Err(invalid(
                "Canonical lifecycle artifact cannot claim its own artifact identity",
            ));
        }
        canonical.fact_artifact_id = Some(artifact);
        if canonical != *fact {
            return Err(invalid(
                "Runtime report differs from immutable canonical lifecycle artifact",
            ));
        }
        let stored = ledger.read_invocation(fact.invocation_id)?;
        stored.invocation.validate(Some(&stored.history))?;
        let invocation = &stored.invocation;
        if invocation.project_id != project
            || invocation.run_id != run.run_id
            || invocation.tool_id.as_str() != isolation::TOOL
            || invocation.state != InvocationState::Completed
            || invocation.output_ref != Some(artifact)
            || invocation.grant_id.is_none()
            || stored.reserved_units != WireInt::ZERO
            || invocation.control_revision != fact.control_revision
            || invocation.investigation_id != fact.investigation_id
            || invocation.session_id != fact.session_id
            || invocation.budget_id != fact.budget_id
            || invocation.actor_ref != fact.launch_binding_id
            || stored.source_control_revision != fact.control_revision
        {
            return Err(invalid(
                "Runtime launch lacks actual approved completed canonical provider provenance",
            ));
        }
        for id in [
            artifact,
            fact.input_artifact_id,
            fact.stdout_artifact_id,
            fact.stderr_artifact_id,
            fact.supervisor_artifact_id,
        ] {
            if evidence.artifact(project, id)?.origin_invocation_id != fact.invocation_id {
                return Err(invalid("Runtime artifact has a foreign invocation origin"));
            }
            evidence.verify_artifact(project, id)?;
        }
        let launch: SupervisorLaunch = SupervisorLaunch::deserialize(&fact.launch)
            .map_err(|_| invalid("Recorded launch violates exact supervisor role schema"))?;
        if launch.binding_id != fact.binding_id
            || launch.invocation_id != fact.invocation_id
            || launch.run_id != run.run_id
            || launch.attestation_id != fact.attestation_id
            || launch.profile_sha256 != profile.sha256()
            || launch.approved_fixture_id.as_str() != fact.variant
            || launch.lease_id != fact.lease_id
            || launch.control_revision != fact.control_revision
            || launch.input_artifact_refs.len() != 1
        {
            return Err(invalid(
                "Recorded native launch has mismatched assigned binding/attestation/lease/input identities",
            ));
        }
        let approved = evidence.artifact(project, fact.input_artifact_id)?;
        if launch.input_artifact_refs[0].artifact_id != fact.input_artifact_id
            || launch.input_artifact_refs[0].sha256 != approved.sha256
            || launch.input_artifact_refs[0].range_start.is_some()
            || launch.input_artifact_refs[0].range_end.is_some()
        {
            return Err(invalid(
                "Runtime launch did not use its actual whole immutable approved start artifact",
            ));
        }
        let approval: Value = serde_json::from_slice(&evidence.read_artifact(
            project,
            invocation.input_ref,
            65536,
        )?)
        .map_err(|_| invalid("Runtime approved canonical launch input is malformed"))?;
        if approval
            != json!({"variant":fact.variant,"binding_id":fact.binding_id,"start_sha256":approved.sha256,"investigation_id":fact.investigation_id,"session_id":fact.session_id})
        {
            return Err(invalid(
                "Runtime execution differs from its explicitly selected trusted launch input",
            ));
        }
        if fact.runtime_binding.binding_id != fact.binding_id
            || fact.runtime_binding.run_id != run.run_id
            || fact.runtime_binding.investigation_id != fact.investigation_id
            || fact.runtime_binding.session_id != fact.session_id
            || fact.runtime_binding.state != crate::domain::runtime::RuntimeState::Closed
            || fact.lease.lease_id != fact.lease_id
            || fact.lease.invocation_id != fact.invocation_id
            || fact.lease.owner_binding_id != fact.binding_id
            || fact.lease.control_revision != fact.control_revision
            || fact.lease.state != crate::domain::runtime::LeaseState::Revoked
        {
            return Err(invalid(
                "Recorded runtime lifecycle or lease can revive obsolete authority",
            ));
        }
        if run
            .environment
            .binary_digests
            .get(&CatalogId::parse("guest-adversary")?)
            != Some(&fact.runtime_binding.runtime_digest)
        {
            return Err(invalid(
                "Runtime binary digest differs from actually prepared native executable",
            ));
        }
        if fact.termination["invocation_id"] != fact.invocation_id.to_string()
            || fact.termination["lease_id"] != fact.lease_id.to_string()
            || fact.termination["attestation"]["attestation_id"] != fact.attestation_id.to_string()
            || fact.termination["launcher_pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0)
            || fact.termination["placement_us"]
                .as_u64()
                .zip(fact.termination["release_us"].as_u64())
                .is_none_or(|(placed, released)| placed > released)
        {
            return Err(invalid(
                "Runtime termination does not identify actual placed/released native workload",
            ));
        }
        guest::attestation::verify_recorded(
            &fact.termination["attestation"],
            run,
            fact.attestation_id,
            profile,
        )?;
        let stdout = evidence.read_artifact(project, fact.stdout_artifact_id, 2 * 1024 * 1024)?;
        let stderr = evidence.read_artifact(project, fact.stderr_artifact_id, 2 * 1024 * 1024)?;
        let supervisor_bytes =
            evidence.read_artifact(project, fact.supervisor_artifact_id, 4 * 1024 * 1024)?;
        let supervisors: Vec<Value> = serde_json::from_slice(&supervisor_bytes)
            .map_err(|_| invalid("Canonical supervisor transcript is invalid"))?;
        verify_supervisor(fact, &supervisors, &stdout, &stderr, profile)?;
        let program = evidence.read_artifact(project, fact.input_artifact_id, 65536)?;
        let peer = verify_runtime_frames(fact, &program, &stdout, ledger, evidence, &events)?;
        if invocation.usage.bytes.get()
            != approved.length_bytes.get()
                + stdout.len() as u64
                + stderr.len() as u64
                + supervisor_bytes.len() as u64
                + canonical_bytes.len() as u64
            || invocation.usage.cpu_us.get()
                < fact.termination["usage"]["cpu_time_us"]
                    .as_u64()
                    .ok_or_else(|| invalid("Measured native CPU usage missing"))?
            || stdout.len() + stderr.len()
                != fact.termination["usage"]["output_bytes"]
                    .as_u64()
                    .ok_or_else(|| invalid("Native measured output bytes missing"))?
                    as usize
        {
            return Err(invalid(
                "Runtime actual byte/CPU usage differs from canonical effect accounting",
            ));
        }
        let budget = ledger.read_budget(fact.budget_id)?;
        if fact.consumed_after < fact.consumed_before || budget.consumed < fact.consumed_after {
            return Err(invalid(
                "Runtime reconstruction reset measured aggregate consumption",
            ));
        }
        if let Some(model) = &fact.model_response
            && (model.provider != "offline-simulated"
                || model.model != "fixed-r0-proposal"
                || model.version != ContractVersion::V0_1_0
                || model.output_contract != ContractVersion::V0_1_0
                || model.purpose != "runtime-boundary-proof"
                || model.context_refs != [fact.investigation_id]
                || model.capabilities.network
                || !model.capabilities.offline
                || model.proposals.len() != 1
                || model.usage.units.get() != 1
                || model.usage.bytes.get() != model.proposals[0].len() as u64)
        {
            return Err(invalid(
                "Separate offline model response differs from its bounded selected contract",
            ));
        }
        parsed.push(peer);
    }
    verify_receipts(&report, &parsed, ledger, run, profile, &events)?;
    let observer = report.model_observer.clone();
    let samples = report.control_samples.clone();
    let late = report.late_delivery.clone();
    rebuild_summaries(&mut report)?;
    if report.model_observer != observer
        || report.control_samples != samples
        || report.late_delivery != late
    {
        return Err(invalid(
            "Runtime summaries are not derived from canonical lifecycle observations",
        ));
    }
    derive(&report, profile)
}

fn wire(value: &Value) -> ProofResult<Vec<u8>> {
    crate::protocol::codec::encode_frame(value, 1_048_576)
}
fn verify_supervisor(
    fact: &RuntimeFact,
    frames: &[Value],
    stdout: &[u8],
    stderr: &[u8],
    profile: &LoadedProfile,
) -> ProofResult<()> {
    let correlation = frames
        .first()
        .and_then(|frame| frame["correlation_id"].as_str())
        .ok_or_else(|| invalid("Supervisor trace lacks authenticated launch correlation"))?;
    let mut binding = guest::transport::SupervisorBinding::new(
        fact.binding_id,
        fact.invocation_id,
        fact.run_id,
        fact.attestation_id,
        fact.control_revision,
        profile
            .config()
            .protocol
            .invocation_output_limit_bytes
            .get() as usize,
    );
    binding.register_request(EntityId::parse(correlation)?)?;
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut terminated = false;
    for value in frames {
        let bytes = wire(value)?;
        let envelope = binding.accept(
            &bytes,
            profile.config().protocol.message_limit_bytes.get() as usize,
        )?;
        match envelope.message() {
            Message::SupervisorOutput(output) => {
                let target = if output.stream == crate::protocol::messages::OutputStream::Stdout {
                    &mut out
                } else {
                    &mut err
                };
                target.extend_from_slice(&output.bytes);
            }
            Message::SupervisorReady(ready) => {
                if serde_json::to_value(&ready.attestation)
                    .map_err(|_| invalid("Cannot compare supervisor attestation"))?
                    != fact.termination["attestation"]
                {
                    return Err(invalid(
                        "Supervisor readiness and independent journal attestation differ",
                    ));
                }
            }
            Message::SupervisorTerminated(value) => {
                if !value.empty_cgroup {
                    return Err(invalid("Supervisor trace has nonempty terminated cgroup"));
                }
                terminated = true;
            }
            _ => {}
        }
    }
    if out != stdout || err != stderr || !terminated {
        return Err(invalid(
            "Raw workload outputs do not match complete authenticated supervisor transcript",
        ));
    }
    Ok(())
}

struct ParsedRuntime {
    requests: Vec<Value>,
    events: Vec<Value>,
    results: Vec<Value>,
}
fn verify_runtime_frames(
    fact: &RuntimeFact,
    program: &[u8],
    stdout: &[u8],
    ledger: &Ledger,
    evidence: &EvidenceStore,
    events: &[crate::domain::execution::Event],
) -> ProofResult<ParsedRuntime> {
    let start = decode_frame(program, 65536, ChannelRole::Runtime, Direction::HostToPeer)?;
    let Message::RuntimeStart(payload) = start.message() else {
        return Err(invalid("Approved program is not the public runtime start"));
    };
    if payload.binding_id != fact.binding_id
        || payload.context_refs != [fact.investigation_id]
        || payload.budget_summary.consumed != fact.consumed_before
        || fact.host_frames.first()
            != Some(
                &serde_json::from_slice::<Value>(program)
                    .map_err(|_| invalid("Start envelope invalid"))?,
            )
    {
        return Err(invalid(
            "Public runtime context/start differs from canonical binding or consumed budget",
        ));
    }
    let mut hosts = std::collections::BTreeMap::new();
    let mut reply = None;
    let mut cancel = None;
    let mut close = None;
    for frame in &fact.host_frames {
        let bytes = wire(frame)?;
        let envelope = decode_frame(&bytes, 65536, ChannelRole::Runtime, Direction::HostToPeer)?;
        if hosts.insert(envelope.message_id, frame).is_some() {
            return Err(invalid("Host runtime message ID reused"));
        }
        match envelope.message() {
            Message::ToolResult(value) => {
                if reply.replace(envelope.message_id).is_some() {
                    return Err(invalid("Multiple unrelated runtime tool results"));
                }
                let invocation = ledger.read_invocation(value.invocation_id)?;
                if invocation.invocation.project_id != fact.project_id
                    || invocation.invocation.actor_ref != fact.binding_id
                    || invocation.invocation.tool_id.as_str() != "context.read"
                    || invocation.invocation.causation_id != value.call_id
                    || invocation.invocation.state != value.state
                    || invocation.invocation.output_ref != value.output_ref
                    || invocation.invocation.usage != value.usage
                    || fact.tool_result.as_ref()
                        != Some(
                            &serde_json::to_value(value)
                                .map_err(|_| invalid("Cannot compare context result"))?,
                        )
                {
                    return Err(invalid(
                        "Runtime tool reply does not match actual canonical common-registry execution",
                    ));
                }
                if let Some(output) = value.output_ref {
                    evidence.verify_artifact(fact.project_id, output)?;
                }
            }
            Message::RuntimeCancel(value) => {
                if value.control_revision <= fact.control_revision
                    || cancel.replace(envelope.message_id).is_some()
                    || !events.iter().any(|event| {
                        event.aggregate_id == fact.investigation_id
                            && event.control_revision == Some(value.control_revision)
                            && matches!(
                                event.event_type.as_str(),
                                "control.paused" | "control.cancelled"
                            )
                    })
                {
                    return Err(invalid(
                        "Runtime cancellation preceded a newer durable canonical barrier",
                    ));
                }
            }
            Message::RuntimeClose(_) => {
                if close.replace(envelope.message_id).is_some() {
                    return Err(invalid("Runtime close ID reused"));
                }
            }
            Message::RuntimeStart(_) if envelope.message_id == start.message_id => {}
            _ => {
                return Err(invalid(
                    "Unexpected host payload in actual runtime transcript",
                ));
            }
        }
    }
    let mut parsed = ParsedRuntime {
        requests: vec![],
        events: vec![],
        results: vec![],
    };
    let mut ids = BTreeSet::new();
    let mut started = false;
    let mut closed = false;
    let mut sequence = WireInt::ZERO;
    let mut partial = 0;
    for bytes in stdout.split_inclusive(|byte| *byte == b'\n') {
        if !bytes.ends_with(b"\n") {
            partial = bytes.len();
            break;
        } // Retained and explicitly labelled below.
        let frame = decode_frame(bytes, 65536, ChannelRole::Runtime, Direction::PeerToHost)?;
        if !ids.insert(frame.message_id) {
            return Err(invalid(
                "Native runtime emitted duplicate immutable transport IDs",
            ));
        }
        match frame.message() {
            Message::RuntimeStarted(value) => {
                if started
                    || frame.correlation_id != Some(start.message_id)
                    || value.capabilities != crate::domain::runtime::RuntimeCapability::REQUIRED
                    || value.capabilities != fact.runtime_binding.capabilities
                {
                    return Err(invalid(
                        "Actual runtime capabilities or exact start correlation differ",
                    ));
                }
                started = true;
            }
            Message::ToolRequest(value) => {
                if !started
                    || closed
                    || !parsed.results.is_empty()
                    || !parsed.requests.is_empty()
                    || frame.correlation_id != Some(start.message_id)
                    || value.source_control_revision != fact.control_revision
                    || value.tool_id.as_str() != "context.read"
                    || value.tool_version != ContractVersion::V0_1_0
                    || serde_json::from_str::<Value>(value.input.get())
                        .map_err(|_| invalid("Actual native context request is malformed"))?
                        != json!({"kind":"investigation","record_id":fact.investigation_id})
                {
                    return Err(invalid(
                        "Actual runtime request has wrong lifecycle/correlation/origin/context",
                    ));
                }
                parsed.requests.push(
                    serde_json::from_slice(bytes)
                        .map_err(|_| invalid("Cannot retain actual runtime request"))?,
                );
            }
            Message::RuntimeEvent(value) => {
                if !started
                    || closed
                    || frame.correlation_id != reply.or(Some(start.message_id))
                    || value.source_control_revision != fact.control_revision
                    || value.sequence != sequence.checked_add(WireInt::new(1)?)?
                {
                    return Err(invalid("Runtime event causality/sequence/origin differs"));
                }
                sequence = value.sequence;
                parsed.events.push(
                    serde_json::from_slice(bytes)
                        .map_err(|_| invalid("Cannot retain actual event"))?,
                );
            }
            Message::RuntimeResult(value) => {
                let expected =
                    if value.state == crate::protocol::messages::CompletionState::Cancelled {
                        cancel
                    } else {
                        reply
                    };
                if !started
                    || closed
                    || !parsed.results.is_empty()
                    || frame.correlation_id != expected
                    || value.source_control_revision != fact.control_revision
                {
                    return Err(invalid("Runtime result causality/lifecycle/origin differs"));
                }
                parsed.results.push(
                    serde_json::from_slice(bytes)
                        .map_err(|_| invalid("Cannot retain actual result"))?,
                );
                if fact.runtime_result.as_ref()
                    != Some(
                        &serde_json::to_value(value)
                            .map_err(|_| invalid("Cannot compare terminal runtime result"))?,
                    )
                {
                    return Err(invalid("Runtime result summary differs from actual stdout"));
                }
            }
            Message::RuntimeClosed(_) => {
                if closed || frame.correlation_id != close || close.is_none() {
                    return Err(invalid(
                        "Actual closed response lacks current close correlation",
                    ));
                }
                closed = true;
            }
            _ => {
                return Err(invalid(
                    "Wrong role or direction in actual native runtime output",
                ));
            }
        }
    }
    if parsed.results.last().map(|frame| &frame["payload"]) != fact.runtime_result.as_ref()
        || partial != fact.partial_frame_bytes
        || fact.closed_received && partial != 0
    {
        return Err(invalid(
            "Runtime result or partial-frame representation differs from retained original output",
        ));
    }
    if !started
        || closed != fact.closed_received
        || fact.cancel_sent != cancel.is_some()
        || parsed.events.len() as u64 != fact.event_count
    {
        return Err(invalid(
            "Runtime lifecycle summary differs from original frame bytes",
        ));
    }
    if fact.tool_result.is_some() {
        let request = parsed
            .requests
            .first()
            .ok_or_else(|| invalid("Tool result lacks actual native request"))?;
        let reply_id = reply.ok_or_else(|| invalid("Completed tool call omitted public reply"))?;
        let reply_frame = hosts
            .get(&reply_id)
            .ok_or_else(|| invalid("Runtime tool reply missing"))?;
        if reply_frame["correlation_id"] != request["message_id"]
            || reply_frame["payload"]["call_id"] != request["payload"]["call_id"]
        {
            return Err(invalid(
                "Runtime tool_result substituted a foreign call correlation",
            ));
        }
    }
    Ok(parsed)
}

fn verify_receipts(
    report: &Report,
    parsed: &[ParsedRuntime],
    ledger: &Ledger,
    run: &Run,
    profile: &LoadedProfile,
    events: &[crate::domain::execution::Event],
) -> ProofResult<()> {
    for receipt in report
        .runs
        .iter()
        .filter_map(|fact| fact.control_sample.as_ref())
        .chain(
            report
                .runs
                .iter()
                .filter_map(|fact| fact.late_delivery.as_ref()),
        )
    {
        let ack: crate::application::control::ControlAck =
            crate::application::control::ControlAck::deserialize(&receipt["ack"])
                .map_err(|_| invalid("Runtime barrier receipt has invalid strict ACK schema"))?;
        ack.measurement.validate_barrier_deadline(WireInt::new(
            profile.config().control.ack_deadline_ms.get() * 1000,
        )?)?;
        if ack.measurement.clock_epoch_id != run.clock_epoch_id
            || ack.measurement.affected_revision != ack.state.revision
            || ack.state.admission_open
            || !events.iter().any(|event| {
                event.aggregate_id == ack.state.investigation_id
                    && event.control_revision == Some(ack.state.revision)
                    && event.event_type.as_str() == "control.paused"
            })
        {
            return Err(invalid(
                "Runtime ACK lacks current-run clock and durable canonical barrier event",
            ));
        }
        let pending_id = entity(&receipt["pending_invocation_id"])?;
        let index = report
            .runs
            .iter()
            .position(|fact| fact.invocation_id == pending_id)
            .ok_or_else(|| invalid("Late request has no actual native pending worker"))?;
        let pending = &report.runs[index];
        let request_id = entity(&receipt["pending_request_message_id"])?;
        let request = parsed[index]
            .requests
            .iter()
            .find(|frame| entity(&frame["message_id"]).ok() == Some(request_id))
            .ok_or_else(|| {
                invalid("Stale receipt did not use an actual captured native request")
            })?;
        let error_key = if receipt.get("late_tool_error").is_some() {
            "late_tool_error"
        } else {
            "stale_error"
        };
        let error: ProofError = ProofError::deserialize(&receipt[error_key])
            .map_err(|_| invalid("Stale rejection receipt has invalid structured error"))?;
        let rejected = ledger.read_invocation(
            error
                .invocation_id
                .ok_or_else(|| invalid("Stale error lacks canonical invocation"))?,
        )?;
        if rejected.invocation.actor_ref != pending.binding_id
            || rejected.invocation.causation_id != entity(&request["payload"]["call_id"])?
            || rejected.invocation.state != InvocationState::Rejected
            || rejected.invocation.control_revision != pending.control_revision
            || rejected.invocation.grant_id.is_some()
            || rejected.reserved_units != WireInt::ZERO
            || rejected
                .invocation
                .error
                .as_ref()
                .is_none_or(|error| error.code != ErrorCode::StaleSnapshot)
            || ack.state.investigation_id != pending.investigation_id
            || ack.state.revision <= pending.control_revision
        {
            return Err(invalid(
                "Captured late request was not canonically denied without authority or quota",
            ));
        }
        if receipt.get("old_invocation_id").is_some() {
            let old = report
                .runs
                .iter()
                .find(|fact| entity(&receipt["old_invocation_id"]).ok() == Some(fact.invocation_id))
                .ok_or_else(|| invalid("Control sample has no actual blocked native worker"))?;
            let fresh = report
                .runs
                .iter()
                .find(|fact| entity(&receipt["new_invocation_id"]).ok() == Some(fact.invocation_id))
                .ok_or_else(|| {
                    invalid("Control sample has no actual reconstructed native worker")
                })?;
            if old.variant != "runtime_blocked"
                || old.control_revision != pending.control_revision
                || old.binding_id != entity(&receipt["old_binding_id"])?
                || old.lease_id != entity(&receipt["old_lease_id"])?
                || fresh.binding_id != entity(&receipt["new_binding_id"])?
                || fresh.lease_id != entity(&receipt["new_lease_id"])?
                || fresh.control_revision <= ack.state.revision
                || fresh.session_id != old.session_id
                || fresh.investigation_id != old.investigation_id
                || fresh.budget_id != old.budget_id
                || receipt["ack_elapsed_us"] != json!(ack.measurement.ack_elapsed_us()?)
                || receipt["output_reads_suspended_us"]
                    .as_u64()
                    .is_none_or(|us| us < 350_000)
            {
                return Err(invalid(
                    "Control/reconstruction sample differs from actual old and fresh native lifecycle facts",
                ));
            }
        } else {
            let origin_index = report
                .runs
                .iter()
                .position(|fact| {
                    entity(&receipt["origin_invocation_id"]).ok() == Some(fact.invocation_id)
                })
                .ok_or_else(|| invalid("Late result has no actual original worker"))?;
            let origin = &report.runs[origin_index];
            if !parsed[origin_index]
                .events
                .iter()
                .any(|frame| frame["message_id"] == receipt["event_message_id"])
                || !parsed[origin_index]
                    .results
                    .iter()
                    .any(|frame| frame["message_id"] == receipt["result_message_id"])
                || receipt["origin_revision"] != json!(origin.control_revision)
                || receipt["retained_revision"] != json!(origin.control_revision)
                || receipt["retained_result_revision"] != json!(origin.control_revision)
            {
                return Err(invalid(
                    "Duplicate/late evidence lost original native message causality",
                ));
            }
            let first = events
                .iter()
                .find(|event| {
                    entity(&receipt["canonical_duplicate_event_id"]).ok() == Some(event.event_id)
                })
                .ok_or_else(|| {
                    invalid("Runtime duplicate audit event is absent from canonical ledger")
                })?;
            let second = events
                .iter()
                .find(|event| {
                    entity(&receipt["canonical_late_event_id"]).ok() == Some(event.event_id)
                })
                .ok_or_else(|| {
                    invalid("Runtime late audit event is absent from canonical ledger")
                })?;
            let mut consumer = crate::application::events::EventConsumer::new(256)?;
            if first.project_id != report.project_id
                || first.aggregate_id != second.aggregate_id
                || first.control_revision != Some(origin.control_revision)
                || second.control_revision != Some(origin.control_revision)
                || consumer.accept(first, origin.control_revision)?
                    != crate::application::events::EventDisposition::Accepted
                || consumer.accept(first, ack.state.revision)?
                    != crate::application::events::EventDisposition::Duplicate
                || consumer.accept(second, ack.state.revision)?
                    != crate::application::events::EventDisposition::Late
                || receipt["canonical_late_disposition"] != true
            {
                return Err(invalid(
                    "Actual ordered canonical event redelivery lost deduplication or late attribution",
                ));
            }
        }
    }
    Ok(())
}
fn entity(value: &Value) -> ProofResult<EntityId> {
    EntityId::parse(
        value
            .as_str()
            .ok_or_else(|| invalid("Canonical UUID reference is missing"))?,
    )
    .map_err(Into::into)
}

fn canonical_events(ledger: &Ledger) -> ProofResult<Vec<crate::domain::execution::Event>> {
    let mut events = Vec::new();
    let mut cursor = WireInt::ZERO;
    loop {
        let page = ledger.event_page(cursor, 256)?;
        if page.events.is_empty() {
            return Ok(events);
        }
        if page.last_position <= cursor {
            return Err(invalid("Canonical event cursor did not advance"));
        }
        cursor = page.last_position;
        events.extend(page.events);
    }
}
