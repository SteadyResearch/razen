//! Actual dedicated-VM observations. Verification reads sealed canonical artifacts, never reruns providers.
use super::{
    integrity,
    preflight::{self, PreparedGuest},
    unavailable,
};
use crate::{
    adapters::{evidence_store::EvidenceStore, ledger::Ledger, workspace::OwnedDirectory},
    application::{
        admission::PreparedCall, effect_meter::EffectMeter, isolation, profile::LoadedProfile,
        proof_host::ProofHost, suites::CaseObservation,
    },
    domain::{
        evidence::RedactionStatus,
        proofs::{Assertions, CheckName, Run},
        values::{CatalogId, ContractVersion, Digest, EntityId, InvocationState, WireInt},
    },
    protocol::{
        error::{ErrorCode, ProofError, ProofResult},
        messages::{ArtifactEvidenceRef, SupervisorLaunch},
    },
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    os::unix::{
        fs::{DirBuilderExt, OpenOptionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};
const FILESYSTEM: &[&str] = &[
    "host_canary",
    "manager_canary",
    "other_invocation",
    "credential",
];
const NETWORK: &[&str] = &[
    "ipv4_tcp",
    "ipv6_tcp",
    "ipv4_udp",
    "ipv6_udp",
    "dns",
    "loopback",
    "gateway",
    "target",
    "model",
    "unix",
    "vsock",
    "inherited_fd",
];
const RESOURCE: &[&str] = &[
    "fork",
    "thread",
    "memory",
    "cpu",
    "tmpfs",
    "output",
    "privilege",
    "namespace",
    "cgroup",
    "descriptor",
];
struct HostEpoch {
    clock: Instant,
    id: EntityId,
}
static HOST_EPOCH: std::sync::LazyLock<HostEpoch> = std::sync::LazyLock::new(|| HostEpoch {
    clock: Instant::now(),
    id: EntityId::new(),
});
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunFact {
    invocation_id: EntityId,
    binding_id: EntityId,
    run_id: EntityId,
    attestation_id: EntityId,
    lease_id: EntityId,
    variant: String,
    input_snapshot_id: EntityId,
    input_revision: WireInt,
    input_sha256: Digest,
    input_artifact_id: EntityId,
    stdout_artifact_id: EntityId,
    stderr_artifact_id: EntityId,
    stdout_bytes: u64,
    stderr_bytes: u64,
    host_clock_epoch_id: EntityId,
    host_started_us: u64,
    host_finished_us: u64,
    transport_pid: u32,
    transport_reaped: bool,
    empty_cgroup: bool,
    live_slots_after: u64,
    elapsed_us: u64,
    outcome: String,
    guest: Value,
    host_canary_sha256: Digest,
    host_canary_read_bytes: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Execution {
    fact: RunFact,
    fact_artifact_id: EntityId,
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
    runs: Vec<Value>,
    executions: Vec<Execution>,
    attempts: Vec<Value>,
    attestations: Vec<Value>,
    contaminations: Vec<Value>,
    observers: Vec<Value>,
    orphan_variants: Vec<Value>,
}
struct Canary {
    path: PathBuf,
    sha: Digest,
    bytes: u64,
}
impl Canary {
    fn new(guest: &PreparedGuest, invocation: EntityId) -> ProofResult<Self> {
        let directory = guest.repository.join("target/r0-guest/canaries");
        if !directory.exists() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|_| unavailable("Cannot create private owned canary store"))?;
        }
        preflight::check_private(&directory, true)?;
        let path = directory.join(invocation.to_string());
        let bytes = EntityId::new().to_string().into_bytes();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| unavailable("Cannot create controlled host canary"))?;
        file.write_all(&bytes)
            .map_err(|_| unavailable("Cannot write controlled host canary"))?;
        file.sync_all()
            .map_err(|_| unavailable("Cannot persist controlled host canary"))?;
        let control = preflight::private_read(&path, 128)?;
        if control != bytes {
            return Err(integrity("Healthy host canary read failed"));
        }
        Ok(Self {
            path,
            sha: Digest::of(&control),
            bytes: control.len() as u64,
        })
    }
}
impl Drop for Canary {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub fn execute(
    host: &ProofHost,
    profile: &LoadedProfile,
    repo: &Path,
    case_id: &CatalogId,
) -> ProofResult<CaseObservation> {
    if !matches!(
        case_id.as_str(),
        "RUN-02" | "RUN-03" | "RUN-04" | "RUN-05" | "RUN-08"
    ) {
        return Err(integrity("Unknown guest isolation proof case"));
    }
    let scenario = fs::read(repo.join("fixtures/scenarios/runtime.json"))
        .map_err(|_| unavailable("Reviewed runtime scenario is unavailable"))?;
    let scenario_value: Value = serde_json::from_slice(&scenario)
        .map_err(|_| integrity("Runtime scenario is malformed"))?;
    if scenario_value["filesystem_variants"] != json!(FILESYSTEM)
        || scenario_value["network_variants"] != json!(NETWORK)
        || scenario_value["resource_variants"] != json!(RESOURCE)
    {
        return Err(integrity("Reviewed closed adversary inventory changed"));
    }
    let guest = Arc::new(PreparedGuest::discover(repo, profile)?);
    let descriptor = isolation::registered_tool(host.provider_digest, profile)?;
    match host.ledger.find_tool(&descriptor.descriptor.tool_id)? {
        Some(existing) => {
            if existing.descriptor != descriptor.descriptor
                || existing.provider_digest != descriptor.provider_digest
            {
                return Err(integrity(
                    "Guest provider registration differs from current trusted controller",
                ));
            }
        }
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
        runs: vec![],
        executions: vec![],
        attempts: vec![],
        attestations: vec![],
        contaminations: vec![],
        observers: vec![],
        orphan_variants: vec![],
    };
    match case_id.as_str() {
        "RUN-02" => {
            push(
                &mut report,
                run_fixture(host, profile, &guest, "snapshot_control", None)?,
                host,
            )?;
            for (name, contents) in [
                ("mount", "mounts: [{location: /tmp}]\n"),
                ("agent", "ssh: {forwardAgent: true}\n"),
                ("proxy", "propagateProxyEnv: true\n"),
                ("missing_plain", "plain: false\n"),
                ("wrong_backend", "vmType: qemu\n"),
                ("missing_limits", "cpus: 4\n"),
            ] {
                report
                    .contaminations
                    .push(contamination(host, profile, &guest, name, contents)?);
                push(
                    &mut report,
                    run_fixture(host, profile, &guest, "snapshot_control", None)?,
                    host,
                )?;
            }
        }
        "RUN-03" | "RUN-04" | "RUN-05" => {
            push(
                &mut report,
                run_fixture(host, profile, &guest, "snapshot_control", None)?,
                host,
            )?;
            let variants = match case_id.as_str() {
                "RUN-03" => FILESYSTEM,
                "RUN-04" => NETWORK,
                _ => RESOURCE,
            };
            for variant in variants {
                push(
                    &mut report,
                    run_fixture(host, profile, &guest, variant, None)?,
                    host,
                )?;
                push(
                    &mut report,
                    run_fixture(host, profile, &guest, "snapshot_control", None)?,
                    host,
                )?;
            }
        }
        "RUN-08" => {
            for variant in ["host_sigkill", "ssh_sigkill"] {
                let execution = run_fixture(host, profile, &guest, "orphan", Some(variant))?;
                report
                    .orphan_variants
                    .push(orphan_summary(&execution, variant)?);
                push(&mut report, execution, host)?;
                push(
                    &mut report,
                    run_fixture(host, profile, &guest, "snapshot_control", None)?,
                    host,
                )?;
            }
        }
        _ => unreachable!(),
    }
    // Healthy controls are linked only after the next real execution succeeds.
    for attempt in &mut report.attempts {
        let invocation = attempt["invocation_id"].as_str().unwrap_or("");
        if let Some(index) = report
            .runs
            .iter()
            .position(|run| run["invocation_id"] == invocation)
            && report.runs.get(index + 1).is_some_and(|next| {
                next["variant"] == "snapshot_control" && next["outcome"] == "completed"
            })
        {
            attempt["healthy_control"] = json!("completed");
            attempt["successor_invocation_id"] = report.runs[index + 1]["invocation_id"].clone();
        }
    }
    let observed = derive(&report, profile)?;
    Ok(CaseObservation {
        case_id: case_id.clone(),
        observed,
        report: serde_json::to_value(report)
            .map_err(|_| integrity("Cannot encode factual guest report"))?,
        attachment_paths: vec![],
    })
}
fn push(report: &mut Report, execution: Execution, host: &ProofHost) -> ProofResult<()> {
    let output = host.evidence.read_artifact(
        report.project_id,
        execution.fact.stdout_artifact_id,
        2 * 1024 * 1024,
    )?;
    let mut attempts = parse_attempts(&output, &execution.fact.variant)?;
    for attempt in &mut attempts {
        attempt["invocation_id"] = json!(execution.fact.invocation_id);
    }
    report.attempts.extend(attempts);
    report
        .attestations
        .push(execution.fact.guest["attestation"].clone());
    if let Some(observers) = execution.fact.guest["observers"].as_array() {
        report.observers.extend(observers.iter().cloned());
    }
    report.runs.push(json!({"invocation_id":execution.fact.invocation_id,"variant":execution.fact.variant,"outcome":execution.fact.outcome,"empty_cgroup":execution.fact.empty_cgroup,"live_slots_after":execution.fact.live_slots_after,"elapsed_us":execution.fact.elapsed_us}));
    report.executions.push(execution);
    Ok(())
}
fn parse_attempts(bytes: &[u8], variant: &str) -> ProofResult<Vec<Value>> {
    let mut attempts = Vec::new();
    for line in bytes.split(|b| *b == b'\n') {
        if line.len() > 65536 {
            continue;
        }
        if let Ok(value) = serde_json::from_slice::<Value>(line)
            && value["variant"] == variant
            && value["pid"].as_u64().is_some_and(|p| p > 0)
            && value["primitive_attempt_count"]
                .as_u64()
                .is_some_and(|n| n > 0)
            && value["count_semantics"] == "completed_primitive_attempts"
        {
            attempts.push(value);
        }
    }
    Ok(attempts)
}

fn run_fixture(
    host: &ProofHost,
    profile: &LoadedProfile,
    guest: &Arc<PreparedGuest>,
    variant: &str,
    orphan: Option<&str>,
) -> ProofResult<Execution> {
    let host_started_us = HOST_EPOCH.clock.elapsed().as_micros() as u64;
    let snapshot = host
        .evidence
        .snapshots()?
        .into_iter()
        .find(|s| {
            s.project_id == host.project.project_id
                && !s.truncated
                && s.length_bytes.get() > 0
                && s.length_bytes.get() <= 65536
        })
        .ok_or_else(|| integrity("No approved bounded public snapshot is available"))?;
    let mut spec = host.local_spec();
    spec.allowed_tools = vec![CatalogId::parse(isolation::TOOL)?];
    spec.permissions = vec![CatalogId::parse("guest.proof")?];
    let binding = Arc::new(host.admission.bind(spec)?);
    let invocation_id = EntityId::new();
    let canary = Canary::new(guest, invocation_id)?;
    let input = json!({"variant":variant,"snapshot_id":snapshot.snapshot_id,"revision":snapshot.revision,"sha256":snapshot.sha256,"orphan_variant":orphan,"host_canary_path_sha256":Digest::of(canary.path.as_os_str().as_encoded_bytes()),"host_canary_sha256":canary.sha});
    let input_bytes = serde_json::to_vec(&input)
        .map_err(|_| integrity("Cannot encode trusted guest fixture input"))?;
    let input_artifact = host.evidence.write_artifact(
        host.project.project_id,
        CatalogId::parse("guest-input")?,
        invocation_id,
        &input_bytes,
        RedactionStatus::Original,
    )?;
    let call = PreparedCall {
        invocation_id,
        call_id: EntityId::new(),
        tool_id: CatalogId::parse(isolation::TOOL)?,
        tool_version: ContractVersion::V0_1_0,
        input_ref: input_artifact.artifact_id,
        input_sha256: input_artifact.sha256,
        input_revision: snapshot.revision,
        source_control_revision: binding.control_revision(),
        requested: isolation::requested(profile)?,
    };
    host.admission.propose(&binding, &call)?;
    host.approve(&binding, &call)?;
    host.admission.reserve(&binding, &call)?;
    let permit = host.admission.begin_effect(&binding, invocation_id)?;
    let mut meter = EffectMeter::start();
    let result = (|| {
        let reader = host.evidence.snapshot_reader(
            host.project.project_id,
            snapshot.snapshot_id,
            snapshot.revision,
        )?;
        host.admission.recheck_effect(&binding, &permit)?;
        let body = reader.read(WireInt::ZERO, snapshot.length_bytes)?;
        meter.write_pending = true;
        let approved = host.evidence.write_artifact(
            host.project.project_id,
            CatalogId::parse("guest-approved-snapshot")?,
            invocation_id,
            &body,
            RedactionStatus::Original,
        )?;
        meter.write_pending = false;
        meter.add_bytes(body.len())?;
        guest.stage(invocation_id, approved.artifact_id, &body, &canary.path)?;
        let launch = SupervisorLaunch {
            binding_id: binding.binding_id(),
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
            control_revision: binding.control_revision(),
        };
        let attestation_id = launch.attestation_id;
        let lease_id = launch.lease_id;
        let started = Instant::now();
        let (mut journal, stdout, stderr, transport_pid) =
            if orphan == Some("host_sigkill") {
                host_loss(host, profile, guest, launch, &mut meter)?
            } else {
                let mut invocation = guest.launch(launch, profile)?;
                meter.dispatched = true;
                let transport_pid = invocation.transport_pid;
                let mut stdout = Vec::new();
                let mut stderr = Vec::new();
                let mut active = false;
                let mut refresh = Instant::now();
                let mut killed = None;
                loop {
                    if started.elapsed() > Duration::from_secs(10) {
                        let _ = invocation.terminate(lease_id, binding.control_revision());
                        return Err(unavailable(
                            "Guest proof exceeded the bounded lifecycle deadline",
                        ));
                    }
                    match invocation.poll() {
                        Ok(Some(frame)) => match frame["kind"].as_str() {
                            Some("started") => {
                                active = true;
                                if orphan == Some("ssh_sigkill") {
                                    killed = Some(invocation.detach_transport()?);
                                    break;
                                }
                            }
                            Some("output") => {
                                let bytes = STANDARD
                                    .decode(frame["payload"]["bytes_base64"].as_str().ok_or_else(
                                        || integrity("Validated output missing bytes"),
                                    )?)
                                    .map_err(|_| integrity("Validated output encoding changed"))?;
                                let target = if frame["payload"]["stream"] == "stdout" {
                                    &mut stdout
                                } else {
                                    &mut stderr
                                };
                                target.extend_from_slice(&bytes);
                            }
                            Some("terminated") => break,
                            _ => {}
                        },
                        Ok(None) => {}
                        Err(error) => return Err(error),
                    }
                    if active && refresh.elapsed() > Duration::from_millis(500) {
                        invocation.refresh(lease_id, binding.control_revision())?;
                        refresh = Instant::now();
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
                let mut journal = wait_journal(guest, invocation_id, Duration::from_millis(3300))?;
                if let Some(pid) = killed {
                    journal["owned_killed_pid"] = json!(pid);
                } else {
                    let containment = invocation.terminate(lease_id, binding.control_revision())?;
                    if !containment.empty_cgroup {
                        return Err(integrity("Normal guest proof required VM-stop escalation"));
                    }
                }
                if orphan.is_some() {
                    observe_stopped_output(guest, invocation_id, &mut journal)?;
                    invocation.accept_independent_containment(&journal)?;
                    stdout = STANDARD
                        .decode(journal["stdout_prefix_base64"].as_str().ok_or_else(|| {
                            integrity("Independent orphan attempt prefix missing")
                        })?)
                        .map_err(|_| integrity("Independent orphan attempt prefix invalid"))?;
                    journal["ssh_parent_reaped"] = json!(true);
                    journal["ssh_exit_observed"] = json!(true);
                }
                (journal, stdout, stderr, transport_pid)
            };
        meter.dispatched = true;
        meter.write_pending = true;
        let stdout_artifact = host.evidence.write_artifact(
            host.project.project_id,
            CatalogId::parse("guest-stdout")?,
            invocation_id,
            &stdout,
            RedactionStatus::Original,
        )?;
        let stderr_artifact = host.evidence.write_artifact(
            host.project.project_id,
            CatalogId::parse("guest-stderr")?,
            invocation_id,
            &stderr,
            RedactionStatus::Original,
        )?;
        meter.write_pending = false;
        meter.add_bytes(stdout.len())?;
        meter.add_bytes(stderr.len())?;
        if journal["invocation_id"] != invocation_id.to_string()
            || journal["attestation"]["attestation_id"] != attestation_id.to_string()
            || journal["empty_cgroup"] != true
        {
            return Err(integrity(
                "Independent guest journal is not bound to actual current launch",
            ));
        }
        let _slot = guest.capacity_lock()?;
        let fact = RunFact {
            invocation_id,
            binding_id: binding.binding_id(),
            run_id: host.workspace.run_id(),
            attestation_id,
            lease_id,
            variant: variant.into(),
            input_snapshot_id: snapshot.snapshot_id,
            input_revision: snapshot.revision,
            input_sha256: snapshot.sha256,
            input_artifact_id: approved.artifact_id,
            stdout_artifact_id: stdout_artifact.artifact_id,
            stderr_artifact_id: stderr_artifact.artifact_id,
            stdout_bytes: stdout.len() as u64,
            stderr_bytes: stderr.len() as u64,
            transport_pid,
            transport_reaped: orphan != Some("host_sigkill"),
            host_clock_epoch_id: HOST_EPOCH.id,
            host_started_us,
            host_finished_us: HOST_EPOCH.clock.elapsed().as_micros() as u64,
            empty_cgroup: true,
            live_slots_after: 0,
            elapsed_us: started.elapsed().as_micros() as u64,
            outcome: journal["outcome"]
                .as_str()
                .ok_or_else(|| integrity("Guest outcome missing"))?
                .into(),
            guest: std::mem::take(&mut journal),
            host_canary_sha256: canary.sha,
            host_canary_read_bytes: canary.bytes,
        };
        let bytes = serde_json::to_vec(&fact)
            .map_err(|_| integrity("Cannot encode measured guest lifecycle fact"))?;
        meter.add_bytes(bytes.len())?;
        meter.write_pending = true;
        let artifact = host.evidence.write_artifact(
            host.project.project_id,
            CatalogId::parse("guest-lifecycle")?,
            invocation_id,
            &bytes,
            RedactionStatus::Original,
        )?;
        meter.write_pending = false;
        Ok(Execution {
            fact,
            fact_artifact_id: artifact.artifact_id,
        })
    })();
    let mut usage = meter.usage()?;
    if let Ok(execution) = &result {
        let guest_cpu = execution.fact.guest["usage"]["cpu_time_us"]
            .as_u64()
            .ok_or_else(|| integrity("Measured guest CPU usage missing"))?;
        usage.cpu_us = usage.cpu_us.checked_add(WireInt::new(guest_cpu)?)?;
    }
    match result {
        Ok(execution) => {
            host.admission
                .complete(&binding, permit, usage, Some(execution.fact_artifact_id))?;
            Ok(execution)
        }
        Err(error) => {
            if meter.write_pending || meter.dispatched {
                host.admission.outcome_unknown(
                    &binding,
                    permit,
                    usage,
                    ProofError::new(
                        ErrorCode::OutcomeUnknown,
                        "Dispatched guest execution or evidence requires reconciliation",
                    ),
                )?;
            } else {
                host.admission
                    .fail(&binding, permit, usage, error.clone())?;
            }
            Err(error)
        }
    }
}
fn wait_journal(
    guest: &PreparedGuest,
    invocation: EntityId,
    deadline: Duration,
) -> ProofResult<Value> {
    let start = Instant::now();
    loop {
        let result = guest.guest_command(
            &["--termination", &invocation.to_string()],
            None,
            Duration::from_secs(2),
        );
        if let Ok(bytes) = result {
            let value: Value = serde_json::from_slice(&bytes)
                .map_err(|_| integrity("Malformed independent termination journal"))?;
            if value["invocation_id"] != invocation.to_string() || value["empty_cgroup"] != true {
                return Err(integrity(
                    "Independent journal does not prove current empty cgroup",
                ));
            }
            return Ok(value);
        }
        if start.elapsed() > deadline {
            return Err(unavailable(
                "Independent guest watchdog did not produce bounded containment evidence",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn observe_stopped_output(
    guest: &PreparedGuest,
    invocation: EntityId,
    journal: &mut Value,
) -> ProofResult<()> {
    let first = guest.guest_command(
        &["--observe", &invocation.to_string()],
        None,
        Duration::from_secs(2),
    )?;
    let first = std::str::from_utf8(&first)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| integrity("Independent orphan output observer unavailable"))?;
    std::thread::sleep(Duration::from_millis(250));
    let second = guest.guest_command(
        &["--observe", &invocation.to_string()],
        None,
        Duration::from_secs(2),
    )?;
    let second = std::str::from_utf8(&second)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| integrity("Independent orphan output observer unavailable after cleanup"))?;
    journal["observer_at_cleanup"] = json!(first);
    journal["observer_after_cleanup"] = json!(second);
    Ok(())
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerConfig {
    repository: PathBuf,
    workspace: PathBuf,
    run_id: EntityId,
    profile_sha256: Digest,
    launch: Value,
}
struct OwnedEngine(std::process::Child);
impl std::ops::Deref for OwnedEngine {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedEngine {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for OwnedEngine {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
struct OrphanContainment<'a> {
    guest: &'a PreparedGuest,
    launch: SupervisorLaunch,
    occupancy_id: Option<EntityId>,
}
impl Drop for OrphanContainment<'_> {
    fn drop(&mut self) {
        if let Some(id) = self.occupancy_id
            && let Err(error) = super::lifecycle::force_stop_orphan(self.guest, &self.launch, id)
        {
            eprintln!(
                "razen: orphan containment refused or failed; durable ownership remains sealed: {error}"
            );
        }
    }
}
fn process_birth_identity(pid: u32) -> ProofResult<Option<Digest>> {
    use std::ffi::OsStr;
    let pid = pid.to_string();
    let observed = crate::adapters::command::capture_status(
        Path::new("/bin/ps"),
        &[
            OsStr::new("-p"),
            OsStr::new(&pid),
            OsStr::new("-o"),
            OsStr::new("pid=,lstart="),
        ],
        None,
        crate::adapters::command::CommandLimits {
            stdin_bytes: 0,
            stdout_bytes: 4096,
            stderr_bytes: 4096,
            timeout: Duration::from_secs(1),
        },
    )?;
    if observed.exit_code == 1 && observed.stdout.iter().all(u8::is_ascii_whitespace) {
        return Ok(None);
    }
    if observed.exit_code != 0 || observed.stdout.is_empty() {
        return Err(unavailable(
            "Cannot observe the authenticated owned SSH process identity",
        ));
    }
    Ok(Some(Digest::of(&observed.stdout)))
}
fn observe_transport_exit(pid: u32, birth: Digest) -> ProofResult<()> {
    let start = Instant::now();
    loop {
        if process_birth_identity(pid)? != Some(birth) {
            return Ok(());
        }
        if start.elapsed() > Duration::from_secs(4) {
            return Err(unavailable(
                "Owned engine's SSH transport exit was not observed; it is not parent-reapable after engine SIGKILL",
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn host_loss(
    host: &ProofHost,
    profile: &LoadedProfile,
    guest: &Arc<PreparedGuest>,
    launch: SupervisorLaunch,
    meter: &mut EffectMeter,
) -> ProofResult<(Value, Vec<u8>, Vec<u8>, u32)> {
    let directory = guest.repository.join("target/r0-guest/workers");
    if !directory.exists() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .map_err(|_| unavailable("Cannot create owned private orphan worker directory"))?;
    }
    preflight::check_private(&directory, true)?;
    let invocation = launch.invocation_id;
    let worker = directory.join(invocation.to_string());
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&worker)
        .map_err(|_| integrity("Orphan worker directory is not fresh"))?;
    let config = WorkerConfig {
        repository: guest.repository.clone(),
        workspace: host.workspace.path().into(),
        run_id: host.workspace.run_id(),
        profile_sha256: profile.sha256(),
        launch: serde_json::to_value(&launch)
            .map_err(|_| integrity("Cannot encode owned orphan launch"))?,
    };
    let path = worker.join("launch.json");
    write_private(
        &path,
        &serde_json::to_vec(&config)
            .map_err(|_| integrity("Cannot encode owned orphan worker configuration"))?,
    )?;
    let engine = guest.repository.join("target/debug/razen-engine");
    if preflight::hash_file(&engine)? != host.provider_digest {
        return Err(integrity(
            "Orphan worker is not the current measured production engine",
        ));
    }
    let diagnostics = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(worker.join("stderr"))
        .map_err(|_| unavailable("Cannot create owned orphan worker diagnostics"))?;
    let mut cleanup = OrphanContainment {
        guest,
        launch,
        occupancy_id: None,
    };
    let mut child = OwnedEngine(
        Command::new(engine)
            .arg("--guest-orphan-worker")
            .arg(&path)
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(diagnostics))
            .process_group(0)
            .spawn()
            .map_err(|_| unavailable("Cannot start owned production engine orphan worker"))?,
    );
    meter.dispatched = true;
    let ready_path = worker.join("ready.json");
    let start = Instant::now();
    let ready = loop {
        if ready_path.exists() {
            break preflight::private_read(&ready_path, 1_048_576)?;
        }
        if child
            .try_wait()
            .map_err(|_| unavailable("Cannot observe owned orphan worker"))?
            .is_some()
            || start.elapsed() > Duration::from_secs(10)
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(unavailable(
                "Owned production engine did not reach attested orphan barrier",
            ));
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    let ready: Value =
        serde_json::from_slice(&ready).map_err(|_| integrity("Invalid owned orphan barrier"))?;
    if ready["invocation_id"] != invocation.to_string()
        || ready["run_id"] != host.workspace.run_id().to_string()
        || ready["profile_sha256"] != profile.sha256().to_string()
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err(integrity(
            "Owned orphan barrier has foreign launch/profile identity",
        ));
    }
    cleanup.occupancy_id = Some(EntityId::parse(
        ready["occupancy_id"].as_str().ok_or_else(|| {
            integrity("Owned orphan barrier has no exact durable occupancy identity")
        })?,
    )?);
    let transport_pid = ready["transport_pid"]
        .as_u64()
        .ok_or_else(|| integrity("Owned SSH PID missing at engine barrier"))?
        as u32;
    let birth = Digest::parse(
        ready["ssh_birth_identity_sha256"]
            .as_str()
            .ok_or_else(|| integrity("Owned SSH birth identity missing at engine barrier"))?,
    )?;
    if process_birth_identity(transport_pid)? != Some(birth) {
        return Err(integrity(
            "Authenticated orphan transport identity changed before host SIGKILL",
        ));
    }
    let killed_pid = child.id();
    child
        .kill()
        .map_err(|_| unavailable("Cannot SIGKILL owned production engine"))?;
    let status = child
        .wait()
        .map_err(|_| unavailable("Cannot reap owned production engine"))?;
    use std::os::unix::process::ExitStatusExt;
    if status.signal() != Some(9) {
        return Err(integrity(
            "Owned engine was not actually terminated by SIGKILL",
        ));
    }
    let mut journal = wait_journal(guest, invocation, Duration::from_millis(3300))?;
    journal["owned_killed_pid"] = json!(killed_pid);
    journal["engine_reaped"] = json!(true);
    if let Err(error) = observe_transport_exit(transport_pid, birth) {
        if let Some(id) = cleanup.occupancy_id {
            let _ = super::lifecycle::force_stop_orphan(guest, &cleanup.launch, id);
        }
        return Err(error);
    }
    journal["ssh_exit_observed"] = json!(true);
    journal["ssh_birth_identity_sha256"] = json!(birth);
    journal["ssh_parent_reaped"] = json!(false);
    observe_stopped_output(guest, invocation, &mut journal)?;
    cleanup.occupancy_id = None;
    let stdout = STANDARD
        .decode(
            journal["stdout_prefix_base64"]
                .as_str()
                .ok_or_else(|| integrity("Independent orphan attempt prefix missing"))?,
        )
        .map_err(|_| integrity("Independent orphan output prefix is invalid"))?;
    for name in ["launch.json", "ready.json", "stderr"] {
        fs::remove_file(worker.join(name))
            .map_err(|_| integrity("Cannot remove private owned orphan worker material"))?;
    }
    fs::remove_dir(worker)
        .map_err(|_| integrity("Cannot remove private owned orphan worker directory"))?;
    Ok((journal, stdout, vec![], transport_pid))
}
pub fn orphan_worker(args: &[OsString]) -> ProofResult<()> {
    if args.len() != 1 {
        return Err(integrity(
            "Orphan worker requires exactly one owned configuration path",
        ));
    }
    let path = Path::new(&args[0]);
    if path.file_name() != Some(std::ffi::OsStr::new("launch.json")) {
        return Err(integrity("Unapproved orphan worker configuration grammar"));
    }
    let bytes = preflight::private_read(path, 1_048_576)?;
    let config: WorkerConfig = serde_json::from_slice(&bytes)
        .map_err(|_| integrity("Invalid owned orphan worker configuration"))?;
    let root = config
        .workspace
        .parent()
        .ok_or_else(|| integrity("Owned run has no parent"))?;
    let relative = Path::new(
        config
            .workspace
            .file_name()
            .ok_or_else(|| integrity("Owned run has no basename"))?,
    );
    let workspace = OwnedDirectory::open(root, relative)?;
    if workspace.run_id() != config.run_id {
        return Err(integrity("Orphan worker run ownership changed"));
    }
    let profile = LoadedProfile::load(
        &config
            .repository
            .join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
    )?;
    if profile.sha256() != config.profile_sha256 {
        return Err(integrity("Orphan worker current profile changed"));
    }
    let guest = Arc::new(PreparedGuest::discover(&config.repository, &profile)?);
    let launch: SupervisorLaunch = serde_json::from_value(config.launch)
        .map_err(|_| integrity("Invalid fixed orphan launch"))?;
    if launch.run_id != config.run_id
        || launch.approved_fixture_id.as_str() != "orphan"
        || path.parent().and_then(Path::file_name)
            != Some(std::ffi::OsStr::new(&launch.invocation_id.to_string()))
        || !path.starts_with(config.repository.join("target/r0-guest/workers"))
    {
        return Err(integrity(
            "Orphan worker configuration is not current-run owned",
        ));
    }
    let invocation_id = launch.invocation_id;
    let mut invocation = guest.launch(launch, &profile)?;
    let mut stdout = Vec::new();
    let mut ready_written = false;
    let mut started = false;
    loop {
        if let Some(frame) = invocation.poll()? {
            match frame["kind"].as_str() {
                Some("output") if frame["payload"]["stream"] == "stdout" => {
                    let bytes = STANDARD
                        .decode(frame["payload"]["bytes_base64"].as_str().unwrap_or(""))
                        .map_err(|_| integrity("Invalid bounded orphan output"))?;
                    if stdout.len() + bytes.len() > 65536 {
                        return Err(integrity("Owned orphan barrier output bound"));
                    }
                    stdout.extend_from_slice(&bytes);
                }
                Some("started") => started = true,
                _ => {}
            }
        }
        let attempts = parse_attempts(&stdout, "orphan")?;
        if started
            && !ready_written
            && ["parent", "exec_descendant"]
                .iter()
                .all(|actor| attempts.iter().any(|a| a["actor"] == *actor))
        {
            let birth = process_birth_identity(invocation.transport_pid)?
                .ok_or_else(|| integrity("Owned SSH exited before host-loss barrier"))?;
            write_private(&path.parent().unwrap().join("ready.json"),&serde_json::to_vec(&json!({"invocation_id":invocation_id,"run_id":config.run_id,"profile_sha256":profile.sha256(),"occupancy_id":invocation.occupancy_id(),"transport_pid":invocation.transport_pid,"ssh_birth_identity_sha256":birth})).map_err(|_|integrity("Cannot encode owned orphan readiness"))?)?;
            ready_written = true;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
}
fn write_private(path: &Path, bytes: &[u8]) -> ProofResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| integrity("Worker file has no owned parent"))?;
    preflight::check_private(parent, true)?;
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(
            rustix::fs::OFlags::DIRECTORY.bits() as i32
                | rustix::fs::OFlags::NOFOLLOW.bits() as i32,
        )
        .open(parent)
        .map_err(|_| integrity("Cannot open private worker directory"))?;
    let temporary = format!(".publish-{}", EntityId::new());
    let temporary_path = parent.join(&temporary);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&temporary_path)
            .map_err(|_| integrity("Cannot create private worker publication"))?;
        file.write_all(bytes)
            .map_err(|_| integrity("Cannot write private worker publication"))?;
        file.sync_all()
            .map_err(|_| integrity("Cannot sync private worker publication"))?;
        let name = path
            .file_name()
            .ok_or_else(|| integrity("Worker file has no basename"))?;
        rustix::fs::renameat_with(
            &directory,
            temporary.as_str(),
            &directory,
            name,
            rustix::fs::RenameFlags::NOREPLACE,
        )
        .map_err(|_| integrity("Cannot atomically publish fresh private worker file"))?;
        directory
            .sync_all()
            .map_err(|_| integrity("Cannot sync private worker directory"))?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary_path);
    }
    result
}

fn complete_observers(value: &Value) -> bool {
    let Some(observers) = value.as_array() else {
        return false;
    };
    let mut seen = 0u16;
    for observer in observers {
        let family = match observer["family"].as_str() {
            Some("ipv4_tcp") => 1,
            Some("ipv6_tcp") => 1 << 1,
            Some("ipv4_udp") => 1 << 2,
            Some("ipv6_udp") => 1 << 3,
            Some("unix") => 1 << 4,
            Some("vsock") => 1 << 5,
            Some("dns") => 1 << 6,
            Some("gateway") => 1 << 7,
            Some("target") => 1 << 8,
            Some("model") => 1 << 9,
            _ => return false,
        };
        if seen & family != 0
            || observer["healthy_arrivals"]
                .as_u64()
                .is_none_or(|count| count == 0)
            || observer["unauthorized_arrivals"].as_u64() != Some(0)
        {
            return false;
        }
        seen |= family;
    }
    seen == 0b11_1111_1111
}

fn denied_attempt(attempt: &Value) -> bool {
    if attempt["result"] != "denied" {
        return false;
    }
    let Some(variant) = attempt["variant"].as_str() else {
        return false;
    };
    if !NETWORK.contains(&variant) || variant == "inherited_fd" {
        return true;
    }
    let detail = &attempt["detail"];
    let Some(primitive) = detail["denied_primitive"].as_str() else {
        return false;
    };
    // Errno values belong to the Linux guest, not the macOS host ABI.
    if !["socket", "bind", "connect", "sendto"].contains(&primitive)
        || detail["attempted_primitive"] != primitive
        || !attempt["errno"]
            .as_i64()
            .is_some_and(|errno| (1..=4095).contains(&errno) && errno != 114 && errno != 115)
    {
        return false;
    }
    !["ipv4_udp", "ipv6_udp", "dns"].contains(&variant)
        || detail["udp_send_attempted"].as_bool() == Some(primitive == "sendto")
}

fn derive(report: &Report, profile: &LoadedProfile) -> ProofResult<Assertions> {
    let complete = !report.executions.is_empty()
        && report.executions.iter().all(|e| {
            e.fact.empty_cgroup
                && (e.fact.transport_reaped
                    || e.fact.guest["engine_reaped"] == true
                        && e.fact.guest["ssh_exit_observed"] == true
                        && e.fact.guest["ssh_parent_reaped"] == false)
                && e.fact.transport_pid > 0
                && e.fact.live_slots_after == 0
                && e.fact.guest["cgroup_populated_after"] == 0
                && e.fact.guest["descendants_after"] == 0
        });
    let fresh = report.executions.first().is_some_and(|first| {
        report.executions.iter().all(|e| {
            e.fact.host_clock_epoch_id == first.fact.host_clock_epoch_id
                && e.fact.host_finished_us > e.fact.host_started_us
        }) && report.executions.windows(2).all(|pair| {
            pair[1].fact.host_started_us >= pair[0].fact.host_finished_us
                && (pair[0].fact.variant == "snapshot_control"
                    || pair[1].fact.variant == "snapshot_control"
                        && pair[1].fact.outcome == "completed"
                        && pair[0].fact.invocation_id != pair[1].fact.invocation_id)
        })
    }) && report
        .executions
        .last()
        .is_some_and(|e| e.fact.variant == "snapshot_control" && e.fact.outcome == "completed");
    let required = match report.case_id.as_str() {
        "RUN-03" => FILESYSTEM,
        "RUN-04" => NETWORK,
        "RUN-05" => RESOURCE,
        _ => &[],
    };
    let attempts = required.iter().all(|variant| {
        ["parent", "exec_descendant"].iter().all(|actor| {
            report.attempts.iter().any(|a| {
                a["variant"] == *variant
                    && a["actor"] == *actor
                    && a["primitive_attempt_count"].as_u64().is_some_and(|n| n > 0)
                    && a["count_semantics"] == "completed_primitive_attempts"
                    && a["result"] != "allowed"
                    && a["healthy_control"] == "completed"
            })
        })
    });
    let denied = !report.attempts.iter().any(|a| {
        required.iter().any(|v| a["variant"] == *v)
            && (a["result"] == "allowed"
                || NETWORK.iter().any(|variant| {
                    *variant != "inherited_fd" && a["variant"] == *variant && !denied_attempt(a)
                }))
    }) && required
        .iter()
        .filter(|v| !["fork", "thread", "memory", "cpu", "output"].contains(v))
        .all(|variant| {
            ["parent", "exec_descendant"].iter().all(|actor| {
                report
                    .attempts
                    .iter()
                    .any(|a| a["variant"] == *variant && a["actor"] == *actor && denied_attempt(a))
            })
        });
    let observers = !report.executions.is_empty()
        && report
            .executions
            .iter()
            .all(|execution| complete_observers(&execution.fact.guest["observers"]));
    let attested = !report.attestations.is_empty()
        && report.attestations.iter().all(|a| {
            [
                "namespace_checks",
                "controller_checks",
                "mount_checks",
                "socket_checks",
                "uid_checks",
            ]
            .iter()
            .all(|map| {
                a[*map]
                    .as_object()
                    .is_some_and(|m| !m.is_empty() && m.values().all(|v| v == true))
            })
        });
    let resources = report
        .executions
        .iter()
        .filter(|e| e.fact.variant != "snapshot_control")
        .all(|e| {
            let f = &e.fact;
            let g = &f.guest;
            let u = &g["usage"];
            let counter = |field: &str, key: &str| {
                g[field]
                    .as_str()
                    .and_then(|text| {
                        text.lines().find_map(|line| {
                            line.split_once(' ')
                                .filter(|(name, _)| *name == key)
                                .and_then(|(_, value)| value.parse::<u64>().ok())
                        })
                    })
                    .unwrap_or(0)
            };
            let both_progress = |field: &str, minimum: u64| {
                ["parent", "exec_descendant"].iter().all(|actor| {
                    report.attempts.iter().any(|a| {
                        a["variant"] == f.variant
                            && a["actor"] == *actor
                            && a["result"] == "flood_progress"
                            && a["detail"][field].as_u64().is_some_and(|n| n >= minimum)
                    })
                })
            };
            let bounded = u["memory_peak_bytes"].as_u64().is_some_and(|n| n > 0)
                && u["pids_peak"]
                    .as_u64()
                    .is_some_and(|n| n <= profile.config().external_runner.pids_max.get())
                && f.stdout_bytes + f.stderr_bytes
                    <= profile
                        .config()
                        .protocol
                        .invocation_output_limit_bytes
                        .get()
                && g["lease_elapsed_us"].as_u64().is_some_and(|n| {
                    n <= (profile.config().external_runner.wall_deadline_ms.get() + 1200) * 1000
                });
            let enforced = match f.variant.as_str() {
                "fork" | "thread" => {
                    u["pids_peak"].as_u64().is_some_and(|n| n >= 60)
                        && counter("pids_events", "max") > 0
                        && ["parent", "exec_descendant"].iter().all(|actor| {
                            report.attempts.iter().any(|a| {
                                a["variant"] == f.variant
                                    && a["actor"] == *actor
                                    && a["result"] == "denied"
                            })
                        })
                }
                "memory" => {
                    counter("memory_events", "oom_kill") > 0
                        && both_progress("touched_bytes", 16 * 1048576)
                }
                "cpu" => {
                    u["cpu_time_us"].as_u64().is_some_and(|n| n > 0)
                        && counter("cpu_stat", "nr_throttled") > 0
                        && g["termination_reason"] == "wall_deadline"
                }
                "tmpfs" => report
                    .attempts
                    .iter()
                    .any(|a| a["variant"] == "tmpfs" && a["errno"] == 28),
                "output" => {
                    g["termination_reason"] == "output_limit"
                        && both_progress("written_bytes", 65536)
                }
                _ => true,
            };
            bounded && enforced
        });
    let negative_successors = report.contaminations.len() == 6
        && report.executions.len() == 7
        && report
            .contaminations
            .iter()
            .enumerate()
            .all(|(index, receipt)| {
                let before = &report.executions[index].fact;
                let after = &report.executions[index + 1].fact;
                receipt["host_clock_epoch_id"] == after.host_clock_epoch_id.to_string()
                    && receipt["host_started_us"]
                        .as_u64()
                        .is_some_and(|started| started >= before.host_finished_us)
                    && receipt["host_finished_us"]
                        .as_u64()
                        .is_some_and(|finished| finished <= after.host_started_us)
                    && after.variant == "snapshot_control"
                    && after.outcome == "completed"
            });
    use CheckName::*;
    let checks = match report.case_id.as_str() {
        "RUN-02" => vec![
            (EffectiveConfigAttested, attested),
            (MandatoryIsolation, attested && complete),
            (
                ContaminationRejected,
                negative_successors
                    && report.contaminations.iter().all(|c| {
                        c["launch_admitted"] == false && c["error"]["code"] == "integrity_error"
                    }),
            ),
            (NoFallback, report.prepared["available"] == true && complete),
        ],
        "RUN-03" => vec![
            (ActualAttempts, attempts && denied),
            (DescendantsRestricted, attempts && complete),
            (
                GrantedRead,
                fresh
                    && report
                        .executions
                        .iter()
                        .filter(|e| e.fact.variant == "snapshot_control")
                        .all(|e| e.fact.outcome == "completed"),
            ),
            (
                SecretsAbsent,
                denied
                    && report
                        .executions
                        .iter()
                        .all(|e| e.fact.host_canary_read_bytes > 0),
            ),
        ],
        "RUN-04" => vec![
            (ActualAttempts, attempts && denied),
            (DescendantsRestricted, attempts && complete),
            (HealthyObserver, observers),
            (ZeroForbiddenArrivals, observers),
            (
                DescriptorsClosed,
                report
                    .attempts
                    .iter()
                    .filter(|a| a["variant"] == "inherited_fd")
                    .all(|a| a["detail"]["inherited_nonstdio_fds"] == 0),
            ),
        ],
        "RUN-05" => vec![
            (ActualAttempts, attempts && denied),
            (DescendantsRestricted, attempts && complete),
            (ResourceLimits, resources),
            (FreshSuccess, fresh && complete),
        ],
        "RUN-08" => {
            let orphans = report.orphan_variants.len() == 2
                && report.orphan_variants.iter().all(|v| {
                    v["killed_pid"].as_u64().is_some_and(|p| p > 0)
                        && v["guest_manager_pid"].as_u64().is_some_and(|p| p > 0)
                        && v["lease_refreshes_after_loss"] == 0
                        && v["guest_elapsed_us"]
                            .as_u64()
                            .is_some_and(|n| n <= 3_200_000)
                        && v["observer_at_cleanup"] == v["observer_after_cleanup"]
                });
            vec![
                (HostTransportLost, orphans),
                (
                    LeaseExpired,
                    orphans
                        && report
                            .executions
                            .iter()
                            .filter(|e| e.fact.variant == "orphan")
                            .all(|e| e.fact.guest["termination_reason"] == "orphan_lease_expired"),
                ),
                (DescendantsTerminated, complete),
                (Contained, complete && fresh),
            ]
        }
        _ => return Err(integrity("Unknown factual guest report case")),
    };
    Assertions::new(checks)
}
#[allow(clippy::too_many_arguments)]
pub fn verify_report(
    result: &crate::domain::proofs::ProofResult,
    report: &Value,
    project: EntityId,
    run: &Run,
    profile: &LoadedProfile,
    evidence: &EvidenceStore,
    ledger: &Ledger,
) -> ProofResult<Assertions> {
    let mut report: Report = Report::deserialize(report)
        .map_err(|_| integrity("Guest report strict schema mismatch"))?;
    if report.schema_version != "0.1.0"
        || report.case_id != result.case_id
        || report.project_id != project
        || report.run_id != run.run_id
        || report.profile_sha256 != profile.sha256()
        || run.profile_sha256 != profile.sha256()
    {
        return Err(integrity(
            "Guest report current run/profile/project identity mismatch",
        ));
    }
    if run.environment.provisioning_sha256.map(|d| d.to_string())
        != report.prepared["provisioning_sha256"]
            .as_str()
            .map(str::to_owned)
        || run
            .environment
            .effective_config_sha256
            .map(|d| d.to_string())
            != report.prepared["effective_config_sha256"]
                .as_str()
                .map(str::to_owned)
        || run.environment.seccomp_sha256.map(|d| d.to_string())
            != report.prepared["seccomp_sha256"]
                .as_str()
                .map(str::to_owned)
    {
        return Err(integrity(
            "Guest report provenance differs from immutable Run environment",
        ));
    }
    if run
        .environment
        .fixture_digests
        .get(&CatalogId::parse("runtime")?)
        != Some(&report.scenario_sha256)
        || run.environment.guest_package_manifest_sha256
            != Some(Digest::parse(
                report.prepared["package_manifest_sha256"]
                    .as_str()
                    .ok_or_else(|| integrity("Actual guest package manifest digest missing"))?,
            )?)
    {
        return Err(integrity(
            "Guest scenario/package provenance differs from immutable Run",
        ));
    }
    let mut unique = BTreeSet::new();
    let mut reconstructed = Report {
        schema_version: report.schema_version.clone(),
        case_id: report.case_id.clone(),
        project_id: project,
        run_id: run.run_id,
        profile_sha256: profile.sha256(),
        scenario_sha256: report.scenario_sha256,
        prepared: report.prepared.clone(),
        runs: vec![],
        executions: vec![],
        attempts: vec![],
        attestations: vec![],
        contaminations: report.contaminations.clone(),
        observers: vec![],
        orphan_variants: report.orphan_variants.clone(),
    };
    for execution in &report.executions {
        let f = &execution.fact;
        if !unique.insert(f.invocation_id) || f.run_id != run.run_id {
            return Err(integrity("Guest execution identity reused or foreign"));
        }
        let stored = ledger.read_invocation(f.invocation_id)?;
        if stored.invocation.project_id != project
            || stored.invocation.tool_id.as_str() != isolation::TOOL
            || stored.invocation.state != InvocationState::Completed
            || stored.invocation.output_ref != Some(execution.fact_artifact_id)
            || stored.reserved_units != WireInt::ZERO
            || stored.invocation.grant_id.is_none()
        {
            return Err(integrity(
                "Guest execution lacks canonical approved completed provider history",
            ));
        }
        stored.invocation.validate(Some(&stored.history))?;
        let bytes = evidence.read_artifact(project, execution.fact_artifact_id, 1_048_576)?;
        let canonical: RunFact = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("Canonical guest lifecycle fact is invalid"))?;
        if canonical != *f {
            return Err(integrity(
                "Guest report fact differs from immutable canonical artifact",
            ));
        }
        for artifact in [
            execution.fact_artifact_id,
            f.input_artifact_id,
            f.stdout_artifact_id,
            f.stderr_artifact_id,
        ] {
            let a = evidence.artifact(project, artifact)?;
            if a.origin_invocation_id != f.invocation_id {
                return Err(integrity("Guest fact/output ownership mismatch"));
            }
            evidence.verify_artifact(project, artifact)?;
        }
        let snapshot = evidence.snapshot(project, f.input_snapshot_id, f.input_revision)?;
        let approved = evidence.artifact(project, f.input_artifact_id)?;
        if snapshot.sha256 != f.input_sha256 || approved.sha256 != f.input_sha256 {
            return Err(integrity("Guest granted snapshot provenance changed"));
        }
        if f.guest["attestation"]["run_id"] != run.run_id.to_string()
            || f.guest["attestation"]["attestation_id"] != f.attestation_id.to_string()
            || f.guest["invocation_id"] != f.invocation_id.to_string()
            || f.guest["lease_id"] != f.lease_id.to_string()
        {
            return Err(integrity(
                "Guest attestation/lease/termination binding mismatch",
            ));
        }
        super::attestation::verify_recorded(
            &f.guest["attestation"],
            run,
            f.attestation_id,
            profile,
        )?;
        verify_measured_boundary(f)?;
        let (binding, call) = stored
            .invocation
            .deduplication_key
            .split_once(':')
            .ok_or_else(|| integrity("Canonical guest binding key missing"))?;
        if EntityId::parse(binding)? != f.binding_id
            || EntityId::parse(call)? != stored.invocation.causation_id
            || stored.invocation.input_revision != f.input_revision
            || stored.invocation.usage.cpu_us.get()
                < f.guest["usage"]["cpu_time_us"]
                    .as_u64()
                    .ok_or_else(|| integrity("Measured guest CPU usage missing"))?
        {
            return Err(integrity(
                "Canonical guest binding, revision or measured CPU differs",
            ));
        }
        let prepared: Value = serde_json::from_slice(&evidence.read_artifact(
            project,
            stored.invocation.input_ref,
            65536,
        )?)
        .map_err(|_| integrity("Canonical guest approval input invalid"))?;
        if prepared["variant"] != f.variant
            || prepared["snapshot_id"] != f.input_snapshot_id.to_string()
            || prepared["sha256"] != f.input_sha256.to_string()
            || prepared["host_canary_sha256"] != f.host_canary_sha256.to_string()
        {
            return Err(integrity(
                "Guest execution differs from actually approved bounded input",
            ));
        }
        if f.variant == "other_invocation" {
            let other = EntityId::parse(
                f.guest["other_invocation_id"]
                    .as_str()
                    .ok_or_else(|| integrity("Real other-invocation identity missing"))?,
            )?;
            let other = ledger.read_invocation(other)?;
            if other.invocation.project_id != project
                || other.invocation.state != InvocationState::Completed
                || other.invocation.invocation_id == f.invocation_id
            {
                return Err(integrity(
                    "Other-invocation canary has no distinct real completed invocation",
                ));
            }
        }
        let output = evidence.read_artifact(project, f.stdout_artifact_id, 2 * 1024 * 1024)?;
        let stderr = evidence.read_artifact(project, f.stderr_artifact_id, 2 * 1024 * 1024)?;
        if output.len() as u64 != f.stdout_bytes
            || stderr.len() as u64 != f.stderr_bytes
            || stored.invocation.usage.bytes.get()
                != approved.length_bytes.get()
                    + f.stdout_bytes
                    + f.stderr_bytes
                    + bytes.len() as u64
        {
            return Err(integrity(
                "Guest factual output/usage byte accounting differs",
            ));
        }
        let mut attempts = parse_attempts(&output, &f.variant)?;
        if f.variant == "host_canary"
            && attempts
                .iter()
                .any(|a| a["detail"]["target_sha256"] != prepared["host_canary_path_sha256"])
        {
            return Err(integrity(
                "Host canary attempt differs from the approved actual target",
            ));
        }
        for attempt in &mut attempts {
            attempt["invocation_id"] = json!(f.invocation_id);
        }
        reconstructed.attempts.extend(attempts);
        reconstructed
            .attestations
            .push(f.guest["attestation"].clone());
        if let Some(o) = f.guest["observers"].as_array() {
            reconstructed.observers.extend(o.iter().cloned());
        }
        reconstructed.runs.push(json!({"invocation_id":f.invocation_id,"variant":f.variant,"outcome":f.outcome,"empty_cgroup":f.empty_cgroup,"live_slots_after":f.live_slots_after,"elapsed_us":f.elapsed_us}));
    }
    reconstructed.executions = std::mem::take(&mut report.executions);
    let expected_orphans = reconstructed
        .executions
        .iter()
        .filter(|e| e.fact.variant == "orphan")
        .map(|e| {
            orphan_summary(
                e,
                if e.fact.transport_reaped {
                    "ssh_sigkill"
                } else {
                    "host_sigkill"
                },
            )
        })
        .collect::<ProofResult<Vec<_>>>()?;
    if expected_orphans != report.orphan_variants {
        return Err(integrity(
            "Orphan summary differs from actual owned-process/journal observations",
        ));
    }
    reconstructed.orphan_variants = expected_orphans;
    for receipt in &report.contaminations {
        let invocation = EntityId::parse(
            receipt["invocation_id"]
                .as_str()
                .ok_or_else(|| integrity("Preflight receipt has no actual invocation"))?,
        )?;
        let artifact = EntityId::parse(
            receipt["fact_artifact_id"]
                .as_str()
                .ok_or_else(|| integrity("Preflight receipt has no immutable fact artifact"))?,
        )?;
        let stored = ledger.read_invocation(invocation)?;
        stored.invocation.validate(Some(&stored.history))?;
        if stored.invocation.project_id != project
            || stored.invocation.state != InvocationState::Completed
            || stored.invocation.tool_id.as_str() != isolation::TOOL
            || stored.invocation.output_ref != Some(artifact)
            || stored.invocation.grant_id.is_none()
            || stored.reserved_units != WireInt::ZERO
        {
            return Err(integrity(
                "Preflight rejection is not a real approved completed provider execution",
            ));
        }
        let metadata = evidence.artifact(project, artifact)?;
        if metadata.origin_invocation_id != invocation {
            return Err(integrity("Preflight fact belongs to another invocation"));
        }
        let mut body = receipt.clone();
        body.as_object_mut()
            .ok_or_else(|| integrity("Preflight receipt must be an object"))?
            .remove("fact_artifact_id");
        let canonical: Value =
            serde_json::from_slice(&evidence.read_artifact(project, artifact, 65536)?)
                .map_err(|_| integrity("Preflight canonical fact is invalid"))?;
        if body != canonical
            || canonical["restored_effective_config_sha256"]
                != report.prepared["effective_config_sha256"]
        {
            return Err(integrity(
                "Preflight summary differs from actual immutable rejection/restoration evidence",
            ));
        }
    }
    for attempt in &mut reconstructed.attempts {
        let id = attempt["invocation_id"].clone();
        if let Some(index) = reconstructed
            .runs
            .iter()
            .position(|r| r["invocation_id"] == id)
            && reconstructed
                .runs
                .get(index + 1)
                .is_some_and(|r| r["variant"] == "snapshot_control" && r["outcome"] == "completed")
        {
            attempt["healthy_control"] = json!("completed");
            attempt["successor_invocation_id"] =
                reconstructed.runs[index + 1]["invocation_id"].clone();
        }
    }
    if report.runs != reconstructed.runs
        || report.attempts != reconstructed.attempts
        || report.attestations != reconstructed.attestations
        || report.observers != reconstructed.observers
    {
        return Err(integrity(
            "Guest summary is not derived from immutable attempts and actual canonical executions",
        ));
    }
    derive(&reconstructed, profile)
}

fn orphan_summary(execution: &Execution, variant: &str) -> ProofResult<Value> {
    let g = &execution.fact.guest;
    Ok(
        json!({"variant":variant,"invocation_id":execution.fact.invocation_id,"killed_pid":g["owned_killed_pid"],"transport_reaped":execution.fact.transport_reaped,"engine_reaped":g.get("engine_reaped").and_then(Value::as_bool).unwrap_or(false),"ssh_exit_observed":g["ssh_exit_observed"],"guest_manager_pid":g["guest_manager_pid"],"lease_refreshes_after_loss":g["lease_refreshes"],"cgroup_populated_after":g["cgroup_populated_after"],"descendants_after":g["descendants_after"],"guest_elapsed_us":g["lease_elapsed_us"],"observer_at_cleanup":g["observer_at_cleanup"],"observer_after_cleanup":g["observer_after_cleanup"],"termination_record_sha256":Digest::of(&serde_json::to_vec(g).map_err(|_|integrity("Cannot hash actual guest journal"))?)}),
    )
}
struct OwnedOverride {
    path: PathBuf,
    digest: Digest,
}
impl OwnedOverride {
    fn create(guest: &PreparedGuest, contents: &[u8]) -> ProofResult<Self> {
        let directory = guest.record.lima_home.join("_config");
        if !directory.exists() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .map_err(|_| unavailable("Cannot create owned contamination directory"))?;
        }
        preflight::check_private(&directory, true)?;
        let path = directory.join("override.yaml");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .map_err(|_| integrity("Preexisting private override is not adopted"))?;
        file.write_all(contents)
            .map_err(|_| integrity("Cannot write actual override contamination"))?;
        file.sync_all()
            .map_err(|_| integrity("Cannot sync actual override contamination"))?;
        Ok(Self {
            path,
            digest: Digest::of(contents),
        })
    }
    fn remove(&self) -> ProofResult<()> {
        if Digest::of(&preflight::private_read(&self.path, 65536)?) != self.digest {
            return Err(integrity(
                "Owned contamination file changed; refusing to remove foreign bytes",
            ));
        }
        fs::remove_file(&self.path)
            .map_err(|_| integrity("Cannot restore actual override contamination"))
    }
}
impl Drop for OwnedOverride {
    fn drop(&mut self) {
        if self.path.exists() {
            let _ = self.remove();
        }
    }
}
fn contamination(
    host: &ProofHost,
    profile: &LoadedProfile,
    guest: &Arc<PreparedGuest>,
    name: &str,
    contents: &str,
) -> ProofResult<Value> {
    let host_started_us = HOST_EPOCH.clock.elapsed().as_micros() as u64;
    let mut spec = host.local_spec();
    spec.allowed_tools = vec![CatalogId::parse(isolation::TOOL)?];
    spec.permissions = vec![CatalogId::parse("guest.proof")?];
    let binding = host.admission.bind(spec)?;
    let invocation_id = EntityId::new();
    let input = serde_json::to_vec(
        &json!({"variant":name,"override_sha256":Digest::of(contents.as_bytes())}),
    )
    .map_err(|_| integrity("Cannot encode controlled preflight input"))?;
    let artifact = host.evidence.write_artifact(
        host.project.project_id,
        CatalogId::parse("guest-preflight-input")?,
        invocation_id,
        &input,
        RedactionStatus::Original,
    )?;
    let call = PreparedCall {
        invocation_id,
        call_id: EntityId::new(),
        tool_id: CatalogId::parse(isolation::TOOL)?,
        tool_version: ContractVersion::V0_1_0,
        input_ref: artifact.artifact_id,
        input_sha256: artifact.sha256,
        input_revision: WireInt::ZERO,
        source_control_revision: binding.control_revision(),
        requested: isolation::requested(profile)?,
    };
    host.admission.propose(&binding, &call)?;
    host.approve(&binding, &call)?;
    host.admission.reserve(&binding, &call)?;
    let permit = host.admission.begin_effect(&binding, invocation_id)?;
    let mut meter = EffectMeter::start();
    let result = (|| {
        host.admission.recheck_effect(&binding, &permit)?;
        let fault = OwnedOverride::create(guest, contents.as_bytes())?;
        meter.dispatched = true;
        let lease_id = EntityId::new();
        let launch = SupervisorLaunch {
            binding_id: binding.binding_id(),
            invocation_id,
            run_id: host.workspace.run_id(),
            attestation_id: EntityId::new(),
            profile_sha256: profile.sha256(),
            approved_fixture_id: CatalogId::parse("snapshot_control")?,
            input_artifact_refs: vec![],
            lease_id,
            control_revision: binding.control_revision(),
        };
        let result = guest.launch(launch, profile);
        fault.remove()?;
        let (admitted, error) = match result {
            Ok(mut child) => {
                let _ = child.terminate(lease_id, binding.control_revision());
                (
                    true,
                    integrity("Contaminated configuration admitted a manager launch"),
                )
            }
            Err(error) => (false, error),
        };
        let effective = guest.effective_configuration()?;
        let restored = preflight::configuration_digest(&effective)?;
        if restored != guest.record.configuration_sha256 {
            return Err(integrity(
                "Actual contaminated VM configuration was not restored",
            ));
        }
        let receipt = json!({"variant":name,"invocation_id":invocation_id,"actual_override_sha256":Digest::of(contents.as_bytes()),"launch_admitted":admitted,"error":error,"restored_effective_config_sha256":restored,"host_clock_epoch_id":HOST_EPOCH.id,"host_started_us":host_started_us,"host_finished_us":HOST_EPOCH.clock.elapsed().as_micros()as u64});
        let bytes = serde_json::to_vec(&receipt)
            .map_err(|_| integrity("Cannot encode actual preflight rejection receipt"))?;
        meter.add_bytes(bytes.len())?;
        meter.write_pending = true;
        let fact = host.evidence.write_artifact(
            host.project.project_id,
            CatalogId::parse("guest-preflight-negative")?,
            invocation_id,
            &bytes,
            RedactionStatus::Original,
        )?;
        meter.write_pending = false;
        Ok((receipt, fact.artifact_id))
    })();
    let usage = meter.usage()?;
    match result {
        Ok((mut receipt, id)) => {
            host.admission.complete(&binding, permit, usage, Some(id))?;
            receipt["fact_artifact_id"] = json!(id);
            Ok(receipt)
        }
        Err(error) => {
            if meter.write_pending {
                host.admission.outcome_unknown(
                    &binding,
                    permit,
                    usage,
                    ProofError::new(
                        ErrorCode::OutcomeUnknown,
                        "Preflight receipt persistence requires reconciliation",
                    ),
                )?;
            } else {
                host.admission
                    .fail(&binding, permit, usage, error.clone())?;
            }
            Err(error)
        }
    }
}

fn verify_measured_boundary(f: &RunFact) -> ProofResult<()> {
    let guest = &f.guest;
    let probe = &guest["probe"];
    for name in ["user", "mnt", "pid", "ipc", "uts", "net", "cgroup"] {
        let inside = probe["namespaces"][name]
            .as_str()
            .ok_or_else(|| integrity("Workload namespace identity missing"))?;
        let outside = guest["manager_namespaces"][name]
            .as_str()
            .ok_or_else(|| integrity("Independent manager namespace identity missing"))?;
        if inside.is_empty() || inside == outside {
            return Err(integrity(
                "Required sandbox namespace was not actually distinct",
            ));
        }
    }
    let status = probe["status"]
        .as_str()
        .ok_or_else(|| integrity("Actual filtered workload status missing"))?;
    let field = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .map(str::trim)
    };
    if field("NoNewPrivs:") != Some("1")
        || field("Seccomp:") != Some("2")
        || !field("Uid:").is_some_and(|v| v.split_whitespace().all(|uid| uid == "61000"))
        || ["CapEff:", "CapPrm:", "CapAmb:"]
            .iter()
            .any(|key| field(key) != Some("0000000000000000"))
    {
        return Err(integrity(
            "Recorded UID/capability/seccomp enforcement is not actually established",
        ));
    }
    let mounts = probe["mountinfo"]
        .as_str()
        .ok_or_else(|| integrity("Actual filtered mount table missing"))?;
    for target in ["/", "/runtime", "/inputs", "/dev", "/proc"] {
        if !mounts.lines().any(|line| {
            let mut fields = line.split_whitespace();
            fields.nth(4) == Some(target)
                && fields
                    .next()
                    .is_some_and(|options| options.split(',').any(|option| option == "ro"))
        }) {
            return Err(integrity(
                "Sandbox filesystem/runtime/input/proc/device mount was not actually readonly",
            ));
        }
    }
    if !mounts.lines().any(|line| {
        line.split_whitespace().nth(4) == Some("/tmp")
            && line.contains(" - tmpfs ")
            && (line.contains("size=16384k") || line.contains("size=16777216"))
    }) {
        return Err(integrity(
            "Sandbox scratch mount was not actually size bounded",
        ));
    }
    let descriptors = probe["descriptors"]
        .as_array()
        .ok_or_else(|| integrity("Actual filtered descriptor table missing"))?;
    if descriptors.iter().any(|fd| {
        fd["target"].as_str().is_none_or(|target| {
            target.starts_with("socket:")
                || target.contains("/var/lib")
                || target.contains("/sys/fs/cgroup")
        })
    }) {
        return Err(integrity(
            "Workload inherited an unapproved management descriptor",
        ));
    }
    let events = guest["empty_observation"]["cgroup_events"]
        .as_str()
        .ok_or_else(|| integrity("Actual empty-cgroup event observation missing"))?;
    if !events.lines().any(|line| line == "populated 0")
        || guest["placement_us"]
            .as_u64()
            .zip(guest["release_us"].as_u64())
            .is_none_or(|(placed, released)| placed == 0 || placed >= released)
        || guest["guest_manager_pid"] == guest["launcher_pid"]
    {
        return Err(integrity(
            "Current placement-before-release/whole-cgroup-empty evidence missing",
        ));
    }
    if f.variant == "snapshot_control" {
        let output = guest["probe"]["snapshot_sha256"]
            .as_str()
            .ok_or_else(|| integrity("Actual permitted snapshot hash missing"))?;
        if output != f.input_sha256.to_string() {
            return Err(integrity(
                "Actual permitted snapshot differs from approved immutable evidence",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod orphan_guard_tests {
    use super::super::transport::{GuestInvocation, encode_runtime_program};
    use super::*;
    use crate::protocol::messages::{BudgetSummary, RuntimeStart};

    fn launch(
        guest: &Arc<PreparedGuest>,
        profile: &LoadedProfile,
        run_id: EntityId,
    ) -> (SupervisorLaunch, GuestInvocation) {
        let binding_id = EntityId::new();
        let invocation_id = EntityId::new();
        let artifact_id = EntityId::new();
        let start = RuntimeStart {
            binding_id,
            contract_version: ContractVersion::V0_1_0,
            context_refs: vec![EntityId::new()],
            tool_ids: vec![],
            budget_summary: BudgetSummary {
                limit: WireInt::new(64).unwrap(),
                consumed: WireInt::ZERO,
                reserved: WireInt::ZERO,
            },
        };
        let bytes = encode_runtime_program(EntityId::new(), &start).unwrap();
        guest
            .stage_runtime(invocation_id, artifact_id, &bytes)
            .unwrap();
        let launch = SupervisorLaunch {
            binding_id,
            invocation_id,
            run_id,
            attestation_id: EntityId::new(),
            profile_sha256: profile.sha256(),
            approved_fixture_id: CatalogId::parse("runtime_blocked").unwrap(),
            input_artifact_refs: vec![ArtifactEvidenceRef {
                artifact_id,
                sha256: Digest::of(&bytes),
                range_start: None,
                range_end: None,
            }],
            lease_id: EntityId::new(),
            control_revision: WireInt::ZERO,
        };
        let copy = serde_json::from_value(serde_json::to_value(&launch).unwrap()).unwrap();
        let mut invocation = guest.launch(copy, profile).unwrap();
        let started = Instant::now();
        loop {
            if invocation
                .poll()
                .unwrap()
                .is_some_and(|frame| frame["kind"] == "started")
            {
                break;
            }
            assert!(
                started.elapsed() < Duration::from_secs(5),
                "actual prepared sandbox must reach attested release"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        (launch, invocation)
    }

    #[test]
    fn delayed_orphan_failure_cannot_stop_a_successor_with_available_flock() {
        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .canonicalize()
            .unwrap();
        let profile = LoadedProfile::load(
            &repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let guest = Arc::new(
            PreparedGuest::discover(&repository, &profile)
                .expect("explicitly prepared current-source Linux VM required"),
        );
        let (old_launch, mut old) = launch(&guest, &profile, EntityId::new());
        let guard = OrphanContainment {
            guest: &guest,
            launch: old_launch,
            occupancy_id: Some(old.occupancy_id()),
        };
        old.detach_transport().unwrap();
        let started = Instant::now();
        while old.read_termination_record().is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "actual independent keeper must publish its authenticated empty-group journal"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let (_, mut successor) = launch(&guest, &profile, EntityId::new());
        successor.detach_transport().unwrap();
        let marker = repository.join("target/r0-guest/invocation.lock");
        let before = fs::read(&marker).unwrap();
        {
            let free=guest.raw_capacity_lock().expect("the successor SSH child has actually been reaped; flock alone must not authorize the old guard");
            assert_eq!(
                free.host_record().unwrap().unwrap().invocation_id,
                successor.invocation_id
            );
        }
        // This is exactly the delayed observe_stopped_output error unwind, without fabricating a journal or VM.
        drop(guard);
        assert_eq!(
            fs::read(&marker).unwrap(),
            before,
            "old orphan cleanup cannot mutate or release successor ownership"
        );
        guest
            .validate_live(&profile)
            .expect("old orphan cleanup must not stop the actual successor VM");
        let started = Instant::now();
        while successor.read_termination_record().is_err() {
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "successor's real independent containment must remain operational"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let contained = successor
            .terminate(successor.lease_id, WireInt::ZERO)
            .unwrap();
        assert!(contained.empty_cgroup);
        assert!(!contained.vm_force_stopped);
        drop(old);
        let (_, mut next) = launch(&guest, &profile, EntityId::new());
        next.refresh(next.lease_id, WireInt::ZERO).unwrap();
        assert!(
            next.terminate(next.lease_id, WireInt::ZERO)
                .unwrap()
                .empty_cgroup
        );
    }
}

#[cfg(test)]
mod network_evidence_tests {
    use super::*;

    #[test]
    fn network_evidence_rejects_unreached_sends_and_pending_or_incomplete_connections() {
        let mut attempt = json!({
            "variant":"ipv4_udp",
            "result":"denied",
            "errno":1,
            "detail":{
                "attempted_primitive":"socket",
                "denied_primitive":"socket",
                "udp_send_attempted":false
            }
        });
        assert!(denied_attempt(&attempt));
        attempt["detail"]["udp_send_attempted"] = json!(true);
        assert!(!denied_attempt(&attempt));
        attempt["detail"]["udp_send_attempted"] = json!(false);
        attempt["result"] = json!("incomplete");
        assert!(!denied_attempt(&attempt));
        attempt["result"] = json!("denied");
        attempt["variant"] = json!("ipv4_tcp");
        attempt["detail"]["attempted_primitive"] = json!("connect");
        attempt["detail"]["denied_primitive"] = json!("connect");
        for pending in [114, 115] {
            attempt["errno"] = json!(pending);
            assert!(!denied_attempt(&attempt));
        }
        attempt["errno"] = json!(1);
        assert!(denied_attempt(&attempt));
        attempt["detail"]["denied_primitive"] = json!("socket");
        assert!(!denied_attempt(&attempt));
    }

    #[test]
    fn observer_evidence_requires_every_reachable_role_and_zero_unauthorized_effects() {
        let mut observations = json!([
            {"family":"ipv4_tcp","healthy_arrivals":1,"unauthorized_arrivals":0},
            {"family":"ipv6_tcp","healthy_arrivals":1,"unauthorized_arrivals":0},
            {"family":"ipv4_udp","healthy_arrivals":1,"unauthorized_arrivals":0},
            {"family":"ipv6_udp","healthy_arrivals":1,"unauthorized_arrivals":0},
            {"family":"unix","healthy_arrivals":1,"unauthorized_arrivals":0},
            {"family":"vsock","healthy_arrivals":1,"unauthorized_arrivals":0},
            {"family":"dns","healthy_arrivals":1,"unauthorized_arrivals":0},
            {"family":"gateway","healthy_arrivals":1,"unauthorized_arrivals":0},
            {"family":"target","healthy_arrivals":1,"unauthorized_arrivals":0},
            {"family":"model","healthy_arrivals":1,"unauthorized_arrivals":0}
        ]);
        assert!(complete_observers(&observations));
        let gateway = observations.as_array_mut().unwrap().remove(7);
        assert!(!complete_observers(&observations));
        observations.as_array_mut().unwrap().push(gateway.clone());
        assert!(complete_observers(&observations));
        observations.as_array_mut().unwrap().push(gateway);
        assert!(!complete_observers(&observations));
        observations.as_array_mut().unwrap().pop();
        observations[0]["unauthorized_arrivals"] = json!(1);
        assert!(!complete_observers(&observations));
        observations[0]["unauthorized_arrivals"] = json!(0);
        observations[0]["healthy_arrivals"] = json!(0);
        assert!(!complete_observers(&observations));
    }
}
