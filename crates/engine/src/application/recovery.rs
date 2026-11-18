//! Trusted, closed fixture orchestration and canonical restart reconciliation.
//! Receiver processes belong to the controller, never the worker being SIGKILLed.
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::admission::{BindingSpec, HostAdmission, PreparedCall};
use super::control::ControlService;
use super::events::{EventConsumer, EventDisposition};
use super::http_send::{self, HttpSendInput, HttpSendProvider, RequestSnapshot};
use super::profile::LoadedProfile;
use super::registry::Registry;
use crate::adapters::evidence_store::EvidenceStore;
use crate::adapters::ledger::{Ledger, RegisteredTool};
use crate::adapters::workspace::OwnedDirectory;
use crate::domain::authority::{
    ApprovalGrant, Budget, Destination, DestinationCheck, FixtureProject, IdentityProfile,
    ScopePolicy,
};
use crate::domain::evidence::RedactionStatus;
use crate::domain::execution::{Checkpoint, ControlMode, ControlState, Event};
use crate::domain::invocation::{Invocation, InvocationHistory, InvocationWire};
use crate::domain::knowledge::InvestigationSession;
use crate::domain::runtime::{Lease, LeaseState};
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, InvocationState, Usage, WireInt,
};
use crate::protocol::codec::{ChannelRole, Direction, decode_frame, read_frame};
use crate::protocol::contracts::CanonicalFixtures;
use crate::protocol::engine::encode_envelope;
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use crate::protocol::messages::{Message, ToolResult};

const MAX_FACTS: usize = 4 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(15);
const POST: &str = "proof.recovery.post";
const GET: &str = "proof.recovery.reconcile";
const BASELINE: &str = "proof.recovery.baseline";
const SEAMS: [&str; 5] = [
    "before_reservation_commit",
    "after_reservation_commit",
    "after_sending_commit",
    "after_receiver_increment",
    "after_completion_commit",
];

pub struct RecoveryPrograms {
    pub engine: PathBuf,
    pub receiver: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "WireLedgerSnapshot")]
pub struct LedgerSnapshot {
    pub run_id: EntityId,
    pub budget: Budget,
    pub project: FixtureProject,
    pub scope: ScopePolicy,
    pub session: InvestigationSession,
    pub identities: Vec<IdentityProfile>,
    pub tools: Vec<RegisteredTool>,
    pub invocations: Vec<Invocation>,
    pub histories: Vec<Value>,
    pub reservations: BTreeMap<EntityId, WireInt>,
    pub grants: Vec<ApprovalGrant>,
    pub controls: Vec<ControlState>,
    pub checkpoint: Option<Checkpoint>,
    pub events: Vec<Event>,
    pub database_sha256: Digest,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLedgerSnapshot {
    run_id: EntityId,
    budget: Budget,
    project: FixtureProject,
    scope: ScopePolicy,
    session: InvestigationSession,
    identities: Vec<IdentityProfile>,
    tools: Vec<RegisteredTool>,
    invocations: Vec<InvocationWire>,
    histories: Vec<Value>,
    reservations: BTreeMap<EntityId, WireInt>,
    grants: Vec<ApprovalGrant>,
    controls: Vec<ControlState>,
    checkpoint: Option<Checkpoint>,
    events: Vec<Event>,
    database_sha256: Digest,
}

impl TryFrom<WireLedgerSnapshot> for LedgerSnapshot {
    type Error = ProofError;

    fn try_from(wire: WireLedgerSnapshot) -> ProofResult<Self> {
        if wire.invocations.len() != wire.histories.len() {
            return Err(invalid());
        }
        let invocations = wire
            .invocations
            .into_iter()
            .zip(&wire.histories)
            .map(|(invocation, facts)| {
                let history = InvocationHistory::restore_json(&encode(facts)?)?;
                let invocation = invocation.into_validated(Some(&history))?;
                if history.last() != &invocation {
                    return Err(invalid());
                }
                Ok(invocation)
            })
            .collect::<ProofResult<Vec<_>>>()?;
        Ok(Self {
            run_id: wire.run_id,
            budget: wire.budget,
            project: wire.project,
            scope: wire.scope,
            session: wire.session,
            identities: wire.identities,
            tools: wire.tools,
            invocations,
            histories: wire.histories,
            reservations: wire.reservations,
            grants: wire.grants,
            controls: wire.controls,
            checkpoint: wire.checkpoint,
            events: wire.events,
            database_sha256: wire.database_sha256,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CrashScenario {
    pub directory: PathBuf,
    pub seam: String,
    pub invocation_id: EntityId,
    pub receiver_action_id: EntityId,
    pub worker_pid: u32,
    pub receiver_pid: u32,
    pub restart_pid: u32,
    pub worker_signal: i32,
    pub worker_epoch: EntityId,
    pub restart_epoch: EntityId,
    pub receiver_before: u64,
    pub receiver_after_kill: u64,
    pub receiver_after_restart: u64,
    pub before: LedgerSnapshot,
    pub after: LedgerSnapshot,
    pub baseline_invocation_id: EntityId,
    pub reconcile_invocation_id: EntityId,
    pub runtime_admission: Option<RuntimeRecoveryFact>,
}

/// The unchanged SDK request is actually dispatched on the restarted host channel.
/// Lease records describe the lost binding; they are never edited into a rejection.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRecoveryFact {
    pub original_message: Vec<u8>,
    pub original_reply: Vec<u8>,
    pub submitted_message: Vec<u8>,
    pub original_lease: Lease,
    pub submitted_lease: Lease,
    pub current_binding_id: EntityId,
    pub current_control_revision: WireInt,
    pub before: LedgerSnapshot,
    pub after: LedgerSnapshot,
    pub healthy_message: Vec<u8>,
    pub error: ProofError,
    pub authority_error: ProofError,
    pub healthy_invocation_id: EntityId,
    pub receiver_before: u64,
    pub receiver_after: u64,
    pub receiver_after_healthy: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryFact {
    pub event: Event,
    pub current_revision: WireInt,
    pub first: String,
    pub second: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityAttempt {
    pub kind: String,
    pub directory: PathBuf,
    pub before: LedgerSnapshot,
    pub after: LedgerSnapshot,
    pub error: ProofError,
    pub receiver_before: u64,
    pub receiver_after: u64,
    pub current_engine_sha256: Digest,
    pub current_identity: IdentityProfile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageFaultFact {
    pub kind: String,
    pub directory: PathBuf,
    pub before: LedgerSnapshot,
    pub after: Option<LedgerSnapshot>,
    pub error: Option<ProofError>,
    pub admission_error: Option<ProofError>,
    pub sqlite_primary_code: Option<i32>,
    pub sqlite_extended_code: Option<i32>,
    pub telemetry: String,
    pub page_limit: Option<u64>,
    pub sync_fixture: Option<SyncFixture>,
    pub bytes_before: Digest,
    pub bytes_after: Digest,
    pub receiver_before: u64,
    pub receiver_after: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncFixture {
    pub source_sha256: Digest,
    pub build_sha256: Digest,
    pub dylib_sha256: Digest,
}

fn prepared_sync_fixture(repo: &Path) -> ProofResult<SyncFixture> {
    let fixture = SyncFixture {
        source_sha256: hash_file(&repo.join("fixtures/storage-faults/sync_eio.c"))?,
        build_sha256: hash_file(&repo.join("scripts/proofs/build-storage-fault.sh"))?,
        dylib_sha256: hash_file(&repo.join("target/r0-tools/storage-faults/sync_eio.dylib"))?,
    };
    validate_sync_fixture(&fixture)?;
    Ok(fixture)
}

fn validate_sync_fixture(fixture: &SyncFixture) -> ProofResult<()> {
    if fixture.source_sha256
        != Digest::parse("09599108c5a02ac009b5405dfa9554c4fdcc33e8997ee04d77655c026b0fb564")?
        || fixture.build_sha256
            != Digest::parse("2d5de367b3a6c7bcd904b30eb5b02e4e12c0001a9abf4fb09659b58745df64ce")?
        || fixture.dylib_sha256
            != Digest::parse("2438cad0286ab6a4f4958af97d76f49749aca108574935240857cac2251d1c98")?
    {
        return Err(integrity());
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReport {
    pub case_id: CatalogId,
    pub profile_sha256: Digest,
    pub fixture_sha256: Digest,
    pub engine_sha256: Digest,
    pub receiver_sha256: Digest,
    pub scenarios: Vec<CrashScenario>,
    /// Additional SDK channel-epoch exercise; never a ledger-owner crash seam.
    pub channel_scenario: Option<CrashScenario>,
    pub deliveries: Vec<DeliveryFact>,
    pub authority_attempts: Vec<AuthorityAttempt>,
    pub storage_faults: Vec<StorageFaultFact>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    profile_path: PathBuf,
    profile_sha256: Digest,
    engine_sha256: Digest,
    address: SocketAddr,
    token: String,
    project: FixtureProject,
    scope: ScopePolicy,
    identity: IdentityProfile,
    session: InvestigationSession,
    budget_id: EntityId,
    baseline_id: EntityId,
    action_id: EntityId,
    target_input: EntityId,
    target_sha256: Digest,
    target_call_id: EntityId,
    runtime_recovery: bool,
    post_request: Option<HttpSendInput>,
    get_request: Option<HttpSendInput>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkerMessage {
    protocol: String,
    epoch: EntityId,
    pid: u32,
    seam: String,
    snapshot: Option<LedgerSnapshot>,
    reconcile_invocation_id: Option<EntityId>,
    lease: Option<crate::domain::runtime::Lease>,
}

#[track_caller]
fn invalid() -> ProofError {
    eprintln!(
        r#"{{"component":"recovery-proof","validation_line":{}}}"#,
        std::panic::Location::caller().line(),
    );
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Recovery facts are missing, inconsistent, or incomplete",
    )
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Recovery canonical storage or executable integrity failed",
    )
}
#[track_caller]
fn unavailable() -> ProofError {
    eprintln!(
        r#"{{"component":"recovery-process","validation_line":{}}}"#,
        std::panic::Location::caller().line(),
    );
    ProofError::new(
        ErrorCode::ProviderUnavailable,
        "Owned recovery process or observer is unavailable",
    )
}
fn wire(value: u64) -> ProofResult<WireInt> {
    Ok(WireInt::new(value)?)
}
fn encode(value: &impl Serialize) -> ProofResult<Vec<u8>> {
    let bytes = serde_json::to_vec(value).map_err(|_| invalid())?;
    if bytes.len() > MAX_FACTS {
        return Err(invalid());
    }
    Ok(bytes)
}
fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> ProofResult<T> {
    if bytes.len() > MAX_FACTS {
        return Err(invalid());
    }
    serde_json::from_slice(bytes).map_err(|_| invalid())
}

/// No network, new authority, replay, quota reconstruction, or usage estimation occurs here.
/// The invocation/history, quota settlement, event and checkpoint commit atomically.
pub fn reconcile(ledger: &Ledger) -> ProofResult<Vec<EntityId>> {
    let pending: Vec<_> = ledger
        .invocations()?
        .into_iter()
        .filter(|stored| {
            matches!(
                stored.invocation.state,
                InvocationState::Proposed
                    | InvocationState::WaitingApproval
                    | InvocationState::Reserved
                    | InvocationState::Sending
            )
        })
        .map(|stored| stored.invocation.invocation_id)
        .collect();
    ledger.transaction(|tx| {
        let mut changed = Vec::with_capacity(pending.len());
        for id in &pending {
            let mut stored = tx.read_invocation(*id)?;
            let previous = stored.invocation.state;
            let next = match previous {
                InvocationState::Proposed => InvocationState::Rejected,
                InvocationState::WaitingApproval | InvocationState::Reserved => {
                    InvocationState::Cancelled
                }
                InvocationState::Sending => InvocationState::OutcomeUnknown,
                _ => continue,
            };
            if previous == InvocationState::Reserved {
                let budget = tx.read_budget(stored.invocation.budget_id)?;
                tx.settle_budget(
                    budget.budget_id,
                    stored.reserved_units,
                    WireInt::ZERO,
                    budget.revision,
                )?;
                stored.reserved_units = WireInt::ZERO;
            }
            stored.invocation.state = next;
            stored.invocation.error = Some(
                ProofError::new(
                    if next == InvocationState::OutcomeUnknown {
                        ErrorCode::OutcomeUnknown
                    } else {
                        ErrorCode::Cancelled
                    },
                    if next == InvocationState::OutcomeUnknown {
                        "Engine restart leaves the external outcome unknown; no automatic resend"
                    } else {
                        "Restart invalidated unspent pending work"
                    },
                )
                .with_invocation(*id),
            );
            let now = AuditTime::now();
            stored.history.record(&stored.invocation, None, now)?;
            tx.update_invocation(&stored, previous)?;
            let invocation = &stored.invocation;
            let sequence = stored.history.event_sequence();
            tx.append_event(&Event {
                event_id: EntityId::new(),
                schema_version: ContractVersion::V0_1_0,
                project_id: invocation.project_id,
                aggregate_id: *id,
                aggregate_sequence: sequence,
                event_type: CatalogId::parse(if next == InvocationState::OutcomeUnknown {
                    "invocation.outcome_unknown"
                } else if next == InvocationState::Rejected {
                    "invocation.rejected"
                } else {
                    "invocation.cancelled"
                })?,
                timestamp: now,
                correlation_id: invocation.causation_id,
                causation_id: invocation.causation_id,
                control_revision: Some(invocation.control_revision),
                data_refs: vec![invocation.input_ref],
                published: false,
            })?;
            let project = tx.read_project(invocation.project_id)?;
            let scope = tx.read_scope(project.scope_policy_id)?;
            let control = tx.read_control(invocation.investigation_id)?;
            tx.write_checkpoint(&Checkpoint {
                checkpoint_id: EntityId::new(),
                run_id: ledger.run_id(),
                schema_version: ContractVersion::V0_1_0,
                control_revision: control.revision,
                scope_revision: scope.revision,
                budget_refs: vec![invocation.budget_id],
                invocation_refs: vec![*id],
                lease_refs: Vec::new(),
                event_cursors: BTreeMap::from([(*id, sequence)]),
                created_at: now,
            })?;
            changed.push(*id);
        }
        Ok(changed)
    })
}

fn snapshot(
    ledger: &Ledger,
    workspace: &OwnedDirectory,
    budget_id: EntityId,
) -> ProofResult<LedgerSnapshot> {
    let stored = ledger.invocations()?;
    let mut histories = Vec::with_capacity(stored.len());
    let mut reservations = BTreeMap::new();
    for item in &stored {
        histories.push(decode(&item.history.export_json()?)?);
        reservations.insert(item.invocation.invocation_id, item.reserved_units);
    }
    let mut events = Vec::new();
    let mut cursor = WireInt::ZERO;
    loop {
        let page = ledger.event_page(cursor, 256)?;
        if page.events.is_empty() {
            break;
        }
        if events.len() + page.events.len() > 16_384 {
            return Err(integrity());
        }
        cursor = page.last_position;
        events.extend(page.events);
    }
    let origin = &stored.first().ok_or_else(invalid)?.invocation;
    let project = ledger.read_project(origin.project_id)?;
    let scope = ledger.read_scope(project.scope_policy_id)?;
    let session = ledger.read_session(origin.session_id)?.session;
    let mut identities = BTreeMap::new();
    let mut tools = BTreeMap::new();
    for item in &stored {
        if let std::collections::btree_map::Entry::Vacant(e) =
            identities.entry(item.invocation.identity_id)
        {
            e.insert(ledger.read_identity(item.invocation.identity_id)?);
        }
        if !tools.contains_key(&item.invocation.tool_id) {
            tools.insert(
                item.invocation.tool_id.clone(),
                ledger.read_tool(&item.invocation.tool_id)?,
            );
        }
    }
    Ok(LedgerSnapshot {
        run_id: ledger.run_id(),
        budget: ledger.read_budget(budget_id)?,
        project,
        scope,
        session,
        identities: identities.into_values().collect(),
        tools: tools.into_values().collect(),
        invocations: stored.into_iter().map(|item| item.invocation).collect(),
        histories,
        reservations,
        grants: ledger.grants()?,
        controls: ledger.controls()?,
        checkpoint: ledger.latest_checkpoint()?,
        events,
        database_sha256: hash_file(&workspace.path().join("ledger.sqlite"))?,
    })
}

fn hash_file(path: &Path) -> ProofResult<Digest> {
    let flags = rustix::fs::OFlags::RDONLY
        | rustix::fs::OFlags::NOFOLLOW
        | rustix::fs::OFlags::CLOEXEC
        | rustix::fs::OFlags::NONBLOCK;
    let mut file = std::fs::File::from(
        rustix::fs::open(path, flags, rustix::fs::Mode::empty()).map_err(|_| integrity())?,
    );
    let metadata = file.metadata().map_err(|_| integrity())?;
    if !metadata.is_file() || metadata.len() > 1024 * 1024 * 1024 {
        return Err(integrity());
    }
    use sha2::{Digest as _, Sha256};
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let started = Instant::now();
    let mut total = 0_u64;
    loop {
        if started.elapsed() > DEADLINE {
            return Err(ProofError::new(
                ErrorCode::Timeout,
                "Recovery immutable-file hashing deadline exceeded",
            ));
        }
        let length = file.read(&mut buffer).map_err(|_| integrity())?;
        if length == 0 {
            break;
        }
        total = total.checked_add(length as u64).ok_or_else(integrity)?;
        if total > metadata.len() {
            return Err(integrity());
        }
        hash.update(&buffer[..length]);
    }
    let after = file.metadata().map_err(|_| integrity())?;
    let named = std::fs::File::from(
        rustix::fs::open(path, flags, rustix::fs::Mode::empty()).map_err(|_| integrity())?,
    )
    .metadata()
    .map_err(|_| integrity())?;
    if total != metadata.len()
        || !crate::adapters::native_files::same_file(&metadata, &after)
        || !crate::adapters::native_files::same_file(&metadata, &named)
    {
        return Err(integrity());
    }
    Ok(Digest::from_sha256(hash.finalize().into()))
}

fn call(
    config: &Configuration,
    tool: &str,
    id: EntityId,
    call_id: EntityId,
    input: EntityId,
    sha: Digest,
    units: u64,
) -> ProofResult<PreparedCall> {
    Ok(PreparedCall {
        invocation_id: id,
        call_id,
        tool_id: CatalogId::parse(tool)?,
        tool_version: ContractVersion::V0_1_0,
        input_ref: input,
        input_sha256: sha,
        input_revision: WireInt::ZERO,
        source_control_revision: config.session.control_revision,
        requested: Usage {
            units: wire(units)?,
            bytes: wire(65_536)?,
            cpu_us: wire(10_000_000)?,
            elapsed_us: wire(10_000_000)?,
        },
    })
}

fn spec(config: &Configuration, tool: &str) -> ProofResult<BindingSpec> {
    Ok(BindingSpec {
        user_id: config.project.user_id,
        project_id: config.project.project_id,
        investigation_id: config.session.investigation_id,
        session_id: config.session.session_id,
        identity_id: config.identity.identity_id,
        budget_id: config.budget_id,
        provider_digest: config.engine_sha256,
        allowed_tools: vec![CatalogId::parse(tool)?],
        permissions: vec![CatalogId::parse("fixture.recovery")?],
    })
}

fn approve(ledger: &Ledger, config: &Configuration, call: &PreparedCall) -> ProofResult<()> {
    ledger.insert_grant(&ApprovalGrant {
        grant_id: EntityId::new(),
        project_id: config.project.project_id,
        tool_id: call.tool_id.clone(),
        tool_version: call.tool_version,
        provider_digest: config.engine_sha256,
        scope_revision: config.scope.revision,
        identity_id: config.identity.identity_id,
        bounded_input_sha256: call.input_sha256,
        limits: call.requested,
        expires_at: AuditTime::now().checked_add(Duration::from_secs(300))?,
        revoked: false,
    })
}

fn initialize(
    workspace: &Arc<OwnedDirectory>,
    profile: &LoadedProfile,
    profile_path: &Path,
    engine_sha256: Digest,
    address: SocketAddr,
    token: String,
    runtime_recovery: bool,
) -> ProofResult<Configuration> {
    let project: FixtureProject = decode(&encode(
        &json!({"project_id": EntityId::new(), "user_id": EntityId::new(), "scope_policy_id": EntityId::new(), "revision": 0}),
    )?)?;
    let scope: ScopePolicy = decode(&encode(
        &json!({"scope_policy_id": project.scope_policy_id, "project_id": project.project_id, "revision": 0,
        "allowed_destinations": [{"scheme": "http", "host": "127.0.0.1", "port": address.port(), "path": {"kind": "prefix", "value": "/"}, "resolved_addresses": ["127.0.0.1"]}], "exclusions": []}),
    )?)?;
    let identity: IdentityProfile = decode(&encode(
        &json!({"identity_id": EntityId::new(), "project_id": project.project_id, "secret_ref_names": []}),
    )?)?;
    let session: InvestigationSession = decode(&encode(
        &json!({"investigation_id": EntityId::new(), "session_id": EntityId::new(), "user_id": project.user_id,
        "goal": "Exercise only this owned synthetic crash recovery counter", "control_revision": 0, "branch_refs": [], "evidence_refs": []}),
    )?)?;
    let ledger = Arc::new(Ledger::create(workspace, profile)?);
    ledger.transaction(|tx| {
        tx.insert_project(&project)?;
        tx.insert_scope(&scope)?;
        tx.insert_identity(&identity)
    })?;
    for tool in [BASELINE, POST, GET] {
        let record: RegisteredTool = decode(&encode(
            &json!({"provider_digest": engine_sha256, "descriptor": {
                "tool_id": tool, "version": "0.1.0", "input_contract": "proof.recovery.input", "output_contract": "proof.recovery.output",
                "effect": if tool == BASELINE { "local_write" } else { "active_network" }, "permissions": ["fixture.recovery"],
                "limits": {"units": 4, "bytes": 65536, "cpu_us": 10000000, "elapsed_us": 10000000}, "retry_class": if tool == GET { "safe_read" } else { "non_retryable" }
            }}),
        )?)?;
        ledger.insert_tool(&record)?;
    }
    if runtime_recovery {
        ledger.insert_tool(&http_send::registered_tool(engine_sha256, profile)?)?;
    }
    let budget_id = EntityId::new();
    ledger.insert_budget(&Budget {
        budget_id,
        parent_budget_id: None,
        limit: wire(64)?,
        consumed: WireInt::ZERO,
        reserved: WireInt::ZERO,
        revision: WireInt::ZERO,
    })?;
    let baseline_id = EntityId::new();
    let action_id = EntityId::new();
    let evidence = EvidenceStore::open(Arc::clone(workspace))?;
    let instruction = evidence.write_artifact(
        project.project_id,
        CatalogId::parse("recovery-instruction")?,
        baseline_id,
        b"Only the controlled synthetic loopback counter is approved.",
        RedactionStatus::Original,
    )?;
    let input = evidence.write_artifact(
        project.project_id,
        CatalogId::parse("recovery-post-input")?,
        action_id,
        &encode(&json!({"method":"POST","action_id":action_id,"port":address.port()}))?,
        RedactionStatus::Original,
    )?;
    ledger.insert_control(
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
    ledger.insert_session(&session, project.project_id)?;
    let mut config = Configuration {
        profile_path: profile_path.to_path_buf(),
        profile_sha256: profile.sha256(),
        engine_sha256,
        address,
        token,
        project,
        scope,
        identity,
        session,
        budget_id,
        baseline_id,
        action_id,
        target_input: input.artifact_id,
        target_sha256: input.sha256,
        target_call_id: EntityId::new(),
        runtime_recovery,
        post_request: None,
        get_request: None,
    };
    let control = Arc::new(ControlService::new(
        Arc::clone(&ledger),
        profile,
        config.session.investigation_id,
    )?);
    let admission = HostAdmission::new(Arc::clone(&ledger), control);
    let binding = admission.bind(spec(&config, BASELINE)?)?;
    let prepared = call(
        &config,
        BASELINE,
        baseline_id,
        EntityId::new(),
        instruction.artifact_id,
        instruction.sha256,
        1,
    )?;
    approve(&ledger, &config, &prepared)?;
    admission.reserve(&binding, &prepared)?;
    let permit = admission.begin_effect(&binding, baseline_id)?;
    let started = Instant::now();
    let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    if runtime_recovery {
        config.post_request = Some(recovery_request(&evidence, &binding, &config, "POST")?);
        config.get_request = Some(recovery_request(&evidence, &binding, &config, "GET")?);
    }
    let bytes = b"Actual prior completed local consumption survives every restart.";
    let output = evidence.write_artifact(
        config.project.project_id,
        CatalogId::parse("recovery-baseline")?,
        baseline_id,
        bytes,
        RedactionStatus::Original,
    )?;
    let mut written = bytes.len();
    for input in [&config.post_request, &config.get_request]
        .into_iter()
        .flatten()
    {
        let descriptor = evidence.snapshot(
            config.project.project_id,
            input.request_snapshot_id,
            input.base_revision,
        )?;
        written = written
            .checked_add(usize::try_from(descriptor.length_bytes.get()).map_err(|_| integrity())?)
            .ok_or_else(integrity)?;
    }
    admission.complete(
        &binding,
        permit,
        measured(started, cpu, written, 1)?,
        Some(output.artifact_id),
    )?;
    if !runtime_recovery {
        let target = call(
            &config,
            POST,
            action_id,
            config.target_call_id,
            config.target_input,
            config.target_sha256,
            4,
        )?;
        approve(&ledger, &config, &target)?;
    }
    workspace.write_new(Path::new("recovery-config.json"), &encode(&config)?)?;
    Ok(config)
}

fn measured(
    started: Instant,
    cpu: rustix::time::Timespec,
    bytes: usize,
    units: u64,
) -> ProofResult<Usage> {
    let end = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let elapsed_cpu = (i128::from(end.tv_sec) - i128::from(cpu.tv_sec)) * 1_000_000_000
        + i128::from(end.tv_nsec)
        - i128::from(cpu.tv_nsec);
    if elapsed_cpu < 0 {
        return Err(integrity());
    }
    Ok(Usage {
        units: wire(units)?,
        bytes: wire(bytes as u64)?,
        cpu_us: wire(u64::try_from((elapsed_cpu + 999) / 1000).map_err(|_| integrity())?)?,
        elapsed_us: wire(u64::try_from(started.elapsed().as_micros()).map_err(|_| integrity())?)?,
    })
}

fn authorize(
    admission: &HostAdmission,
    binding: &super::admission::TrustedBinding,
    permit: &super::admission::EffectPermit,
    config: &Configuration,
    method: &str,
) -> ProofResult<()> {
    let destination = Destination::parse(&format!(
        "http://127.0.0.1:{}/{}/{}",
        config.address.port(),
        if method == "POST" { "effect" } else { "count" },
        config.action_id
    ))?;
    admission.authorize_destination(
        binding,
        permit,
        &DestinationCheck {
            destination: &destination,
            resolved_addresses: &[IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
            chosen_address: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            connect_authority: None,
            server_name: None,
            request_authority: None,
        },
    )
}

fn http(
    address: SocketAddr,
    token: &str,
    method: &str,
    action: EntityId,
) -> ProofResult<(u64, Vec<u8>)> {
    if !address.ip().is_loopback()
        || token.len() != 64
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(integrity());
    }
    let mut stream =
        TcpStream::connect_timeout(&address, Duration::from_secs(2)).map_err(|_| unavailable())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| unavailable())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(2)))
        .map_err(|_| unavailable())?;
    write!(stream, "{method} /{}/{action} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", if method == "POST" { "effect" } else { "count" }).map_err(|_| unavailable())?;
    let mut bytes = Vec::new();
    stream
        .take(65_537)
        .read_to_end(&mut bytes)
        .map_err(|_| unavailable())?;
    if bytes.len() > 65_536 || !bytes.starts_with(b"HTTP/1.1 200 ") {
        return Err(invalid());
    }
    let split = bytes
        .windows(4)
        .position(|part| part == b"\r\n\r\n")
        .ok_or_else(invalid)?
        + 4;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Count {
        action_id: EntityId,
        count: WireInt,
    }
    let count: Count = decode(&bytes[split..])?;
    if count.action_id != action {
        return Err(invalid());
    }
    Ok((count.count.get(), bytes))
}

fn emit(message: &WorkerMessage) -> ProofResult<()> {
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&encode(message)?)
        .map_err(|_| unavailable())?;
    stdout.write_all(b"\n").map_err(|_| unavailable())?;
    stdout.flush().map_err(|_| unavailable())
}
fn barrier(seam: &str, epoch: EntityId, lease: Option<&Lease>) -> ProofResult<()> {
    emit(&WorkerMessage {
        protocol: "razen.recovery-worker/0.1.0".to_owned(),
        epoch,
        pid: std::process::id(),
        seam: seam.to_owned(),
        snapshot: None,
        reconcile_invocation_id: None,
        lease: lease.cloned(),
    })?;
    let mut byte = [0];
    // This wait is legal only in this dedicated trusted fixture worker, never a runtime callback.
    std::io::stdin()
        .read_exact(&mut byte)
        .map_err(|_| unavailable())?;
    Err(invalid())
}

/// Engine-only private entry. No executable path, shell command, peer fault flag, or PID is accepted.
pub fn engine_worker(args: &[OsString]) -> ProofResult<()> {
    let outcome = worker_inner(args);
    if let Err(error) = &outcome {
        // Partial diagnostics are retained only in a successfully revalidated owned run.
        if args.len() == 4 && args[0] == "--directory" {
            let path = Path::new(&args[1]);
            if let (Some(base), Some(name)) = (path.parent(), path.file_name())
                && let Ok(workspace) = OwnedDirectory::open(base, Path::new(name))
            {
                let diagnostic = json!({"error": error, "sqlite": error.storage_fault()});
                if let Ok(bytes) = encode(&diagnostic) {
                    let _ = workspace.write_new(
                        Path::new(&format!("worker-error-{}.json", EntityId::new())),
                        &bytes,
                    );
                }
            }
        }
    }
    outcome
}

fn worker_inner(args: &[OsString]) -> ProofResult<()> {
    if args.len() != 4 || args[0] != "--directory" || args[2] != "--mode" {
        return Err(invalid());
    }
    let path = Path::new(&args[1]);
    if !path.is_absolute() {
        return Err(invalid());
    }
    let workspace = Arc::new(OwnedDirectory::open(
        path.parent().ok_or_else(invalid)?,
        Path::new(path.file_name().ok_or_else(invalid)?),
    )?);
    let config: Configuration =
        decode(&workspace.read(Path::new("recovery-config.json"), 65_536)?)?;
    let profile = LoadedProfile::load(&config.profile_path)?;
    if profile.sha256() != config.profile_sha256
        || hash_file(&std::env::current_exe().map_err(|_| integrity())?)? != config.engine_sha256
    {
        return Err(integrity());
    }
    let mode = args[3].to_str().ok_or_else(invalid)?;
    if mode != "restart"
        && mode != "storage_full"
        && mode != "storage_sync"
        && !SEAMS.contains(&mode)
    {
        return Err(invalid());
    }
    if config.runtime_recovery {
        return runtime_worker(&workspace, &config, mode);
    }
    let ledger = Arc::new(Ledger::open(&workspace, &profile)?);
    let evidence = EvidenceStore::open(Arc::clone(&workspace))?;
    let control = Arc::new(ControlService::new(
        Arc::clone(&ledger),
        &profile,
        config.session.investigation_id,
    )?);
    let epoch = control.clock_epoch_id();
    let admission = Arc::new(HostAdmission::new(
        Arc::clone(&ledger),
        Arc::clone(&control),
    ));
    if mode == "restart" {
        if let Err(error) = reconcile(&ledger) {
            admission.invalidate_integrity();
            return Err(error);
        }
        let id = EntityId::new();
        let input_bytes = encode(
            &json!({"method":"GET","action_id":config.action_id,"purpose":"read-only outcome reconciliation","port":config.address.port()}),
        )?;
        let input = evidence.write_artifact(
            config.project.project_id,
            CatalogId::parse("recovery-get-input")?,
            id,
            &input_bytes,
            RedactionStatus::Original,
        )?;
        let binding = admission.bind(spec(&config, GET)?)?;
        let prepared = call(
            &config,
            GET,
            id,
            EntityId::new(),
            input.artifact_id,
            input.sha256,
            0,
        )?;
        approve(&ledger, &config, &prepared)?;
        admission.reserve(&binding, &prepared)?;
        let permit = admission.begin_effect(&binding, id)?;
        authorize(&admission, &binding, &permit, &config, "GET")?;
        let started = Instant::now();
        let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
        let (_, bytes) = http(config.address, &config.token, "GET", config.action_id)?;
        let output = evidence.write_artifact(
            config.project.project_id,
            CatalogId::parse("recovery-get-output")?,
            id,
            &bytes,
            RedactionStatus::Original,
        )?;
        admission.complete(
            &binding,
            permit,
            measured(started, cpu, bytes.len(), 0)?,
            Some(output.artifact_id),
        )?;
        let state = snapshot(&ledger, &workspace, config.budget_id)?;
        return emit(&WorkerMessage {
            protocol: "razen.recovery-worker/0.1.0".to_owned(),
            epoch,
            pid: std::process::id(),
            seam: "restarted".to_owned(),
            snapshot: Some(state),
            reconcile_invocation_id: Some(id),
            lease: None,
        });
    }
    let binding = admission.bind(spec(&config, POST)?)?;
    let prepared = call(
        &config,
        POST,
        config.action_id,
        config.target_call_id,
        config.target_input,
        config.target_sha256,
        4,
    )?;
    if mode == "before_reservation_commit" {
        ledger.install_fixture_commit_hook(move || {
            let _ = barrier("before_reservation_commit", epoch, None);
            true
        })?;
    }
    if mode == "storage_full" || mode == "storage_sync" {
        return storage_worker(
            StorageWorkerContext {
                workspace: &workspace,
                ledger: &ledger,
                admission: &admission,
            },
            &binding,
            &prepared,
            &config,
            mode,
            epoch,
        );
    }
    admission.reserve(&binding, &prepared)?;
    if mode == "after_reservation_commit" {
        return barrier(mode, epoch, None);
    }
    let permit = admission.begin_effect(&binding, config.action_id)?;
    if mode == "after_sending_commit" {
        return barrier(mode, epoch, None);
    }
    authorize(&admission, &binding, &permit, &config, "POST")?;
    let started = Instant::now();
    let cpu = rustix::time::clock_gettime(rustix::time::ClockId::ProcessCPUTime);
    let (_, bytes) = http(config.address, &config.token, "POST", config.action_id)?;
    if mode == "after_receiver_increment" {
        return barrier(mode, epoch, None);
    }
    let output = evidence.write_artifact(
        config.project.project_id,
        CatalogId::parse("recovery-post-output")?,
        config.action_id,
        &bytes,
        RedactionStatus::Original,
    )?;
    admission.complete(
        &binding,
        permit,
        measured(started, cpu, bytes.len(), 1)?,
        Some(output.artifact_id),
    )?;
    barrier("after_completion_commit", epoch, None)
}

fn runtime_registry(
    admission: &Arc<HostAdmission>,
    evidence: &Arc<EvidenceStore>,
    profile: &LoadedProfile,
    config: &Configuration,
) -> ProofResult<Arc<Registry>> {
    use crate::adapters::transport::{Mode, TransportConfig, scope_connector::Resolver};
    let transport = TransportConfig {
        mode: Mode::Http1Forward,
        resolver: Resolver::System,
        upstream_roots: Arc::new(rustls::RootCertStore::empty()),
        client_roots: Arc::new(rustls::RootCertStore::empty()),
        ingress_tls: None,
        tls_server_name: None,
        connect_authority: None,
    };
    let provider = HttpSendProvider::new(
        Arc::clone(admission),
        Arc::clone(evidence),
        profile,
        transport,
    )?;
    let provider = provider.with_secret_headers(
        config.identity.identity_id,
        vec![crate::domain::evidence::Header {
            name: "authorization".to_owned(),
            value: format!("Bearer {}", config.token),
        }],
    )?;
    let repo = config
        .profile_path
        .ancestors()
        .nth(4)
        .ok_or_else(integrity)?;
    Ok(Arc::new(Registry::with_http(
        Arc::clone(admission),
        Arc::clone(evidence),
        CanonicalFixtures::load(&repo.join("fixtures/scenarios/contracts.json"))?,
        profile,
        provider,
    )?))
}

fn runtime_binding(
    admission: &HostAdmission,
    config: &Configuration,
) -> ProofResult<Arc<super::admission::TrustedBinding>> {
    let mut binding = spec(config, "http.send")?;
    binding.permissions = vec![CatalogId::parse("http.send")?];
    Ok(Arc::new(admission.bind(binding)?))
}

fn runtime_dispatch(
    registry: &Registry,
    binding: &Arc<super::admission::TrustedBinding>,
    frame: &[u8],
) -> ProofResult<ToolResult> {
    let decoded = decode_frame(frame, 65_536, ChannelRole::Runtime, Direction::PeerToHost)?;
    let Message::ToolRequest(request) = decoded.into_message() else {
        return Err(invalid());
    };
    registry.execute(binding, &request)
}

fn approve_runtime(
    registry: &Registry,
    binding: &Arc<super::admission::TrustedBinding>,
    ledger: &Ledger,
    config: &Configuration,
    frame: &[u8],
) -> ProofResult<EntityId> {
    let decoded = decode_frame(frame, 65_536, ChannelRole::Runtime, Direction::PeerToHost)?;
    let Message::ToolRequest(request) = decoded.into_message() else {
        return Err(invalid());
    };
    let prepared = registry.prepare(binding, &request)?;
    approve(ledger, config, prepared.call())?;
    Ok(prepared.call().invocation_id)
}

fn recovery_request(
    evidence: &EvidenceStore,
    binding: &super::admission::TrustedBinding,
    config: &Configuration,
    method: &str,
) -> ProofResult<HttpSendInput> {
    use crate::adapters::transport::capture;
    use crate::domain::evidence::{Header, Representation};
    let body = capture::snapshot(
        evidence,
        config.project.project_id,
        config.baseline_id,
        capture::SnapshotBody {
            bytes: b"",
            headers: Vec::new(),
            representation: Representation::Http1Body,
            truncated: false,
            derived_from: None,
        },
    )?;
    http_send::install_request(
        evidence,
        binding,
        config.baseline_id,
        RequestSnapshot {
            body_snapshot_id: body,
            body_revision: WireInt::ZERO,
            url: format!(
                "http://127.0.0.1:{}/{}/{}",
                config.address.port(),
                if method == "POST" { "effect" } else { "count" },
                config.action_id
            ),
            method: method.to_owned(),
            headers: vec![Header {
                name: "host".to_owned(),
                value: config.address.to_string(),
            }],
            request_count: wire(1)?,
            reset_first_stream: false,
        },
    )
}

fn runtime_request(
    input: &HttpSendInput,
    call_id: EntityId,
    revision: WireInt,
) -> ProofResult<Vec<u8>> {
    encode_envelope(
        EntityId::new(),
        "tool_request",
        None,
        &json!({
            "call_id": call_id, "tool_id": "http.send", "tool_version": "0.1.0",
            "input": input, "source_control_revision": revision,
        }),
        65_536,
    )
}

/// A real native SDK sender, not a guest runtime or a claimed sandbox attestation.
/// Its host-only channel capability remains in the owning controller, never JSON.
fn runtime_worker(
    workspace: &OwnedDirectory,
    config: &Configuration,
    mode: &str,
) -> ProofResult<()> {
    if mode != "after_completion_commit" && mode != "restart" {
        return Err(invalid());
    }
    let frame = workspace.read(Path::new("runtime-request.json"), 65_536)?;
    let lease: Lease = decode(&workspace.read(Path::new("worker-lease.json"), 65_536)?)?;
    let epoch: EntityId = decode(&workspace.read(Path::new("worker-epoch.json"), 1024)?)?;
    let decoded = decode_frame(&frame, 65_536, ChannelRole::Runtime, Direction::PeerToHost)?;
    let request_id = decoded.message_id;
    let Message::ToolRequest(request) = decoded.into_message() else {
        return Err(invalid());
    };
    if request.call_id != config.target_call_id
        || lease.control_revision != request.source_control_revision
    {
        return Err(integrity());
    }
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&frame).map_err(|_| unavailable())?;
    stdout.flush().map_err(|_| unavailable())?;
    drop(stdout);
    let mut stdin = std::io::stdin().lock();
    if mode == "restart" {
        // The real current host rejects this lost channel and closes its input.
        if stdin.read(&mut [0_u8; 1]).map_err(|_| unavailable())? != 0 {
            return Err(invalid());
        }
        return Ok(());
    }
    let reply = read_frame(&mut stdin, 65_536)?.ok_or_else(unavailable)?;
    drop(stdin);
    let decoded = decode_frame(&reply, 65_536, ChannelRole::Runtime, Direction::HostToPeer)?;
    if decoded.correlation_id != Some(request_id) {
        return Err(invalid());
    }
    let Message::ToolResult(result) = decoded.into_message() else {
        return Err(invalid());
    };
    if result.call_id != request.call_id
        || result.invocation_id != lease.invocation_id
        || result.state != InvocationState::Completed
    {
        return Err(invalid());
    }
    barrier(mode, epoch, Some(&lease))
}

fn runtime_scenario(
    parent: &OwnedDirectory,
    profile: &LoadedProfile,
    programs: &RecoveryPrograms,
    workspace: Arc<OwnedDirectory>,
    config: Configuration,
    mut receiver: Receiver,
) -> ProofResult<(CrashScenario, Arc<OwnedDirectory>, Configuration, Receiver)> {
    let receiver_before = receiver.count(config.action_id)?;
    let ledger = Arc::new(Ledger::open(&workspace, profile)?);
    let evidence = Arc::new(EvidenceStore::open(Arc::clone(&workspace))?);
    let control = Arc::new(ControlService::new(
        Arc::clone(&ledger),
        profile,
        config.session.investigation_id,
    )?);
    let worker_epoch = control.clock_epoch_id();
    let admission = Arc::new(HostAdmission::new(Arc::clone(&ledger), control));
    let binding = runtime_binding(&admission, &config)?;
    let registry = runtime_registry(&admission, &evidence, profile, &config)?;
    let original_message = runtime_request(
        config.post_request.as_ref().ok_or_else(integrity)?,
        config.target_call_id,
        binding.control_revision(),
    )?;
    let invocation_id = approve_runtime(&registry, &binding, &ledger, &config, &original_message)?;
    let original_lease = Lease {
        lease_id: EntityId::new(),
        invocation_id,
        owner_binding_id: binding.binding_id(),
        control_revision: binding.control_revision(),
        expires_at: AuditTime::now().checked_add(Duration::from_secs(60))?,
        state: LeaseState::Active,
    };
    workspace.write_new(Path::new("runtime-request.json"), &original_message)?;
    workspace.write_new(Path::new("worker-lease.json"), &encode(&original_lease)?)?;
    workspace.write_new(Path::new("worker-epoch.json"), &encode(&worker_epoch)?)?;
    let mut child = worker(programs, &workspace, "after_completion_commit")?;
    let sent = child.line()?;
    if sent != original_message {
        return Err(integrity());
    }
    let result = runtime_dispatch(&registry, &binding, &sent)?;
    if result.state != InvocationState::Completed || result.invocation_id != invocation_id {
        return Err(invalid());
    }
    let request_id =
        decode_frame(&sent, 65_536, ChannelRole::Runtime, Direction::PeerToHost)?.message_id;
    let reply = encode_envelope(
        EntityId::new(),
        "tool_result",
        Some(request_id),
        &result,
        65_536,
    )?;
    workspace.write_new(Path::new("runtime-reply.json"), &reply)?;
    let input = child.child.stdin.as_mut().ok_or_else(unavailable)?;
    input.write_all(&reply).map_err(|_| unavailable())?;
    input.flush().map_err(|_| unavailable())?;
    let barrier_bytes = child.line()?;
    workspace.write_new(Path::new("worker-barrier.json"), &barrier_bytes)?;
    let barrier: WorkerMessage = decode(&barrier_bytes)?;
    if barrier.protocol != "razen.recovery-worker/0.1.0"
        || barrier.snapshot.is_some()
        || barrier.reconcile_invocation_id.is_some()
        || barrier.pid != child.child.id()
        || barrier.epoch != worker_epoch
        || barrier.seam != "after_completion_commit"
        || barrier.lease.as_ref() != Some(&original_lease)
    {
        return Err(invalid());
    }
    let worker_pid = child.child.id();
    let worker_signal = child.kill()?;
    let receiver_after_kill = receiver.count(config.action_id)?;
    let before = snapshot(&ledger, &workspace, config.budget_id)?;
    // Keep the actual opaque old capability, but destroy its host and every old
    // ledger/provider handle. No serialized binding or restored balance is used.
    drop(registry);
    drop(admission);
    drop(evidence);
    drop(ledger);
    let ledger = Arc::new(Ledger::open(&workspace, profile)?);
    let evidence = Arc::new(EvidenceStore::open(Arc::clone(&workspace))?);
    let control = Arc::new(ControlService::new(
        Arc::clone(&ledger),
        profile,
        config.session.investigation_id,
    )?);
    let restart_epoch = control.clock_epoch_id();
    let admission = Arc::new(HostAdmission::new(Arc::clone(&ledger), control));
    let registry = runtime_registry(&admission, &evidence, profile, &config)?;
    let current = runtime_binding(&admission, &config)?;
    let stale_before = snapshot(&ledger, &workspace, config.budget_id)?;
    let mut restarted = worker(programs, &workspace, "restart")?;
    let submitted_message = restarted.line()?;
    let submitted_lease: Lease = decode(&workspace.read(Path::new("worker-lease.json"), 65_536)?)?;
    let count_before = receiver.count(config.action_id)?;
    // REAL rejection: Registry -> HostAdmission::owns on the unchanged original
    // TrustedBinding. Its revision still equals current canonical control.
    let error = runtime_dispatch(&registry, &binding, &submitted_message)
        .err()
        .ok_or_else(integrity)?;
    let authority_error = admission
        .existing_invocation(&binding, config.target_call_id)
        .err()
        .ok_or_else(integrity)?;
    let stale_after = snapshot(&ledger, &workspace, config.budget_id)?;
    let count_after = receiver.count(config.action_id)?;
    drop(restarted.child.stdin.take());
    let restart_pid = restarted.child.id();
    if !restarted.wait()?.success() {
        return Err(unavailable());
    }
    let healthy_message = runtime_request(
        config.get_request.as_ref().ok_or_else(integrity)?,
        EntityId::new(),
        current.control_revision(),
    )?;
    let healthy_invocation_id =
        approve_runtime(&registry, &current, &ledger, &config, &healthy_message)?;
    let healthy = runtime_dispatch(&registry, &current, &healthy_message)?;
    if healthy.state != InvocationState::Completed || healthy.invocation_id != healthy_invocation_id
    {
        return Err(invalid());
    }
    let receiver_after_restart = receiver.count(config.action_id)?;
    let after = snapshot(&ledger, &workspace, config.budget_id)?;
    let fact = RuntimeRecoveryFact {
        original_message,
        submitted_message,
        original_reply: reply,
        original_lease,
        submitted_lease,
        current_binding_id: current.binding_id(),
        current_control_revision: current.control_revision(),
        before: stale_before,
        after: stale_after,
        healthy_message,
        error,
        authority_error,
        healthy_invocation_id,
        receiver_before: count_before,
        receiver_after: count_after,
        receiver_after_healthy: receiver_after_restart,
    };
    workspace.write_new(Path::new("runtime-admission.json"), &encode(&fact)?)?;
    let observed = CrashScenario {
        directory: workspace
            .path()
            .strip_prefix(parent.path())
            .map_err(|_| integrity())?
            .to_path_buf(),
        seam: "after_completion_commit".to_owned(),
        invocation_id,
        receiver_action_id: config.action_id,
        worker_pid,
        receiver_pid: receiver.process.child.id(),
        restart_pid,
        worker_signal,
        worker_epoch,
        restart_epoch,
        receiver_before,
        receiver_after_kill,
        receiver_after_restart,
        before,
        after,
        baseline_invocation_id: config.baseline_id,
        reconcile_invocation_id: healthy_invocation_id,
        runtime_admission: Some(fact),
    };
    Ok((observed, workspace, config, receiver))
}

struct Process {
    child: Child,
    output: UnixStream,
    reaped: bool,
}
impl Process {
    fn spawn(command: &mut Command) -> ProofResult<Self> {
        let (output, writer) = UnixStream::pair().map_err(|_| unavailable())?;
        output.set_nonblocking(true).map_err(|_| unavailable())?;
        let child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::from(OwnedFd::from(writer)))
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| unavailable())?;
        Ok(Self {
            child,
            output,
            reaped: false,
        })
    }
    fn line(&mut self) -> ProofResult<Vec<u8>> {
        let start = Instant::now();
        let mut bytes = Vec::new();
        let mut buffer = [0; 8192];
        loop {
            match self.output.read(&mut buffer) {
                Ok(0) => return Err(unavailable()),
                Ok(length) => {
                    bytes.extend_from_slice(&buffer[..length]);
                    if bytes.len() > MAX_FACTS {
                        return Err(invalid());
                    }
                    if bytes.last() == Some(&b'\n') {
                        if bytes[..bytes.len() - 1].contains(&b'\n') {
                            return Err(invalid());
                        }
                        return Ok(bytes);
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(unavailable()),
            }
            if start.elapsed() > DEADLINE {
                return Err(ProofError::new(
                    ErrorCode::Timeout,
                    "Owned recovery worker did not reach its named barrier",
                ));
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn wait(&mut self) -> ProofResult<std::process::ExitStatus> {
        let start = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().map_err(|_| unavailable())? {
                self.reaped = true;
                return Ok(status);
            }
            if start.elapsed() > DEADLINE {
                return Err(unavailable());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn kill(&mut self) -> ProofResult<i32> {
        self.child.kill().map_err(|_| unavailable())?;
        self.wait()?.signal().ok_or_else(invalid)
    }
    fn running(&mut self) -> ProofResult<()> {
        if self.child.try_wait().map_err(|_| unavailable())?.is_some() {
            return Err(unavailable());
        }
        Ok(())
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        if !self.reaped {
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
            let _ = self.child.wait();
        }
    }
}

struct Receiver {
    process: Process,
    workspace: Arc<OwnedDirectory>,
    address: SocketAddr,
    token: String,
    engine: Option<Arc<OwnedDirectory>>,
}
impl Receiver {
    fn start(parent: &OwnedDirectory, programs: &RecoveryPrograms) -> ProofResult<Self> {
        let workspace = Arc::new(OwnedDirectory::create(
            parent.path(),
            Path::new("receiver"),
            EntityId::new(),
        )?);
        let token = format!(
            "{}{}",
            EntityId::new().to_string().replace('-', ""),
            EntityId::new().to_string().replace('-', "")
        );
        if let Err(error) = workspace.write_new(Path::new("receiver.token"), token.as_bytes()) {
            if workspace.open_readonly(Path::new("receiver.token")).is_ok() {
                remove_private(&workspace, "receiver.token")?;
            }
            return Err(error);
        }
        let mut command = Command::new(&programs.receiver);
        command.env_clear();
        command.args([
            OsString::from("--bind"),
            OsString::from("127.0.0.1:0"),
            OsString::from("--token-file"),
            workspace.path().join("receiver.token").into_os_string(),
            OsString::from("--state"),
            workspace.path().join("counter.sqlite3").into_os_string(),
        ]);
        let spawned: ProofResult<(Process, SocketAddr)> = (|| {
            let mut process = Process::spawn(&mut command)?;
            #[derive(Deserialize)]
            #[serde(deny_unknown_fields)]
            struct Ready {
                protocol: String,
                address: SocketAddr,
            }
            let ready: Ready = decode(&process.line()?)?;
            if ready.protocol != "razen.fixture-receiver/0.1.0" || !ready.address.ip().is_loopback()
            {
                return Err(invalid());
            }
            Ok((process, ready.address))
        })();
        let (process, address) = match spawned {
            Ok(result) => result,
            Err(error) => {
                remove_private(&workspace, "receiver.token")?;
                return Err(error);
            }
        };
        Ok(Self {
            process,
            workspace,
            address,
            token,
            engine: None,
        })
    }
    fn count(&mut self, action: EntityId) -> ProofResult<u64> {
        self.process.running()?;
        Ok(http(self.address, &self.token, "GET", action)?.0)
    }
    fn finish(&mut self, engine: &OwnedDirectory) -> ProofResult<()> {
        if self.process.kill()? != 9 {
            return Err(invalid());
        }
        remove_private(&self.workspace, "receiver.token")?;
        remove_private(engine, "recovery-config.json")
    }
}

fn worker(
    programs: &RecoveryPrograms,
    workspace: &OwnedDirectory,
    mode: &str,
) -> ProofResult<Process> {
    Process::spawn(
        Command::new(&programs.engine)
            .env_clear()
            .arg("--recovery-fixture")
            .arg("--directory")
            .arg(workspace.path())
            .arg("--mode")
            .arg(mode),
    )
}

fn scenario(
    parent: &OwnedDirectory,
    profile: &LoadedProfile,
    repo: &Path,
    programs: &RecoveryPrograms,
    seam: &str,
    name: &str,
    runtime_recovery: bool,
) -> ProofResult<(CrashScenario, Arc<OwnedDirectory>, Configuration, Receiver)> {
    let container = Arc::new(OwnedDirectory::create(
        parent.path(),
        Path::new(name),
        EntityId::new(),
    )?);
    let mut receiver = Receiver::start(&container, programs)?;
    let workspace = Arc::new(OwnedDirectory::create(
        container.path(),
        Path::new("engine"),
        EntityId::new(),
    )?);
    receiver.engine = Some(Arc::clone(&workspace));
    let config = initialize(
        &workspace,
        profile,
        &repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        hash_file(&programs.engine)?,
        receiver.address,
        receiver.token.clone(),
        runtime_recovery,
    )?;
    if config.runtime_recovery {
        return runtime_scenario(parent, profile, programs, workspace, config, receiver);
    }
    let receiver_before = receiver.count(config.action_id)?;
    let mut child = worker(programs, &workspace, seam)?;
    let message: WorkerMessage = decode(&child.line()?)?;
    if message.protocol != "razen.recovery-worker/0.1.0"
        || message.pid != child.child.id()
        || message.seam != seam
        || message.snapshot.is_some()
    {
        return Err(invalid());
    }
    let worker_pid = child.child.id();
    let worker_signal = child.kill()?;
    receiver.process.running()?;
    let receiver_after_kill = receiver.count(config.action_id)?;
    // SQLite performs genuine hot-journal recovery when required; no restored-state import.
    let ledger = Ledger::open(&workspace, profile)?;
    let before = snapshot(&ledger, &workspace, config.budget_id)?;
    drop(ledger);
    let mut restarted = worker(programs, &workspace, "restart")?;
    let restored: WorkerMessage = decode(&restarted.line()?)?;
    let restart_pid = restarted.child.id();
    if !restarted.wait()?.success()
        || restored.seam != "restarted"
        || restored.pid != restart_pid
        || restored.epoch == message.epoch
    {
        return Err(invalid());
    }
    let after = restored.snapshot.ok_or_else(invalid)?;
    let receiver_after_restart = receiver.count(config.action_id)?;
    let observed = CrashScenario {
        directory: workspace
            .path()
            .strip_prefix(parent.path())
            .map_err(|_| integrity())?
            .to_path_buf(),
        seam: seam.to_owned(),
        invocation_id: config.action_id,
        receiver_action_id: config.action_id,
        worker_pid,
        receiver_pid: receiver.process.child.id(),
        restart_pid,
        worker_signal,
        worker_epoch: message.epoch,
        restart_epoch: restored.epoch,
        receiver_before,
        receiver_after_kill,
        receiver_after_restart,
        before,
        after,
        baseline_invocation_id: config.baseline_id,
        reconcile_invocation_id: restored.reconcile_invocation_id.ok_or_else(invalid)?,
        runtime_admission: None,
    };
    Ok((observed, workspace, config, receiver))
}

pub fn run_fixture(
    parent: &Arc<OwnedDirectory>,
    profile: &LoadedProfile,
    repo: &Path,
    programs: &RecoveryPrograms,
    case_id: &CatalogId,
) -> ProofResult<RecoveryReport> {
    if !programs.engine.is_absolute() || !programs.receiver.is_absolute() {
        return Err(invalid());
    }
    let mut report = RecoveryReport {
        case_id: case_id.clone(),
        profile_sha256: profile.sha256(),
        fixture_sha256: hash_file(&repo.join("fixtures/scenarios/recovery.json"))?,
        engine_sha256: hash_file(&programs.engine)?,
        receiver_sha256: hash_file(&programs.receiver)?,
        scenarios: Vec::new(),
        channel_scenario: None,
        deliveries: Vec::new(),
        authority_attempts: Vec::new(),
        storage_faults: Vec::new(),
    };
    let seams: &[&str] = match case_id.as_str() {
        "REC-01" => &SEAMS[..2],
        "REC-02" => &SEAMS[2..4],
        "REC-03" => &SEAMS[4..],
        "REC-04" | "REC-05" => &SEAMS[2..3],
        _ => return Err(invalid()),
    };
    for (index, seam) in seams.iter().enumerate() {
        let (mut facts, workspace, config, mut receiver) = scenario(
            parent,
            profile,
            repo,
            programs,
            seam,
            &format!("crash-{index}"),
            false,
        )?;
        if case_id.as_str() == "REC-03" {
            let ledger = Ledger::open(&workspace, profile)?;
            let mut control = ledger.read_control(config.session.investigation_id)?;
            let previous = control.revision;
            control.revision = previous.checked_add(wire(1)?)?;
            control.mode = ControlMode::Paused;
            control.admission_open = false;
            ledger.transaction(|tx| tx.apply_control(&control, previous))?;
            facts.after = snapshot(&ledger, &workspace, config.budget_id)?;
            report.deliveries = event_deliveries(&facts.after)?;
        }
        if case_id.as_str() == "REC-04" {
            report.authority_attempts = authority_attempts(parent, profile, repo, programs)?;
        }
        if case_id.as_str() == "REC-05" {
            report.storage_faults = storage_faults(parent, profile, repo, programs)?;
        }
        receiver.process.running()?;
        let ledger = Ledger::open_readonly(&workspace, profile)?;
        if snapshot(&ledger, &workspace, config.budget_id)?.database_sha256
            != facts.after.database_sha256
        {
            return Err(integrity());
        }
        receiver.finish(&workspace)?;
        report.scenarios.push(facts);
    }
    if case_id.as_str() == "REC-03" {
        // Separate fixture run/project/budget/receiver: this proves channel epoch
        // denial in addition to, never instead of, the killed ledger-owning worker.
        let (channel, workspace, config, mut receiver) = scenario(
            parent,
            profile,
            repo,
            programs,
            "after_completion_commit",
            "channel-0",
            true,
        )?;
        receiver.process.running()?;
        let ledger = Ledger::open_readonly(&workspace, profile)?;
        if snapshot(&ledger, &workspace, config.budget_id)?.database_sha256
            != channel.after.database_sha256
        {
            return Err(integrity());
        }
        receiver.finish(&workspace)?;
        report.channel_scenario = Some(channel);
    }
    report.validate()?;
    verify_saved(parent, profile, &report)?;
    parent.write_new(Path::new("recovery-facts.json"), &encode(&report)?)?;
    Ok(report)
}

fn event_deliveries(state: &LedgerSnapshot) -> ProofResult<Vec<DeliveryFact>> {
    let mut consumer = EventConsumer::new(16_384)?;
    let revision = state.controls.first().ok_or_else(invalid)?.revision;
    let mut facts = Vec::with_capacity(state.events.len());
    for event in &state.events {
        let first = consumer.accept(event, revision)?;
        let second = consumer.accept(event, revision)?;
        facts.push(DeliveryFact {
            event: event.clone(),
            current_revision: revision,
            first: disposition(first).to_owned(),
            second: disposition(second).to_owned(),
        });
    }
    Ok(facts)
}
fn disposition(value: EventDisposition) -> &'static str {
    match value {
        EventDisposition::Accepted => "accepted",
        EventDisposition::Duplicate => "duplicate",
        EventDisposition::Late => "late",
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StorageWorkerResult {
    error: ProofError,
    admission_error: ProofError,
    sqlite_primary_code: Option<i32>,
    sqlite_extended_code: Option<i32>,
    page_limit: Option<u64>,
}

struct StorageWorkerContext<'a> {
    workspace: &'a OwnedDirectory,
    ledger: &'a Ledger,
    admission: &'a HostAdmission,
}

fn storage_worker(
    context: StorageWorkerContext<'_>,
    binding: &super::admission::TrustedBinding,
    prepared: &PreparedCall,
    config: &Configuration,
    mode: &str,
    epoch: EntityId,
) -> ProofResult<()> {
    let StorageWorkerContext {
        workspace,
        ledger,
        admission,
    } = context;
    admission.reserve(binding, prepared)?;
    let _permit = admission.begin_effect(binding, prepared.invocation_id)?;
    let page_limit = if mode == "storage_full" {
        Some(ledger.fixture_limit_pages()?)
    } else {
        workspace.write_new(
            Path::new("sync.arm"),
            b"exact owned database sync failure armed",
        )?;
        None
    };
    // Every attempted write goes through the actual admission transaction and its common
    // integrity latch. Repeated canonical proposals consume SQLite pages, not host disk.
    let mut failure = None;
    for _ in 0..4096 {
        let extra = call(
            config,
            POST,
            EntityId::new(),
            EntityId::new(),
            config.target_input,
            config.target_sha256,
            4,
        )?;
        match admission.propose(binding, &extra) {
            Ok(_) => {}
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    let error = failure.ok_or_else(invalid)?;
    let native = error.storage_fault();
    let sqlite_primary_code = native.map(|fault| fault.primary_code);
    let sqlite_extended_code = native.map(|fault| fault.extended_code);
    let extra = call(
        config,
        POST,
        EntityId::new(),
        EntityId::new(),
        config.target_input,
        config.target_sha256,
        4,
    )?;
    let admission_error = admission
        .reserve(binding, &extra)
        .err()
        .ok_or_else(invalid)?;
    let result = StorageWorkerResult {
        error,
        admission_error,
        sqlite_primary_code,
        sqlite_extended_code,
        page_limit,
    };
    workspace.write_new(Path::new("storage-result.json"), &encode(&result)?)?;
    emit(&WorkerMessage {
        protocol: "razen.recovery-worker/0.1.0".to_owned(),
        epoch,
        pid: std::process::id(),
        seam: "storage_fault_observed".to_owned(),
        snapshot: None,
        reconcile_invocation_id: None,
        lease: None,
    })
}

fn owned_sql(workspace: &OwnedDirectory) -> ProofResult<rusqlite::Connection> {
    // The controller calls this only with all ledger owners reaped/dropped, on its
    // exact private scenario database. No arbitrary SQL is accepted by worker argv.
    let guard = workspace.lock_directory()?;
    let metadata = std::fs::symlink_metadata(workspace.path().join("ledger.sqlite"))
        .map_err(|_| integrity())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(integrity());
    }
    let connection = rusqlite::Connection::open_with_flags(
        workspace.path().join("ledger.sqlite"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| integrity())?;
    drop(guard);
    Ok(connection)
}

fn authority_attempts(
    parent: &OwnedDirectory,
    profile: &LoadedProfile,
    repo: &Path,
    programs: &RecoveryPrograms,
) -> ProofResult<Vec<AuthorityAttempt>> {
    let mut attempts = Vec::new();
    for (index, kind) in [
        "scope",
        "grant_revoked",
        "grant_expired",
        "control",
        "identity",
        "contract_version",
    ]
    .into_iter()
    .enumerate()
    {
        let container = Arc::new(OwnedDirectory::create(
            parent.path(),
            Path::new(&format!("authority-{index}")),
            EntityId::new(),
        )?);
        let mut receiver = Receiver::start(&container, programs)?;
        let workspace = Arc::new(OwnedDirectory::create(
            container.path(),
            Path::new("engine"),
            EntityId::new(),
        )?);
        receiver.engine = Some(Arc::clone(&workspace));
        let mut config = initialize(
            &workspace,
            profile,
            &repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
            hash_file(&programs.engine)?,
            receiver.address,
            receiver.token.clone(),
            false,
        )?;
        let mut child = worker(programs, &workspace, "after_reservation_commit")?;
        let message: WorkerMessage = decode(&child.line()?)?;
        if message.seam != "after_reservation_commit" || child.kill()? != 9 {
            return Err(invalid());
        }
        let ledger = Arc::new(Ledger::open(&workspace, profile)?);
        let before = snapshot(&ledger, &workspace, config.budget_id)?;
        let receiver_before = receiver.count(config.action_id)?;
        match kind {
            "scope" => {
                let mut scope = config.scope.clone();
                scope.revision = scope.revision.checked_add(wire(1)?)?;
                scope.allowed_destinations.clear();
                ledger.replace_scope(&scope, config.scope.revision)?;
            }
            "grant_revoked" => {
                ledger.revoke_grant(
                    ledger
                        .read_invocation(config.action_id)?
                        .invocation
                        .grant_id
                        .ok_or_else(invalid)?,
                )?;
            }
            "grant_expired" => {
                let grant_id = ledger
                    .read_invocation(config.action_id)?
                    .invocation
                    .grant_id
                    .ok_or_else(invalid)?;
                let mut grant = ledger.read_grant(grant_id)?;
                grant.expires_at = AuditTime::parse("2000-01-01T00:00:00Z")?;
                drop(ledger);
                let connection = owned_sql(&workspace)?;
                connection
                    .execute(
                        "UPDATE grants SET data=?1 WHERE grant_id=?2",
                        rusqlite::params![encode(&grant)?, grant_id.to_string()],
                    )
                    .map_err(|_| integrity())?;
                drop(connection);
                let ledger = Arc::new(Ledger::open(&workspace, profile)?);
                let control = Arc::new(ControlService::new(
                    Arc::clone(&ledger),
                    profile,
                    config.session.investigation_id,
                )?);
                let admission = HostAdmission::new(Arc::clone(&ledger), control);
                let binding = admission.bind(spec(&config, POST)?)?;
                let error = admission
                    .begin_effect(&binding, config.action_id)
                    .err()
                    .ok_or_else(invalid)?;
                reconcile(&ledger)?;
                let after = snapshot(&ledger, &workspace, config.budget_id)?;
                attempts.push(AuthorityAttempt {
                    kind: kind.to_owned(),
                    directory: workspace
                        .path()
                        .strip_prefix(parent.path())
                        .map_err(|_| integrity())?
                        .to_path_buf(),
                    before,
                    after,
                    error,
                    receiver_before,
                    receiver_after: receiver.count(config.action_id)?,
                    current_engine_sha256: hash_file(&programs.engine)?,
                    current_identity: ledger.read_identity(config.identity.identity_id)?,
                });
                receiver.finish(&workspace)?;
                continue;
            }
            "control" => {
                let mut control = ledger.read_control(config.session.investigation_id)?;
                let previous = control.revision;
                control.revision = previous.checked_add(wire(1)?)?;
                control.mode = ControlMode::Paused;
                control.admission_open = false;
                ledger.transaction(|tx| tx.apply_control(&control, previous))?;
            }
            "identity" => {
                let mut identity = config.identity.clone();
                identity.identity_id = EntityId::new();
                ledger.insert_identity(&identity)?;
                config.identity = identity;
            }
            "contract_version" => {}
            _ => return Err(invalid()),
        }
        let control = Arc::new(ControlService::new(
            Arc::clone(&ledger),
            profile,
            config.session.investigation_id,
        )?);
        let admission = HostAdmission::new(Arc::clone(&ledger), control);
        let error = if kind == "contract_version" {
            // Actual strict current wire-version decoder rejects the restored request.
            // This is not represented as execution of a different production build.
            let mut value = serde_json::to_value(
                before
                    .invocations
                    .iter()
                    .find(|item| item.invocation_id == config.action_id)
                    .ok_or_else(invalid)?,
            )
            .map_err(|_| invalid())?;
            value["tool_version"] = json!("0.2.0");
            Invocation::parse_json(&encode(&value)?, None)
                .err()
                .ok_or_else(invalid)?
        } else {
            match admission.bind(spec(&config, POST)?) {
                Ok(binding) => admission
                    .begin_effect(&binding, config.action_id)
                    .err()
                    .ok_or_else(invalid)?,
                Err(error) => error,
            }
        };
        reconcile(&ledger)?;
        let after = snapshot(&ledger, &workspace, config.budget_id)?;
        attempts.push(AuthorityAttempt {
            kind: kind.to_owned(),
            directory: workspace
                .path()
                .strip_prefix(parent.path())
                .map_err(|_| integrity())?
                .to_path_buf(),
            before,
            after,
            error,
            receiver_before,
            receiver_after: receiver.count(config.action_id)?,
            current_engine_sha256: hash_file(&programs.engine)?,
            current_identity: ledger.read_identity(config.identity.identity_id)?,
        });
        receiver.finish(&workspace)?;
    }
    Ok(attempts)
}

fn storage_faults(
    parent: &OwnedDirectory,
    profile: &LoadedProfile,
    repo: &Path,
    programs: &RecoveryPrograms,
) -> ProofResult<Vec<StorageFaultFact>> {
    let mut facts = Vec::new();
    for (index, kind) in [
        "sqlite_full",
        "injected_sync_eio",
        "damaged_ledger",
        "incompatible_checkpoint",
    ]
    .into_iter()
    .enumerate()
    {
        let container = Arc::new(OwnedDirectory::create(
            parent.path(),
            Path::new(&format!("storage-{index}")),
            EntityId::new(),
        )?);
        let mut receiver = Receiver::start(&container, programs)?;
        let workspace = Arc::new(OwnedDirectory::create(
            container.path(),
            Path::new("engine"),
            EntityId::new(),
        )?);
        receiver.engine = Some(Arc::clone(&workspace));
        let config = initialize(
            &workspace,
            profile,
            &repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
            hash_file(&programs.engine)?,
            receiver.address,
            receiver.token.clone(),
            false,
        )?;
        let receiver_before = receiver.count(config.action_id)?;
        let ledger = Ledger::open(&workspace, profile)?;
        let before = snapshot(&ledger, &workspace, config.budget_id)?;
        drop(ledger);
        let bytes_before = hash_file(&workspace.path().join("ledger.sqlite"))?;
        if kind == "sqlite_full" || kind == "injected_sync_eio" {
            let mut command = Command::new(&programs.engine);
            command
                .env_clear()
                .arg("--recovery-fixture")
                .arg("--directory")
                .arg(workspace.path())
                .arg("--mode")
                .arg(if kind == "sqlite_full" {
                    "storage_full"
                } else {
                    "storage_sync"
                });
            let sync_fixture = if kind == "injected_sync_eio" {
                Some(prepared_sync_fixture(repo)?)
            } else {
                None
            };
            if kind == "injected_sync_eio" {
                let dylib = repo.join("target/r0-tools/storage-faults/sync_eio.dylib");
                // Explicit reviewed setup is mandatory. No build or silent substitution here.
                hash_file(&dylib)?;
                let manifest = repo.join("target/r0-tools/storage-faults/build-manifest.txt");
                hash_file(&manifest)?;
                workspace.write_new(Path::new("sync-telemetry.txt"), b"")?;
                let database = std::fs::symlink_metadata(workspace.path().join("ledger.sqlite"))
                    .map_err(|_| integrity())?;
                command
                    .env("DYLD_INSERT_LIBRARIES", dylib)
                    .env("RAZEN_SYNC_DEVICE", database.dev().to_string())
                    .env("RAZEN_SYNC_INODE", database.ino().to_string())
                    .env("RAZEN_SYNC_ARM", workspace.path().join("sync.arm"))
                    .env(
                        "RAZEN_SYNC_TELEMETRY",
                        workspace.path().join("sync-telemetry.txt"),
                    );
            }
            let mut child = Process::spawn(&mut command)?;
            let message: WorkerMessage = decode(&child.line()?)?;
            if message.seam != "storage_fault_observed" || !child.wait()?.success() {
                return Err(invalid());
            }
            let result: StorageWorkerResult =
                decode(&workspace.read(Path::new("storage-result.json"), 65_536)?)?;
            let telemetry = if kind == "injected_sync_eio" {
                String::from_utf8(workspace.read(Path::new("sync-telemetry.txt"), 4096)?)
                    .map_err(|_| invalid())?
            } else {
                String::new()
            };
            let reopened = Ledger::open(&workspace, profile)?;
            let after = snapshot(&reopened, &workspace, config.budget_id)?;
            let bytes_after = after.database_sha256;
            facts.push(StorageFaultFact {
                kind: kind.to_owned(),
                directory: workspace
                    .path()
                    .strip_prefix(parent.path())
                    .map_err(|_| integrity())?
                    .to_path_buf(),
                before,
                after: Some(after),
                error: Some(result.error),
                admission_error: Some(result.admission_error),
                sqlite_primary_code: result.sqlite_primary_code,
                sqlite_extended_code: result.sqlite_extended_code,
                telemetry,
                page_limit: result.page_limit,
                sync_fixture,
                bytes_before,
                bytes_after,
                receiver_before,
                receiver_after: receiver.count(config.action_id)?,
            });
        } else {
            let mut child = worker(programs, &workspace, "after_sending_commit")?;
            let message: WorkerMessage = decode(&child.line()?)?;
            if message.seam != "after_sending_commit" || child.kill()? != 9 {
                return Err(invalid());
            }
            let ledger = Ledger::open(&workspace, profile)?;
            let before = snapshot(&ledger, &workspace, config.budget_id)?;
            let bytes_before = before.database_sha256;
            drop(ledger);
            if kind == "damaged_ledger" {
                let fd = rustix::fs::open(
                    workspace.path().join("ledger.sqlite"),
                    rustix::fs::OFlags::WRONLY
                        | rustix::fs::OFlags::NOFOLLOW
                        | rustix::fs::OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                )
                .map_err(|_| integrity())?;
                let mut file = std::fs::File::from(fd);
                file.write_all(b"R0 controlled damaged SQLite header")
                    .map_err(|_| integrity())?;
                file.sync_all().map_err(|_| integrity())?;
            } else {
                let connection = owned_sql(&workspace)?;
                let (position, bytes): (i64, Vec<u8>) = connection
                    .query_row(
                        "SELECT position,data FROM checkpoints ORDER BY position DESC LIMIT 1",
                        [],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .map_err(|_| integrity())?;
                let mut checkpoint: Value = decode(&bytes)?;
                checkpoint["schema_version"] = json!("0.2.0");
                connection
                    .execute(
                        "UPDATE checkpoints SET data=?1 WHERE position=?2",
                        rusqlite::params![encode(&checkpoint)?, position],
                    )
                    .map_err(|_| integrity())?;
            }
            let bytes_after = hash_file(&workspace.path().join("ledger.sqlite"))?;
            let error = Ledger::open(&workspace, profile)
                .err()
                .ok_or_else(invalid)?;
            let admission_error = Ledger::open(&workspace, profile)
                .err()
                .ok_or_else(invalid)?;
            if hash_file(&workspace.path().join("ledger.sqlite"))? != bytes_after {
                return Err(integrity());
            }
            facts.push(StorageFaultFact {
                kind: kind.to_owned(),
                directory: workspace
                    .path()
                    .strip_prefix(parent.path())
                    .map_err(|_| integrity())?
                    .to_path_buf(),
                before,
                after: None,
                error: Some(error),
                admission_error: Some(admission_error),
                sqlite_primary_code: None,
                sqlite_extended_code: None,
                telemetry: String::new(),
                page_limit: None,
                sync_fixture: None,
                bytes_before,
                bytes_after,
                receiver_before,
                receiver_after: receiver.count(config.action_id)?,
            });
        }
        receiver.finish(&workspace)?;
    }
    Ok(facts)
}

fn validate_runtime_recovery(scenario: &CrashScenario) -> ProofResult<()> {
    let fact = scenario.runtime_admission.as_ref().ok_or_else(invalid)?;
    let before = encode(&fact.before)?;
    if fact.original_message != fact.submitted_message
        || fact.original_lease != fact.submitted_lease
        || fact.original_lease.state != LeaseState::Active
        || fact.original_lease.invocation_id != scenario.invocation_id
        || fact.original_lease.owner_binding_id == fact.current_binding_id
        || fact.original_lease.control_revision != fact.current_control_revision
        || fact.error.code != ErrorCode::PermissionDenied
        || fact.error != fact.authority_error
        || before != encode(&fact.after)?
        || before != encode(&scenario.before)?
        || fact.receiver_before != 1
        || fact.receiver_after != 1
        || fact.receiver_after_healthy != 1
        || scenario.receiver_after_kill != 1
        || scenario.receiver_after_restart != 1
        || fact.healthy_invocation_id != scenario.reconcile_invocation_id
    {
        return Err(invalid());
    }
    validate_snapshot(&fact.before)?;
    validate_snapshot(&fact.after)?;
    let target = scenario
        .before
        .invocations
        .iter()
        .find(|item| item.invocation_id == scenario.invocation_id)
        .ok_or_else(invalid)?;
    let healthy = scenario
        .after
        .invocations
        .iter()
        .find(|item| item.invocation_id == fact.healthy_invocation_id)
        .ok_or_else(invalid)?;
    if target.tool_id.as_str() != "http.send"
        || target.state != InvocationState::Completed
        || target.actor_ref != fact.original_lease.owner_binding_id
        || target.control_revision != fact.current_control_revision
        || scenario.before.session.control_revision != fact.current_control_revision
        || healthy.tool_id.as_str() != "http.send"
        || healthy.actor_ref != fact.current_binding_id
        || healthy.state != InvocationState::Completed
        || healthy.error.is_some()
        || healthy.usage.units == WireInt::ZERO
        || healthy.usage.bytes == WireInt::ZERO
        || healthy.usage.cpu_us == WireInt::ZERO
        || healthy.output_ref.is_none()
        || healthy.control_revision != fact.current_control_revision
        || scenario.after.budget.consumed
            != scenario
                .before
                .budget
                .consumed
                .checked_add(healthy.usage.units)?
        || scenario.before.budget.limit != scenario.after.budget.limit
        || scenario.before.budget.parent_budget_id != scenario.after.budget.parent_budget_id
        || scenario.before.budget.reserved != scenario.after.budget.reserved
        || scenario.before.project != scenario.after.project
        || scenario.before.scope != scenario.after.scope
        || scenario.before.identities != scenario.after.identities
        || scenario.before.tools != scenario.after.tools
    {
        return Err(invalid());
    }
    for (index, original) in scenario.before.invocations.iter().enumerate() {
        let after_index = scenario
            .after
            .invocations
            .iter()
            .position(|item| item.invocation_id == original.invocation_id)
            .ok_or_else(invalid)?;
        if scenario.after.invocations[after_index] != *original
            || scenario.after.histories.get(after_index) != scenario.before.histories.get(index)
        {
            return Err(invalid());
        }
    }
    if scenario.after.invocations.iter().any(|item| {
        item.invocation_id != healthy.invocation_id
            && !scenario
                .before
                .invocations
                .iter()
                .any(|original| original.invocation_id == item.invocation_id)
    }) {
        return Err(invalid());
    }
    for grant in &scenario.before.grants {
        if !scenario.after.grants.contains(grant) {
            return Err(invalid());
        }
    }
    if scenario.after.grants.iter().any(|grant| {
        !scenario.before.grants.contains(grant) && Some(grant.grant_id) != healthy.grant_id
    }) {
        return Err(invalid());
    }
    let original = decode_frame(
        &fact.original_message,
        65_536,
        ChannelRole::Runtime,
        Direction::PeerToHost,
    )?;
    let message_id = original.message_id;
    let Message::ToolRequest(request) = original.into_message() else {
        return Err(invalid());
    };
    let fresh = decode_frame(
        &fact.healthy_message,
        65_536,
        ChannelRole::Runtime,
        Direction::PeerToHost,
    )?;
    let Message::ToolRequest(fresh) = fresh.into_message() else {
        return Err(invalid());
    };
    if request.call_id != target.causation_id
        || request.tool_id != target.tool_id
        || request.tool_version != target.tool_version
        || request.source_control_revision != fact.current_control_revision
        || fresh.call_id == request.call_id
        || fresh.call_id != healthy.causation_id
        || fresh.tool_id != healthy.tool_id
        || fresh.source_control_revision != fact.current_control_revision
    {
        return Err(invalid());
    }
    let reply = decode_frame(
        &fact.original_reply,
        65_536,
        ChannelRole::Runtime,
        Direction::HostToPeer,
    )?;
    if reply.correlation_id != Some(message_id) {
        return Err(invalid());
    }
    let Message::ToolResult(reply) = reply.into_message() else {
        return Err(invalid());
    };
    if reply.call_id != request.call_id
        || reply.invocation_id != target.invocation_id
        || reply.state != target.state
        || reply.usage != target.usage
        || reply.output_ref != target.output_ref
        || reply.error != target.error
    {
        return Err(invalid());
    }
    Ok(())
}

fn verify_runtime_requests(
    workspace: &Arc<OwnedDirectory>,
    scenario: &CrashScenario,
) -> ProofResult<()> {
    use crate::domain::evidence::Representation;
    let fact = scenario.runtime_admission.as_ref().ok_or_else(integrity)?;
    let evidence = EvidenceStore::open_readonly(Arc::clone(workspace))?;
    for (frame, invocation_id, method) in [
        (&fact.original_message, scenario.invocation_id, "POST"),
        (&fact.healthy_message, fact.healthy_invocation_id, "GET"),
    ] {
        let decoded = decode_frame(frame, 65_536, ChannelRole::Runtime, Direction::PeerToHost)?;
        let Message::ToolRequest(request) = decoded.into_message() else {
            return Err(integrity());
        };
        let input: HttpSendInput =
            serde_json::from_str(request.input.get()).map_err(|_| integrity())?;
        let invocation = scenario
            .after
            .invocations
            .iter()
            .find(|item| item.invocation_id == invocation_id)
            .ok_or_else(integrity)?;
        if input.identity_id != invocation.identity_id
            || input.base_revision != invocation.input_revision
        {
            return Err(integrity());
        }
        let descriptor = evidence.snapshot(
            invocation.project_id,
            input.request_snapshot_id,
            input.base_revision,
        )?;
        let bytes = evidence.read_artifact(invocation.project_id, descriptor.body_ref, 65_536)?;
        let descriptor_request: RequestSnapshot = decode(&bytes)?;
        let body = evidence.snapshot(
            invocation.project_id,
            descriptor_request.body_snapshot_id,
            descriptor_request.body_revision,
        )?;
        let body_bytes = evidence.read_artifact(invocation.project_id, body.body_ref, 65_536)?;
        let url = url::Url::parse(&descriptor_request.url).map_err(|_| integrity())?;
        let port = url.port().ok_or_else(integrity)?;
        if descriptor.representation != Representation::RawBody
            || descriptor.truncated
            || descriptor.sha256 != Digest::of(&bytes)
            || descriptor.derived_from != Some(body.snapshot_id)
            || bytes != encode(&descriptor_request)?
            || !body_bytes.is_empty()
            || body.truncated
            || body.sha256 != Digest::of(&body_bytes)
            || descriptor_request.method != method
            || descriptor_request.request_count.get() != 1
            || descriptor_request.reset_first_stream
            || url.scheme() != "http"
            || url.host_str() != Some("127.0.0.1")
            || url.path()
                != format!(
                    "/{}/{}",
                    if method == "POST" { "effect" } else { "count" },
                    scenario.receiver_action_id
                )
            || descriptor_request.headers.len() != 1
            || !descriptor_request.headers[0]
                .name
                .eq_ignore_ascii_case("host")
            || descriptor_request.headers[0].value != format!("127.0.0.1:{port}")
        {
            return Err(integrity());
        }
        let prepared: Value = decode(&evidence.read_artifact(
            invocation.project_id,
            invocation.input_ref,
            65_536,
        )?)?;
        if prepared.get("input") != Some(&serde_json::to_value(&input).map_err(|_| integrity())?)
            || prepared.get("request")
                != Some(&serde_json::to_value(&descriptor_request).map_err(|_| integrity())?)
            || prepared.get("request_snapshot_sha256") != Some(&json!(descriptor.sha256))
            || prepared.get("body_snapshot_sha256") != Some(&json!(body.sha256))
        {
            return Err(integrity());
        }
        let output: http_send::HttpSendOutput = decode(&evidence.read_artifact(
            invocation.project_id,
            invocation.output_ref.ok_or_else(integrity)?,
            65_536,
        )?)?;
        for id in [output.exchange_ref, output.timing_ref] {
            let artifact = evidence.artifact(invocation.project_id, id)?;
            evidence.verify_artifact(invocation.project_id, id)?;
            if artifact.origin_invocation_id != invocation_id {
                return Err(integrity());
            }
        }
        let record: http_send::SendRecord =
            decode(&evidence.read_artifact(invocation.project_id, output.exchange_ref, 65_536)?)?;
        let timing: http_send::HttpSendTiming =
            decode(&evidence.read_artifact(invocation.project_id, output.timing_ref, 65_536)?)?;
        let exchange = record.exchanges.first().ok_or_else(integrity)?;
        if record.invocation_id != invocation_id
            || record.project_id != invocation.project_id
            || record.input_snapshot_id != descriptor_request.body_snapshot_id
            || record.input_revision != descriptor_request.body_revision
            || record.mode != crate::adapters::transport::Mode::Http1Forward
            || record.exchanges.len() != 1
            || !record.stream_errors.is_empty()
            || !record.partial_captures.is_empty()
            || !record.redirect_chain.is_empty()
            || record.connections.is_empty()
            || record.connections.iter().any(|connection| {
                !connection.connected_peer.ip().is_loopback()
                    || connection.connected_peer.port() != port
                    || connection.url != descriptor_request.url
            })
            || exchange.status != 200
            || exchange.response_capture.truncated
            || exchange.request_body_sha256 != body.sha256
            || exchange.response_snapshot_id != output.response_snapshot_ref
            || timing.finished_us < timing.started_us
            || timing.network_elapsed_us != record.network_elapsed_us
        {
            return Err(integrity());
        }
        let response = evidence.snapshot(
            invocation.project_id,
            output.response_snapshot_ref.ok_or_else(integrity)?,
            WireInt::ZERO,
        )?;
        let response_bytes =
            evidence.read_artifact(invocation.project_id, response.body_ref, 65_536)?;
        let count: Value = decode(&response_bytes)?;
        if response.truncated
            || response.sha256 != Digest::of(&response_bytes)
            || response.sha256 != exchange.response_body_sha256
            || count.get("action_id") != Some(&json!(scenario.receiver_action_id))
            || count.get("count") != Some(&json!(1))
        {
            return Err(integrity());
        }
    }
    Ok(())
}

impl RecoveryReport {
    /// Derive invariants from factual snapshots, never trust a serialized pass map.
    pub fn validate(&self) -> ProofResult<()> {
        let expected: &[&str] = match self.case_id.as_str() {
            "REC-01" => &SEAMS[..2],
            "REC-02" => &SEAMS[2..4],
            "REC-03" => &SEAMS[4..],
            "REC-04" | "REC-05" => &SEAMS[2..3],
            _ => return Err(invalid()),
        };
        if self.scenarios.len() != expected.len() {
            return Err(invalid());
        }
        if self.case_id.as_str() != "REC-03" && self.channel_scenario.is_some() {
            return Err(invalid());
        }
        for (scenario, seam) in self.scenarios.iter().zip(expected) {
            if scenario.seam != *seam
                || scenario.worker_signal != 9
                || scenario.worker_pid == 0
                || scenario.receiver_pid == 0
                || scenario.worker_pid == scenario.receiver_pid
                || scenario.restart_pid == scenario.receiver_pid
                || scenario.worker_epoch == scenario.restart_epoch
                || scenario.receiver_before != 0
                || scenario.receiver_after_kill != scenario.receiver_after_restart
                || scenario.before.run_id != scenario.after.run_id
                || scenario.before.budget.budget_id != scenario.after.budget.budget_id
            {
                return Err(invalid());
            }
            if scenario.runtime_admission.is_some()
                || scenario.before.budget.consumed != scenario.after.budget.consumed
            {
                return Err(invalid());
            }
            validate_snapshot(&scenario.before)?;
            validate_snapshot(&scenario.after)?;
            let baseline_before = scenario
                .before
                .invocations
                .iter()
                .find(|item| item.invocation_id == scenario.baseline_invocation_id)
                .ok_or_else(invalid)?;
            let baseline_after = scenario
                .after
                .invocations
                .iter()
                .find(|item| item.invocation_id == scenario.baseline_invocation_id)
                .ok_or_else(invalid)?;
            if baseline_before != baseline_after
                || baseline_before.state != InvocationState::Completed
                || baseline_before.usage.units.get() != 1
                || baseline_before.usage.bytes == WireInt::ZERO
                || baseline_before.usage.cpu_us == WireInt::ZERO
                || baseline_before.output_ref.is_none()
            {
                return Err(invalid());
            }
            let target = scenario
                .after
                .invocations
                .iter()
                .find(|item| item.invocation_id == scenario.invocation_id);
            match *seam {
                "before_reservation_commit" => {
                    if target.is_some()
                        || scenario.after.budget.reserved != WireInt::ZERO
                        || scenario.receiver_after_restart != 0
                    {
                        return Err(invalid());
                    }
                }
                "after_reservation_commit" => {
                    let target = target.ok_or_else(invalid)?;
                    if target.state != InvocationState::Cancelled
                        || target.grant_id.is_none()
                        || scenario.after.budget.reserved != WireInt::ZERO
                        || scenario.receiver_after_restart != 0
                    {
                        return Err(invalid());
                    }
                }
                "after_sending_commit" | "after_receiver_increment" => {
                    let target = target.ok_or_else(invalid)?;
                    if target.state != InvocationState::OutcomeUnknown
                        || target.usage.units != WireInt::ZERO
                        || scenario
                            .after
                            .reservations
                            .get(&target.invocation_id)
                            .copied()
                            != Some(wire(4)?)
                        || scenario.after.budget.reserved.get() != 4
                        || scenario.receiver_after_restart
                            != u64::from(*seam == "after_receiver_increment")
                    {
                        return Err(invalid());
                    }
                }
                "after_completion_commit" => {
                    let target = target.ok_or_else(invalid)?;
                    if target.state != InvocationState::Completed
                        || target.output_ref.is_none()
                        || scenario.receiver_after_restart != 1
                        || scenario.after.budget.reserved != WireInt::ZERO
                    {
                        return Err(invalid());
                    }
                }
                _ => return Err(invalid()),
            }
            let read = scenario
                .after
                .invocations
                .iter()
                .find(|item| item.invocation_id == scenario.reconcile_invocation_id)
                .ok_or_else(invalid)?;
            if read.tool_id.as_str() != GET
                || read.state != InvocationState::Completed
                || read.usage.units != WireInt::ZERO
                || read.output_ref.is_none()
                || read.grant_id.is_none()
            {
                return Err(invalid());
            }
        }
        if self.case_id.as_str() == "REC-03" {
            let primary = self.scenarios.first().ok_or_else(invalid)?;
            let channel = self.channel_scenario.as_ref().ok_or_else(invalid)?;
            if channel.directory != *"channel-0/engine"
                || channel.seam != "after_completion_commit"
                || channel.worker_signal != 9
                || channel.worker_pid == 0
                || channel.restart_pid == 0
                || channel.receiver_pid == 0
                || channel.worker_pid == channel.receiver_pid
                || channel.restart_pid == channel.receiver_pid
                || channel.worker_epoch == channel.restart_epoch
                || channel.receiver_before != 0
                || channel.before.run_id != channel.after.run_id
                || channel.before.budget.budget_id != channel.after.budget.budget_id
                || channel.before.run_id == primary.before.run_id
                || channel.before.project.project_id == primary.before.project.project_id
                || channel.before.scope.scope_policy_id == primary.before.scope.scope_policy_id
                || channel.before.session.investigation_id
                    == primary.before.session.investigation_id
                || channel.before.budget.budget_id == primary.before.budget.budget_id
                || channel.invocation_id == primary.invocation_id
                || channel.receiver_action_id == primary.receiver_action_id
            {
                return Err(invalid());
            }
            validate_snapshot(&channel.before)?;
            validate_snapshot(&channel.after)?;
            validate_runtime_recovery(channel)?;
            let state = &self.scenarios.first().ok_or_else(invalid)?.after;
            if self.deliveries.len() != state.events.len() || self.deliveries.is_empty() {
                return Err(invalid());
            }
            let actual_revision = state.controls.first().ok_or_else(invalid)?.revision;
            let mut consumer = EventConsumer::new(16_384)?;
            for (delivery, actual_event) in self.deliveries.iter().zip(&state.events) {
                if delivery.event != *actual_event || delivery.current_revision != actual_revision {
                    return Err(invalid());
                }
                if disposition(consumer.accept(&delivery.event, delivery.current_revision)?)
                    != delivery.first
                    || disposition(consumer.accept(&delivery.event, delivery.current_revision)?)
                        != delivery.second
                    || delivery.first
                        != if delivery
                            .event
                            .control_revision
                            .is_some_and(|revision| revision < delivery.current_revision)
                        {
                            "late"
                        } else {
                            "accepted"
                        }
                    || delivery.second != "duplicate"
                {
                    return Err(invalid());
                }
            }
        }
        if self.case_id.as_str() == "REC-04" {
            let expected = [
                "scope",
                "grant_revoked",
                "grant_expired",
                "control",
                "identity",
                "contract_version",
            ];
            if self.authority_attempts.len() != expected.len() {
                return Err(invalid());
            }
            for (attempt, kind) in self.authority_attempts.iter().zip(expected) {
                validate_snapshot(&attempt.before)?;
                validate_snapshot(&attempt.after)?;
                if attempt.kind != kind
                    || attempt.receiver_before != 0
                    || attempt.receiver_after != 0
                    || attempt.before.run_id != attempt.after.run_id
                    || attempt.before.budget.consumed != attempt.after.budget.consumed
                    || attempt
                        .after
                        .invocations
                        .iter()
                        .any(|item| item.state == InvocationState::Sending)
                    || attempt.current_engine_sha256 != self.engine_sha256
                {
                    return Err(invalid());
                }
                let original = attempt
                    .before
                    .invocations
                    .iter()
                    .find(|item| item.tool_id.as_str() == POST)
                    .ok_or_else(invalid)?;
                if original.state != InvocationState::Reserved
                    || attempt.after.budget.reserved != WireInt::ZERO
                {
                    return Err(invalid());
                }
                let grant = attempt
                    .after
                    .grants
                    .iter()
                    .find(|grant| Some(grant.grant_id) == original.grant_id)
                    .ok_or_else(invalid)?;
                match kind {
                    "scope"
                        if attempt.after.scope.revision > attempt.before.scope.revision
                            && attempt.after.scope.allowed_destinations.is_empty()
                            && attempt.error.code == ErrorCode::PermissionDenied => {}
                    "grant_revoked"
                        if grant.revoked && attempt.error.code == ErrorCode::PermissionDenied => {}
                    "grant_expired"
                        if attempt.before.events.iter().any(|event| {
                            event.aggregate_id == original.invocation_id
                                && grant.expires_at < event.timestamp
                        }) && attempt.error.code == ErrorCode::PermissionDenied => {}
                    "control"
                        if attempt.after.controls.iter().any(|control| {
                            control.mode == ControlMode::Paused && !control.admission_open
                        }) && attempt.error.code == ErrorCode::Cancelled => {}
                    "identity"
                        if attempt.current_identity.identity_id != original.identity_id
                            && attempt.current_identity.project_id == original.project_id
                            && attempt.error.code == ErrorCode::PermissionDenied => {}
                    "contract_version" if attempt.error.code == ErrorCode::InvalidInput => {}
                    _ => return Err(invalid()),
                }
            }
        }
        if self.case_id.as_str() == "REC-05" {
            let expected = [
                "sqlite_full",
                "injected_sync_eio",
                "damaged_ledger",
                "incompatible_checkpoint",
            ];
            if self.storage_faults.len() != expected.len() {
                return Err(invalid());
            }
            for (fault, kind) in self.storage_faults.iter().zip(expected) {
                validate_snapshot(&fault.before)?;
                if fault.bytes_before != fault.before.database_sha256 {
                    return Err(invalid());
                }
                if fault.kind != kind
                    || fault
                        .error
                        .as_ref()
                        .is_none_or(|error| error.code != ErrorCode::IntegrityError)
                    || fault
                        .admission_error
                        .as_ref()
                        .is_none_or(|error| error.code != ErrorCode::IntegrityError)
                    || fault.receiver_before != 0
                    || fault.receiver_after != 0
                {
                    return Err(invalid());
                }
                if kind == "sqlite_full" && fault.sqlite_primary_code != Some(13) {
                    return Err(invalid());
                }
                if kind == "sqlite_full" && fault.page_limit.is_none_or(|limit| limit == 0) {
                    return Err(invalid());
                }
                if kind == "injected_sync_eio" {
                    validate_sync_fixture(fault.sync_fixture.as_ref().ok_or_else(invalid)?)?;
                }
                if kind == "injected_sync_eio"
                    && (fault.sqlite_primary_code != Some(10)
                        || fault.telemetry.is_empty()
                        || !fault
                            .telemetry
                            .lines()
                            .all(|line| line == "fsync:EIO" || line == "F_FULLFSYNC:EIO"))
                {
                    return Err(invalid());
                }
                if let Some(after) = &fault.after {
                    validate_snapshot(after)?;
                    if fault.bytes_after != after.database_sha256 {
                        return Err(invalid());
                    }
                    if fault.before.budget.consumed != after.budget.consumed
                        || after.budget.reserved.get() != 4
                        || !after
                            .invocations
                            .iter()
                            .any(|item| item.state == InvocationState::Sending)
                    {
                        return Err(invalid());
                    }
                } else if fault.bytes_before == fault.bytes_after {
                    return Err(invalid());
                }
            }
        }
        Ok(())
    }
}

fn validate_snapshot(state: &LedgerSnapshot) -> ProofResult<()> {
    state.budget.validate()?;
    if state.project.scope_policy_id != state.scope.scope_policy_id
        || state.scope.project_id != state.project.project_id
        || state.session.user_id != state.project.user_id
        || !state.controls.iter().any(|control| {
            control.investigation_id == state.session.investigation_id
                && control.revision == state.session.control_revision
        })
    {
        return Err(invalid());
    }
    if state.invocations.len() != state.histories.len()
        || state.reservations.len() != state.invocations.len()
    {
        return Err(invalid());
    }
    let mut held = WireInt::ZERO;
    let mut consumed = WireInt::ZERO;
    for (invocation, history) in state.invocations.iter().zip(&state.histories) {
        let history =
            crate::domain::invocation::InvocationHistory::restore_json(&encode(history)?)?;
        invocation.validate(Some(&history))?;
        if history.last() != invocation
            || invocation.run_id != state.run_id
            || invocation.budget_id != state.budget.budget_id
        {
            return Err(invalid());
        }
        if invocation.project_id != state.project.project_id
            || invocation.session_id != state.session.session_id
            || invocation.investigation_id != state.session.investigation_id
            || invocation.scope_revision > state.scope.revision
            || !state.identities.iter().any(|identity| {
                identity.identity_id == invocation.identity_id
                    && identity.project_id == invocation.project_id
            })
            || !state.tools.iter().any(|tool| {
                tool.descriptor.tool_id == invocation.tool_id
                    && tool.descriptor.version == invocation.tool_version
                    && tool.provider_digest == invocation.provider_digest
            })
        {
            return Err(invalid());
        }
        held = held.checked_add(
            *state
                .reservations
                .get(&invocation.invocation_id)
                .ok_or_else(invalid)?,
        )?;
        if matches!(
            invocation.state,
            InvocationState::Completed | InvocationState::Failed
        ) {
            consumed = consumed.checked_add(invocation.usage.units)?;
        }
    }
    if held != state.budget.reserved || consumed != state.budget.consumed {
        return Err(invalid());
    }
    let mut consumer = EventConsumer::new(16_384)?;
    let revision = state
        .controls
        .iter()
        .map(|item| item.revision)
        .max()
        .unwrap_or(WireInt::ZERO);
    for event in &state.events {
        consumer.accept(event, revision)?;
    }
    Ok(())
}

/// Quiescent factual inspection for packet verification; never starts a provider/process.
pub fn verify_saved(
    parent: &OwnedDirectory,
    profile: &LoadedProfile,
    report: &RecoveryReport,
) -> ProofResult<()> {
    report.validate()?;
    let scenarios = report
        .scenarios
        .iter()
        .enumerate()
        .map(|(index, scenario)| (PathBuf::from(format!("crash-{index}/engine")), scenario))
        .chain(
            report
                .channel_scenario
                .iter()
                .map(|scenario| (PathBuf::from("channel-0/engine"), scenario)),
        );
    for (expected_directory, scenario) in scenarios {
        if scenario.directory != expected_directory {
            return Err(integrity());
        }
        let workspace = Arc::new(OwnedDirectory::open(parent.path(), &scenario.directory)?);
        let ledger = Ledger::open_readonly(&workspace, profile)?;
        let actual = snapshot(&ledger, &workspace, scenario.after.budget.budget_id)?;
        if encode(&actual)? != encode(&scenario.after)? {
            return Err(integrity());
        }
        if let Some(fact) = &scenario.runtime_admission {
            let saved: RuntimeRecoveryFact =
                decode(&workspace.read(Path::new("runtime-admission.json"), MAX_FACTS)?)?;
            let lease: Lease = decode(&workspace.read(Path::new("worker-lease.json"), 65_536)?)?;
            let epoch: EntityId = decode(&workspace.read(Path::new("worker-epoch.json"), 1024)?)?;
            let barrier: WorkerMessage =
                decode(&workspace.read(Path::new("worker-barrier.json"), 65_536)?)?;
            if encode(&saved)? != encode(fact)?
                || lease != fact.original_lease
                || epoch != scenario.worker_epoch
                || workspace.read(Path::new("runtime-request.json"), 65_536)?
                    != fact.original_message
                || workspace.read(Path::new("runtime-reply.json"), 65_536)? != fact.original_reply
                || barrier.protocol != "razen.recovery-worker/0.1.0"
                || barrier.snapshot.is_some()
                || barrier.reconcile_invocation_id.is_some()
                || barrier.lease.as_ref() != Some(&lease)
                || barrier.pid != scenario.worker_pid
                || barrier.epoch != epoch
                || barrier.seam != scenario.seam
            {
                return Err(integrity());
            }
            verify_runtime_requests(&workspace, scenario)?;
        }
        verify_receiver(
            parent,
            &scenario.directory,
            scenario.receiver_action_id,
            scenario.receiver_after_restart,
        )?;
        verify_evidence(Arc::clone(&workspace), &actual)?;
    }
    for (index, attempt) in report.authority_attempts.iter().enumerate() {
        if attempt.directory != format!("authority-{index}/engine") {
            return Err(integrity());
        }
        let workspace = OwnedDirectory::open(parent.path(), &attempt.directory)?;
        let ledger = Ledger::open_readonly(&workspace, profile)?;
        if encode(&snapshot(
            &ledger,
            &workspace,
            attempt.after.budget.budget_id,
        )?)? != encode(&attempt.after)?
        {
            return Err(integrity());
        }
        if ledger.read_identity(attempt.current_identity.identity_id)? != attempt.current_identity {
            return Err(integrity());
        }
        let action = attempt
            .before
            .invocations
            .iter()
            .find(|item| item.tool_id.as_str() == POST)
            .ok_or_else(invalid)?
            .invocation_id;
        verify_receiver(parent, &attempt.directory, action, attempt.receiver_after)?;
    }
    for (index, fault) in report.storage_faults.iter().enumerate() {
        if fault.directory != format!("storage-{index}/engine") {
            return Err(integrity());
        }
        let workspace = OwnedDirectory::open(parent.path(), &fault.directory)?;
        let state = fault.after.as_ref().unwrap_or(&fault.before);
        let action = state
            .invocations
            .iter()
            .find(|item| item.tool_id.as_str() == POST && item.state == InvocationState::Sending)
            .ok_or_else(invalid)?
            .invocation_id;
        verify_receiver(parent, &fault.directory, action, fault.receiver_after)?;
        if let Some(after) = &fault.after {
            let saved: StorageWorkerResult =
                decode(&workspace.read(Path::new("storage-result.json"), 65_536)?)?;
            if saved.sqlite_primary_code != fault.sqlite_primary_code
                || saved.sqlite_extended_code != fault.sqlite_extended_code
                || saved.page_limit != fault.page_limit
                || fault.error.as_ref() != Some(&saved.error)
                || fault.admission_error.as_ref() != Some(&saved.admission_error)
            {
                return Err(integrity());
            }
            if fault.kind == "injected_sync_eio"
                && workspace.read(Path::new("sync-telemetry.txt"), 4096)?
                    != fault.telemetry.as_bytes()
            {
                return Err(integrity());
            }
            let ledger = Ledger::open_readonly(&workspace, profile)?;
            if encode(&snapshot(&ledger, &workspace, after.budget.budget_id)?)? != encode(after)? {
                return Err(integrity());
            }
        } else if hash_file(&workspace.path().join("ledger.sqlite"))? != fault.bytes_after
            || Ledger::open_readonly(&workspace, profile).is_ok()
        {
            return Err(integrity());
        }
    }
    Ok(())
}

fn verify_evidence(workspace: Arc<OwnedDirectory>, state: &LedgerSnapshot) -> ProofResult<()> {
    let evidence = EvidenceStore::open_readonly(workspace)?;
    for invocation in &state.invocations {
        evidence.verify_artifact(invocation.project_id, invocation.input_ref)?;
        let input = evidence.artifact(invocation.project_id, invocation.input_ref)?;
        if input.sha256 != invocation.input_sha256 {
            return Err(integrity());
        }
        if invocation.tool_id.as_str() == GET {
            let request: Value = decode(&evidence.read_artifact(
                invocation.project_id,
                invocation.input_ref,
                65_536,
            )?)?;
            if request.get("method").and_then(Value::as_str) != Some("GET")
                || request.get("purpose").and_then(Value::as_str)
                    != Some("read-only outcome reconciliation")
            {
                return Err(integrity());
            }
        }
        if let Some(output) = invocation.output_ref {
            evidence.verify_artifact(invocation.project_id, output)?;
            let artifact = evidence.artifact(invocation.project_id, output)?;
            if artifact.origin_invocation_id != invocation.invocation_id {
                return Err(integrity());
            }
        }
    }
    Ok(())
}

fn remove_private(workspace: &OwnedDirectory, name: &str) -> ProofResult<()> {
    let guard = workspace.lock_directory()?;
    let file = std::fs::File::from(
        rustix::fs::openat(
            &guard,
            name,
            rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::empty(),
        )
        .map_err(|_| integrity())?,
    );
    let metadata = file.metadata().map_err(|_| integrity())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o777 != 0o600
    {
        return Err(integrity());
    }
    rustix::fs::unlinkat(&guard, name, rustix::fs::AtFlags::empty()).map_err(|_| integrity())?;
    guard.sync_all().map_err(|_| integrity())
}

fn verify_receiver(
    parent: &OwnedDirectory,
    engine_relative: &Path,
    action: EntityId,
    expected: u64,
) -> ProofResult<()> {
    let receiver_relative = engine_relative
        .parent()
        .ok_or_else(invalid)?
        .join("receiver");
    let receiver = OwnedDirectory::open(parent.path(), &receiver_relative)?;
    // Validate private inode through the trusted workspace before SQLite's read-only open.
    let original = receiver.open_readonly(Path::new("counter.sqlite3"))?;
    let before = original.metadata().map_err(|_| integrity())?;
    let connection = rusqlite::Connection::open_with_flags(
        receiver.path().join("counter.sqlite3"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )
    .map_err(|_| integrity())?;
    connection
        .execute_batch("PRAGMA query_only=ON; PRAGMA trusted_schema=OFF;")
        .map_err(|_| integrity())?;
    let application_id: u32 = connection
        .query_row("PRAGMA application_id", [], |row| row.get(0))
        .map_err(|_| integrity())?;
    let integrity_check: String = connection
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|_| integrity())?;
    let observed: i64 = connection
        .query_row(
            "SELECT coalesce((SELECT count FROM counters WHERE action_id=?1),0)",
            [action.to_string()],
            |row| row.get(0),
        )
        .map_err(|_| integrity())?;
    let total: i64 = connection
        .query_row("SELECT coalesce(sum(count),0) FROM counters", [], |row| {
            row.get(0)
        })
        .map_err(|_| integrity())?;
    let after = receiver
        .open_readonly(Path::new("counter.sqlite3"))?
        .metadata()
        .map_err(|_| integrity())?;
    if application_id != 0x525a_5230
        || integrity_check != "ok"
        || observed < 0
        || observed as u64 != expected
        || total != observed
        || before.dev() != after.dev()
        || before.ino() != after.ino()
    {
        return Err(integrity());
    }
    Ok(())
}

impl Drop for Receiver {
    fn drop(&mut self) {
        if !self.process.reaped {
            let _ = self.process.kill();
        }
        let _ = remove_private(&self.workspace, "receiver.token");
        if let Some(engine) = &self.engine {
            let _ = remove_private(engine, "recovery-config.json");
        }
    }
}
