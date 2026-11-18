//! Host-only, one-request-per-connection control channel. No runtime output is serviced here.
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixListener as StdUnixListener;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rustix::fs::{self, AtFlags, FileType, Mode, OFlags, Stat};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::runtime::{Builder, Runtime};
use tokio::sync::oneshot;
use tokio::time::{Instant as TokioInstant, timeout_at};

use super::profile::LoadedProfile;
use crate::adapters::ledger::Ledger;
use crate::adapters::workspace::OwnedDirectory;
use crate::domain::execution::{ControlMeasurement, ControlMode, ControlState};
use crate::domain::values::{Digest, EntityId, WireInt, non_null_optional};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

const MAX_FRAME: usize = 4096;
// One live connection, one owned worker, no spawned or detached per-peer tasks. An
// unauthenticated/slow peer can occupy that connection for at most this interval.
const FRAME_TIMEOUT: Duration = Duration::from_millis(250);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(2);
const TOKEN_NAME: &str = "control.token";
const SOCKET_NAME: &str = "control.sock";
const TOKEN_PATH: &str = "ephemeral/control.token";
const MAX_CONTROLS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlAction {
    Pause,
    Resume,
    Cancel,
}

impl<'de> Deserialize<'de> for ControlAction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Kind {
            Pause,
            Resume,
            Cancel,
        }
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Action {
            kind: Kind,
        }
        Ok(match Action::deserialize(deserializer)?.kind {
            Kind::Pause => Self::Pause,
            Kind::Resume => Self::Resume,
            Kind::Cancel => Self::Cancel,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCommand {
    pub request_id: EntityId,
    pub investigation_id: EntityId,
    pub expected_revision: WireInt,
    pub action: ControlAction,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlAck {
    pub request_id: EntityId,
    pub state: ControlState,
    pub measurement: ControlMeasurement,
}

struct ControlSlot {
    // A single atomic contains revision << 1 | closed. Packing prevents a stale
    // receipt racing a resume publication from closing/reopening a different revision.
    gate: AtomicU64,
    state: Mutex<ControlState>,
}

pub struct ControlService {
    ledger: Arc<Ledger>,
    enclosing_investigation_id: EntityId,
    enclosing_cancelled: AtomicBool,
    closed: AtomicBool,
    slots: RwLock<BTreeMap<EntityId, Arc<ControlSlot>>>,
    epoch: Instant,
    clock_epoch_id: EntityId,
    deadline_us: WireInt,
}

impl ControlService {
    pub fn new(
        ledger: Arc<Ledger>,
        profile: &LoadedProfile,
        enclosing_investigation_id: EntityId,
    ) -> ProofResult<Self> {
        let controls = ledger.controls()?;
        if controls.len() > MAX_CONTROLS {
            return Err(integrity());
        }
        let deadline_us = WireInt::new(
            profile
                .config()
                .control
                .ack_deadline_ms
                .get()
                .checked_mul(1000)
                .ok_or_else(integrity)?,
        )?;
        let mut slots = BTreeMap::new();
        let mut enclosing_cancelled = false;
        for state in controls {
            state.validate()?;
            let id = state.investigation_id;
            if id == enclosing_investigation_id {
                enclosing_cancelled = state.mode == ControlMode::Cancelled;
            }
            let slot = Arc::new(ControlSlot {
                gate: AtomicU64::new(gate_value(state.revision, !state.admission_open)),
                state: Mutex::new(state),
            });
            if slots.insert(id, slot).is_some() {
                return Err(integrity());
            }
        }
        if !slots.contains_key(&enclosing_investigation_id) {
            return Err(denied());
        }
        Ok(Self {
            ledger,
            enclosing_investigation_id,
            enclosing_cancelled: AtomicBool::new(enclosing_cancelled),
            closed: AtomicBool::new(false),
            slots: RwLock::new(slots),
            epoch: Instant::now(),
            clock_epoch_id: EntityId::new(),
            deadline_us,
        })
    }

    pub fn clock_epoch_id(&self) -> EntityId {
        self.clock_epoch_id
    }
    pub(crate) fn enclosing_investigation_id(&self) -> EntityId {
        self.enclosing_investigation_id
    }
    pub(crate) fn enclosing_cancelled(&self) -> bool {
        self.enclosing_cancelled.load(Ordering::SeqCst)
    }
    pub(crate) fn enclosing_dispatch_state(&self) -> ProofResult<(ControlMode, bool)> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(denied());
        }
        let slot = self.slot(self.enclosing_investigation_id)?;
        let state = slot.state.lock().map_err(|_| integrity())?;
        Ok((state.mode, slot.gate.load(Ordering::SeqCst) & 1 == 0))
    }

    /// Host-only registration of already durable context, never peer-supplied authority.
    /// Existing gates are never refreshed from an older disk state or reopened.
    pub fn register_existing(&self, investigation_id: EntityId) -> ProofResult<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(denied());
        }
        if self
            .slots
            .read()
            .map_err(|_| integrity())?
            .contains_key(&investigation_id)
        {
            return Ok(());
        }
        // No slot-map lock is held during canonical I/O: admission may already hold
        // the ledger mutex while consulting its memory-only gate.
        let state = self.ledger.read_control(investigation_id)?;
        state.validate()?;
        let slot = Arc::new(ControlSlot {
            gate: AtomicU64::new(gate_value(state.revision, !state.admission_open)),
            state: Mutex::new(state),
        });
        let mut slots = self.slots.write().map_err(|_| integrity())?;
        if self.closed.load(Ordering::SeqCst) {
            return Err(denied());
        }
        let full = slots.len() >= MAX_CONTROLS;
        match slots.entry(investigation_id) {
            std::collections::btree_map::Entry::Occupied(_) => Ok(()),
            std::collections::btree_map::Entry::Vacant(entry) => {
                if full {
                    return Err(ProofError::new(
                        ErrorCode::BudgetExhausted,
                        "Host control context capacity is exhausted",
                    ));
                }
                entry.insert(slot);
                Ok(())
            }
        }
    }

    fn slot(&self, investigation_id: EntityId) -> ProofResult<Arc<ControlSlot>> {
        self.slots
            .read()
            .map_err(|_| integrity())?
            .get(&investigation_id)
            .cloned()
            .ok_or_else(denied)
    }

    /// Memory-only: safe while the caller holds the ledger transaction. The final
    /// admission transaction and apply_control serialize durable effect admission.
    pub fn check_admission(
        &self,
        investigation_id: EntityId,
        source_revision: WireInt,
    ) -> ProofResult<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(denied());
        }
        let slots = self.slots.read().map_err(|_| integrity())?;
        let slot = slots.get(&investigation_id).ok_or_else(denied)?;
        let gate = slot.gate.load(Ordering::SeqCst);
        if gate >> 1 != source_revision.get() {
            return Err(stale());
        }
        if gate & 1 != 0 {
            return Err(denied());
        }
        if investigation_id != self.enclosing_investigation_id
            && slots
                .get(&self.enclosing_investigation_id)
                .ok_or_else(denied)?
                .gate
                .load(Ordering::SeqCst)
                & 1
                != 0
        {
            return Err(denied());
        }
        Ok(())
    }

    fn now_us(&self) -> ProofResult<WireInt> {
        WireInt::new(u64::try_from(self.epoch.elapsed().as_micros()).map_err(|_| integrity())?)
            .map_err(Into::into)
    }

    // Called only after peer UID, exact wire shape and capability authentication.
    fn apply(&self, command: &ControlCommand) -> ProofResult<ControlAck> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(denied());
        }
        let received_us = self.now_us()?;
        let slot = self.slot(command.investigation_id)?;
        let mut observed = slot.gate.load(Ordering::SeqCst);
        loop {
            if observed >> 1 != command.expected_revision.get() {
                return Err(stale());
            }
            match slot.gate.compare_exchange(
                observed,
                observed | 1,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
        // The gate is already closed, even if a prior control or SQLite writer is
        // currently contended. Neither check_admission nor runtime work takes this mutex.
        let mut state = slot.state.lock().map_err(|_| integrity())?;
        if state.revision != command.expected_revision {
            return Err(stale());
        }
        if state.mode == ControlMode::Cancelled {
            return Err(ProofError::new(
                ErrorCode::Cancelled,
                "Investigation is cancelled",
            ));
        }
        let mode = match command.action {
            ControlAction::Pause => ControlMode::Paused,
            ControlAction::Cancel => ControlMode::Cancelled,
            ControlAction::Resume if state.mode == ControlMode::Paused => ControlMode::Running,
            ControlAction::Resume => return Err(denied()),
        };
        let next = ControlState {
            revision: state.revision.checked_add(WireInt::new(1)?)?,
            mode,
            admission_open: mode == ControlMode::Running,
            ..state.clone()
        };
        self.ledger.transaction(|transaction| {
            transaction.apply_control(&next, command.expected_revision)
        })?;
        if command.investigation_id == self.enclosing_investigation_id
            && mode == ControlMode::Cancelled
        {
            self.enclosing_cancelled.store(true, Ordering::SeqCst);
        }
        // This timestamp is after the real durable commit, not merely the in-memory closure.
        let barrier_active_us = self.now_us()?;
        *state = next.clone();
        slot.gate
            .store(gate_value(next.revision, true), Ordering::SeqCst);
        let measurement = ControlMeasurement {
            request_id: command.request_id,
            clock_epoch_id: self.clock_epoch_id,
            received_us,
            barrier_active_us,
            acknowledged_us: self.now_us()?,
            affected_revision: next.revision,
            // Observed at acknowledgment only. All admissions through this service
            // were denied while closed; this is not a forecast of future runtime sends.
            late_admissions: WireInt::ZERO,
        };
        measurement.validate_barrier_deadline(self.deadline_us)?;
        slot.gate.store(
            gate_value(next.revision, !next.admission_open),
            Ordering::SeqCst,
        );
        Ok(ControlAck {
            request_id: command.request_id,
            state: next,
            measurement,
        })
    }

    fn close_revision(&self, investigation_id: EntityId, revision: WireInt) {
        // A poisoned map also makes every admission check fail closed.
        if let Ok(slots) = self.slots.read()
            && let Some(slot) = slots.get(&investigation_id)
        {
            let open = gate_value(revision, false);
            let _ = slot
                .gate
                .compare_exchange(open, open | 1, Ordering::SeqCst, Ordering::SeqCst);
        }
    }
}

fn gate_value(revision: WireInt, closed: bool) -> u64 {
    // WireInt is bounded to 2^53-1, so this shift cannot overflow.
    (revision.get() << 1) | u64::from(closed)
}

#[derive(Clone, Copy, Serialize, Deserialize)]
enum Protocol {
    #[serde(rename = "razen.control/0.1.0")]
    V0,
}

// Deliberately neither Debug nor publicly serializable outside this private wire.
struct Capability([u8; 64]);

impl Capability {
    fn generate() -> Self {
        let mut bytes = [0; 64];
        uuid::Uuid::new_v4().simple().encode_lower(&mut bytes[..32]);
        uuid::Uuid::new_v4().simple().encode_lower(&mut bytes[32..]);
        Self(bytes)
    }

    fn parse(bytes: &[u8]) -> ProofResult<Self> {
        if bytes.len() != 64
            || !bytes
                .iter()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
        {
            return Err(denied());
        }
        let mut token = [0; 64];
        token.copy_from_slice(bytes);
        Ok(Self(token))
    }
}

impl Serialize for Capability {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let text = std::str::from_utf8(&self.0).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(text)
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct TokenVisitor;
        impl serde::de::Visitor<'_> for TokenVisitor {
            type Value = Capability;
            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a private control capability")
            }
            fn visit_str<E: serde::de::Error>(self, text: &str) -> Result<Capability, E> {
                Capability::parse(text.as_bytes())
                    .map_err(|_| E::custom("Invalid control capability"))
            }
        }
        deserializer.deserialize_str(TokenVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: Protocol,
    capability: Capability,
    command: ControlCommand,
}

#[derive(Serialize)]
struct ClientRequest<'a> {
    protocol: Protocol,
    capability: &'a Capability,
    command: &'a ControlCommand,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Success {
    protocol: Protocol,
    request_id: EntityId,
    state: ControlState,
    measurement: ControlMeasurement,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    protocol: Protocol,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    request_id: Option<EntityId>,
    error: ProofError,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Response {
    Success(Success),
    Failure(Failure),
}

pub struct ControlServer {
    stop: Option<oneshot::Sender<()>>,
    worker: Option<JoinHandle<ProofResult<()>>>,
    endpoint: Endpoint,
}

impl ControlServer {
    pub fn start(
        workspace: Arc<OwnedDirectory>,
        service: Arc<ControlService>,
    ) -> ProofResult<Self> {
        let capability = Capability::generate();
        let (endpoint, listener) = Endpoint::create(workspace, &capability)?;
        listener.set_nonblocking(true).map_err(|_| integrity())?;
        let runtime = runtime()?;
        let listener = {
            let _entered = runtime.enter();
            UnixListener::from_std(listener).map_err(|_| integrity())?
        };
        let uid = rustix::process::geteuid().as_raw();
        let (stop, stopped) = oneshot::channel();
        let worker = thread::Builder::new()
            .name("razen-control".into())
            .spawn(move || runtime.block_on(serve(listener, service, capability, uid, stopped)))
            .map_err(|_| integrity())?;
        Ok(Self {
            stop: Some(stop),
            worker: Some(worker),
            endpoint,
        })
    }

    pub(crate) fn ownership(&self) -> ProofResult<ControlEndpointRecord> {
        self.endpoint.ownership()
    }

    pub fn shutdown(mut self) -> ProofResult<()> {
        let stopped = self.stop_and_join();
        let cleaned = self.endpoint.cleanup();
        stopped.and(cleaned)
    }

    fn stop_and_join(&mut self) -> ProofResult<()> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        match self.worker.take() {
            Some(worker) => worker.join().map_err(|_| integrity())?,
            None => Ok(()),
        }
    }
}

impl Drop for ControlServer {
    fn drop(&mut self) {
        // Dropping the owner is also graceful: never detach a live worker.
        let _ = self.stop_and_join();
    }
}

async fn serve(
    listener: UnixListener,
    service: Arc<ControlService>,
    capability: Capability,
    uid: u32,
    mut stop: oneshot::Receiver<()>,
) -> ProofResult<()> {
    let outcome = loop {
        let accepted = tokio::select! {
            biased;
            _ = &mut stop => break Ok(()),
            accepted = listener.accept() => accepted,
        };
        let (stream, _) = match accepted {
            Ok(connection) => connection,
            Err(_) => break Err(integrity()),
        };
        tokio::select! {
            biased;
            _ = &mut stop => break Ok(()),
            _ = serve_connection(stream, &service, &capability, uid) => {},
        }
    };
    // No live control owner means no new effect admission. This also covers an
    // interrupted response after a committed resume and listener failure.
    service.closed.store(true, Ordering::SeqCst);
    for slot in service.slots.read().map_err(|_| integrity())?.values() {
        slot.gate.fetch_or(1, Ordering::SeqCst);
    }
    outcome
}

async fn serve_connection(
    mut stream: UnixStream,
    service: &ControlService,
    capability: &Capability,
    uid: u32,
) {
    let request = read_request(&mut stream, capability, uid).await;
    let mut committed = None;
    let response = match request {
        Ok(command) => match service.apply(&command) {
            Ok(mut ack) => {
                // Include host response construction time, not just transaction duration.
                let ready = service.now_us().and_then(|now| {
                    ack.measurement.acknowledged_us = now;
                    ack.measurement
                        .validate_barrier_deadline(service.deadline_us)
                });
                match ready {
                    Ok(()) => {
                        committed = Some((ack.state.investigation_id, ack.state.revision));
                        Response::Success(Success {
                            protocol: Protocol::V0,
                            request_id: ack.request_id,
                            state: ack.state,
                            measurement: ack.measurement,
                        })
                    }
                    Err(error) => {
                        service.close_revision(ack.state.investigation_id, ack.state.revision);
                        failure(Some(command.request_id), error)
                    }
                }
            }
            Err(error) => failure(Some(command.request_id), error),
        },
        Err(error) => failure(None, error),
    };
    let io_deadline = TokioInstant::now() + FRAME_TIMEOUT;
    let deadline = match &response {
        Response::Success(success) => {
            let offset = Duration::from_micros(
                success.measurement.received_us.get() + service.deadline_us.get(),
            );
            match service.epoch.checked_add(offset) {
                Some(limit) => io_deadline.min(TokioInstant::from_std(limit)),
                None => {
                    service.close_revision(success.state.investigation_id, success.state.revision);
                    return;
                }
            }
        }
        Response::Failure(_) => io_deadline,
    };
    let written = write_frame(&mut stream, &response, deadline).await;
    if written.is_err()
        && let Some((id, revision)) = committed
    {
        service.close_revision(id, revision);
    }
}

async fn read_request(
    stream: &mut UnixStream,
    capability: &Capability,
    uid: u32,
) -> ProofResult<ControlCommand> {
    if stream.peer_cred().map_err(|_| denied())?.uid() != uid {
        return Err(denied());
    }
    let bytes = read_frame(stream, TokioInstant::now() + FRAME_TIMEOUT).await?;
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let _ = request.protocol;
    if !bool::from(request.capability.0.ct_eq(&capability.0)) {
        return Err(denied());
    }
    Ok(request.command)
}

fn failure(request_id: Option<EntityId>, error: ProofError) -> Response {
    Response::Failure(Failure {
        protocol: Protocol::V0,
        request_id,
        error,
    })
}

pub struct ControlClient {
    path: PathBuf,
    capability: Capability,
    uid: u32,
    _directory: File,
    socket_identity: Stat,
}

impl ControlClient {
    pub fn new(workspace: &OwnedDirectory) -> ProofResult<Self> {
        let path = socket_path(workspace)?;
        let capability = Capability::parse(&workspace.read(Path::new(TOKEN_PATH), 64)?)?;
        let guard = workspace.lock_directory()?;
        let directory = open_ephemeral(&guard)?;
        let uid = rustix::process::geteuid().as_raw();
        let socket_identity = socket_stat(&directory, uid)?;
        Ok(Self {
            path,
            capability,
            uid,
            _directory: directory,
            socket_identity,
        })
    }

    /// Synchronous, including when called by a Tokio host. Its scoped worker owns
    /// the private reactor and is always joined; there are no nested block_on calls.
    pub fn request(&self, command: &ControlCommand) -> ProofResult<ControlAck> {
        let named = socket_stat(&self._directory, self.uid)?;
        if !same_object(&named, &self.socket_identity) {
            return Err(integrity());
        }
        thread::scope(|scope| {
            thread::Builder::new()
                .name("razen-control-client".into())
                .spawn_scoped(scope, || runtime()?.block_on(self.exchange(command)))
                .map_err(|_| unavailable())?
                .join()
                .map_err(|_| integrity())?
        })
    }

    async fn exchange(&self, command: &ControlCommand) -> ProofResult<ControlAck> {
        let deadline = TokioInstant::now() + CLIENT_TIMEOUT;
        let mut stream = timeout_at(deadline, UnixStream::connect(&self.path))
            .await
            .map_err(|_| timed_out())?
            .map_err(|_| unavailable())?;
        if stream.peer_cred().map_err(|_| denied())?.uid() != self.uid {
            return Err(denied());
        }
        let request = ClientRequest {
            protocol: Protocol::V0,
            capability: &self.capability,
            command,
        };
        write_frame(&mut stream, &request, deadline).await?;
        let bytes = read_frame(&mut stream, deadline).await?;
        let response: Response = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        match response {
            Response::Failure(failed) => {
                if failed.request_id.is_some_and(|id| id != command.request_id) {
                    return Err(invalid());
                }
                Err(failed.error)
            }
            Response::Success(success) => {
                let expected_mode = match command.action {
                    ControlAction::Pause => ControlMode::Paused,
                    ControlAction::Resume => ControlMode::Running,
                    ControlAction::Cancel => ControlMode::Cancelled,
                };
                if success.request_id != command.request_id
                    || success.measurement.request_id != command.request_id
                    || success.state.investigation_id != command.investigation_id
                    || success.state.revision
                        != command.expected_revision.checked_add(WireInt::new(1)?)?
                    || success.measurement.affected_revision != success.state.revision
                    || success.state.mode != expected_mode
                    || success.state.admission_open != (expected_mode == ControlMode::Running)
                {
                    return Err(invalid());
                }
                success.state.validate()?;
                success
                    .measurement
                    .validate_barrier_deadline(WireInt::new(1_000_000)?)?;
                Ok(ControlAck {
                    request_id: success.request_id,
                    state: success.state,
                    measurement: success.measurement,
                })
            }
        }
    }
}

fn runtime() -> ProofResult<Runtime> {
    Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .map_err(|_| unavailable())
}

async fn read_frame(stream: &mut UnixStream, deadline: TokioInstant) -> ProofResult<Vec<u8>> {
    let mut bytes = vec![0; MAX_FRAME];
    let mut used = 0;
    loop {
        if used == MAX_FRAME {
            return Err(invalid());
        }
        let count = timeout_at(deadline, stream.read(&mut bytes[used..]))
            .await
            .map_err(|_| timed_out())?
            .map_err(|_| unavailable())?;
        if count == 0 {
            return Err(invalid());
        }
        let end = used + count;
        if let Some(position) = bytes[used..end].iter().position(|byte| *byte == b'\n') {
            if used + position + 1 != end {
                return Err(invalid());
            }
            bytes.truncate(end - 1);
            return Ok(bytes);
        }
        used = end;
    }
}

async fn write_frame(
    stream: &mut UnixStream,
    value: &impl Serialize,
    deadline: TokioInstant,
) -> ProofResult<()> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| integrity())?;
    if bytes.len() >= MAX_FRAME {
        return Err(invalid());
    }
    bytes.push(b'\n');
    timeout_at(deadline, stream.write_all(&bytes))
        .await
        .map_err(|_| timed_out())?
        .map_err(|_| unavailable())
}

// These two exact names are the only resources this owner may remove. Inode checks
// prevent cleanup from deleting a replacement, another server's files, or other ephemeral data.
struct Endpoint {
    _workspace: Arc<OwnedDirectory>,
    directory: File,
    socket: Option<Stat>,
    token: Option<Stat>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct NativeControlFile {
    device: u64,
    inode: u64,
    mode: u32,
    uid: u32,
}

impl NativeControlFile {
    fn from_stat(value: &Stat) -> Self {
        Self {
            device: value.st_dev as u64,
            inode: value.st_ino,
            mode: value.st_mode as u32,
            uid: value.st_uid,
        }
    }
    fn matches(&self, value: &Stat) -> bool {
        self.device == value.st_dev as u64
            && self.inode == value.st_ino
            && self.mode == value.st_mode as u32
            && self.uid == value.st_uid
            && value.st_nlink == 1
            && value.st_uid == rustix::process::geteuid().as_raw()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ControlEndpointRecord {
    socket: NativeControlFile,
    token: NativeControlFile,
    token_sha256: Digest,
}

impl ControlEndpointRecord {
    pub(crate) fn reclaim(&self, workspace: &OwnedDirectory) -> ProofResult<()> {
        let guard = workspace.lock_directory()?;
        match fs::statat(&guard, "ephemeral", AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(_) => return Err(integrity()),
            Ok(_) => {}
        }
        let directory = open_ephemeral(&guard)?;
        let inspect = |name: &str,
                       expected: &NativeControlFile,
                       kind: FileType|
         -> ProofResult<Option<Stat>> {
            match fs::statat(&directory, name, AtFlags::SYMLINK_NOFOLLOW) {
                Err(rustix::io::Errno::NOENT) => Ok(None),
                Err(_) => Err(integrity()),
                Ok(native)
                    if expected.matches(&native)
                        && FileType::from_raw_mode(native.st_mode) == kind =>
                {
                    Ok(Some(native))
                }
                Ok(_) => Err(integrity()),
            }
        };
        let mut socket = inspect(SOCKET_NAME, &self.socket, FileType::Socket)?;
        let mut token = inspect(TOKEN_NAME, &self.token, FileType::RegularFile)?;
        let mut entries = fs::Dir::read_from(&directory).map_err(|_| integrity())?;
        for entry in &mut entries {
            let entry = entry.map_err(|_| integrity())?;
            if !matches!(
                entry.file_name().to_bytes(),
                b"." | b".." | b"control.sock" | b"control.token"
            ) {
                return Err(integrity());
            }
        }
        if token.is_some() && token_digest(&directory)? != self.token_sha256 {
            return Err(integrity());
        }
        remove_owned(&directory, SOCKET_NAME, &mut socket)?;
        remove_owned(&directory, TOKEN_NAME, &mut token)?;
        directory.sync_all().map_err(|_| integrity())
    }
}

fn token_digest(directory: &File) -> ProofResult<Digest> {
    let mut file = File::from(
        fs::openat(
            directory,
            TOKEN_NAME,
            OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| integrity())?,
    );
    let native = fs::fstat(&file).map_err(|_| integrity())?;
    if FileType::from_raw_mode(native.st_mode) != FileType::RegularFile
        || native.st_nlink != 1
        || native.st_uid != rustix::process::geteuid().as_raw()
        || native.st_mode as u32 & 0o7777 != 0o600
        || native.st_size != 64
    {
        return Err(integrity());
    }
    let mut bytes = [0; 65];
    let count = file.read(&mut bytes).map_err(|_| integrity())?;
    if count != 64 {
        return Err(integrity());
    }
    Ok(Digest::of(&bytes[..64]))
}

impl Endpoint {
    fn create(
        workspace: Arc<OwnedDirectory>,
        capability: &Capability,
    ) -> ProofResult<(Self, StdUnixListener)> {
        let path = socket_path(&workspace)?;
        let guard = workspace.lock_directory()?;
        match fs::mkdirat(&guard, "ephemeral", Mode::RWXU) {
            Ok(()) => {}
            Err(rustix::io::Errno::EXIST) => {}
            Err(_) => return Err(integrity()),
        }
        let directory = open_ephemeral(&guard)?;
        let mut endpoint = Self {
            _workspace: Arc::clone(&workspace),
            directory,
            socket: None,
            token: None,
        };
        // Do not adopt or unlink an existing socket or capability, even after a crash.
        let listener = StdUnixListener::bind(&path).map_err(|_| unavailable())?;
        let identity = fs::statat(&endpoint.directory, SOCKET_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| integrity())?;
        endpoint.socket = Some(identity);
        fs::chmodat(
            &endpoint.directory,
            SOCKET_NAME,
            Mode::RUSR | Mode::WUSR,
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| integrity())?;
        let checked = socket_stat(&endpoint.directory, rustix::process::geteuid().as_raw())?;
        if !same_object(&checked, endpoint.socket.as_ref().ok_or_else(integrity)?) {
            return Err(integrity());
        }
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut token = File::from(
            fs::openat(
                &endpoint.directory,
                TOKEN_NAME,
                flags,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| integrity())?,
        );
        let identity = fs::fstat(&token).map_err(|_| integrity())?;
        endpoint.token = Some(identity);
        let identity = endpoint.token.as_ref().ok_or_else(integrity)?;
        if FileType::from_raw_mode(identity.st_mode) != FileType::RegularFile
            || identity.st_nlink != 1
            || identity.st_uid != rustix::process::geteuid().as_raw()
            || u32::from(identity.st_mode) & 0o7777 != 0o600
        {
            return Err(denied());
        }
        token.write_all(&capability.0).map_err(|_| integrity())?;
        token.sync_all().map_err(|_| integrity())?;
        endpoint.directory.sync_all().map_err(|_| integrity())?;
        guard.sync_all().map_err(|_| integrity())?;
        Ok((endpoint, listener))
    }

    fn ownership(&self) -> ProofResult<ControlEndpointRecord> {
        // chmod changes the captured bind-time socket mode, so observe and
        // authenticate the actual current object before sealing its identity.
        let socket = socket_stat(&self.directory, rustix::process::geteuid().as_raw())?;
        if !same_object(&socket, self.socket.as_ref().ok_or_else(integrity)?) {
            return Err(integrity());
        }
        let token = fs::statat(&self.directory, TOKEN_NAME, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(|_| integrity())?;
        if !same_object(&token, self.token.as_ref().ok_or_else(integrity)?) {
            return Err(integrity());
        }
        Ok(ControlEndpointRecord {
            socket: NativeControlFile::from_stat(&socket),
            token: NativeControlFile::from_stat(&token),
            token_sha256: token_digest(&self.directory)?,
        })
    }

    fn cleanup(&mut self) -> ProofResult<()> {
        let socket = remove_owned(&self.directory, SOCKET_NAME, &mut self.socket);
        let token = remove_owned(&self.directory, TOKEN_NAME, &mut self.token);
        let synced = self.directory.sync_all().map_err(|_| integrity());
        socket.and(token).and(synced)
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn remove_owned(directory: &File, name: &str, owned: &mut Option<Stat>) -> ProofResult<()> {
    let Some(identity) = owned.as_ref() else {
        return Ok(());
    };
    let named = fs::statat(directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| integrity())?;
    if !same_object(identity, &named) {
        return Err(integrity());
    }
    fs::unlinkat(directory, name, AtFlags::empty()).map_err(|_| integrity())?;
    *owned = None;
    Ok(())
}

fn open_ephemeral(root: &File) -> ProofResult<File> {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let directory =
        File::from(fs::openat(root, "ephemeral", flags, Mode::empty()).map_err(|_| denied())?);
    let stat = fs::fstat(&directory).map_err(|_| integrity())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || u32::from(stat.st_mode) & 0o7777 != 0o700
    {
        return Err(denied());
    }
    Ok(directory)
}

fn socket_stat(directory: &File, uid: u32) -> ProofResult<Stat> {
    let stat =
        fs::statat(directory, SOCKET_NAME, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| denied())?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket
        || stat.st_uid != uid
        || stat.st_nlink != 1
        || u32::from(stat.st_mode) & 0o7777 != 0o600
    {
        return Err(denied());
    }
    Ok(stat)
}

fn socket_path(workspace: &OwnedDirectory) -> ProofResult<PathBuf> {
    let path = workspace.path().join("ephemeral").join(SOCKET_NAME);
    // Darwin sockaddr_un has 104 bytes including the terminating NUL. Use that
    // conservative limit on every host, rather than silently selecting another path.
    if path.as_os_str().as_bytes().len() >= 104 {
        return Err(ProofError::new(
            ErrorCode::InvalidInput,
            "Private control socket path exceeds platform limit",
        ));
    }
    Ok(path)
}

fn same_object(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}
fn invalid() -> ProofError {
    ProofError::new(ErrorCode::InvalidInput, "Invalid private control frame")
}
fn denied() -> ProofError {
    ProofError::new(ErrorCode::PermissionDenied, "Private control access denied")
}
fn stale() -> ProofError {
    ProofError::new(ErrorCode::StaleSnapshot, "Control revision is stale")
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Private control integrity failure",
    )
}
fn unavailable() -> ProofError {
    ProofError::new(
        ErrorCode::ProviderUnavailable,
        "Private control channel unavailable",
    )
}
fn timed_out() -> ProofError {
    ProofError::new(ErrorCode::Timeout, "Private control deadline exceeded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::application::control_owner::OwnedControl;
    use crate::application::proof_host::ProofHost;
    use crate::domain::values::{CatalogId, ContractVersion, Digest, InvocationState};
    use crate::protocol::contracts::CanonicalFixtures;
    use crate::protocol::messages::ToolRequest;
    use serde_json::{Value, json};

    mod private_root {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/private_root.rs"
        ));
    }

    fn host(root: &private_root::PrivateRoot) -> (LoadedProfile, ProofHost) {
        let repo = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = LoadedProfile::load(
            &repo.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let examples = std::fs::read(repo.join("fixtures/scenarios/contracts.json")).unwrap();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("run"), EntityId::new()).unwrap(),
        );
        let host = ProofHost::create(
            workspace,
            &profile,
            CanonicalFixtures::from_bytes(&examples).unwrap(),
            Digest::of(&examples),
            crate::adapters::native_files::executable_digest().unwrap(),
        )
        .unwrap();
        (profile, host)
    }

    #[test]
    fn newly_registered_owned_investigation_uses_the_same_policy_and_durable_control_service() {
        let root = private_root::PrivateRoot::new();
        let (_, host) = host(&root);
        let mut session = host.session.clone();
        session.session_id = EntityId::new();
        session.investigation_id = EntityId::new();
        session.goal = "Dynamically registered controlled context".into();
        let state = ControlState {
            investigation_id: session.investigation_id,
            ..host
                .ledger
                .read_control(host.session.investigation_id)
                .unwrap()
        };
        host.ledger
            .insert_control(&state, host.project.project_id, host.scope.revision)
            .unwrap();
        host.ledger
            .insert_session(&session, host.project.project_id)
            .unwrap();
        let mut spec = host.local_spec();
        spec.session_id = session.session_id;
        spec.investigation_id = session.investigation_id;
        assert_eq!(
            host.admission.bind(spec.clone()).err().unwrap().code,
            ErrorCode::PermissionDenied
        );
        host.control
            .register_existing(session.investigation_id)
            .unwrap();
        let binding = Arc::new(host.admission.bind(spec).unwrap());
        let raw = serde_json::value::RawValue::from_string(
            json!({"kind":"investigation","record_id":session.investigation_id}).to_string(),
        )
        .unwrap();
        let request = ToolRequest {
            call_id: EntityId::new(),
            tool_id: CatalogId::parse("context.read").unwrap(),
            tool_version: ContractVersion::V0_1_0,
            input: &raw,
            source_control_revision: WireInt::ZERO,
        };
        let prepared = host.registry.prepare(&binding, &request).unwrap();
        host.approve(&binding, prepared.call()).unwrap();
        let result = host.registry.execute_prepared(&binding, prepared).unwrap();
        assert_eq!(result.state, InvocationState::Completed);
        let bytes = host
            .evidence
            .read_artifact(host.project.project_id, result.output_ref.unwrap(), 65_536)
            .unwrap();
        let context: Value = serde_json::from_slice(&bytes).unwrap();
        let record_ref = EntityId::parse(context["record_ref"].as_str().unwrap()).unwrap();
        let record = host
            .evidence
            .read_artifact(host.project.project_id, record_ref, 65_536)
            .unwrap();
        let context: Value = serde_json::from_slice(&record).unwrap();
        assert_eq!(context["record"]["session_id"], json!(session.session_id));
        let owner = OwnedControl::start(host.workspace.clone(), host.control.clone()).unwrap();
        host.install_control_client(owner.client().unwrap())
            .unwrap();
        let ack = host
            .control_client()
            .unwrap()
            .request(&ControlCommand {
                request_id: EntityId::new(),
                investigation_id: session.investigation_id,
                expected_revision: WireInt::ZERO,
                action: ControlAction::Cancel,
            })
            .unwrap();
        ack.measurement
            .validate_barrier_deadline(WireInt::new(1_000_000).unwrap())
            .unwrap();
        assert_eq!(
            host.ledger.read_control(session.investigation_id).unwrap(),
            ack.state
        );
        host.control
            .register_existing(session.investigation_id)
            .unwrap();
        assert_eq!(
            host.control
                .check_admission(session.investigation_id, ack.state.revision)
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );
        host.control
            .check_admission(host.session.investigation_id, WireInt::ZERO)
            .unwrap();
        owner.shutdown().unwrap();
        assert_eq!(
            host.control
                .register_existing(session.investigation_id)
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );
        assert_eq!(
            host.control
                .check_admission(host.session.investigation_id, WireInt::ZERO)
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn repeated_registration_never_reopens_a_gate_closed_by_an_actual_failed_durable_barrier() {
        let root = private_root::PrivateRoot::new();
        let (_, host) = host(&root);
        let external =
            rusqlite::Connection::open(host.workspace.path().join("ledger.sqlite")).unwrap();
        external.execute_batch("BEGIN IMMEDIATE").unwrap();
        let error = host
            .control
            .apply(&ControlCommand {
                request_id: EntityId::new(),
                investigation_id: host.session.investigation_id,
                expected_revision: WireInt::ZERO,
                action: ControlAction::Pause,
            })
            .unwrap_err();
        assert_eq!(error.code, ErrorCode::IntegrityError);
        assert_eq!(
            host.ledger
                .read_control(host.session.investigation_id)
                .unwrap()
                .revision,
            WireInt::ZERO
        );
        host.control
            .register_existing(host.session.investigation_id)
            .unwrap();
        assert_eq!(
            host.control
                .check_admission(host.session.investigation_id, WireInt::ZERO)
                .unwrap_err()
                .code,
            ErrorCode::PermissionDenied
        );
        external.execute_batch("ROLLBACK").unwrap();
        assert_eq!(
            host.admission.bind(host.local_spec()).err().unwrap().code,
            ErrorCode::PermissionDenied
        );
    }

    #[test]
    fn dead_endpoint_reclamation_refuses_replaced_token_and_preserves_unknown_symlink() {
        let root = private_root::PrivateRoot::new();
        let workspace = Arc::new(
            OwnedDirectory::create(root.path(), Path::new("endpoint"), EntityId::new()).unwrap(),
        );
        let (mut endpoint, listener) =
            Endpoint::create(workspace.clone(), &Capability::generate()).unwrap();
        let record = endpoint.ownership().unwrap();
        drop(listener);
        let directory = workspace.path().join("ephemeral");
        let original = directory.join("retained-original-token");
        std::fs::rename(directory.join(TOKEN_NAME), &original).unwrap();
        let target = root.path().join("unrelated-target");
        std::fs::write(&target, b"must not be read or removed").unwrap();
        std::os::unix::fs::symlink(&target, directory.join(TOKEN_NAME)).unwrap();
        assert_eq!(
            record.reclaim(&workspace).unwrap_err().code,
            ErrorCode::IntegrityError
        );
        assert!(
            directory
                .join(TOKEN_NAME)
                .symlink_metadata()
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            directory.join(SOCKET_NAME).exists(),
            "validate every object before deleting either one"
        );
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"must not be read or removed"
        );
        // Restore only this test's own token so its captured owner can finish.
        std::fs::remove_file(directory.join(TOKEN_NAME)).unwrap();
        std::fs::rename(original, directory.join(TOKEN_NAME)).unwrap();
        endpoint.cleanup().unwrap();
        workspace.remove_empty().unwrap();
    }
}
