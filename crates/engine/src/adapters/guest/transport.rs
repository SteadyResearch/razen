use super::{
    attestation, integrity,
    lifecycle::{self, Containment},
    preflight::{self, DurableCapacity, HostOccupancy, OwnedTransport, PreparedGuest},
    unavailable,
};
use crate::application::profile::LoadedProfile;
use crate::domain::values::{Digest, EntityId, WireInt};
use crate::protocol::{
    codec::{self, ChannelRole, Direction, Envelope},
    error::ProofResult,
    messages::{Message, OutputStream, SupervisorLaunch},
};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::os::{
    fd::OwnedFd,
    unix::{net::UnixStream, process::CommandExt},
};
use std::process::{Child, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct SupervisorBinding {
    binding: EntityId,
    invocation: EntityId,
    run: EntityId,
    attestation: EntityId,
    revision: WireInt,
    requests: BTreeSet<EntityId>,
    seen: BTreeMap<EntityId, Digest>,
    sequence: [u64; 2],
    output: usize,
    output_cap: usize,
    ready: bool,
    started: bool,
    terminal: bool,
}
impl SupervisorBinding {
    pub fn new(
        binding: EntityId,
        invocation: EntityId,
        run: EntityId,
        attestation: EntityId,
        revision: WireInt,
        output_cap: usize,
    ) -> Self {
        Self {
            binding,
            invocation,
            run,
            attestation,
            revision,
            requests: BTreeSet::new(),
            seen: BTreeMap::new(),
            sequence: [0; 2],
            output: 0,
            output_cap,
            ready: false,
            started: false,
            terminal: false,
        }
    }
    pub fn register_request(&mut self, id: EntityId) -> ProofResult<()> {
        if self.requests.len() == 256 {
            return Err(integrity(
                "Supervisor request correlation capacity exhausted",
            ));
        }
        self.requests.insert(id);
        Ok(())
    }
    pub fn accept<'a>(&mut self, bytes: &'a [u8], max_frame: usize) -> ProofResult<Envelope<'a>> {
        let envelope = codec::decode_frame(
            bytes,
            max_frame,
            ChannelRole::Supervisor,
            Direction::PeerToHost,
        )?;
        if !envelope
            .correlation_id
            .is_some_and(|id| self.requests.contains(&id))
        {
            return Err(integrity(
                "Supervisor reply has no current authenticated request correlation",
            ));
        }
        let digest = Digest::of(bytes);
        if let Some(previous) = self.seen.get(&envelope.message_id) {
            if *previous != digest {
                return Err(integrity("Supervisor message ID changed immutable content"));
            }
            return Err(integrity(
                "Duplicate supervisor reply cannot replay lifecycle or output",
            ));
        }
        if self.terminal || self.seen.len() == 1024 {
            return Err(integrity(
                "Terminal supervisor binding or bounded reply history exhausted",
            ));
        }
        let invocation = match envelope.message() {
            Message::SupervisorReady(value) => value.invocation_id,
            Message::SupervisorStarted(value) => value.invocation_id,
            Message::SupervisorOutput(value) => value.invocation_id,
            Message::SupervisorUsage(value) => value.invocation_id,
            Message::SupervisorTerminated(value) => value.invocation_id,
            Message::SupervisorError(value) => value.invocation_id,
            _ => {
                return Err(integrity(
                    "Non-supervisor response on authenticated supervisor channel",
                ));
            }
        };
        if invocation != self.invocation {
            return Err(integrity(
                "Supervisor reply refers to a foreign launch invocation",
            ));
        }
        match envelope.message() {
            Message::SupervisorReady(ready) => {
                if self.ready
                    || ready.attestation.run_id != self.run
                    || ready.attestation.attestation_id != self.attestation
                {
                    return Err(integrity("Foreign or repeated launch attestation"));
                }
                self.ready = true;
            }
            Message::SupervisorStarted(_) => {
                if !self.ready || self.started {
                    return Err(integrity("Supervisor started before current readiness"));
                }
                self.started = true;
            }
            Message::SupervisorOutput(output) => {
                if !self.started {
                    return Err(integrity("Workload output preceded attested release"));
                }
                let stream = match output.stream {
                    OutputStream::Stdout => 0,
                    OutputStream::Stderr => 1,
                };
                if output.sequence.get() != self.sequence[stream] + 1
                    || output.bytes.len() > self.output_cap.saturating_sub(self.output)
                {
                    return Err(integrity(
                        "Supervisor output sequence or cumulative byte limit violated",
                    ));
                }
                self.sequence[stream] += 1;
                self.output += output.bytes.len();
            }
            Message::SupervisorUsage(usage) => {
                if !self.started || usage.output_bytes.get() != self.output as u64 {
                    return Err(integrity(
                        "Supervisor usage is not bound to observed workload output",
                    ));
                }
            }
            Message::SupervisorTerminated(_) => {
                if !self.ready {
                    return Err(integrity("Termination has no current sandbox readiness"));
                }
                self.terminal = true;
            }
            Message::SupervisorError(_) => self.terminal = true,
            _ => {
                return Err(integrity(
                    "Non-supervisor response on authenticated supervisor channel",
                ));
            }
        }
        self.seen.insert(envelope.message_id, digest);
        Ok(envelope)
    }
}

enum DiagnosticKind {
    Stderr,
    Failure,
}

fn create_private_diagnostic(
    home: &std::path::Path,
    owner_id: EntityId,
    uid: u32,
    invocation_id: EntityId,
    kind: DiagnosticKind,
) -> ProofResult<File> {
    use rustix::fs::{FileType, Mode, OFlags};

    let directory = rustix::fs::open(
        home,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| integrity("Private supervisor diagnostic directory is unavailable"))?;
    let stat = rustix::fs::fstat(&directory)
        .map_err(|_| integrity("Cannot inspect private supervisor diagnostic directory"))?;
    if uid != rustix::process::geteuid().as_raw()
        || stat.st_uid != uid
        || stat.st_mode & 0o777 != 0o700
    {
        return Err(integrity(
            "Private supervisor diagnostic directory ownership changed",
        ));
    }
    let marker = rustix::fs::openat(
        &directory,
        ".razen-owner.json",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| integrity("Private supervisor diagnostic owner is unavailable"))?;
    let stat = rustix::fs::fstat(&marker)
        .map_err(|_| integrity("Cannot inspect private supervisor diagnostic owner"))?;
    let length = usize::try_from(stat.st_size)
        .map_err(|_| integrity("Private supervisor diagnostic owner length is invalid"))?;
    if stat.st_uid != uid
        || stat.st_mode & 0o777 != 0o600
        || stat.st_nlink != 1
        || FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || length > 1024
    {
        return Err(integrity(
            "Private supervisor diagnostic owner is not a private regular file",
        ));
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Owner {
        owner_id: EntityId,
        uid: u32,
    }
    let mut marker = File::from(marker);
    let mut bytes = [0; 1024];
    marker
        .read_exact(&mut bytes[..length])
        .map_err(|_| integrity("Cannot read private supervisor diagnostic owner"))?;
    let owner: Owner = serde_json::from_slice(&bytes[..length])
        .map_err(|_| integrity("Private supervisor diagnostic owner is malformed"))?;
    if owner.owner_id != owner_id || owner.uid != uid {
        return Err(integrity(
            "Private supervisor diagnostic owner does not match this invocation",
        ));
    }
    let name = match kind {
        DiagnosticKind::Stderr => format!(".razen-diagnostic-{invocation_id}.stderr"),
        DiagnosticKind::Failure => format!(".razen-failure-{invocation_id}.json"),
    };
    let file = rustix::fs::openat(
        &directory,
        name.as_str(),
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::RUSR | Mode::WUSR,
    )
    .map_err(|_| integrity("Cannot create private owned supervisor diagnostics"))?;
    File::from(directory)
        .sync_all()
        .map_err(|_| integrity("Cannot persist private supervisor diagnostic directory"))?;
    Ok(File::from(file))
}

#[derive(Default)]
struct PrivateDiagnostics {
    file: Option<File>,
    observed: usize,
}

impl PrivateDiagnostics {
    fn push(
        &mut self,
        home: &std::path::Path,
        owner_id: EntityId,
        uid: u32,
        invocation_id: EntityId,
        bytes: &[u8],
    ) -> ProofResult<()> {
        let previous = self.observed;
        self.observed = previous.saturating_add(bytes.len());
        let retained = bytes.len().min(65536_usize.saturating_sub(previous));
        if retained != 0 {
            if self.file.is_none() {
                self.file = Some(create_private_diagnostic(
                    home,
                    owner_id,
                    uid,
                    invocation_id,
                    DiagnosticKind::Stderr,
                )?);
            }
            self.file
                .as_mut()
                .ok_or_else(|| integrity("Owned supervisor diagnostic capture disappeared"))?
                .write_all(&bytes[..retained])
                .map_err(|_| integrity("Cannot retain private owned supervisor diagnostics"))?;
        }
        if self.observed > 65536 {
            return Err(integrity(
                "Supervisor diagnostics exceeded independent bound",
            ));
        }
        Ok(())
    }

    fn finish(&self, invocation_id: EntityId) -> ProofResult<()> {
        if let Some(file) = &self.file {
            file.sync_all()
                .map_err(|_| integrity("Cannot persist private owned supervisor diagnostics"))?;
            eprintln!(
                r#"{{"component":"guest-diagnostics","invocation_id":"{}","observed_bytes":{},"bounded_truncation":{}}}"#,
                invocation_id,
                self.observed,
                self.observed > 65536,
            );
        }
        Ok(())
    }
}

pub struct GuestInvocation {
    guest: Arc<PreparedGuest>,
    child: Child,
    input: UnixStream,
    output: UnixStream,
    diagnostic: UnixStream,
    pending: Vec<u8>,
    diagnostics: PrivateDiagnostics,
    pub invocation_id: EntityId,
    pub lease_id: EntityId,
    binding: SupervisorBinding,
    profile: LoadedProfile,
    capacity: Option<DurableCapacity>,
    occupancy: HostOccupancy,
    closing: bool,
    terminal: Option<Containment>,
    transport_reaped: bool,
    pub transport_pid: u32,
}
impl PreparedGuest {
    pub fn stage_runtime(
        &self,
        invocation_id: EntityId,
        artifact_id: EntityId,
        snapshot: &[u8],
    ) -> ProofResult<()> {
        use base64::Engine as _;
        let envelope =
            codec::decode_frame(snapshot, 65536, ChannelRole::Runtime, Direction::HostToPeer)?;
        if !matches!(envelope.message(), Message::RuntimeStart(_)) {
            return Err(integrity(
                "Runtime staging accepts only the existing public start envelope",
            ));
        }
        if snapshot.is_empty() || snapshot.len() > 65536 {
            return Err(integrity(
                "Runtime approved input must be a bounded nonempty immutable artifact",
            ));
        }
        let bytes=serde_json::to_vec(&json!({"invocation_id":invocation_id,"artifact_id":artifact_id,"snapshot_sha256":Digest::of(snapshot),"snapshot_base64":base64::engine::general_purpose::STANDARD.encode(snapshot)})).map_err(|_|integrity("Cannot encode immutable runtime input staging"))?;
        self.guest_command(&["--stage"], Some(&bytes), Duration::from_secs(5))?;
        Ok(())
    }
    pub fn stage(
        &self,
        invocation_id: EntityId,
        artifact_id: EntityId,
        snapshot: &[u8],
        host_canary_path: &std::path::Path,
    ) -> ProofResult<()> {
        use base64::Engine as _;
        if !host_canary_path.starts_with(self.repository.join("target/r0-guest/canaries"))
            || host_canary_path.file_name()
                != Some(std::ffi::OsStr::new(&invocation_id.to_string()))
        {
            return Err(integrity(
                "Staged canary is not the current invocation's controlled owned resource",
            ));
        }
        if snapshot.len() > 65536 {
            return Err(integrity(
                "Approved guest snapshot exceeds the fixed staging chunk",
            ));
        }
        let input = json!({"invocation_id":invocation_id,"artifact_id":artifact_id,"snapshot_sha256":Digest::of(snapshot),"snapshot_base64":base64::engine::general_purpose::STANDARD.encode(snapshot),"host_canary_path":host_canary_path});
        let bytes = serde_json::to_vec(&input)
            .map_err(|_| integrity("Cannot encode immutable guest staging input"))?;
        self.guest_command(&["--stage"], Some(&bytes), Duration::from_secs(5))?;
        Ok(())
    }
    pub fn launch(
        self: &Arc<Self>,
        launch: SupervisorLaunch,
        profile: &LoadedProfile,
    ) -> ProofResult<GuestInvocation> {
        if launch.profile_sha256 != self.profile_sha256()
            || profile.sha256() != self.profile_sha256()
        {
            return Err(integrity("Launch profile differs from prepared boundary"));
        }
        self.validate_live(profile)?;
        let profile = LoadedProfile::load(
            &self
                .repository
                .join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )?;
        let capacity = self.capacity_lock()?;
        let mut occupancy = self.claim_capacity(&capacity, &launch)?;
        let (input, child_input) = UnixStream::pair()
            .map_err(|_| unavailable("Cannot create approved supervisor stdin"))?;
        let (output, child_output) = UnixStream::pair()
            .map_err(|_| unavailable("Cannot create approved supervisor stdout"))?;
        let (diagnostic, child_diagnostic) = UnixStream::pair()
            .map_err(|_| unavailable("Cannot create bounded supervisor diagnostics"))?;
        for stream in [&input, &output, &diagnostic] {
            stream
                .set_nonblocking(true)
                .map_err(|_| unavailable("Cannot configure bounded supervisor transport"))?;
        }
        let mut command = self.ssh_command()?;
        command
            .args([
                "sudo",
                "-n",
                "/usr/local/libexec/razen-tool-supervisor",
                "--serve",
            ])
            .stdin(Stdio::from(OwnedFd::from(child_input)))
            .stdout(Stdio::from(OwnedFd::from(child_output)))
            .stderr(Stdio::from(OwnedFd::from(child_diagnostic)))
            .process_group(0);
        let child = command
            .spawn()
            .map_err(|_| unavailable("Cannot start dedicated authenticated supervisor session"))?;
        let pid = child.id();
        let mut invocation = GuestInvocation {
            guest: Arc::clone(self),
            child,
            input,
            output,
            diagnostic,
            pending: Vec::new(),
            diagnostics: PrivateDiagnostics::default(),
            invocation_id: launch.invocation_id,
            lease_id: launch.lease_id,
            binding: SupervisorBinding::new(
                launch.binding_id,
                launch.invocation_id,
                launch.run_id,
                launch.attestation_id,
                launch.control_revision,
                profile
                    .config()
                    .protocol
                    .invocation_output_limit_bytes
                    .get() as usize,
            ),
            profile,
            capacity: Some(capacity),
            occupancy: occupancy.clone(),
            closing: false,
            terminal: None,
            transport_reaped: false,
            transport_pid: pid,
        };
        occupancy.transport = Some(OwnedTransport {
            pid,
            birth_sha256: preflight::process_identity(pid)?
                .ok_or_else(|| unavailable("Owned SSH exited before durable launch binding"))?,
        });
        invocation
            .capacity
            .as_ref()
            .ok_or_else(|| integrity("Durable launch reservation disappeared"))?
            .replace(&invocation.occupancy, &occupancy)?;
        invocation.occupancy = occupancy;
        invocation.send(
            "launch",
            serde_json::to_value(launch)
                .map_err(|_| integrity("Cannot encode supervisor launch"))?,
        )?;
        Ok(invocation)
    }
}
impl GuestInvocation {
    fn ensure_live_transport(&self) -> ProofResult<()> {
        if self.closing || self.capacity.is_none() || self.transport_reaped || self.binding.terminal
        {
            return Err(crate::protocol::error::ProofError::new(
                crate::protocol::error::ErrorCode::Cancelled,
                "Owned guest transport is closed; a fresh current launch is required",
            ));
        }
        Ok(())
    }

    fn send(&mut self, kind: &str, payload: Value) -> ProofResult<EntityId> {
        self.ensure_live_transport()?;
        if self.binding.requests.len() >= 256 {
            return Err(integrity(
                "Supervisor request correlation capacity exhausted",
            ));
        }
        let id = EntityId::new();
        if self.binding.requests.contains(&id) {
            return Err(integrity(
                "Supervisor request ID would reuse an existing binding",
            ));
        }
        let bytes = codec::encode_frame(
            &json!({"protocol":codec::PROTOCOL,"message_id":id,"kind":kind,"payload":payload}),
            self.profile.config().protocol.message_limit_bytes.get() as usize,
        )?;
        // Exercise the exact outbound supervisor schema before touching the transport.
        codec::decode_frame(
            &bytes,
            self.profile.config().protocol.message_limit_bytes.get() as usize,
            ChannelRole::Supervisor,
            Direction::HostToPeer,
        )?;
        let start = Instant::now();
        let mut offset = 0;
        while offset < bytes.len() {
            match self.input.write(&bytes[offset..]) {
                Ok(0) => {
                    self.closing = true;
                    return Err(unavailable("Supervisor request channel closed"));
                }
                Ok(n) => offset += n,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && start.elapsed() < Duration::from_millis(100) =>
                {
                    std::thread::sleep(Duration::from_millis(1))
                }
                Err(error) => {
                    self.closing = true;
                    let mut failure =
                        unavailable("Supervisor control write failed or exceeded bound");
                    // Only the validated supervisor kind and bounded I/O metadata are public.
                    failure.message = std::borrow::Cow::Owned(format!(
                        "Supervisor {kind} write failed: kind={:?} errno={:?} offset={offset}/{} elapsed_us={}",
                        error.kind(),
                        error.raw_os_error(),
                        bytes.len(),
                        start.elapsed().as_micros()
                    ));
                    return Err(failure);
                }
            }
        }
        self.binding.register_request(id)?;
        Ok(id)
    }
    pub fn refresh(&mut self, lease: EntityId, revision: WireInt) -> ProofResult<()> {
        self.ensure_live_transport()?;
        if lease != self.lease_id {
            return Err(integrity("Refresh refers to a foreign guest lease"));
        }
        if revision != self.binding.revision {
            return Err(integrity(
                "Refresh cannot advance or restore lease authority",
            ));
        }
        self.send("lease_refresh",json!({"binding_id":self.binding.binding,"invocation_id":self.invocation_id,"lease_id":lease,"control_revision":revision}))?;
        Ok(())
    }
    pub fn cancel(&mut self, lease: EntityId, revision: WireInt, reason: &str) -> ProofResult<()> {
        self.ensure_live_transport()?;
        if lease != self.lease_id {
            return Err(integrity("Cancellation refers to a foreign guest lease"));
        }
        if revision < self.binding.revision {
            return Err(integrity("Stale supervisor cancellation"));
        }
        self.send("cancel",json!({"binding_id":self.binding.binding,"invocation_id":self.invocation_id,"lease_id":lease,"control_revision":revision,"reason":reason}))?;
        self.binding.revision = revision;
        self.closing = true;
        Ok(())
    }
    pub fn close(&mut self, lease: EntityId, revision: WireInt, reason: &str) -> ProofResult<()> {
        self.ensure_live_transport()?;
        if lease != self.lease_id || revision < self.binding.revision {
            return Err(integrity(
                "Closure refers to a foreign lease or stale control revision",
            ));
        }
        self.send("close",json!({"binding_id":self.binding.binding,"invocation_id":self.invocation_id,"lease_id":lease,"control_revision":revision,"reason":reason}))?;
        self.binding.revision = revision;
        self.closing = true;
        Ok(())
    }
    pub fn send_runtime(&mut self, frame: &[u8]) -> ProofResult<()> {
        self.ensure_live_transport()?;
        codec::decode_frame(
            frame,
            self.profile.config().protocol.message_limit_bytes.get() as usize,
            ChannelRole::Runtime,
            Direction::HostToPeer,
        )?;
        if let Err(error) = self.guest.guest_command(
            &["--runtime-input", &self.invocation_id.to_string()],
            Some(frame),
            Duration::from_millis(250),
        ) {
            // Management failure cannot distinguish no delivery from an effected FIFO prefix.
            self.closing = true;
            return Err(error);
        }
        Ok(())
    }
    fn drain_diagnostic(&mut self, scratch: &mut [u8]) -> ProofResult<()> {
        loop {
            match self.diagnostic.read(scratch) {
                Ok(0) => return Ok(()),
                Ok(n) => {
                    self.diagnostics.push(
                        &self.guest.record.lima_home,
                        self.guest.record.owner_id,
                        self.guest.record.uid,
                        self.invocation_id,
                        &scratch[..n],
                    )?;
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(_) => return Err(unavailable("Supervisor diagnostic channel failed")),
            }
        }
    }
    fn retain_failure_record(&self) -> ProofResult<()> {
        let bytes = self.guest.failure_record(&self.occupancy)?;
        let mut file = create_private_diagnostic(
            &self.guest.record.lima_home,
            self.guest.record.owner_id,
            self.guest.record.uid,
            self.invocation_id,
            DiagnosticKind::Failure,
        )?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| integrity("Cannot persist private owned guest failure record"))?;
        eprintln!(
            r#"{{"component":"guest-failure-record","invocation_id":"{}","bytes":{},"sha256":"{}"}}"#,
            self.invocation_id,
            bytes.len(),
            Digest::of(&bytes),
        );
        Ok(())
    }

    /// One bounded supervisor reply. Runtime bytes remain nested untrusted output.
    pub fn poll(&mut self) -> ProofResult<Option<Value>> {
        let mut scratch = [0; 65536];
        self.drain_diagnostic(&mut scratch)?;
        if !self.pending.contains(&b'\n') {
            match self.output.read(&mut scratch) {
                Ok(0) => {
                    if self.terminal.is_none() {
                        return Err(unavailable(
                            "Supervisor transport lost before verified containment",
                        ));
                    }
                }
                Ok(n) => self.pending.extend_from_slice(&scratch[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(_) => return Err(unavailable("Supervisor response channel failed")),
            }
        }
        let cap = self.profile.config().protocol.message_limit_bytes.get() as usize;
        if self.pending.len() > cap {
            return Err(integrity("Supervisor response frame exceeds profile bound"));
        }
        let Some(end) = self.pending.iter().position(|b| *b == b'\n') else {
            return Ok(None);
        };
        let frame = &self.pending[..=end];
        let envelope = self.binding.accept(frame, cap)?;
        if let Message::SupervisorReady(ready) = envelope.message() {
            attestation::validate(
                &ready.attestation,
                self.binding.run,
                self.binding.attestation,
                &self.profile,
                &self.guest,
            )?;
        }
        if let Message::SupervisorError(error) = envelope.message() {
            if error.invocation_id != self.invocation_id {
                return Err(integrity("Supervisor error has a foreign invocation"));
            }
            if let Err(diagnostic) = self.retain_failure_record() {
                eprintln!(
                    r#"{{"component":"guest-failure-record","invocation_id":"{}","capture_error":"{:?}"}}"#,
                    self.invocation_id, diagnostic.code,
                );
            }
            return Err(error.error.clone());
        }
        if let Message::SupervisorTerminated(terminated) = envelope.message() {
            if !terminated.empty_cgroup {
                return Err(integrity(
                    "Supervisor did not verify empty owned workload cgroup",
                ));
            }
            self.terminal = Some(Containment {
                invocation_id: self.invocation_id,
                empty_cgroup: true,
                vm_force_stopped: false,
                observed_vm_status: "Running".into(),
                elapsed_us: 0,
            });
        }
        let value = serde_json::from_slice(frame)
            .map_err(|_| integrity("Cannot retain validated supervisor response"))?;
        self.pending.drain(..=end);
        Ok(Some(value))
    }
    pub fn terminate(&mut self, lease: EntityId, revision: WireInt) -> ProofResult<Containment> {
        if lease != self.lease_id || revision < self.binding.revision {
            return Err(integrity(
                "Containment refers to a foreign lease or stale revision",
            ));
        }
        let started = Instant::now();
        let _ = self.cancel(lease, revision, "host containment after durable barrier");
        let deadline = Duration::from_millis(
            self.profile
                .config()
                .external_runner
                .termination_grace_ms
                .get()
                + self
                    .profile
                    .config()
                    .external_runner
                    .empty_cgroup_observation_deadline_ms
                    .get(),
        );
        while started.elapsed() < deadline && self.terminal.is_none() {
            if self.poll().is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        if let Some(mut result) = self.terminal.clone() {
            result.elapsed_us = started.elapsed().as_micros() as u64;
            self.reap_transport()?;
            return Ok(result);
        }
        if let Ok(record) = self.read_termination_record() {
            let result = Containment {
                invocation_id: self.invocation_id,
                empty_cgroup: true,
                vm_force_stopped: false,
                observed_vm_status: "Running".into(),
                elapsed_us: record["lease_elapsed_us"]
                    .as_u64()
                    .ok_or_else(|| integrity("Validated journal lost its elapsed observation"))?,
            };
            self.terminal = Some(result.clone());
            self.reap_transport()?;
            return Ok(result);
        }
        let result = self.force_stop_owned()?;
        self.terminal = Some(result.clone());
        self.reap_transport()?;
        Ok(result)
    }
    fn reap_transport(&mut self) -> ProofResult<()> {
        if !self.transport_reaped {
            let deadline = Instant::now();
            let mut scratch = [0; 65536];
            let mut diagnostic_result = Ok(());
            while deadline.elapsed() < Duration::from_millis(250)
                && self
                    .child
                    .try_wait()
                    .map_err(|_| unavailable("Cannot observe owned SSH termination"))?
                    .is_none()
            {
                if diagnostic_result.is_ok() {
                    diagnostic_result = self.drain_diagnostic(&mut scratch);
                }
                std::thread::sleep(Duration::from_millis(2));
            }
            if self
                .child
                .try_wait()
                .map_err(|_| unavailable("Cannot observe owned SSH transport"))?
                .is_none()
            {
                if let Some(pid) = rustix::process::Pid::from_raw(self.child.id() as i32) {
                    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
                }
                let _ = self.child.kill();
            }
            self.child
                .wait()
                .map_err(|_| unavailable("Cannot reap owned SSH transport"))?;
            self.transport_reaped = true;
            // The guest writes its cause after the generic failure frame; collect that tail
            // even when the SSH child had already exited before this cleanup began.
            if diagnostic_result.is_ok() {
                diagnostic_result = self.drain_diagnostic(&mut scratch);
            }
            if let Err(error) = self.diagnostics.finish(self.invocation_id)
                && diagnostic_result.is_ok()
            {
                diagnostic_result = Err(error);
            }
            if let Err(error) = diagnostic_result {
                eprintln!(
                    "razen: owned supervisor diagnostic drain failed for {}: {error}",
                    self.invocation_id
                );
            }
        }
        self.closing = true;
        if self.occupancy.transport.is_none() {
            // Reaping our actual Child proves its exit, not the identity of an unbound launch.
            // Keep the original uncertain reservation intact; never invent a terminated marker.
            drop(self.capacity.take());
            return Ok(());
        }
        if self.capacity.is_some() {
            let mut terminated = self.occupancy.clone();
            terminated.transport_terminated = true;
            let capacity = self
                .capacity
                .as_ref()
                .ok_or_else(|| integrity("Owned capacity disappeared during transport reaping"))?;
            if !self.occupancy.transport_terminated {
                capacity.replace(&self.occupancy, &terminated)?;
                self.occupancy = terminated;
            }
            if self.terminal.as_ref().is_some_and(|fact| {
                fact.invocation_id == self.invocation_id
                    && (fact.empty_cgroup || fact.vm_force_stopped)
            }) {
                if !self
                    .terminal
                    .as_ref()
                    .is_some_and(|fact| fact.vm_force_stopped)
                {
                    self.read_termination_record()?;
                }
                capacity.clear(&self.occupancy)?;
            }
            drop(self.capacity.take());
        }
        Ok(())
    }
    /// Deliberate SSH-loss fixture: this is NOT containment evidence.
    pub fn detach_transport(&mut self) -> ProofResult<u32> {
        let pid = self.child.id();
        self.reap_transport()?;
        Ok(pid)
    }
    pub fn containment(&self) -> Option<&Containment> {
        self.terminal.as_ref()
    }
    pub fn accept_independent_containment(&mut self, journal: &Value) -> ProofResult<()> {
        let measured = self.read_termination_record()?;
        if measured["invocation_id"] != journal["invocation_id"]
            || measured["lease_id"] != journal["lease_id"]
            || measured["empty_cgroup"] != true
            || measured["cgroup_populated_after"] != 0
            || measured["descendants_after"] != 0
        {
            return Err(integrity(
                "Independent containment evidence is not current or empty",
            ));
        }
        self.terminal = Some(Containment {
            invocation_id: self.invocation_id,
            empty_cgroup: true,
            vm_force_stopped: false,
            observed_vm_status: "Running".into(),
            elapsed_us: measured["lease_elapsed_us"]
                .as_u64()
                .ok_or_else(|| integrity("Independent lease elapsed observation is missing"))?,
        });
        self.reap_transport()
    }
    pub fn read_termination_record(&self) -> ProofResult<Value> {
        self.guest.termination_record(&self.occupancy)
    }
    fn force_stop_owned(&mut self) -> ProofResult<Containment> {
        if self.capacity.is_none() {
            let capacity = self.guest.raw_capacity_lock()?;
            let current = capacity.require_occupancy(&self.occupancy)?;
            self.guest.validate_occupancy(&current)?;
            self.occupancy = current;
            self.capacity = Some(capacity);
        }
        lifecycle::force_stop_invocation(
            &self.guest,
            self.capacity
                .as_ref()
                .ok_or_else(|| integrity("Owned stop capacity disappeared"))?,
            &self.occupancy,
        )
    }
    pub(super) fn occupancy_id(&self) -> EntityId {
        self.occupancy.occupancy_id
    }
}
impl Drop for GuestInvocation {
    fn drop(&mut self) {
        self.closing = true;
        if self.terminal.is_none() {
            if let Ok(record) = self.read_termination_record() {
                if let Some(elapsed_us) = record["lease_elapsed_us"].as_u64() {
                    self.terminal = Some(Containment {
                        invocation_id: self.invocation_id,
                        empty_cgroup: true,
                        vm_force_stopped: false,
                        observed_vm_status: "Running".into(),
                        elapsed_us,
                    });
                }
            } else {
                match self.force_stop_owned() {
                    Ok(result) => self.terminal = Some(result),
                    Err(error) => eprintln!(
                        "razen: containment refused or failed; durable guest occupancy remains sealed: {error}"
                    ),
                }
            }
        }
        if let Err(error) = self.reap_transport() {
            eprintln!(
                "razen: owned transport cleanup failed; durable guest occupancy remains sealed: {error}"
            );
        }
    }
}

pub fn encode_runtime_program(
    message_id: EntityId,
    start: &crate::protocol::messages::RuntimeStart,
) -> ProofResult<Vec<u8>> {
    let bytes = codec::encode_frame(
        &json!({"protocol":codec::PROTOCOL,"message_id":message_id,"kind":"start","payload":start}),
        65536,
    )?;
    codec::decode_frame(&bytes, 65536, ChannelRole::Runtime, Direction::HostToPeer)?;
    Ok(bytes)
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, symlink};
    use std::path::PathBuf;

    struct Home {
        root: PathBuf,
        path: PathBuf,
        owner: EntityId,
    }

    impl Home {
        fn new() -> Self {
            let root = std::env::temp_dir()
                .canonicalize()
                .unwrap()
                .join(format!("razen-private-diagnostics-{}", EntityId::new()));
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&root)
                .unwrap();
            let path = root.join("home");
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&path)
                .unwrap();
            let owner = EntityId::new();
            let mut marker = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(path.join(".razen-owner.json"))
                .unwrap();
            marker
                .write_all(
                    &serde_json::to_vec(&json!({
                        "owner_id": owner,
                        "uid": rustix::process::geteuid().as_raw(),
                    }))
                    .unwrap(),
                )
                .unwrap();
            Self { root, path, owner }
        }

        fn diagnostic(&self, invocation: EntityId) -> PathBuf {
            self.path
                .join(format!(".razen-diagnostic-{invocation}.stderr"))
        }
    }

    impl Drop for Home {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn diagnostic_overflow_retains_exact_private_prefix_without_exporting_untrusted_text() {
        let home = Home::new();
        let invocation = EntityId::new();
        let uid = rustix::process::geteuid().as_raw();
        let mut capture = PrivateDiagnostics::default();
        let mut bytes = vec![b'x'; 65536];
        let untrusted = b"credential-marker /Users/private-home \x1b[31m\n";
        bytes[..untrusted.len()].copy_from_slice(untrusted);
        capture
            .push(&home.path, home.owner, uid, invocation, &bytes[..32768])
            .unwrap();
        capture
            .push(&home.path, home.owner, uid, invocation, &bytes[32768..])
            .unwrap();
        assert!(
            capture
                .push(&home.path, home.owner, uid, invocation, b"overflow")
                .is_err()
        );
        capture.finish(invocation).unwrap();
        let path = home.diagnostic(invocation);
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        let metadata = std::fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }

    #[test]
    fn diagnostic_capture_preserves_foreign_owner_and_symlink_targets_without_adoption() {
        let home = Home::new();
        let uid = rustix::process::geteuid().as_raw();
        let outside = home.root.join("outside");
        std::fs::write(&outside, b"unrelated bytes").unwrap();
        let invocation = EntityId::new();
        let linked = home.diagnostic(invocation);
        symlink(&outside, &linked).unwrap();
        let mut capture = PrivateDiagnostics::default();
        assert!(
            capture
                .push(
                    &home.path,
                    home.owner,
                    uid,
                    invocation,
                    b"must not overwrite"
                )
                .is_err()
        );
        assert_eq!(std::fs::read(&outside).unwrap(), b"unrelated bytes");
        assert!(
            std::fs::symlink_metadata(&linked)
                .unwrap()
                .file_type()
                .is_symlink()
        );

        let invocation = EntityId::new();
        let mut capture = PrivateDiagnostics::default();
        assert!(
            capture
                .push(
                    &home.path,
                    EntityId::new(),
                    uid,
                    invocation,
                    b"foreign owner"
                )
                .is_err()
        );
        assert!(!home.diagnostic(invocation).exists());

        let alias = home.root.join("linked-home");
        symlink(&home.path, &alias).unwrap();
        let mut capture = PrivateDiagnostics::default();
        assert!(
            capture
                .push(&alias, home.owner, uid, invocation, b"symlinked home")
                .is_err()
        );
        assert!(!home.diagnostic(invocation).exists());
        assert_eq!(std::fs::read(&outside).unwrap(), b"unrelated bytes");
    }
}
