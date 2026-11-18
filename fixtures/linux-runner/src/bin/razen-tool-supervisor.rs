use razen_runner_fixtures::{
    Result,
    adversaries::Observers,
    attestation, fail,
    lifecycle::{self, Cgroup, Lease},
    sandbox,
    wire::{self, Direction, Role},
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::Path,
    time::{Duration, Instant},
};
fn main() {
    if let Err(error) = run() {
        eprintln!("razen supervisor: {error}");
        std::process::exit(1);
    }
}
fn run() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.first().map(String::as_str) {
        Some("--launcher") => sandbox::launcher(&args[1..]),
        Some("--compile-seccomp") if args.len() == 1 => {
            std::io::stdout().write_all(&sandbox::seccomp_bytes()?)?;
            Ok(())
        }
        Some("--inspect") if args.len() == 1 => {
            serde_json::to_writer(std::io::stdout(), &attestation::inspect()?)?;
            Ok(())
        }
        Some("--host-public-key") if args.len() == 1 => {
            root()?;
            let key = fs::read_to_string("/etc/ssh/ssh_host_ed25519_key.pub")?
                .split_whitespace()
                .take(2)
                .collect::<Vec<_>>()
                .join(" ");
            std::io::stdout().write_all(key.as_bytes())?;
            Ok(())
        }
        Some("--sudo-policy-hash") if args.len() == 1 => {
            root()?;
            std::io::stdout().write_all(attestation::sudo_policy_digest()?.as_bytes())?;
            Ok(())
        }
        Some("--stage") if args.len() == 1 => stage(),
        Some("--termination") if args.len() == 2 => {
            validate_id(&args[1])?;
            std::io::stdout().write_all(&lifecycle::read_bounded(
                &Path::new(lifecycle::ROOT)
                    .join(&args[1])
                    .join("termination.json"),
                wire::FRAME,
            )?)?;
            Ok(())
        }
        Some("--failure") if args.len() == 2 => {
            root()?;
            validate_id(&args[1])?;
            let directory = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(lifecycle::ROOT)?;
            let metadata = directory.metadata()?;
            if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
                return Err(fail("failure record directory is not root-private"));
            }
            let name = std::ffi::CString::new(format!("{}.failure.json", args[1]))?;
            // SAFETY: the root-private directory is held open and the UUID filename
            // has no path separators; the returned descriptor is adopted once.
            let fd = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            // SAFETY: openat returned this new owned descriptor.
            let file = unsafe { File::from_raw_fd(fd) };
            let metadata = file.metadata()?;
            if !metadata.is_file()
                || metadata.uid() != 0
                || metadata.mode() & 0o777 != 0o600
                || metadata.nlink() != 1
                || metadata.len() > wire::FRAME as u64
            {
                return Err(fail(
                    "failure record is not a bounded root-private regular file",
                ));
            }
            let mut bytes = Vec::with_capacity(metadata.len() as usize);
            file.take(wire::FRAME as u64 + 1).read_to_end(&mut bytes)?;
            if bytes.len() as u64 != metadata.len() || bytes.len() > wire::FRAME {
                return Err(fail("failure record length changed"));
            }
            std::io::stdout().write_all(&bytes)?;
            Ok(())
        }
        Some("--observe") if args.len() == 2 => {
            root()?;
            validate_id(&args[1])?;
            std::io::stdout().write_all(&lifecycle::read_bounded(
                &Path::new(lifecycle::ROOT)
                    .join(&args[1])
                    .join("output-count"),
                64,
            )?)?;
            Ok(())
        }
        Some("--runtime-input") if args.len() == 2 => runtime_input(&args[1]),
        Some("--serve") if args.len() == 1 => serve(),
        _ => Err(fail("unapproved supervisor operation")),
    }
}
fn validate_id(id: &str) -> Result<()> {
    if !wire::uuid(id) {
        return Err(fail("invalid invocation ID"));
    }
    Ok(())
}
fn root() -> Result<()> {
    // SAFETY: reads the current supervisor identity only.
    if unsafe { libc::geteuid() } != 0 {
        return Err(fail(
            "management operation requires dedicated root supervisor",
        ));
    }
    Ok(())
}
fn stage() -> Result<()> {
    root()?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(wire::FRAME as u64 + 1)
        .read_to_end(&mut bytes)?;
    let v = wire::unique(&bytes)?;
    wire::fields(
        &v,
        &[
            "invocation_id",
            "artifact_id",
            "snapshot_sha256",
            "snapshot_base64",
        ],
        &["host_canary_path"],
    )?;
    let invocation = wire::id(&v["invocation_id"])?;
    wire::id(&v["artifact_id"])?;
    use base64::Engine as _;
    let body = base64::engine::general_purpose::STANDARD.decode(
        v["snapshot_base64"]
            .as_str()
            .ok_or_else(|| fail("snapshot body missing"))?,
    )?;
    if body.len() > 65536 || sandbox::hash(&body) != v["snapshot_sha256"] {
        return Err(fail("staged snapshot immutable content mismatch"));
    }
    let dir = Path::new("/var/lib/razen/staged");
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir.join(format!("{invocation}.json")))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
fn runtime_input(invocation: &str) -> Result<()> {
    root()?;
    validate_id(invocation)?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(wire::FRAME as u64 + 1)
        .read_to_end(&mut bytes)?;
    wire::decode(&bytes, Role::Runtime, Direction::HostToPeer)?;
    let path = Path::new(lifecycle::ROOT).join(invocation);
    if path.join("termination.json").exists() {
        return Err(fail("terminal runtime cannot receive input"));
    }
    let mut fifo = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path.join("runtime.fifo"))?;
    let started = Instant::now();
    let mut offset = 0;
    while offset < bytes.len() {
        match fifo.write(&bytes[offset..]) {
            Ok(0) => return Err(fail("runtime input FIFO closed")),
            Ok(n) => offset += n,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    && started.elapsed() < Duration::from_millis(100) =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
struct Replies {
    queue: VecDeque<Vec<u8>>,
    offset: usize,
    bytes: usize,
    gone: bool,
}
impl Replies {
    fn new() -> Self {
        Self {
            queue: VecDeque::new(),
            offset: 0,
            bytes: 0,
            gone: false,
        }
    }
    fn add(&mut self, kind: &str, payload: Value, correlation: &str) -> Result<()> {
        if self.gone {
            return Ok(());
        }
        let bytes = wire::encode(
            kind,
            payload,
            Some(correlation),
            Role::Supervisor,
            Direction::PeerToHost,
        )?;
        if self.bytes + bytes.len() > 4 * 1024 * 1024 {
            return Err(fail("supervisor bounded output queue saturated"));
        }
        self.bytes += bytes.len();
        self.queue.push_back(bytes);
        Ok(())
    }
    fn fail(&mut self, payload: Value, correlation: &str) -> Result<()> {
        // Drop only wholly unsent frames. A partial front frame must finish first
        // or the following authenticated error would corrupt the wire stream.
        if self.offset == 0 {
            self.queue.clear();
            self.bytes = 0;
        } else if let Some(front) = self.queue.front() {
            self.bytes = front.len() - self.offset;
            self.queue.truncate(1);
        }
        self.add("error", payload, correlation)
    }
    fn flush(&mut self) -> Result<()> {
        while let Some(front) = self.queue.front() {
            match std::io::stdout().write(&front[self.offset..]) {
                Ok(0) => {
                    self.gone = true;
                    self.queue.clear();
                    self.bytes = 0;
                    break;
                }
                Ok(n) => {
                    self.offset += n;
                    self.bytes -= n;
                    if self.offset == front.len() {
                        self.queue.pop_front();
                        self.offset = 0;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                    self.gone = true;
                    self.queue.clear();
                    self.bytes = 0;
                    break;
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}
fn read_channel(file: &mut impl Read, pending: &mut Vec<u8>, cap: usize) -> Result<bool> {
    let mut buffer = [0u8; 65536];
    match file.read(&mut buffer) {
        Ok(0) => Ok(false),
        Ok(n) => {
            if pending.len() + n > cap {
                let keep = n.min(cap.saturating_add(1).saturating_sub(pending.len()));
                pending.extend_from_slice(&buffer[..keep]);
                return Err(fail("bounded channel exceeded frame capacity"));
            }
            pending.extend_from_slice(&buffer[..n]);
            Ok(true)
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
        Err(e) => Err(e.into()),
    }
}
fn take_line(bytes: &mut Vec<u8>) -> Option<Vec<u8>> {
    let end = bytes.iter().position(|b| *b == b'\n')?;
    Some(bytes.drain(..=end).collect())
}
fn serve() -> Result<()> {
    root()?;
    lifecycle::ignore_transport_signals()?;
    // SAFETY: this fixed entrypoint is single-threaded and holds no stdio or shared-library locks.
    let child = unsafe { libc::fork() };
    if child < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if child == 0 {
        // SAFETY: a newly forked non-group-leader detaches the root keeper from the SSH/sudo session.
        if unsafe { libc::setsid() } < 0 {
            // SAFETY: this failed fork child has not allocated an invocation; exit without resuming the parent wrapper.
            unsafe {
                libc::_exit(1);
            }
        }
        let result = serve_manager();
        let code = match result {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("independent guest manager: {error}");
                1
            }
        };
        // SAFETY: all manager-owned Rust resources were dropped by serve_manager; do not resume the SSH wrapper.
        unsafe {
            libc::_exit(code);
        }
    }
    let mut status = 0;
    loop {
        // SAFETY: child is this wrapper's exclusively owned fork child and status is writable.
        let waited = unsafe { libc::waitpid(child, &mut status, 0) };
        if waited == child {
            break;
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error.into());
        }
    }
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        return Err(fail("independent guest keeper failed"));
    }
    Ok(())
}
fn serve_manager() -> Result<()> {
    for fd in [0, 1, 2] {
        lifecycle::nonblocking(fd)?;
    }
    let epoch = Instant::now();
    let mut input = Vec::new();
    let launch_frame = loop {
        read_channel(&mut std::io::stdin(), &mut input, wire::FRAME)?;
        if let Some(frame) = take_line(&mut input) {
            break frame;
        }
        if epoch.elapsed() > Duration::from_secs(5) {
            return Err(fail("authenticated launch deadline"));
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let envelope = wire::decode(&launch_frame, Role::Supervisor, Direction::HostToPeer)?;
    if envelope.kind != "launch" {
        return Err(fail("first authenticated supervisor message must launch"));
    }
    let launch: wire::Launch = serde_json::from_value(envelope.payload)?;
    let mut failure = FailureReport::new();
    let mut cgroup = None;
    let mut child = None;
    let result = execute_launch(
        &launch,
        &envelope.message_id,
        epoch,
        input,
        &mut failure,
        &mut cgroup,
        &mut child,
    );
    if let Err(error) = result {
        // Capture the primary cause before any cleanup, diagnostic drain, or persistence.
        let cause = error_record(error.as_ref());
        let message = failure.public_message(error.as_ref());
        let (cleanup, cleanup_error) = if let Some(cgroup) = &mut cgroup {
            let (disposition, result) = cgroup.finish_failure();
            (
                disposition,
                result.err().map(|error| error_record(error.as_ref())),
            )
        } else {
            (
                json!({"operation":"not_attempted","reason":"no_returned_cgroup_handle","allocation_state":"unknown","empty_observation":null}),
                None,
            )
        };
        let drain = failure.drain(child.as_mut());
        failure.retain(
            &launch,
            &envelope.message_id,
            cause,
            cleanup,
            cleanup_error,
            drain,
        );
        // Preserve any partly written frame and its offset before appending the error.
        let payload = json!({"invocation_id":launch.invocation_id,"error":{"code":"isolation_unavailable","message":message,"retryability":"never","diagnostic_refs":[],"invocation_id":launch.invocation_id}});
        let _ = failure.replies.fail(payload, &envelope.message_id);
        let deadline = Instant::now() + Duration::from_millis(200);
        while !failure.replies.queue.is_empty()
            && !failure.replies.gone
            && Instant::now() < deadline
        {
            if failure.replies.flush().is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        return Err(fail(&message));
    }
    Ok(())
}
fn execute_launch(
    launch: &wire::Launch,
    correlation: &str,
    epoch: Instant,
    mut input: Vec<u8>,
    failure: &mut FailureReport,
    cgroup_slot: &mut Option<Cgroup>,
    child_slot: &mut Option<sandbox::Sandboxed>,
) -> Result<()> {
    failure.stage("launch", "validate_fixture");
    if !sandbox::FIXTURES.contains(&launch.approved_fixture_id.as_str()) {
        return Err(fail("unapproved fixture launch"));
    }
    failure.stage("staged_input", "read_decode");
    let staged = wire::unique(&lifecycle::read_bounded(
        &Path::new("/var/lib/razen/staged").join(format!("{}.json", launch.invocation_id)),
        wire::FRAME,
    )?)?;
    failure.stage("staged_input", "validate_references");
    if launch.input_artifact_refs.len() != 1
        || launch.input_artifact_refs[0].range_start.is_some()
        || launch.input_artifact_refs[0].range_end.is_some()
        || launch.input_artifact_refs[0].artifact_id != staged["artifact_id"]
        || launch.input_artifact_refs[0].sha256 != staged["snapshot_sha256"]
    {
        return Err(fail(
            "launch immutable approved input references differ from staged content",
        ));
    }
    let runtime_fixture =
        ["runtime", "runtime_blocked"].contains(&launch.approved_fixture_id.as_str());
    if runtime_fixture {
        use base64::Engine as _;
        failure.stage("runtime_start", "decode_validate_binding");
        let bytes = base64::engine::general_purpose::STANDARD.decode(
            staged["snapshot_base64"]
                .as_str()
                .ok_or_else(|| fail("immutable runtime start missing"))?,
        )?;
        let start = wire::decode(&bytes, Role::Runtime, Direction::HostToPeer)?;
        if start.kind != "start" || start.payload["binding_id"] != launch.binding_id {
            return Err(fail(
                "runtime program is not the current host-assigned launch binding",
            ));
        }
    }
    failure.stage("cgroup", "create");
    *cgroup_slot = Some(Cgroup::create(launch)?);
    let cgroup = cgroup_slot.as_mut().unwrap();
    failure.occupancy = cgroup.failure_occupancy();
    failure.stage("observers", "create_healthy_controls");
    let mut observers = if runtime_fixture {
        None
    } else {
        Some(Observers::new(&cgroup.directory)?)
    };
    let endpoints = observers
        .as_ref()
        .map(|o| o.endpoints.clone())
        .unwrap_or_else(|| json!({}));
    failure.stage("canaries", "resolve_previous");
    let other_id = fs::read_to_string("/var/lib/razen/last-invocation")
        .ok()
        .filter(|id| wire::uuid(id.trim()))
        .map(|id| id.trim().to_owned());
    if launch.approved_fixture_id == "other_invocation" && other_id.is_none() {
        return Err(fail(
            "real completed other-invocation canary is unavailable",
        ));
    }
    let other_path = other_id
        .as_ref()
        .map(|id| format!("{}/{id}/ownership-canary", lifecycle::ROOT))
        .unwrap_or_else(|| "/var/lib/razen/private-other/snapshot".into());
    let mut canaries = json!({"manager_canary":"/var/lib/razen/manager-canary","other_invocation":other_path,"credential":"/var/lib/razen/credentials/synthetic","ssh_private":"/etc/ssh/ssh_host_ed25519_key"});
    if let Some(host_canary) = staged.get("host_canary_path") {
        canaries["host_canary"] = host_canary.clone();
    }
    let mut healthy_canaries = Vec::new();
    for key in [
        "manager_canary",
        "other_invocation",
        "credential",
        "ssh_private",
    ] {
        failure.stage("canaries", key);
        let path = canaries[key].as_str().unwrap();
        let body = fs::read(path)?;
        if body.is_empty() {
            return Err(fail("real canary absent"));
        }
        healthy_canaries
            .push(json!({"variant":key,"read_bytes":body.len(),"sha256":sandbox::hash(&body)}));
    }
    let configuration = json!({"variant":launch.approved_fixture_id,"invocation_id":launch.invocation_id,"snapshot_sha256":staged["snapshot_sha256"],"control_revision":launch.control_revision,"endpoints":endpoints,"canaries":canaries});
    failure.stage("launcher", "start");
    *child_slot = Some(sandbox::start(
        cgroup,
        &launch.approved_fixture_id,
        &configuration,
    )?);
    let child = child_slot.as_mut().unwrap();
    failure.launcher_pid = Some(child.child.id());
    // Complete cgroup placement while the independently exec'd trusted launcher is blocked.
    failure.stage("launcher", "place");
    cgroup.place(child.child.id(), epoch)?;
    failure.placement_us = Some(cgroup.placement_us);
    failure.stage("launcher", "placement_gate");
    let mut release = child
        .release
        .take()
        .ok_or_else(|| fail("trusted final-placement gate was already consumed"))?;
    release.write_all(b"P")?;
    drop(release);
    failure.stage("probe", "read_validate");
    let setup_deadline = Instant::now() + Duration::from_secs(1);
    let probe = loop {
        failure.operation = "read_stdout";
        read_channel(&mut child.stdout, &mut failure.probe_stdout, wire::FRAME)?;
        failure.operation = "read_setup";
        read_channel(&mut child.setup, &mut failure.setup, wire::CHUNK)?;
        failure.operation = "read_stderr";
        read_channel(&mut child.stderr, &mut failure.probe_stderr, wire::CHUNK)?;
        if let Some(line) = take_line(&mut failure.probe_stdout) {
            failure.operation = "validate_launcher_handoff";
            if let Some(error) = child.launcher_failure.read()? {
                failure.stage("launcher", error.operation());
                return Err(error.into());
            }
            if !child.launcher_failure.exec_closed() {
                return Err(fail("trusted launcher diagnostic descriptor survived exec"));
            }
            keep_prefix(&mut failure.probe_line, &line);
            failure.operation = "decode_validate";
            let v = wire::unique(&line)?;
            wire::fields(&v, &["sandbox_probe"], &[])?;
            break v["sandbox_probe"].clone();
        }
        failure.operation = "wait_probe";
        if Instant::now() > setup_deadline || child.child.try_wait()?.is_some() {
            failure.operation = "read_launcher_failure";
            if let Some(error) = child.launcher_failure.read()? {
                failure.stage("launcher", error.operation());
                return Err(error.into());
            }
            failure.operation = "wait_probe";
            // Finalization preserves this primary cause even if cleanup also fails.
            return Err(fail(
                "mandatory filtered sandbox probe failed before release",
            ));
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    failure.stage("attestation", "attest");
    let attested = attestation::attest(launch, cgroup, &probe)?;
    failure.attestation_completed = true;
    // The timer is rooted in this manager and starts BEFORE any hostile release.
    let mut lease = Lease::new(launch.lease_id.clone(), launch.control_revision);
    failure.stage("release", "queue_ready");
    let replies = &mut failure.replies;
    replies.add(
        "ready",
        json!({"invocation_id":launch.invocation_id,"attestation":attested}),
        correlation,
    )?;
    replies.add(
        "started",
        json!({"invocation_id":launch.invocation_id}),
        correlation,
    )?;
    failure.phase = "release";
    failure.operation = "hostile_gate";
    child.input.write_all(b"R")?;
    let released_us = epoch.elapsed().as_micros();
    failure.released_us = Some(released_us);
    failure.phase = "runtime_fifo";
    failure.operation = "create_open";
    let runtime_fifo = cgroup.directory.join("runtime.fifo");
    let fifo_name = std::ffi::CString::new(runtime_fifo.as_os_str().as_encoded_bytes())?;
    // SAFETY: fifo_name is NUL-terminated and names a new owned root-private invocation file.
    if unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut runtime = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(runtime_fifo)?;
    failure.phase = "runtime_fifo";
    failure.operation = "configure_input";
    lifecycle::nonblocking(child.input.as_raw_fd())?;
    let mut stdout_prefix = Vec::new();
    let mut sequence = [0u64; 2];
    let mut output_bytes = 0u64;
    let mut tmpfs_peak = 0u64;
    let mut input_open = true;
    let mut outcome = "completed";
    let mut refreshes = 0u64;
    let mut reason = "process_exit";
    let mut runtime_pending = Vec::new();
    let status = loop {
        failure.phase = "management";
        failure.operation = "flush_replies";
        replies.flush()?;
        if let Some(observers) = &mut observers {
            failure.operation = "poll_observers";
            observers.poll()?;
        }
        failure.operation = "measure_tmpfs";
        tmpfs_peak = tmpfs_peak.max(cgroup.tmpfs_bytes()?);
        if input_open {
            failure.operation = "read_control";
            input_open = read_channel(&mut std::io::stdin(), &mut input, wire::FRAME)?;
        }
        while let Some(frame) = take_line(&mut input) {
            failure.operation = "authenticate_control";
            let request = wire::decode(&frame, Role::Supervisor, Direction::HostToPeer)?;
            let p = &request.payload;
            failure.operation = "authenticate_control";
            if p["binding_id"] != launch.binding_id
                || p["invocation_id"] != launch.invocation_id
                || p["lease_id"] != launch.lease_id
            {
                return Err(fail("foreign supervisor control binding"));
            }
            let revision = wire::number(&p["control_revision"])?;
            match request.kind.as_str() {
                "lease_refresh" => {
                    failure.operation = "refresh_lease";
                    if lease.refresh(&request.message_id, &launch.lease_id, revision)? {
                        refreshes += 1;
                    }
                }
                "cancel" | "close" => {
                    failure.operation = "cancel_lease";
                    lease.cancel(&launch.lease_id, revision)?;
                    outcome = "cancelled";
                    reason = "authenticated_cancel";
                }
                _ => return Err(fail("unexpected supervisor message after launch")),
            }
        }
        if launch.approved_fixture_id == "runtime"
            || launch.approved_fixture_id == "runtime_blocked"
        {
            failure.operation = "runtime_input";
            read_channel(&mut runtime, &mut runtime_pending, wire::FRAME)?;
            if !runtime_pending.is_empty() {
                match child.input.write(&runtime_pending) {
                    Ok(n) => {
                        runtime_pending.drain(..n);
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => {}
                }
            }
        }
        for (index, stream) in [(0, &mut child.stdout), (1, &mut child.stderr)] {
            failure.phase = "output";
            failure.operation = if index == 0 {
                "read_stdout"
            } else {
                "read_stderr"
            };
            let mut buffer = [0u8; wire::CHUNK];
            match stream.read(&mut buffer) {
                Ok(n) if n > 0 => {
                    keep_prefix(
                        if index == 0 {
                            &mut failure.stdout
                        } else {
                            &mut failure.stderr
                        },
                        &buffer[..n],
                    );
                    if index == 0 && launch.approved_fixture_id == "orphan" {
                        let keep = n.min(65536usize.saturating_sub(stdout_prefix.len()));
                        stdout_prefix.extend_from_slice(&buffer[..keep]);
                    }
                    let accepted = n.min((2097152u64 - output_bytes) as usize);
                    if accepted > 0 {
                        sequence[index] += 1;
                        output_bytes += accepted as u64;
                        replies.add("output",json!({"invocation_id":launch.invocation_id,"stream":if index==0{"stdout"}else{"stderr"},"sequence":sequence[index],"bytes_base64":wire::base64(&buffer[..accepted])}),correlation)?;
                    }
                    if n > accepted {
                        outcome = "budget_exhausted";
                        reason = "output_limit";
                        failure.operation = "cancel_output_limit";
                        lease.cancel(&launch.lease_id, lease.revision)?;
                    }
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
        if launch.approved_fixture_id == "orphan" {
            failure.phase = "output";
            failure.operation = "persist_count";
            fs::write(
                cgroup.directory.join("output-count"),
                output_bytes.to_string(),
            )?;
        }
        if lease.expired() {
            if reason == "process_exit" {
                outcome = "budget_exhausted";
                reason = if lease.started.elapsed() >= Duration::from_secs(5) {
                    "wall_deadline"
                } else {
                    "orphan_lease_expired"
                };
            }
            failure.phase = "cleanup";
            failure.operation = "lease_kill_empty";
            failure.empty_observation = Some(cgroup.kill_empty()?);
            failure.operation = "wait_child";
            break child.child.wait()?;
        }
        failure.phase = "management";
        failure.operation = "poll_child";
        if let Some(status) = child.child.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(2));
    };
    failure.phase = "cleanup";
    failure.operation = "kill_empty";
    let containment = cgroup.kill_empty()?;
    failure.empty_observation = Some(containment.clone());
    if let Some(observers) = &mut observers {
        failure.operation = "poll_observers";
        observers.poll()?;
    }
    let drain_start = Instant::now();
    let mut eof = [false; 2];
    while !eof.iter().all(|v| *v) && drain_start.elapsed() < Duration::from_millis(200) {
        for (index, stream) in [(0, &mut child.stdout), (1, &mut child.stderr)] {
            failure.phase = "output_drain";
            failure.operation = if index == 0 {
                "read_stdout"
            } else {
                "read_stderr"
            };
            let mut buffer = [0u8; wire::CHUNK];
            match stream.read(&mut buffer) {
                Ok(0) => eof[index] = true,
                Ok(n) => {
                    if index == 0 && launch.approved_fixture_id == "orphan" {
                        let keep = n.min(65536usize.saturating_sub(stdout_prefix.len()));
                        stdout_prefix.extend_from_slice(&buffer[..keep]);
                    }
                    keep_prefix(
                        if index == 0 {
                            &mut failure.stdout
                        } else {
                            &mut failure.stderr
                        },
                        &buffer[..n],
                    );
                    let accepted = n.min((2097152u64 - output_bytes) as usize);
                    if accepted > 0 {
                        sequence[index] += 1;
                        output_bytes += accepted as u64;
                        replies.add("output",json!({"invocation_id":launch.invocation_id,"stream":if index==0{"stdout"}else{"stderr"},"sequence":sequence[index],"bytes_base64":wire::base64(&buffer[..accepted])}),correlation)?;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
        }
        failure.operation = "flush_replies";
        replies.flush()?;
        std::thread::sleep(Duration::from_millis(1));
    }
    failure.operation = "require_eof";
    if !eof.iter().all(|v| *v) {
        return Err(fail(
            "terminated owned cgroup output pipes did not reach EOF",
        ));
    }
    if launch.approved_fixture_id == "orphan" {
        failure.operation = "persist_count";
        fs::write(
            cgroup.directory.join("output-count"),
            output_bytes.to_string(),
        )?;
    }
    use std::os::unix::process::ExitStatusExt;
    if !status.success() && outcome == "completed" {
        outcome = "failed";
    }
    failure.phase = "journal";
    failure.operation = "read_memory_events";
    let memory_events = fs::read_to_string(cgroup.path.join("memory.events"))?;
    if memory_events.lines().any(|line| {
        line.split_once(' ').is_some_and(|(key, value)| {
            key == "oom_kill" && value.parse::<u64>().is_ok_and(|value| value > 0)
        })
    }) {
        outcome = "budget_exhausted";
        reason = "memory_limit";
    }
    failure.operation = "measure_usage";
    let usage = cgroup.usage(output_bytes, tmpfs_peak)?;
    let mut terminated =
        json!({"invocation_id":launch.invocation_id,"outcome":outcome,"empty_cgroup":true});
    if let Some(code) = status.code() {
        terminated["exit_code"] = json!(code);
    } else if let Some(signal) = status.signal() {
        terminated["signal"] = json!(signal);
    }
    failure.operation = "collect_facts";
    let journal = json!({"invocation_id":launch.invocation_id,"lease_id":launch.lease_id,"guest_manager_pid":cgroup.manager_pid,"launcher_pid":cgroup.placed_pid,"placement_us":cgroup.placement_us,"release_us":released_us,"empty_cgroup":containment["empty_cgroup"],"cgroup_populated_after":containment["cgroup_populated_after"],"descendants_after":containment["descendants_after"],"empty_observation":containment,"lease_elapsed_us":lease.started.elapsed().as_micros(),"lease_refreshes":refreshes,"termination_reason":reason,"outcome":outcome,"status_code":status.code(),"signal":status.signal(),"usage":usage,"observers":observers.as_ref().map(Observers::facts).unwrap_or_default(),"healthy_canaries":healthy_canaries,"probe":probe,"attestation":attested,"supervisor_termination":terminated,"stdout_prefix_base64":wire::base64(&stdout_prefix),"memory_events":memory_events,"pids_events":fs::read_to_string(cgroup.path.join("pids.events"))?,"cpu_stat":fs::read_to_string(cgroup.path.join("cpu.stat"))?});
    let mut journal = journal;
    journal["other_invocation_id"] = json!(other_id);
    journal["binding_id"] = json!(launch.binding_id);
    journal["run_id"] = json!(launch.run_id);
    journal["profile_sha256"] = json!(launch.profile_sha256);
    journal["owner_id"] = json!(cgroup.owner_id());
    journal["native_occupancy_sha256"] = json!(cgroup.occupancy_sha256()?);
    journal["control_revision"] = json!(lease.revision);
    failure.operation = "decode_setup";
    journal["bwrap_setup"] = wire::unique(&failure.setup)?;
    failure.operation = "read_namespaces";
    let mut manager_namespaces = serde_json::Map::new();
    for name in ["user", "mnt", "pid", "ipc", "uts", "net", "cgroup"] {
        manager_namespaces.insert(
            name.into(),
            json!(fs::read_link(format!("/proc/self/ns/{name}"))?.to_string_lossy()),
        );
    }
    journal["manager_namespaces"] = Value::Object(manager_namespaces);
    failure.operation = "hash_owner_canary";
    journal["owner_canary_sha256"] = json!(sandbox::file_hash(
        &cgroup.directory.join("ownership-canary")
    )?);
    failure.operation = "persist_termination";
    cgroup.journal(&journal)?;
    failure.operation = "persist_last_invocation";
    fs::write("/var/lib/razen/last-invocation", &launch.invocation_id)?;
    failure.operation = "queue_terminal";
    replies.add("usage", usage, correlation)?;
    replies.add("terminated", terminated, correlation)?;
    failure.operation = "flush_terminal";
    let flush = Instant::now();
    while !replies.queue.is_empty() && !replies.gone && flush.elapsed() < Duration::from_millis(200)
    {
        replies.flush()?;
        std::thread::sleep(Duration::from_millis(1));
    }
    Ok(())
}

// Failure records are diagnostic evidence, never successful termination journals.
struct FailureReport {
    phase: &'static str,
    operation: &'static str,
    provenance: Value,
    occupancy: Value,
    attestation_completed: bool,
    released_us: Option<u128>,
    launcher_pid: Option<u32>,
    placement_us: Option<u128>,
    empty_observation: Option<Value>,
    setup: Vec<u8>,
    probe_stdout: Vec<u8>,
    probe_line: Vec<u8>,
    probe_stderr: Vec<u8>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    replies: Replies,
}
impl FailureReport {
    fn new() -> Self {
        Self {
            phase: "launch",
            operation: "validate_fixture",
            provenance: observed_provenance().unwrap_or_else(
                |error| json!({"status":"unavailable","error":error_record(error.as_ref())}),
            ),
            occupancy: Value::Null,
            attestation_completed: false,
            released_us: None,
            launcher_pid: None,
            placement_us: None,
            empty_observation: None,
            setup: Vec::new(),
            probe_stdout: Vec::new(),
            probe_line: Vec::new(),
            probe_stderr: Vec::new(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            replies: Replies::new(),
        }
    }
    fn stage(&mut self, phase: &'static str, operation: &'static str) {
        self.phase = phase;
        self.operation = operation;
    }
    fn public_message(&self, error: &(dyn std::error::Error + 'static)) -> String {
        let (classification, errno) = error_classification(error);
        format!(
            "Mandatory guest isolation or management failed; stage={}; operation={}; class={}; errno={}; successful containment is not inferred",
            self.phase,
            self.operation,
            classification,
            errno
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".into()),
        )
    }
    fn drain(&mut self, child: Option<&mut sandbox::Sandboxed>) -> Value {
        let Some(child) = child else {
            return json!({"attempted":false});
        };
        let mut eof = [false; 3];
        let mut errors = [false; 3];
        let deadline = Instant::now() + Duration::from_millis(200);
        while Instant::now() < deadline && !eof.iter().zip(errors).all(|(end, error)| *end || error)
        {
            for (index, stream) in [
                (0, &mut child.stdout),
                (1, &mut child.stderr),
                (2, &mut child.setup),
            ] {
                if eof[index] || errors[index] {
                    continue;
                }
                let mut bytes = [0; wire::CHUNK];
                match stream.read(&mut bytes) {
                    Ok(0) => eof[index] = true,
                    Ok(n) => {
                        let prefix = match (index, self.released_us.is_some()) {
                            (0, true) => &mut self.stdout,
                            (0, false) => &mut self.probe_stdout,
                            (1, true) => &mut self.stderr,
                            (1, false) => &mut self.probe_stderr,
                            _ => &mut self.setup,
                        };
                        keep_prefix(prefix, &bytes[..n]);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(_) => errors[index] = true,
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        json!({"attempted":true,"stream_order":["stdout","stderr","setup"],"eof":eof,"read_failed":errors,"deadline_ms":200})
    }
    fn retain(
        &self,
        launch: &wire::Launch,
        correlation: &str,
        cause: Value,
        cleanup: Value,
        cleanup_error: Option<Value>,
        drain: Value,
    ) {
        let record = json!({
            "record_type":"native_invocation_failure",
            "version":1,
            "outcome":"failed",
            "invocation_id":launch.invocation_id,
            "binding_id":launch.binding_id,
            "run_id":launch.run_id,
            "lease_id":launch.lease_id,
            "requested_attestation_id":launch.attestation_id,
            "profile_sha256":launch.profile_sha256,
            "approved_fixture_id":launch.approved_fixture_id,
            "launch_message_id":correlation,
            "initial_control_revision":launch.control_revision,
            "guest_manager_pid":std::process::id(),
            "launcher_pid":self.launcher_pid,
            "placement_us":self.placement_us,
            "provenance":self.provenance,
            "allocated_occupancy":self.occupancy,
            "stage":self.phase,
            "operation":self.operation,
            "cause":cause,
            "attestation_completed":self.attestation_completed,
            "hostile_release_us":self.released_us,
            "prior_empty_observation":self.empty_observation,
            "cleanup":cleanup,
            "cleanup_error":cleanup_error,
            "diagnostic_drain":drain,
            "prefix_limit_bytes":wire::CHUNK,
            "prefixes":{
                "bwrap_setup":prefix_record(&self.setup),
                "probe_stdout_pending":prefix_record(&self.probe_stdout),
                "probe_line":prefix_record(&self.probe_line),
                "probe_stderr":prefix_record(&self.probe_stderr),
                "stdout":prefix_record(&self.stdout),
                "stderr":prefix_record(&self.stderr)
            }
        });
        if write_failure(launch, &record).is_err() {
            // Persistence failure must not hide the original safe stage/errno reply.
            eprintln!("razen: private native failure record could not be persisted");
        }
    }
}
fn keep_prefix(prefix: &mut Vec<u8>, bytes: &[u8]) {
    // One sentinel byte distinguishes an exactly full prefix from actual truncation.
    let keep = bytes
        .len()
        .min((wire::CHUNK + 1).saturating_sub(prefix.len()));
    prefix.extend_from_slice(&bytes[..keep]);
}
fn prefix_record(bytes: &[u8]) -> Value {
    let retained = bytes.len().min(wire::CHUNK);
    json!({"bytes_base64":wire::base64(&bytes[..retained]),"retained_bytes":retained,"truncated":bytes.len()>wire::CHUNK})
}
fn error_classification(
    mut error: &(dyn std::error::Error + 'static),
) -> (&'static str, Option<i32>) {
    let mut classification = "other_error";
    for _ in 0..wire::CHUNK {
        if let Some(io) = error.downcast_ref::<std::io::Error>() {
            classification = "io_error";
            if let Some(errno) = io.raw_os_error() {
                return ("os_error", Some(errno));
            }
        }
        let Some(source) = error.source() else { break };
        error = source;
    }
    (classification, None)
}
struct ErrorText {
    bytes: Vec<u8>,
    truncated: bool,
}
impl std::fmt::Write for ErrorText {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let keep = text.len().min(wire::CHUNK.saturating_sub(self.bytes.len()));
        self.bytes.extend_from_slice(&text.as_bytes()[..keep]);
        self.truncated |= keep < text.len();
        if self.truncated {
            Err(std::fmt::Error)
        } else {
            Ok(())
        }
    }
}
fn error_record(error: &(dyn std::error::Error + 'static)) -> Value {
    use std::fmt::Write as _;
    let (classification, errno) = error_classification(error);
    let mut text = ErrorText {
        bytes: Vec::new(),
        truncated: false,
    };
    let mut current = error;
    let mut complete = false;
    for index in 0..wire::CHUNK {
        if index > 0 && text.write_str("\ncaused by: ").is_err() {
            break;
        }
        if write!(&mut text, "{current}").is_err() {
            break;
        }
        let Some(source) = current.source() else {
            complete = true;
            break;
        };
        current = source;
    }
    json!({"classification":classification,"raw_os_errno":errno,"chain_base64":wire::base64(&text.bytes),"retained_bytes":text.bytes.len(),"truncated":!complete})
}
fn observed_provenance() -> Result<Value> {
    let bytes = lifecycle::read_bounded(Path::new(attestation::METADATA), wire::FRAME)?;
    let metadata = wire::unique(&bytes)?;
    let mut observed = json!({"status":"observed","provenance_sha256":sandbox::hash(&bytes)});
    for key in [
        "owner_id",
        "source_sha256",
        "profile_sha256",
        "provisioning_sha256",
        "configuration_sha256",
    ] {
        let value = metadata[key]
            .as_str()
            .ok_or_else(|| fail("provenance association missing"))?;
        if value.len() > 64 {
            return Err(fail("provenance association exceeds bound"));
        }
        observed[key] = json!(value);
    }
    Ok(observed)
}
fn write_failure(launch: &wire::Launch, record: &Value) -> Result<()> {
    validate_id(&launch.invocation_id)?;
    let bytes = serde_json::to_vec(record)?;
    if bytes.len() > wire::FRAME {
        return Err(fail("private failure record exceeds bound"));
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(lifecycle::ROOT)?;
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o077 != 0 {
        return Err(fail("failure record parent is not root-private"));
    }
    let name = std::ffi::CString::new(format!("{}.failure.json", launch.invocation_id))?;
    // SAFETY: the validated private directory FD and NUL-terminated single-component
    // name pin creation to that directory; exclusive/no-follow creation never adopts a file.
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: openat returned a new uniquely owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&bytes)?;
    file.sync_all()?;
    directory.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    fn decoded_field(record: &Value, field: &str) -> Vec<u8> {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD
            .decode(record[field].as_str().unwrap())
            .unwrap()
    }

    #[test]
    fn private_prefixes_preserve_exact_bytes_and_distinguish_full_from_truncated() {
        let input = (0..wire::CHUNK)
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let mut prefix = Vec::new();
        for chunk in input.chunks(97) {
            keep_prefix(&mut prefix, chunk);
        }
        let exact = prefix_record(&prefix);
        assert_eq!(decoded_field(&exact, "bytes_base64"), input);
        assert_eq!(exact["retained_bytes"], wire::CHUNK);
        assert_eq!(exact["truncated"], false);

        keep_prefix(&mut prefix, &[255]);
        keep_prefix(&mut prefix, &[254; 4096]);
        let overflow = prefix_record(&prefix);
        assert_eq!(decoded_field(&overflow, "bytes_base64"), input);
        assert_eq!(overflow["retained_bytes"], wire::CHUNK);
        assert_eq!(overflow["truncated"], true);
    }

    #[derive(Debug)]
    struct PrivateFailure(std::io::Error);
    impl std::fmt::Display for PrivateFailure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .write_str("TEST_PRIVATE_DIAGNOSTIC_DO_NOT_PUBLISH /private/test-key\u{1b}[31m\n")
        }
    }
    impl std::error::Error for PrivateFailure {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(&self.0)
        }
    }

    #[test]
    fn wrapped_errno_survives_without_exporting_private_error_text() {
        let error = PrivateFailure(std::io::Error::from_raw_os_error(libc::EPERM));
        let mut failure = FailureReport::new();
        failure.stage("launch", "validate_fixture");
        let public = failure.public_message(&error);
        assert!(public.contains("class=os_error; errno=1;"));
        assert!(!public.contains("TEST_PRIVATE_DIAGNOSTIC_DO_NOT_PUBLISH"));
        assert!(!public.contains("/private/"));
        assert!(!public.bytes().any(|byte| byte.is_ascii_control()));

        let private = error_record(&error);
        assert_eq!(private["raw_os_errno"], libc::EPERM);
        assert_eq!(private["truncated"], false);
        assert!(
            decoded_field(&private, "chain_base64")
                .starts_with(b"TEST_PRIVATE_DIAGNOSTIC_DO_NOT_PUBLISH /private/test-key")
        );
    }

    #[test]
    fn oversized_error_chains_retain_a_bounded_exact_prefix_with_truncation() {
        let error = std::io::Error::other("x".repeat(wire::CHUNK + 1));
        let private = error_record(&error);
        assert_eq!(private["classification"], "io_error");
        assert!(private["raw_os_errno"].is_null());
        assert_eq!(private["truncated"], true);
        assert_eq!(
            decoded_field(&private, "chain_base64"),
            vec![b'x'; wire::CHUNK]
        );
    }

    #[test]
    fn actual_unstaged_launch_retains_a_private_bound_failure_without_claiming_containment() {
        const SUPERVISOR: &str = "/usr/local/libexec/razen-tool-supervisor";
        let provenance = observed_provenance()
            .expect("the actual prepared native supervisor provenance is required");
        let invocation_id = wire::new_id().unwrap();
        let binding_id = wire::new_id().unwrap();
        let run_id = wire::new_id().unwrap();
        let lease_id = wire::new_id().unwrap();
        let attestation_id = wire::new_id().unwrap();
        let message_id = wire::new_id().unwrap();
        let staged = Path::new("/var/lib/razen/staged").join(format!("{invocation_id}.json"));
        assert!(!staged.try_exists().unwrap());
        let frame = wire::encode_with_id(
            &message_id,
            "launch",
            json!({
                "binding_id":binding_id,
                "invocation_id":invocation_id,
                "run_id":run_id,
                "attestation_id":attestation_id,
                "profile_sha256":provenance["profile_sha256"],
                "approved_fixture_id":"runtime_blocked",
                "input_artifact_refs":[{
                    "artifact_id":wire::new_id().unwrap(),
                    "sha256":"0".repeat(64)
                }],
                "lease_id":lease_id,
                "control_revision":0
            }),
            None,
            Role::Supervisor,
            Direction::HostToPeer,
        )
        .unwrap();
        let mut child = std::process::Command::new(SUPERVISOR)
            .arg("--serve")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let written = input.write_all(&frame);
        let output = child.wait_with_output().unwrap();
        written.unwrap();
        assert!(!output.status.success());
        let reply = wire::decode(&output.stdout, Role::Supervisor, Direction::PeerToHost).unwrap();
        assert_eq!(reply.correlation_id.as_deref(), Some(message_id.as_str()));
        assert_eq!(reply.payload["error"]["code"], "isolation_unavailable");
        let message = reply.payload["error"]["message"].as_str().unwrap();
        assert!(message.contains("stage=staged_input; operation=read_decode;"));
        assert!(message.contains("class=os_error; errno=2;"));
        assert!(!message.contains("/var/lib/razen/"));

        let output = std::process::Command::new(SUPERVISOR)
            .args(["--failure", &invocation_id])
            .output()
            .unwrap();
        assert!(output.status.success());
        let record = wire::unique(&output.stdout).unwrap();
        assert_eq!(record["record_type"], "native_invocation_failure");
        assert_eq!(record["outcome"], "failed");
        assert_eq!(record["invocation_id"], invocation_id);
        assert_eq!(record["binding_id"], binding_id);
        assert_eq!(record["run_id"], run_id);
        assert_eq!(record["lease_id"], lease_id);
        assert_eq!(record["requested_attestation_id"], attestation_id);
        assert_eq!(record["launch_message_id"], message_id);
        assert_eq!(record["cause"]["raw_os_errno"], libc::ENOENT);
        assert_eq!(record["attestation_completed"], false);
        assert!(record["hostile_release_us"].is_null());
        assert!(record["allocated_occupancy"].is_null());
        assert_eq!(record["cleanup"]["operation"], "not_attempted");
        assert!(record["cleanup_error"].is_null());
        let path = Path::new(lifecycle::ROOT).join(format!("{invocation_id}.failure.json"));
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), 0);
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.nlink(), 1);
    }
}

#[cfg(test)]
mod launcher_failure_tests {
    use super::*;
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };
    use std::io::{Seek, SeekFrom};

    const POISON: &[u8] = b"{owned-launcher-regression-interrupted-occupancy";

    struct RestoreOccupancy {
        file: File,
        original: Vec<u8>,
        active: bool,
    }
    impl RestoreOccupancy {
        fn restore(&mut self) -> std::io::Result<()> {
            if !self.active {
                return Ok(());
            }
            self.file.seek(SeekFrom::Start(0))?;
            let mut current = Vec::new();
            self.file.read_to_end(&mut current)?;
            if !current.starts_with(&self.original)
                || !POISON.starts_with(&current[self.original.len()..])
            {
                return Err(std::io::Error::other("foreign occupancy change preserved"));
            }
            self.file.set_len(self.original.len() as u64)?;
            self.file.sync_all()?;
            self.active = false;
            Ok(())
        }
    }
    impl Drop for RestoreOccupancy {
        fn drop(&mut self) {
            let _ = self.restore();
        }
    }

    #[test]
    fn real_launcher_errno_survives_a_separate_owned_cleanup_failure() {
        let provenance = observed_provenance()
            .expect("actual prepared native supervisor provenance is required");
        let invocation_id = wire::new_id().unwrap();
        let artifact_id = wire::new_id().unwrap();
        let body = b"public native launcher failure regression";
        let launch: wire::Launch = serde_json::from_value(json!({
            "binding_id":wire::new_id().unwrap(),
            "invocation_id":invocation_id,
            "run_id":wire::new_id().unwrap(),
            "attestation_id":wire::new_id().unwrap(),
            "profile_sha256":provenance["profile_sha256"],
            "approved_fixture_id":"snapshot_control",
            "input_artifact_refs":[{
                "artifact_id":artifact_id,
                "sha256":sandbox::hash(body)
            }],
            "lease_id":wire::new_id().unwrap(),
            "control_revision":0
        }))
        .unwrap();
        let staged = serde_json::to_vec(&json!({
            "invocation_id":invocation_id,
            "artifact_id":artifact_id,
            "snapshot_sha256":sandbox::hash(body),
            "snapshot_base64":wire::base64(body)
        }))
        .unwrap();
        let mut stage = std::process::Command::new("/usr/local/libexec/razen-tool-supervisor")
            .arg("--stage")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let written = stage.stdin.take().unwrap().write_all(&staged);
        let staged = stage.wait_with_output().unwrap();
        written.unwrap();
        assert!(staged.status.success());

        // This kernel filter affects only this test thread and its launcher child.
        // Sibling tests are unaffected; no production policy or installed binary changes.
        let rule = SeccompRule::new(vec![
            SeccompCondition::new(
                1,
                SeccompCmpArgLen::Qword,
                SeccompCmpOp::Eq,
                libc::RLIMIT_NOFILE as u64,
            )
            .unwrap(),
            SeccompCondition::new(2, SeccompCmpArgLen::Qword, SeccompCmpOp::Ne, 0).unwrap(),
        ])
        .unwrap();
        let filter: BpfProgram = SeccompFilter::new(
            std::collections::BTreeMap::from([(libc::SYS_prlimit64, vec![rule])]),
            SeccompAction::Allow,
            SeccompAction::Errno(libc::EPERM as u32),
            TargetArch::aarch64,
        )
        .unwrap()
        .try_into()
        .unwrap();
        seccompiler::apply_filter(&filter).unwrap();

        let correlation = wire::new_id().unwrap();
        let mut failure = FailureReport::new();
        let mut cgroup = None;
        let mut child = None;
        let error = execute_launch(
            &launch,
            &correlation,
            Instant::now(),
            Vec::new(),
            &mut failure,
            &mut cgroup,
            &mut child,
        )
        .unwrap_err();
        assert_eq!(failure.phase, "launcher");
        assert_eq!(failure.operation, "launcher.setrlimit_nofile");
        let cause = error_record(error.as_ref());
        assert_eq!(cause["raw_os_errno"], libc::EPERM);
        let message = failure.public_message(error.as_ref());
        assert!(message.contains("operation=launcher.setrlimit_nofile;"));
        assert!(message.contains("class=os_error; errno=1;"));
        assert!(!child.as_mut().unwrap().child.wait().unwrap().success());
        cgroup.as_mut().unwrap().kill_empty().unwrap();

        // Poison only this fixture's canonical record after actual child exit/emptiness.
        // The guard restores only our exact appended bytes, including on assertion failure.
        let mut restore = RestoreOccupancy {
            file: OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open("/var/lib/razen/invocation.lock")
                .unwrap(),
            original: fs::read("/var/lib/razen/invocation.lock").unwrap(),
            active: true,
        };
        restore.file.seek(SeekFrom::End(0)).unwrap();
        restore.file.write_all(POISON).unwrap();
        restore.file.sync_all().unwrap();
        let (cleanup, cleanup_result) = cgroup.as_mut().unwrap().finish_failure();
        let cleanup_error = cleanup_result.unwrap_err();
        let drain = failure.drain(child.as_mut());
        failure.retain(
            &launch,
            &correlation,
            cause,
            cleanup,
            Some(error_record(cleanup_error.as_ref())),
            drain,
        );
        let record = wire::unique(
            &fs::read(Path::new(lifecycle::ROOT).join(format!("{invocation_id}.failure.json")))
                .unwrap(),
        )
        .unwrap();
        assert_eq!(record["operation"], "launcher.setrlimit_nofile");
        assert_eq!(record["cause"]["raw_os_errno"], libc::EPERM);
        assert!(record["cleanup_error"].is_object());
        assert_eq!(record["cleanup"]["operation"], "kill_empty");
        assert_eq!(record["attestation_completed"], false);
        assert!(record["hostile_release_us"].is_null());
        restore.restore().unwrap();
        drop(child);
        drop(cgroup);

        let mut successor = launch;
        successor.invocation_id = wire::new_id().unwrap();
        successor.binding_id = wire::new_id().unwrap();
        successor.run_id = wire::new_id().unwrap();
        successor.attestation_id = wire::new_id().unwrap();
        successor.lease_id = wire::new_id().unwrap();
        drop(Cgroup::create(&successor).expect("real empty old group must permit safe reuse"));
        assert!(
            lifecycle::read_bounded(Path::new("/var/lib/razen/invocation.lock"), 16384)
                .unwrap()
                .is_empty()
        );
    }
}
