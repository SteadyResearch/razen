use super::{
    ComponentCapacity, SlotKind,
    bindings::{InvocationContext, Observation},
    error, invalid,
    runner::{ReadReply, RunnerFrame, RunnerInput, StoreFacts},
    snapshot_reader::{ReadFact, SnapshotBroker},
};
use crate::adapters::command::{CommandLimits, capture};
use crate::application::profile::LoadedProfile;
use crate::domain::values::{Digest, EntityId};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, kill_process_group, waitid};
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs::{File, Metadata};
use std::io::{ErrorKind, Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::{fs::MetadataExt, net::UnixStream, process::CommandExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant};

pub const VARIANTS: [&str; 6] = [
    "fixture-valid",
    "fixture-loop",
    "fixture-grow",
    "fixture-output",
    "fixture-host-call",
    "fixture-denied-access",
];
pub const WIT_SHA256: &str = "c1fa7edeab97ff43ccca45f898a5155f8c43cfb06937be8c247bcde1b0e760c9";
pub const WASMTIME_VERSION: &str = "50.0.2";
pub const WIT_BINDGEN_VERSION: &str = "0.63.0";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovedComponent {
    pub variant: String,
    pub file: String,
    pub sha256: Digest,
    pub length_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildManifest {
    pub schema_version: String,
    pub rust: String,
    pub target: String,
    pub wit_bindgen: String,
    pub wasmtime: String,
    pub wit_sha256: Digest,
    pub lock_sha256: Digest,
    pub guest_manifest_sha256: Digest,
    pub guest_source_sha256: Digest,
    pub bindings_sha256: Digest,
    pub helper_sha256: Digest,
    pub runner_sha256: Digest,
    pub variants: Vec<ApprovedComponent>,
}
pub struct ApprovedComponents {
    root: PathBuf,
    runner: PathBuf,
    pub manifest: BuildManifest,
    pub manifest_sha256: Digest,
}
impl ApprovedComponents {
    pub fn load(repo: &Path, profile: &LoadedProfile) -> ProofResult<Self> {
        let root = repo.canonicalize().map_err(|_| invalid())?;
        let bytes = bounded_file(
            &root.join("target/proof-components/build-manifest.json"),
            16_384,
        )?;
        let manifest: BuildManifest = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if manifest.schema_version != "0.1.0"
            || manifest.rust != profile.config().toolchain.rust
            || manifest.target != "wasm32-wasip2"
            || manifest.wit_bindgen != WIT_BINDGEN_VERSION
            || manifest.wasmtime != WASMTIME_VERSION
            || manifest.wit_sha256 != Digest::parse(WIT_SHA256)?
            || manifest.variants.len() != 6
        {
            return Err(invalid());
        }
        for (relative, expected) in [
            (
                "specs/001-r0-feasibility/contracts/plugin-sdk.wit",
                manifest.wit_sha256,
            ),
            ("fixtures/components/Cargo.lock", manifest.lock_sha256),
            (
                "fixtures/components/Cargo.toml",
                manifest.guest_manifest_sha256,
            ),
            (
                "fixtures/components/src/lib.rs",
                manifest.guest_source_sha256,
            ),
            (
                "fixtures/components/src/bindings.rs",
                manifest.bindings_sha256,
            ),
            ("scripts/proofs/build-components.sh", manifest.helper_sha256),
        ] {
            if Digest::of(&bounded_file(&root.join(relative), 1024 * 1024)?) != expected {
                return Err(error(
                    ErrorCode::IntegrityError,
                    "Approved component build inputs changed",
                ));
            }
        }
        let mut seen = 0_u8;
        for (position, entry) in manifest.variants.iter().enumerate() {
            let variant = VARIANTS
                .iter()
                .position(|variant| *variant == entry.variant)
                .ok_or_else(invalid)?;
            let bit = 1_u8 << variant;
            if entry.file.strip_suffix(".wasm") != Some(entry.variant.as_str())
                || seen & bit != 0
                || manifest.variants[..position]
                    .iter()
                    .any(|prior| prior.sha256 == entry.sha256)
            {
                return Err(invalid());
            }
            seen |= bit;
            let (digest, length) = file_digest(
                &root.join("target/proof-components").join(&entry.file),
                16 * 1024 * 1024,
                Some(b"\0asm\x0d\0\x01\0"),
            )?;
            if length != entry.length_bytes || digest != entry.sha256 {
                return Err(error(
                    ErrorCode::IntegrityError,
                    "Approved native component bytes changed",
                ));
            }
        }
        let runner = root.join("target/debug/razen-component-runner");
        if file_digest(&runner, 512 * 1024 * 1024, None)?.0 != manifest.runner_sha256 {
            return Err(error(
                ErrorCode::IntegrityError,
                "Approved native runner bytes changed",
            ));
        }
        Ok(Self {
            root,
            runner,
            manifest,
            manifest_sha256: Digest::of(&bytes),
        })
    }
    pub fn variants(&self) -> &[ApprovedComponent] {
        &self.manifest.variants
    }
    pub fn component(&self, variant: &str) -> ProofResult<&ApprovedComponent> {
        self.manifest
            .variants
            .iter()
            .find(|entry| entry.variant == variant)
            .ok_or_else(invalid)
    }
}
fn bounded_file(path: &Path, cap: usize) -> ProofResult<Vec<u8>> {
    let (mut file, before) = open_file(path, cap)?;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    Read::by_ref(&mut file)
        .take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let after = file.metadata().map_err(|_| invalid())?;
    let named = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
    if bytes.len() as u64 != before.len()
        || !crate::adapters::native_files::same_file(&before, &after)
        || !crate::adapters::native_files::same_file(&before, &named)
    {
        return Err(invalid());
    }
    Ok(bytes)
}
fn file_digest(
    path: &Path,
    cap: usize,
    expected_header: Option<&[u8; 8]>,
) -> ProofResult<(Digest, u64)> {
    use sha2::{Digest as _, Sha256};
    let (mut file, before) = open_file(path, cap)?;
    let mut hash = Sha256::new();
    let mut total = 0_usize;
    if let Some(expected) = expected_header {
        let mut header = [0; 8];
        file.read_exact(&mut header).map_err(|_| invalid())?;
        if &header != expected {
            return Err(invalid());
        }
        hash.update(header);
        total = header.len();
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut chunk = [0_u8; 16 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(error(
                ErrorCode::Timeout,
                "Approved component hashing deadline exceeded",
            ));
        }
        let count = file.read(&mut chunk).map_err(|_| invalid())?;
        if count == 0 {
            break;
        }
        total += count;
        if total > cap {
            return Err(invalid());
        }
        hash.update(&chunk[..count]);
    }
    let after = file.metadata().map_err(|_| invalid())?;
    let named = std::fs::symlink_metadata(path).map_err(|_| invalid())?;
    if total as u64 != before.len()
        || !crate::adapters::native_files::same_file(&before, &after)
        || !crate::adapters::native_files::same_file(&before, &named)
    {
        return Err(invalid());
    }
    Ok((Digest::from_sha256(hash.finalize().into()), total as u64))
}
fn open_file(path: &Path, cap: usize) -> ProofResult<(File, Metadata)> {
    let descriptor = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|cause| {
        if cause == rustix::io::Errno::NOENT {
            error(
                ErrorCode::ProviderUnavailable,
                "Required approved component fixture is absent",
            )
        } else {
            invalid()
        }
    })?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.len() > cap as u64
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid());
    }
    Ok((file, metadata))
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunFact {
    pub invocation_id: EntityId,
    pub variant: String,
    pub component_sha256: Digest,
    pub pid: u32,
    pub ready: bool,
    pub reaped: bool,
    pub outcome: String,
    pub elapsed_us: u64,
    pub rss_samples: Vec<u64>,
    pub rss_monitor_threshold_bytes: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub invocations_after: usize,
    pub host_calls_after: usize,
    pub reads: Vec<ReadFact>,
    #[serde(with = "super::wit_number::observations")]
    pub observations: Vec<Observation>,
    pub store: StoreFacts,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ProofError>,
}
pub struct Supervisor {
    capacity: Arc<ComponentCapacity>,
}
impl Supervisor {
    pub fn new(capacity: Arc<ComponentCapacity>) -> Self {
        Self { capacity }
    }
    pub fn run(
        &self,
        approved: &ApprovedComponents,
        profile: &LoadedProfile,
        variant: &str,
        broker: &mut SnapshotBroker<'_>,
        cancelled: Arc<AtomicBool>,
    ) -> ProofResult<RunFact> {
        // Must precede manifest reads, native spawning and all component I/O.
        let slot = self.capacity.acquire(SlotKind::Invocation)?;
        let entry = approved.component(variant)?;
        if file_digest(&approved.runner, 512 * 1024 * 1024, None)?.0
            != approved.manifest.runner_sha256
        {
            return Err(error(
                ErrorCode::IntegrityError,
                "Approved native runner changed before spawning",
            ));
        }
        let input = RunnerInput {
            component: approved
                .root
                .join("target/proof-components")
                .join(&entry.file),
            component_sha256: entry.sha256,
            context: InvocationContext {
                invocation_id: broker.invocation_id().to_string(),
                snapshot: broker.reference(),
            },
            limits: profile.config().component.clone(),
            output_limit: profile
                .config()
                .protocol
                .invocation_output_limit_bytes
                .get() as usize,
        };
        let started = Instant::now();
        let (mut writer, stdin) = channel()?;
        let (mut reader, stdout) = channel()?;
        let (mut errors, stderr) = channel()?;
        let child = Command::new(&approved.runner)
            .env_clear()
            .stdin(stdin)
            .stdout(stdout)
            .stderr(stderr)
            .process_group(0)
            .spawn()
            .map_err(|_| {
                error(
                    ErrorCode::ProviderUnavailable,
                    "Approved native component runner could not spawn",
                )
            })?;
        self.capacity.spawned();
        let pid = child.id();
        let mut process = OwnedProcess {
            child,
            group: Pid::from_raw(pid as i32).ok_or_else(invalid)?,
            reaped: false,
        };
        let mut fact = RunFact {
            invocation_id: broker.invocation_id(),
            variant: variant.into(),
            component_sha256: entry.sha256,
            pid,
            ready: false,
            reaped: false,
            outcome: "failed".into(),
            elapsed_us: 0,
            rss_samples: Vec::new(),
            rss_monitor_threshold_bytes: profile
                .config()
                .component
                .runner_rss_monitor_threshold_mib
                .get()
                * 1024
                * 1024,
            stdout_bytes: 0,
            stderr_bytes: 0,
            invocations_after: 0,
            host_calls_after: 0,
            reads: Vec::new(),
            observations: Vec::new(),
            store: StoreFacts::default(),
            error: None,
        };
        let deadline = started
            + Duration::from_millis(profile.config().component.invocation_deadline_ms.get());
        let result = self.exchange(
            &mut process,
            &mut writer,
            &mut reader,
            &mut errors,
            &input,
            broker,
            &cancelled,
            profile,
            deadline,
            &mut fact,
        );
        if let Err(cause) = result {
            fact.error = Some(cause);
        }
        let exited = waitid(
            WaitId::Pid(process.group),
            WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
        )
        .map_err(|_| invalid())?
        .is_some();
        let status = process.finish(!exited)?;
        fact.reaped = true;
        if !status.success() && fact.error.is_none() {
            fact.error = Some(error(
                ErrorCode::OutputInvalid,
                "Native component runner exited without success",
            ));
        }
        fact.elapsed_us = started.elapsed().as_micros() as u64;
        fact.reads = std::mem::take(&mut broker.reads);
        fact.outcome = match fact.error.as_ref().map(|cause| cause.code) {
            None => "completed",
            Some(ErrorCode::Timeout) => "timeout",
            Some(ErrorCode::Cancelled) => "cancelled",
            _ => "failed",
        }
        .into();
        drop(slot); // The actual owned child was reaped before aggregate release.
        let capacity = self.capacity.state();
        fact.invocations_after = capacity.invocations;
        fact.host_calls_after = capacity.host_calls;
        Ok(fact)
    }
    #[allow(clippy::too_many_arguments)]
    fn exchange(
        &self,
        process: &mut OwnedProcess,
        writer: &mut UnixStream,
        reader: &mut UnixStream,
        errors: &mut UnixStream,
        input: &RunnerInput,
        broker: &mut SnapshotBroker<'_>,
        cancelled: &AtomicBool,
        profile: &LoadedProfile,
        deadline: Instant,
        fact: &mut RunFact,
    ) -> ProofResult<()> {
        let cap = input.output_limit;
        let mut pending = serde_json::to_vec(input).map_err(|_| invalid())?;
        pending.push(b'\n');
        let mut sent = 0;
        let mut buffer = Vec::new();
        let mut stdout_eof = false;
        let mut stderr_eof = false;
        let mut done = false;
        let mut next_sample = Instant::now();
        loop {
            if cancelled.load(Ordering::SeqCst) || broker.enclosing_cancelled() {
                return Err(error(
                    ErrorCode::Cancelled,
                    "Native component invocation cancelled",
                ));
            }
            if Instant::now() >= deadline {
                return Err(error(
                    ErrorCode::Timeout,
                    "Independent native runner invocation deadline expired",
                ));
            }
            if Instant::now() >= next_sample {
                if fact.rss_samples.len() >= 1024 {
                    return Err(error(
                        ErrorCode::BudgetExhausted,
                        "Native RSS audit sample cap exceeded",
                    ));
                }
                if let Some(rss) = sample_rss(process.child.id())? {
                    fact.rss_samples.push(rss);
                    if rss > fact.rss_monitor_threshold_bytes {
                        return Err(error(
                            ErrorCode::BudgetExhausted,
                            "Empirical runner RSS monitor threshold exceeded; not a hard guest cap",
                        ));
                    }
                }
                next_sample = Instant::now()
                    + Duration::from_millis(profile.config().component.rss_sampling_ms.get());
            }
            if sent < pending.len() {
                match writer.write(&pending[sent..]) {
                    Ok(0) => return Err(invalid()),
                    Ok(count) => sent += count,
                    Err(cause)
                        if matches!(
                            cause.kind(),
                            ErrorKind::WouldBlock | ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(invalid()),
                }
            }
            if !stdout_eof {
                stdout_eof = read_stream(
                    reader,
                    Some(&mut buffer),
                    &mut fact.stdout_bytes,
                    cap as u64,
                )?;
            }
            if !stderr_eof {
                stderr_eof = read_stream(errors, None, &mut fact.stderr_bytes, 16_384)?;
            }
            while let Some(end) = buffer.iter().position(|byte| *byte == b'\n') {
                let frame: RunnerFrame =
                    serde_json::from_slice(&buffer[..end]).map_err(|_| invalid())?;
                buffer.drain(..=end);
                match frame {
                    RunnerFrame::Ready if !fact.ready && !done => fact.ready = true,
                    RunnerFrame::Read {
                        snapshot,
                        offset,
                        max_bytes,
                    } if fact.ready && !done && sent == pending.len() => {
                        let result = broker.read(snapshot, offset, max_bytes);
                        let reply = match result {
                            Ok(bytes) => ReadReply { bytes, error: None },
                            Err(cause) => ReadReply {
                                bytes: Vec::new(),
                                error: Some(cause),
                            },
                        };
                        pending = serde_json::to_vec(&reply).map_err(|_| invalid())?;
                        if pending.len() > 400_000 {
                            return Err(invalid());
                        }
                        pending.push(b'\n');
                        sent = 0;
                    }
                    RunnerFrame::Done {
                        observations,
                        facts,
                        error,
                    } if !done => {
                        fact.observations = observations;
                        fact.store = facts;
                        fact.error = error;
                        done = true;
                    }
                    _ => return Err(invalid()),
                }
            }
            if stdout_eof && stderr_eof {
                if !done || !buffer.is_empty() {
                    return Err(error(
                        ErrorCode::OutputInvalid,
                        "Native component runner ended without a complete terminal frame",
                    ));
                }
                if waitid(
                    WaitId::Pid(process.group),
                    WaitIdOptions::EXITED | WaitIdOptions::NOWAIT | WaitIdOptions::NOHANG,
                )
                .map_err(|_| invalid())?
                .is_some()
                {
                    return Ok(());
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
fn channel() -> ProofResult<(UnixStream, Stdio)> {
    let (host, child) = UnixStream::pair().map_err(|_| invalid())?;
    host.set_nonblocking(true).map_err(|_| invalid())?;
    Ok((host, Stdio::from(OwnedFd::from(child))))
}
fn read_stream(
    stream: &mut UnixStream,
    buffer: Option<&mut Vec<u8>>,
    total: &mut u64,
    cap: u64,
) -> ProofResult<bool> {
    let mut chunk = [0; 8192];
    match stream.read(&mut chunk) {
        Ok(0) => Ok(true),
        Ok(count) => {
            *total += count as u64;
            if *total > cap {
                return Err(error(
                    ErrorCode::OutputInvalid,
                    "Native component bounded I/O exceeded",
                ));
            }
            if let Some(buffer) = buffer {
                buffer.extend_from_slice(&chunk[..count]);
            }
            Ok(false)
        }
        Err(cause) if matches!(cause.kind(), ErrorKind::WouldBlock | ErrorKind::Interrupted) => {
            Ok(false)
        }
        Err(_) => Err(invalid()),
    }
}
fn sample_rss(pid: u32) -> ProofResult<Option<u64>> {
    let pid = pid.to_string();
    let result = capture(
        Path::new("/bin/ps"),
        &[
            OsStr::new("-o"),
            OsStr::new("rss="),
            OsStr::new("-p"),
            OsStr::new(&pid),
        ],
        None,
        CommandLimits {
            stdin_bytes: 0,
            stdout_bytes: 128,
            stderr_bytes: 128,
            timeout: Duration::from_millis(100),
        },
    );
    match result {
        Ok(output) => {
            let text = std::str::from_utf8(&output.stdout)
                .map_err(|_| invalid())?
                .trim();
            if text.is_empty() {
                return Ok(None);
            }
            let kib: u64 = text.parse().map_err(|_| invalid())?;
            Ok(Some(kib.checked_mul(1024).ok_or_else(invalid)?))
        }
        Err(cause) if cause.code == ErrorCode::ProviderUnavailable => Ok(None),
        Err(cause) => Err(cause),
    }
}
struct OwnedProcess {
    child: Child,
    group: Pid,
    reaped: bool,
}
impl OwnedProcess {
    fn finish(&mut self, terminate: bool) -> ProofResult<std::process::ExitStatus> {
        if terminate {
            match kill_process_group(self.group, Signal::KILL) {
                Ok(()) | Err(rustix::io::Errno::SRCH) => {}
                Err(_) => {
                    let _ = self.child.kill();
                }
            }
        }
        let status = self.child.wait().map_err(|_| invalid())?;
        self.reaped = true;
        Ok(status)
    }
}
impl Drop for OwnedProcess {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.finish(true);
        }
    }
}
