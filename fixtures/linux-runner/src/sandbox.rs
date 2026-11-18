use crate::{Result, fail, lifecycle::Cgroup};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::OpenOptionsExt, process::CommandExt},
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

pub mod launcher_failure;
use launcher_failure::{Channel, Failure, Operation};
pub const UID: u32 = 61000;
pub const GID: u32 = 61000;
pub const FIXTURES: &[&str] = &[
    "snapshot_control",
    "host_canary",
    "manager_canary",
    "other_invocation",
    "credential",
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
    "orphan",
    "runtime",
    "runtime_blocked",
];
/// seccompiler compiles the reviewed AArch64 policy; no handwritten BPF instructions.
pub fn seccomp_bytes() -> Result<Vec<u8>> {
    let calls = [
        libc::SYS_read,
        libc::SYS_write,
        libc::SYS_readv,
        libc::SYS_writev,
        libc::SYS_pread64,
        libc::SYS_pwrite64,
        libc::SYS_close,
        libc::SYS_close_range,
        libc::SYS_openat,
        libc::SYS_newfstatat,
        libc::SYS_fstat,
        libc::SYS_statx,
        libc::SYS_lseek,
        libc::SYS_readlinkat,
        libc::SYS_getdents64,
        libc::SYS_faccessat,
        libc::SYS_faccessat2,
        libc::SYS_mmap,
        libc::SYS_mprotect,
        libc::SYS_munmap,
        libc::SYS_mremap,
        libc::SYS_madvise,
        libc::SYS_brk,
        libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask,
        libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack,
        libc::SYS_futex,
        libc::SYS_set_tid_address,
        libc::SYS_set_robust_list,
        libc::SYS_rseq,
        libc::SYS_getpid,
        libc::SYS_getppid,
        libc::SYS_gettid,
        libc::SYS_getuid,
        libc::SYS_geteuid,
        libc::SYS_getgid,
        libc::SYS_getegid,
        libc::SYS_getgroups,
        libc::SYS_getresuid,
        libc::SYS_getresgid,
        libc::SYS_clock_gettime,
        libc::SYS_clock_nanosleep,
        libc::SYS_nanosleep,
        libc::SYS_sched_yield,
        libc::SYS_sched_getaffinity,
        libc::SYS_getrandom,
        libc::SYS_uname,
        libc::SYS_getcwd,
        libc::SYS_chdir,
        libc::SYS_fchdir,
        libc::SYS_dup,
        libc::SYS_dup3,
        libc::SYS_fcntl,
        libc::SYS_pipe2,
        libc::SYS_ppoll,
        libc::SYS_pselect6,
        libc::SYS_wait4,
        libc::SYS_waitid,
        libc::SYS_execve,
        libc::SYS_execveat,
        libc::SYS_exit,
        libc::SYS_exit_group,
        libc::SYS_tgkill,
        libc::SYS_kill,
        libc::SYS_getrlimit,
        libc::SYS_prlimit64,
        libc::SYS_getrusage,
        libc::SYS_statfs,
        libc::SYS_fstatfs,
        libc::SYS_ftruncate,
        libc::SYS_unlinkat,
        libc::SYS_mkdirat,
        libc::SYS_renameat2,
        libc::SYS_fsync,
        libc::SYS_fdatasync,
        libc::SYS_capget,
    ];
    let mut rules: BTreeMap<i64, Vec<SeccompRule>> =
        calls.into_iter().map(|n| (n, vec![])).collect();
    let forbidden = (libc::CLONE_NEWUSER
        | libc::CLONE_NEWNS
        | libc::CLONE_NEWPID
        | libc::CLONE_NEWNET
        | libc::CLONE_NEWIPC
        | libc::CLONE_NEWUTS
        | libc::CLONE_NEWCGROUP
        | libc::CLONE_PTRACE
        | libc::CLONE_UNTRACED) as u64;
    rules.insert(
        libc::SYS_clone,
        vec![SeccompRule::new(vec![SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(forbidden),
            0,
        )?])?],
    );
    // ENOSYS makes libc's clone3 probe fall back to the argument-filtered clone syscall.
    let filter: BpfProgram = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::ENOSYS as u32),
        SeccompAction::Allow,
        TargetArch::aarch64,
    )?
    .try_into()?;
    let mut bytes = Vec::with_capacity(filter.len() * 8);
    for instruction in filter {
        bytes.extend_from_slice(&instruction.code.to_ne_bytes());
        bytes.push(instruction.jt);
        bytes.push(instruction.jf);
        bytes.extend_from_slice(&instruction.k.to_ne_bytes());
    }
    Ok(bytes)
}
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn file_hash(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 65536];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(hex::encode(hash.finalize()))
}
pub struct Sandboxed {
    pub child: Child,
    pub release: Option<File>,
    pub input: File,
    pub stdout: File,
    pub stderr: File,
    pub setup: File,
    pub launcher_failure: Channel,
}
impl Drop for Sandboxed {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}
fn pipe() -> Result<(File, File)> {
    let mut fds = [-1; 2];
    // SAFETY: fds points to two initialized integers, pipe2 fills both on success.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: successful pipe2 returned unique owned descriptors.
    Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
}
pub fn start(cgroup: &Cgroup, fixture: &str, configuration: &Value) -> Result<Sandboxed> {
    if !FIXTURES.contains(&fixture) {
        return Err(fail("unapproved fixture"));
    }
    let (gate, release) = pipe()?;
    let (child_input, input) = pipe()?;
    let (stdout, child_stdout) = pipe()?;
    let (stderr, child_stderr) = pipe()?;
    let (setup, setup_out) = pipe()?;
    let (failure_input, failure_output) = pipe()?;
    let launcher_failure = Channel::new(failure_input)?;
    let filter = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open("/usr/local/share/razen/seccomp.bpf")?;
    let gate_fd = gate.as_raw_fd();
    let filter_fd = filter.as_raw_fd();
    let setup_fd = setup_out.as_raw_fd();
    let failure_fd = failure_output.as_raw_fd();
    let inputs = Path::new("/var/lib/razen/inputs").join(&cgroup.invocation);
    fs::create_dir(&inputs)?;
    use base64::Engine as _;
    let staged = crate::wire::unique(&fs::read(
        Path::new("/var/lib/razen/staged").join(format!("{}.json", cgroup.invocation)),
    )?)?;
    let snapshot = base64::engine::general_purpose::STANDARD.decode(
        staged["snapshot_base64"]
            .as_str()
            .ok_or_else(|| fail("approved staged snapshot body missing"))?,
    )?;
    fs::write(inputs.join("snapshot"), &snapshot)?;
    fs::write(
        inputs.join("fixture.json"),
        serde_json::to_vec(configuration)?,
    )?;
    use std::os::unix::fs::PermissionsExt;
    for name in ["snapshot", "fixture.json"] {
        fs::set_permissions(inputs.join(name), fs::Permissions::from_mode(0o444))?;
    }
    fs::set_permissions(&inputs, fs::Permissions::from_mode(0o555))?;
    let mut command = Command::new("/usr/local/libexec/razen-tool-supervisor");
    command
        .args([
            "--launcher",
            &gate_fd.to_string(),
            &filter_fd.to_string(),
            &setup_fd.to_string(),
            inputs.to_str().ok_or_else(|| fail("invalid inputs path"))?,
            fixture,
            &failure_fd.to_string(),
        ])
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(child_input))
        .stdout(Stdio::from(child_stdout))
        .stderr(Stdio::from(child_stderr));
    // SAFETY: this single-threaded root supervisor uses only async-signal-safe fcntl in pre_exec.
    unsafe {
        command.pre_exec(move || {
            for fd in [gate_fd, filter_fd, setup_fd, failure_fd] {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    drop(gate);
    drop(filter);
    drop(setup_out);
    drop(failure_output);
    for file in [&stdout, &stderr, &setup] {
        crate::lifecycle::nonblocking(file.as_raw_fd())?;
    }
    Ok(Sandboxed {
        child,
        release: Some(release),
        input,
        stdout,
        stderr,
        setup,
        launcher_failure,
    })
}
/// Trusted launcher reaches this gate BEFORE namespace creation/hostile release.
pub fn launcher(args: &[String]) -> Result<()> {
    if args.len() != 6 {
        return Err(fail("invalid fixed launcher arguments"));
    }
    let descriptor = args[5].parse::<i32>()?;
    if descriptor < 3 {
        return Err(fail("invalid trusted launcher failure descriptor"));
    }
    // SAFETY: F_GETFD validates the supplied descriptor without acquiring ownership.
    if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: the parent exclusively transfers this validated pipe writer to the launcher.
    let mut channel = unsafe { File::from_raw_fd(descriptor) };
    let result = launcher_inner(&args[..5], descriptor);
    if let Err(error) = &result
        && let Some(error) = error.downcast_ref::<Failure>()
    {
        let _ = error.report(&mut channel);
    }
    result
}

fn launcher_inner(args: &[String], failure_fd: i32) -> Result<()> {
    let invalid_argument =
        || Failure::condition(Operation::Arguments, std::io::ErrorKind::InvalidInput);
    let gate = args[0].parse::<i32>().map_err(|_| invalid_argument())?;
    let seccomp = args[1].parse::<i32>().map_err(|_| invalid_argument())?;
    let info = args[2].parse::<i32>().map_err(|_| invalid_argument())?;
    let inputs = PathBuf::from(&args[3]);
    let fixture = &args[4];
    if !inputs.starts_with("/var/lib/razen/inputs")
        || !FIXTURES.contains(&fixture.as_str())
        || [gate, seccomp, info]
            .iter()
            .any(|fd| *fd < 3 || *fd == failure_fd)
        || gate == seccomp
        || gate == info
        || seccomp == info
    {
        return Err(invalid_argument().into());
    }
    // SAFETY: this owned private descriptor must close atomically before bwrap executes.
    let result = unsafe { libc::fcntl(failure_fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    launcher_call(Operation::DiagnosticCloexec, result.into())?;
    let mut byte = [0u8; 1];
    // SAFETY: gate is the exclusively inherited approved read pipe; byte is writable.
    let received = unsafe { libc::read(gate, byte.as_mut_ptr().cast(), 1) };
    if received < 0 {
        return Err(Failure::io(
            Operation::ReadPlacementGate,
            std::io::Error::last_os_error(),
        )
        .into());
    }
    if received != 1 {
        return Err(Failure::condition(
            Operation::ReadPlacementGate,
            std::io::ErrorKind::UnexpectedEof,
        )
        .into());
    }
    // SAFETY: gate is this launcher's exclusively owned placement descriptor.
    let result = unsafe { libc::close(gate) };
    launcher_call(Operation::ClosePlacementGate, result.into())?;
    let mut approved = [seccomp as u32, info as u32, failure_fd as u32];
    approved.sort();
    let mut first = 3u32;
    for last in approved.into_iter().chain(std::iter::once(u32::MAX)) {
        if first < last {
            // SAFETY: close_range closes only this launcher's non-approved inherited FD interval.
            if unsafe { libc::syscall(libc::SYS_close_range, first, last - 1, 0) } < 0 {
                return Err(Failure::io(
                    Operation::CloseDescriptors,
                    std::io::Error::last_os_error(),
                )
                .into());
            }
        }
        first = last.saturating_add(1);
    }
    let limit = libc::rlimit {
        rlim_cur: 64,
        rlim_max: 64,
    };
    let core = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: valid rlimit pointers, empty supplementary groups, numeric dedicated
    // account IDs and integer prctl arguments establish only this launcher's limits.
    unsafe {
        launcher_call(
            Operation::LimitDescriptors,
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit).into(),
        )?;
        launcher_call(
            Operation::DisableCoreDump,
            libc::setrlimit(libc::RLIMIT_CORE, &core).into(),
        )?;
        launcher_call(
            Operation::ClearGroups,
            libc::setgroups(0, std::ptr::null()).into(),
        )?;
        launcher_call(Operation::SetGroup, libc::setresgid(GID, GID, GID).into())?;
        launcher_call(Operation::SetUser, libc::setresuid(UID, UID, UID).into())?;
        launcher_call(
            Operation::NoNewPrivileges,
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0).into(),
        )?;
    }
    let mut cmd = Command::new("/usr/local/bin/bwrap");
    cmd.args([
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-net",
        "--unshare-cgroup",
        "--disable-userns",
        "--uid",
        "61000",
        "--gid",
        "61000",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--new-session",
        "--hostname",
        "razen-workload",
        "--ro-bind",
        "/usr/local/share/razen/runtime",
        "/runtime",
        "--ro-bind",
        inputs.to_str().ok_or_else(|| fail("inputs path invalid"))?,
        "/inputs",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dir",
        "/tmp",
        "--size",
        "16777216",
        "--tmpfs",
        "/tmp",
        "--symlink",
        "runtime/lib",
        "/lib",
        "--symlink",
        "runtime/lib",
        "/lib64",
        "--remount-ro",
        "/dev",
        "--remount-ro",
        "/proc",
        "--remount-ro",
        "/",
        "--chdir",
        "/",
        "--seccomp",
        &seccomp.to_string(),
        "--info-fd",
        &info.to_string(),
        "--",
        "/runtime/razen-sandbox-adversary",
        "--gate",
        fixture,
    ])
    .env_clear();
    Err(Failure::io(Operation::ExecBubblewrap, cmd.exec()).into())
}
fn launcher_call(operation: Operation, result: libc::c_long) -> Result<()> {
    if result < 0 {
        return Err(Failure::io(operation, std::io::Error::last_os_error()).into());
    }
    Ok(())
}
/// Read directly from the filtered process BEFORE accepting hostile release.
pub fn probe() -> Result<Value> {
    let mut namespaces = serde_json::Map::new();
    for name in ["user", "mnt", "pid", "ipc", "uts", "net", "cgroup"] {
        namespaces.insert(
            name.into(),
            json!(fs::read_link(format!("/proc/self/ns/{name}"))?.to_string_lossy()),
        );
    }
    let status = fs::read_to_string("/proc/self/status")?;
    let mounts = fs::read_to_string("/proc/self/mountinfo")?;
    let descriptors = fs::read_dir("/proc/self/fd")?
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().parse::<u32>().ok()?;
            let target = fs::read_link(e.path()).ok()?;
            Some(json!({"fd":name,"target":target.to_string_lossy()}))
        })
        .collect::<Vec<_>>();
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: limit is a writable initialized rlimit for this process's own descriptor bound.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(
        json!({"pid":std::process::id(),"namespaces":namespaces,"status":status,"mountinfo":mounts,"descriptors":descriptors,"environment":std::env::vars().collect::<BTreeMap<_,_>>(),"snapshot_sha256":file_hash(Path::new("/inputs/snapshot"))?,"rlimit_nofile":limit.rlim_cur,"rlimit_nofile_hard":limit.rlim_max}),
    )
}
