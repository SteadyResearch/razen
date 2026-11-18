use crate::{Result, fail, wire};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
pub const ROOT: &str = "/var/lib/razen/invocations";
pub const CGROUP: &str = "/sys/fs/cgroup/razen-proof";
pub struct Lease {
    pub id: String,
    pub revision: u64,
    pub started: Instant,
    expires: Instant,
    wall: Instant,
    seen: BTreeSet<String>,
    terminal: bool,
}
impl Lease {
    pub fn new(id: String, revision: u64) -> Self {
        let now = Instant::now();
        Self {
            id,
            revision,
            started: now,
            expires: now + Duration::from_millis(2000),
            wall: now + Duration::from_millis(5000),
            seen: BTreeSet::new(),
            terminal: false,
        }
    }
    pub fn expired(&mut self) -> bool {
        self.terminal |= Instant::now() >= self.expires || Instant::now() >= self.wall;
        self.terminal
    }
    pub fn refresh(&mut self, message: &str, id: &str, revision: u64) -> Result<bool> {
        if self.expired() || id != self.id || revision != self.revision {
            return Err(fail("foreign/stale/terminal lease refresh"));
        }
        if self.seen.contains(message) {
            return Ok(false);
        }
        if self.seen.len() == 256 {
            return Err(fail("lease replay capacity"));
        }
        self.seen.insert(message.into());
        self.expires = (Instant::now() + Duration::from_millis(2000)).min(self.wall);
        Ok(true)
    }
    pub fn cancel(&mut self, id: &str, revision: u64) -> Result<()> {
        if id != self.id || revision < self.revision {
            return Err(fail("foreign/stale cancellation"));
        }
        self.revision = revision;
        self.terminal = true;
        Ok(())
    }
}
pub struct Cgroup {
    pub path: PathBuf,
    pub directory: PathBuf,
    pub invocation: String,
    _lock: File,
    occupancy: NativeOccupancy,
    pub manager_pid: u32,
    pub placed_pid: u32,
    pub placement_us: u128,
    failure_finalized: bool,
}
impl Cgroup {
    pub fn create(launch: &wire::Launch) -> Result<Self> {
        let invocation = &launch.invocation_id;
        if !wire::uuid(invocation) {
            return Err(fail("invalid invocation"));
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/var/lib/razen/invocation.lock")?;
        // SAFETY: flock operates on the owned, opened descriptor; no foreign PID is used.
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(fail("guest invocation capacity exhausted"));
        }
        validate_private(&lock.metadata()?, false)?;
        let named = fs::symlink_metadata("/var/lib/razen/invocation.lock")?;
        if named.file_type().is_symlink()
            || named.dev() != lock.metadata()?.dev()
            || named.ino() != lock.metadata()?.ino()
        {
            return Err(fail("native capacity inode was replaced"));
        }
        identity(Path::new(CGROUP), false)?;
        identity(Path::new(ROOT), true)?;
        recover_occupancy(&lock)?;
        for entry in fs::read_dir(CGROUP)? {
            if entry?.file_type()?.is_dir() {
                return Err(fail(
                    "unmarked or surviving workload group; capacity remains closed",
                ));
            }
        }
        let mut occupancy = NativeOccupancy::new(launch)?;
        append_occupancy(&lock, &occupancy)?;
        let directory = Path::new(ROOT).join(invocation);
        fs::create_dir(&directory)?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))?;
        fs::write(
            directory.join("ownership-canary"),
            crate::wire::new_id()?.as_bytes(),
        )?;
        let path = Path::new(CGROUP).join(invocation);
        fs::create_dir(&path)?;
        occupancy.directory = Some(identity(&directory, true)?);
        occupancy.group = Some(identity(&path, false)?);
        append_occupancy(&lock, &occupancy)?;
        for (name, value) in [
            ("memory.max", "268435456"),
            ("memory.swap.max", "0"),
            ("memory.oom.group", "1"),
            ("pids.max", "64"),
            ("cpu.max", "100000 100000"),
        ] {
            fs::write(path.join(name), value)?;
            if fs::read_to_string(path.join(name))?.trim() != value {
                return Err(fail("effective cgroup limit mismatch"));
            }
        }
        let manager_pid = std::process::id();
        if fs::read_to_string(path.join("cgroup.procs"))?
            .split_whitespace()
            .any(|p| p == manager_pid.to_string())
        {
            return Err(fail("manager is inside hostile workload cgroup"));
        }
        Ok(Self {
            path,
            directory,
            invocation: invocation.into(),
            _lock: lock,
            occupancy,
            manager_pid,
            failure_finalized: false,
            placed_pid: 0,
            placement_us: 0,
        })
    }
    pub fn place(&mut self, pid: u32, epoch: Instant) -> Result<()> {
        fs::write(self.path.join("cgroup.procs"), pid.to_string())?;
        if !fs::read_to_string(self.path.join("cgroup.procs"))?
            .split_whitespace()
            .any(|p| p == pid.to_string())
        {
            return Err(fail("launcher placement not observed"));
        }
        self.placed_pid = pid;
        self.placement_us = epoch.elapsed().as_micros();
        Ok(())
    }
    pub fn populated(&self) -> Result<bool> {
        let events = fs::read_to_string(self.path.join("cgroup.events"))?;
        events
            .lines()
            .find_map(|l| l.strip_prefix("populated "))
            .map(|v| v != "0")
            .ok_or_else(|| fail("cgroup populated counter missing"))
    }
    pub fn kill_empty(&self) -> Result<Value> {
        self.validate_owned_group()?;
        let start = Instant::now();
        let before = fs::read_to_string(self.path.join("cgroup.procs"))?;
        fs::write(self.path.join("cgroup.kill"), "1")?;
        while self.populated()? && start.elapsed() < Duration::from_millis(1000) {
            std::thread::sleep(Duration::from_millis(2));
        }
        let populated = self.populated()?;
        let after = fs::read_to_string(self.path.join("cgroup.procs"))?;
        if populated || !after.trim().is_empty() {
            return Err(fail("owned cgroup did not become empty by deadline"));
        }
        Ok(
            json!({"empty_cgroup":true,"cgroup_populated_after":0,"descendants_after":0,"pids_before":before.split_whitespace().map(str::to_owned).collect::<Vec<_>>(),"observed_empty_us":start.elapsed().as_micros(),"cgroup_events":fs::read_to_string(self.path.join("cgroup.events"))?}),
        )
    }
    pub fn usage(&self, output: u64, tmpfs_peak: u64) -> Result<Value> {
        let stat = fs::read_to_string(self.path.join("cpu.stat"))?;
        let cpu = stat
            .lines()
            .find_map(|l| l.strip_prefix("usage_usec "))
            .ok_or_else(|| fail("CPU usage counter missing"))?
            .parse::<u64>()?;
        Ok(
            json!({"invocation_id":self.invocation,"cpu_time_us":cpu,"memory_peak_bytes":fs::read_to_string(self.path.join("memory.peak"))?.trim().parse::<u64>()?,"pids_peak":fs::read_to_string(self.path.join("pids.peak"))?.trim().parse::<u64>()?,"tmpfs_peak_bytes":tmpfs_peak,"output_bytes":output}),
        )
    }
    pub fn tmpfs_bytes(&self) -> Result<u64> {
        let stat = fs::read_to_string(self.path.join("memory.stat"))?;
        Ok(stat
            .lines()
            .find_map(|l| l.strip_prefix("shmem "))
            .ok_or_else(|| fail("shmem counter missing"))?
            .parse()?)
    }
    pub fn journal(&self, value: &Value) -> Result<()> {
        let path = self.directory.join("termination.json");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
    pub fn occupancy_sha256(&self) -> Result<String> {
        Ok(crate::sandbox::hash(&serde_json::to_vec(&self.occupancy)?))
    }
    pub fn owner_id(&self) -> &str {
        &self.occupancy.owner_id
    }
    pub fn failure_occupancy(&self) -> Value {
        json!(&self.occupancy)
    }
    // Unlike the success journal, this reports each completed cleanup step independently.
    // A failed explicit attempt must not be silently retried by Drop after it is recorded.
    pub fn finish_failure(&mut self) -> (Value, Result<()>) {
        self.failure_finalized = true;
        let mut disposition = json!({
            "operation":"kill_empty",
            "empty_observation":null,
            "group_removed":false,
            "occupancy_cleared":false
        });
        let result = (|| {
            disposition["empty_observation"] = self.kill_empty()?;
            disposition["operation"] = json!("remove_group");
            fs::remove_dir(&self.path)?;
            disposition["group_removed"] = json!(true);
            disposition["operation"] = json!("clear_occupancy");
            clear_occupancy(&self._lock, &self.occupancy)?;
            disposition["occupancy_cleared"] = json!(true);
            disposition["operation"] = json!("complete");
            Ok(())
        })();
        (disposition, result)
    }
    fn validate_owned_group(&self) -> Result<()> {
        if read_occupancy(&self._lock)?.as_ref() != Some(&self.occupancy)
            || self.occupancy.group.as_ref() != Some(&identity(&self.path, false)?)
            || self.occupancy.directory.as_ref() != Some(&identity(&self.directory, true)?)
        {
            return Err(fail(
                "owned group identity changed; no foreign group may be killed or released",
            ));
        }
        self.occupancy.validate_current()
    }
    fn release(&self) -> Result<()> {
        self.kill_empty()?;
        fs::remove_dir(&self.path)?;
        clear_occupancy(&self._lock, &self.occupancy)
    }
}
impl Drop for Cgroup {
    fn drop(&mut self) {
        if !self.failure_finalized && self.release().is_err() {
            eprintln!("razen: native cleanup failed; durable occupancy remains sealed");
        }
    }
}
pub fn nonblocking(fd: i32) -> Result<()> {
    // SAFETY: caller supplies an owned live FD. fcntl only modifies that descriptor's status.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    // SAFETY: F_SETFL takes an integer status flag argument, not a pointer.
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
pub fn ignore_transport_signals() -> Result<()> {
    // SAFETY: SIG_IGN is a valid disposition. The root watchdog must survive SSH HUP/PIPE.
    unsafe {
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        libc::signal(libc::SIGPIPE, libc::SIG_IGN);
    }
    Ok(())
}
pub fn read_bounded(path: &Path, cap: usize) -> Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > cap {
        return Err(fail("owned input exceeds bound"));
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct InodeIdentity {
    device: u64,
    inode: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct NativeOccupancy {
    occupancy_id: String,
    owner_id: String,
    provenance_sha256: String,
    boot_id: String,
    binary_digests: [String; 4],
    invocation_id: String,
    binding_id: String,
    run_id: String,
    lease_id: String,
    attestation_id: String,
    profile_sha256: String,
    initial_revision: u64,
    directory: Option<InodeIdentity>,
    group: Option<InodeIdentity>,
}
impl NativeOccupancy {
    fn new(launch: &wire::Launch) -> Result<Self> {
        let bytes = read_bounded(Path::new(crate::attestation::METADATA), wire::FRAME)?;
        let provenance = wire::unique(&bytes)?;
        let owner_id = wire::id(&provenance["owner_id"])?.to_owned();
        if provenance["profile_sha256"] != launch.profile_sha256 {
            return Err(fail(
                "native capacity profile differs from prepared provenance",
            ));
        }
        Ok(Self {
            occupancy_id: wire::new_id()?,
            owner_id,
            provenance_sha256: crate::sandbox::hash(&bytes),
            binary_digests: native_binary_digests()?,
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")?
                .trim()
                .into(),
            invocation_id: launch.invocation_id.clone(),
            binding_id: launch.binding_id.clone(),
            run_id: launch.run_id.clone(),
            lease_id: launch.lease_id.clone(),
            attestation_id: launch.attestation_id.clone(),
            profile_sha256: launch.profile_sha256.clone(),
            initial_revision: launch.control_revision,
            directory: None,
            group: None,
        })
    }
    fn validate_current(&self) -> Result<()> {
        let bytes = read_bounded(Path::new(crate::attestation::METADATA), wire::FRAME)?;
        let provenance = wire::unique(&bytes)?;
        if [
            &self.occupancy_id,
            &self.invocation_id,
            &self.binding_id,
            &self.run_id,
            &self.lease_id,
            &self.attestation_id,
            &self.owner_id,
        ]
        .iter()
        .any(|id| !wire::uuid(id))
            || crate::sandbox::hash(&bytes) != self.provenance_sha256
            || provenance["owner_id"] != self.owner_id
            || provenance["profile_sha256"] != self.profile_sha256
            || native_binary_digests()? != self.binary_digests
            || fs::read_to_string("/proc/sys/kernel/random/boot_id")?.trim() != self.boot_id
            || !wire::uuid(&self.boot_id)
        {
            return Err(fail(
                "foreign or unknown native occupancy owner/source/configuration/binary/profile/boot identity",
            ));
        }
        Ok(())
    }
}
fn native_binary_digests() -> Result<[String; 4]> {
    Ok([
        crate::sandbox::file_hash(Path::new("/usr/local/libexec/razen-tool-supervisor"))?,
        crate::sandbox::file_hash(Path::new(
            "/usr/local/share/razen/runtime/razen-sandbox-adversary",
        ))?,
        crate::sandbox::file_hash(Path::new("/usr/local/bin/bwrap"))?,
        crate::sandbox::file_hash(Path::new("/usr/local/share/razen/seccomp.bpf"))?,
    ])
}
fn validate_private(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    if metadata.uid() != 0
        || metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir() || metadata.mode() & 0o077 != 0
        } else {
            !metadata.is_file() || metadata.nlink() != 1 || metadata.mode() & 0o077 != 0
        }
    {
        return Err(fail(
            "native occupancy resource is not root-private and unshared",
        ));
    }
    Ok(())
}
fn identity(path: &Path, private: bool) -> Result<InodeIdentity> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() || metadata.uid() != 0 {
        return Err(fail("owned group path is foreign or replaced"));
    }
    if private {
        validate_private(&metadata, true)?;
    }
    Ok(InodeIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}
fn read_occupancy(lock: &File) -> Result<Option<NativeOccupancy>> {
    let mut file = lock;
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(16385).read_to_end(&mut bytes)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > 16384 || bytes.last() != Some(&b'\n') {
        return Err(fail(
            "interrupted or overlarge native occupancy; capacity remains closed",
        ));
    }
    let mut last: Option<NativeOccupancy> = None;
    for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
        let next: NativeOccupancy = serde_json::from_slice(line)?;
        if last.is_none() && (next.directory.is_some() || next.group.is_some()) {
            return Err(fail(
                "native occupancy history lacks its original pre-launch reservation",
            ));
        }
        if let Some(previous) = &last
            && (previous.occupancy_id != next.occupancy_id
                || previous.owner_id != next.owner_id
                || previous.provenance_sha256 != next.provenance_sha256
                || previous.boot_id != next.boot_id
                || previous.binary_digests != next.binary_digests
                || previous.invocation_id != next.invocation_id
                || previous.binding_id != next.binding_id
                || previous.run_id != next.run_id
                || previous.lease_id != next.lease_id
                || previous.attestation_id != next.attestation_id
                || previous.profile_sha256 != next.profile_sha256
                || previous.initial_revision != next.initial_revision
                || previous
                    .directory
                    .as_ref()
                    .is_some_and(|directory| Some(directory) != next.directory.as_ref())
                || previous
                    .group
                    .as_ref()
                    .is_some_and(|group| Some(group) != next.group.as_ref()))
        {
            return Err(fail("foreign or changed native occupancy history"));
        }
        last = Some(next);
    }
    Ok(last)
}
fn append_occupancy(lock: &File, occupancy: &NativeOccupancy) -> Result<()> {
    let mut bytes = serde_json::to_vec(occupancy)?;
    bytes.push(b'\n');
    let mut file = lock;
    if file.seek(SeekFrom::End(0))? + bytes.len() as u64 > 16384 {
        return Err(fail("native durable occupancy bound"));
    }
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}
fn clear_occupancy(lock: &File, expected: &NativeOccupancy) -> Result<()> {
    if read_occupancy(lock)?.as_ref() != Some(expected) {
        return Err(fail("never clear foreign native occupancy"));
    }
    lock.set_len(0)?;
    lock.sync_all()?;
    Ok(())
}
fn recover_occupancy(lock: &File) -> Result<()> {
    let Some(previous) = read_occupancy(lock)? else {
        return Ok(());
    };
    previous.validate_current()?;
    let directory = Path::new(ROOT).join(&previous.invocation_id);
    if previous.directory.as_ref() != Some(&identity(&directory, true)?) {
        return Err(fail("previous invocation directory identity changed"));
    }
    let path = Path::new(CGROUP).join(&previous.invocation_id);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            if previous.group.as_ref() != Some(&identity(&path, false)?) {
                return Err(fail("previous owned group identity changed"));
            }
            let events = fs::read_to_string(path.join("cgroup.events"))?;
            if events
                .lines()
                .find_map(|line| line.strip_prefix("populated "))
                != Some("0")
                || !fs::read_to_string(path.join("cgroup.procs"))?
                    .trim()
                    .is_empty()
            {
                return Err(fail(
                    "previous owned group is not independently empty; native occupancy remains sealed",
                ));
            }
            fs::remove_dir(&path)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let journal = wire::unique(&read_bounded(
                &directory.join("termination.json"),
                wire::FRAME,
            )?)?;
            if journal["native_occupancy_sha256"]
                != crate::sandbox::hash(&serde_json::to_vec(&previous)?)
                || journal["invocation_id"] != previous.invocation_id
                || journal["lease_id"] != previous.lease_id
                || journal["binding_id"] != previous.binding_id
                || journal["run_id"] != previous.run_id
                || journal["owner_id"] != previous.owner_id
                || journal["profile_sha256"] != previous.profile_sha256
                || journal["empty_cgroup"] != true
                || journal["cgroup_populated_after"] != 0
                || journal["descendants_after"] != 0
            {
                return Err(fail(
                    "missing owned group has no authenticated previous empty-group journal",
                ));
            }
        }
        Err(error) => return Err(error.into()),
    }
    clear_occupancy(lock, &previous)
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    struct OwnedChild(std::process::Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    fn launch() -> wire::Launch {
        let provenance = wire::unique(
            &read_bounded(Path::new(crate::attestation::METADATA), wire::FRAME)
                .expect("explicitly prepared Linux supervisor provenance required"),
        )
        .unwrap();
        wire::Launch {
            binding_id: wire::new_id().unwrap(),
            invocation_id: wire::new_id().unwrap(),
            run_id: wire::new_id().unwrap(),
            attestation_id: wire::new_id().unwrap(),
            profile_sha256: provenance["profile_sha256"].as_str().unwrap().into(),
            approved_fixture_id: "runtime_blocked".into(),
            input_artifact_refs: vec![],
            lease_id: wire::new_id().unwrap(),
            control_revision: 0,
        }
    }
    #[test]
    fn failed_native_drop_cannot_admit_a_surviving_group_and_verified_emptiness_allows_a_successor()
    {
        let mut old = Cgroup::create(&launch())
            .expect("root access to the real prepared Linux cgroup hierarchy required");
        let mut child = OwnedChild(
            std::process::Command::new("/bin/sleep")
                .arg("30")
                .spawn()
                .unwrap(),
        );
        old.place(child.0.id(), Instant::now()).unwrap();
        assert!(
            old.populated().unwrap(),
            "test must actually place a live owned process"
        );
        let path = old.path.clone();
        let original = read_bounded(Path::new("/var/lib/razen/invocation.lock"), 16384).unwrap();
        let interrupted = b"{test-owned-interrupted-write";
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open("/var/lib/razen/invocation.lock")
            .unwrap();
        writer.seek(SeekFrom::End(0)).unwrap();
        writer.write_all(interrupted).unwrap();
        writer.sync_all().unwrap();
        drop(old);
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "failed Drop must leave a real surviving process for this regression"
        );
        assert_eq!(
            // SAFETY: writer owns this test's live native capacity descriptor, not a foreign PID.
            unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
            0,
            "the keeper's actual OS lock must have been released"
        );
        // SAFETY: releases only this test descriptor's exclusive flock.
        assert_eq!(unsafe { libc::flock(writer.as_raw_fd(), libc::LOCK_UN) }, 0);
        assert!(
            Cgroup::create(&launch()).is_err(),
            "an available flock must not bypass malformed durable occupancy"
        );
        let current = read_bounded(Path::new("/var/lib/razen/invocation.lock"), 16384).unwrap();
        assert_eq!(&current[..original.len()], original.as_slice());
        assert_eq!(
            &current[original.len()..],
            interrupted,
            "never repair or truncate a foreign writer's state"
        );
        writer.set_len(original.len() as u64).unwrap();
        writer.sync_all().unwrap();
        assert!(
            Cgroup::create(&launch()).is_err(),
            "valid ownership still cannot authorize overlap with a populated old group"
        );
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        let deadline = Instant::now();
        loop {
            let events = fs::read_to_string(path.join("cgroup.events")).unwrap();
            if events
                .lines()
                .find_map(|line| line.strip_prefix("populated "))
                == Some("0")
            {
                break;
            }
            assert!(
                deadline.elapsed() < Duration::from_secs(1),
                "real owned group never became empty"
            );
            std::thread::sleep(Duration::from_millis(2));
        }
        let successor = Cgroup::create(&launch())
            .expect("actual independently empty old group must permit sequential reuse");
        assert_ne!(successor.path, path);
        assert!(
            !path.exists(),
            "only the authenticated empty previous group is removed"
        );
        drop(successor);
        assert!(
            read_bounded(Path::new("/var/lib/razen/invocation.lock"), 16384)
                .unwrap()
                .is_empty()
        );
    }
}
