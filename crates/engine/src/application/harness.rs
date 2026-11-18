//! Shared trusted orchestration records. Private engine files never contain capabilities.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::cli::Suite;
use super::profile::LoadedProfile;
use crate::domain::proofs::{
    CaseStatus, ProofCase, ProofInventory, ProofResult as CaseResult, Run, WorkPackage,
};
use crate::domain::validation::bounded_vec;
use crate::domain::values::{
    AuditTime, CatalogId, ContractVersion, Digest, EntityId, WireInt, non_null_optional,
};
use crate::protocol::codec::PROTOCOL;
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

pub const BOOTSTRAP_PATH: &str = "ephemeral/engine-bootstrap.json";
pub const OUTCOME_PATH: &str = "ephemeral/engine-outcome.json";
pub const READY_PATH: &str = "ephemeral/engine-ready.json";
pub const TRACE_PATH: &str = "ephemeral/engine-trace.jsonl";
pub const LIVE_RUN_PATH: &str = "ephemeral/live-run.json";
pub const EXAMPLES_PATH: &str = "ephemeral/contract-examples.json";
pub const MAX_METADATA_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TRACE_BYTES: usize = 32 * 1024 * 1024;

// Stable, immutable native lease bindings survive ephemeral cleanup. stdout is
// the reserved inherited lease descriptor, never an engine output channel.
pub const ENGINE_LEASE_PATH: &str = "engine-lifetime.json";
pub const ENGINE_STARTUP_PATH: &str = "engine-startup.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseRecord {
    schema_version: ContractVersion,
    run_id: EntityId,
    lease_id: EntityId,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartupRecord {
    schema_version: ContractVersion,
    run_id: EntityId,
    device: u64,
    inode: u64,
    lease_sha256: Digest,
}

pub struct EngineLease(std::fs::File);
pub struct EngineQuiescence {
    lease: std::fs::File,
    run_id: EntityId,
}

impl EngineLease {
    /// Publish the native binding while holding both the workspace guard and
    /// the lease. No engine may be forked until this function has returned.
    pub fn create(workspace: &crate::adapters::workspace::OwnedDirectory) -> ProofResult<Self> {
        use rustix::fs::{self, FlockOperation, Mode, OFlags};
        use std::io::Write;
        let directory = workspace.lock_directory()?;
        let flags =
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        let mut lease = std::fs::File::from(
            fs::openat(
                &directory,
                ENGINE_LEASE_PATH,
                flags,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| invalid())?,
        );
        fs::flock(&lease, FlockOperation::NonBlockingLockExclusive).map_err(|_| invalid())?;
        let bytes = serde_json::to_vec(&LeaseRecord {
            schema_version: ContractVersion::V0_1_0,
            run_id: workspace.run_id(),
            lease_id: EntityId::new(),
        })
        .map_err(|_| invalid())?;
        lease.write_all(&bytes).map_err(|_| invalid())?;
        lease.sync_all().map_err(|_| invalid())?;
        let native = fs::fstat(&lease).map_err(|_| invalid())?;
        let startup = StartupRecord {
            schema_version: ContractVersion::V0_1_0,
            run_id: workspace.run_id(),
            device: native.st_dev as u64,
            inode: native.st_ino as u64,
            lease_sha256: Digest::of(&bytes),
        };
        let mut seal = std::fs::File::from(
            fs::openat(
                &directory,
                ENGINE_STARTUP_PATH,
                flags,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(|_| invalid())?,
        );
        seal.write_all(&serde_json::to_vec(&startup).map_err(|_| invalid())?)
            .map_err(|_| invalid())?;
        seal.sync_all().map_err(|_| invalid())?;
        directory.sync_all().map_err(|_| invalid())?;
        Ok(Self(lease))
    }

    /// dup2 at fork/exec preserves the already locked open-file description.
    /// The parent never unlocks it: its own descriptor is merely closed later.
    pub fn child_stdio(&self) -> ProofResult<std::process::Stdio> {
        self.0
            .try_clone()
            .map(std::process::Stdio::from)
            .map_err(|_| invalid())
    }

    pub(crate) fn inherit(
        workspace: &crate::adapters::workspace::OwnedDirectory,
    ) -> ProofResult<Self> {
        use rustix::fs::{self, FlockOperation};
        let directory = workspace.lock_directory()?;
        let (named, _) = bound_lease(&directory, workspace.run_id())?;
        let inherited = std::io::stdout();
        let original = fs::fstat(&inherited).map_err(|_| invalid())?;
        let expected = fs::fstat(&named).map_err(|_| invalid())?;
        if original.st_dev != expected.st_dev || original.st_ino != expected.st_ino {
            return Err(invalid());
        }
        // A fresh independent open must NOT own this lock. Only the inherited
        // description may retain it; reacquiring a recreated idle lock is denied.
        match fs::flock(&named, FlockOperation::NonBlockingLockExclusive) {
            Err(rustix::io::Errno::WOULDBLOCK) => {}
            _ => return Err(invalid()),
        }
        fs::flock(&inherited, FlockOperation::NonBlockingLockExclusive).map_err(|_| invalid())?;
        let duplicate = rustix::io::fcntl_dupfd_cloexec(&inherited, 3).map_err(|_| invalid())?;
        Ok(Self(std::fs::File::from(duplicate)))
    }

    /// The independent native lock must remain held throughout cleanup.
    /// Missing or unbound old engine artifacts never establish quiescence.
    pub fn quiescent(
        workspace: &crate::adapters::workspace::OwnedDirectory,
    ) -> ProofResult<Option<EngineQuiescence>> {
        use rustix::fs::{self, AtFlags, FlockOperation};
        let directory = workspace.lock_directory()?;
        match fs::statat(&directory, ENGINE_LEASE_PATH, AtFlags::SYMLINK_NOFOLLOW) {
            Err(rustix::io::Errno::NOENT) => {
                for path in [ENGINE_STARTUP_PATH, BOOTSTRAP_PATH, READY_PATH] {
                    match fs::statat(&directory, path, AtFlags::SYMLINK_NOFOLLOW) {
                        Err(rustix::io::Errno::NOENT) => {}
                        _ => return Err(invalid()),
                    }
                }
                return Ok(None);
            }
            Err(_) => return Err(invalid()),
            Ok(_) => {}
        }
        let (lease, _) = bound_lease(&directory, workspace.run_id())?;
        fs::flock(&lease, FlockOperation::NonBlockingLockExclusive).map_err(|_| {
            ProofError::new(
                ErrorCode::ProviderUnavailable,
                "Owned engine or orchestrator still holds its native execution lease",
            )
        })?;
        Ok(Some(EngineQuiescence {
            lease,
            run_id: workspace.run_id(),
        }))
    }
}

impl EngineQuiescence {
    pub(crate) fn validate(
        &self,
        workspace: &crate::adapters::workspace::OwnedDirectory,
    ) -> ProofResult<()> {
        if self.run_id != workspace.run_id() {
            return Err(invalid());
        }
        let directory = workspace.lock_directory()?;
        let (named, _) = bound_lease(&directory, self.run_id)?;
        let first = rustix::fs::fstat(&named).map_err(|_| invalid())?;
        let held = rustix::fs::fstat(&self.lease).map_err(|_| invalid())?;
        if first.st_dev != held.st_dev || first.st_ino != held.st_ino {
            return Err(invalid());
        }
        Ok(())
    }

    pub(crate) fn binding(
        &self,
        workspace: &crate::adapters::workspace::OwnedDirectory,
    ) -> ProofResult<Digest> {
        self.validate(workspace)?;
        Ok(Digest::of(
            &workspace.read(std::path::Path::new(ENGINE_STARTUP_PATH), 4096)?,
        ))
    }
}

fn bound_lease(
    directory: &std::fs::File,
    run_id: EntityId,
) -> ProofResult<(std::fs::File, StartupRecord)> {
    use rustix::fs::{self, FileType, Mode, OFlags};
    use std::io::Read;
    let read = |path: &str| -> ProofResult<(std::fs::File, Vec<u8>)> {
        let mut file = std::fs::File::from(
            fs::openat(
                directory,
                path,
                OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| invalid())?,
        );
        let native = fs::fstat(&file).map_err(|_| invalid())?;
        if FileType::from_raw_mode(native.st_mode) != FileType::RegularFile
            || native.st_nlink != 1
            || native.st_uid != rustix::process::geteuid().as_raw()
            || native.st_mode as u32 & 0o7777 != 0o600
            || native.st_size <= 0
            || native.st_size > 4096
        {
            return Err(invalid());
        }
        let mut bytes = Vec::new();
        file.by_ref()
            .take(4097)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid())?;
        if bytes.len() != native.st_size as usize {
            return Err(invalid());
        }
        Ok((file, bytes))
    };
    let (_, startup) = read(ENGINE_STARTUP_PATH)?;
    let startup: StartupRecord = serde_json::from_slice(&startup).map_err(|_| invalid())?;
    let (lease, bytes) = read(ENGINE_LEASE_PATH)?;
    let record: LeaseRecord = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let native = fs::fstat(&lease).map_err(|_| invalid())?;
    if startup.run_id != run_id
        || record.run_id != run_id
        || startup.schema_version != ContractVersion::V0_1_0
        || record.schema_version != ContractVersion::V0_1_0
        || startup.device != native.st_dev as u64
        || startup.inode != native.st_ino as u64
        || startup.lease_sha256 != Digest::of(&bytes)
    {
        return Err(invalid());
    }
    Ok((lease, startup))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScenarioManifest {
    pub schema_version: ContractVersion,
    pub fixture_catalog: String,
    #[serde(deserialize_with = "bounded_vec")]
    pub packages: Vec<WorkPackage>,
    #[serde(deserialize_with = "bounded_vec")]
    pub cases: Vec<ProofCase>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseSelection {
    pub schema_version: ContractVersion,
    pub fixture_catalog: String,
    pub fixture_manifest_sha256: Digest,
    pub inventory: ProofInventory,
    #[serde(deserialize_with = "bounded_vec")]
    pub selected_case_ids: Vec<CatalogId>,
}

impl ScenarioManifest {
    pub fn select(
        self,
        suite: Suite,
        case_id: Option<&CatalogId>,
        digest: Digest,
    ) -> ProofResult<CaseSelection> {
        if self.fixture_catalog != "fixtures/scenarios/approved-fixtures.json" {
            return Err(invalid());
        }
        let inventory = ProofInventory::new(self.packages, self.cases)?;
        let selected_case_ids = {
            let mut initial = BTreeSet::new();
            for case in inventory.cases() {
                if case_id.is_none_or(|id| *id == case.case_id) && suite.contains(&case.case_id)? {
                    initial.insert(&case.case_id);
                }
            }
            if initial.is_empty() {
                return Err(invalid());
            }
            let mut dependencies = BTreeSet::new();
            for case in inventory
                .cases()
                .iter()
                .filter(|case| initial.contains(&case.case_id))
            {
                let package = inventory
                    .packages()
                    .iter()
                    .find(|package| package.package_id == case.package_id)
                    .ok_or_else(invalid)?;
                dependencies.extend(package.requires.iter());
            }
            for _ in 0..inventory.packages().len() {
                let previous = dependencies.len();
                for package in inventory.packages() {
                    if dependencies.contains(&package.package_id) {
                        dependencies.extend(package.requires.iter());
                    }
                }
                if dependencies.len() == previous {
                    break;
                }
            }
            inventory
                .cases()
                .iter()
                .filter(|case| {
                    initial.contains(&case.case_id) || dependencies.contains(&case.package_id)
                })
                .map(|case| case.case_id.clone())
                .collect()
        };
        let selection = CaseSelection {
            schema_version: self.schema_version,
            fixture_catalog: self.fixture_catalog,
            fixture_manifest_sha256: digest,
            inventory,
            selected_case_ids,
        };
        selection.validate()?;
        Ok(selection)
    }
}

impl CaseSelection {
    pub fn validate(&self) -> ProofResult<()> {
        if self.fixture_catalog != "fixtures/scenarios/approved-fixtures.json"
            || self.selected_case_ids.is_empty()
            || self.selected_case_ids.len() > self.inventory.cases().len()
        {
            return Err(invalid());
        }
        let selected: BTreeSet<_> = self.selected_case_ids.iter().collect();
        if selected.len() != self.selected_case_ids.len() {
            return Err(invalid());
        }
        // Selection is an ordered subsequence, so execution and result assembly
        // can merge it with the full inventory without cloning or repeated scans.
        let mut cursor = self.selected_case_ids.iter();
        let mut next = cursor.next();
        for case in self.inventory.cases() {
            if next == Some(&case.case_id) {
                next = cursor.next();
            }
            if !selected.contains(&case.case_id) {
                continue;
            }
            let package = self
                .inventory
                .packages()
                .iter()
                .find(|package| package.package_id == case.package_id)
                .ok_or_else(invalid)?;
            for dependency in &package.requires {
                let required = self
                    .inventory
                    .packages()
                    .iter()
                    .find(|package| package.package_id == *dependency)
                    .ok_or_else(invalid)?;
                if required.case_ids.iter().any(|id| !selected.contains(id)) {
                    return Err(invalid());
                }
            }
        }
        if next.is_some() {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineBootstrap {
    pub schema_version: ContractVersion,
    pub run_id: EntityId,
    pub started_at: AuditTime,
    pub profile_sha256: Digest,
    pub fixture_manifest_sha256: Digest,
    pub contract_examples_sha256: Digest,
    pub orchestrator_sha256: Digest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineReady {
    pub schema_version: ContractVersion,
    pub run_id: EntityId,
    pub engine_pid: WireInt,
    pub control_resource_id: EntityId,
    pub investigation_id: EntityId,
    pub clock_epoch_id: EntityId,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineOutcome {
    pub schema_version: ContractVersion,
    pub run: Run,
    #[serde(deserialize_with = "bounded_vec")]
    pub results: Vec<CaseResult>,
    pub trace_sha256: Digest,
    pub trace_length_bytes: WireInt,
    pub interrupted: bool,
    #[serde(
        default,
        deserialize_with = "non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    pub error: Option<ProofError>,
}

impl EngineOutcome {
    pub fn validate(
        &self,
        bootstrap: &EngineBootstrap,
        selection: &CaseSelection,
        profile: &LoadedProfile,
    ) -> ProofResult<()> {
        self.run.validate()?;
        selection.validate()?;
        if self.run.run_id != bootstrap.run_id
            || self.run.started_at != bootstrap.started_at
            || self.run.profile_sha256 != bootstrap.profile_sha256
            || self.run.profile_sha256 != profile.sha256()
            || self.run.profile_id != profile.config().profile_id
            || self.run.fixture_manifest_sha256 != bootstrap.fixture_manifest_sha256
            || self.run.fixture_manifest_sha256 != selection.fixture_manifest_sha256
            || self.results.len() != selection.inventory.cases().len()
            || self.trace_length_bytes.get() > MAX_TRACE_BYTES as u64
        {
            return Err(invalid());
        }
        let mut selected = selection.selected_case_ids.iter();
        let mut next = selected.next();
        for (case, result) in selection.inventory.cases().iter().zip(&self.results) {
            result.validate()?;
            let wanted = next == Some(&case.case_id);
            if wanted {
                next = selected.next();
            }
            if result.run_id != self.run.run_id
                || result.case_id != case.case_id
                || result.expected != case.expected
                || (!wanted && result.status != CaseStatus::Unexecuted)
                || (wanted
                    && result.status == CaseStatus::Unexecuted
                    && self.run.finished_at.is_some()
                    && !self.interrupted
                    && self.error.is_none())
            {
                return Err(invalid());
            }
        }
        if next.is_some() {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    pub total: WireInt,
    pub passed: WireInt,
    pub failed: WireInt,
    pub blocked: WireInt,
    pub unexecuted: WireInt,
}

impl Counts {
    pub fn from_results(results: &[CaseResult]) -> ProofResult<Self> {
        if results.len() > 35 {
            return Err(invalid());
        }
        let mut ids = BTreeSet::new();
        let mut counts = Self {
            total: WireInt::new(results.len() as u64)?,
            passed: WireInt::ZERO,
            failed: WireInt::ZERO,
            blocked: WireInt::ZERO,
            unexecuted: WireInt::ZERO,
        };
        let run_id = results.first().map(|result| result.run_id);
        for result in results {
            result.validate()?;
            if Some(result.run_id) != run_id || !ids.insert(&result.case_id) {
                return Err(invalid());
            }
            let value = match result.status {
                CaseStatus::Passed => &mut counts.passed,
                CaseStatus::Failed => &mut counts.failed,
                CaseStatus::Blocked => &mut counts.blocked,
                CaseStatus::Unexecuted => &mut counts.unexecuted,
            };
            *value = value.checked_add(WireInt::new(1)?)?;
        }
        Ok(counts)
    }

    pub fn validate(&self) -> ProofResult<()> {
        if self.total.get() > 35
            || self
                .passed
                .checked_add(self.failed)?
                .checked_add(self.blocked)?
                .checked_add(self.unexecuted)?
                != self.total
        {
            return Err(invalid());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandStatus {
    Passed,
    Failed,
    Blocked,
    Incomplete,
}

impl CommandStatus {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Passed => 0,
            Self::Failed => 1,
            Self::Blocked => 3,
            Self::Incomplete => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewStatus {
    Unreviewed,
    Approved,
    Rejected,
}

#[derive(Debug, Serialize)]
pub struct CommandSummary {
    pub protocol: &'static str,
    pub command: &'static str,
    pub status: CommandStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_ref: Option<&'static str>,
    pub counts: Counts,
    pub review_status: ReviewStatus,
    pub r0_exit_ready: bool,
    pub error_refs: Vec<EntityId>,
}

impl CommandSummary {
    pub fn without_run(command: &'static str, status: CommandStatus) -> Self {
        Self {
            protocol: PROTOCOL,
            command,
            status,
            run_ref: None,
            counts: Counts {
                total: WireInt::ZERO,
                passed: WireInt::ZERO,
                failed: WireInt::ZERO,
                blocked: WireInt::ZERO,
                unexecuted: WireInt::ZERO,
            },
            review_status: ReviewStatus::Unreviewed,
            r0_exit_ready: false,
            error_refs: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub struct PacketVerdict {
    pub counts: Counts,
    pub selected_status: CommandStatus,
    pub full_status: CommandStatus,
    pub review_status: ReviewStatus,
    pub r0_exit_ready: bool,
}

fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Harness inventory, bindings, chronology, or outcome is inconsistent",
    )
}
