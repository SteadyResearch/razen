use super::{integrity, unavailable};
use crate::application::profile::LoadedProfile;
use crate::domain::proofs::ImageDigest;
use crate::domain::values::{Digest, EntityId, WireInt};
use crate::protocol::error::ProofResult;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256, Sha512};
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::os::unix::{
    fs::{MetadataExt, OpenOptionsExt},
    net::UnixStream,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub const INSTANCE: &str = "razen-r0";
pub const IMAGE_SHA512: &str = "255ed35957114b453d72cf021f70542d09dccbb9210640a220a4d0931fa80e1ea956785a7ca88b33d58b55dd4d00f0677b0016a14c99a168b6ed8e239ac98b09";
#[derive(Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreparedRecord {
    pub owner_id: EntityId,
    pub uid: u32,
    pub lima_home: PathBuf,
    pub instance: String,
    pub profile_sha256: Digest,
    pub manager_sha256: Digest,
    pub source_sha256: Digest,
    pub provisioning_sha256: Digest,
    pub configuration_sha256: Digest,
    pub instance_yaml_sha256: Digest,
    pub ssh_config_sha256: Digest,
    pub manager_identity: ManagerIdentity,
    pub image_sha512: String,
    pub guest_manifest: serde_json::Value,
}
#[derive(Debug, Serialize)]
pub struct DoctorReport {
    pub available: bool,
    pub blockers: Vec<String>,
    pub observations: serde_json::Value,
}
pub struct PreparedGuest {
    pub(crate) repository: PathBuf,
    pub(crate) record: PreparedRecord,
}
/// Host-authenticated cleanup capability. It deliberately exposes no guest execution or staging API.
pub struct PreparedGuestStop {
    guest: PreparedGuest,
}
impl PreparedGuestStop {
    pub fn discover(repository: &Path, profile: &LoadedProfile) -> ProofResult<Self> {
        let guest = PreparedGuest::load_owned_record(repository, profile)?;
        guest.validate_stop_identity()?;
        Ok(Self { guest })
    }
    pub fn stop_for_run(&self, run_id: EntityId) -> ProofResult<()> {
        self.guest.stop_for_run(run_id)
    }
}
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagerIdentity {
    pub pid: u32,
    pub birth_sha256: Digest,
    pub boot_session_sha256: Digest,
}
impl PreparedGuest {
    pub fn discover(repository: &Path, profile: &LoadedProfile) -> ProofResult<Self> {
        let guest = Self::load_owned_record(repository, profile)?;
        let repository = &guest.repository;
        let record = &guest.record;
        let home = &record.lima_home;
        check_private(home, true)?;
        let owner: serde_json::Value =
            serde_json::from_slice(&private_read(&home.join(".razen-owner.json"), 1024)?)
                .map_err(|_| integrity("Guest resource ownership marker is invalid"))?;
        if owner["owner_id"] != record.owner_id.to_string() || owner["uid"] != record.uid {
            return Err(integrity("Guest resource ownership marker changed"));
        }
        validate_private_configuration(home)?;
        let manager = repository.join("target/r0-tools/lima/2.3.0/bin/limactl");
        if hash_file(&repository.join("target/r0-tools/lima-2.3.0-Darwin-arm64.tar.gz"))?
            != Digest::parse("b7af444bd8f91d3c307477e562f2cf3bd7595d62b9429185e4fa841563578cfc")?
        {
            return Err(integrity("Original pinned private Lima archive changed"));
        }
        if hash_file(&manager)? != record.manager_sha256
            || source_digest(repository)? != record.source_sha256
            || hash_file(&repository.join("scripts/proofs/provision-guest.sh"))?
                != record.provisioning_sha256
        {
            return Err(integrity(
                "Prepared manager/source/provisioning provenance changed",
            ));
        }
        guest.validate_manager_identity()?;
        let version = guest.manager(&["--version"], None, Duration::from_secs(5))?;
        if std::str::from_utf8(&version).ok().map(str::trim) != Some("limactl version 2.3.0") {
            return Err(unavailable(
                "Pinned private Lima manager version is unavailable",
            ));
        }
        let raw = guest.effective_configuration()?;
        if configuration_digest(&raw)? != guest.record.configuration_sha256 {
            return Err(integrity(
                "Effective VM configuration changed after preparation",
            ));
        }
        validate_configuration(&raw, profile)?;
        let image = guest.repository.join("target/r0-guest/debian.raw");
        verify_image_cache(&image, &profile.config().external_runner.image_digest)?;
        let observed = guest.guest_command(&["--inspect"], None, Duration::from_secs(10))?;
        let manifest: serde_json::Value = serde_json::from_slice(&observed)
            .map_err(|_| integrity("Guest preflight observations are malformed"))?;
        if manifest != guest.record.guest_manifest
            || manifest["owner_id"] != guest.record.owner_id.to_string()
        {
            return Err(integrity(
                "Installed guest resource owner/kernel/packages/binaries or mandatory prerequisites changed",
            ));
        }
        if manifest["available"] != true {
            return Err(unavailable(
                "Mandatory guest isolation primitives are unavailable",
            ));
        }
        Ok(guest)
    }
    fn load_owned_record(repository: &Path, profile: &LoadedProfile) -> ProofResult<Self> {
        let repository = repository
            .canonicalize()
            .map_err(|_| unavailable("Repository is unavailable"))?;
        let record: PreparedRecord = serde_json::from_slice(&private_read(
            &repository.join("target/r0-guest/prepared.json"),
            1_048_576,
        )?)
        .map_err(|_| integrity("Prepared guest registry is malformed"))?;
        if record.uid != rustix::process::geteuid().as_raw()
            || record.instance != INSTANCE
            || record.profile_sha256 != profile.sha256()
            || record.image_sha512 != IMAGE_SHA512
        {
            return Err(integrity("Prepared guest ownership/profile/image mismatch"));
        }
        let home = record
            .lima_home
            .canonicalize()
            .map_err(|_| unavailable("Prepared private Lima home is missing"))?;
        if home != record.lima_home
            || home.as_os_str().len() > 48
            || !home.starts_with("/private/tmp") && !home.starts_with("/tmp")
        {
            return Err(integrity(
                "Prepared Lima home is not a private short owned resource",
            ));
        }
        Ok(Self { repository, record })
    }
    pub fn instance(&self) -> &str {
        &self.record.instance
    }
    pub fn provenance(&self) -> &serde_json::Value {
        &self.record.guest_manifest
    }
    pub fn profile_sha256(&self) -> Digest {
        self.record.profile_sha256
    }
    pub(crate) fn manager(
        &self,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> ProofResult<Vec<u8>> {
        self.run_program(
            &self
                .repository
                .join("target/r0-tools/lima/2.3.0/bin/limactl"),
            args,
            stdin,
            timeout,
        )
    }
    pub(crate) fn command(&self) -> Command {
        let mut command = Command::new(
            self.repository
                .join("target/r0-tools/lima/2.3.0/bin/limactl"),
        );
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", &self.record.lima_home)
            .env("LIMA_HOME", &self.record.lima_home)
            .env("SSH", "/usr/bin/ssh")
            .env("TERM", "dumb")
            .current_dir(&self.record.lima_home);
        command
    }
    fn run_program(
        &self,
        program: &Path,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> ProofResult<Vec<u8>> {
        let mut command = self.command();
        if program
            != self
                .repository
                .join("target/r0-tools/lima/2.3.0/bin/limactl")
        {
            return Err(integrity("Unapproved manager executable"));
        }
        command.args(args);
        bounded_command(command, stdin, timeout, 8 * 1024 * 1024)
    }
    pub(crate) fn ssh_command(&self) -> ProofResult<Command> {
        let config = self
            .record
            .lima_home
            .join(self.instance())
            .join("ssh.config");
        if hash_file(&config)? != self.record.ssh_config_sha256 {
            return Err(integrity(
                "Prepared SSH configuration changed; no unreviewed SSH configuration is executed",
            ));
        }
        let known = self.record.lima_home.join("known_hosts");
        check_private(&known, false)?;
        let mut command = Command::new("/usr/bin/ssh");
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.record.lima_home)
            .current_dir(&self.record.lima_home);
        command
            .arg("-F")
            .arg(config)
            .args([
                "-T",
                "-oBatchMode=yes",
                "-oForwardAgent=no",
                "-oForwardX11=no",
                "-oForwardX11Trusted=no",
                "-oClearAllForwardings=yes",
                "-oControlMaster=no",
                "-oControlPath=none",
                "-oControlPersist=no",
                "-oStrictHostKeyChecking=yes",
                "-oHostKeyAlias=razen-r0-owned",
                "-oGlobalKnownHostsFile=/dev/null",
            ])
            .arg(format!("-oUserKnownHostsFile={}", known.display()))
            .arg(format!("lima-{}", self.instance()));
        Ok(command)
    }
    pub fn guest_command(
        &self,
        args: &[&str],
        stdin: Option<&[u8]>,
        timeout: Duration,
    ) -> ProofResult<Vec<u8>> {
        let approved = match args {
            ["--inspect"] | ["--stage"] => true,
            [
                "--termination" | "--failure" | "--observe" | "--runtime-input",
                id,
            ] => EntityId::parse(id).is_ok(),
            _ => false,
        };
        if !approved {
            return Err(integrity(
                "Unapproved supervisor operation; arbitrary commands are forbidden",
            ));
        }
        let mut command = self.ssh_command()?;
        command
            .args(["sudo", "-n", "/usr/local/libexec/razen-tool-supervisor"])
            .args(args);
        bounded_command(command, stdin, timeout, 8 * 1024 * 1024)
    }
    pub fn validate_live(&self, profile: &LoadedProfile) -> ProofResult<()> {
        if profile.sha256() != self.record.profile_sha256 {
            return Err(integrity("Current guest profile changed"));
        }
        self.validate_manager_identity()?;
        validate_private_configuration(&self.record.lima_home)?;
        let value = self.effective_configuration()?;
        validate_configuration(&value, profile)?;
        if configuration_digest(&value)? != self.record.configuration_sha256 {
            return Err(integrity("Current effective guest configuration changed"));
        }
        let bytes = self.guest_command(&["--inspect"], None, Duration::from_secs(5))?;
        let observed: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("Current guest inspection is invalid"))?;
        if observed != self.record.guest_manifest || observed["available"] != true {
            return Err(unavailable(
                "Current guest provenance or isolation primitives changed",
            ));
        }
        Ok(())
    }
    pub(crate) fn validate_manager_identity(&self) -> ProofResult<()> {
        if manager_identity(&self.record.lima_home, self.record.uid)?
            != self.record.manager_identity
        {
            return Err(unavailable(
                "Prepared VZ owner process or boot identity changed; doctor never repairs or adopts it",
            ));
        }
        Ok(())
    }
    pub fn effective_configuration(&self) -> ProofResult<serde_json::Value> {
        let path = self
            .record
            .lima_home
            .join(self.instance())
            .join("lima.yaml");
        check_private(&path, false)?;
        if hash_file(&path)? != self.record.instance_yaml_sha256 {
            return Err(integrity(
                "Prepared instance YAML changed; refusing to resolve any new template or remote reference",
            ));
        }
        let raw =
            fs::read(&path).map_err(|_| unavailable("Instance configuration is unavailable"))?;
        if raw.len() > 262_144
            || raw.windows(8).any(|w| w == b"https://") && raw.windows(6).any(|w| w == b"base: ")
        {
            return Err(integrity(
                "External template references are forbidden in prepared configuration",
            ));
        }
        let path = path
            .to_str()
            .ok_or_else(|| integrity("Invalid configuration pathname"))?;
        let bytes = self.manager(
            &["template", "yq", path, ". | @json"],
            None,
            Duration::from_secs(5),
        )?;
        serde_json::from_slice(&bytes)
            .map_err(|_| integrity("Cannot decode effective Lima configuration"))
    }
    pub(crate) fn capacity_lock(&self) -> ProofResult<DurableCapacity> {
        let capacity = self.raw_capacity_lock()?;
        if let Some(occupancy) = capacity.host_record()? {
            self.validate_occupancy(&occupancy)?;
            if !occupancy.transport_terminated {
                let transport = occupancy.transport.as_ref().ok_or_else(|| {
                    unavailable(
                        "Previous launch transport identity is unknown; occupancy remains sealed",
                    )
                })?;
                if process_identity(transport.pid)? == Some(transport.birth_sha256) {
                    return Err(occupied());
                }
            }
            self.termination_record(&occupancy)?;
            capacity.clear(&occupancy)?;
        }
        capacity.ensure_empty()?;
        Ok(capacity)
    }
    pub(crate) fn raw_capacity_lock(&self) -> ProofResult<DurableCapacity> {
        DurableCapacity::acquire(&self.repository.join("target/r0-guest/invocation.lock"))
    }
    pub(crate) fn claim_capacity(
        &self,
        capacity: &DurableCapacity,
        launch: &crate::protocol::messages::SupervisorLaunch,
    ) -> ProofResult<HostOccupancy> {
        capacity.ensure_empty()?;
        let occupancy = HostOccupancy {
            occupancy_id: EntityId::new(),
            prepared_sha256: self.prepared_digest()?,
            binding_id: launch.binding_id,
            invocation_id: launch.invocation_id,
            run_id: launch.run_id,
            attestation_id: launch.attestation_id,
            lease_id: launch.lease_id,
            profile_sha256: launch.profile_sha256,
            initial_revision: launch.control_revision,
            transport: None,
            transport_terminated: false,
        };
        capacity.store(&occupancy)?;
        Ok(occupancy)
    }
    pub(crate) fn prepared_digest(&self) -> ProofResult<Digest> {
        Ok(Digest::of(&serde_json::to_vec(&self.record).map_err(
            |_| integrity("Cannot bind durable capacity to prepared ownership"),
        )?))
    }
    pub(crate) fn validate_occupancy(&self, occupancy: &HostOccupancy) -> ProofResult<()> {
        if occupancy.transport_terminated && occupancy.transport.is_none()
            || occupancy
                .transport
                .as_ref()
                .is_some_and(|transport| transport.pid <= 1)
        {
            return Err(integrity(
                "Durable guest occupancy has no valid owned transport identity",
            ));
        }
        if occupancy.prepared_sha256 != self.prepared_digest()?
            || occupancy.profile_sha256 != self.profile_sha256()
        {
            return Err(integrity(
                "Durable guest occupancy has foreign prepared owner/source/configuration/binary/boot bindings",
            ));
        }
        Ok(())
    }
    /// Emergency containment must not depend on the possibly unresponsive guest transport.
    /// The immutable prepared binary observations remain bound to this exact original VM boot.
    pub(crate) fn validate_stop_identity(&self) -> ProofResult<()> {
        let current: PreparedRecord = serde_json::from_slice(&private_read(
            &self.repository.join("target/r0-guest/prepared.json"),
            1_048_576,
        )?)
        .map_err(|_| integrity("Prepared stop ownership record is malformed"))?;
        if current != self.record
            || current.uid != rustix::process::geteuid().as_raw()
            || current.instance != INSTANCE
            || current.image_sha512 != IMAGE_SHA512
        {
            return Err(integrity(
                "Prepared resource identity changed; no replacement VM is stopped",
            ));
        }
        check_private(&current.lima_home, true)?;
        let owner: serde_json::Value = serde_json::from_slice(&private_read(
            &current.lima_home.join(".razen-owner.json"),
            1024,
        )?)
        .map_err(|_| integrity("Prepared stop resource marker is malformed"))?;
        if owner["owner_id"] != current.owner_id.to_string() || owner["uid"] != current.uid {
            return Err(integrity("Prepared stop resource owner changed"));
        }
        if source_digest(&self.repository)? != current.source_sha256
            || hash_file(&self.repository.join("scripts/proofs/provision-guest.sh"))?
                != current.provisioning_sha256
            || hash_file(
                &self
                    .repository
                    .join("target/r0-tools/lima/2.3.0/bin/limactl"),
            )? != current.manager_sha256
            || hash_file(
                &self
                    .repository
                    .join("target/r0-tools/lima-2.3.0-Darwin-arm64.tar.gz"),
            )? != Digest::parse(
                "b7af444bd8f91d3c307477e562f2cf3bd7595d62b9429185e4fa841563578cfc",
            )?
            || hash_file(&current.lima_home.join(INSTANCE).join("ssh.config"))?
                != current.ssh_config_sha256
        {
            return Err(integrity(
                "Prepared stop source/configuration/binary provenance changed",
            ));
        }
        validate_private_configuration(&current.lima_home)?;
        self.validate_manager_identity()?;
        let profile = LoadedProfile::load(
            &self
                .repository
                .join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )?;
        if profile.sha256() != current.profile_sha256 {
            return Err(integrity("Prepared stop profile changed"));
        }
        let effective = self.effective_configuration()?;
        validate_configuration(&effective, &profile)?;
        if configuration_digest(&effective)? != current.configuration_sha256 {
            return Err(integrity("Prepared stop effective configuration changed"));
        }
        Ok(())
    }
    pub(crate) fn termination_record(
        &self,
        occupancy: &HostOccupancy,
    ) -> ProofResult<serde_json::Value> {
        self.validate_manager_identity()?;
        self.validate_occupancy(occupancy)?;
        let bytes = self.guest_command(
            &["--termination", &occupancy.invocation_id.to_string()],
            None,
            Duration::from_secs(5),
        )?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("Invalid independent guest termination journal"))?;
        if value["invocation_id"] != occupancy.invocation_id.to_string()
            || value["lease_id"] != occupancy.lease_id.to_string()
            || value["binding_id"] != occupancy.binding_id.to_string()
            || value["run_id"] != occupancy.run_id.to_string()
            || value["profile_sha256"] != occupancy.profile_sha256.to_string()
            || value["owner_id"] != self.record.owner_id.to_string()
            || value["empty_cgroup"] != true
            || value["cgroup_populated_after"] != 0
            || value["descendants_after"] != 0
            || value["control_revision"]
                .as_u64()
                .is_none_or(|revision| revision < occupancy.initial_revision.get())
            || value["lease_elapsed_us"].as_u64().is_none()
        {
            return Err(integrity(
                "Independent termination journal has foreign launch bindings or lacks whole-group emptiness",
            ));
        }
        let attestation = serde::Deserialize::deserialize(&value["attestation"])
            .map_err(|_| integrity("Independent journal attestation is malformed"))?;
        let profile = LoadedProfile::load(
            &self
                .repository
                .join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )?;
        if profile.sha256() != occupancy.profile_sha256 {
            return Err(integrity(
                "Independent journal current profile binding changed",
            ));
        }
        super::attestation::validate(
            &attestation,
            occupancy.run_id,
            occupancy.attestation_id,
            &profile,
            self,
        )?;
        Ok(value)
    }
    pub(crate) fn failure_record(&self, occupancy: &HostOccupancy) -> ProofResult<Vec<u8>> {
        self.validate_manager_identity()?;
        self.validate_occupancy(occupancy)?;
        let bytes = self.guest_command(
            &["--failure", &occupancy.invocation_id.to_string()],
            None,
            Duration::from_secs(5),
        )?;
        if bytes.len() > 1_048_576 {
            return Err(integrity("Private guest failure record exceeds its bound"));
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("Private guest failure record is malformed"))?;
        if value["record_type"] != "native_invocation_failure"
            || value["version"].as_u64() != Some(1)
            || value["outcome"] != "failed"
            || value["initial_control_revision"].as_u64() != Some(occupancy.initial_revision.get())
        {
            return Err(integrity(
                "Private guest failure record has an incompatible identity",
            ));
        }
        for (field, expected) in [
            ("invocation_id", occupancy.invocation_id),
            ("binding_id", occupancy.binding_id),
            ("run_id", occupancy.run_id),
            ("lease_id", occupancy.lease_id),
            ("requested_attestation_id", occupancy.attestation_id),
        ] {
            let actual: EntityId = serde::Deserialize::deserialize(&value[field])
                .map_err(|_| integrity("Private guest failure record has a malformed binding"))?;
            if actual != expected {
                return Err(integrity(
                    "Private guest failure record has a foreign binding",
                ));
            }
        }
        let profile: Digest = serde::Deserialize::deserialize(&value["profile_sha256"])
            .map_err(|_| integrity("Private guest failure profile is malformed"))?;
        if profile != occupancy.profile_sha256 {
            return Err(integrity(
                "Private guest failure record has a foreign profile",
            ));
        }
        let provenance = &value["provenance"];
        if provenance["status"] == "observed" {
            let owner: EntityId = serde::Deserialize::deserialize(&provenance["owner_id"])
                .map_err(|_| integrity("Private guest failure owner is malformed"))?;
            if owner != self.record.owner_id {
                return Err(integrity(
                    "Private guest failure record has a foreign owner",
                ));
            }
            for (field, expected) in [
                ("source_sha256", self.record.source_sha256),
                ("profile_sha256", self.record.profile_sha256),
                ("provisioning_sha256", self.record.provisioning_sha256),
                ("configuration_sha256", self.record.configuration_sha256),
            ] {
                let actual: Digest = serde::Deserialize::deserialize(&provenance[field])
                    .map_err(|_| integrity("Private guest failure provenance is malformed"))?;
                if actual != expected {
                    return Err(integrity("Private guest failure provenance changed"));
                }
            }
        } else if provenance["status"] != "unavailable" {
            return Err(integrity(
                "Private guest failure provenance status is invalid",
            ));
        }
        Ok(bytes)
    }
}

/// Preparation and cleanup share the invocation inode; neither may race a launched successor.
pub(crate) fn preparation_capacity(repository: &Path) -> ProofResult<DurableCapacity> {
    let capacity = DurableCapacity::acquire(&repository.join("target/r0-guest/invocation.lock"))?;
    capacity.ensure_empty()?;
    Ok(capacity)
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PreparationStopRecord {
    owner_id: EntityId,
    run_id: EntityId,
    uid: u32,
    profile_sha256: Digest,
    source_sha256: Digest,
    provisioning_sha256: Digest,
    manager_sha256: Digest,
    instance_yaml_sha256: Digest,
    manager_identity: ManagerIdentity,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoppedPreparation {
    original: PreparationStopRecord,
    #[serde(
        default,
        deserialize_with = "crate::domain::values::non_null_optional",
        skip_serializing_if = "Option::is_none"
    )]
    manager: Option<OwnedTransport>,
    configuration_sha256: Digest,
}

fn write_private_record(path: &Path, value: &impl Serialize) -> ProofResult<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| integrity("Cannot encode immutable preparation cleanup record"))?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| integrity("Cannot create immutable preparation cleanup record"))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|_| integrity("Cannot persist immutable preparation cleanup record"))
}

fn validate_configuration_binding(
    value: &serde_json::Value,
    expected: Digest,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    validate_configuration(value, profile)?;
    if configuration_digest(value)? != expected {
        return Err(integrity(
            "Cleanup effective configuration differs from its immutable stopped binding",
        ));
    }
    Ok(())
}

fn capture_cleanup_configuration(
    path: &Path,
    observed: &serde_json::Value,
    expected: Digest,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    validate_configuration_binding(observed, expected, profile)?;
    match path.symlink_metadata() {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_private_record(path, observed)
        }
        Err(_) => Err(integrity(
            "Cannot inspect immutable cleanup configuration capture",
        )),
        Ok(_) => {
            let saved: serde_json::Value = serde_json::from_slice(&private_read(path, 65536)?)
                .map_err(|_| integrity("Immutable cleanup configuration capture is malformed"))?;
            validate_configuration_binding(&saved, expected, profile)
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreparationRetirement {
    owner_id: EntityId,
    run_id: EntityId,
    entries: std::collections::BTreeMap<String, Digest>,
}

fn registry_entry(name: &str) -> bool {
    matches!(
        name,
        "owner.json"
            | "provenance.json"
            | "preparation-stop.json"
            | "preparation-stopped.json"
            | "source.tar"
            | "instance-yaml.sha256"
            | "effective.json"
            | "cleanup-effective.json"
            | "provision.log"
            | "guest-inspect.json"
            | "ssh-host-public-key"
            | "guest-dependency-captures.tar"
            | "guest-dependency-captures"
            | "canaries"
    )
}

fn registry_entry_digest(path: &Path) -> ProofResult<Digest> {
    if path.file_name() == Some(OsStr::new("canaries")) {
        check_private(path, true)?;
        if fs::read_dir(path)
            .map_err(|_| integrity("Cannot inspect owned canary directory"))?
            .next()
            .is_some()
        {
            return Err(integrity(
                "Nonempty canary directory is preserved; retirement refused",
            ));
        }
        return Ok(Digest::of(b""));
    }
    if path.file_name() != Some(OsStr::new("guest-dependency-captures")) {
        check_private(path, false)?;
        return hash_file(path);
    }
    check_private(path, true)?;
    let packages = path.join("guest-packages");
    check_private(&packages, true)?;
    if fs::read_dir(path)
        .map_err(|_| integrity("Cannot inspect package captures"))?
        .take(2)
        .count()
        != 1
    {
        return Err(integrity("Unknown entry in preparation package captures"));
    }
    let mut files = std::collections::BTreeMap::new();
    let mut total = 0u64;
    for entry in
        fs::read_dir(&packages).map_err(|_| integrity("Cannot inspect package captures"))?
    {
        let entry = entry.map_err(|_| integrity("Cannot inspect package capture"))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| integrity("Invalid package capture name"))?;
        let valid = matches!(name.as_str(), "packages.tsv" | "checked-at.txt")
            || name.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"+.-".contains(&byte)
            }) && [".arm64.", ".all."].iter().any(|arch| name.contains(arch))
                && [".copyright", ".policy", ".metadata", ".facts.json", ".uri"]
                    .iter()
                    .any(|suffix| name.ends_with(suffix));
        if !valid || files.len() >= 4096 {
            return Err(integrity(
                "Unknown or excessive preparation package captures",
            ));
        }
        check_private(&entry.path(), false)?;
        let size = entry
            .metadata()
            .map_err(|_| integrity("Cannot inspect package capture size"))?
            .len();
        total = total
            .checked_add(size)
            .ok_or_else(|| integrity("Package captures overflow"))?;
        if size > 16 * 1024 * 1024 || total > 128 * 1024 * 1024 {
            return Err(integrity("Preparation package captures exceed their bound"));
        }
        files.insert(name, hash_file(&entry.path())?);
    }
    Ok(Digest::of(
        &serde_json::to_vec(&files).map_err(|_| integrity("Cannot bind package captures"))?,
    ))
}

fn retired_directory(state: &Path, plan: &PreparationRetirement) -> PathBuf {
    state
        .join("retired")
        .join(format!("{}-{}", plan.owner_id, plan.run_id))
}

fn retirement_entry(state: &Path, archive: &Path, name: &str) -> ProofResult<PathBuf> {
    if !registry_entry(name) {
        return Err(integrity("Unknown preparation retirement entry"));
    }
    match (
        state.join(name).symlink_metadata(),
        archive.join(name).symlink_metadata(),
    ) {
        (Ok(_), Err(error)) if error.kind() == std::io::ErrorKind::NotFound => Ok(state.join(name)),
        (Err(error), Ok(_)) if error.kind() == std::io::ErrorKind::NotFound => {
            Ok(archive.join(name))
        }
        _ => Err(integrity(
            "Preparation retirement entry is missing, duplicated, or inaccessible",
        )),
    }
}

fn validate_retirement_files(
    state: &Path,
    archive: &Path,
    plan: &PreparationRetirement,
) -> ProofResult<()> {
    check_private(&state.join("retired"), true)?;
    for directory in [state, archive] {
        check_private(directory, true)?;
        for entry in fs::read_dir(directory)
            .map_err(|_| integrity("Cannot inspect preparation retirement"))?
        {
            let entry =
                entry.map_err(|_| integrity("Cannot inspect preparation retirement entry"))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| integrity("Invalid retirement entry name"))?;
            if directory == state
                && matches!(
                    name.as_str(),
                    "invocation.lock" | "debian.raw" | "retired" | "preparation-retirement.json"
                )
            {
                continue;
            }
            if !plan.entries.contains_key(&name) {
                return Err(integrity(
                    "Unknown preparation entry is preserved; retirement refused",
                ));
            }
        }
    }
    for (name, digest) in &plan.entries {
        if registry_entry_digest(&retirement_entry(state, archive, name)?)? != *digest {
            return Err(integrity("Preparation evidence changed during retirement"));
        }
    }
    Ok(())
}

fn archive_preparation(state: &Path, plan: &PreparationRetirement) -> ProofResult<()> {
    let archive = retired_directory(state, plan);
    validate_retirement_files(state, &archive, plan)?;
    // The write-ahead plan keeps preparation sealed throughout an interrupted move.
    // Every original fact is renamed, never rewritten; the stable capacity inode and image stay put.
    for name in plan.entries.keys() {
        let source = retirement_entry(state, &archive, name)?;
        if source.parent() == Some(state) {
            fs::rename(&source, archive.join(name))
                .map_err(|_| integrity("Cannot archive authenticated preparation evidence"))?;
        }
    }
    File::open(&archive)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| integrity("Cannot persist retired preparation evidence"))?;
    fs::rename(
        state.join("preparation-retirement.json"),
        archive.join("preparation-retirement.json"),
    )
    .map_err(|_| integrity("Cannot complete preparation retirement"))?;
    File::open(state)
        .and_then(|directory| directory.sync_all())
        .map_err(|_| integrity("Cannot persist preparation retirement"))
}

/// Only explicit selected-run cleanup retires a failed preparation. Automatic failure containment
/// leaves the stopped owner sealed until this call; it never retries provisioning.
pub fn retire_failed_preparation(
    repository: &Path,
    profile: &LoadedProfile,
    run_id: EntityId,
) -> ProofResult<()> {
    let repository = repository
        .canonicalize()
        .map_err(|_| unavailable("Preparation repository is unavailable"))?;
    let state = repository.join("target/r0-guest");
    if state
        .join("preparation-stopped.json")
        .symlink_metadata()
        .is_err()
        && state
            .join("preparation-retirement.json")
            .symlink_metadata()
            .is_err()
    {
        cleanup_failed_preparation(&repository, profile, run_id)?;
    }
    let capacity = preparation_capacity(&repository)?;
    ensure_unprepared(&state)?;
    let plan_path = state.join("preparation-retirement.json");
    let existing: Option<PreparationRetirement> = match plan_path.symlink_metadata() {
        Ok(_) => Some(
            serde_json::from_slice(&private_read(&plan_path, 65536)?)
                .map_err(|_| integrity("Preparation retirement plan is malformed"))?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => return Err(integrity("Cannot inspect preparation retirement plan")),
    };
    let receipt_path = match &existing {
        Some(plan) => {
            check_private(&state.join("retired"), true)?;
            let archive = retired_directory(&state, plan);
            check_private(&archive, true)?;
            retirement_entry(&state, &archive, "preparation-stopped.json")?
        }
        None => state.join("preparation-stopped.json"),
    };
    let stopped: StoppedPreparation = serde_json::from_slice(&private_read(&receipt_path, 16384)?)
        .map_err(|_| integrity("Preparation has no authenticated stopped receipt"))?;
    let original = &stopped.original;
    if original.run_id != run_id
        || original.uid != rustix::process::geteuid().as_raw()
        || original.profile_sha256 != profile.sha256()
        || stopped
            .manager
            .as_ref()
            .is_some_and(|manager| manager.pid != original.manager_identity.pid)
        || existing
            .as_ref()
            .is_some_and(|plan| plan.owner_id != original.owner_id || plan.run_id != run_id)
    {
        return Err(integrity(
            "Selected run does not own stopped preparation retirement",
        ));
    }
    if source_digest(&repository)? != original.source_sha256
        || hash_file(&repository.join("scripts/proofs/provision-guest.sh"))?
            != original.provisioning_sha256
        || hash_file(&repository.join("target/r0-tools/lima-2.3.0-Darwin-arm64.tar.gz"))?
            != Digest::parse("b7af444bd8f91d3c307477e562f2cf3bd7595d62b9429185e4fa841563578cfc")?
    {
        return Err(integrity(
            "Stopped preparation original source/manager provenance changed before retirement",
        ));
    }
    verify_image_cache(
        &state.join("debian.raw"),
        &profile.config().external_runner.image_digest,
    )?;
    let short = original.owner_id.to_string().replace('-', "");
    let home = Path::new("/private/tmp").join(format!("rzg-{}", &short[..12]));
    check_private(&home, true)?;
    if home
        .canonicalize()
        .map_err(|_| integrity("Stopped preparation home is unavailable"))?
        != home
    {
        return Err(integrity("Stopped preparation home changed"));
    }
    let marker: serde_json::Value =
        serde_json::from_slice(&private_read(&home.join(".razen-owner.json"), 1024)?)
            .map_err(|_| integrity("Stopped preparation resource owner is malformed"))?;
    if marker["owner_id"] != original.owner_id.to_string()
        || marker["uid"] != original.uid
        || hash_file(&home.join(INSTANCE).join("lima.yaml"))? != original.instance_yaml_sha256
        || hash_file(&repository.join("target/r0-tools/lima/2.3.0/bin/limactl"))?
            != original.manager_sha256
    {
        return Err(integrity("Stopped preparation resource identity changed"));
    }
    validate_private_configuration(&home)?;
    match &stopped.manager {
        Some(manager) if process_identity(manager.pid)? == Some(manager.birth_sha256) => {
            return Err(integrity(
                "Original preparation manager is still present; retirement refused",
            ));
        }
        None => ensure_original_manager_absent(&home, original.manager_identity.pid)?,
        Some(_) => {}
    }
    let mut command = Command::new(repository.join("target/r0-tools/lima/2.3.0/bin/limactl"));
    command
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", &home)
        .env("LIMA_HOME", &home)
        .env("SSH", "/usr/bin/ssh")
        .env("TERM", "dumb")
        .current_dir(&home)
        .args(["list", "--json", INSTANCE]);
    let status: serde_json::Value = serde_json::from_slice(&bounded_command(
        command,
        None,
        Duration::from_secs(5),
        65536,
    )?)
    .map_err(|_| integrity("Stopped preparation state is malformed"))?;
    if status["name"] != INSTANCE || status["status"] != "Stopped" {
        return Err(integrity(
            "Preparation is not independently observed stopped",
        ));
    }
    let cleanup_configuration = match &existing {
        Some(plan) => retirement_entry(
            &state,
            &retired_directory(&state, plan),
            "cleanup-effective.json",
        )?,
        None => state.join("cleanup-effective.json"),
    };
    // The actual pinned manager observation is authenticated above. Its full configuration
    // must match the ORIGINAL stopped receipt; no receipt or birth fact is rewritten.
    capture_cleanup_configuration(
        &cleanup_configuration,
        &status["config"],
        stopped.configuration_sha256,
        profile,
    )?;
    let plan = match existing {
        Some(plan) => plan,
        None => {
            let mut entries = std::collections::BTreeMap::new();
            for entry in fs::read_dir(&state)
                .map_err(|_| integrity("Cannot inspect owned preparation registry"))?
            {
                let entry = entry
                    .map_err(|_| integrity("Cannot inspect owned preparation registry entry"))?;
                let name = entry
                    .file_name()
                    .into_string()
                    .map_err(|_| integrity("Invalid preparation entry"))?;
                if matches!(name.as_str(), "invocation.lock" | "debian.raw" | "retired") {
                    continue;
                }
                if !registry_entry(&name) {
                    return Err(integrity(
                        "Unknown preparation entry is preserved; retirement refused",
                    ));
                }
                entries.insert(name, registry_entry_digest(&entry.path())?);
            }
            let plan = PreparationRetirement {
                owner_id: original.owner_id,
                run_id,
                entries,
            };
            let retired = state.join("retired");
            if retired.symlink_metadata().is_err() {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&retired)
                    .map_err(|_| integrity("Cannot create private retired preparation registry"))?;
            }
            check_private(&retired, true)?;
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(retired_directory(&state, &plan))
                .map_err(|_| integrity("Cannot create exact owner-bound preparation archive"))?;
            write_private_record(&plan_path, &plan)?;
            plan
        }
    };
    let archive = retired_directory(&state, &plan);
    for name in [
        "owner.json",
        "provenance.json",
        "preparation-stop.json",
        "preparation-stopped.json",
        "cleanup-effective.json",
    ] {
        if !plan.entries.contains_key(name) {
            return Err(integrity(
                "Retirement plan omits original ownership or stopped configuration facts",
            ));
        }
    }
    let owner: serde_json::Value = serde_json::from_slice(&private_read(
        &retirement_entry(&state, &archive, "owner.json")?,
        4096,
    )?)
    .map_err(|_| integrity("Retirement owner is malformed"))?;
    let provenance: serde_json::Value = serde_json::from_slice(&private_read(
        &retirement_entry(&state, &archive, "provenance.json")?,
        4096,
    )?)
    .map_err(|_| integrity("Retirement provenance is malformed"))?;
    if owner["owner_id"] != original.owner_id.to_string()
        || owner["run_id"] != run_id.to_string()
        || owner["uid"] != original.uid
        || owner["profile_sha256"] != original.profile_sha256.to_string()
        || provenance["owner_id"] != original.owner_id.to_string()
        || provenance["profile_sha256"] != original.profile_sha256.to_string()
        || provenance["source_sha256"] != original.source_sha256.to_string()
        || provenance["provisioning_sha256"] != original.provisioning_sha256.to_string()
    {
        return Err(integrity(
            "Retirement original owner/run/source facts changed",
        ));
    }
    // A build may have failed before writing this later artifact. If present it remains
    // evidence and must agree; cleanup authority never depends on its existence.
    if plan.entries.contains_key("effective.json") {
        let effective: serde_json::Value = serde_json::from_slice(&private_read(
            &retirement_entry(&state, &archive, "effective.json")?,
            65536,
        )?)
        .map_err(|_| integrity("Retirement effective configuration is malformed"))?;
        validate_configuration_binding(&effective, stopped.configuration_sha256, profile)?;
    }
    let recorded: PreparationStopRecord = serde_json::from_slice(&private_read(
        &retirement_entry(&state, &archive, "preparation-stop.json")?,
        8192,
    )?)
    .map_err(|_| integrity("Original preparation stop record is malformed"))?;
    if recorded != stopped.original {
        return Err(integrity(
            "Retirement cannot overwrite original preparation facts",
        ));
    }
    capacity.ensure_empty()?;
    archive_preparation(&state, &plan)
}

/// Cleanup of an actually started but not yet fully prepared VM requires its original birth capture.
/// It never constructs a PreparedRecord, adopts a new boot, repairs markers, or signals a PID.
pub fn cleanup_failed_preparation(
    repository: &Path,
    profile: &LoadedProfile,
    run_id: EntityId,
) -> ProofResult<()> {
    let repository = repository
        .canonicalize()
        .map_err(|_| unavailable("Partial preparation repository is unavailable"))?;
    let state = repository.join("target/r0-guest");
    let capacity = preparation_capacity(&repository)?;
    ensure_unprepared(&state)?;
    let record: PreparationStopRecord = serde_json::from_slice(&private_read(
        &state.join("preparation-stop.json"),
        8192,
    )?)
    .map_err(|_| {
        integrity(
            "Partial preparation has no valid original manager birth capture; no VM is adopted",
        )
    })?;
    let uid = rustix::process::geteuid().as_raw();
    let owner: serde_json::Value =
        serde_json::from_slice(&private_read(&state.join("owner.json"), 4096)?)
            .map_err(|_| integrity("Partial preparation owner is malformed"))?;
    let provenance: serde_json::Value =
        serde_json::from_slice(&private_read(&state.join("provenance.json"), 4096)?)
            .map_err(|_| integrity("Partial preparation provenance is malformed"))?;
    if record.run_id != run_id
        || record.uid != uid
        || record.profile_sha256 != profile.sha256()
        || owner["owner_id"] != record.owner_id.to_string()
        || owner["run_id"] != run_id.to_string()
        || owner["uid"] != uid
        || owner["profile_sha256"] != profile.sha256().to_string()
        || provenance["owner_id"] != record.owner_id.to_string()
        || provenance["profile_sha256"] != record.profile_sha256.to_string()
        || provenance["source_sha256"] != record.source_sha256.to_string()
        || provenance["provisioning_sha256"] != record.provisioning_sha256.to_string()
    {
        return Err(integrity(
            "Partial preparation does not belong to the selected run/owner/profile/source",
        ));
    }
    let short = record.owner_id.to_string().replace('-', "");
    let home = Path::new("/private/tmp").join(format!("rzg-{}", &short[..12]));
    check_private(&home, true)?;
    if home
        .canonicalize()
        .map_err(|_| unavailable("Partial preparation home is unavailable"))?
        != home
    {
        return Err(integrity("Partial preparation home changed"));
    }
    let marker: serde_json::Value =
        serde_json::from_slice(&private_read(&home.join(".razen-owner.json"), 1024)?)
            .map_err(|_| integrity("Partial preparation resource marker is malformed"))?;
    if marker["owner_id"] != record.owner_id.to_string() || marker["uid"] != uid {
        return Err(integrity(
            "Partial preparation resource has a different owner",
        ));
    }
    let manager = repository.join("target/r0-tools/lima/2.3.0/bin/limactl");
    let yaml = home.join(INSTANCE).join("lima.yaml");
    if source_digest(&repository)? != record.source_sha256
        || hash_file(&repository.join("scripts/proofs/provision-guest.sh"))?
            != record.provisioning_sha256
        || hash_file(&manager)? != record.manager_sha256
        || hash_file(&yaml)? != record.instance_yaml_sha256
        || hash_file(&repository.join("target/r0-tools/lima-2.3.0-Darwin-arm64.tar.gz"))?
            != Digest::parse("b7af444bd8f91d3c307477e562f2cf3bd7595d62b9429185e4fa841563578cfc")?
    {
        return Err(integrity(
            "Partial preparation source/configuration/pinned manager changed; no new process is adopted",
        ));
    }
    validate_private_configuration(&home)?;
    let command = |args: &[&str]| -> ProofResult<Vec<u8>> {
        let mut command = Command::new(&manager);
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
            .env("HOME", &home)
            .env("LIMA_HOME", &home)
            .env("SSH", "/usr/bin/ssh")
            .env("TERM", "dumb")
            .current_dir(&home)
            .args(args);
        bounded_command(command, None, Duration::from_secs(30), 8 * 1024 * 1024)
    };
    if std::str::from_utf8(&command(&["--version"])?)
        .ok()
        .map(str::trim)
        != Some("limactl version 2.3.0")
    {
        return Err(integrity(
            "Partial preparation manager version differs from the reviewed pin",
        ));
    }
    let bytes = command(&[
        "template",
        "yq",
        yaml.to_str()
            .ok_or_else(|| integrity("Partial instance path is invalid"))?,
        ". | @json",
    ])?;
    let effective: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| integrity("Partial preparation effective configuration is invalid"))?;
    let configuration_sha256 = configuration_digest(&effective)?;
    capture_cleanup_configuration(
        &state.join("cleanup-effective.json"),
        &effective,
        configuration_sha256,
        profile,
    )?;
    let observed: serde_json::Value =
        serde_json::from_slice(&command(&["list", "--json", INSTANCE])?)
            .map_err(|_| integrity("Partial preparation state observation is invalid"))?;
    if observed["name"] != INSTANCE {
        return Err(integrity(
            "Partial preparation instance observation changed",
        ));
    }
    let manager_process = if observed["status"] == "Stopped" {
        // A prior stop has no fresh transport birth capture; never synthesize one.
        ensure_original_manager_absent(&home, record.manager_identity.pid)?;
        None
    } else {
        if manager_identity(&home, uid)? != record.manager_identity {
            return Err(integrity(
                "Partial preparation manager birth/boot changed; no successor is stopped",
            ));
        }
        let manager_process = OwnedTransport {
            pid: record.manager_identity.pid,
            birth_sha256: process_identity(record.manager_identity.pid)?
                .ok_or_else(|| unavailable("Partial preparation manager disappeared"))?,
        };
        // Destructive boundary: only the original birth, still-empty capacity, and still-unprepared resource.
        ensure_unprepared(&state)?;
        capacity.ensure_empty()?;
        if manager_identity(&home, uid)? != record.manager_identity {
            return Err(integrity(
                "Partial preparation resource changed at stop boundary",
            ));
        }
        command(&["stop", "--force", INSTANCE])?;
        let bytes = command(&["list", "--json", INSTANCE])?;
        let status: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|_| integrity("Partial preparation stopped-state observation is invalid"))?;
        if status["name"] != INSTANCE || status["status"] != "Stopped" {
            return Err(integrity(
                "Partial preparation owned VM was not observed stopped",
            ));
        }
        super::lifecycle::observe_owned_exit(&manager_process)?;
        Some(manager_process)
    };
    write_private_record(
        &state.join("preparation-stopped.json"),
        &StoppedPreparation {
            original: record,
            manager: manager_process,
            configuration_sha256,
        },
    )
}

fn ensure_original_manager_absent(home: &Path, pid: u32) -> ProofResult<()> {
    if pid <= 1 || pid > i32::MAX as u32 || process_identity(pid)?.is_some() {
        return Err(integrity(
            "Stopped preparation original PID is live or invalid; no process is adopted or signaled",
        ));
    }
    let mut path = home.join(INSTANCE);
    check_private(&path, true)?;
    for name in ["ha.pid", "vz.pid"] {
        path.push(name);
        let entry = fs::symlink_metadata(&path);
        path.pop();
        if !matches!(entry, Err(error) if error.kind() == std::io::ErrorKind::NotFound) {
            return Err(integrity(
                "Stopped preparation retains manager PID state; no successor is adopted",
            ));
        }
    }
    Ok(())
}

fn ensure_unprepared(state: &Path) -> ProofResult<()> {
    match fs::symlink_metadata(state.join("prepared.json")) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(integrity(
            "A fully prepared resource requires selected-run PreparedGuest cleanup authority",
        )),
        Err(_) => Err(unavailable("Cannot authenticate partial preparation state")),
    }
}

pub fn doctor(repository: &Path, profile: &LoadedProfile) -> ProofResult<DoctorReport> {
    match PreparedGuest::discover(repository, profile) {
        Ok(guest) => Ok(DoctorReport {
            available: true,
            blockers: vec![],
            observations: serde_json::json!({"owner_id":guest.record.owner_id,"profile_sha256":guest.record.profile_sha256,"configuration_sha256":guest.record.configuration_sha256,"guest":guest.record.guest_manifest}),
        }),
        Err(error) => Ok(DoctorReport {
            available: false,
            blockers: vec![error.message.to_string()],
            observations: serde_json::json!({"isolation_status":"unavailable"}),
        }),
    }
}
pub fn validate_configuration(
    value: &serde_json::Value,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    let runner = &profile.config().external_runner;
    for (key, expected) in [
        ("vmType", serde_json::json!("vz")),
        ("arch", serde_json::json!("aarch64")),
        ("plain", serde_json::json!(true)),
        ("cpus", serde_json::json!(runner.guest_cpus.get())),
        ("propagateProxyEnv", serde_json::json!(false)),
    ] {
        if value[key] != expected {
            return Err(unavailable(
                "Effective VM isolation configuration is contaminated",
            ));
        }
    }
    // The pinned manager serializes empty sequences/maps with omitempty.
    // Absence means empty only for these fields, never for an isolation switch.
    for key in ["mounts", "portForwards", "networks"] {
        if value
            .get(key)
            .is_some_and(|entry| !entry.as_array().is_some_and(Vec::is_empty))
        {
            return Err(unavailable(
                "Effective VM mounts, forwards or networks are not empty",
            ));
        }
    }
    for key in [
        "forwardAgent",
        "forwardX11",
        "forwardX11Trusted",
        "loadDotSSHPubKeys",
        "overVsock",
    ] {
        if value["ssh"][key] != false {
            return Err(unavailable(
                "Effective SSH management configuration is contaminated",
            ));
        }
    }
    if value["containerd"]["system"] != false
        || value["containerd"]["user"] != false
        || value["vmOpts"]["vz"]["rosetta"]["enabled"] != false
        || value["hostResolver"]["enabled"] != false
        || value
            .get("env")
            .is_some_and(|entry| !entry.as_object().is_some_and(serde_json::Map::is_empty))
    {
        return Err(unavailable(
            "Guest agents, proxy environment or Rosetta are not disabled",
        ));
    }
    if value["memory"].as_str() != Some("2GiB") || value["user"]["name"] != "razen-manager" {
        return Err(unavailable(
            "Prepared VM CPU/memory/management user differs from approved profile",
        ));
    }
    Ok(())
}

/// Lima 2.3.0 creates this inert catalog, not an active instance network.
/// Only its reviewed original bytes and generated private SSH key files are allowed.
fn validate_private_configuration(home: &Path) -> ProofResult<()> {
    let config = home.join("_config");
    match fs::symlink_metadata(&config) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(integrity("Cannot inspect private Lima configuration")),
        Ok(_) => check_private(&config, true)?,
    }
    for entry in fs::read_dir(&config)
        .map_err(|_| integrity("Cannot enumerate private Lima configuration"))?
    {
        let entry =
            entry.map_err(|_| integrity("Cannot inspect private Lima configuration entry"))?;
        check_private(&entry.path(), false)?;
        match entry.file_name().to_str() {
            Some("user" | "user.pub") => {}
            Some("networks.yaml")
                if Digest::of(&private_read(&entry.path(), 8192)?)
                    == Digest::parse(
                        "6a81404a3a74190814c937e03610ff8cab1a0063b3bd153b642ee533db2f88ec",
                    )? => {}
            _ => {
                return Err(integrity(
                    "Private Lima configuration contains an override or changed generated catalog",
                ));
            }
        }
    }
    Ok(())
}
pub(crate) fn check_private(path: &Path, directory: bool) -> ProofResult<()> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| unavailable("Owned guest resource is missing"))?;
    if metadata.file_type().is_symlink()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || directory != metadata.is_dir()
        || !directory && (!metadata.is_file() || metadata.nlink() != 1)
    {
        return Err(integrity(
            "Guest resource ownership, type or private permissions are invalid",
        ));
    }
    Ok(())
}
pub(crate) fn private_read(path: &Path, cap: usize) -> ProofResult<Vec<u8>> {
    check_private(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| integrity("Cannot open private guest resource"))?;
    let mut bytes = Vec::new();
    file.take(cap as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| integrity("Cannot read private guest resource"))?;
    if bytes.len() > cap {
        return Err(integrity("Private guest resource exceeds its bound"));
    }
    Ok(bytes)
}
pub(crate) fn hash_file(path: &Path) -> ProofResult<Digest> {
    let metadata =
        fs::symlink_metadata(path).map_err(|_| unavailable("Pinned source/binary is missing"))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.nlink() != 1 {
        return Err(integrity(
            "Pinned sources/binaries must be regular non-symlink unshared files",
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| unavailable("Pinned source/binary is missing"))?;
    let mut hash = Sha256::new();
    let mut buf = [0; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| integrity("Cannot hash pinned source/binary"))?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(Digest::from_sha256(hash.finalize().into()))
}
pub(crate) fn sha512_file(path: &Path) -> ProofResult<ImageDigest> {
    check_private(path, false)?;
    let mut file = File::open(path).map_err(|_| unavailable("Pinned original image is missing"))?;
    let mut hash = Sha512::new();
    let mut buf = [0; 65536];
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|_| integrity("Cannot hash original image"))?;
        if n == 0 {
            break;
        }
        hash.update(&buf[..n]);
    }
    Ok(ImageDigest::from_sha512(hash.finalize().into()))
}

fn verify_image_cache(path: &Path, expected: &str) -> ProofResult<()> {
    if sha512_file(path)?.as_str() != expected {
        return Err(integrity("Original pinned Debian raw image hash differs"));
    }
    Ok(())
}

pub fn source_digest(repository: &Path) -> ProofResult<Digest> {
    fn collect(base: &Path, path: &Path, entries: &mut Vec<PathBuf>) -> ProofResult<()> {
        let mut children = fs::read_dir(path)
            .map_err(|_| unavailable("Approved guest source is missing"))?
            .map(|e| e.map(|v| v.path()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| integrity("Cannot enumerate guest source"))?;
        children.sort();
        for child in children {
            let meta = fs::symlink_metadata(&child)
                .map_err(|_| integrity("Cannot inspect guest source"))?;
            if meta.file_type().is_symlink() {
                return Err(integrity("Symlinked guest sources are forbidden"));
            }
            if meta.is_dir() {
                collect(base, &child, entries)?;
            } else {
                entries.push(
                    child
                        .strip_prefix(base)
                        .map_err(|_| integrity("Invalid guest source path"))?
                        .to_path_buf(),
                );
            }
        }
        Ok(())
    }
    let mut paths = vec![
        PathBuf::from("fixtures/linux-runner/Cargo.toml"),
        PathBuf::from("fixtures/linux-runner/Cargo.lock"),
        PathBuf::from("scripts/proofs/lima.yaml"),
        PathBuf::from("scripts/proofs/provision-guest.sh"),
        PathBuf::from("scripts/proofs/build-guest.sh"),
    ];
    collect(
        repository,
        &repository.join("fixtures/linux-runner/src"),
        &mut paths,
    )?;
    paths.sort();
    let mut hash = Sha256::new();
    for path in paths {
        hash.update(path.as_os_str().as_encoded_bytes());
        hash.update([0]);
        hash.update(hash_file(&repository.join(path))?.to_string().as_bytes());
    }
    Ok(Digest::from_sha256(hash.finalize().into()))
}
pub(crate) fn bounded_command(
    mut command: Command,
    input: Option<&[u8]>,
    timeout: Duration,
    cap: usize,
) -> ProofResult<Vec<u8>> {
    let (mut output, child_out) =
        UnixStream::pair().map_err(|_| unavailable("Cannot create manager output pipe"))?;
    let (mut diagnostics, child_err) =
        UnixStream::pair().map_err(|_| unavailable("Cannot create manager diagnostic pipe"))?;
    let (writer, child_in) =
        UnixStream::pair().map_err(|_| unavailable("Cannot create manager input pipe"))?;
    for stream in [&output, &diagnostics, &writer] {
        stream
            .set_nonblocking(true)
            .map_err(|_| unavailable("Cannot bound manager I/O"))?;
    }
    command
        .stdin(Stdio::from(OwnedFd::from(child_in)))
        .stdout(Stdio::from(OwnedFd::from(child_out)))
        .stderr(Stdio::from(OwnedFd::from(child_err)));
    let mut owned = crate::adapters::command::OwnedProcess::spawn(command)
        .map_err(|_| unavailable("Pinned guest manager cannot be launched"))?;
    let mut writer = Some(writer);
    (|| {
        let start = Instant::now();
        let mut bytes = Vec::new();
        let mut errors = Vec::new();
        let mut written = 0;
        let mut out_eof = false;
        let mut err_eof = false;
        let input = input.unwrap_or(&[]);
        loop {
            if start.elapsed() > timeout {
                return Err(unavailable(
                    "Guest management operation exceeded its independent deadline",
                ));
            }
            if let Some(stream) = writer.as_mut() {
                if written < input.len() {
                    let end = input.len().min(written + 8192);
                    match stream.write(&input[written..end]) {
                        Ok(0) => return Err(unavailable("Guest management input closed")),
                        Ok(n) => written += n,
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) => {}
                        Err(_) => return Err(unavailable("Guest management input failed")),
                    }
                }
                if written == input.len() {
                    drop(writer.take());
                }
            }
            for (stream, target, eof) in [
                (&mut output, &mut bytes, &mut out_eof),
                (&mut diagnostics, &mut errors, &mut err_eof),
            ] {
                if *eof {
                    continue;
                }
                let mut buffer = [0; 8192];
                match stream.read(&mut buffer) {
                    Ok(0) => *eof = true,
                    Ok(n) if n <= cap.saturating_sub(target.len()) => {
                        target.extend_from_slice(&buffer[..n])
                    }
                    Ok(_) => return Err(integrity("Guest management output exceeded its bound")),
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(_) => return Err(unavailable("Guest manager I/O failed")),
                }
            }
            if out_eof
                && err_eof
                && owned
                    .exited()
                    .map_err(|_| unavailable("Cannot observe guest manager status"))?
            {
                let status = owned
                    .finish(false)
                    .map_err(|_| unavailable("Cannot reap guest manager"))?;
                if writer.is_some() {
                    return Err(unavailable(
                        "Guest manager exited before receiving its complete request",
                    ));
                }
                if !status.success() {
                    return Err(unavailable(
                        "Guest management operation failed; no successful containment or preparation is inferred",
                    ));
                }
                return Ok(bytes);
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    })()
}

pub fn configuration_digest(value: &serde_json::Value) -> ProofResult<Digest> {
    struct Canonical<'a>(&'a serde_json::Value);
    impl serde::Serialize for Canonical<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::{SerializeMap, SerializeSeq};
            match self.0 {
                serde_json::Value::Object(object) => {
                    let mut map = serializer.serialize_map(Some(object.len()))?;
                    if object.keys().is_sorted() {
                        for (key, value) in object {
                            map.serialize_entry(key, &Canonical(value))?;
                        }
                    } else {
                        let mut keys = object.keys().collect::<Vec<_>>();
                        keys.sort_unstable();
                        for key in keys {
                            map.serialize_entry(key, &Canonical(&object[key.as_str()]))?;
                        }
                    }
                    map.end()
                }
                serde_json::Value::Array(values) => {
                    let mut sequence = serializer.serialize_seq(Some(values.len()))?;
                    for value in values {
                        sequence.serialize_element(&Canonical(value))?;
                    }
                    sequence.end()
                }
                value => value.serialize(serializer),
            }
        }
    }
    struct Hasher(Sha256);
    impl Write for Hasher {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut hash = Hasher(Sha256::new());
    serde_json::to_writer(&mut hash, &Canonical(value))
        .map_err(|_| integrity("Cannot hash canonical effective configuration"))?;
    Ok(Digest::from_sha256(hash.0.finalize().into()))
}

pub(crate) fn manager_identity(home: &Path, uid: u32) -> ProofResult<ManagerIdentity> {
    fn owned_read(path: &Path, uid: u32, cap: usize) -> ProofResult<Vec<u8>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|_| {
                unavailable("Owned VZ process state is missing; no implicit restart is permitted")
            })?;
        let metadata = file
            .metadata()
            .map_err(|_| integrity("Cannot inspect owned VZ process state"))?;
        if !metadata.is_file()
            || metadata.uid() != uid
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
            || metadata.len() > cap as u64
        {
            return Err(integrity(
                "Owned VZ PID/boot state is not a bounded regular owned file",
            ));
        }
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        (&mut file)
            .take(cap as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| integrity("Cannot read owned VZ process state"))?;
        if bytes.len() > cap {
            return Err(integrity("Owned VZ process state exceeds bound"));
        }
        Ok(bytes)
    }
    fn pid(bytes: &[u8]) -> ProofResult<u32> {
        let text = std::str::from_utf8(bytes)
            .map_err(|_| integrity("Owned VZ PID is not ASCII"))?
            .trim();
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(integrity("Owned VZ PID syntax invalid"));
        }
        let pid = text
            .parse::<u32>()
            .map_err(|_| integrity("Owned VZ PID out of range"))?;
        if pid <= 1 || pid > i32::MAX as u32 {
            return Err(integrity("Owned VZ PID out of range"));
        }
        Ok(pid)
    }
    let directory = home.join(INSTANCE);
    check_private(&directory, true)?;
    let host = pid(&owned_read(&directory.join("ha.pid"), uid, 32)?)?;
    let driver = pid(&owned_read(&directory.join("vz.pid"), uid, 32)?)?;
    if host != driver {
        return Err(integrity(
            "Pinned in-process VZ driver and host agent have different owner PIDs",
        ));
    }
    let boot = owned_read(&directory.join("boot-session.tmp"), uid, 128)?;
    let limits = || crate::adapters::command::CommandLimits {
        stdin_bytes: 0,
        stdout_bytes: 65536,
        stderr_bytes: 4096,
        timeout: Duration::from_secs(1),
    };
    let current = crate::adapters::command::capture_status(
        Path::new("/usr/sbin/sysctl"),
        &[OsStr::new("-n"), OsStr::new("kern.bootsessionuuid")],
        None,
        limits(),
    )?;
    let stored = std::str::from_utf8(&boot)
        .map_err(|_| integrity("Stored VZ boot session is invalid"))?
        .trim();
    let observed = std::str::from_utf8(&current.stdout)
        .map_err(|_| integrity("Current host boot session is invalid"))?
        .trim();
    if current.exit_code != 0 || stored.is_empty() || stored != observed {
        return Err(unavailable(
            "Owned VZ PID files are stale across host boot; no repair or PID signaling is performed",
        ));
    }
    let number = host.to_string();
    let process = crate::adapters::command::capture_status(
        Path::new("/bin/ps"),
        &[
            OsStr::new("-ww"),
            OsStr::new("-p"),
            OsStr::new(&number),
            OsStr::new("-o"),
            OsStr::new("pid=,uid=,lstart=,command="),
        ],
        None,
        limits(),
    )?;
    let text = std::str::from_utf8(&process.stdout)
        .map_err(|_| integrity("Owned VZ process identity is invalid"))?;
    let mut fields = text.split_whitespace();
    if process.exit_code != 0
        || fields.next().and_then(|value| value.parse::<u32>().ok()) != Some(host)
        || fields.next().and_then(|value| value.parse::<u32>().ok()) != Some(uid)
        || !text.contains(" hostagent ")
        || !text.contains(
            directory
                .join("ha.pid")
                .to_str()
                .ok_or_else(|| integrity("Owned VZ PID path is not UTF-8"))?,
        )
    {
        return Err(unavailable(
            "Owned VZ process is absent, stale, or no longer the dedicated host agent",
        ));
    }
    Ok(ManagerIdentity {
        pid: host,
        birth_sha256: Digest::of(&process.stdout),
        boot_session_sha256: Digest::of(stored.as_bytes()),
    })
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OwnedTransport {
    pub pid: u32,
    pub birth_sha256: Digest,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostOccupancy {
    pub occupancy_id: EntityId,
    pub prepared_sha256: Digest,
    pub binding_id: EntityId,
    pub invocation_id: EntityId,
    pub run_id: EntityId,
    pub attestation_id: EntityId,
    pub lease_id: EntityId,
    pub profile_sha256: Digest,
    pub initial_revision: WireInt,
    pub transport: Option<OwnedTransport>,
    pub transport_terminated: bool,
}
pub(crate) struct DurableCapacity {
    file: File,
}
fn occupied() -> crate::protocol::error::ProofError {
    crate::protocol::error::ProofError::new(
        crate::protocol::error::ErrorCode::BudgetExhausted,
        "Dedicated guest invocation capacity has unresolved durable occupancy",
    )
}
impl DurableCapacity {
    fn acquire(path: &Path) -> ProofResult<Self> {
        check_private(
            path.parent()
                .ok_or_else(|| integrity("Capacity has no owned parent"))?,
            true,
        )?;
        check_private(path, false)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(path)
            .map_err(|_| unavailable("Guest capacity inode cannot be opened"))?;
        let metadata = file
            .metadata()
            .map_err(|_| unavailable("Cannot authenticate capacity inode"))?;
        let named = fs::symlink_metadata(path)
            .map_err(|_| unavailable("Cannot authenticate named capacity inode"))?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o077 != 0
            || metadata.ino() != named.ino()
            || metadata.dev() != named.dev()
        {
            return Err(integrity(
                "Capacity inode is foreign, shared, replaced, or not private",
            ));
        }
        rustix::fs::flock(&file, rustix::fs::FlockOperation::NonBlockingLockExclusive)
            .map_err(|_| occupied())?;
        Ok(Self { file })
    }
    fn bytes(&self) -> ProofResult<Vec<u8>> {
        let mut file = &self.file;
        file.seek(SeekFrom::Start(0))
            .map_err(|_| unavailable("Cannot seek durable capacity"))?;
        let mut bytes = Vec::new();
        file.take(16385)
            .read_to_end(&mut bytes)
            .map_err(|_| unavailable("Cannot read durable capacity"))?;
        if bytes.len() > 16384 {
            return Err(integrity(
                "Durable capacity journal exceeds its fixed bound",
            ));
        }
        Ok(bytes)
    }
    pub(crate) fn host_record(&self) -> ProofResult<Option<HostOccupancy>> {
        let bytes = self.bytes()?;
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.last() != Some(&b'\n') {
            return Err(integrity(
                "Interrupted durable guest occupancy; capacity remains sealed",
            ));
        }
        let mut last: Option<HostOccupancy> = None;
        for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
            let next: HostOccupancy = serde_json::from_slice(line)
                .map_err(|_| integrity("Malformed or foreign durable guest occupancy"))?;
            if last.is_none() && (next.transport.is_some() || next.transport_terminated) {
                return Err(integrity(
                    "Durable capacity history lacks its original pre-launch reservation",
                ));
            }
            if let Some(previous) = &last
                && (previous.occupancy_id != next.occupancy_id
                    || previous.prepared_sha256 != next.prepared_sha256
                    || previous.binding_id != next.binding_id
                    || previous.invocation_id != next.invocation_id
                    || previous.run_id != next.run_id
                    || previous.attestation_id != next.attestation_id
                    || previous.lease_id != next.lease_id
                    || previous.profile_sha256 != next.profile_sha256
                    || previous.initial_revision != next.initial_revision
                    || previous
                        .transport
                        .as_ref()
                        .is_some_and(|transport| Some(transport) != next.transport.as_ref())
                    || previous.transport_terminated && !next.transport_terminated)
            {
                return Err(integrity(
                    "Durable capacity history changes immutable launch ownership",
                ));
            }
            last = Some(next);
        }
        Ok(last)
    }
    pub(crate) fn ensure_empty(&self) -> ProofResult<()> {
        if !self.bytes()?.is_empty() {
            return Err(occupied());
        }
        Ok(())
    }
    /// A free flock is not stop authority: the exact durable invocation must still own it.
    pub(crate) fn require_occupancy(&self, expected: &HostOccupancy) -> ProofResult<HostOccupancy> {
        let current = self.host_record()?.ok_or_else(|| {
            integrity(
                "Old guest occupancy has been released; no idle VM or successor may be stopped",
            )
        })?;
        let mut allowed = expected.clone();
        if allowed.transport.is_none() {
            allowed.transport = current.transport.clone();
        }
        allowed.transport_terminated = current.transport_terminated;
        if allowed != current || expected.transport_terminated && !current.transport_terminated {
            return Err(integrity(
                "Old guest invocation does not own current durable capacity; no successor may be stopped",
            ));
        }
        Ok(current)
    }
    /// Invocation stop authority requires a transport birth bound durably before launch delivery.
    /// A legitimate prebinding reservation remains valid occupancy, but is never destructive authority.
    pub(crate) fn require_stop_occupancy(
        &self,
        expected: &HostOccupancy,
    ) -> ProofResult<HostOccupancy> {
        let current = self.require_occupancy(expected)?;
        if current.transport.is_none() {
            return Err(integrity(
                "Invocation has no durably bound transport birth; uncertain occupancy remains sealed",
            ));
        }
        Ok(current)
    }
    pub(crate) fn record<T: serde::de::DeserializeOwned>(&self) -> ProofResult<Option<T>> {
        let bytes = self.bytes()?;
        if bytes.is_empty() {
            return Ok(None);
        }
        if bytes.last() != Some(&b'\n') {
            return Err(integrity(
                "Interrupted durable capacity write; occupancy remains sealed",
            ));
        }
        let mut last = None;
        for line in bytes[..bytes.len() - 1].split(|byte| *byte == b'\n') {
            last = Some(serde_json::from_slice(line).map_err(|_| {
                integrity("Malformed or foreign durable capacity journal; occupancy remains sealed")
            })?);
        }
        Ok(last)
    }
    pub(crate) fn store<T: Serialize>(&self, value: &T) -> ProofResult<()> {
        let mut bytes = serde_json::to_vec(value)
            .map_err(|_| integrity("Cannot encode durable guest occupancy"))?;
        bytes.push(b'\n');
        let mut file = &self.file;
        let previous = file
            .seek(SeekFrom::End(0))
            .map_err(|_| unavailable("Cannot append durable guest occupancy"))?;
        if previous + bytes.len() as u64 > 16384 {
            return Err(integrity(
                "Durable occupancy update exceeds its fixed bound",
            ));
        }
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| unavailable("Cannot durably seal guest occupancy"))?;
        Ok(())
    }
    pub(crate) fn replace<T: Serialize + serde::de::DeserializeOwned + PartialEq>(
        &self,
        expected: &T,
        value: &T,
    ) -> ProofResult<()> {
        if self.record::<T>()?.as_ref() != Some(expected) {
            return Err(integrity(
                "Durable occupancy changed; never replace a foreign owner",
            ));
        }
        self.store(value)
    }
    pub(crate) fn clear<T: serde::de::DeserializeOwned + PartialEq>(
        &self,
        expected: &T,
    ) -> ProofResult<()> {
        if self.record::<T>()?.as_ref() != Some(expected) {
            return Err(integrity(
                "Durable occupancy changed; never clear a foreign owner",
            ));
        }
        self.file
            .set_len(0)
            .and_then(|()| self.file.sync_all())
            .map_err(|_| unavailable("Cannot durably release verified guest occupancy"))
    }
}
pub(crate) fn process_identity(pid: u32) -> ProofResult<Option<Digest>> {
    if pid == 0 {
        return Err(integrity("Owned transport PID is invalid"));
    }
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
            "Cannot independently observe owned transport birth identity",
        ));
    }
    Ok(Some(Digest::of(&observed.stdout)))
}

#[cfg(test)]
mod capacity_tests {
    use super::*;
    use std::os::unix::fs::DirBuilderExt;
    struct PrivateCapacity {
        root: PathBuf,
    }
    impl PrivateCapacity {
        fn new() -> Self {
            let root =
                std::env::temp_dir().join(format!("razen-durable-capacity-{}", EntityId::new()));
            fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(root.join("invocation.lock"))
                .unwrap()
                .sync_all()
                .unwrap();
            Self { root }
        }
        fn path(&self) -> PathBuf {
            self.root.join("invocation.lock")
        }
    }
    impl Drop for PrivateCapacity {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.root)
                .expect("remove only this test's private capacity directory");
        }
    }
    #[test]
    fn already_stopped_retirement_never_adopts_live_or_replacement_pid_state() {
        let private = PrivateCapacity::new();
        let instance = private.root.join(INSTANCE);
        fs::DirBuilder::new().mode(0o700).create(&instance).unwrap();
        assert_eq!(
            ensure_original_manager_absent(&private.root, std::process::id())
                .unwrap_err()
                .code,
            crate::protocol::error::ErrorCode::IntegrityError
        );
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let original_pid = child.id();
        assert!(child.wait().unwrap().success());
        ensure_original_manager_absent(&private.root, original_pid).unwrap();
        let replacement = instance.join("ha.pid");
        let replacement_pid = std::process::id().to_string();
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&replacement)
            .unwrap();
        file.write_all(replacement_pid.as_bytes()).unwrap();
        file.sync_all().unwrap();
        assert!(ensure_original_manager_absent(&private.root, original_pid).is_err());
        assert_eq!(fs::read_to_string(&replacement).unwrap(), replacement_pid);
        fs::remove_file(&replacement).unwrap();
        let symbolic = instance.join("vz.pid");
        std::os::unix::fs::symlink(private.path(), &symbolic).unwrap();
        assert!(ensure_original_manager_absent(&private.root, original_pid).is_err());
        assert!(
            fs::symlink_metadata(&symbolic)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&symbolic).unwrap();
        ensure_original_manager_absent(&private.root, original_pid).unwrap();
    }
    #[test]
    fn generated_network_catalog_is_inert_but_overrides_drift_and_symlinks_fail_closed() {
        let private = PrivateCapacity::new();
        let config = private.root.join("_config");
        fs::DirBuilder::new().mode(0o700).create(&config).unwrap();
        let catalog = config.join("networks.yaml");
        let original = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/lima-2.3.0-networks.yaml"
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&catalog)
            .unwrap();
        file.write_all(original).unwrap();
        file.sync_all().unwrap();
        validate_private_configuration(&private.root).unwrap();
        file.write_all(b"\nunknown: true\n").unwrap();
        file.sync_all().unwrap();
        assert!(validate_private_configuration(&private.root).is_err());
        assert!(fs::read(&catalog).unwrap().starts_with(original));
        fs::remove_file(&catalog).unwrap();
        std::os::unix::fs::symlink(private.path(), &catalog).unwrap();
        assert!(validate_private_configuration(&private.root).is_err());
        assert!(
            fs::symlink_metadata(&catalog)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&catalog).unwrap();
        let override_path = config.join("override.yaml");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&override_path)
            .unwrap();
        assert!(validate_private_configuration(&private.root).is_err());
        assert!(override_path.exists());
    }

    #[test]
    fn typed_image_cache_pin_matches_real_bytes_and_rejects_same_length_drift() {
        let private = PrivateCapacity::new();
        let image = private.root.join("debian.raw");
        let original = b"actual-private-cache-checksum-test\n";
        let expected = ImageDigest::from_sha512(Sha512::digest(original).into());
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&image)
            .unwrap();
        file.write_all(original).unwrap();
        file.sync_all().unwrap();
        verify_image_cache(&image, expected.as_str()).unwrap();
        let mut changed = *original;
        changed[0] ^= 1;
        fs::write(&image, changed).unwrap();
        let error = verify_image_cache(&image, expected.as_str()).unwrap_err();
        assert_eq!(
            error.code,
            crate::protocol::error::ErrorCode::IntegrityError
        );
        assert_eq!(fs::read(&image).unwrap(), changed);
    }

    #[test]
    fn cleanup_configuration_capture_precedes_build_outputs_and_preserves_bound_facts() {
        let private = PrivateCapacity::new();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = LoadedProfile::load(
            &repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let observed = serde_json::json!({
            "vmType":"vz", "arch":"aarch64", "plain":true,
            "cpus":profile.config().external_runner.guest_cpus.get(), "memory":"2GiB",
            "propagateProxyEnv":false,
            "ssh":{"forwardAgent":false,"forwardX11":false,"forwardX11Trusted":false,
                "loadDotSSHPubKeys":false,"overVsock":false},
            "containerd":{"system":false,"user":false},
            "vmOpts":{"vz":{"rosetta":{"enabled":false}}},
            "hostResolver":{"enabled":false}, "user":{"name":"razen-manager"}
        });
        let expected = configuration_digest(&observed).unwrap();
        let capture = private.root.join("cleanup-effective.json");
        assert!(!private.root.join("effective.json").exists());
        capture_cleanup_configuration(&capture, &observed, expected, &profile).unwrap();
        let bytes = fs::read(&capture).unwrap();
        let inode = fs::metadata(&capture).unwrap().ino();
        capture_cleanup_configuration(&capture, &observed, expected, &profile).unwrap();
        assert_eq!(fs::metadata(&capture).unwrap().ino(), inode);
        assert_eq!(fs::read(&capture).unwrap(), bytes);
        let mut drift = observed.clone();
        drift["networks"] = serde_json::json!([{"lima":"shared"}]);
        assert!(capture_cleanup_configuration(&capture, &drift, expected, &profile).is_err());
        assert_eq!(fs::read(&capture).unwrap(), bytes);
        let unrelated = private.root.join("wrong-binding.json");
        assert!(
            capture_cleanup_configuration(
                &unrelated,
                &observed,
                Digest::of(b"foreign configuration"),
                &profile
            )
            .is_err()
        );
        assert!(!unrelated.exists());
        fs::write(&capture, serde_json::to_vec(&drift).unwrap()).unwrap();
        let drift_bytes = fs::read(&capture).unwrap();
        assert!(capture_cleanup_configuration(&capture, &observed, expected, &profile).is_err());
        assert_eq!(fs::read(&capture).unwrap(), drift_bytes);
        fs::remove_file(&capture).unwrap();
        std::os::unix::fs::symlink(private.path(), &capture).unwrap();
        assert!(capture_cleanup_configuration(&capture, &observed, expected, &profile).is_err());
        assert!(
            fs::symlink_metadata(&capture)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        fs::remove_file(&capture).unwrap();
        capture_cleanup_configuration(&capture, &observed, expected, &profile).unwrap();
        let plan = PreparationRetirement {
            owner_id: EntityId::new(),
            run_id: EntityId::new(),
            entries: std::collections::BTreeMap::from([(
                "cleanup-effective.json".to_owned(),
                hash_file(&capture).unwrap(),
            )]),
        };
        fs::DirBuilder::new()
            .mode(0o700)
            .create(private.root.join("retired"))
            .unwrap();
        let archive = retired_directory(&private.root, &plan);
        fs::DirBuilder::new().mode(0o700).create(&archive).unwrap();
        write_private_record(&private.root.join("preparation-retirement.json"), &plan).unwrap();
        archive_preparation(&private.root, &plan).unwrap();
        assert_eq!(
            fs::read(archive.join("cleanup-effective.json")).unwrap(),
            bytes
        );
        assert!(!private.root.join("effective.json").exists());
        assert!(!archive.join("effective.json").exists());
    }

    #[test]
    fn short_native_nonzero_exit_drains_without_waiting_for_the_management_deadline() {
        let mut command = Command::new("/usr/bin/printf");
        command.args(["%d", "public-invalid-integer"]);
        let start = Instant::now();
        let error = bounded_command(command, None, Duration::from_secs(3), 4096).unwrap_err();
        assert_eq!(
            error.code,
            crate::protocol::error::ErrorCode::IsolationUnavailable
        );
        assert!(error.message.contains("operation failed"));
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn native_management_kills_descendants_before_reaping_exited_or_overflowing_leaders() {
        const CHILD: &str = "RAZEN_MANAGEMENT_PROCESS_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let mode = std::env::var("RAZEN_MANAGEMENT_PROCESS_MODE").unwrap();
            let descendant = Command::new("/bin/sleep")
                .arg("30")
                .stdin(Stdio::null())
                .spawn()
                .unwrap();
            let identities = [
                OwnedTransport {
                    pid: std::process::id(),
                    birth_sha256: process_identity(std::process::id()).unwrap().unwrap(),
                },
                OwnedTransport {
                    pid: descendant.id(),
                    birth_sha256: process_identity(descendant.id()).unwrap().unwrap(),
                },
            ];
            fs::write(path, serde_json::to_vec(&identities).unwrap()).unwrap();
            if mode == "overflow" {
                std::io::stdout().write_all(&[b'x'; 8192]).unwrap();
                std::io::stdout().flush().unwrap();
                std::thread::sleep(Duration::from_secs(30));
            }
            std::process::exit(37);
        }
        let private = PrivateCapacity::new();
        let mut unrelated = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        struct Survivor<'a>(&'a mut std::process::Child);
        impl Drop for Survivor<'_> {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let unrelated = Survivor(&mut unrelated);
        for mode in ["inherited", "overflow"] {
            let ready = private.root.join(mode);
            let module = module_path!().split_once("::").unwrap().1;
            let name = format!(
                "{module}::native_management_kills_descendants_before_reaping_exited_or_overflowing_leaders"
            );
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, &ready)
                .env("RAZEN_MANAGEMENT_PROCESS_MODE", mode);
            let start = Instant::now();
            let error = bounded_command(
                command,
                None,
                Duration::from_secs(2),
                if mode == "overflow" { 4096 } else { 16384 },
            )
            .unwrap_err();
            assert!(start.elapsed() < Duration::from_secs(4));
            assert_eq!(
                error.code,
                if mode == "overflow" {
                    crate::protocol::error::ErrorCode::IntegrityError
                } else {
                    crate::protocol::error::ErrorCode::IsolationUnavailable
                }
            );
            assert!(error.message.contains(if mode == "overflow" {
                "output exceeded"
            } else {
                "independent deadline"
            }));
            let identities: [OwnedTransport; 2] =
                serde_json::from_slice(&fs::read(&ready).unwrap()).unwrap();
            let leader = rustix::process::Pid::from_raw(identities[0].pid as i32).unwrap();
            assert!(
                matches!(
                    rustix::process::waitpid(Some(leader), rustix::process::WaitOptions::NOHANG),
                    Err(rustix::io::Errno::CHILD)
                ),
                "the exact leader must already be reaped"
            );
            let observed_until = Instant::now() + Duration::from_secs(1);
            loop {
                let observed = crate::adapters::command::capture_status(
                    Path::new("/bin/ps"),
                    &[
                        OsStr::new("-p"),
                        OsStr::new(&identities[1].pid.to_string()),
                        OsStr::new("-o"),
                        OsStr::new("state="),
                    ],
                    None,
                    crate::adapters::command::CommandLimits {
                        stdin_bytes: 0,
                        stdout_bytes: 4096,
                        stderr_bytes: 4096,
                        timeout: Duration::from_secs(1),
                    },
                )
                .unwrap();
                if observed.exit_code == 1 && observed.stdout.iter().all(u8::is_ascii_whitespace)
                    || observed.exit_code == 0
                        && observed
                            .stdout
                            .iter()
                            .find(|byte| !byte.is_ascii_whitespace())
                            == Some(&b'Z')
                {
                    break;
                }
                assert!(
                    Instant::now() < observed_until,
                    "the actual descendant must be gone or a non-running zombie, never left executing"
                );
                std::thread::sleep(Duration::from_millis(2));
            }
            assert!(
                unrelated.0.try_wait().unwrap().is_none(),
                "an unrelated native process must survive"
            );
        }
    }

    #[test]
    fn native_management_delivers_all_input_and_checks_both_output_bounds() {
        const CHILD: &str = "RAZEN_MANAGEMENT_INPUT_CHILD";
        if let Ok(mode) = std::env::var(CHILD) {
            let mut input = Vec::new();
            std::io::stdin().read_to_end(&mut input).unwrap();
            if mode == "input" {
                std::io::stdout()
                    .write_all(Digest::of(&input).to_string().as_bytes())
                    .unwrap();
            } else {
                std::io::stderr().write_all(&[b'x'; 8192]).unwrap();
            }
            std::process::exit(0);
        }
        let module = module_path!().split_once("::").unwrap().1;
        let name =
            format!("{module}::native_management_delivers_all_input_and_checks_both_output_bounds");
        let bytes = vec![0xa5; 1024 * 1024];
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &name, "--nocapture"])
            .env(CHILD, "input");
        let output = bounded_command(command, Some(&bytes), Duration::from_secs(5), 4096).unwrap();
        assert!(output.ends_with(Digest::of(&bytes).to_string().as_bytes()));
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", &name, "--nocapture"])
            .env(CHILD, "diagnostics");
        let error = bounded_command(command, None, Duration::from_secs(5), 4096).unwrap_err();
        assert_eq!(
            error.code,
            crate::protocol::error::ErrorCode::IntegrityError
        );
        assert!(error.message.contains("output exceeded"));
    }

    #[test]
    fn retirement_moves_exact_evidence_resumes_interruption_and_preserves_capacity_cache_and_unknowns()
     {
        let private = PrivateCapacity::new();
        let state = &private.root;
        let owner = EntityId::new();
        let run = EntityId::new();
        let mut entries = std::collections::BTreeMap::new();
        for (name, bytes) in [
            ("owner.json", b"original-owner".as_slice()),
            ("provision.log", b"actual compiler failure".as_slice()),
        ] {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(state.join(name))
                .unwrap();
            file.write_all(bytes).unwrap();
            file.sync_all().unwrap();
            entries.insert(name.to_owned(), Digest::of(bytes));
        }
        let captures = state.join("guest-dependency-captures");
        fs::DirBuilder::new().mode(0o700).create(&captures).unwrap();
        let packages = captures.join("guest-packages");
        fs::DirBuilder::new().mode(0o700).create(&packages).unwrap();
        let uri = packages.join("adduser.all.uri");
        let original_uri = b"https://snapshot.debian.org/archive/debian/20261112T000000Z/pool/main/a/adduser/adduser_3.152_all.deb\n";
        let mut uri_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&uri)
            .unwrap();
        uri_file.write_all(original_uri).unwrap();
        uri_file.sync_all().unwrap();
        entries.insert(
            "guest-dependency-captures".into(),
            registry_entry_digest(&captures).unwrap(),
        );
        let canaries = state.join("canaries");
        fs::DirBuilder::new().mode(0o700).create(&canaries).unwrap();
        entries.insert("canaries".into(), registry_entry_digest(&canaries).unwrap());
        let image = state.join("debian.raw");
        let mut image_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&image)
            .unwrap();
        image_file
            .write_all(b"private cache bytes: this unit test does not attest an image")
            .unwrap();
        let lock = fs::metadata(private.path()).unwrap();
        let image_inode = fs::metadata(&image).unwrap().ino();
        let plan = PreparationRetirement {
            owner_id: owner,
            run_id: run,
            entries,
        };
        fs::DirBuilder::new()
            .mode(0o700)
            .create(state.join("retired"))
            .unwrap();
        let archive = retired_directory(state, &plan);
        fs::DirBuilder::new().mode(0o700).create(&archive).unwrap();
        write_private_record(&state.join("preparation-retirement.json"), &plan).unwrap();
        let unknown = state.join("unrelated-not-owned");
        fs::write(&unknown, b"preserve me").unwrap();
        assert!(archive_preparation(state, &plan).is_err());
        assert_eq!(fs::read(&unknown).unwrap(), b"preserve me");
        assert_eq!(
            fs::read(state.join("owner.json")).unwrap(),
            b"original-owner"
        );
        fs::remove_file(&unknown).unwrap();
        let foreign_canary = canaries.join("foreign-canary");
        fs::write(&foreign_canary, b"preserve unrelated canary bytes").unwrap();
        assert!(archive_preparation(state, &plan).is_err());
        assert_eq!(
            fs::read(&foreign_canary).unwrap(),
            b"preserve unrelated canary bytes"
        );
        fs::remove_file(&foreign_canary).unwrap();
        fs::write(&uri, b"changed original repository URI").unwrap();
        assert!(archive_preparation(state, &plan).is_err());
        assert_eq!(fs::read(&uri).unwrap(), b"changed original repository URI");
        fs::write(&uri, original_uri).unwrap();
        let unknown_capture = packages.join("adduser.all.executable");
        fs::write(&unknown_capture, b"must be preserved").unwrap();
        assert!(archive_preparation(state, &plan).is_err());
        assert_eq!(fs::read(&unknown_capture).unwrap(), b"must be preserved");
        fs::remove_file(&unknown_capture).unwrap();
        let log = state.join("provision.log");
        fs::write(&log, b"changed evidence").unwrap();
        assert!(archive_preparation(state, &plan).is_err());
        assert_eq!(fs::read(&log).unwrap(), b"changed evidence");
        fs::remove_file(&log).unwrap();
        std::os::unix::fs::symlink(private.path(), &log).unwrap();
        assert!(archive_preparation(state, &plan).is_err());
        assert!(fs::symlink_metadata(&log).unwrap().file_type().is_symlink());
        assert_eq!(fs::metadata(private.path()).unwrap().ino(), lock.ino());
        fs::remove_file(&log).unwrap();
        let mut restored = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&log)
            .unwrap();
        restored.write_all(b"actual compiler failure").unwrap();
        restored.sync_all().unwrap();
        fs::rename(state.join("provision.log"), archive.join("provision.log")).unwrap();
        let capacity = DurableCapacity::acquire(&private.path()).unwrap();
        capacity.ensure_empty().unwrap();
        archive_preparation(state, &plan).unwrap();
        assert_eq!(fs::metadata(private.path()).unwrap().ino(), lock.ino());
        assert_eq!(fs::metadata(&image).unwrap().ino(), image_inode);
        assert_eq!(
            fs::read(&image).unwrap(),
            b"private cache bytes: this unit test does not attest an image"
        );
        assert_eq!(
            fs::read(archive.join("owner.json")).unwrap(),
            b"original-owner"
        );
        assert_eq!(
            fs::read(archive.join("provision.log")).unwrap(),
            b"actual compiler failure"
        );
        assert_eq!(
            fs::read(archive.join("guest-dependency-captures/guest-packages/adduser.all.uri"))
                .unwrap(),
            original_uri
        );
        assert!(archive.join("canaries").is_dir());
        assert!(
            fs::read_dir(archive.join("canaries"))
                .unwrap()
                .next()
                .is_none()
        );
        assert!(!state.join("owner.json").exists());
        assert!(!state.join("preparation-retirement.json").exists());
        assert!(archive.join("preparation-retirement.json").exists());
        assert!(
            DurableCapacity::acquire(&private.path()).is_err(),
            "retirement must not replace the locked inode"
        );
    }
    #[test]
    fn durable_occupancy_survives_a_real_holder_sigkill() {
        const CHILD: &str = "RAZEN_DURABLE_CAPACITY_CHILD";
        if let Some(path) = std::env::var_os(CHILD) {
            let path = PathBuf::from(path);
            let capacity = DurableCapacity::acquire(&path).unwrap();
            capacity.ensure_empty().unwrap();
            capacity
                .store(&serde_json::json!({"holder_pid":std::process::id()}))
                .unwrap();
            File::create(path.with_extension("ready"))
                .unwrap()
                .sync_all()
                .unwrap();
            loop {
                std::thread::park();
            }
        }
        let private = PrivateCapacity::new();
        let path = private.path();
        let module = module_path!()
            .split_once("::")
            .expect("nested capacity test module")
            .1;
        let name = format!("{module}::durable_occupancy_survives_a_real_holder_sigkill");
        struct Holder(std::process::Child);
        impl std::ops::Deref for Holder {
            type Target = std::process::Child;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
        impl std::ops::DerefMut for Holder {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }
        impl Drop for Holder {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let mut child = Holder(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env(CHILD, &path)
                .spawn()
                .unwrap(),
        );
        let start = Instant::now();
        while !path.with_extension("ready").exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "actual lock holder exited before durable write"
            );
            if start.elapsed() > Duration::from_secs(5) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("actual lock holder never established durable occupancy");
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            DurableCapacity::acquire(&path).is_err(),
            "live child must actually hold flock"
        );
        let killed = child.id();
        child.kill().unwrap();
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(child.wait().unwrap().signal(), Some(9));
        let successor = DurableCapacity::acquire(&path).expect("SIGKILL releases the OS lock");
        assert_eq!(
            successor.record::<serde_json::Value>().unwrap().unwrap()["holder_pid"],
            killed
        );
        assert!(
            successor.ensure_empty().is_err(),
            "OS lock release cannot erase unresolved occupancy"
        );
    }
    #[test]
    fn incomplete_or_foreign_records_are_preserved_and_cannot_be_cleared_by_another_owner() {
        let private = PrivateCapacity::new();
        let capacity = DurableCapacity::acquire(&private.path()).unwrap();
        let owner = serde_json::json!({"owner":EntityId::new()});
        capacity.store(&owner).unwrap();
        let foreign = serde_json::json!({"owner":EntityId::new()});
        assert!(capacity.clear(&foreign).is_err());
        assert_eq!(
            capacity.record::<serde_json::Value>().unwrap(),
            Some(owner.clone())
        );
        let mut file = &capacity.file;
        file.seek(SeekFrom::End(0)).unwrap();
        file.write_all(b"{interrupted").unwrap();
        file.sync_all().unwrap();
        assert!(capacity.record::<serde_json::Value>().is_err());
        assert!(capacity.ensure_empty().is_err());
        assert!(capacity.clear(&owner).is_err());
        assert!(capacity.bytes().unwrap().ends_with(b"{interrupted"));
    }
    #[test]
    fn a_released_object_cannot_clear_a_sequential_successors_durable_record() {
        let private = PrivateCapacity::new();
        let first = DurableCapacity::acquire(&private.path()).unwrap();
        let old = serde_json::json!({"owner":EntityId::new()});
        first.store(&old).unwrap();
        first.clear(&old).unwrap();
        drop(first);
        let successor = DurableCapacity::acquire(&private.path()).unwrap();
        let current = serde_json::json!({"owner":EntityId::new()});
        successor.store(&current).unwrap();
        assert!(successor.clear(&old).is_err());
        assert_eq!(
            successor.record::<serde_json::Value>().unwrap(),
            Some(current)
        );
    }
    #[test]
    fn a_free_flock_never_grants_stop_authority_over_a_sequential_real_child_owner() {
        struct Child(std::process::Child);
        impl Drop for Child {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let private = PrivateCapacity::new();
        let first = DurableCapacity::acquire(&private.path()).unwrap();
        let mut child = Child(Command::new("/bin/sleep").arg("30").spawn().unwrap());
        let mut old = HostOccupancy {
            occupancy_id: EntityId::new(),
            prepared_sha256: Digest::of(private.root.as_os_str().as_encoded_bytes()),
            binding_id: EntityId::new(),
            invocation_id: EntityId::new(),
            run_id: EntityId::new(),
            attestation_id: EntityId::new(),
            lease_id: EntityId::new(),
            profile_sha256: Digest::of(b"capacity-test-profile"),
            initial_revision: WireInt::ZERO,
            transport: None,
            transport_terminated: false,
        };
        first.store(&old).unwrap();
        let reservation = old.clone();
        old.transport = Some(OwnedTransport {
            pid: child.0.id(),
            birth_sha256: process_identity(child.0.id()).unwrap().unwrap(),
        });
        first.replace(&reservation, &old).unwrap();
        assert_eq!(first.require_occupancy(&reservation).unwrap(), old);
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        assert_ne!(
            process_identity(child.0.id()).unwrap(),
            old.transport
                .as_ref()
                .map(|transport| transport.birth_sha256)
        );
        let previous = old.clone();
        old.transport_terminated = true;
        first.replace(&previous, &old).unwrap();
        first.clear(&old).unwrap();
        assert!(
            first.require_occupancy(&old).is_err(),
            "a released invocation cannot authorize stopping an idle VM"
        );
        drop(first);
        let successor = DurableCapacity::acquire(&private.path()).unwrap();
        let next_child = Child(Command::new("/bin/sleep").arg("30").spawn().unwrap());
        // Even an exact replay of launch IDs has a different durable occupancy authority.
        let mut next = old.clone();
        next.occupancy_id = EntityId::new();
        next.transport = None;
        next.transport_terminated = false;
        successor.store(&next).unwrap();
        let reserved = next.clone();
        next.transport = Some(OwnedTransport {
            pid: next_child.0.id(),
            birth_sha256: process_identity(next_child.0.id()).unwrap().unwrap(),
        });
        successor.replace(&reserved, &next).unwrap();
        assert!(successor.require_occupancy(&old).is_err());
        assert!(successor.require_occupancy(&reservation).is_err());
        assert_eq!(successor.host_record().unwrap(), Some(next.clone()));
        assert_eq!(
            process_identity(next_child.0.id()).unwrap(),
            next.transport
                .as_ref()
                .map(|transport| transport.birth_sha256)
        );
    }
    #[test]
    fn a_real_child_exiting_before_birth_binding_cannot_authorize_a_vm_stop() {
        let private = PrivateCapacity::new();
        let capacity = DurableCapacity::acquire(&private.path()).unwrap();
        let reservation = HostOccupancy {
            occupancy_id: EntityId::new(),
            prepared_sha256: Digest::of(private.root.as_os_str().as_encoded_bytes()),
            binding_id: EntityId::new(),
            invocation_id: EntityId::new(),
            run_id: EntityId::new(),
            attestation_id: EntityId::new(),
            lease_id: EntityId::new(),
            profile_sha256: Digest::of(b"capacity-test-profile"),
            initial_revision: WireInt::ZERO,
            transport: None,
            transport_terminated: false,
        };
        capacity.store(&reservation).unwrap();
        let before = capacity.bytes().unwrap();
        let mut child = Command::new("/bin/sleep").arg("0").spawn().unwrap();
        assert!(
            child.wait().unwrap().success(),
            "reap the actual prebinding child, not an invented exit"
        );
        assert_eq!(process_identity(child.id()).unwrap(), None);
        assert!(
            capacity.require_stop_occupancy(&reservation).is_err(),
            "a free slot and matching reservation do not bind the exited transport"
        );
        assert_eq!(
            capacity.host_record().unwrap(),
            Some(reservation.clone()),
            "prebinding reservations remain valid durable records, not invalid terminated placeholders"
        );
        assert_eq!(
            capacity.bytes().unwrap(),
            before,
            "unknown birth must not fabricate termination or clear occupancy"
        );
        drop(capacity);
        let reacquired = DurableCapacity::acquire(&private.path()).unwrap();
        assert!(reacquired.require_stop_occupancy(&reservation).is_err());
        assert!(reacquired.ensure_empty().is_err());
        assert_eq!(reacquired.bytes().unwrap(), before);
    }
    #[test]
    fn failed_preparation_cleanup_preserves_unmarked_unknown_and_locked_resources() {
        let private = PrivateCapacity::new();
        let state = private.root.join("target/r0-guest");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&state)
            .unwrap();
        let lock = state.join("invocation.lock");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock)
            .unwrap()
            .sync_all()
            .unwrap();
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let profile = LoadedProfile::load(
            &repository.join("specs/001-r0-feasibility/contracts/pilot-profile.json"),
        )
        .unwrap();
        let run_id = EntityId::new();
        assert!(
            cleanup_failed_preparation(&private.root, &profile, run_id).is_err(),
            "a selected run cannot adopt an unmarked VM"
        );
        let partial = state.join("preparation-stop.json");
        let mut record = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&partial)
            .unwrap();
        record.write_all(b"{interrupted-real-record-write").unwrap();
        record.sync_all().unwrap();
        assert!(cleanup_failed_preparation(&private.root, &profile, run_id).is_err());
        assert_eq!(
            fs::read(&partial).unwrap(),
            b"{interrupted-real-record-write"
        );
        let held = preparation_capacity(&private.root).unwrap();
        assert!(
            cleanup_failed_preparation(&private.root, &profile, run_id).is_err(),
            "actual exclusive capacity must be acquired before any stop"
        );
        assert!(preparation_capacity(&private.root).is_err());
        drop(held);
        let capacity = DurableCapacity::acquire(&lock).unwrap();
        capacity
            .store(&serde_json::json!({"unknown_run":EntityId::new()}))
            .unwrap();
        let before = fs::read(&lock).unwrap();
        drop(capacity);
        assert!(cleanup_failed_preparation(&private.root, &profile, run_id).is_err());
        assert_eq!(
            fs::read(&lock).unwrap(),
            before,
            "unknown occupancy cannot be repaired into partial-stop authority"
        );
    }
}
