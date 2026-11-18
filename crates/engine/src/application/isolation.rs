//! Read-only discovery and the single explicit, caller-confirmed provisioning entry point.
use crate::{
    adapters::{
        guest::{
            integrity,
            preflight::{self, DoctorReport, PreparedGuest, PreparedRecord},
            unavailable,
        },
        workspace::OwnedDirectory,
    },
    application::profile::LoadedProfile,
    domain::values::{Digest, EntityId},
    protocol::error::ProofResult,
};
use serde_json::json;
use std::{
    fs::{self, OpenOptions},
    io::Write,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::Path,
    process::Command,
    time::Duration,
};

pub fn doctor(repository: &Path, profile: &LoadedProfile) -> ProofResult<DoctorReport> {
    let mut report = preflight::doctor(repository, profile)?;
    match super::environment::preflight(repository, profile) {
        Ok(environment) => {
            report.observations["environment"] = serde_json::to_value(&environment)
                .map_err(|_| integrity("Cannot encode observed prerequisites"))?;
            match super::provenance::preflight(repository, &environment, profile) {
                Ok(()) => {
                    report.observations["provenance_ready"] = json!(true);
                }
                Err(error) => {
                    report.available = false;
                    report.blockers.push(format!(
                        "Offline provenance prerequisite failed: {:?}",
                        error.code
                    ));
                    report.observations["provenance_ready"] = json!(false);
                }
            }
        }
        Err(error) => {
            report.available = false;
            report.blockers.push(format!(
                "Host, toolchain or reviewed backend prerequisite failed: {:?}",
                error.code
            ));
        }
    }
    Ok(report)
}
/// Only the CLI's explicit --confirm-provision branch may call this function.
/// Normal proof execution/discovery never invokes it.
pub fn prepare(
    repository: &Path,
    profile: &LoadedProfile,
    owned_output: &OwnedDirectory,
) -> ProofResult<PreparedGuest> {
    match prepare_inner(repository, profile, owned_output) {
        Ok(guest) => Ok(guest),
        Err(error) => {
            let cleanup = if repository
                .join("target/r0-guest/prepared.json")
                .symlink_metadata()
                .is_ok()
            {
                preflight::PreparedGuestStop::discover(repository, profile)
                    .and_then(|guest| guest.stop_for_run(owned_output.run_id()))
            } else {
                preflight::cleanup_failed_preparation(repository, profile, owned_output.run_id())
            };
            owned_output.write_new(
                Path::new("preparation-error.json"),
                &serde_json::to_vec(&json!({"preparation":error,"cleanup":cleanup.as_ref().err()}))
                    .map_err(|_| integrity("Cannot encode preparation failure"))?,
            )?;
            Err(error)
        }
    }
}
fn prepare_inner(
    repository: &Path,
    profile: &LoadedProfile,
    owned_output: &OwnedDirectory,
) -> ProofResult<PreparedGuest> {
    let repository = repository
        .canonicalize()
        .map_err(|_| unavailable("Cannot resolve approved repository"))?;
    let target = repository.join("target");
    let metadata = fs::symlink_metadata(&target).map_err(|_| {
        unavailable("Explicit preparation requires the existing private tool/build target")
    })?;
    use std::os::unix::fs::MetadataExt;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
    {
        return Err(integrity(
            "Preparation target is not an owned real repository directory",
        ));
    }
    let state = repository.join("target/r0-guest");
    if state.join("prepared.json").exists() {
        return PreparedGuest::discover(&repository, profile);
    }
    if !state.exists() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&state)
            .map_err(|_| unavailable("Cannot create private prepared guest registry"))?;
    }
    preflight::check_private(&state, true)?;
    let lock = state.join("invocation.lock");
    if lock.symlink_metadata().is_err() {
        write_private(&lock, b"")?;
    }
    let capacity = preflight::preparation_capacity(&repository)?;
    for name in [
        "preparation-stopped.json",
        "preparation-retirement.json",
        "preparation-stop.json",
    ] {
        if state.join(name).symlink_metadata().is_ok() {
            return Err(integrity(
                "Previous preparation remains sealed; explicit selected-run cleanup must retire it before a fresh preparation",
            ));
        }
    }
    let marker = state.join("owner.json");
    let owner_id = if marker.exists() {
        let v: serde_json::Value = serde_json::from_slice(&preflight::private_read(&marker, 4096)?)
            .map_err(|_| integrity("Invalid preparation owner marker"))?;
        if v["run_id"] != owned_output.run_id().to_string()
            || v["profile_sha256"] != profile.sha256().to_string()
        {
            return Err(integrity(
                "Existing preparation state belongs to another owner/profile",
            ));
        }
        EntityId::parse(
            v["owner_id"]
                .as_str()
                .ok_or_else(|| integrity("Missing preparation owner"))?,
        )?
    } else {
        let owner = EntityId::new();
        write_private(&marker,&serde_json::to_vec(&json!({"owner_id":owner,"run_id":owned_output.run_id(),"uid":rustix::process::geteuid().as_raw(),"profile_sha256":profile.sha256()})).map_err(|_|integrity("Cannot encode preparation ownership"))?)?;
        owner
    };
    let short = owner_id.to_string().replace('-', "");
    let home = Path::new("/private/tmp").join(format!("rzg-{}", &short[..12]));
    if !home.exists() {
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&home)
            .map_err(|_| unavailable("Cannot create private short Lima home"))?;
        write_private(
            &home.join(".razen-owner.json"),
            &serde_json::to_vec(
                &json!({"owner_id":owner_id,"uid":rustix::process::geteuid().as_raw()}),
            )
            .map_err(|_| integrity("Cannot encode guest ownership"))?,
        )?;
    }
    preflight::check_private(&home, true)?;
    let marker: serde_json::Value = serde_json::from_slice(&preflight::private_read(
        &home.join(".razen-owner.json"),
        1024,
    )?)
    .map_err(|_| integrity("Invalid owned Lima home marker"))?;
    if marker["owner_id"] != owner_id.to_string() {
        return Err(integrity("Short Lima resource belongs to another owner"));
    }
    let source = preflight::source_digest(&repository)?;
    let provision = preflight::hash_file(&repository.join("scripts/proofs/provision-guest.sh"))?;
    let provenance = json!({"owner_id":owner_id,"source_sha256":source,"provisioning_sha256":provision,"profile_sha256":profile.sha256()});
    let provenance_path = state.join("provenance.json");
    if !provenance_path.exists() {
        write_private(
            &provenance_path,
            &serde_json::to_vec(&provenance)
                .map_err(|_| integrity("Cannot encode preparation provenance"))?,
        )?;
    } else {
        preflight::check_private(&provenance_path, false)?;
        let old: serde_json::Value =
            serde_json::from_slice(&preflight::private_read(&provenance_path, 4096)?)
                .map_err(|_| integrity("Invalid partial preparation provenance"))?;
        for key in ["source_sha256", "provisioning_sha256", "profile_sha256"] {
            if old[key] != provenance[key] {
                return Err(integrity(
                    "Partial preparation source/profile changed; explicit new owner required",
                ));
            }
        }
    }
    let mut command = Command::new("/bin/bash");
    command
        .arg(repository.join("scripts/proofs/build-guest.sh"))
        .arg("--confirm-provision")
        .arg(&repository)
        .arg(&home)
        .arg(&state)
        .env_clear()
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .env("HOME", &home)
        .current_dir(&state);
    let output =
        preflight::bounded_command(command, None, Duration::from_secs(1800), 16 * 1024 * 1024)?;
    let prefixes = [
        repository.as_os_str().as_encoded_bytes(),
        home.as_os_str().as_encoded_bytes(),
    ];
    let mut redacted = Vec::new();
    let mut offset = 0;
    let mut retained = 0;
    while offset < output.len() {
        if let Some((index, prefix)) = prefixes
            .iter()
            .enumerate()
            .find(|(_, prefix)| output[offset..].starts_with(prefix))
        {
            if redacted.is_empty() {
                redacted.reserve(output.len());
            }
            redacted.extend_from_slice(&output[retained..offset]);
            redacted.extend_from_slice(if index == 0 {
                b"<repository>"
            } else {
                b"<owned-lima-home>"
            });
            offset += prefix.len();
            retained = offset;
        } else {
            offset += 1;
        }
    }
    let reviewable = if retained == 0 {
        output.as_slice()
    } else {
        redacted.extend_from_slice(&output[retained..]);
        redacted.as_slice()
    };
    owned_output.write_new(Path::new("guest-preparation.stdout"), reviewable)?;
    let mut manifest_file = fs::read(state.join("guest-inspect.json"))
        .map_err(|_| unavailable("Explicit preparation produced no guest inspection"))?;
    if manifest_file.len() > 1_048_576 {
        return Err(integrity("Prepared guest manifest exceeds bound"));
    }
    let guest_manifest: serde_json::Value = serde_json::from_slice(&manifest_file)
        .map_err(|_| integrity("Prepared guest inspection is invalid"))?;
    manifest_file.clear();
    if guest_manifest["owner_id"] != owner_id.to_string() {
        return Err(integrity(
            "Prepared native guest belongs to a different resource owner",
        ));
    }
    let key_file = state.join("ssh-host-public-key");
    let key_bytes = preflight::private_read(&key_file, 4096)?;
    let host_key = std::str::from_utf8(&key_bytes)
        .map_err(|_| integrity("Prepared SSH host public key is not UTF-8"))?;
    if !host_key.starts_with("ssh-ed25519 ")
        || host_key.contains('\n')
        || guest_manifest["ssh_host_key_sha256"] != Digest::of(&key_bytes).to_string()
    {
        return Err(integrity(
            "Invalid or mismatched prepared SSH host public key",
        ));
    }
    let known = home.join("known_hosts");
    let known_bytes = format!("razen-r0-owned {host_key}\n");
    if !known.exists() {
        write_private(&known, known_bytes.as_bytes())?;
    } else if preflight::private_read(&known, 4096)? != known_bytes.as_bytes() {
        return Err(integrity("Prepared SSH host key changed"));
    }
    fs::remove_file(key_file)
        .map_err(|_| integrity("Cannot remove temporary private SSH host-key material"))?;
    let provenance: serde_json::Value =
        serde_json::from_slice(&preflight::private_read(&provenance_path, 4096)?)
            .map_err(|_| integrity("Prepared provenance is invalid"))?;
    let configuration = Digest::parse(
        provenance["configuration_sha256"]
            .as_str()
            .ok_or_else(|| integrity("Effective configuration digest is missing"))?,
    )?;
    let manager_identity = preflight::manager_identity(&home, rustix::process::geteuid().as_raw())?;
    let record = PreparedRecord {
        owner_id,
        uid: rustix::process::geteuid().as_raw(),
        manager_identity,
        instance_yaml_sha256: preflight::hash_file(
            &home.join(preflight::INSTANCE).join("lima.yaml"),
        )?,
        ssh_config_sha256: preflight::hash_file(
            &home.join(preflight::INSTANCE).join("ssh.config"),
        )?,
        lima_home: home,
        instance: preflight::INSTANCE.into(),
        profile_sha256: profile.sha256(),
        manager_sha256: preflight::hash_file(
            &repository.join("target/r0-tools/lima/2.3.0/bin/limactl"),
        )?,
        source_sha256: source,
        provisioning_sha256: provision,
        configuration_sha256: configuration,
        image_sha512: preflight::IMAGE_SHA512.into(),
        guest_manifest,
    };
    write_private(
        &state.join("prepared.json"),
        &serde_json::to_vec(&record)
            .map_err(|_| integrity("Cannot encode prepared guest registry"))?,
    )?;
    fs::set_permissions(
        state.join("effective.json"),
        fs::Permissions::from_mode(0o600),
    )
    .map_err(|_| integrity("Cannot protect prepared effective configuration"))?;
    drop(capacity);
    PreparedGuest::discover(&repository, profile)
}
fn write_private(path: &Path, bytes: &[u8]) -> ProofResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(|_| integrity("Cannot create owned preparation record"))?;
    file.write_all(bytes)
        .map_err(|_| integrity("Cannot write owned preparation record"))?;
    file.sync_all()
        .map_err(|_| integrity("Cannot sync preparation record"))?;
    Ok(())
}

pub const TOOL: &str = "guest.isolation.proof";
pub fn requested(profile: &LoadedProfile) -> ProofResult<crate::domain::values::Usage> {
    use crate::domain::values::{Usage, WireInt};
    Ok(Usage {
        units: WireInt::new(1)?,
        bytes: WireInt::new(8 * 1024 * 1024)?,
        cpu_us: WireInt::new(60_000_000)?,
        elapsed_us: WireInt::new(
            (profile.config().external_runner.wall_deadline_ms.get() + 30_000) * 1000,
        )?,
    })
}
pub fn registered_tool(
    provider_digest: Digest,
    profile: &LoadedProfile,
) -> ProofResult<crate::adapters::ledger::RegisteredTool> {
    use crate::domain::{
        authority::{Effect, RetryClass, ToolDescriptor},
        values::{CatalogId, ContractVersion},
    };
    Ok(crate::adapters::ledger::RegisteredTool {
        provider_digest,
        descriptor: ToolDescriptor {
            tool_id: CatalogId::parse(TOOL)?,
            version: ContractVersion::V0_1_0,
            input_contract: CatalogId::parse("guest.isolation.input")?,
            output_contract: CatalogId::parse("guest.isolation.output")?,
            effect: Effect::LocalWrite,
            permissions: vec![CatalogId::parse("guest.proof")?],
            limits: requested(profile)?,
            retry_class: RetryClass::NonRetryable,
        },
    })
}
