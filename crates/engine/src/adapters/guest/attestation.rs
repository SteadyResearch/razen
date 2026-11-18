use super::{integrity, preflight::PreparedGuest};
use crate::application::profile::LoadedProfile;
use crate::domain::values::{Digest, EntityId};
use crate::protocol::{error::ProofResult, messages::SandboxAttestation};

pub fn validate(
    attestation: &SandboxAttestation<'_>,
    run: EntityId,
    assigned: EntityId,
    profile: &LoadedProfile,
    guest: &PreparedGuest,
) -> ProofResult<()> {
    if attestation.attestation_id != assigned
        || attestation.run_id != run
        || attestation.backend.as_str() != profile.config().external_runner.backend
        || attestation.manager_version != "2.3.0"
        || attestation.image_digest != profile.config().external_runner.image_digest
        || attestation.provisioning_sha256 != guest.record.provisioning_sha256
        || attestation.effective_config_sha256 != guest.record.configuration_sha256
    {
        return Err(integrity(
            "Attestation is not bound to the current assigned launch/profile/provenance",
        ));
    }
    if attestation.kernel_version.as_ref()
        != guest.provenance()["kernel_version"].as_str().unwrap_or("")
    {
        return Err(integrity("Attested kernel differs from prepared guest"));
    }
    let expected = &guest.provenance()["binary_digests"];
    for name in ["supervisor", "adversary", "bubblewrap", "source"] {
        let observed = attestation
            .binary_digests
            .iter()
            .find(|(key, _)| key.as_str() == name)
            .map(|(_, digest)| *digest);
        let wanted = expected[name].as_str().and_then(|v| Digest::parse(v).ok());
        if observed.is_none() || observed != wanted {
            return Err(integrity(
                "Attested installed binary/source provenance differs",
            ));
        }
    }
    if guest.provenance()["seccomp_sha256"]
        .as_str()
        .and_then(|value| Digest::parse(value).ok())
        != Some(attestation.seccomp_sha256)
    {
        return Err(integrity(
            "Attested seccomp bytes differ from prepared compiled policy",
        ));
    }
    validate_policy(attestation, profile)
}

fn validate_policy(
    attestation: &SandboxAttestation<'_>,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    for (checks, names) in [
        (
            &attestation.namespace_checks,
            &["user", "mount", "pid", "ipc", "uts", "network", "cgroup"][..],
        ),
        (
            &attestation.controller_checks,
            &["memory", "cpu", "pids", "cgroup_v2"][..],
        ),
        (
            &attestation.mount_checks,
            &[
                "readonly_runtime",
                "readonly_inputs",
                "bounded_tmpfs",
                "no_host_mounts",
                "no_management",
                "private_proc",
            ][..],
        ),
        (
            &attestation.socket_checks,
            &[
                "no_inherited_sockets",
                "no_agent_forwarding",
                "seccomp_socket_denied",
            ][..],
        ),
        (
            &attestation.uid_checks,
            &[
                "dedicated_uid",
                "no_sudo",
                "caps_empty",
                "no_new_privileges",
                "manager_outside_cgroup",
                "placement_before_release",
            ][..],
        ),
    ] {
        for name in names {
            if !checks
                .iter()
                .any(|(key, value)| key.as_str() == *name && *value)
            {
                return Err(integrity(
                    "Mandatory measured sandbox check is absent or false",
                ));
            }
        }
    }
    let runner = &profile.config().external_runner;
    for (name, expected) in [
        ("memory_max_bytes", runner.memory_max_bytes.get()),
        ("memory_swap_max_bytes", runner.memory_swap_max_bytes.get()),
        ("pids_max", runner.pids_max.get()),
        ("cpu_quota_us", 100000),
        ("cpu_period_us", 100000),
        ("tmpfs_max_bytes", runner.tmpfs_max_bytes.get()),
        ("file_descriptors_max", runner.file_descriptors_max.get()),
        ("wall_deadline_ms", runner.wall_deadline_ms.get()),
        ("orphan_lease_ms", runner.orphan_lease_ms.get()),
        (
            "output_limit_bytes",
            profile
                .config()
                .protocol
                .invocation_output_limit_bytes
                .get(),
        ),
    ] {
        if !attestation
            .observed_limits
            .iter()
            .any(|(key, value)| key.as_str() == name && value.get() == expected)
        {
            return Err(integrity(
                "Effective measured sandbox resource limit differs from the profile",
            ));
        }
    }
    Ok(())
}
pub fn verify_recorded(
    value: &serde_json::Value,
    run: &crate::domain::proofs::Run,
    assigned: EntityId,
    profile: &LoadedProfile,
) -> ProofResult<()> {
    let observed: SandboxAttestation<'_> = serde::Deserialize::deserialize(value)
        .map_err(|_| integrity("Recorded sandbox attestation violates the existing wire schema"))?;
    if observed.attestation_id != assigned
        || observed.run_id != run.run_id
        || observed.backend.as_str() != profile.config().external_runner.backend
        || observed.manager_version != profile.config().external_runner.lima_version
        || observed.image_digest != profile.config().external_runner.image_digest
        || Some(observed.provisioning_sha256) != run.environment.provisioning_sha256
        || Some(observed.effective_config_sha256) != run.environment.effective_config_sha256
        || Some(observed.seccomp_sha256) != run.environment.seccomp_sha256
    {
        return Err(integrity(
            "Recorded sandbox attestation differs from current immutable run/profile pins",
        ));
    }
    for (native, global) in [
        ("supervisor", "guest-supervisor"),
        ("adversary", "guest-adversary"),
        ("bubblewrap", "bubblewrap"),
    ] {
        let digest = observed
            .binary_digests
            .iter()
            .find(|(key, _)| key.as_str() == native)
            .map(|(_, value)| value);
        if digest.is_none()
            || run
                .environment
                .binary_digests
                .iter()
                .find(|(key, _)| key.as_str() == global)
                .map(|(_, value)| value)
                != digest
        {
            return Err(integrity(
                "Recorded native sandbox executable provenance differs from the Run",
            ));
        }
    }
    let source = observed
        .binary_digests
        .iter()
        .find(|(key, _)| key.as_str() == "source")
        .map(|(_, value)| value);
    if source.is_none()
        || run
            .environment
            .fixture_digests
            .iter()
            .find(|(key, _)| key.as_str() == "guest-source")
            .map(|(_, value)| value)
            != source
    {
        return Err(integrity(
            "Recorded Linux source provenance differs from the Run",
        ));
    }
    validate_policy(&observed, profile)
}
