use std::fs::File;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::domain::values::{CatalogId, ContractVersion, Digest, WireInt};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

const MAX_PROFILE_BYTES: usize = 1024 * 1024;
const MIB: u64 = 1024 * 1024;
const IMAGE_URL: &str = "https://cloud.debian.org/images/cloud/trixie/20261111-2659/debian-13-genericcloud-arm64-20261111-2659.raw";
const IMAGE_DIGEST: &str = "sha512:255ed35957114b453d72cf021f70542d09dccbb9210640a220a4d0931fa80e1ea956785a7ca88b33d58b55dd4d00f0677b0016a14c99a168b6ed8e239ac98b09";
const REQUIRED_MODES: [&str; 4] = [
    "http1_forward",
    "https_connect_tunnel",
    "https_http1_intercept",
    "https_http2_intercept",
];
const REQUIRED_METADATA: [&str; 9] = [
    "hardware_model",
    "logical_cpus",
    "memory_mib",
    "os_build",
    "kernel",
    "filesystem",
    "storage",
    "dependency_versions",
    "fixture_digests",
];

/// A validated configuration bound to the SHA-256 of its original input bytes.
#[derive(Debug)]
pub struct LoadedProfile {
    config: PilotProfile,
    sha256: Digest,
}

impl LoadedProfile {
    pub fn from_bytes(bytes: &[u8]) -> ProofResult<Self> {
        check_input_size(bytes.len() as u64)?;
        let config: PilotProfile = serde_json::from_slice(bytes)
            .map_err(|_| invalid("profile does not match the strict schema"))?;
        config.validate()?;
        Ok(Self {
            config,
            sha256: Digest::of(bytes),
        })
    }

    pub fn load(path: &Path) -> ProofResult<Self> {
        let file = File::open(path).map_err(|_| invalid("profile file cannot be opened"))?;
        let metadata = file
            .metadata()
            .map_err(|_| invalid("profile metadata cannot be read"))?;
        if !metadata.is_file() {
            return Err(invalid("profile input must be a regular file"));
        }
        check_input_size(metadata.len())?;
        // Bound the read as well as the metadata check: the file can grow after stat.
        let mut bytes = Vec::with_capacity(metadata.len() as usize);
        file.take(MAX_PROFILE_BYTES as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| invalid("profile file cannot be read"))?;
        Self::from_bytes(&bytes)
    }

    pub fn config(&self) -> &PilotProfile {
        &self.config
    }

    pub fn sha256(&self) -> Digest {
        self.sha256
    }
}

/// Configuration policy versions are independent of the unchanged SDK wire contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ProfileVersion {
    #[serde(rename = "0.1.0")]
    V0_1_0,
    #[serde(rename = "0.2.0")]
    V0_2_0,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PilotProfile {
    pub profile_version: ProfileVersion,
    pub profile_id: CatalogId,
    pub host: HostProfile,
    pub toolchain: ToolchainProfile,
    pub transport: TransportProfile,
    pub control: ControlProfile,
    pub parser_fuzz: ParserFuzzProfile,
    pub component: ComponentProfile,
    pub external_runner: ExternalRunnerProfile,
    pub protocol: ProtocolProfile,
    pub ledger: LedgerProfile,
    pub measurement: MeasurementProfile,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostProfile {
    pub os: String,
    pub os_version: String,
    pub arch: String,
    pub minimum_logical_cpus: WireInt,
    pub minimum_memory_mib: WireInt,
    pub required_run_metadata: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolchainProfile {
    pub rust: String,
    pub component_target: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransportProfile {
    pub required_modes: Vec<String>,
    pub bind: String,
    pub fixture_scope: String,
    pub client_trust: String,
    pub upstream_tls_verification: bool,
    pub requests_per_case: WireInt,
    pub redirect_limit: WireInt,
    pub request_timeout_ms: WireInt,
    pub body_limit_bytes: WireInt,
    pub chunk_limit_bytes: WireInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlProfile {
    pub ack_deadline_ms: WireInt,
    pub stale_admissions_after_barrier: WireInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParserFuzzProfile {
    pub seed: WireInt,
    pub mutation_version: ContractVersion,
    pub max_inputs: WireInt,
    pub max_input_bytes: WireInt,
    pub deadline_ms: WireInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentProfile {
    pub world: String,
    pub linear_memory_bytes: WireInt,
    pub instances: WireInt,
    pub memories: WireInt,
    pub tables: WireInt,
    pub table_elements: WireInt,
    pub max_concurrent_invocations: WireInt,
    pub max_concurrent_host_calls: WireInt,
    pub fuel_per_invocation: WireInt,
    pub epoch_interval_ms: WireInt,
    pub invocation_deadline_ms: WireInt,
    pub host_call_deadline_ms: WireInt,
    pub runner_rss_monitor_threshold_mib: WireInt,
    pub rss_sampling_ms: WireInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalRunnerProfile {
    pub backend: String,
    pub lima_version: String,
    pub bubblewrap_version: String,
    pub guest_os: String,
    pub guest_cpus: WireInt,
    pub guest_memory_mib: WireInt,
    pub image_url: String,
    pub image_digest: String,
    pub direct_network: bool,
    pub host_mounts: bool,
    pub agent_or_manager_socket_forwarding: bool,
    pub memory_max_bytes: WireInt,
    pub memory_swap_max_bytes: WireInt,
    pub pids_max: WireInt,
    pub cpu_max: String,
    pub tmpfs_max_bytes: WireInt,
    pub file_descriptors_max: WireInt,
    pub wall_deadline_ms: WireInt,
    pub termination_grace_ms: WireInt,
    pub empty_cgroup_observation_deadline_ms: WireInt,
    pub orphan_lease_ms: WireInt,
    pub max_concurrent_invocations: WireInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtocolProfile {
    pub version: String,
    pub message_limit_bytes: WireInt,
    pub invocation_output_limit_bytes: WireInt,
    pub admission_queue_capacity: WireInt,
    pub event_queue_capacity: WireInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerProfile {
    pub journal_mode: String,
    pub synchronous: String,
    pub fullfsync: bool,
    pub foreign_keys: bool,
    pub busy_timeout_ms: WireInt,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeasurementProfile {
    pub latency_warmup_exchanges: WireInt,
    pub latency_sample_exchanges: WireInt,
    pub sample_body_bytes: WireInt,
    pub product_performance_thresholds_are_r0_gates: bool,
    pub provision_or_compile_during_timing: bool,
}

impl PilotProfile {
    pub fn validate(&self) -> ProofResult<()> {
        self.validate_pins()?;
        self.validate_security()?;
        self.validate_limits()?;
        self.validate_relationships()
    }

    fn validate_pins(&self) -> ProofResult<()> {
        if self.parser_fuzz.mutation_version != ContractVersion::V0_1_0
            || self.protocol.version != "razen.proof/0.1.0"
        {
            return Err(ProofError::new(
                ErrorCode::UnsupportedVersion,
                "unsupported profile contract version",
            ));
        }
        if self.profile_id.as_str() != "macos-arm64-proof"
            || self.host.os != "macOS"
            || self.host.os_version != "26.5.1"
            || self.host.arch != "arm64"
            || self.host.minimum_logical_cpus.get() < 4
            || self.host.minimum_memory_mib.get() < 16384
            || self.toolchain.rust != "1.100.0"
            || self.toolchain.component_target != "wasm32-wasip2"
            || self.component.world != "razen:component-proof/passive-proof@0.1.0"
        {
            return Err(invalid("unsupported pilot, toolchain, or component world"));
        }
        let runner = &self.external_runner;
        if runner.backend != "lima-vz-plain-bubblewrap-cgroup-v2"
            || runner.lima_version != "2.3.0"
            || runner.bubblewrap_version != "0.13.1"
            || runner.guest_os != "Debian 13.7 arm64"
            || runner.image_url != IMAGE_URL
            || runner.image_digest != IMAGE_DIGEST
        {
            return Err(invalid("unsupported runner backend or image pin"));
        }
        exact_members(&self.transport.required_modes, &REQUIRED_MODES)?;
        exact_members(&self.host.required_run_metadata, &REQUIRED_METADATA)
    }

    fn validate_security(&self) -> ProofResult<()> {
        let transport = &self.transport;
        let runner = &self.external_runner;
        if transport.bind != "loopback"
            || transport.fixture_scope != "explicit-address-and-ephemeral-port-grants"
            || transport.client_trust != "isolated-test-client-only"
            || !transport.upstream_tls_verification
            || runner.direct_network
            || runner.host_mounts
            || runner.agent_or_manager_socket_forwarding
            || runner.memory_swap_max_bytes.get() != 0
            || self.control.stale_admissions_after_barrier.get() != 0
        {
            return Err(ProofError::new(
                ErrorCode::PermissionDenied,
                "profile weakens fixture isolation",
            ));
        }
        if self.ledger.journal_mode != "DELETE"
            || self.ledger.synchronous != "FULL"
            || !self.ledger.fullfsync
            || !self.ledger.foreign_keys
            || self.measurement.product_performance_thresholds_are_r0_gates
            || self.measurement.provision_or_compile_during_timing
        {
            return Err(invalid("profile weakens durability or measurement policy"));
        }
        Ok(())
    }

    fn validate_limits(&self) -> ProofResult<()> {
        let transport = &self.transport;
        let fuzz = &self.parser_fuzz;
        let component = &self.component;
        let runner = &self.external_runner;
        let protocol = &self.protocol;
        let measurement = &self.measurement;
        let (instances_max, tables_max) = match self.profile_version {
            ProfileVersion::V0_1_0 => (1, 1),
            ProfileVersion::V0_2_0 => (3, 2),
        };
        // Reviewed maxima remain hard ceilings; stricter positive budgets are valid.
        for (value, maximum) in [
            (transport.requests_per_case, 20),
            (transport.redirect_limit, 3),
            (transport.request_timeout_ms, 2000),
            (transport.body_limit_bytes, 1048576),
            (transport.chunk_limit_bytes, 65536),
            (self.control.ack_deadline_ms, 1000),
            (fuzz.max_inputs, 10000),
            (fuzz.max_input_bytes, 65536),
            (fuzz.deadline_ms, 30000),
            (component.linear_memory_bytes, 67108864),
            (component.instances, instances_max),
            (component.memories, 1),
            (component.tables, tables_max),
            (component.table_elements, 16384),
            (component.max_concurrent_invocations, 1),
            (component.max_concurrent_host_calls, 1),
            (component.fuel_per_invocation, 10000000),
            (component.epoch_interval_ms, 10),
            (component.invocation_deadline_ms, 5000),
            (component.host_call_deadline_ms, 250),
            (component.runner_rss_monitor_threshold_mib, 256),
            (component.rss_sampling_ms, 10),
            (runner.guest_cpus, 2),
            (runner.guest_memory_mib, 2048),
            (runner.memory_max_bytes, 268435456),
            (runner.pids_max, 64),
            (runner.tmpfs_max_bytes, 16777216),
            (runner.file_descriptors_max, 64),
            (runner.wall_deadline_ms, 5000),
            (runner.termination_grace_ms, 200),
            (runner.empty_cgroup_observation_deadline_ms, 1000),
            (runner.orphan_lease_ms, 2000),
            (runner.max_concurrent_invocations, 1),
            (protocol.message_limit_bytes, 1048576),
            (protocol.invocation_output_limit_bytes, 2097152),
            (protocol.admission_queue_capacity, 64),
            (protocol.event_queue_capacity, 256),
            (self.ledger.busy_timeout_ms, 250),
            (measurement.latency_warmup_exchanges, 20),
            (measurement.latency_sample_exchanges, 100),
            (measurement.sample_body_bytes, 4096),
        ] {
            if value.get() == 0 || value.get() > maximum {
                return Err(invalid(
                    "profile limit is outside approved positive finite bounds",
                ));
            }
        }
        validate_cpu_max(&runner.cpu_max, runner.guest_cpus.get())
    }

    fn validate_relationships(&self) -> ProofResult<()> {
        let component = &self.component;
        let runner = &self.external_runner;
        if self.transport.chunk_limit_bytes > self.transport.body_limit_bytes
            || self.parser_fuzz.max_input_bytes > self.protocol.message_limit_bytes
            || component.host_call_deadline_ms > component.invocation_deadline_ms
            || component.epoch_interval_ms > component.invocation_deadline_ms
            || component.rss_sampling_ms > component.invocation_deadline_ms
            || component.linear_memory_bytes.get()
                > component.runner_rss_monitor_threshold_mib.get() * MIB
            || runner.memory_max_bytes.get() > runner.guest_memory_mib.get() * MIB
            || runner.tmpfs_max_bytes > runner.memory_max_bytes
            || runner.termination_grace_ms > runner.empty_cgroup_observation_deadline_ms
            || runner.empty_cgroup_observation_deadline_ms > runner.wall_deadline_ms
            || runner.termination_grace_ms > runner.orphan_lease_ms
            || runner.orphan_lease_ms > runner.wall_deadline_ms
            || self.ledger.busy_timeout_ms > self.control.ack_deadline_ms
            || self.measurement.sample_body_bytes > self.transport.body_limit_bytes
        {
            return Err(invalid("profile limits are internally inconsistent"));
        }
        Ok(())
    }
}

fn exact_members(actual: &[String], expected: &[&str]) -> ProofResult<()> {
    if actual.len() != expected.len()
        || expected.iter().any(|required| {
            actual
                .iter()
                .filter(|value| value.as_str() == *required)
                .count()
                != 1
        })
    {
        return Err(invalid(
            "profile requires each reviewed mode and metadata field exactly once",
        ));
    }
    Ok(())
}

fn validate_cpu_max(value: &str, guest_cpus: u64) -> ProofResult<()> {
    let failure = || invalid("invalid finite runner CPU quota");
    let (quota, period) = value.split_once(' ').ok_or_else(failure)?;
    let parse = |part: &str| -> ProofResult<u64> {
        if part.is_empty()
            || part.starts_with('0')
            || !part.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(failure());
        }
        part.parse::<u64>().map_err(|_| failure())
    };
    let quota = parse(quota)?;
    let period = parse(period)?;
    if quota < 1000 || !(1000..=1000000).contains(&period) || quota > period * guest_cpus {
        return Err(failure());
    }
    Ok(())
}

fn check_input_size(length: u64) -> ProofResult<()> {
    if length > MAX_PROFILE_BYTES as u64 {
        return Err(ProofError::new(
            ErrorCode::BudgetExhausted,
            "profile exceeds the input byte budget",
        ));
    }
    Ok(())
}

fn invalid(message: &'static str) -> ProofError {
    ProofError::new(ErrorCode::InvalidInput, message)
}
