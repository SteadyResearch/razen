//! Read-only host and selected fixture observations. Isolation pins alone do not
//! establish that a managed guest has been prepared.
use std::collections::BTreeMap;
use std::path::Path;

use crate::adapters::workspace::OwnedDirectory;
use crate::application::profile::LoadedProfile;
use crate::domain::proofs::RunEnvironment;
use crate::domain::values::{CatalogId, Digest};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

pub fn observe(
    repo_root: &Path,
    workspace: &OwnedDirectory,
    profile: &LoadedProfile,
    binary_digests: BTreeMap<CatalogId, Digest>,
    case_ids: &[CatalogId],
) -> ProofResult<RunEnvironment> {
    if case_ids.is_empty()
        || case_ids.len() > 35
        || case_ids
            .iter()
            .any(|id| crate::domain::proofs::package_for_case(id).is_err())
    {
        return Err(ProofError::new(
            ErrorCode::InvalidInput,
            "Environment selection contains no valid bounded proof inventory",
        ));
    }
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        macos::observe(
            repo_root,
            workspace.path(),
            profile,
            binary_digests,
            case_ids,
        )
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (repo_root, workspace, profile, binary_digests, case_ids);
        Err(ProofError::new(
            ErrorCode::UnsupportedProtocol,
            "Run environment observation requires macOS arm64",
        ))
    }
}

/// Full prerequisite observations without creating an output directory or starting a VM.
pub fn preflight(repo_root: &Path, profile: &LoadedProfile) -> ProofResult<RunEnvironment> {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        let bytes = super::cli_workspace::reviewed(
            repo_root,
            Path::new(super::cli_workspace::SCENARIOS),
            super::harness::MAX_METADATA_BYTES,
        )?;
        let manifest: super::harness::ScenarioManifest =
            serde_json::from_slice(&bytes).map_err(|_| {
                ProofError::new(ErrorCode::IntegrityError, "Reviewed inventory is invalid")
            })?;
        let selection = manifest.select(super::cli::Suite::All, None, Digest::of(&bytes))?;
        let executable = std::env::current_exe().map_err(|_| {
            ProofError::new(
                ErrorCode::ProviderUnavailable,
                "Owned proof binary is unavailable",
            )
        })?;
        let mut binaries = BTreeMap::new();
        for name in ["razen-proof", "razen-engine"] {
            let path = executable.with_file_name(name);
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::symlink_metadata(&path).map_err(|_| {
                ProofError::new(
                    ErrorCode::ProviderUnavailable,
                    "Owned proof binary is unavailable",
                )
            })?;
            if metadata.uid() != rustix::process::geteuid().as_raw()
                || metadata.mode() & 0o022 != 0
                || metadata.mode() & 0o111 == 0
            {
                return Err(ProofError::new(
                    ErrorCode::IntegrityError,
                    "Proof binary ownership or permissions are invalid",
                ));
            }
            binaries.insert(
                CatalogId::parse(name)?,
                crate::adapters::guest::preflight::hash_file(&path)?,
            );
        }
        macos::observe(
            repo_root,
            repo_root,
            profile,
            binaries,
            &selection.selected_case_ids,
        )
    }
    #[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
    {
        let _ = (repo_root, profile);
        Err(ProofError::new(
            ErrorCode::UnsupportedProtocol,
            "Run environment observation requires macOS arm64",
        ))
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos {
    use super::*;
    use crate::adapters::command::{CommandLimits, capture};
    use crate::domain::proofs::{ImageDigest, IsolationStatus, VersionPin};
    use crate::domain::values::WireInt;
    use rustix::fs::{self, Mode, OFlags};
    use serde::Deserialize;
    use sha2::{Digest as _, Sha256};
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::Read;
    use std::path::Component;
    use std::time::{Duration, Instant};

    fn missing() -> ProofError {
        ProofError::new(
            ErrorCode::ProviderUnavailable,
            "Required host or reviewed-file observation is missing or invalid",
        )
    }

    fn native(program: &str, args: &[&OsStr], input: Option<&[u8]>) -> ProofResult<Vec<u8>> {
        Ok(capture(
            Path::new(program),
            args,
            input,
            CommandLimits {
                stdin_bytes: 128 * 1024,
                stdout_bytes: 128 * 1024,
                stderr_bytes: 4096,
                timeout: Duration::from_secs(3),
            },
        )?
        .stdout)
    }

    fn text(program: &str, args: &[&str]) -> ProofResult<String> {
        let args: Vec<&OsStr> = args.iter().map(OsStr::new).collect();
        let bytes = native(program, &args, None)?;
        let value = std::str::from_utf8(&bytes).map_err(|_| missing())?.trim();
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(missing());
        }
        Ok(value.to_owned())
    }

    fn number(program: &str, args: &[&str]) -> ProofResult<u64> {
        text(program, args)?.parse().map_err(|_| missing())
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct DiskInfo {
        filesystem_type: String,
        total_size: u64,
        device_block_size: u64,
        solid_state: bool,
    }

    fn disk(path: &Path) -> ProofResult<(String, String)> {
        // Resolve the actual containing volume; diskutil does not accept directories.
        if !path.is_absolute() {
            return Err(missing());
        }
        let df = native("/bin/df", &[OsStr::new("-P"), path.as_os_str()], None)?;
        let df = std::str::from_utf8(&df).map_err(|_| missing())?;
        let mut lines = df.lines();
        lines.next().ok_or_else(missing)?;
        let volume = lines.next().ok_or_else(missing)?;
        if lines.any(|line| !line.trim().is_empty()) {
            return Err(missing());
        }
        let device = volume.split_whitespace().next().ok_or_else(missing)?;
        let suffix = device.strip_prefix("/dev/disk").ok_or_else(missing)?;
        if !suffix.as_bytes().first().is_some_and(u8::is_ascii_digit)
            || !suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || byte == b's')
        {
            return Err(missing());
        }
        let plist = native(
            "/usr/sbin/diskutil",
            &[OsStr::new("info"), OsStr::new("-plist"), OsStr::new(device)],
            None,
        )?;
        let json = native(
            "/usr/bin/plutil",
            &[
                OsStr::new("-convert"),
                OsStr::new("json"),
                OsStr::new("-o"),
                OsStr::new("-"),
                OsStr::new("--"),
                OsStr::new("-"),
            ],
            Some(&plist),
        )?;
        let disk: DiskInfo = serde_json::from_slice(&json).map_err(|_| missing())?;
        if disk.filesystem_type.is_empty()
            || disk.filesystem_type.len() > 64
            || !disk
                .filesystem_type
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || disk.total_size == 0
            || disk.device_block_size == 0
        {
            return Err(missing());
        }
        let storage = format!(
            "solid_state={}; capacity_bytes={}; block_bytes={}",
            disk.solid_state, disk.total_size, disk.device_block_size
        );
        Ok((disk.filesystem_type, storage))
    }

    fn open_reviewed(root: &File, relative: &Path) -> ProofResult<File> {
        let mut parent = root.try_clone().map_err(|_| missing())?;
        let mut components = relative.components().peekable();
        while let Some(component) = components.next() {
            let Component::Normal(name) = component else {
                return Err(missing());
            };
            let mut flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
            if components.peek().is_some() {
                flags |= OFlags::DIRECTORY;
            }
            parent =
                File::from(fs::openat(&parent, name, flags, Mode::empty()).map_err(|_| missing())?);
        }
        if !parent.metadata().map_err(|_| missing())?.is_file() {
            return Err(missing());
        }
        Ok(parent)
    }

    fn hash(root: &File, relative: &str, deadline: Instant) -> ProofResult<Digest> {
        const MAX_FILE: u64 = 256 * 1024 * 1024;
        let mut file = open_reviewed(root, Path::new(relative))?;
        let before = file.metadata().map_err(|_| missing())?;
        if before.len() > MAX_FILE {
            return Err(missing());
        }
        let mut bytes = 0u64;
        let mut sha = Sha256::new();
        let mut buffer = [0; 16 * 1024];
        loop {
            if Instant::now() >= deadline {
                return Err(ProofError::new(
                    ErrorCode::Timeout,
                    "Reviewed-file hashing deadline exceeded",
                ));
            }
            let count = file.read(&mut buffer).map_err(|_| missing())?;
            if count == 0 {
                break;
            }
            bytes = bytes.checked_add(count as u64).ok_or_else(missing)?;
            if bytes > MAX_FILE {
                return Err(missing());
            }
            sha.update(&buffer[..count]);
        }
        let after = file.metadata().map_err(|_| missing())?;
        if bytes != before.len()
            || bytes != after.len()
            || before.modified().ok() != after.modified().ok()
        {
            return Err(missing());
        }
        Ok(Digest::from_sha256(sha.finalize().into()))
    }

    #[derive(Deserialize)]
    struct CorpusManifest {
        entries: Vec<CorpusEntry>,
    }
    #[derive(Deserialize)]
    struct CorpusEntry {
        path: String,
        sha256: Digest,
    }

    fn verify_corpus(root: &File, manifest_digest: Digest, deadline: Instant) -> ProofResult<()> {
        let file = open_reviewed(
            root,
            Path::new("fixtures/scenarios/parser-corpus/manifest.json"),
        )?;
        let mut bytes = Vec::new();
        file.take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| missing())?;
        if bytes.len() > 1024 * 1024 || Digest::of(&bytes) != manifest_digest {
            return Err(missing());
        }
        let manifest: CorpusManifest = serde_json::from_slice(&bytes).map_err(|_| missing())?;
        if manifest.entries.is_empty() || manifest.entries.len() > 4096 {
            return Err(missing());
        }
        let mut seen = std::collections::BTreeSet::new();
        for entry in manifest.entries {
            if !seen.insert(entry.path.clone())
                || entry.path.len() > 256
                || !Path::new(&entry.path)
                    .components()
                    .all(|c| matches!(c, Component::Normal(_)))
            {
                return Err(missing());
            }
            let path = format!("fixtures/scenarios/parser-corpus/{}", entry.path);
            if hash(root, &path, deadline)? != entry.sha256 {
                return Err(missing());
            }
        }
        Ok(())
    }

    pub(super) fn observe(
        repo_root: &Path,
        workspace: &Path,
        profile: &LoadedProfile,
        mut binary_digests: BTreeMap<CatalogId, Digest>,
        case_ids: &[CatalogId],
    ) -> ProofResult<RunEnvironment> {
        let selected = profile.config();
        let compiler = env!("RAZEN_BUILD_RUSTC");
        let mut tokens = compiler.split_whitespace();
        if tokens.next() != Some("rustc") {
            return Err(missing());
        }
        let compiler_version = tokens.next().ok_or_else(missing)?;
        if compiler_version != selected.toolchain.rust
            || !compiler_version
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err(ProofError::new(
                ErrorCode::UnsupportedVersion,
                "Compiled Rust compiler differs from the selected stable profile",
            ));
        }
        if binary_digests.is_empty() || binary_digests.len() > 128 {
            return Err(missing());
        }
        let os = text("/usr/bin/sw_vers", &["-productName"])?;
        let os_version = text("/usr/bin/sw_vers", &["-productVersion"])?;
        let arch = text("/usr/bin/uname", &["-m"])?;
        let logical_cpus = number("/usr/sbin/sysctl", &["-n", "hw.logicalcpu"])?;
        let memory_mib = number("/usr/sbin/sysctl", &["-n", "hw.memsize"])? / (1024 * 1024);
        if os != selected.host.os
            || os_version != selected.host.os_version
            || arch != selected.host.arch
            || logical_cpus < selected.host.minimum_logical_cpus.get()
            || memory_mib < selected.host.minimum_memory_mib.get()
        {
            return Err(ProofError::new(
                ErrorCode::UnsupportedProtocol,
                "Observed host does not meet the selected macOS arm64 profile",
            ));
        }
        let hardware_model = text("/usr/sbin/sysctl", &["-n", "hw.model"])?;
        let os_build = text("/usr/bin/sw_vers", &["-buildVersion"])?;
        let kernel = text("/usr/bin/uname", &["-sr"])?;
        let (filesystem, storage) = disk(workspace)?;
        let root = File::from(
            fs::open(
                repo_root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|_| missing())?,
        );
        let deadline = Instant::now() + Duration::from_secs(15);
        let lockfile_sha256 = hash(&root, "Cargo.lock", deadline)?;
        let component_lockfile_sha256 = hash(&root, "fixtures/components/Cargo.lock", deadline)?;
        let wit_sha256 = hash(
            &root,
            "specs/001-r0-feasibility/contracts/plugin-sdk.wit",
            deadline,
        )?;
        let mut fixture_digests = BTreeMap::new();
        for (id, path) in [
            ("scenario-manifest", "fixtures/scenarios/manifest.json"),
            ("contract-scenarios", "fixtures/scenarios/contracts.json"),
            (
                "approved-fixtures",
                "fixtures/scenarios/approved-fixtures.json",
            ),
            (
                "parser-corpus-manifest",
                "fixtures/scenarios/parser-corpus/manifest.json",
            ),
            (
                "pilot-profile",
                "specs/001-r0-feasibility/contracts/pilot-profile.json",
            ),
        ] {
            fixture_digests.insert(CatalogId::parse(id)?, hash(&root, path, deadline)?);
        }
        if fixture_digests[&CatalogId::parse("pilot-profile")?] != profile.sha256() {
            return Err(missing());
        }
        verify_corpus(
            &root,
            fixture_digests[&CatalogId::parse("parser-corpus-manifest")?],
            deadline,
        )?;
        let mut dependency_versions = BTreeMap::from([(
            CatalogId::parse("rust")?,
            VersionPin::parse(compiler_version)?,
        )]);
        let has = |prefix: &str| case_ids.iter().any(|id| id.as_str().starts_with(prefix));
        if has("NET-") {
            fixture_digests.insert(
                CatalogId::parse("transport-scenarios")?,
                hash(&root, "fixtures/scenarios/transport.json", deadline)?,
            );
        }
        if has("NET-") || has("EXIT-") {
            dependency_versions.insert(
                CatalogId::parse("rama")?,
                VersionPin::parse(crate::adapters::transport::RAMA_VERSION)?,
            );
        }
        if has("REC-") {
            fixture_digests.insert(
                CatalogId::parse("recovery-scenarios")?,
                hash(&root, "fixtures/scenarios/recovery.json", deadline)?,
            );
            let receiver = std::env::current_exe()
                .map_err(|_| missing())?
                .with_file_name("razen-fixture-receiver");
            let parent = receiver.parent().ok_or_else(missing)?;
            let parent = File::from(
                fs::open(
                    parent,
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| missing())?,
            );
            binary_digests.insert(
                CatalogId::parse("razen-fixture-receiver")?,
                hash(&parent, "razen-fixture-receiver", deadline)?,
            );
        }
        if case_ids.iter().any(|id| id.as_str().starts_with("CMP-")) {
            let approved = crate::adapters::components::supervisor::ApprovedComponents::load(
                repo_root, profile,
            )?;
            fixture_digests.insert(
                CatalogId::parse("components")?,
                hash(&root, "fixtures/scenarios/components.json", deadline)?,
            );
            fixture_digests.insert(
                CatalogId::parse("component-build-manifest")?,
                approved.manifest_sha256,
            );
            for variant in approved.variants() {
                fixture_digests.insert(CatalogId::parse(&variant.variant)?, variant.sha256);
            }
            if binary_digests
                .insert(
                    CatalogId::parse("razen-component-runner")?,
                    approved.manifest.runner_sha256,
                )
                .is_some_and(|prior| prior != approved.manifest.runner_sha256)
            {
                return Err(missing());
            }
            dependency_versions.insert(
                CatalogId::parse("wasmtime")?,
                VersionPin::parse(&approved.manifest.wasmtime)?,
            );
            dependency_versions.insert(
                CatalogId::parse("wit-bindgen")?,
                VersionPin::parse(&approved.manifest.wit_bindgen)?,
            );
        }
        let mut environment = RunEnvironment {
            hardware_model,
            logical_cpus: WireInt::new(logical_cpus)?,
            memory_mib: WireInt::new(memory_mib)?,
            os,
            os_version,
            arch,
            os_build,
            kernel,
            filesystem,
            storage,
            component_target: selected.toolchain.component_target.clone(),
            backend: selected.external_runner.backend.clone(),
            isolation_status: IsolationStatus::NotRequired,
            guest_os: selected.external_runner.guest_os.clone(),
            image_digest: ImageDigest::parse(&selected.external_runner.image_digest)?,
            dependency_versions,
            fixture_digests,
            binary_digests,
            lockfile_sha256,
            component_lockfile_sha256,
            guest_package_manifest_sha256: None,
            provisioning_sha256: None,
            effective_config_sha256: None,
            seccomp_sha256: None,
            wit_sha256,
        };
        if has("RUN-") || has("EXIT-") {
            environment.fixture_digests.insert(
                CatalogId::parse("runtime")?,
                hash(&root, "fixtures/scenarios/runtime.json", deadline)?,
            );
            let guest =
                crate::adapters::guest::preflight::PreparedGuest::discover(repo_root, profile)?;
            let manifest = guest.provenance();
            let digest = |value: &serde_json::Value| -> ProofResult<Digest> {
                Ok(Digest::parse(value.as_str().ok_or_else(missing)?)?)
            };
            if manifest["guest_os"].as_str() != Some(selected.external_runner.guest_os.as_str())
                || manifest["bubblewrap_version"].as_str() != Some("bubblewrap 0.13.1")
            {
                return Err(missing());
            }
            environment.isolation_status = IsolationStatus::Prepared;
            environment.fixture_digests.insert(
                CatalogId::parse("guest-source")?,
                digest(&manifest["source_sha256"])?,
            );
            for (key, source) in [
                ("guest-supervisor", "supervisor"),
                ("guest-adversary", "adversary"),
                ("bubblewrap", "bubblewrap"),
            ] {
                environment.binary_digests.insert(
                    CatalogId::parse(key)?,
                    digest(&manifest["binary_digests"][source])?,
                );
            }
            // discover executed the pinned private manager's real version query.
            environment
                .dependency_versions
                .insert(CatalogId::parse("lima")?, VersionPin::parse("2.3.0")?);
            let bubblewrap = manifest["bubblewrap_version"]
                .as_str()
                .and_then(|text| text.strip_prefix("bubblewrap "))
                .ok_or_else(missing)?;
            environment.dependency_versions.insert(
                CatalogId::parse("bubblewrap")?,
                VersionPin::parse(bubblewrap)?,
            );
            environment.guest_package_manifest_sha256 =
                Some(digest(&manifest["package_manifest_sha256"])?);
            environment.provisioning_sha256 = Some(digest(&manifest["provisioning_sha256"])?);
            environment.effective_config_sha256 =
                Some(digest(&manifest["effective_config_sha256"])?);
            environment.seccomp_sha256 = Some(digest(&manifest["seccomp_sha256"])?);
        }
        environment.validate()?;
        Ok(environment)
    }
}
