//! A control endpoint has an explicitly owned short workspace, independent of
//! arbitrarily long evidence paths. No cwd changes, aliases, or shared sockets.
use std::path::{Path, PathBuf};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::control::{ControlClient, ControlEndpointRecord, ControlServer, ControlService};
use crate::adapters::workspace::OwnedDirectory;
use crate::domain::values::{ContractVersion, Digest, EntityId};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

#[cfg(target_os = "macos")]
const CONTROL_BASE: &str = "/private/tmp";
#[cfg(not(target_os = "macos"))]
const CONTROL_BASE: &str = "/tmp";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Resource {
    schema_version: ContractVersion,
    run_id: EntityId,
    resource_id: EntityId,
    directory_identity_sha256: Digest,
    #[serde(default)]
    endpoint: Option<ControlEndpointRecord>,
    #[serde(default)]
    execution_lease_sha256: Option<Digest>,
}

pub struct OwnedControl {
    resource_id: EntityId,
    workspace: Option<Arc<OwnedDirectory>>,
    server: Option<ControlServer>,
}

impl OwnedControl {
    pub fn start(run: Arc<OwnedDirectory>, service: Arc<ControlService>) -> ProofResult<Self> {
        let resource_id = EntityId::new();
        let workspace = Arc::new(OwnedDirectory::create(
            Path::new(CONTROL_BASE),
            &directory_name(resource_id),
            run.run_id(),
        )?);
        let mut owner = Self {
            resource_id,
            workspace: Some(workspace),
            server: None,
        };
        let workspace = owner
            .workspace
            .as_ref()
            .expect("new owner retains its workspace");
        let mut resource = Resource {
            schema_version: ContractVersion::V0_1_0,
            run_id: run.run_id(),
            resource_id,
            directory_identity_sha256: workspace.identity_digest()?,
            endpoint: None,
            execution_lease_sha256: match run
                .path()
                .join(super::harness::ENGINE_STARTUP_PATH)
                .symlink_metadata()
            {
                Ok(_) => Some(Digest::of(
                    &run.read(Path::new(super::harness::ENGINE_STARTUP_PATH), 4096)?,
                )),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(_) => return Err(integrity()),
            },
        };
        let bytes = serde_json::to_vec(&resource).map_err(|_| integrity())?;
        // Record ownership before opening the socket or accepting any proof work.
        // The capability stays ONLY in the private endpoint, not this record.
        run.write_new(&record_path(resource_id), &bytes)?;
        owner.server = Some(ControlServer::start(Arc::clone(workspace), service)?);
        resource.endpoint = Some(owner.server.as_ref().ok_or_else(integrity)?.ownership()?);
        run.atomic_write(
            &record_path(resource_id),
            &serde_json::to_vec(&resource).map_err(|_| integrity())?,
        )?;
        Ok(owner)
    }

    pub fn resource_id(&self) -> EntityId {
        self.resource_id
    }

    pub fn workspace_path(&self) -> &Path {
        self.workspace
            .as_ref()
            .expect("active owner retains its workspace")
            .path()
    }

    pub fn client(&self) -> ProofResult<ControlClient> {
        ControlClient::new(self.workspace.as_ref().ok_or_else(integrity)?)
    }

    /// Opening an endpoint by a resource UUID alone never establishes authority:
    /// verify its private run record, marker, UID/mode and exact directory inode.
    pub fn client_for(run: &OwnedDirectory, resource_id: EntityId) -> ProofResult<ControlClient> {
        let bytes = run.read(&record_path(resource_id), 4096)?;
        let resource: Resource = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
        if resource.run_id != run.run_id() || resource.resource_id != resource_id {
            return Err(integrity());
        }
        let workspace =
            OwnedDirectory::open(Path::new(CONTROL_BASE), &directory_name(resource_id))?;
        if workspace.run_id() != run.run_id()
            || workspace.identity_digest()? != resource.directory_identity_sha256
        {
            return Err(integrity());
        }
        ControlClient::new(&workspace)
    }

    pub fn shutdown(mut self) -> ProofResult<()> {
        self.cleanup()
    }

    /// Only a separately acquired, still-held native lease proves the original
    /// engine and its orchestrator are gone. Never infer that from READY/PIDs.
    pub fn reclaim_all(
        run: &OwnedDirectory,
        quiescent: Option<&super::harness::EngineQuiescence>,
    ) -> ProofResult<()> {
        use rustix::fs::{self, Dir, FileType, Mode, OFlags};
        let directory = run.lock_directory()?;
        let ephemeral = match fs::openat(
            &directory,
            "ephemeral",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => std::fs::File::from(fd),
            Err(rustix::io::Errno::NOENT) => return Ok(()),
            Err(_) => return Err(integrity()),
        };
        let native = fs::fstat(&ephemeral).map_err(|_| integrity())?;
        if FileType::from_raw_mode(native.st_mode) != FileType::Directory
            || native.st_uid != rustix::process::geteuid().as_raw()
            || native.st_mode as u32 & 0o7777 != 0o700
        {
            return Err(integrity());
        }
        let mut resources = Vec::new();
        let mut entries = Dir::read_from(&ephemeral).map_err(|_| integrity())?;
        for entry in &mut entries {
            let entry = entry.map_err(|_| integrity())?;
            let name = entry.file_name().to_str().map_err(|_| integrity())?;
            if !name.starts_with("control-resource-") {
                continue;
            }
            let id = name
                .strip_prefix("control-resource-")
                .and_then(|name| name.strip_suffix(".json"))
                .ok_or_else(integrity)?;
            if resources.len() == 64 {
                return Err(integrity());
            }
            resources.push(EntityId::parse(id)?);
        }
        drop(directory);
        for resource_id in resources {
            let proof = quiescent.ok_or_else(integrity)?;
            proof.validate(run)?;
            let resource: Resource =
                serde_json::from_slice(&run.read(&record_path(resource_id), 4096)?)
                    .map_err(|_| integrity())?;
            if resource.schema_version != ContractVersion::V0_1_0
                || resource.run_id != run.run_id()
                || resource.resource_id != resource_id
            {
                return Err(integrity());
            }
            let path = Path::new(CONTROL_BASE).join(directory_name(resource_id));
            match path.symlink_metadata() {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(_) => return Err(integrity()),
                Ok(_) => {}
            }
            let workspace =
                OwnedDirectory::open(Path::new(CONTROL_BASE), &directory_name(resource_id))?;
            if workspace.run_id() != run.run_id()
                || workspace.identity_digest()? != resource.directory_identity_sha256
            {
                return Err(integrity());
            }
            if resource.execution_lease_sha256 != Some(proof.binding(run)?) {
                return Err(integrity());
            }
            if let Some(endpoint) = resource.endpoint {
                endpoint.reclaim(&workspace)?;
            }
            // No captured endpoint means only an actually empty partial
            // resource can be reclaimed; unknown sockets/tokens survive.
            workspace.remove_empty()?;
        }
        Ok(())
    }

    fn cleanup(&mut self) -> ProofResult<()> {
        let stopped = match self.server.take() {
            Some(server) => server.shutdown(),
            None => Ok(()),
        };
        // Never recursively erase auxiliary data or follow a replaced pathname.
        let removed = match self.workspace.as_ref() {
            Some(workspace) => workspace.remove_empty(),
            None => Ok(()),
        };
        if removed.is_ok() {
            self.workspace = None;
        }
        stopped.and(removed)
    }
}

impl Drop for OwnedControl {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn directory_name(resource_id: EntityId) -> PathBuf {
    PathBuf::from(format!("razen-ctl-{resource_id}"))
}
fn record_path(resource_id: EntityId) -> PathBuf {
    PathBuf::from(format!("ephemeral/control-resource-{resource_id}.json"))
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Owned private control resource failed validation",
    )
}
