//! Host-owned immutable evidence. The append-only catalog is rebuilt from strict,
//! hash-chained records; body files are never treated as committed metadata.
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use rustix::fs::{self, Dir, FileType, FlockOperation, Mode, OFlags};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::workspace::OwnedDirectory;
use crate::domain::evidence::{
    Artifact, EvidenceRange, EvidenceRef, MAX_CHUNK_BYTES, ObservationProposal, RedactionStatus,
    Snapshot,
};
use crate::domain::values::{ByteRange, CatalogId, ContractVersion, Digest, EntityId, WireInt};
use crate::protocol::contracts::{CanonicalFixtures, ContractRecord};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

const MAX_ARTIFACT_BYTES: usize = 32 * 1_048_576;
const MAX_RECORD_BYTES: usize = 128 * 1024;
// The full R0 history includes transport samples and the complete provenance register.
const MAX_ARTIFACT_RECORDS: usize = 8_192;
const MAX_RECORDS: usize = 4096;
const MAX_CATALOG_ENTRIES: usize = MAX_ARTIFACT_RECORDS + 2 * MAX_RECORDS;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
    links: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
}

impl FileIdentity {
    fn read(file: &File) -> ProofResult<Self> {
        let metadata = file.metadata().map_err(storage_error)?;
        if !metadata.is_file()
            || metadata.uid() != rustix::process::geteuid().as_raw()
            || metadata.mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(denied());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
        })
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreHeader {
    schema_version: ContractVersion,
    run_id: EntityId,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Record {
    Artifact {
        artifact: Artifact,
        body_identity: FileIdentity,
    },
    Snapshot {
        snapshot: Snapshot,
    },
    Proposal {
        proposal: ObservationProposal,
    },
}

impl Record {
    fn id(&self) -> EntityId {
        match self {
            Self::Artifact { artifact, .. } => artifact.artifact_id,
            Self::Snapshot { snapshot } => snapshot.snapshot_id,
            Self::Proposal { proposal } => proposal.proposal_id,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogEntry {
    schema_version: ContractVersion,
    run_id: EntityId,
    sequence: WireInt,
    previous: Option<Digest>,
    record: Record,
}

struct StoredArtifact {
    artifact: Arc<Artifact>,
    identity: FileIdentity,
}

struct MetadataSeal {
    path: String,
    digest: Digest,
    length: u64,
}

#[derive(Default)]
struct Catalog {
    artifacts: BTreeMap<EntityId, StoredArtifact>,
    snapshots: BTreeMap<EntityId, Arc<Snapshot>>,
    proposals: BTreeMap<EntityId, Arc<ObservationProposal>>,
    metadata: BTreeMap<EntityId, MetadataSeal>,
    previous: Option<Digest>,
    tail: Option<EntityId>,
    failed_write: bool,
}

/// One writer or multiple quiescent inspectors per store. The sidecar lease
/// never retains the run directory flock; readonly body readers retain a shared lease.
pub struct EvidenceStore {
    workspace: Arc<OwnedDirectory>,
    writer: Arc<File>,
    writer_identity: FileIdentity,
    readonly: bool,
    catalog: Mutex<Catalog>,
}

impl EvidenceStore {
    pub(crate) fn workspace(&self) -> &Arc<OwnedDirectory> {
        &self.workspace
    }

    pub fn open(workspace: Arc<OwnedDirectory>) -> ProofResult<Self> {
        Self::start(workspace, false)
    }

    /// Inspect an existing quiescent catalog without creating or repairing storage.
    /// A shared native lease excludes writers and is retained by derived readers.
    pub fn open_readonly(workspace: Arc<OwnedDirectory>) -> ProofResult<Self> {
        Self::start(workspace, true)
    }

    fn start(workspace: Arc<OwnedDirectory>, readonly: bool) -> ProofResult<Self> {
        let (writer, paths) = open_layout(&workspace, readonly)?;
        let writer_identity = FileIdentity::read(&writer)?;
        if writer_identity.length != 0 {
            return Err(integrity());
        }
        let store = Self {
            workspace,
            writer: Arc::new(writer),
            writer_identity,
            readonly,
            catalog: Mutex::new(Catalog::default()),
        };
        {
            let mut catalog = store.catalog()?;
            for path in paths {
                let bytes = store.workspace.read(Path::new(&path), MAX_RECORD_BYTES)?;
                let entry: CatalogEntry =
                    serde_json::from_slice(&bytes).map_err(|_| integrity())?;
                let canonical = serde_json::to_vec(&entry).map_err(|_| integrity())?;
                let digest = Digest::of(&bytes);
                if canonical != bytes
                    || entry.schema_version != ContractVersion::V0_1_0
                    || entry.run_id != store.workspace.run_id()
                    || entry.sequence.get() != catalog.metadata.len() as u64
                    || entry.previous != catalog.previous
                    || path != catalog_path(entry.sequence.get(), digest)
                {
                    return Err(integrity());
                }
                store.validate_record(&catalog, &entry.record)?;
                let seal = MetadataSeal {
                    path,
                    digest,
                    length: bytes.len() as u64,
                };
                publish(&mut catalog, entry.record, seal);
            }
        }
        Ok(store)
    }

    pub fn write_artifact(
        &self,
        project_id: EntityId,
        kind: CatalogId,
        origin_invocation_id: EntityId,
        bytes: &[u8],
        redaction_status: RedactionStatus,
    ) -> ProofResult<Arc<Artifact>> {
        let mut catalog = self.catalog()?;
        self.writable(&catalog)?;
        capacity(catalog.artifacts.len(), MAX_ARTIFACT_RECORDS)?;
        if bytes.len() > MAX_ARTIFACT_BYTES {
            return Err(budget());
        }
        let artifact_id = EntityId::new();
        let artifact = Artifact {
            artifact_id,
            project_id,
            kind,
            relative_path: body_path(artifact_id),
            sha256: Digest::of(bytes),
            length_bytes: WireInt::new(bytes.len() as u64)?,
            origin_invocation_id,
            redaction_status,
        };
        self.persist_artifact(&mut catalog, artifact, bytes)
    }

    /// Import schema examples as public bytes only, never as observed operational
    /// results, grants, histories, or proposed findings.
    pub fn import_fixtures(
        &self,
        fixtures: &CanonicalFixtures,
        origin_invocation_id: EntityId,
    ) -> ProofResult<()> {
        let mut catalog = self.catalog()?;
        self.writable(&catalog)?;
        // Preflight every collision before installing any part of an import.
        let source_artifacts: BTreeMap<_, _> = fixtures
            .records()
            .iter()
            .filter_map(|document| match &document.record {
                ContractRecord::Artifact(artifact) => Some((artifact.artifact_id, artifact)),
                _ => None,
            })
            .collect();
        let mut imported_ids = BTreeSet::new();
        let mut new_artifacts = 0;
        let mut new_snapshots = 0;
        for document in fixtures.records() {
            match &document.record {
                ContractRecord::Artifact(source) => {
                    if !imported_ids.insert(source.artifact_id) {
                        return Err(integrity());
                    }
                    if !catalog.artifacts.contains_key(&source.artifact_id) {
                        new_artifacts += 1;
                    }
                    source.validate_bytes(source.project_id, fixtures.body(source.artifact_id)?)?;
                    if let Some(existing) = catalog.artifacts.get(&source.artifact_id) {
                        let mut expected = source.clone();
                        expected.relative_path = body_path(source.artifact_id);
                        expected.origin_invocation_id = origin_invocation_id;
                        if *existing.artifact != expected {
                            return Err(integrity());
                        }
                        self.validate_metadata(&catalog, source.artifact_id)?;
                        self.verified_file(existing)?;
                    } else if catalog.metadata.contains_key(&source.artifact_id) {
                        return Err(integrity());
                    }
                }
                ContractRecord::Snapshot(source) => {
                    if !imported_ids.insert(source.snapshot_id) {
                        return Err(integrity());
                    }
                    if !catalog.snapshots.contains_key(&source.snapshot_id) {
                        new_snapshots += 1;
                    }
                    let body = catalog
                        .artifacts
                        .get(&source.body_ref)
                        .map(|stored| stored.artifact.as_ref())
                        .or_else(|| source_artifacts.get(&source.body_ref).copied())
                        .ok_or_else(denied)?;
                    if body.project_id != source.project_id
                        || body.sha256 != source.sha256
                        || body.length_bytes != source.length_bytes
                    {
                        return Err(integrity());
                    }
                    if let Some(existing) = catalog.snapshots.get(&source.snapshot_id) {
                        if existing.as_ref() != source {
                            return Err(integrity());
                        }
                        self.validate_metadata(&catalog, source.snapshot_id)?;
                    } else if catalog.metadata.contains_key(&source.snapshot_id) {
                        return Err(integrity());
                    }
                }
                _ => {}
            }
        }
        if catalog.artifacts.len() + new_artifacts > MAX_ARTIFACT_RECORDS
            || catalog.snapshots.len() + new_snapshots > MAX_RECORDS
        {
            return Err(budget());
        }
        for document in fixtures.records() {
            if let ContractRecord::Artifact(source) = &document.record {
                if catalog.artifacts.contains_key(&source.artifact_id) {
                    continue;
                }
                let mut artifact = source.clone();
                artifact.relative_path = body_path(source.artifact_id);
                artifact.origin_invocation_id = origin_invocation_id;
                let bytes = fixtures.body(source.artifact_id)?;
                artifact.validate_bytes(artifact.project_id, bytes)?;
                self.persist_artifact(&mut catalog, artifact, bytes)?;
            }
        }
        for document in fixtures.records() {
            if let ContractRecord::Snapshot(source) = &document.record {
                if catalog.snapshots.contains_key(&source.snapshot_id) {
                    continue;
                }
                self.append(
                    &mut catalog,
                    Record::Snapshot {
                        snapshot: source.clone(),
                    },
                )?;
            }
        }
        Ok(())
    }

    pub fn artifact(
        &self,
        project_id: EntityId,
        artifact_id: EntityId,
    ) -> ProofResult<Arc<Artifact>> {
        let catalog = self.catalog()?;
        let stored = owned_artifact(&catalog, project_id, artifact_id)?;
        self.validate_metadata(&catalog, artifact_id)?;
        Ok(stored.artifact.clone())
    }

    pub fn snapshot(
        &self,
        project_id: EntityId,
        snapshot_id: EntityId,
        revision: WireInt,
    ) -> ProofResult<Arc<Snapshot>> {
        let catalog = self.catalog()?;
        let snapshot = owned_snapshot(&catalog, project_id, snapshot_id, revision)?;
        self.validate_metadata(&catalog, snapshot_id)?;
        Ok(snapshot.clone())
    }

    pub fn install_snapshot(&self, snapshot: Snapshot) -> ProofResult<Arc<Snapshot>> {
        let id = snapshot.snapshot_id;
        let mut catalog = self.catalog()?;
        self.append(&mut catalog, Record::Snapshot { snapshot })?;
        catalog.snapshots.get(&id).cloned().ok_or_else(integrity)
    }

    pub fn snapshot_reader(
        &self,
        project_id: EntityId,
        snapshot_id: EntityId,
        revision: WireInt,
    ) -> ProofResult<SnapshotReader> {
        let catalog = self.catalog()?;
        let snapshot = owned_snapshot(&catalog, project_id, snapshot_id, revision)?;
        self.validate_metadata(&catalog, snapshot_id)?;
        let stored = owned_artifact(&catalog, project_id, snapshot.body_ref)?;
        self.validate_metadata(&catalog, snapshot.body_ref)?;
        let file = self.verified_file(stored)?;
        Ok(SnapshotReader {
            workspace: self.workspace.clone(),
            snapshot: snapshot.clone(),
            file,
            relative_path: stored.artifact.relative_path.clone(),
            identity: stored.identity.clone(),
            _read_lease: self.readonly.then(|| Arc::clone(&self.writer)),
        })
    }

    pub fn read_artifact(
        &self,
        project_id: EntityId,
        artifact_id: EntityId,
        max_bytes: usize,
    ) -> ProofResult<Vec<u8>> {
        let catalog = self.catalog()?;
        let stored = owned_artifact(&catalog, project_id, artifact_id)?;
        if stored.artifact.length_bytes.get() > max_bytes as u64 {
            return Err(budget());
        }
        self.validate_metadata(&catalog, artifact_id)?;
        let file = self
            .workspace
            .open_readonly(Path::new(&stored.artifact.relative_path))?;
        if FileIdentity::read(&file)? != stored.identity {
            return Err(integrity());
        }
        let length = usize::try_from(stored.artifact.length_bytes.get()).map_err(|_| budget())?;
        let mut bytes = vec![0; length];
        file.read_exact_at(&mut bytes, 0).map_err(storage_error)?;
        unchanged(
            &self.workspace,
            &stored.artifact.relative_path,
            &file,
            &stored.identity,
        )?;
        if Digest::of(&bytes) != stored.artifact.sha256 {
            return Err(integrity());
        }
        Ok(bytes)
    }

    pub fn verify_artifact(&self, project_id: EntityId, artifact_id: EntityId) -> ProofResult<()> {
        let catalog = self.catalog()?;
        let stored = owned_artifact(&catalog, project_id, artifact_id)?;
        self.validate_metadata(&catalog, artifact_id)?;
        self.verified_file(stored)?;
        Ok(())
    }

    pub fn record_proposal(
        &self,
        proposal: ObservationProposal,
    ) -> ProofResult<Arc<ObservationProposal>> {
        let id = proposal.proposal_id;
        let mut catalog = self.catalog()?;
        self.append(&mut catalog, Record::Proposal { proposal })?;
        catalog.proposals.get(&id).cloned().ok_or_else(integrity)
    }

    pub fn proposal(
        &self,
        project_id: EntityId,
        proposal_id: EntityId,
    ) -> ProofResult<Arc<ObservationProposal>> {
        let catalog = self.catalog()?;
        let proposal = catalog
            .proposals
            .get(&proposal_id)
            .filter(|proposal| proposal.project_id == project_id)
            .ok_or_else(denied)?;
        self.validate_metadata(&catalog, proposal_id)?;
        Ok(proposal.clone())
    }

    pub fn proposals(&self, project_id: EntityId) -> ProofResult<Vec<Arc<ObservationProposal>>> {
        let catalog = self.catalog()?;
        let mut proposals = Vec::new();
        for proposal in catalog
            .proposals
            .values()
            .filter(|proposal| proposal.project_id == project_id)
        {
            self.validate_metadata(&catalog, proposal.proposal_id)?;
            proposals.push(proposal.clone());
        }
        Ok(proposals)
    }

    pub fn artifacts(&self) -> ProofResult<Vec<Arc<Artifact>>> {
        let catalog = self.catalog()?;
        let mut artifacts = Vec::with_capacity(catalog.artifacts.len());
        for stored in catalog.artifacts.values() {
            self.validate_metadata(&catalog, stored.artifact.artifact_id)?;
            artifacts.push(stored.artifact.clone());
        }
        Ok(artifacts)
    }

    pub fn snapshots(&self) -> ProofResult<Vec<Arc<Snapshot>>> {
        let catalog = self.catalog()?;
        let mut snapshots = Vec::with_capacity(catalog.snapshots.len());
        for snapshot in catalog.snapshots.values() {
            self.validate_metadata(&catalog, snapshot.snapshot_id)?;
            snapshots.push(snapshot.clone());
        }
        Ok(snapshots)
    }

    fn catalog(&self) -> ProofResult<MutexGuard<'_, Catalog>> {
        if self.readonly {
            unchanged(
                &self.workspace,
                "evidence/.writer",
                &self.writer,
                &self.writer_identity,
            )?;
        }
        self.catalog.lock().map_err(|_| integrity())
    }

    fn writable(&self, catalog: &Catalog) -> ProofResult<()> {
        if self.readonly {
            return Err(denied());
        }
        if catalog.failed_write {
            return Err(integrity());
        }
        unchanged(
            &self.workspace,
            "evidence/.writer",
            &self.writer,
            &self.writer_identity,
        )?;
        if let Some(id) = catalog.tail {
            self.validate_metadata(catalog, id)?;
        }
        Ok(())
    }

    fn validate_metadata(&self, catalog: &Catalog, id: EntityId) -> ProofResult<()> {
        let seal = catalog.metadata.get(&id).ok_or_else(integrity)?;
        let mut file = self.workspace.open_readonly(Path::new(&seal.path))?;
        verify_stream(&mut file, seal.digest, seal.length)?;
        Ok(())
    }

    fn verified_file(&self, stored: &StoredArtifact) -> ProofResult<File> {
        self.verified_artifact(&stored.artifact, &stored.identity)
    }

    fn verified_artifact(&self, artifact: &Artifact, identity: &FileIdentity) -> ProofResult<File> {
        let mut file = self
            .workspace
            .open_readonly(Path::new(&artifact.relative_path))?;
        if FileIdentity::read(&file)? != *identity {
            return Err(integrity());
        }
        verify_stream(&mut file, artifact.sha256, artifact.length_bytes.get())?;
        unchanged(&self.workspace, &artifact.relative_path, &file, identity)?;
        Ok(file)
    }

    fn persist_artifact(
        &self,
        catalog: &mut Catalog,
        artifact: Artifact,
        bytes: &[u8],
    ) -> ProofResult<Arc<Artifact>> {
        self.writable(catalog)?;
        capacity(catalog.artifacts.len(), MAX_ARTIFACT_RECORDS)?;
        if bytes.len() > MAX_ARTIFACT_BYTES || catalog.metadata.contains_key(&artifact.artifact_id)
        {
            return Err(invalid());
        }
        artifact.validate_bytes(artifact.project_id, bytes)?;
        let result = self
            .workspace
            .write_new(Path::new(&artifact.relative_path), bytes);
        if let Err(error) = result {
            catalog.failed_write = true;
            return Err(error);
        }
        let identity = match self
            .workspace
            .open_readonly(Path::new(&artifact.relative_path))
            .and_then(|file| FileIdentity::read(&file))
        {
            Ok(identity) => identity,
            Err(error) => {
                catalog.failed_write = true;
                return Err(error);
            }
        };
        let id = artifact.artifact_id;
        self.append(
            catalog,
            Record::Artifact {
                artifact,
                body_identity: identity,
            },
        )?;
        catalog
            .artifacts
            .get(&id)
            .map(|stored| stored.artifact.clone())
            .ok_or_else(integrity)
    }

    fn append(&self, catalog: &mut Catalog, record: Record) -> ProofResult<()> {
        self.writable(catalog)?;
        self.validate_record(catalog, &record)?;
        let entry = CatalogEntry {
            schema_version: ContractVersion::V0_1_0,
            run_id: self.workspace.run_id(),
            sequence: WireInt::new(catalog.metadata.len() as u64)?,
            previous: catalog.previous,
            record,
        };
        let bytes = serde_json::to_vec(&entry).map_err(|_| invalid())?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(budget());
        }
        let digest = Digest::of(&bytes);
        let path = catalog_path(entry.sequence.get(), digest);
        if let Err(error) = self.workspace.write_new(Path::new(&path), &bytes) {
            catalog.failed_write = true;
            return Err(error);
        }
        publish(
            catalog,
            entry.record,
            MetadataSeal {
                path,
                digest,
                length: bytes.len() as u64,
            },
        );
        Ok(())
    }

    fn validate_record(&self, catalog: &Catalog, record: &Record) -> ProofResult<()> {
        if catalog.metadata.contains_key(&record.id()) {
            return Err(integrity());
        }
        match record {
            Record::Artifact {
                artifact,
                body_identity,
            } => {
                capacity(catalog.artifacts.len(), MAX_ARTIFACT_RECORDS)?;
                artifact.validate()?;
                if artifact.relative_path != body_path(artifact.artifact_id)
                    || artifact.length_bytes.get() > MAX_ARTIFACT_BYTES as u64
                    || artifact.length_bytes.get() != body_identity.length
                {
                    return Err(integrity());
                }
                self.verified_artifact(artifact, body_identity)?;
            }
            Record::Snapshot { snapshot } => {
                capacity(catalog.snapshots.len(), MAX_RECORDS)?;
                snapshot.validate()?;
                let body = owned_artifact(catalog, snapshot.project_id, snapshot.body_ref)?;
                self.validate_metadata(catalog, snapshot.body_ref)?;
                if snapshot.sha256 != body.artifact.sha256
                    || snapshot.length_bytes != body.artifact.length_bytes
                {
                    return Err(integrity());
                }
                self.verified_file(body)?;
                if let Some(base_id) = snapshot.derived_from {
                    let base = catalog
                        .snapshots
                        .get(&base_id)
                        .filter(|base| base.project_id == snapshot.project_id)
                        .ok_or_else(denied)?;
                    self.validate_metadata(catalog, base.snapshot_id)?;
                }
            }
            Record::Proposal { proposal } => {
                capacity(catalog.proposals.len(), MAX_RECORDS)?;
                proposal.validate()?;
                for reference in &proposal.evidence_refs {
                    self.validate_reference(catalog, proposal.project_id, reference)?;
                }
            }
        }
        Ok(())
    }

    fn validate_reference(
        &self,
        catalog: &Catalog,
        project_id: EntityId,
        reference: &EvidenceRef,
    ) -> ProofResult<ByteRange> {
        reference.validate()?;
        match reference {
            EvidenceRef::Snapshot {
                snapshot_id,
                revision,
                sha256,
                range,
            } => {
                let snapshot = owned_snapshot(catalog, project_id, *snapshot_id, *revision)?;
                if *sha256 != snapshot.sha256 {
                    return Err(integrity());
                }
                self.validate_metadata(catalog, *snapshot_id)?;
                let body = owned_artifact(catalog, project_id, snapshot.body_ref)?;
                self.validate_metadata(catalog, snapshot.body_ref)?;
                self.verified_file(body)?;
                resolve_range(*range, snapshot.length_bytes)
            }
            EvidenceRef::Artifact {
                artifact_id,
                sha256,
                range,
            } => {
                let artifact = owned_artifact(catalog, project_id, *artifact_id)?;
                if *sha256 != artifact.artifact.sha256 {
                    return Err(integrity());
                }
                self.validate_metadata(catalog, *artifact_id)?;
                self.verified_file(artifact)?;
                resolve_range(*range, artifact.artifact.length_bytes)
            }
        }
    }
}

pub struct SnapshotReader {
    workspace: Arc<OwnedDirectory>,
    snapshot: Arc<Snapshot>,
    file: File,
    relative_path: String,
    identity: FileIdentity,
    _read_lease: Option<Arc<File>>,
}

impl SnapshotReader {
    pub fn metadata(&self) -> &Snapshot {
        &self.snapshot
    }

    pub fn read(&self, offset: WireInt, count: WireInt) -> ProofResult<Vec<u8>> {
        if count.get() > MAX_CHUNK_BYTES as u64 || offset > self.snapshot.length_bytes {
            return Err(invalid());
        }
        let end = offset.checked_add(count)?.min(self.snapshot.length_bytes);
        unchanged(
            &self.workspace,
            &self.relative_path,
            &self.file,
            &self.identity,
        )?;
        let length = usize::try_from(end.checked_sub(offset)?.get()).map_err(|_| invalid())?;
        let mut bytes = vec![0; length];
        self.file
            .read_exact_at(&mut bytes, offset.get())
            .map_err(storage_error)?;
        unchanged(
            &self.workspace,
            &self.relative_path,
            &self.file,
            &self.identity,
        )?;
        Ok(bytes)
    }

    pub fn validate_reference(&self, reference: &EvidenceRef) -> ProofResult<ByteRange> {
        let EvidenceRef::Snapshot {
            snapshot_id,
            revision,
            sha256,
            range,
        } = reference
        else {
            return Err(invalid());
        };
        if *snapshot_id != self.snapshot.snapshot_id {
            return Err(denied());
        }
        if *revision != self.snapshot.revision {
            return Err(stale());
        }
        if *sha256 != self.snapshot.sha256 {
            return Err(integrity());
        }
        unchanged(
            &self.workspace,
            &self.relative_path,
            &self.file,
            &self.identity,
        )?;
        resolve_range(*range, self.snapshot.length_bytes)
    }
}

fn owned_artifact(
    catalog: &Catalog,
    project_id: EntityId,
    id: EntityId,
) -> ProofResult<&StoredArtifact> {
    catalog
        .artifacts
        .get(&id)
        .filter(|stored| stored.artifact.project_id == project_id)
        .ok_or_else(denied)
}

fn owned_snapshot(
    catalog: &Catalog,
    project_id: EntityId,
    id: EntityId,
    revision: WireInt,
) -> ProofResult<&Arc<Snapshot>> {
    let snapshot = catalog
        .snapshots
        .get(&id)
        .filter(|snapshot| snapshot.project_id == project_id)
        .ok_or_else(denied)?;
    if snapshot.revision != revision {
        return Err(stale());
    }
    Ok(snapshot)
}

fn resolve_range(range: Option<EvidenceRange>, length: WireInt) -> ProofResult<ByteRange> {
    let (start, end) = range.map_or((WireInt::ZERO, length), |range| {
        (range.range_start, range.range_end)
    });
    Ok(ByteRange::new(start, end, length)?)
}

fn publish(catalog: &mut Catalog, record: Record, seal: MetadataSeal) {
    let id = record.id();
    match record {
        Record::Artifact {
            artifact,
            body_identity,
        } => {
            catalog.artifacts.insert(
                id,
                StoredArtifact {
                    artifact: Arc::new(artifact),
                    identity: body_identity,
                },
            );
        }
        Record::Snapshot { snapshot } => {
            catalog.snapshots.insert(id, Arc::new(snapshot));
        }
        Record::Proposal { proposal } => {
            catalog.proposals.insert(id, Arc::new(proposal));
        }
    }
    catalog.previous = Some(seal.digest);
    catalog.tail = Some(id);
    catalog.metadata.insert(id, seal);
}

fn verify_stream(file: &mut File, expected: Digest, length: u64) -> ProofResult<()> {
    let before = FileIdentity::read(file)?;
    if before.length != length {
        return Err(integrity());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0; 65_536];
    let mut remaining = length;
    while remaining > 0 {
        let requested = remaining.min(buffer.len() as u64) as usize;
        let count = file.read(&mut buffer[..requested]).map_err(storage_error)?;
        if count == 0 {
            return Err(integrity());
        }
        hasher.update(&buffer[..count]);
        remaining -= count as u64;
    }
    if Digest::from_sha256(hasher.finalize().into()) != expected
        || FileIdentity::read(file)? != before
    {
        return Err(integrity());
    }
    Ok(())
}

fn unchanged(
    workspace: &OwnedDirectory,
    relative: &str,
    file: &File,
    expected: &FileIdentity,
) -> ProofResult<()> {
    if FileIdentity::read(file)? != *expected {
        return Err(integrity());
    }
    // Re-resolve securely to catch parent/path substitutions while the old inode
    // remains alive. This temporary descriptor is closed before returning.
    let named = workspace.open_readonly(Path::new(relative))?;
    if FileIdentity::read(&named)? != *expected {
        return Err(integrity());
    }
    Ok(())
}

fn body_path(id: EntityId) -> String {
    format!("evidence/bodies/{id}.bin")
}
fn catalog_path(sequence: u64, digest: Digest) -> String {
    format!("evidence/catalog/{sequence:05}-{digest}.json")
}

fn open_layout(workspace: &OwnedDirectory, readonly: bool) -> ProofResult<(File, Vec<String>)> {
    let root = workspace.lock_directory()?;
    let created = if readonly {
        false
    } else {
        match fs::mkdirat(&root, "evidence", Mode::RWXU) {
            Ok(()) => true,
            Err(Errno::EXIST) => false,
            Err(error) => return Err(storage_error(error)),
        }
    };
    let directory = open_directory(&root, "evidence")?;
    let access = if readonly {
        OFlags::RDONLY
    } else {
        OFlags::RDWR
    };
    let flags = access | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let writer = File::from(
        fs::openat(
            &directory,
            ".writer",
            if created {
                flags | OFlags::CREATE | OFlags::EXCL
            } else {
                flags
            },
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(storage_error)?,
    );
    FileIdentity::read(&writer)?;
    fs::flock(
        &writer,
        if readonly {
            FlockOperation::NonBlockingLockShared
        } else {
            FlockOperation::NonBlockingLockExclusive
        },
    )
    .map_err(storage_error)?;
    if created {
        for name in ["catalog", "bodies"] {
            fs::mkdirat(&directory, name, Mode::RWXU).map_err(storage_error)?;
        }
        let header = StoreHeader {
            schema_version: ContractVersion::V0_1_0,
            run_id: workspace.run_id(),
        };
        let bytes = serde_json::to_vec(&header).map_err(|_| integrity())?;
        let mut file = File::from(
            fs::openat(
                &directory,
                "store.json",
                flags | OFlags::CREATE | OFlags::EXCL,
                Mode::RUSR | Mode::WUSR,
            )
            .map_err(storage_error)?,
        );
        FileIdentity::read(&file)?;
        file.write_all(&bytes).map_err(storage_error)?;
        file.sync_all().map_err(storage_error)?;
        writer.sync_all().map_err(storage_error)?;
        directory.sync_all().map_err(storage_error)?;
        root.sync_all().map_err(storage_error)?;
    }
    let catalog = open_directory(&directory, "catalog")?;
    let bodies = open_directory(&directory, "bodies")?;
    if created {
        catalog.sync_all().map_err(storage_error)?;
        bodies.sync_all().map_err(storage_error)?;
    }
    let mut paths = Vec::new();
    for entry in Dir::read_from(&catalog).map_err(storage_error)? {
        let entry = entry.map_err(storage_error)?;
        let name = entry.file_name();
        if name == c"." || name == c".." {
            continue;
        }
        let name = name.to_str().map_err(|_| integrity())?;
        if paths.len() >= MAX_CATALOG_ENTRIES || name.len() != 75 || !name.ends_with(".json") {
            return Err(integrity());
        }
        paths.push(format!("evidence/catalog/{name}"));
    }
    paths.sort_unstable();
    drop(root);
    let bytes = workspace.read(Path::new("evidence/store.json"), 1024)?;
    let header: StoreHeader = serde_json::from_slice(&bytes).map_err(|_| integrity())?;
    if header.run_id != workspace.run_id()
        || header.schema_version != ContractVersion::V0_1_0
        || serde_json::to_vec(&header).map_err(|_| integrity())? != bytes
    {
        return Err(integrity());
    }
    Ok((writer, paths))
}

fn open_directory(parent: &File, name: &str) -> ProofResult<File> {
    let file = File::from(
        fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(storage_error)?,
    );
    let stat = fs::fstat(&file).map_err(storage_error)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || u32::from(stat.st_mode) & 0o7777 != 0o700
    {
        return Err(denied());
    }
    Ok(file)
}

fn capacity(count: usize, limit: usize) -> ProofResult<()> {
    if count >= limit {
        return Err(budget());
    }
    Ok(())
}
fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "Invalid evidence record or byte range",
    )
}
fn denied() -> ProofError {
    ProofError::new(
        ErrorCode::PermissionDenied,
        "Evidence is not private storage owned by this context",
    )
}
fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Immutable evidence integrity check failed",
    )
}
fn budget() -> ProofError {
    ProofError::new(
        ErrorCode::BudgetExhausted,
        "Evidence exceeds its finite storage or read limit",
    )
}
fn stale() -> ProofError {
    ProofError::new(ErrorCode::StaleSnapshot, "The snapshot revision is stale")
}
fn storage_error<E>(_: E) -> ProofError {
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Evidence filesystem operation failed",
    )
}
