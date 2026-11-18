//! Private run storage. All untrusted descendants are resolved one component at a time
//! through directory descriptors; a pathname is never used as the authority for an I/O operation.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{self, AtFlags, Dir, FileType, FlockOperation, Mode, OFlags, RenameFlags, Stat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use crate::domain::values::{ContractVersion, Digest, EntityId};
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

const MARKER: &str = ".razen-run.json";
const MAX_MARKER_BYTES: usize = 1024;
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RunMarker {
    version: ContractVersion,
    run_id: EntityId,
    uid: u32,
}

/// A handle is bound both to the original directory inode and its recorded run identity.
/// The trusted base descriptor also lets each operation reject a replaced or moved run path.
pub struct OwnedDirectory {
    base: File,
    relative: PathBuf,
    path: PathBuf,
    directory: File,
    run_id: EntityId,
    uid: u32,
}

impl OwnedDirectory {
    pub fn create(base: &Path, relative: &Path, run_id: EntityId) -> ProofResult<Self> {
        validate_relative(relative)?;
        let uid = rustix::process::geteuid().as_raw();
        let base_file = trusted_base(base)?;
        let (parents, name) = parent_and_name(relative)?;
        let parent = walk(&base_file, parents, true, uid)?;
        // No adoption of preexisting output, including an already valid run directory.
        fs::mkdirat(&parent, name, Mode::RWXU).map_err(io_error)?;
        let directory = open_directory(&parent, name, uid)?;
        let marker = RunMarker {
            version: ContractVersion::V0_1_0,
            run_id,
            uid,
        };
        let bytes = serde_json::to_vec(&marker).map_err(|_| integrity_error())?;
        let mut marker_file = create_file(&directory, OsStr::new(MARKER), uid)?;
        marker_file.write_all(&bytes).map_err(io_error)?;
        marker_file.sync_all().map_err(io_error)?;
        directory.sync_all().map_err(io_error)?;
        parent.sync_all().map_err(io_error)?;
        Ok(Self {
            base: base_file,
            relative: relative.to_path_buf(),
            path: base.join(relative),
            directory,
            run_id,
            uid,
        })
    }

    pub fn open(base: &Path, relative: &Path) -> ProofResult<Self> {
        validate_relative(relative)?;
        let uid = rustix::process::geteuid().as_raw();
        let base_file = trusted_base(base)?;
        let directory = walk(&base_file, relative, false, uid)?;
        let marker = read_marker(&directory, uid)?;
        Ok(Self {
            base: base_file,
            relative: relative.to_path_buf(),
            path: base.join(relative),
            directory,
            run_id: marker.run_id,
            uid,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn run_id(&self) -> EntityId {
        self.run_id
    }

    pub fn write_new(&self, relative: &Path, bytes: &[u8]) -> ProofResult<Digest> {
        validate_relative(relative)?;
        let guard = self.lock_directory()?;
        let (parents, name) = parent_and_name(relative)?;
        let parent = walk(&guard, parents, true, self.uid)?;
        let mut file = create_file(&parent, name, self.uid)?;
        // On failure, retain the partial private file rather than hiding the failed write
        // or making an immutable artifact appear safe to overwrite on a subsequent call.
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        parent.sync_all().map_err(io_error)?;
        Ok(Digest::of(bytes))
    }

    pub fn atomic_write(&self, relative: &Path, bytes: &[u8]) -> ProofResult<Digest> {
        validate_relative(relative)?;
        if !mutable_metadata(relative) {
            return Err(permission_error());
        }
        let guard = self.lock_directory()?;
        let (parents, name) = parent_and_name(relative)?;
        let parent = walk(&guard, parents, true, self.uid)?;
        let previous = replacement_target(&parent, name, self.uid)?;
        let temporary = format!(".razen-tmp-{}", EntityId::new());
        let temporary = OsStr::new(&temporary);
        let mut file = create_file(&parent, temporary, self.uid)?;
        // Failed staging files are intentionally retained as private failure evidence.
        file.write_all(bytes).map_err(io_error)?;
        file.sync_all().map_err(io_error)?;
        let current = replacement_target(&parent, name, self.uid)?;
        if !same_optional_object(previous.as_ref(), current.as_ref()) {
            return Err(integrity_error());
        }
        if previous.is_some() {
            fs::renameat(&parent, temporary, &parent, name).map_err(io_error)?;
        } else {
            fs::renameat_with(&parent, temporary, &parent, name, RenameFlags::NOREPLACE)
                .map_err(io_error)?;
        }
        parent.sync_all().map_err(io_error)?;
        Ok(Digest::of(bytes))
    }

    pub fn read(&self, relative: &Path, max_bytes: usize) -> ProofResult<Vec<u8>> {
        validate_relative(relative)?;
        let guard = self.lock_directory()?;
        let (parents, name) = parent_and_name(relative)?;
        let parent = walk(&guard, parents, false, self.uid)?;
        let file = open_regular_file(&parent, name, self.uid)?;
        bounded_read(file, max_bytes)
    }

    /// Open one owned immutable file for bounded streaming without retaining the directory lock.
    pub(crate) fn open_readonly(&self, relative: &Path) -> ProofResult<File> {
        validate_relative(relative)?;
        let guard = self.lock_directory()?;
        let (parents, name) = parent_and_name(relative)?;
        let parent = walk(&guard, parents, false, self.uid)?;
        open_regular_file(&parent, name, self.uid)
    }

    pub fn cleanup_ephemeral(&self) -> ProofResult<()> {
        let guard = self.lock_directory()?;
        match fs::statat(&guard, "ephemeral", AtFlags::SYMLINK_NOFOLLOW) {
            Err(Errno::NOENT) => return Ok(()),
            Err(error) => return Err(io_error(error)),
            Ok(_) => {}
        }
        let ephemeral = open_directory(&guard, OsStr::new("ephemeral"), self.uid)?;
        // Reject unsafe descendants before deleting anything. The destructive pass also
        // checks every entry again; neither pass follows links or crosses a directory fd.
        visit_ephemeral(&ephemeral, self.uid, false)?;
        self.validate_identity(&guard)?;
        visit_ephemeral(&ephemeral, self.uid, true)?;
        ephemeral.sync_all().map_err(io_error)?;
        guard.sync_all().map_err(io_error)?;
        Ok(())
    }

    /// Native directory identity, not a content hash or standalone authority token.
    pub(crate) fn identity_digest(&self) -> ProofResult<Digest> {
        let guard = self.lock_directory()?;
        let stat = fs::fstat(&guard).map_err(io_error)?;
        let device = stat.st_dev.to_le_bytes();
        let inode = stat.st_ino.to_le_bytes();
        let mut identity = [0_u8; 16];
        identity[..device.len()].copy_from_slice(&device);
        identity[8..8 + inode.len()].copy_from_slice(&inode);
        Ok(Digest::of(&identity))
    }

    /// Remove a freshly owned auxiliary workspace only when it contains its
    /// marker and, optionally, an empty ephemeral directory. Never recurse.
    pub(crate) fn remove_empty(&self) -> ProofResult<()> {
        let guard = self.lock_directory()?;
        let marker = open_regular_file(&guard, OsStr::new(MARKER), self.uid)?;
        let marker_identity = fs::fstat(&marker).map_err(io_error)?;
        let mut ephemeral = None;
        let mut entries = Dir::read_from(&guard).map_err(io_error)?;
        for entry in &mut entries {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            if name == c"." || name == c".." || name.to_bytes() == MARKER.as_bytes() {
                continue;
            }
            if name != c"ephemeral" {
                return Err(permission_error());
            }
            let directory = open_directory(&guard, OsStr::new("ephemeral"), self.uid)?;
            if !directory_is_empty(&directory)? {
                return Err(permission_error());
            }
            ephemeral = Some(directory);
        }
        self.validate_identity(&guard)?;
        if let Some(directory) = ephemeral {
            let named =
                fs::statat(&guard, "ephemeral", AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
            if !same_object(&named, &fs::fstat(&directory).map_err(io_error)?) {
                return Err(integrity_error());
            }
            fs::unlinkat(&guard, "ephemeral", AtFlags::REMOVEDIR).map_err(io_error)?;
        }
        let named = fs::statat(&guard, MARKER, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
        if !same_object(&named, &marker_identity) {
            return Err(integrity_error());
        }
        fs::unlinkat(&guard, MARKER, AtFlags::empty()).map_err(io_error)?;
        guard.sync_all().map_err(io_error)?;
        let (parents, name) = parent_and_name(&self.relative)?;
        let parent = walk(&self.base, parents, false, self.uid)?;
        let named = fs::statat(&parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
        if !same_object(&named, &fs::fstat(&guard).map_err(io_error)?) {
            return Err(integrity_error());
        }
        fs::unlinkat(&parent, name, AtFlags::REMOVEDIR).map_err(io_error)?;
        parent.sync_all().map_err(io_error)
    }

    pub(crate) fn lock_directory(&self) -> ProofResult<File> {
        // Opening "." gives each call an independent open-file description, so flock
        // serializes even concurrent calls through this same Rust handle. Closing the
        // returned guard releases the lock, including on an error path.
        let guard = open_directory(&self.directory, OsStr::new("."), self.uid)?;
        fs::flock(&guard, FlockOperation::LockExclusive).map_err(io_error)?;
        self.validate_identity(&guard)?;
        Ok(guard)
    }

    fn validate_identity(&self, guard: &File) -> ProofResult<()> {
        validate_directory(&fs::fstat(guard).map_err(io_error)?, self.uid)?;
        if rustix::process::geteuid().as_raw() != self.uid {
            return Err(permission_error());
        }
        let named = walk(&self.base, &self.relative, false, self.uid)?;
        if !same_object(
            &fs::fstat(guard).map_err(io_error)?,
            &fs::fstat(&named).map_err(io_error)?,
        ) {
            return Err(integrity_error());
        }
        if read_marker(guard, self.uid)?.run_id != self.run_id {
            return Err(integrity_error());
        }
        Ok(())
    }
}

fn directory_is_empty(directory: &File) -> ProofResult<bool> {
    let mut entries = Dir::read_from(directory).map_err(io_error)?;
    for entry in &mut entries {
        let entry = entry.map_err(io_error)?;
        if entry.file_name() != c"." && entry.file_name() != c".." {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_relative(path: &Path) -> ProofResult<()> {
    // Path::components normalizes interior '.' and repeated separators, so validate
    // the original bytes before using any normalized path operations.
    let bytes = path.as_os_str().as_bytes();
    if bytes.contains(&0)
        || bytes
            .split(|byte| *byte == b'/')
            .any(|part| part.is_empty() || part == b"." || part == b"..")
    {
        return Err(ProofError::new(
            ErrorCode::InvalidInput,
            "Invalid relative workspace path",
        ));
    }
    Ok(())
}

fn parent_and_name(path: &Path) -> ProofResult<(&Path, &OsStr)> {
    match (path.parent(), path.file_name()) {
        (Some(parent), Some(name)) => Ok((parent, name)),
        _ => Err(ProofError::new(
            ErrorCode::InvalidInput,
            "Invalid relative workspace path",
        )),
    }
}

fn trusted_base(path: &Path) -> ProofResult<File> {
    let file = File::open(path).map_err(io_error)?;
    if FileType::from_raw_mode(fs::fstat(&file).map_err(io_error)?.st_mode) != FileType::Directory {
        return Err(permission_error());
    }
    Ok(file)
}

fn walk(start: &File, relative: &Path, create: bool, uid: u32) -> ProofResult<File> {
    // The starting descriptor may be the explicitly trusted base, whose permissions
    // need not be private. Every named descendant, however, must be private and owned.
    let mut current =
        File::from(fs::openat(start, ".", DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?);
    for component in relative.components() {
        let Component::Normal(name) = component else {
            return Err(permission_error());
        };
        let mut created = false;
        if create {
            match fs::mkdirat(&current, name, Mode::RWXU) {
                Ok(()) => created = true,
                Err(Errno::EXIST) => {}
                Err(error) => return Err(io_error(error)),
            }
        }
        let next = open_directory(&current, name, uid)?;
        if created {
            next.sync_all().map_err(io_error)?;
            current.sync_all().map_err(io_error)?;
        }
        current = next;
    }
    Ok(current)
}

fn open_directory(parent: &File, name: &OsStr, uid: u32) -> ProofResult<File> {
    let file =
        File::from(fs::openat(parent, name, DIRECTORY_FLAGS, Mode::empty()).map_err(io_error)?);
    validate_directory(&fs::fstat(&file).map_err(io_error)?, uid)?;
    Ok(file)
}

fn validate_directory(stat: &Stat, uid: u32) -> ProofResult<()> {
    validate_permissions(stat, uid, 0o700)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        return Err(permission_error());
    }
    Ok(())
}

fn validate_permissions(stat: &Stat, uid: u32, mode: u32) -> ProofResult<()> {
    if stat.st_uid != uid || u32::from(stat.st_mode) & 0o7777 != mode {
        return Err(permission_error());
    }
    Ok(())
}

fn validate_regular_file(stat: &Stat, uid: u32) -> ProofResult<()> {
    validate_permissions(stat, uid, 0o600)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile || stat.st_nlink != 1 {
        return Err(permission_error());
    }
    Ok(())
}

fn create_file(parent: &File, name: &OsStr, uid: u32) -> ProofResult<File> {
    let flags = OFlags::WRONLY
        | OFlags::CREATE
        | OFlags::EXCL
        | OFlags::NOFOLLOW
        | OFlags::CLOEXEC
        | OFlags::NONBLOCK;
    let file =
        File::from(fs::openat(parent, name, flags, Mode::RUSR | Mode::WUSR).map_err(io_error)?);
    validate_regular_file(&fs::fstat(&file).map_err(io_error)?, uid)?;
    Ok(file)
}

fn open_regular_file(parent: &File, name: &OsStr, uid: u32) -> ProofResult<File> {
    let file = File::from(fs::openat(parent, name, READ_FLAGS, Mode::empty()).map_err(io_error)?);
    validate_regular_file(&fs::fstat(&file).map_err(io_error)?, uid)?;
    Ok(file)
}

fn bounded_read(file: File, max_bytes: usize) -> ProofResult<Vec<u8>> {
    let stat = fs::fstat(&file).map_err(io_error)?;
    let length = usize::try_from(stat.st_size).map_err(|_| integrity_error())?;
    if length > max_bytes {
        return Err(ProofError::new(
            ErrorCode::OutputInvalid,
            "Workspace file exceeds read limit",
        ));
    }
    let mut bytes = Vec::with_capacity(length);
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > max_bytes {
        return Err(ProofError::new(
            ErrorCode::OutputInvalid,
            "Workspace file exceeds read limit",
        ));
    }
    Ok(bytes)
}

fn read_marker(directory: &File, uid: u32) -> ProofResult<RunMarker> {
    let file = open_regular_file(directory, OsStr::new(MARKER), uid)?;
    let bytes = bounded_read(file, MAX_MARKER_BYTES)?;
    let marker: RunMarker = serde_json::from_slice(&bytes).map_err(|_| integrity_error())?;
    if marker.uid != uid {
        return Err(permission_error());
    }
    Ok(marker)
}

fn mutable_metadata(path: &Path) -> bool {
    let bytes = path.as_os_str().as_bytes();
    bytes.starts_with(b"ephemeral/")
        || matches!(
            bytes,
            b"run.json" | b"results.json" | b"exit.json" | b"review.json"
        )
}

fn replacement_target(parent: &File, name: &OsStr, uid: u32) -> ProofResult<Option<Stat>> {
    match fs::statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            validate_regular_file(&stat, uid)?;
            Ok(Some(stat))
        }
        Err(Errno::NOENT) => Ok(None),
        Err(error) => Err(io_error(error)),
    }
}

fn same_object(left: &Stat, right: &Stat) -> bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

fn same_optional_object(left: Option<&Stat>, right: Option<&Stat>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => same_object(left, right),
        _ => false,
    }
}

struct CleanupFrame {
    directory: File,
    entries: Dir,
    name: Option<CString>,
}

impl CleanupFrame {
    fn new(directory: File, name: Option<CString>) -> ProofResult<Self> {
        let entries = Dir::read_from(&directory).map_err(io_error)?;
        Ok(Self {
            directory,
            entries,
            name,
        })
    }
}

fn visit_ephemeral(directory: &File, uid: u32, remove: bool) -> ProofResult<()> {
    // An explicit stack avoids host-stack exhaustion for deeply nested owned input.
    let root = open_directory(directory, OsStr::new("."), uid)?;
    let mut stack = vec![CleanupFrame::new(root, None)?];
    while let Some(frame) = stack.last_mut() {
        if let Some(entry) = frame.entries.next() {
            let entry = entry.map_err(io_error)?;
            let name = entry.file_name();
            if name == c"." || name == c".." {
                continue;
            }
            let stat =
                fs::statat(&frame.directory, name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_error)?;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Directory => {
                    let child =
                        open_directory(&frame.directory, OsStr::from_bytes(name.to_bytes()), uid)?;
                    if !same_object(&stat, &fs::fstat(&child).map_err(io_error)?) {
                        return Err(integrity_error());
                    }
                    stack.push(CleanupFrame::new(child, Some(name.to_owned()))?);
                }
                FileType::RegularFile | FileType::Socket => {
                    validate_permissions(&stat, uid, 0o600)?;
                    if stat.st_nlink != 1 {
                        return Err(permission_error());
                    }
                    if remove {
                        fs::unlinkat(&frame.directory, name, AtFlags::empty()).map_err(io_error)?;
                    }
                }
                _ => return Err(permission_error()),
            }
            continue;
        }
        let finished = stack.pop().ok_or_else(integrity_error)?;
        if remove {
            finished.directory.sync_all().map_err(io_error)?;
            if let (Some(parent), Some(name)) = (stack.last(), finished.name.as_deref()) {
                remove_empty_directory(&parent.directory, name)?;
            }
        }
    }
    Ok(())
}

fn remove_empty_directory(parent: &File, name: &CStr) -> ProofResult<()> {
    fs::unlinkat(parent, name, AtFlags::REMOVEDIR).map_err(io_error)?;
    parent.sync_all().map_err(io_error)
}

fn permission_error() -> ProofError {
    ProofError::new(
        ErrorCode::PermissionDenied,
        "Workspace entry is not private owned storage",
    )
}

fn integrity_error() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Workspace ownership or identity is invalid",
    )
}

fn io_error<E>(_: E) -> ProofError {
    ProofError::new(
        ErrorCode::OutputInvalid,
        "Workspace filesystem operation failed",
    )
}
