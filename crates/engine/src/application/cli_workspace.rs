//! CLI path policy: reviewed source files and explicitly selected owned run roots.
use std::borrow::Cow;
use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use rustix::fs::{self, FileType, Mode, OFlags};

use crate::adapters::native_files::same_file;
use crate::adapters::workspace::OwnedDirectory;
use crate::domain::values::EntityId;
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

pub(crate) const PROFILE: &str = "specs/001-r0-feasibility/contracts/pilot-profile.json";
pub(crate) const SCENARIOS: &str = "fixtures/scenarios/manifest.json";
pub(crate) const EXAMPLES: &str = "fixtures/scenarios/contracts.json";
const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);
const READ_FLAGS: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);

pub(crate) fn create(repo: &Path, path: &Path, run_id: EntityId) -> ProofResult<OwnedDirectory> {
    let full = absolute(repo, path)?;
    let parent = full.parent().ok_or_else(invalid)?;
    let name = full.file_name().ok_or_else(invalid)?;
    let _parent = directory(parent, true)?;
    OwnedDirectory::create(parent, Path::new(name), run_id)
}

pub(crate) fn open(repo: &Path, path: &Path) -> ProofResult<OwnedDirectory> {
    let full = absolute(repo, path)?;
    let parent = full.parent().ok_or_else(invalid)?;
    let name = full.file_name().ok_or_else(invalid)?;
    let _parent = directory(parent, false)?;
    OwnedDirectory::open(parent, Path::new(name))
}

pub(crate) fn profile(repo: &Path, requested: &Path, max_bytes: usize) -> ProofResult<Vec<u8>> {
    if absolute(repo, requested)?.as_ref() != repo.join(PROFILE) {
        return Err(invalid());
    }
    reviewed(repo, Path::new(PROFILE), max_bytes)
}

pub(crate) fn reviewed(repo: &Path, relative: &Path, max_bytes: usize) -> ProofResult<Vec<u8>> {
    lexical(relative)?;
    if relative.is_absolute() || max_bytes > 4 * 1024 * 1024 {
        return Err(invalid());
    }
    let full = repo.join(relative);
    let parent = directory(full.parent().ok_or_else(invalid)?, false)?;
    read_source(&parent, full.file_name().ok_or_else(invalid)?, max_bytes)
}

fn absolute<'a>(repo: &Path, path: &'a Path) -> ProofResult<Cow<'a, Path>> {
    lexical(path)?;
    if !repo.is_absolute() {
        return Err(invalid());
    }
    Ok(if path.is_absolute() {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(repo.join(path))
    })
}

fn lexical(path: &Path) -> ProofResult<()> {
    let bytes = path.as_os_str().as_encoded_bytes();
    if bytes.is_empty()
        || bytes.len() > 4096
        || bytes.contains(&0)
        || bytes
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b"..")
    {
        return Err(invalid());
    }
    Ok(())
}

fn directory(path: &Path, create: bool) -> ProofResult<File> {
    if !path.is_absolute() {
        return Err(invalid());
    }
    let mut current = File::from(
        fs::open(Path::new("/"), DIRECTORY_FLAGS, Mode::empty()).map_err(|_| invalid())?,
    );
    let uid = rustix::process::geteuid().as_raw();
    for component in path.components() {
        let name = match component {
            Component::RootDir => continue,
            Component::Normal(name) => name,
            _ => return Err(invalid()),
        };
        let opened = match fs::openat(&current, name, DIRECTORY_FLAGS, Mode::empty()) {
            Ok(directory) => directory,
            Err(rustix::io::Errno::NOENT) if create => {
                match fs::mkdirat(&current, name, Mode::RWXU) {
                    Ok(()) => current.sync_all().map_err(|_| invalid())?,
                    Err(rustix::io::Errno::EXIST) => {}
                    Err(_) => return Err(invalid()),
                }
                fs::openat(&current, name, DIRECTORY_FLAGS, Mode::empty()).map_err(|_| invalid())?
            }
            Err(_) => return Err(invalid()),
        };
        let stat = fs::fstat(&opened).map_err(|_| invalid())?;
        let mode = u32::from(stat.st_mode);
        if FileType::from_raw_mode(stat.st_mode) != FileType::Directory
            || (stat.st_uid != uid && stat.st_uid != 0)
            || (mode & 0o022 != 0 && mode & 0o1000 == 0)
        {
            return Err(invalid());
        }
        current = File::from(opened);
    }
    Ok(current)
}

fn read_source(parent: &File, name: &OsStr, max_bytes: usize) -> ProofResult<Vec<u8>> {
    let mut file =
        File::from(fs::openat(parent, name, READ_FLAGS, Mode::empty()).map_err(|_| invalid())?);
    let before = file.metadata().map_err(|_| invalid())?;
    if !before.is_file()
        || before.uid() != rustix::process::geteuid().as_raw()
        || before.nlink() != 1
        || before.mode() & 0o022 != 0
        || before.len() > max_bytes as u64
    {
        return Err(invalid());
    }
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&mut file)
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let after = file.metadata().map_err(|_| invalid())?;
    let named =
        File::from(fs::openat(parent, name, READ_FLAGS, Mode::empty()).map_err(|_| invalid())?)
            .metadata()
            .map_err(|_| invalid())?;
    if bytes.len() as u64 != before.len()
        || !same_file(&before, &after)
        || !same_file(&before, &named)
    {
        return Err(invalid());
    }
    Ok(bytes)
}

fn invalid() -> ProofError {
    ProofError::new(
        ErrorCode::InvalidInput,
        "CLI path is not a reviewed source or safely owned run location",
    )
}
