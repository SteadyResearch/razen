//! Native immutable source identity shared by trusted process entry points.
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::time::{Duration, Instant};

use sha2::{Digest as _, Sha256};

use crate::domain::values::Digest;
use crate::protocol::error::{ErrorCode, ProofError, ProofResult};

pub(crate) fn executable_digest() -> ProofResult<Digest> {
    let path = std::env::current_exe().map_err(|_| integrity())?;
    let mut file = File::open(&path).map_err(|_| integrity())?;
    let before = file.metadata().map_err(|_| integrity())?;
    if !before.is_file() || before.len() > 1024 * 1024 * 1024 {
        return Err(integrity());
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut hash = Sha256::new();
    let mut chunk = [0; 16 * 1024];
    let mut total = 0_u64;
    loop {
        if Instant::now() >= deadline {
            return Err(ProofError::new(
                ErrorCode::Timeout,
                "Executable hashing deadline exceeded",
            ));
        }
        let count = file.read(&mut chunk).map_err(|_| integrity())?;
        if count == 0 {
            break;
        }
        total = total.checked_add(count as u64).ok_or_else(integrity)?;
        if total > before.len() {
            return Err(integrity());
        }
        hash.update(&chunk[..count]);
    }
    let after = file.metadata().map_err(|_| integrity())?;
    let named = File::open(path)
        .and_then(|file| file.metadata())
        .map_err(|_| integrity())?;
    if total != before.len() || !same_file(&before, &after) || !same_file(&before, &named) {
        return Err(integrity());
    }
    Ok(Digest::from_sha256(hash.finalize().into()))
}

pub(crate) fn same_file(first: &Metadata, second: &Metadata) -> bool {
    first.dev() == second.dev()
        && first.ino() == second.ino()
        && first.len() == second.len()
        && first.mode() == second.mode()
        && first.uid() == second.uid()
        && first.nlink() == second.nlink()
        && first.mtime() == second.mtime()
        && first.mtime_nsec() == second.mtime_nsec()
        && first.ctime() == second.ctime()
        && first.ctime_nsec() == second.ctime_nsec()
}

fn integrity() -> ProofError {
    ProofError::new(
        ErrorCode::IntegrityError,
        "Native immutable source identity is invalid",
    )
}
