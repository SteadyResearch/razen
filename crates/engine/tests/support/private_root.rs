use std::fs::{self, DirBuilder};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::thread;

use uuid::Uuid;

/// A private directory created by this test alone, never a shared cleanup target.
pub struct PrivateRoot {
    path: PathBuf,
}

impl PrivateRoot {
    pub fn new() -> Self {
        let mut path = fs::canonicalize("/tmp").expect("resolve short Unix socket-safe test root");
        path.push(format!("razen-foundation-{}", Uuid::new_v4()));
        DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("create unique private test root");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for PrivateRoot {
    fn drop(&mut self) {
        let result = fs::remove_dir_all(&self.path);
        if !thread::panicking() {
            result.expect("remove only this test's private root");
        }
    }
}
