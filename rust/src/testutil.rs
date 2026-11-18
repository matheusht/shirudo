// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the crate's tests share: a directory of a test's own, the files
//! of testing/ in the tree, and a lock for a test that changes what every
//! thread of the process sees.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

/// A directory of the test's own, mode 0700, removed with what it holds
/// when it goes.
pub(crate) struct TempDir(PathBuf);

impl TempDir {
    pub(crate) fn new() -> Self {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "shirudo-unit-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));

        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .expect("a scratch directory");
        TempDir(path)
    }

    /// `name` in the directory, the directory itself for "".
    pub(crate) fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    /// `name` in the directory, as the C string a function of the C's
    /// shape takes.
    pub(crate) fn cpath(&self, name: &str) -> CString {
        CString::new(self.join(name).as_os_str().as_bytes()).expect("a path without a NUL")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The file `rel` of testing/ in the tree the crate is built from.
pub(crate) fn testing_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../testing")
        .join(rel)
}

/// Held by a test that changes the process, its standard error say, so
/// that no other such test runs meanwhile on a thread of its own.
pub(crate) fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}
