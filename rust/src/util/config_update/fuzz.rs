// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-config-update: a journal record decoded, as the state and as an
//! event, and the journal's events scanned whole and partial.

use std::ffi::{CString, OsStr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::OnceLock;

use super::{ConfigUpdate, ConfigUpdateRecord, events_scan, record_decode};
use crate::fuzzing::fuzz_target;

/// The journal directory the events are written to, removed at exit.
static DIR: OnceLock<(CString, OwnedFd)> = OnceLock::new();

extern "C" fn remove_dir() {
    if let Some((dir, _)) = DIR.get() {
        let _ = std::fs::remove_dir_all(OsStr::from_bytes(dir.to_bytes()));
    }
}

fn init() {
    let tmp = std::env::var("TMPDIR")
        .ok()
        .filter(|t| !t.is_empty())
        .unwrap_or_else(|| "/tmp".into());
    let Ok(template) = CString::new(format!("{tmp}/shirudo-fuzz-config-update-XXXXXX")) else {
        std::process::abort();
    };
    let mut template = template.into_bytes_with_nul();
    // SAFETY: a template mkdtemp() fills in place, and a handler of no
    // arguments.
    unsafe {
        if libc::mkdtemp(template.as_mut_ptr().cast()).is_null() || libc::atexit(remove_dir) != 0 {
            std::process::abort();
        }
    }
    let dir = CString::from_vec_with_nul(template).unwrap_or_default();
    let Ok(fd) = std::fs::File::open(OsStr::from_bytes(dir.to_bytes())) else {
        std::process::abort();
    };
    let _ = DIR.set((dir, fd.into()));
}

fuzz_target!(
    shirudo_fuzz_config_update,
    shirudo_fuzz_config_update_init,
    |data| {
        let Some((dir, dir_fd)) = DIR.get() else {
            return;
        };
        let mut record = ConfigUpdateRecord::zeroed();
        // SAFETY: the input's bytes and room for the record.
        unsafe {
            record_decode(data.as_ptr(), data.len(), true, &mut record);
            record_decode(data.as_ptr(), data.len(), false, &mut record);
        }
        let events = std::path::Path::new(OsStr::from_bytes(dir.to_bytes())).join("events");
        if std::fs::write(events, data).is_err() {
            return;
        }
        let mut update = ConfigUpdate::closed();
        update.dir_fd = dir_fd.as_raw_fd();
        let mut last = ConfigUpdateRecord::zeroed();
        let mut value = [0u8; 32];
        // SAFETY: the journal over the directory, which it does not own,
        // and rooms for the last record and the value.
        unsafe {
            for partial in [false, true] {
                events_scan(
                    &update,
                    &mut last,
                    value.as_mut_ptr(),
                    core::ptr::null_mut(),
                    partial,
                    None,
                    core::ptr::null_mut(),
                );
            }
        }
    },
    init
);
