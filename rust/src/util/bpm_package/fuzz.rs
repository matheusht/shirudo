// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-bpm-tar: the Beefile read from a package's gzip tar;
//! fuzz-bpm-index: a package index parsed, its versions in an order
//! install can pick the newest by; fuzz-bpm-package: a package's
//! identity read and its files extracted.

use core::ffi::c_char;
use std::path::PathBuf;
use std::sync::OnceLock;

use super::capi::{bpm_index_parse, bpm_pkg_extract, bpm_pkg_load_info, bpm_pkg_read_member_in};
use super::{IndexEntry, PackageInfo};
use crate::fuzzing::{fuzz_target, input_gzip_file};
use crate::heap::xfree;
use crate::text::cstr;
use crate::util::bpm_oci::MAX_ENTRIES;

fuzz_target!(shirudo_fuzz_bpm_tar, shirudo_fuzz_bpm_tar_init, |data| {
    let Some(input) = input_gzip_file(data) else {
        return;
    };
    let mut dir = [0 as c_char; 256];
    let (mut body, mut len): (*mut u8, usize) = (core::ptr::null_mut(), 0);
    // SAFETY: C strings, no package directory, room for the one found and
    // for the member, freed after.
    unsafe {
        let ret = bpm_pkg_read_member_in(
            input.path.as_ptr(),
            c"Beefile".as_ptr(),
            core::ptr::null(),
            dir.as_mut_ptr(),
            dir.len(),
            &mut body,
            &mut len,
            1 << 20,
        );
        if ret == 0 {
            xfree(body.cast(), len + 1);
        }
    }
});

fuzz_target!(
    shirudo_fuzz_bpm_index,
    shirudo_fuzz_bpm_index_init,
    |data| {
        let mut entries = vec![IndexEntry::new(); MAX_ENTRIES];
        let mut n = 0;
        // SAFETY: the input, room for MAX_ENTRIES entries and their count.
        if unsafe { bpm_index_parse(data.as_ptr(), data.len(), entries.as_mut_ptr(), &mut n) } != 0
        {
            return;
        }
        // install picks the newest version by this order: it must be one.
        for w in entries[..n as usize].windows(2) {
            let ab = super::semver_compare(cstr(&w[0].version), cstr(&w[1].version));
            let ba = super::semver_compare(cstr(&w[1].version), cstr(&w[0].version));
            if ab.signum() != -ba.signum() {
                std::process::abort();
            }
        }
    }
);

/// The directory the packages extract into, removed at exit.
static BASE: OnceLock<PathBuf> = OnceLock::new();

extern "C" fn remove_base() {
    if let Some(base) = BASE.get() {
        let _ = std::fs::remove_dir_all(base);
    }
}

fn package_init() {
    let mut template = *b"/tmp/shirudo-fuzz-bpm-package-XXXXXX\0";
    // SAFETY: a template mkdtemp() fills in place, and a handler of no
    // arguments.
    unsafe {
        if libc::mkdtemp(template.as_mut_ptr().cast()).is_null() || libc::atexit(remove_base) != 0 {
            std::process::abort();
        }
    }
    let base = String::from_utf8_lossy(cstr(&template)).into_owned();
    let _ = BASE.set(PathBuf::from(base));
}

fuzz_target!(
    shirudo_fuzz_bpm_package,
    shirudo_fuzz_bpm_package_init,
    |data| {
        let (Some(base), Some(input)) = (BASE.get(), input_gzip_file(data)) else {
            return;
        };
        let Ok(dest) = std::ffi::CString::new(format!("{}/pkg", base.display())) else {
            return;
        };
        // SAFETY: an identity of nothing, for which zeros are the value.
        let mut info: PackageInfo = unsafe { core::mem::zeroed() };
        // SAFETY: C strings and the identity to fill, its certificate
        // freed after.
        unsafe {
            if bpm_pkg_load_info(input.path.as_ptr(), &mut info) == 0 {
                xfree(info.cert.cast(), info.cert_len + 1);
            }
            bpm_pkg_extract(input.path.as_ptr(), dest.as_ptr());
        }
        if let Ok(entries) = std::fs::read_dir(base) {
            for e in entries.flatten() {
                let _ =
                    std::fs::remove_dir_all(e.path()).or_else(|_| std::fs::remove_file(e.path()));
            }
        }
    },
    package_init
);
