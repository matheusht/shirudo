// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The paths of `util/paths.h` that util/paths.c still builds.

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// The key and certificate paths under `keys_dir`, into rooms of
    /// `pkey_sz` and `cert_sz` bytes: 0, -EINVAL or -ENAMETOOLONG.
    pub fn key_paths(
        keys_dir: *const c_char,
        pkey_path: *mut c_char,
        pkey_sz: usize,
        cert_path: *mut c_char,
        cert_sz: usize,
    ) -> c_int;
    /// The keys directory: the argument, else SHIRUDO_KEYS_DIR, else
    /// KEYS_DIR.
    pub fn keys_dir_resolve(keys_dir_arg: *const c_char) -> *const c_char;
    /// Whether stat() finds `path`.
    pub fn path_exists(path: *const c_char) -> bool;
    /// `keys_dir`/`file` into `out_sz` bytes at `out`: 0, -EINVAL or
    /// -ENAMETOOLONG.
    pub fn format_key_path(
        out: *mut c_char,
        out_sz: usize,
        keys_dir: *const c_char,
        file: *const c_char,
    ) -> c_int;
}
