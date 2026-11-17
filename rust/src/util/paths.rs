// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The paths of the signing keys: the keys directory a command names, the
//! environment's, or the default, and the key and certificate under it.
//! Exported under the names `util/paths.h` gives them; upatch_pin_path()
//! is in upatch_resolve.rs.

use core::ffi::{CStr, c_char, c_int};

use crate::errno::{EINVAL, ENAMETOOLONG};
use crate::sys::libc::getenv;
use crate::text::strsprintf;

/// KEYS_DIR, KEYS_DIR_ENV, SIGNING_KEY_FILE and CERT_FILE of
/// util/paths.h.
const KEYS_DIR: &CStr = c"/var/lib/shirudo/keys";
const KEYS_DIR_ENV: &CStr = c"SHIRUDO_KEYS_DIR";
const SIGNING_KEY_FILE: &CStr = c"signing_key.pem";
const CERT_FILE: &CStr = c"cert.der";

/// `file` under `dir`, a slash between unless `dir` ends in one, into
/// `out` and terminated: -EINVAL for an empty one, -ENAMETOOLONG when it
/// does not fit, with `out` left empty.
fn key_path(out: &mut [u8], dir: &[u8], file: &[u8]) -> Result<(), c_int> {
    if out.is_empty() || dir.is_empty() || file.is_empty() {
        return Err(-EINVAL);
    }
    let sep: &[u8] = if dir.ends_with(b"/") { b"" } else { b"/" };
    strsprintf(out, &[dir, sep, file])
        .map(|_| ())
        .map_err(|_| -ENAMETOOLONG)
}

/// keys_dir_resolve(): `arg`, else $SHIRUDO_KEYS_DIR, else KEYS_DIR.
///
/// # Safety
///
/// `arg` is NULL or a C string, which the result may be.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn keys_dir_resolve(arg: *const c_char) -> *const c_char {
    if !arg.is_null() {
        return arg;
    }
    // SAFETY: a C string; the environment's string or NULL.
    let env = unsafe { getenv(KEYS_DIR_ENV.as_ptr()) };
    if env.is_null() {
        KEYS_DIR.as_ptr()
    } else {
        env
    }
}

/// format_key_path(): `file` under `dir`, KEYS_DIR for NULL, into the
/// `out_sz` bytes at `out`: 0, -EINVAL or -ENAMETOOLONG.
///
/// # Safety
///
/// `out` is NULL or room for `out_sz` bytes, and `dir` and `file` are
/// NULL or C strings.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn format_key_path(
    out: *mut c_char,
    out_sz: usize,
    dir: *const c_char,
    file: *const c_char,
) -> c_int {
    if out.is_null() || file.is_null() {
        return -EINVAL;
    }
    let dir = if dir.is_null() {
        KEYS_DIR.as_ptr()
    } else {
        dir
    };
    // SAFETY: the caller's room and C strings.
    let (out, dir, file) = unsafe {
        (
            core::slice::from_raw_parts_mut(out.cast::<u8>(), out_sz),
            CStr::from_ptr(dir).to_bytes(),
            CStr::from_ptr(file).to_bytes(),
        )
    };
    key_path(out, dir, file).map_or_else(|e| e, |()| 0)
}

/// key_paths(): the signing key and the certificate under `dir`, into
/// rooms of `pkey_sz` and `cert_sz` bytes: 0, -EINVAL or -ENAMETOOLONG.
///
/// # Safety
///
/// As format_key_path(), for both paths.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn key_paths(
    dir: *const c_char,
    pkey: *mut c_char,
    pkey_sz: usize,
    cert: *mut c_char,
    cert_sz: usize,
) -> c_int {
    // SAFETY: the caller's rooms and C strings.
    match unsafe { format_key_path(pkey, pkey_sz, dir, SIGNING_KEY_FILE.as_ptr()) } {
        // SAFETY: as above.
        0 => unsafe { format_key_path(cert, cert_sz, dir, CERT_FILE.as_ptr()) },
        err => err,
    }
}

/// path_exists(): whether stat() finds `path`.
///
/// # Safety
///
/// `path` is a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn path_exists(path: *const c_char) -> bool {
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: the caller's C string.
    let path = unsafe { CStr::from_ptr(path) };
    std::fs::metadata(std::ffi::OsStr::from_bytes(path.to_bytes())).is_ok()
}
