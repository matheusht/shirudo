// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The bootstrap file behind `util/image_bootstrap.h`: where the runtime
//! and config images and the config's verification keys are, the runtime
//! image's root hash and the PCR the config is measured into.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use super::config_measure::pcr_valid;
use crate::errno::{E2BIG, EEXIST, EINVAL, EIO, ENAMETOOLONG, EPERM};
use crate::ffi;
use crate::sys::libc::{File, PATH_MAX, fclose, ferror, free};
use crate::text::{contains, cstr, parse_u64, strscpy, trim_blanks};
use crate::util::hex::hex_decode;
use crate::util::io::read_text_line;
use crate::util::keys::KEYS_MAX;

const RUNTIME_DIR_PREFIX: &[u8] = b"/run/shirudo/runtime/";

/// `struct image_bootstrap`.
#[repr(C)]
pub struct ImageBootstrap {
    pub(crate) runtime: [u8; PATH_MAX],
    pub(crate) config: [u8; PATH_MAX],
    pub(crate) certificates: [[u8; PATH_MAX]; KEYS_MAX],
    pub(crate) n_certificates: usize,
    pub(crate) runtime_root: [u8; 32],
    pub(crate) pcr: u32,
    pub(crate) have_root: bool,
    pub(crate) have_pcr: bool,
}

const _: () = assert!(size_of::<ImageBootstrap>() == 73776);

/// An absolute path without `.` or `..` components or empty ones, and
/// not `/`.
pub(crate) fn path_valid(path: &[u8]) -> bool {
    path.first() == Some(&b'/')
        && !contains(path, b"/../")
        && !contains(path, b"/./")
        && !contains(path, b"//")
        && path != b"/"
        && (path.len() < 3 || !path.ends_with(b"/.."))
}

/// One more config verification certificate, a file of the runtime
/// image named once.
fn add_certificate(boot: &mut ImageBootstrap, path: &[u8]) -> c_int {
    let n = boot.n_certificates;

    if !path.starts_with(RUNTIME_DIR_PREFIX) || !path_valid(path) {
        return -EPERM;
    }
    if n == KEYS_MAX {
        return -E2BIG;
    }
    if boot.certificates[..n].iter().any(|c| cstr(c) == path) {
        return -EEXIST;
    }
    if strscpy(&mut boot.certificates[n], path).is_err() {
        return -ENAMETOOLONG;
    }
    boot.n_certificates += 1;
    0
}

/// One `key = value` line, cut in place, into `boot`.
fn apply(boot: &mut ImageBootstrap, key: &[u8], value: &CStr, initial: bool) -> c_int {
    let v = value.to_bytes();

    match key {
        b"runtime.root_hash" => {
            if !initial || boot.have_root {
                return -EINVAL;
            }
            // SAFETY: a C string, and the room of the root hash.
            if unsafe { hex_decode(value.as_ptr(), boot.runtime_root.as_mut_ptr(), 32) } != 0 {
                return -EINVAL;
            }
            boot.have_root = true;
            0
        }
        b"runtime.image" if initial => {
            if !path_valid(v) || boot.runtime[0] != 0 {
                -EINVAL
            } else if strscpy(&mut boot.runtime, v).is_err() {
                -ENAMETOOLONG
            } else {
                0
            }
        }
        b"config.image" => {
            if !path_valid(v) {
                -EINVAL
            } else if strscpy(&mut boot.config, v).is_err() {
                -ENAMETOOLONG
            } else {
                0
            }
        }
        b"config.verification_key" => add_certificate(boot, v),
        b"config.pcr" => match parse_u64(v, 23) {
            Ok(pcr) if pcr_valid(pcr as u32) == 0 => {
                boot.pcr = pcr as u32;
                boot.have_pcr = true;
                0
            }
            _ => -EINVAL,
        },
        _ if key.starts_with(b"config.") || key.starts_with(b"runtime.") => -EINVAL,
        _ => 0,
    }
}

/// The lines of the stream `f`, which this consumes and closes, into
/// `boot`; only the `initial` read takes the runtime image and its root.
///
/// # Safety
///
/// `f` is an open stream nothing else uses.
unsafe fn parse(f: *mut File, boot: &mut ImageBootstrap, initial: bool) -> c_int {
    let mut line: *mut c_char = ptr::null_mut();
    let mut capacity = 0usize;
    let mut ret = 0;

    // SAFETY: the caller's stream, and getline()'s line, the len bytes
    // before its NUL.
    unsafe {
        loop {
            let got = read_text_line(f, &mut line, &mut capacity, PATH_MAX + 127);

            if got == 0 {
                break;
            }
            if got < 0 {
                ret = got;
                break;
            }
            let len = CStr::from_ptr(line).to_bytes().len();
            let buf = ffi::bytes_mut(line.cast(), len + 1);
            let (ls, le) = trim_blanks(buf, 0, len);
            if ls == le || buf[ls] == b'#' {
                continue;
            }
            let Some(eq) = buf[ls..le].iter().position(|&c| c == b'=').map(|i| ls + i) else {
                ret = -EINVAL;
                break;
            };
            buf[eq] = 0;
            let (ks, ke) = trim_blanks(buf, ls, eq);
            let (vs, _) = trim_blanks(buf, eq + 1, le);
            let key = &buf[ks..ke];
            let value = CStr::from_bytes_until_nul(&buf[vs..]).unwrap_or(c"");
            ret = apply(boot, key, value, initial);
            if ret != 0 {
                break;
            }
        }
        if ferror(f) != 0 && ret == 0 {
            ret = -EIO;
        }
        free(line.cast());
        fclose(f);
    }
    ret
}

pub(crate) use capi::{image_bootstrap_read, image_bootstrap_read_fd};

mod capi {
    use core::ffi::{c_char, c_int};

    use super::{ImageBootstrap, parse, path_valid};
    use crate::ffi;
    use crate::sys::libc::{F_DUPFD_CLOEXEC, SEEK_SET, close, errno, fcntl, fdopen, fopen, lseek};

    /// # Safety
    ///
    /// `path` is NULL or a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn image_path_valid(path: *const c_char) -> bool {
        // SAFETY: the caller passes NULL or a C string.
        !path.is_null() && path_valid(unsafe { ffi::c_str(path) })
    }

    /// # Safety
    ///
    /// `path` is a C string and `boot` a bootstrap to fill.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn image_bootstrap_read(
        path: *const c_char,
        boot: *mut ImageBootstrap,
        initial: bool,
    ) -> c_int {
        // SAFETY: the caller passes a C string and its bootstrap.
        unsafe {
            let f = fopen(path, c"re".as_ptr());
            if f.is_null() {
                return -errno();
            }
            parse(f, &mut *boot, initial)
        }
    }

    /// A copy of `fd` is read from its start; the caller keeps its own.
    ///
    /// # Safety
    ///
    /// `boot` is a bootstrap to fill.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn image_bootstrap_read_fd(
        fd: c_int,
        boot: *mut ImageBootstrap,
        initial: bool,
    ) -> c_int {
        // SAFETY: the caller's bootstrap, and the copy of its fd, which
        // the stream takes over or which is closed here.
        unsafe {
            let copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
            if copy < 0 {
                return -errno();
            }
            if lseek(copy, 0, SEEK_SET) < 0 {
                let ret = -errno();

                close(copy);
                return ret;
            }
            let f = fdopen(copy, c"r".as_ptr());
            if f.is_null() {
                let ret = -errno();

                close(copy);
                return ret;
            }
            parse(f, &mut *boot, initial)
        }
    }
}
