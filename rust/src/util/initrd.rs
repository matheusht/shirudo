// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Where init runs, behind `util/initrd.h`: the initrd, with the root
//! file system at /sysroot, and so where the keys it enrols are.

use core::ffi::CStr;

use crate::sys::libc::{F_OK, access, env};
use crate::util::image_config;

/// The paths of util/paths.h the answers come from: the keys directory
/// and its certificate in the runtime image, in the initrd, and in the
/// state tree.
const RUNTIME_KEYS_DIR: &CStr = c"/run/shirudo/runtime/keys";
const RUNTIME_CERT_PATH: &CStr = c"/run/shirudo/runtime/keys/cert.der";
const INITRD_KEYS_DIR: &CStr = c"/etc/shirudo/keys";
const INITRD_CERT_PATH: &CStr = c"/etc/shirudo/keys/cert.der";
const KEYS_DIR: &CStr = c"/var/lib/shirudo/keys";
const CERT_PATH: &CStr = c"/var/lib/shirudo/keys/cert.der";

/// The test override `name` sets, unless it is empty or a config image
/// is active, which no environment variable moves.
fn test_override(name: &CStr) -> Option<&'static CStr> {
    if image_config::active() {
        return None;
    }
    env(name).filter(|value| !value.is_empty())
}

/// Whether the process runs in the initrd, which marks itself with
/// /etc/initrd-release.
fn in_initrd() -> bool {
    let release = test_override(c"SHIRUDO_INITRD_RELEASE").unwrap_or(c"/etc/initrd-release");

    // SAFETY: a C string.
    unsafe { access(release.as_ptr(), F_OK) == 0 }
}

/// Where the initrd mounts the root file system.
fn sysroot() -> &'static CStr {
    test_override(c"SHIRUDO_SYSROOT").unwrap_or(c"/sysroot")
}

/// The keys init enrols: the runtime image's under a config image, the
/// initrd's own measured copies while the initrd runs, and the state
/// tree's otherwise.
pub(crate) fn keys_dir() -> &'static CStr {
    if image_config::root_fd() >= 0 {
        return RUNTIME_KEYS_DIR;
    }
    if in_initrd() {
        INITRD_KEYS_DIR
    } else {
        KEYS_DIR
    }
}

/// The primary certificate in the directory keys_dir() gives.
pub(crate) fn cert_path() -> &'static CStr {
    if image_config::root_fd() >= 0 {
        return RUNTIME_CERT_PATH;
    }
    if in_initrd() {
        INITRD_CERT_PATH
    } else {
        CERT_PATH
    }
}

mod capi {
    use core::ffi::c_char;

    #[unsafe(no_mangle)]
    pub extern "C" fn in_initrd() -> bool {
        super::in_initrd()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn sysroot() -> *const c_char {
        super::sysroot().as_ptr()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_keys_dir() -> *const c_char {
        super::keys_dir().as_ptr()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn get_cert_path() -> *const c_char {
        super::cert_path().as_ptr()
    }
}
