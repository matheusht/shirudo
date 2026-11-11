// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The hardening of the process at its start, behind `util/harden.h`:
//! its standard descriptors, and what it allows of itself.

use core::ffi::{c_int, c_ulong};

use crate::errno::EBADF;
use crate::sys::libc::{
    __nss_configure_lookup, _exit, F_GETFD, MCL_CURRENT, MCL_FUTURE, O_RDWR, PR_SET_DUMPABLE,
    PR_SET_NO_NEW_PRIVS, PR_SET_PTRACER, RLIMIT_CORE, Rlimit, errno, fcntl, mlockall, open, prctl,
    setrlimit, strerror,
};
use crate::sys::log::pr_err;
use crate::sys::openssl::{OPENSSL_INIT_NO_LOAD_CONFIG, OPENSSL_init_crypto};

/// Started with standard input, output or error closed, the process gives
/// that number to the next file it opens, and what it prints lands in
/// that file: point each closed one at /dev/null before anything opens.
fn harden_stdio() {
    for fd in 0..=2 {
        // SAFETY: a call that takes no pointer.
        if unsafe { fcntl(fd, F_GETFD) } != -1 || errno() != EBADF {
            continue;
        }
        // The ones below fd are open, so fd is the lowest free.
        // SAFETY: a C string.
        if unsafe { open(c"/dev/null".as_ptr(), O_RDWR) } != fd {
            // SAFETY: a call that takes no pointer.
            unsafe { _exit(1) };
        }
    }
}

/// No host file may name code for the process to load: an OpenSSL
/// configuration file can activate a provider module, and nsswitch.conf
/// can name an NSS module for the host lookups libcurl makes, both
/// dlopen()ed from paths root controls whatever secure-exec mode does to
/// the environment. glibc's own files and dns services answer host
/// lookups without a module, in a static binary too.
fn harden_self() -> c_int {
    let no_core = Rlimit { cur: 0, max: 0 };
    let (zero, one): (c_ulong, c_ulong) = (0, 1);

    // SAFETY: prctl() of numbers alone, the limit above, OpenSSL's
    // initialisation with no settings, and two C strings.
    unsafe {
        prctl(PR_SET_DUMPABLE, zero, zero, zero, zero);
        prctl(PR_SET_NO_NEW_PRIVS, one, zero, zero, zero);
        prctl(PR_SET_PTRACER, zero, zero, zero, zero);
        setrlimit(RLIMIT_CORE, &no_core);
        OPENSSL_init_crypto(OPENSSL_INIT_NO_LOAD_CONFIG, core::ptr::null());
        __nss_configure_lookup(c"hosts".as_ptr(), c"files dns".as_ptr());
    }
    // SAFETY: a call that takes no pointer.
    if unsafe { mlockall(MCL_CURRENT | MCL_FUTURE) } != 0 {
        let err = -errno();

        // SAFETY: a format of one C string, and strerror()'s.
        unsafe {
            pr_err(
                c"hardening: cannot lock process memory: %s".as_ptr(),
                strerror(-err),
            )
        };
        return err;
    }
    0
}

mod capi {
    use core::ffi::c_int;

    #[unsafe(no_mangle)]
    pub extern "C" fn harden_stdio() {
        super::harden_stdio();
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn harden_self() -> c_int {
        super::harden_self()
    }
}
