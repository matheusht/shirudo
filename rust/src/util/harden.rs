// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The hardening of the process at its start:
//! its standard descriptors, and what it allows of itself.

use core::ffi::{CStr, c_int, c_ulong};

use crate::errno::EBADF;
use crate::sys::libc::{
    __nss_configure_lookup, _exit, F_GETFD, ITIMER_PROF, ITIMER_REAL, ITIMER_VIRTUAL, Itimerval,
    MCL_CURRENT, MCL_FUTURE, O_RDWR, PER_LINUX, PR_SET_DUMPABLE, PR_SET_NO_NEW_PRIVS,
    PR_SET_PTRACER, RLIM_INFINITY, RLIMIT_CORE, RLIMIT_CPU, RLIMIT_FSIZE, Rlimit, Timeval, errno,
    fcntl, mlockall, open, personality, prctl, setitimer, setrlimit, strerror,
};
use crate::sys::openssl::{OPENSSL_INIT_NO_LOAD_CONFIG, OPENSSL_init_crypto};

/// Started with standard input, output or error closed, the process gives
/// that number to the next file it opens, and what it prints lands in
/// that file: point each closed one at /dev/null before anything opens.
pub(crate) fn harden_stdio() {
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

/// What could not be hardened, logged under `what`: the -errno.
fn failed(what: &CStr) -> c_int {
    let err = -errno();

    // SAFETY: a format of two C strings, and strerror()'s.
    unsafe {
        crate::log::log_c!(
            crate::log::err,
            c"hardening: %s: %s".as_ptr(),
            what.as_ptr(),
            strerror(-err),
        )
    };
    err
}

/// What the caller passes down through exec and the kernel would act on
/// midway: the personality, where UNAME26 has uname() report a 2.6
/// release to the tree selector and READ_IMPLIES_EXEC makes later
/// mappings executable; the file size and CPU time limits; and the
/// interval timers, with which the kernel would stop the command by
/// SIGXFSZ, SIGXCPU or SIGALRM.
fn drop_inherited() -> c_int {
    // SAFETY: a call that takes no pointer.
    if unsafe { personality(PER_LINUX) } < 0 {
        return failed(c"cannot reset the personality");
    }
    let unlimited = Rlimit {
        rlim_cur: RLIM_INFINITY,
        rlim_max: RLIM_INFINITY,
    };
    for limit in [RLIMIT_FSIZE, RLIMIT_CPU] {
        // SAFETY: the limit above.
        if unsafe { setrlimit(limit, &unlimited) } != 0 {
            return failed(c"cannot reset the resource limits");
        }
    }
    let none = || Timeval {
        tv_sec: 0,
        tv_usec: 0,
    };
    let off = Itimerval {
        it_interval: none(),
        it_value: none(),
    };
    for timer in [ITIMER_REAL, ITIMER_VIRTUAL, ITIMER_PROF] {
        // SAFETY: the timer value above, and no room for the old one.
        if unsafe { setitimer(timer, &off, core::ptr::null_mut()) } != 0 {
            return failed(c"cannot disarm the interval timers");
        }
    }
    0
}

/// No host file may name code for the process to load: an OpenSSL
/// configuration file can activate a provider module, and nsswitch.conf
/// can name an NSS module for the host lookups libcurl makes, both
/// dlopen()ed from paths root controls whatever secure-exec mode does to
/// the environment. glibc's own files and dns services answer host
/// lookups without a module, in a static binary too.
pub(crate) fn harden_self() -> c_int {
    let no_core = Rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    let (zero, one): (c_ulong, c_ulong) = (0, 1);

    let ret = drop_inherited();
    if ret != 0 {
        return ret;
    }

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
        return failed(c"cannot lock process memory");
    }
    0
}
