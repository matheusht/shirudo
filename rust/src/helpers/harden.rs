// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-harden: harden_self() with mlockall() made to succeed or fail as
//! the argument says, which the link wraps, and the hardening shirudo
//! sets up before it checked as kept.
//!
//!   test-harden success|denied|limit

use core::ffi::{CStr, c_int};
use std::sync::atomic::{AtomicI32, Ordering};

use super::{err, helper_main, out};
use crate::errno::{ENOMEM, EPERM};
use crate::util::harden::harden_self;

helper_main!(shirudo_helper_test_harden, run);

static LOCK_ERROR: AtomicI32 = AtomicI32::new(0);
static LOCK_FLAGS: AtomicI32 = AtomicI32::new(0);

/// mlockall() for the library's call, which the link wraps: deterministic,
/// without locking the test process.
#[unsafe(no_mangle)]
pub extern "C" fn __wrap_mlockall(flags: c_int) -> c_int {
    LOCK_FLAGS.store(flags, Ordering::Relaxed);
    match LOCK_ERROR.load(Ordering::Relaxed) {
        0 => 0,
        error => {
            crate::sys::libc::set_errno(error);
            -1
        }
    }
}

fn run(args: &[&CStr]) -> c_int {
    let lock_error = match args.get(1).map(|a| a.to_bytes()) {
        Some(b"success") if args.len() == 2 => 0,
        Some(b"denied") if args.len() == 2 => EPERM,
        Some(b"limit") if args.len() == 2 => ENOMEM,
        _ => {
            err(&format!(
                "usage: {} success|denied|limit\n",
                args.first()
                    .map_or("test-harden".into(), |a| a.to_string_lossy())
            ));
            return 2;
        }
    };
    LOCK_ERROR.store(lock_error, Ordering::Relaxed);
    let ret = harden_self();
    if LOCK_FLAGS.load(Ordering::Relaxed) != libc::MCL_CURRENT | libc::MCL_FUTURE
        || ret != -lock_error
    {
        err("unexpected lock flags or result\n");
        return 2;
    }
    let mut core = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    // SAFETY: two queries of the process, and room for its core limit.
    let kept = unsafe {
        libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) == 0
            && libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1
            && libc::getrlimit(libc::RLIMIT_CORE, &mut core) == 0
    };
    if !kept || core.rlim_cur != 0 || core.rlim_max != 0 {
        err("existing startup hardening changed\n");
        return 2;
    }
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}
