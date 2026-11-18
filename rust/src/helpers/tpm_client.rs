// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the TPM client helpers share: prctl() with PR_GET_ENFORCEMENT
//! answered as the test sets, which make links them with
//! --wrap=prctl.

use core::ffi::{c_int, c_ulong};
use core::sync::atomic::{AtomicI32, Ordering};

/// PR_GET_ENFORCEMENT and PR_ENFORCING_ERR of include/shirudo/enforcement.h.
const PR_GET_ENFORCEMENT: c_int = 0x5352_0001;
const PR_ENFORCING_ERR: c_int = 1002;

/// What the kernel answers PR_GET_ENFORCEMENT: enforcing for 1, a kernel
/// without the question for 0, the error for a negative errno.
/// Untrusted clients keep the default; session tests select guarded
/// states.
pub(crate) static ENFORCING: AtomicI32 = AtomicI32::new(0);

unsafe extern "C" {
    fn __real_prctl(option: c_int, ...) -> c_int;
}

/// # Safety
///
/// As prctl(2) with these arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_prctl(
    option: c_int,
    a: c_ulong,
    b: c_ulong,
    c: c_ulong,
    d: c_ulong,
) -> c_int {
    if option != PR_GET_ENFORCEMENT {
        // SAFETY: the caller's call, made.
        return unsafe { __real_prctl(option, a, b, c, d) };
    }
    let errno = match ENFORCING.load(Ordering::Relaxed) {
        1 => PR_ENFORCING_ERR,
        0 => libc::EINVAL,
        e => -e,
    };
    // SAFETY: this thread's errno.
    unsafe { *libc::__errno_location() = errno };
    -1
}
