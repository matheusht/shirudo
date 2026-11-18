// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C-shaped interface the crate still calls.

use core::ffi::{c_char, c_int, c_void};

use super::records::{self, EventlogInit, LineFn};
use crate::ffi;

pub extern "C" fn eventlog_path() -> *const c_char {
    super::path().as_ptr()
}

/// # Safety
///
/// `out` is an init record to fill.
pub unsafe extern "C" fn eventlog_boot_init(out: *mut EventlogInit) -> c_int {
    // SAFETY: the caller passes the structure, all of whose bits zeroed
    // are a valid one.
    unsafe {
        out.write_bytes(0, 1);
        records::boot_init(&mut *out)
    }
}

/// # Safety
///
/// `cb` takes `ctx`.
pub unsafe extern "C" fn eventlog_boot_lines(cb: Option<LineFn>, ctx: *mut c_void) -> c_int {
    records::boot_lines(cb, ctx)
}

/// # Safety
///
/// `out` has room for `cap` bytes.
pub unsafe extern "C" fn eventlog_timestamp(out: *mut c_char, cap: usize) {
    // SAFETY: the caller passes the room.
    super::timestamp(unsafe { ffi::bytes_mut(out.cast(), cap) })
}

/// # Safety
///
/// `out` has room for `cap` bytes, at least one.
pub unsafe extern "C" fn eventlog_boot_id(out: *mut c_char, cap: usize) {
    // SAFETY: the caller passes the room.
    super::read_boot_id(unsafe { ffi::bytes_mut(out.cast(), cap) })
}
