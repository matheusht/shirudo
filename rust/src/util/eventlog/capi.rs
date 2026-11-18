// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C-shaped interface the crate still calls.

use core::ffi::c_int;

use super::records::{self, EventlogInit};

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
