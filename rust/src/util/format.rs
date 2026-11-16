// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The human-readable formats behind `util/format.h`.

use core::ffi::{CStr, c_int};

use crate::errno::E2BIG;
use crate::sys::libc::{File, fputs, snprintf};
use crate::sys::string::text_sanitize;
use crate::text::{decimal, strscpy, strsprintf};

/// `bytes` with a binary unit, `512B`, `1.50K`, `12.3M` or `256G`: two
/// decimals below 10, one below 100 and none above, as printf() rounds
/// them.
fn human_size(bytes: u64, out: &mut [u8]) -> c_int {
    const UNITS: [(u32, &CStr); 3] = [(30, c"G"), (20, c"M"), (10, c"K")];
    let mut digits = [0u8; 20];

    let Some(&(shift, unit)) = UNITS.iter().find(|&&(shift, _)| bytes >= 1 << shift) else {
        return if strsprintf(out, &[decimal(bytes, &mut digits), b"B"]).is_err() {
            -E2BIG
        } else {
            0
        };
    };
    let v = bytes as f64 / (1u64 << shift) as f64;
    let fmt = if v >= 100.0 {
        c"%.0f%s"
    } else if v >= 10.0 {
        c"%.1f%s"
    } else {
        c"%.2f%s"
    };
    // SAFETY: the room at out, a format of a double and a C string, and
    // those two.
    let n = unsafe {
        snprintf(
            out.as_mut_ptr().cast(),
            out.len(),
            fmt.as_ptr(),
            v,
            unit.as_ptr(),
        )
    };
    if n < 0 || n as usize >= out.len() {
        if let Some(first) = out.first_mut() {
            *first = 0;
        }
        return -E2BIG;
    }
    0
}

/// At most 511 bytes of `s`, safe to print, to `f`.
///
/// # Safety
///
/// `f` is an open stream.
pub(crate) unsafe fn fputs_sanitized(s: &[u8], f: *mut File) {
    let mut shown = [0u8; 512];
    let n = strscpy(&mut shown, s).unwrap_or(shown.len() - 1);

    // SAFETY: n bytes of shown, terminated after them, and the caller's
    // stream.
    unsafe {
        text_sanitize(shown.as_mut_ptr().cast(), n, false);
        fputs(shown.as_ptr().cast(), f);
    }
}

mod capi {
    use core::ffi::{c_char, c_int};

    use crate::ffi;
    use crate::sys::libc::File;

    /// # Safety
    ///
    /// `out` has room for `out_cap` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn human_size(bytes: u64, out: *mut c_char, out_cap: usize) -> c_int {
        // SAFETY: the caller passes the room.
        super::human_size(bytes, unsafe { ffi::bytes_mut(out.cast(), out_cap) })
    }

    /// # Safety
    ///
    /// `s` is a C string and `f` an open stream.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn fputs_sanitized(s: *const c_char, f: *mut File) {
        // SAFETY: the caller passes a C string and its stream.
        unsafe { super::fputs_sanitized(ffi::c_str(s), f) }
    }
}
