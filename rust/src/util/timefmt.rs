// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The time formats: a compact duration, and a
//! time as ISO-8601 UTC.

use core::ffi::{c_int, c_long};

use crate::errno::{E2BIG, EINVAL};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{Tm, gmtime_r, strftime};
use crate::text::{decimal, strscpy, strsprintf};

/// `seconds` in the largest whole unit it reaches, `42s`, `5m`, `3h` or
/// `2d`, or `?` for a negative count.
pub(crate) fn format_duration(seconds: c_long, buf: &mut [u8]) -> c_int {
    let mut digits = [0u8; 20];

    if seconds < 0 {
        return if strscpy(buf, b"?").is_err() {
            -E2BIG
        } else {
            0
        };
    }
    let (n, unit) = match seconds {
        0..60 => (seconds, b"s"),
        60..3600 => (seconds / 60, b"m"),
        3600..86400 => (seconds / 3600, b"h"),
        _ => (seconds / 86400, b"d"),
    };
    if strsprintf(buf, &[decimal(n as u64, &mut digits), unit]).is_err() {
        return -E2BIG;
    }
    0
}

/// `t` as `YYYY-MM-DDTHH:MM:SSZ` into `out`, or -EINVAL, and an empty
/// string where there is room, when it does not fit or has no date.
pub(crate) fn iso8601(t: i64, out: &mut [u8]) -> c_int {
    let mut tm = Tm::zeroed();

    // SAFETY: a time and a struct tm to fill, then the room at out and a
    // format, as strftime() takes them.
    let ok = unsafe {
        !gmtime_r(&t, &mut tm).is_null()
            && strftime(
                out.as_mut_ptr().cast(),
                out.len(),
                c"%Y-%m-%dT%H:%M:%SZ".as_ptr(),
                &tm,
            ) != 0
    };
    if ok {
        return 0;
    }
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    -EINVAL
}

/// The seconds since the epoch now, as time() gives them.
pub(crate) fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
