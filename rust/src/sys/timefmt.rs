// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The time formats of `util/timefmt.h`.

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// `t` as ISO-8601 UTC, `YYYY-MM-DDTHH:MM:SSZ`, into the `cap` bytes
    /// at `out`; -EINVAL, and an empty string where there is room, when
    /// it does not fit.
    pub fn iso8601(t: i64, out: *mut c_char, cap: usize) -> c_int;
}
