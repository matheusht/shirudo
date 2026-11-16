// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The upatches-loaded table of `shirudo status` and `upatch list`,
//! behind `util/upatch_table.h`: printed, or as JSON.

use core::ffi::{c_char, c_long};

use crate::sys::libc::{Tm, printf, strptime, time, timegm};
use crate::util::json::JsonEmit;
use crate::util::timefmt::format_duration;

/// `struct upatch_table_row`.
#[repr(C)]
pub struct UpatchTableRow {
    pub(crate) name: [c_char; 257],
    pub(crate) location: [c_char; 160],
    pub(crate) loaded_at: [c_char; 32],
    pub(crate) status: [c_char; 64],
    pub(crate) n_maps: u32,
    pub(crate) age_sec: i64,
    pub(crate) payload_sha256: [c_char; 65],
}

const _: () = assert!(size_of::<UpatchTableRow>() == 600);
const _: () = assert!(core::mem::offset_of!(UpatchTableRow, n_maps) == 516);
const _: () = assert!(core::mem::offset_of!(UpatchTableRow, payload_sha256) == 528);

/// The string in a fixed array, up to its NUL.
fn in_array(a: &[c_char]) -> &[u8] {
    // SAFETY: c_char and u8 have one size and alignment.
    let bytes = unsafe { core::slice::from_raw_parts(a.as_ptr().cast::<u8>(), a.len()) };

    &bytes[..bytes.iter().position(|&c| c == 0).unwrap_or(bytes.len())]
}

/// The seconds since an ISO-8601 UTC time, `YYYY-MM-DDTHH:MM:SSZ` with
/// anything after it; -1 for none or one that does not parse.
///
/// # Safety
///
/// `ts` is NULL or a C string.
pub(crate) unsafe fn age_sec(ts: *const c_char) -> i64 {
    let mut tm = Tm::zeroed();

    // SAFETY: the caller passes NULL or a C string.
    if ts.is_null() || unsafe { *ts } == 0 {
        return -1;
    }
    // SAFETY: a C string, a format and a struct tm to fill.
    if unsafe { strptime(ts, c"%Y-%m-%dT%H:%M:%SZ".as_ptr(), &mut tm) }.is_null() {
        return -1;
    }
    // SAFETY: a call that takes no pointer, and the struct tm filled.
    let (now, then) = unsafe { (time(core::ptr::null_mut()), timegm(&mut tm)) };

    now.wrapping_sub(then)
}

/// The rows as `shirudo status` prints them.
pub(crate) fn print(rows: &[UpatchTableRow]) {
    let row = c"  %-24s  %-28s  %5u  %-28s  %s\n";

    // SAFETY: a format of an unsigned long, and its count.
    unsafe { printf(c"\nLoaded upatches (%zu):\n".as_ptr(), rows.len()) };
    if rows.is_empty() {
        // SAFETY: a format of nothing.
        unsafe { printf(c"  none\n".as_ptr()) };
        return;
    }
    // SAFETY: a format of five C strings, and those.
    unsafe {
        printf(
            c"  %-24s  %-28s  %5s  %-28s  %s\n".as_ptr(),
            c"NAME".as_ptr(),
            c"LOCATION".as_ptr(),
            c"MAPS".as_ptr(),
            c"STATUS".as_ptr(),
            c"AGE".as_ptr(),
        )
    };
    for r in rows {
        let mut age = [0u8; 16];

        age[0] = b'?';
        if r.age_sec >= 0 {
            format_duration(r.age_sec as c_long, &mut age);
        }
        let location = if r.location[0] != 0 {
            r.location.as_ptr()
        } else {
            c"-".as_ptr()
        };
        let status = if r.status[0] != 0 {
            r.status.as_ptr()
        } else {
            c"success".as_ptr()
        };

        // SAFETY: the format, the row's strings, which its arrays end,
        // its count of maps, and the age.
        unsafe {
            printf(
                row.as_ptr(),
                r.name.as_ptr(),
                location,
                r.n_maps,
                status,
                age.as_ptr(),
            )
        };
    }
}

/// The rows as the `upatches_loaded` array of the status JSON.
pub(crate) fn emit_json(e: &mut JsonEmit, rows: &[UpatchTableRow]) {
    e.arr_open(b"upatches_loaded");
    for r in rows {
        let status: &[u8] = if r.status[0] != 0 {
            in_array(&r.status)
        } else {
            b"success"
        };

        e.obj_open();
        e.kv_string(b"name", in_array(&r.name));
        e.kv_string(b"location", in_array(&r.location));
        e.kv_string(b"status", status);
        e.kv_int(b"n_maps", i64::from(r.n_maps));
        e.kv_string(b"loaded_at", in_array(&r.loaded_at));
        if r.age_sec >= 0 {
            e.kv_int(b"age_sec", r.age_sec);
        } else {
            e.kv_null(b"age_sec");
        }
        if r.payload_sha256[0] != 0 {
            e.kv_string(b"payload_sha256", in_array(&r.payload_sha256));
        } else {
            e.kv_null(b"payload_sha256");
        }
        e.obj_close();
    }
    e.arr_close();
}

mod capi {
    use core::ffi::c_char;

    use super::UpatchTableRow;
    use crate::ffi;
    use crate::util::json::JsonEmit;

    /// # Safety
    ///
    /// `ts` is NULL or a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_age_sec(ts: *const c_char) -> i64 {
        // SAFETY: the caller passes NULL or a C string.
        unsafe { super::age_sec(ts) }
    }

    /// # Safety
    ///
    /// `rows` holds `n` rows, each string in it ended.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_table_print(rows: *const UpatchTableRow, n: usize) {
        // SAFETY: the caller passes the rows.
        super::print(unsafe { ffi::slice(rows, n) })
    }

    /// # Safety
    ///
    /// `e` points to an emitter, and `rows` holds `n` rows.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_table_emit_json(
        e: *mut JsonEmit,
        rows: *const UpatchTableRow,
        n: usize,
    ) {
        // SAFETY: the caller passes an emitter and the rows.
        unsafe { super::emit_json(&mut *e, ffi::slice(rows, n)) }
    }
}
