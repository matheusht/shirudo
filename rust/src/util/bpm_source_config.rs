// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The lines of a registry source and of an upatch tree config behind
//! `util/bpm_source_config.h`: `key = value`, cut apart in place as the
//! C cut them.

use core::ffi::c_int;

use crate::errno::{E2BIG, EINVAL};
use crate::text::{cstr, strscpy};

/// isspace() in the C locale.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// A source line's `endpoint`, `index_repository` or `key_file` into
/// its field; other keys and lines without `=` leave the fields as they
/// were.
fn parse_source_line(
    line: &mut [u8],
    endpoint: &mut [u8],
    index_repository: &mut [u8],
    key_file: &mut [u8],
) -> c_int {
    let n = cstr(line).len();
    let mut key = 0;

    while key < n && is_space(line[key]) {
        key += 1;
    }
    let Some(eq) = line[key..n]
        .iter()
        .position(|&c| c == b'=')
        .map(|i| key + i)
    else {
        return 0;
    };
    line[eq] = 0;
    let mut key_end = eq;
    while key_end > key && is_space(line[key_end - 1]) {
        key_end -= 1;
        line[key_end] = 0;
    }
    let mut val = eq + 1;
    while val < n && is_space(line[val]) {
        val += 1;
    }
    let val_end = line[val..n]
        .iter()
        .position(|&c| c == b'\r' || c == b'\n')
        .map_or(n, |i| val + i);
    line[val_end] = 0;
    let (k, v) = (&line[key..key_end], &line[val..val_end]);
    if k == b"endpoint" && strscpy(endpoint, v).is_err() {
        return -E2BIG;
    }
    if k == b"index_repository" && strscpy(index_repository, v).is_err() {
        return -E2BIG;
    }
    if k == b"key_file" && strscpy(key_file, v).is_err() {
        return -E2BIG;
    }
    0
}

/// The text from `start` to `end` of `line` without the blanks around
/// it, terminated in place: where it starts and ends.
fn trim(line: &mut [u8], start: usize, end: usize) -> (usize, usize) {
    let mut s = start;
    let mut e = end;

    while s < e && is_space(line[s]) {
        s += 1;
    }
    while e > s && is_space(line[e - 1]) {
        e -= 1;
    }
    line[e] = 0;
    (s, e)
}

/// A tree line's `endpoint` or `reference`, a value in double quotes
/// taken without them, into its field.
fn parse_tree_line(line: &mut [u8], endpoint: &mut [u8], reference: &mut [u8]) -> c_int {
    let n = cstr(line).len();
    let Some(eq) = line[..n].iter().position(|&c| c == b'=') else {
        return 0;
    };
    line[eq] = 0;
    let (ks, ke) = trim(line, 0, eq);
    let (mut vs, mut ve) = trim(line, eq + 1, n);
    if ve > vs && line[vs] == b'"' {
        if ve - vs < 2 || line[ve - 1] != b'"' {
            return -EINVAL;
        }
        ve -= 1;
        line[ve] = 0;
        vs += 1;
    }
    let (k, v) = (&line[ks..ke], &line[vs..ve]);
    if k == b"endpoint" && strscpy(endpoint, v).is_err() {
        return -E2BIG;
    }
    if k == b"reference" && strscpy(reference, v).is_err() {
        return -E2BIG;
    }
    0
}

mod capi {
    use core::ffi::{CStr, c_char, c_int};

    use super::{parse_source_line, parse_tree_line};
    use crate::errno::EINVAL;
    use crate::ffi;

    /// # Safety
    ///
    /// `line` is NULL or a C string to cut apart, and each field NULL or
    /// room for its size, apart from the line and from each other.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bpm_parse_source_line(
        line: *mut c_char,
        endpoint: *mut c_char,
        endpoint_sz: usize,
        index_repository: *mut c_char,
        index_repository_sz: usize,
        key_file: *mut c_char,
        key_file_sz: usize,
    ) -> c_int {
        if line.is_null()
            || endpoint.is_null()
            || endpoint_sz == 0
            || index_repository.is_null()
            || index_repository_sz == 0
            || key_file.is_null()
            || key_file_sz == 0
        {
            return -EINVAL;
        }
        // SAFETY: the caller passes its line, with its NUL, and three
        // rooms apart from it.
        unsafe {
            let len = CStr::from_ptr(line).to_bytes().len();

            parse_source_line(
                ffi::bytes_mut(line.cast(), len + 1),
                ffi::bytes_mut(endpoint.cast(), endpoint_sz),
                ffi::bytes_mut(index_repository.cast(), index_repository_sz),
                ffi::bytes_mut(key_file.cast(), key_file_sz),
            )
        }
    }

    /// # Safety
    ///
    /// `line` is a C string to cut apart, and `endpoint` and `reference`
    /// have room for their sizes, apart from the line and each other.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bpm_parse_tree_line(
        line: *mut c_char,
        endpoint: *mut c_char,
        endpoint_sz: usize,
        reference: *mut c_char,
        reference_sz: usize,
    ) -> c_int {
        // SAFETY: the caller passes its line, with its NUL, and two rooms
        // apart from it.
        unsafe {
            let len = CStr::from_ptr(line).to_bytes().len();

            parse_tree_line(
                ffi::bytes_mut(line.cast(), len + 1),
                ffi::bytes_mut(endpoint.cast(), endpoint_sz),
                ffi::bytes_mut(reference.cast(), reference_sz),
            )
        }
    }
}
