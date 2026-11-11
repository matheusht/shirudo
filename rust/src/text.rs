// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The string rules of `include/shirudo/string.h` and the C library, for
//! Rust callers: a C string is the bytes of a buffer before its first
//! NUL, and a function here does to them what its C namesake does.

use core::ffi::c_int;

use crate::errno::{E2BIG, EINVAL, ERANGE};

/// The C string a buffer holds: its bytes up to the first NUL.
pub fn cstr(buf: &[u8]) -> &[u8] {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());

    &buf[..n]
}

/// The byte at `i` of a C string, and the NUL past its end.
pub fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// strstr(): where `needle` first starts in `s`.
pub fn find(s: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    s.windows(needle.len()).position(|w| w == needle)
}

pub fn contains(s: &[u8], needle: &[u8]) -> bool {
    find(s, needle).is_some()
}

/// strscpy(): `src` into `dst`, terminated; -E2BIG, with as much of it
/// as fits, when it does not.
pub fn strscpy(dst: &mut [u8], src: &[u8]) -> Result<usize, c_int> {
    let Some(room) = dst.len().checked_sub(1) else {
        return Err(-E2BIG);
    };
    let n = src.len().min(room);

    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
    if src.len() > room {
        return Err(-E2BIG);
    }
    Ok(n)
}

/// strsprintf() of a format of `%s` conversions alone: the parts one
/// after another, or -E2BIG and an empty buffer when they do not fit.
pub fn strsprintf(dst: &mut [u8], parts: &[&[u8]]) -> Result<usize, c_int> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let Some(room) = dst.len().checked_sub(1) else {
        return Err(-E2BIG);
    };
    let mut pos = 0;

    for part in parts {
        let n = part.len().min(room - pos);

        dst[pos..pos + n].copy_from_slice(&part[..n]);
        pos += n;
    }
    dst[pos] = 0;
    if total > room {
        dst[0] = 0;
        return Err(-E2BIG);
    }
    Ok(total)
}

/// digits(): how many of the bytes of `s`, from the first, are decimal
/// digits.
pub fn digits(s: &[u8]) -> usize {
    s.iter().take_while(|c| c.is_ascii_digit()).count()
}

/// parse_u64(): the decimal number `s` spells, digits alone; -EINVAL for
/// anything else, -ERANGE when it is above `max`.
pub fn parse_u64(s: &[u8], max: u64) -> Result<u64, c_int> {
    if s.is_empty() || !s.iter().all(u8::is_ascii_digit) {
        return Err(-EINVAL);
    }
    s.iter().try_fold(0u64, |v, &c| {
        v.checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(c - b'0')))
            .filter(|&v| v <= max)
            .ok_or(-ERANGE)
    })
}

/// name_has_suffix(): whether `name` is a stem of at least one byte and
/// then `suffix`, as a file name and its extension are.
pub fn name_has_suffix(name: &[u8], suffix: &[u8]) -> bool {
    name.len() > suffix.len() && name.ends_with(suffix)
}
