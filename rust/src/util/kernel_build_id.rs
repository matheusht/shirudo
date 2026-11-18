// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The running kernel's build ID: the
//! GNU build ID note of /sys/kernel/notes, in hex.

use core::ffi::{c_char, c_int};

use crate::errno::{E2BIG, EINVAL, ENOENT};
use crate::util::hex::hex_encode;

const BUILD_ID_MAX: usize = 64;
const NOTES_MAX: usize = 64 * 1024;
const NT_GNU_BUILD_ID: u32 = 3;

fn align4(v: usize) -> usize {
    (v + 3) & !3
}

/// The u32 the native-endian bytes at the start of `p` hold.
fn u32_at(p: &[u8]) -> u32 {
    u32::from_ne_bytes([p[0], p[1], p[2], p[3]])
}

/// The hex of the first GNU build ID note of `notes` into `out`, empty
/// until one is found: a note the notes cut short or whose name or
/// descriptor would run past them is -EINVAL, an ID of none or over 64
/// bytes -E2BIG, and notes without one -ENOENT.
///
/// # Safety
///
/// `out` has room for `2 * BUILD_ID_MAX + 1` bytes.
unsafe fn from_notes(mut notes: &[u8], out: *mut c_char) -> c_int {
    // SAFETY: the caller's room.
    unsafe { *out = 0 };
    while !notes.is_empty() {
        let len = notes.len();

        if len < 12 {
            return -EINVAL;
        }
        let namesz = u32_at(notes) as usize;
        let descsz = u32_at(&notes[4..]) as usize;
        let ty = u32_at(&notes[8..]);
        let name_off = 12;
        if namesz > len - name_off || align4(namesz) > len - name_off {
            return -EINVAL;
        }
        let desc_off = name_off + align4(namesz);
        if descsz > len - desc_off || align4(descsz) > len - desc_off {
            return -EINVAL;
        }
        let next = desc_off + align4(descsz);
        if ty == NT_GNU_BUILD_ID && namesz == 4 && &notes[name_off..name_off + 4] == b"GNU\0" {
            if descsz == 0 || descsz > BUILD_ID_MAX {
                return -E2BIG;
            }
            // SAFETY: descsz bytes of the notes, and the caller's room
            // for 2 * 64 hex digits and a NUL.
            unsafe { hex_encode(notes[desc_off..].as_ptr(), descsz, out) };
            return 0;
        }
        notes = &notes[next..];
    }
    -ENOENT
}

/// The running kernel's build ID into `out`.
///
/// # Safety
///
/// `out` has room for `2 * BUILD_ID_MAX + 1` bytes.
pub(crate) unsafe fn read_build_id(out: *mut c_char) -> c_int {
    let mut notes = [0u8; NOTES_MAX];
    let mut len = 0;

    use std::io::Read;

    let errno = |e: std::io::Error| -e.raw_os_error().unwrap_or(crate::errno::EIO);
    let mut f = match std::fs::File::open("/sys/kernel/notes") {
        Ok(f) => f,
        Err(e) => return errno(e),
    };
    loop {
        if len == notes.len() {
            return -E2BIG;
        }
        match f.read(&mut notes[len..]) {
            // SAFETY: the caller's room.
            Ok(0) => return unsafe { from_notes(&notes[..len], out) },
            Ok(n) => len += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return errno(e),
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(shirudo_fuzz)]
mod fuzz;
