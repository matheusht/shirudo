// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The running kernel's build ID behind `util/kernel_build_id.h`: the
//! GNU build ID note of /sys/kernel/notes, in hex.

use core::ffi::{c_char, c_int};

use crate::errno::{E2BIG, EINVAL, ENOENT};
use crate::sys::hex::hex_encode;
use crate::sys::libc::{O_CLOEXEC, O_RDONLY, close, errno, open, read};

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

    // SAFETY: a C string and flags without a mode.
    let fd = unsafe { open(c"/sys/kernel/notes".as_ptr(), O_RDONLY | O_CLOEXEC) };
    if fd < 0 {
        return -errno();
    }
    let ret = loop {
        if len == notes.len() {
            break -E2BIG;
        }
        // SAFETY: the room left in notes, from the fd open() gave.
        let n = unsafe { read(fd, notes[len..].as_mut_ptr().cast(), notes.len() - len) };
        if n < 0 {
            break -errno();
        }
        if n == 0 {
            // SAFETY: the caller's room.
            break unsafe { from_notes(&notes[..len], out) };
        }
        len += n as usize;
    };
    // SAFETY: the fd open() gave, closed once, here.
    unsafe { close(fd) };
    ret
}

mod capi {
    use core::ffi::{c_char, c_int, c_void};

    use super::{from_notes, read_build_id};
    use crate::errno::EINVAL;
    use crate::ffi;

    /// # Safety
    ///
    /// `notes` is NULL or holds `notes_len` bytes, and `out` is NULL or
    /// has room for `KERNEL_BUILD_ID_STRING_MAX` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kernel_build_id_from_notes(
        notes: *const c_void,
        notes_len: usize,
        out: *mut c_char,
    ) -> c_int {
        if notes.is_null() || out.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller passes the notes and the room.
        unsafe { from_notes(ffi::slice(notes.cast(), notes_len), out) }
    }

    /// # Safety
    ///
    /// `out` is NULL or has room for `KERNEL_BUILD_ID_STRING_MAX` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kernel_build_id_read(out: *mut c_char) -> c_int {
        if out.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller passes the room.
        unsafe { read_build_id(out) }
    }
}
