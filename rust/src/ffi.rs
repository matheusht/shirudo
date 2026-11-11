// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Views of the memory C code hands across the boundary.

use core::ffi::{CStr, c_char};

/// The bytes of the C string at `s`, without its terminator.
///
/// # Safety
///
/// `s` points to a NUL-terminated string that stays valid and unchanged
/// for `'a`.
pub unsafe fn c_str<'a>(s: *const c_char) -> &'a [u8] {
    // SAFETY: the caller passes a valid C string.
    unsafe { CStr::from_ptr(s) }.to_bytes()
}

/// The length of `parts` spliced together, with the NUL after them.
pub const fn spliced_len(parts: &[&str]) -> usize {
    let mut len = 1;
    let mut p = 0;

    while p < parts.len() {
        len += parts[p].len();
        p += 1;
    }
    len
}

/// `parts` spliced together and a NUL after them, in the `N` bytes
/// spliced_len() counts.
///
/// # Panics
///
/// When a part holds a NUL or `N` is not their length, which in a
/// constant fails the build.
pub const fn splice<const N: usize>(parts: &[&str]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut n = 0;
    let mut p = 0;

    while p < parts.len() {
        let bytes = parts[p].as_bytes();
        let mut i = 0;

        while i < bytes.len() {
            assert!(bytes[i] != 0, "a NUL in a part");
            out[n] = bytes[i];
            n += 1;
            i += 1;
        }
        p += 1;
    }
    assert!(n + 1 == N, "not the parts' length");
    out
}

/// The C string of string constants and literals spliced together at
/// compile time, as C splices adjacent string literals and the macros
/// that stand for them.
macro_rules! c_splice {
    ($($part:expr),+ $(,)?) => {{
        const PARTS: &[&str] = &[$($part),+];
        const BYTES: [u8; $crate::ffi::spliced_len(PARTS)] = $crate::ffi::splice(PARTS);

        match ::core::ffi::CStr::from_bytes_with_nul(&BYTES) {
            Ok(s) => s,
            Err(_) => panic!("not a C string"),
        }
    }};
}
pub(crate) use c_splice;

/// The `len` elements at `ptr`; none when `len` is 0, whatever `ptr` is.
///
/// # Safety
///
/// When `len` is not 0, `ptr` points to `len` initialised elements that
/// stay valid and unchanged for `'a`.
pub unsafe fn slice<'a, T>(ptr: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    // SAFETY: the caller passes `len` valid elements at `ptr`.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// The `len` bytes of a C buffer to write into, as they are; none when
/// `len` is 0.
///
/// # Safety
///
/// When `len` is not 0, `ptr` points to `len` bytes that nothing else
/// accesses for `'a`.
pub unsafe fn bytes_mut<'a>(ptr: *mut u8, len: usize) -> &'a mut [u8] {
    if len == 0 {
        return &mut [];
    }
    // SAFETY: the caller passes len bytes at ptr, which C initialised.
    unsafe { core::slice::from_raw_parts_mut(ptr, len) }
}

/// The room for `len` elements at `ptr`, zeroed first so that memory C
/// left uninitialised can be handed to safe code; none when `len` is 0.
///
/// # Safety
///
/// When `len` is not 0, `ptr` points to room for `len` elements that
/// nothing else accesses for `'a`, and all-zero bytes are a valid `T`.
pub unsafe fn zeroed_slice_mut<'a, T>(ptr: *mut T, len: usize) -> &'a mut [T] {
    if len == 0 {
        return &mut [];
    }
    // SAFETY: the caller passes room for `len` elements at `ptr`, which
    // zeroing initialises with a valid `T`.
    unsafe {
        ptr.write_bytes(0, len);
        core::slice::from_raw_parts_mut(ptr, len)
    }
}
