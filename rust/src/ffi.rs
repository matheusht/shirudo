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
