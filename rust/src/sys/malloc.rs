// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The allocator of `util/malloc.h`, for memory that C code frees or
//! hands over.

use core::ffi::{c_char, c_void};

unsafe extern "C" {
    /// A zeroed block of `size` bytes, of one for 0; NULL when the
    /// allocation fails.
    pub fn xmalloc(size: usize) -> *mut c_void;
    /// A zeroed block of `nmemb * size` bytes; NULL when the size
    /// overflows or the allocation fails.
    pub fn xcalloc(nmemb: usize, size: usize) -> *mut c_void;
    /// A zeroed block of `new_nmemb * size` bytes holding the start of
    /// `ptr`, which it scrubs and frees; NULL, leaving `ptr` alone, when
    /// the size overflows or the allocation fails.
    pub fn xreallocarray(
        ptr: *mut c_void,
        old_nmemb: usize,
        new_nmemb: usize,
        size: usize,
    ) -> *mut c_void;
    /// Scrubs `size` bytes at `ptr` and frees them; nothing for NULL.
    pub fn xfree(ptr: *mut c_void, size: usize);
    /// A copy of the C string `s`, which it trusts to end, for
    /// xstrfree(); NULL when the allocation fails.
    pub fn xstrdup(s: *const c_char) -> *mut c_char;
    /// A copy of at most `n` bytes of the C string `s`, NUL-terminated,
    /// for xstrfree(); NULL when the allocation fails.
    pub fn xstrndup(s: *const c_char, n: usize) -> *mut c_char;
    /// Scrubs and frees what xstrndup() gave; NULL is nothing to free.
    pub fn xstrfree(s: *mut c_char);
}
