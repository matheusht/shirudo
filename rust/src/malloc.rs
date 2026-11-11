// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The allocator of `util/malloc.h`, for memory that C code frees.

use core::ffi::c_void;

unsafe extern "C" {
    /// A zeroed block of `new_nmemb * size` bytes holding the start of
    /// `ptr`, which it scrubs and frees; NULL, leaving `ptr` alone, when
    /// the size overflows or the allocation fails.
    pub fn xreallocarray(
        ptr: *mut c_void,
        old_nmemb: usize,
        new_nmemb: usize,
        size: usize,
    ) -> *mut c_void;
}
