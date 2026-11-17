// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The allocator of every Rust allocation, and of the xmalloc family
//! `util/malloc.h` declares for C: memory comes zeroed from the C library
//! and is scrubbed before it goes back.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::sys::libc::{calloc, explicit_bzero, free, posix_memalign};

/// The alignment malloc gives every block on the supported targets.
const MALLOC_ALIGN: usize = 16;

struct Scrubbing;

// SAFETY: the C library allocates and frees every block; Scrubbing hands
// out zeroed blocks of the size and alignment asked, and zeroes a block
// handed back before freeing it.
unsafe impl GlobalAlloc for Scrubbing {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let mut block = ptr::null_mut();

        if layout.align() <= MALLOC_ALIGN {
            // SAFETY: calloc() takes any size.
            return unsafe { calloc(1, layout.size()) }.cast();
        }
        // SAFETY: a layout's alignment is a power of two, here above 16
        // and so a multiple of the pointer size posix_memalign() needs.
        if unsafe { posix_memalign(&mut block, layout.align(), layout.size()) } != 0 {
            return ptr::null_mut();
        }
        // SAFETY: posix_memalign() gave layout.size() bytes at block.
        unsafe { block.cast::<u8>().write_bytes(0, layout.size()) };
        block.cast()
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        // SAFETY: the caller hands back the layout.size() bytes at block
        // that alloc() gave, and touches them no more.
        unsafe {
            explicit_bzero(block.cast(), layout.size());
            free(block.cast());
        }
    }

    // As xreallocarray(): a new zeroed block, and the old one scrubbed.
    unsafe fn realloc(&self, block: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: realloc's caller guarantees that new_size with the old
        // alignment is a valid layout.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        // SAFETY: new_layout is valid and its size not zero.
        let new = unsafe { self.alloc(new_layout) };

        if !new.is_null() {
            // SAFETY: both blocks hold the bytes copied, and only the old
            // one, which the caller hands back, goes.
            unsafe {
                ptr::copy_nonoverlapping(block, new, layout.size().min(new_size));
                self.dealloc(block, layout);
            }
        }
        new
    }
}

#[global_allocator]
static ALLOCATOR: Scrubbing = Scrubbing;

/// The allocator of `util/malloc.h`, for memory that C code frees or
/// hands over and that Rust code hands to C: zeroed when it is given out
/// and scrubbed when it comes back, as every Rust allocation is.
pub(crate) use capi::{
    libc_free, xcalloc, xfree, xmalloc, xreallocarray, xstrdup, xstrfree, xstrndup,
};

mod capi {
    use core::ffi::{c_char, c_void};
    use core::ptr;

    use crate::sys::libc::{calloc, explicit_bzero, free, strlen, strnlen};

    /// A zeroed block of `size` bytes, of one for 0, so that NULL means
    /// out of memory and nothing else: a one-shot command reports -ENOMEM
    /// up its normal path rather than dying.
    ///
    /// # Safety
    ///
    /// None beyond the C library's allocator.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xmalloc(size: usize) -> *mut c_void {
        // SAFETY: calloc() takes any size.
        unsafe { calloc(1, size.max(1)) }
    }

    /// A zeroed block of `nmemb * size` bytes; NULL when the product
    /// overflows, which a caller computing it would miss.
    ///
    /// # Safety
    ///
    /// None beyond the C library's allocator.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xcalloc(nmemb: usize, size: usize) -> *mut c_void {
        match nmemb.checked_mul(size) {
            // SAFETY: a size alone.
            Some(bytes) => unsafe { xmalloc(bytes) },
            None => ptr::null_mut(),
        }
    }

    /// A fresh zeroed block of `new_nmemb * size` bytes holding what fits
    /// of `ptr`'s `old_nmemb * size`, which it scrubs and frees, so that
    /// nothing lingers where a realloc would shrink in place or move.
    /// NULL, leaving `ptr` alone, when a size overflows or the allocation
    /// fails.
    ///
    /// # Safety
    ///
    /// `ptr` is NULL or a block of `old_nmemb * size` bytes from this
    /// allocator, which the caller stops using on success.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xreallocarray(
        old: *mut c_void,
        old_nmemb: usize,
        new_nmemb: usize,
        size: usize,
    ) -> *mut c_void {
        let (Some(old_size), Some(new_size)) =
            (old_nmemb.checked_mul(size), new_nmemb.checked_mul(size))
        else {
            return ptr::null_mut();
        };
        // SAFETY: a size alone.
        let new = unsafe { xmalloc(new_size) };
        if !new.is_null() && !old.is_null() {
            // SAFETY: the caller's block and the new one, each holding
            // the bytes copied; the old one goes.
            unsafe {
                ptr::copy_nonoverlapping(
                    old.cast::<u8>(),
                    new.cast::<u8>(),
                    old_size.min(new_size),
                );
                xfree(old, old_size);
            }
        }
        new
    }

    /// A copy of the C string `s` for xstrfree(); NULL for NULL or when
    /// the allocation fails.
    ///
    /// # Safety
    ///
    /// `s` is NULL or a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xstrdup(s: *const c_char) -> *mut c_char {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's C string.
        unsafe { xstrndup(s, strlen(s)) }
    }

    /// A copy of at most `n` bytes of the C string `s`, NUL-terminated,
    /// for xstrfree(); NULL for NULL or when the allocation fails.
    ///
    /// # Safety
    ///
    /// `s` is NULL, or a C string or `n` readable bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xstrndup(s: *const c_char, n: usize) -> *mut c_char {
        if s.is_null() {
            return ptr::null_mut();
        }
        // SAFETY: the caller's string, read up to its NUL or n bytes.
        let len = unsafe { strnlen(s, n) };
        // SAFETY: a size alone.
        let p = unsafe { calloc(1, len + 1) }.cast::<c_char>();
        if !p.is_null() {
            // SAFETY: len bytes of the string into a block of len + 1,
            // whose last byte calloc() zeroed.
            unsafe { ptr::copy_nonoverlapping(s, p, len) };
        }
        p
    }

    /// Scrubs the `size` bytes at `p` and frees them; nothing for NULL.
    ///
    /// # Safety
    ///
    /// `p` is NULL or a block of at least `size` bytes from this
    /// allocator, which the caller stops using.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xfree(p: *mut c_void, size: usize) {
        if p.is_null() {
            return;
        }
        // SAFETY: the caller's block, scrubbed, then freed once.
        unsafe {
            explicit_bzero(p, size);
            free(p);
        }
    }

    /// Scrubs and frees a string xstrdup() or xstrndup() gave; nothing
    /// for NULL.
    ///
    /// # Safety
    ///
    /// `s` is NULL or such a string, which the caller stops using.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn xstrfree(s: *mut c_char) {
        if s.is_null() {
            return;
        }
        // SAFETY: the caller's string, with its NUL.
        unsafe { xfree(s.cast(), strlen(s) + 1) };
    }

    /// Frees what the C library or a library on it allocated, as
    /// scandir(), getline() and realpath() do; the one path for that
    /// memory, since C code may not name free().
    ///
    /// # Safety
    ///
    /// `p` is NULL or a block the C library's malloc gave.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn libc_free(p: *mut c_void) {
        // SAFETY: the caller's block, freed once.
        unsafe { free(p) };
    }
}
