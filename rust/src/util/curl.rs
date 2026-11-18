// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! curl's header lists, scrubbed before they are freed: libcurl copies a
//! header curl_slist_append() takes, so a Basic or bearer authorization
//! outlives the buffer its caller scrubbed, in freed heap memory.

use core::ffi::c_char;

use crate::sys::curl::{CurlSlist, curl_slist_free_all};

/// `struct curl_slist` of curl/curl.h, which libcurl declares public.
#[repr(C)]
struct Node {
    data: *mut c_char,
    next: *mut Node,
}

/// Zeroes the data of each entry of `headers`, then frees the list.
///
/// # Safety
///
/// `headers` is NULL or a list curl_slist_append() built, freed once,
/// after the easy handles that used it are done with it.
pub(crate) unsafe fn slist_free_sensitive(headers: *mut CurlSlist) {
    let mut entry = headers.cast::<Node>();

    while !entry.is_null() {
        // SAFETY: an entry of the caller's list.
        let node = unsafe { &*entry };

        if !node.data.is_null() {
            // SAFETY: the entry's C string, its terminator included,
            // written a byte at a time so that no store is elided.
            unsafe {
                let len = crate::sys::libc::strlen(node.data) + 1;
                for i in 0..len {
                    core::ptr::write_volatile(node.data.add(i), 0);
                }
            }
        }
        entry = node.next;
    }
    // SAFETY: the caller's list, freed once.
    unsafe { curl_slist_free_all(headers) };
}

mod capi {
    use crate::sys::curl::CurlSlist;

    /// # Safety
    ///
    /// As [`super::slist_free_sensitive`].
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn curl_slist_free_sensitive(headers: *mut CurlSlist) {
        // SAFETY: the caller's list.
        unsafe { super::slist_free_sensitive(headers) }
    }
}
