// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! libcurl's header lists and URLs, freed when they go. A list is
//! scrubbed first: libcurl copies a line curl_slist_append() takes, so a
//! Basic or bearer authorization would outlive the buffer its caller
//! scrubbed, in freed heap memory.

use core::ffi::{CStr, c_char, c_int};
use core::ptr::{self, NonNull};
use std::ffi::CString;

use crate::errno::{EINVAL, ENOMEM};
use crate::sys::curl::{
    CURLUE_OK, CURLUPART_URL, CurlSlist, CurlU, CurlUPart, curl_free, curl_slist_append,
    curl_slist_free_all, curl_url, curl_url_cleanup, curl_url_get, curl_url_set,
};

/// A transfer's header lines, scrubbed and freed when it goes.
pub(crate) struct Slist(*mut CurlSlist);

impl Default for Slist {
    fn default() -> Self {
        Slist(ptr::null_mut())
    }
}

impl Slist {
    /// `line` appended: -EINVAL for a line with a NUL in it, or -ENOMEM.
    pub(crate) fn append(&mut self, line: &[u8]) -> c_int {
        let Ok(line) = CString::new(line) else {
            return -EINVAL;
        };
        // SAFETY: the list or NULL, and a C string, which curl copies.
        let next = unsafe { curl_slist_append(self.0, line.as_ptr()) };
        if next.is_null() {
            return -ENOMEM;
        }
        self.0 = next;
        0
    }

    /// The list as libcurl takes it, NULL while it is empty.
    pub(crate) fn raw(&self) -> *mut CurlSlist {
        self.0
    }
}

impl Drop for Slist {
    fn drop(&mut self) {
        // SAFETY: the list or NULL, which no handle uses any more.
        unsafe { slist_scrub(self.0) };
        // SAFETY: as above, freed once.
        unsafe { curl_slist_free_all(self.0) };
    }
}

/// `struct curl_slist` of curl/curl.h, which libcurl declares public.
#[repr(C)]
struct Node {
    data: *mut c_char,
    next: *mut Node,
}

/// Zeroes the data of each entry of `headers`, terminators included.
///
/// # Safety
///
/// `headers` is NULL or a list curl_slist_append() built.
unsafe fn slist_scrub(headers: *mut CurlSlist) {
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
}

/// A URL libcurl parsed, freed when it goes.
pub(crate) struct Url(NonNull<CurlU>);

impl Url {
    /// `url` as libcurl parses it: -ENOMEM, or -EINVAL for a URL with a
    /// NUL in it or one libcurl refuses.
    pub(crate) fn parse(url: &[u8]) -> Result<Self, c_int> {
        // SAFETY: a call that takes nothing.
        let u = Url(NonNull::new(unsafe { curl_url() }).ok_or(-ENOMEM)?);
        let url = CString::new(url).map_err(|_| -EINVAL)?;
        // SAFETY: the handle, and a C string, which libcurl copies.
        if unsafe { curl_url_set(u.0.as_ptr(), CURLUPART_URL, url.as_ptr(), 0) } != CURLUE_OK {
            return Err(-EINVAL);
        }
        Ok(u)
    }

    /// The part `what` of the URL, None when libcurl gives none.
    pub(crate) fn part(&self, what: CurlUPart) -> Option<Vec<u8>> {
        let mut part: *mut c_char = ptr::null_mut();
        // SAFETY: the handle, and room for the C string libcurl allocates.
        let got = unsafe { curl_url_get(self.0.as_ptr(), what, &mut part, 0) } == CURLUE_OK;
        if part.is_null() {
            return got.then(Vec::new);
        }
        // SAFETY: libcurl's C string.
        let bytes = unsafe { CStr::from_ptr(part) }.to_bytes().to_vec();
        // SAFETY: what libcurl allocated, freed once.
        unsafe { curl_free(part.cast()) };
        got.then_some(bytes)
    }
}

impl Drop for Url {
    fn drop(&mut self) {
        // SAFETY: the handle, freed once.
        unsafe { curl_url_cleanup(self.0.as_ptr()) };
    }
}

#[cfg(test)]
mod tests;
