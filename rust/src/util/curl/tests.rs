// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::sys::curl::curl_slist_append;

#[test]
fn sensitive_header_is_scrubbed_before_free() {
    let header = c"Authorization: Bearer secret";
    // SAFETY: a new list of one C string, which libcurl copies.
    let headers = unsafe { curl_slist_append(core::ptr::null_mut(), header.as_ptr()) };
    assert!(!headers.is_null());
    // SAFETY: the list's one entry.
    let data = unsafe { (*headers.cast::<Node>()).data };

    // SAFETY: the list just built, read back before it is freed once.
    unsafe {
        slist_scrub(headers);
        let scrubbed = core::slice::from_raw_parts(data.cast::<u8>(), header.count_bytes() + 1);
        assert!(scrubbed.iter().all(|&b| b == 0));
        curl_slist_free_all(headers);
    }
}
