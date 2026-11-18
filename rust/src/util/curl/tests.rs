// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::sys::curl::{CURLUPART_HOST, CURLUPART_SCHEME, CURLUPART_USER};

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

#[test]
fn header_with_a_nul_is_refused() {
    let mut headers = Slist::default();

    assert_eq!(headers.append(b"Accept: a\0b"), -EINVAL);
    assert!(headers.raw().is_null());
    assert_eq!(headers.append(b"Accept: a"), 0);
    assert!(!headers.raw().is_null());
}

#[test]
fn url_gives_its_parts() {
    let url = Url::parse(b"https://Registry.Example:5000/v2/").unwrap();

    assert_eq!(url.part(CURLUPART_SCHEME).unwrap(), b"https");
    assert_eq!(url.part(CURLUPART_HOST).unwrap(), b"Registry.Example");
    assert_eq!(url.part(CURLUPART_USER), None);
}

#[test]
fn url_libcurl_refuses_is_invalid() {
    assert_eq!(Url::parse(b"https://a\0b/").err(), Some(-EINVAL));
    assert_eq!(Url::parse(b"no scheme").err(), Some(-EINVAL));
}
