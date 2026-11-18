// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::sys::curl::{
    CURLOPT_NOSIGNAL, CURLOPT_PROTOCOLS_STR, CURLOPT_URL, CURLUPART_HOST, CURLUPART_SCHEME,
    CURLUPART_USER,
};
use crate::testutil::TempDir;

/// A write callback that appends what it is handed to a Vec.
unsafe extern "C" fn collect(data: *mut c_char, size: usize, n: usize, ud: *mut c_void) -> usize {
    let len = size * n;
    // SAFETY: the Vec the test set as the data, and the bytes libcurl
    // hands over.
    let (got, bytes) = unsafe {
        (
            &mut *ud.cast::<Vec<u8>>(),
            crate::ffi::slice(data.cast::<u8>(), len),
        )
    };
    got.extend_from_slice(bytes);
    len
}

/// A file:// URL of `name` in `dir`.
fn file_url(dir: &TempDir, name: &str) -> CString {
    CString::new(format!("file://{}", dir.join(name).display())).unwrap()
}

#[test]
fn handle_takes_options_and_escapes() {
    let mut easy = Easy::new().unwrap();

    assert_eq!(easy.set_long(CURLOPT_NOSIGNAL, 1), CURLE_OK);
    assert_eq!(
        easy.set_str(CURLOPT_URL, c"https://registry.example/v2/"),
        CURLE_OK
    );
    assert_ne!(easy.set_str(CURLOPT_PROTOCOLS_STR, c"no-such"), CURLE_OK);
    assert_eq!(easy.set_post_fields(b"{}"), CURLE_OK);
    assert_eq!(easy.escape(c"a b/c").unwrap(), b"a%20b%2Fc");
    assert_eq!(easy.response_code(), Some(0));
}

#[test]
fn transfer_hands_its_body_to_the_callback() {
    let dir = TempDir::new();
    std::fs::write(dir.join("body"), b"hello").unwrap();
    let url = file_url(&dir, "body");
    let mut got: Vec<u8> = Vec::new();
    let mut easy = Easy::new().unwrap();

    easy.set_str(CURLOPT_URL, &url);
    // SAFETY: collect() takes its data for the Vec, which outlives the
    // handle.
    unsafe { easy.set_write(collect, &raw mut got) };
    assert_eq!(easy.perform(), CURLE_OK);
    assert_eq!(easy.effective_url(), Some(url.as_c_str()));
    drop(easy);
    assert_eq!(got, b"hello");
}

#[test]
fn failed_transfer_leaves_its_message() {
    let dir = TempDir::new();
    let url = file_url(&dir, "missing");
    let mut errbuf = [0u8; CURL_ERROR_SIZE];
    let mut easy = Easy::new().unwrap();

    easy.set_str(CURLOPT_URL, &url);
    easy.set_error_buffer(&mut errbuf);
    let code = easy.perform();
    drop(easy);
    assert_ne!(code, CURLE_OK);
    assert_ne!(errbuf[0], 0);
    assert!(!strerror(code).is_empty());
}

#[test]
fn callback_view_leaves_the_handle_alone() {
    let easy = Easy::new().unwrap();

    // SAFETY: NULL, and a live handle whose view goes before it does.
    unsafe {
        assert!(Easy::from_callback(ptr::null_mut()).is_none());
        let view = Easy::from_callback(easy.raw()).unwrap();
        assert_eq!(view.response_code(), Some(0));
    }
    assert_eq!(easy.response_code(), Some(0));
}

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
