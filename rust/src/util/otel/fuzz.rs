// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-otel: a collector's response headers, its Retry-After at most
//! 30 seconds, its partial success for logs and metrics, and the headers
//! the environment configures, each a name and value fit to send.

use core::ffi::{CStr, c_char};

use super::http;
use super::{LOG, METRIC};
use crate::fuzzing::fuzz_target;
use crate::util::curl::Slist;

/// `struct curl_slist`, which the list's nodes are.
#[repr(C)]
struct SlistNode {
    data: *mut c_char,
    next: *mut SlistNode,
}

fn abort() -> ! {
    std::process::abort()
}

fuzz_target!(shirudo_fuzz_otel, shirudo_fuzz_otel_init, |data| {
    // curl hands the header callback one line at a time, end included.
    for line in data.split_inclusive(|&b| b == b'\n') {
        if http::header_retry_after(line).is_some_and(|seconds| seconds > 30) {
            abort();
        }
    }
    http::check_partial_success(LOG, data);
    http::check_partial_success(METRIC, data);
    if data.contains(&0) {
        return;
    }
    let mut headers = Slist::default();
    if http::configured_headers(&mut headers, data, false) != 0 {
        return;
    }
    let mut h = headers.raw().cast::<SlistNode>();
    // SAFETY: the list's nodes, each a C string, which it holds until it
    // goes.
    while let Some(node) = unsafe { h.as_ref() } {
        // SAFETY: as above.
        let line = unsafe { CStr::from_ptr(node.data) }.to_bytes();
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            abort();
        };
        if !http::header_name_ok(&line[..colon]) || !http::header_value_ok(&line[colon + 1..]) {
            abort();
        }
        h = node.next;
    }
});
