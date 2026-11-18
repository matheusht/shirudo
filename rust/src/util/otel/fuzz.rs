// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-otel: a collector's response headers, its Retry-After at most
//! 30 seconds, its partial success for logs and metrics, and the headers
//! the environment configures, each a name and value fit to send.

use core::ffi::{c_char, c_int};

use super::capi::{
    otel_configured_headers, otel_header_name_ok, otel_header_retry_after, otel_header_value_ok,
    otel_partial_success,
};
use super::{LOG, METRIC};
use crate::fuzzing::fuzz_target;
use crate::sys::curl::{CurlSlist, curl_slist_free_all};

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
    // curl hands the header callback one line at a time, end included and
    // not NUL-terminated: each line in a buffer of its own size.
    for line in data.split_inclusive(|&b| b == b'\n') {
        let line = line.to_vec();
        let mut seconds = 0u64;
        // SAFETY: the line's bytes and room for the seconds.
        if unsafe { otel_header_retry_after(line.as_ptr().cast(), line.len(), &mut seconds) } != 0
            && seconds > 30
        {
            abort();
        }
    }
    let body = [data, b"\0"].concat();
    // SAFETY: the body, a C string of the input's length.
    unsafe {
        otel_partial_success(LOG, body.as_ptr().cast(), data.len());
        otel_partial_success(METRIC, body.as_ptr().cast(), data.len());
    }
    if data.contains(&0) {
        return;
    }
    let mut headers: *mut CurlSlist = core::ptr::null_mut();
    // SAFETY: the body as a C string, room for the list, and the list's
    // nodes, each a C string, the list freed once.
    unsafe {
        if otel_configured_headers(body.as_ptr().cast(), &mut headers) == 0 {
            let mut h = headers.cast::<SlistNode>();
            while let Some(node) = h.as_ref() {
                let Some(colon) = libc::strchr(node.data, c_int::from(b':')).as_mut() else {
                    abort();
                };
                *colon = 0;
                let ok = otel_header_name_ok(node.data)
                    && otel_header_value_ok((colon as *mut c_char).add(1));
                *colon = b':' as c_char;
                if !ok {
                    abort();
                }
                h = node.next;
            }
        }
        curl_slist_free_all(headers);
    }
});
