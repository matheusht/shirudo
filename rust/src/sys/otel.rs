// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The OTLP export of `util/upatch_maps_otel.h` that `shirudo status`
//! sends its keepalive through.

use core::ffi::{c_char, c_int};

/// `struct otel_opts`: where and how to export, NULL strings for none.
#[repr(C)]
pub struct OtelOpts {
    pub endpoint: *const c_char,
    pub tenant_id: *const c_char,
    pub s3_uri: *const c_char,
    pub allow_insecure: bool,
    pub retries: u32,
    pub log_record_max_bytes: u32,
    pub otlp_max_bytes: u32,
}

const _: () = assert!(size_of::<OtelOpts>() == 40);

unsafe extern "C" {
    /// Sends the `body_len` bytes of JSON at `body_json` as the body of
    /// one OTLP log; a `tamper_attempts` of 0 or more rides along as an
    /// attribute. 0 or -errno.
    pub fn otel_send_log_json(
        opts: *const OtelOpts,
        scope_name: *const c_char,
        event_name: *const c_char,
        severity_number: c_int,
        severity_text: *const c_char,
        status: *const c_char,
        version_id: *const c_char,
        tamper_attempts: i64,
        body_json: *const c_char,
        body_len: usize,
    ) -> c_int;
    /// The OTLP severity of a status verdict, its text into `text`.
    pub fn status_otel_severity(status: *const c_char, text: *mut *const c_char) -> c_int;
}
