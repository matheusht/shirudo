// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-config: map_export.* and eventlog.max_bytes of shirudo.conf
//! parsed, each case a file the parser reads; exits 0 when every one
//! parses as it should.

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;

use super::helper_main;
use crate::text::cstr;
use crate::util::config::{Config, LOG_RECORD_MAX_DEFAULT, OTLP_MAX_DEFAULT, load_path};

helper_main!(shirudo_helper_test_config, run);

/// The config `contents` give, written to `path` first; None for a
/// file that would not write or load.
fn load(path: &CStr, contents: Option<&str>) -> Option<Box<Config>> {
    let file = std::path::Path::new(std::ffi::OsStr::from_bytes(path.to_bytes()));
    match contents {
        Some(text) => std::fs::write(file, text).ok()?,
        None => {
            let _ = std::fs::remove_file(file);
        }
    }
    let mut cfg = Box::new(Config::zeroed());
    (load_path(&mut cfg, path) == 0).then_some(cfg)
}

fn defaults(path: &CStr) -> bool {
    load(path, None).is_some_and(|c| {
        c.map_export_valid
            && cstr(&c.map_export_json_path).is_empty()
            && cstr(&c.map_export_tenant_id).is_empty()
            && c.map_export_otel_retries == 3
            && c.map_export_log_record_max_bytes == LOG_RECORD_MAX_DEFAULT
            && c.map_export_otlp_max_bytes == OTLP_MAX_DEFAULT
    })
}

fn valid(path: &CStr) -> bool {
    const INPUT: &str = "map_export.json_path = /var/log/shirudo/maps.ndjson\n\
                         map_export.otel_endpoint = https://collector.example:4318\n\
                         map_export.tenant_id = tenant-uuid-1234\n\
                         map_export.otel_insecure = true\n\
                         map_export.otel_retries = 7\n\
                         map_export.s3_uri = s3://bucket/prefix\n\
                         map_export.log_record_max_bytes = 1024\n\
                         map_export.otlp_max_bytes = 2048\n\
                         map_export.s3_uri = s3://bucket/prefix\n";
    load(path, Some(INPUT)).is_some_and(|c| {
        c.map_export_valid
            && cstr(&c.map_export_json_path) == b"/var/log/shirudo/maps.ndjson"
            && cstr(&c.map_export_otel_endpoint) == b"https://collector.example:4318"
            && cstr(&c.map_export_tenant_id) == b"tenant-uuid-1234"
            && c.map_export_otel_insecure
            && c.map_export_otel_retries == 7
            && cstr(&c.map_export_s3_uri) == b"s3://bucket/prefix"
            && c.map_export_log_record_max_bytes == 1024
            && c.map_export_otlp_max_bytes == 2048
    })
}

/// A file that loads with its map export refused.
fn invalid(path: &CStr, input: &str) -> bool {
    load(path, Some(input)).is_some_and(|c| !c.map_export_valid)
}

/// A bad eventlog.max_bytes is ignored, leaving the default of 0.
fn max_bytes(path: &CStr, value: &str, expected: u64) -> bool {
    load(path, Some(&format!("eventlog.max_bytes = {value}\n")))
        .is_some_and(|c| c.eventlog_max_bytes == expected)
}

fn run(_: &[&CStr]) -> c_int {
    let Ok(file) = tempfile_in_tmp() else {
        return 1;
    };
    let path = file.as_c_str();
    let long_tenant = format!("map_export.tenant_id = {}\n", "a".repeat(129));
    let invalid_inputs = [
        "map_export.json_path = relative.json\n",
        "map_export.otel_retries = 11\n",
        "map_export.otel_retries = +5\n",
        "map_export.otel_retries = -1\n",
        "map_export.otel_insecure = yes\n",
        "map_export.otlp_max_bytes = 0\n",
        "map_export.otlp_max_bytes = +1024\n",
        "map_export.otlp_max_bytes = 0x400\n",
        "map_export.otlp_max_bytes = 1024\nmap_export.log_record_max_bytes = 2048\n",
        "map_export.tenant_id = tenant uuid\n",
        "map_export.tenant_id = tenant/id\n",
        &long_tenant,
        "map_export.unknown = value\n",
    ];
    let max_bytes_cases = [
        ("1048576", 1_048_576),
        ("010", 10),
        ("0x10", 0),
        ("+16", 0),
        ("-1", 0),
        ("", 0),
    ];

    let ok = defaults(path)
        & valid(path)
        & invalid_inputs
            .iter()
            .fold(true, |ok, input| invalid(path, input) & ok)
        & max_bytes_cases
            .iter()
            .fold(true, |ok, &(v, n)| max_bytes(path, v, n) & ok);
    let _ = std::fs::remove_file(std::ffi::OsStr::from_bytes(path.to_bytes()));
    c_int::from(!ok)
}

/// A new file of its own in /tmp, as mkstemp() makes one.
fn tempfile_in_tmp() -> std::io::Result<CString> {
    let mut template = *b"/tmp/shirudo-config-test.XXXXXX\0";
    // SAFETY: a template mkstemp() fills in place.
    let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the descriptor mkstemp() gave, closed once.
    unsafe { libc::close(fd) };
    Ok(CStr::from_bytes_with_nul(&template)
        .map_err(std::io::Error::other)?
        .to_owned())
}
