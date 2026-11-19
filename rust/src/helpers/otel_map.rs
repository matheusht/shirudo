// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-otel-map: the OTLP export of a upatch map, offline and against a
//! collector or S3 endpoint the test runs: how a map classifies, the log
//! and metric payloads a decoder makes of it, the sends with their
//! limits, retries, tenants and transports, and the validation that
//! refuses a bad tenant, S3 setting or insecure endpoint.
//!
//!   test-otel-map classify-unsigned|classify-signed|classify-array|classify-hash|classify-lru-hash|classify-no-btf|classify-serialized
//!   test-otel-map log|log-no-location|metric|counter|local-json|record-size
//!   test-otel-map send-log|send-log-insecure <url> <retries>
//!   test-otel-map send-log-limits <url> <retries> <record max> <request max>
//!   test-otel-map send-log-env <retries> | send-metric-env
//!   test-otel-map send-auto-log|send-auto-metric|send-metric <url>
//!   test-otel-map send-keepalive <url> <verdict> <body> <quote>
//!   test-otel-map send-s3|send-s3-large <endpoint> <retries>
//!   test-otel-map s3-validation|tenant-validation|security
//!   test-otel-map retry-after <value> <now>
//!
//! make links it with testing/helper/version.rs for the version "test-1".

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;

use super::{helper_main, out, out_bytes};
use crate::btf_builder::BtfBuilder;
use crate::errno::{E2BIG, EACCES, EINVAL, EOPNOTSUPP, EOVERFLOW, EPERM};
use crate::sys::upatch_maps::{MapEntry, MapView, SerialPage};
use crate::util::decode::{JSON_MAX, decode_map};
use crate::util::json::JsonEmit;
use crate::util::map_render::emit_json_fields;
use crate::util::otel::{
    AUTO, FORCE_LOG, FORCE_METRIC, METRIC, OtelOpts, S3, classify, payload_file, retry_after,
    send_file, send_log_string, status_severity,
};
use crate::util::upatch::{
    DECODER_MAGIC, HEADER_SIZE, MAGIC, SECTION_DECODERS, SIGNED_TRAILER_MAGIC, SIGNED_VERSION,
    TYPE_BPF, VERSION,
};

helper_main!(shirudo_helper_test_otel_map, run);

const BPF_MAP_TYPE_ARRAY: u32 = 2;
const BPF_MAP_TYPE_PERCPU_HASH: u32 = 5;
const BPF_MAP_TYPE_PERCPU_ARRAY: u32 = 6;
const BPF_MAP_TYPE_LRU_PERCPU_HASH: u32 = 10;
const KEEPALIVE_BODY_FILE_MAX: u64 = 64 * 1024;
/// The language and input of a .upatch's decoder.
const DECODER_LANG_LUA: u32 = 1;
const DECODER_INPUT_MAP_V1: u32 = 1;
const DECODER_EXPORT_LOG: u32 = 1;
const DECODER_EXPORT_METRIC: u32 = 2;
const DECODER_BLOB: usize = 16;
const DECODER_ENTRY: usize = 200;
const SIGNED_SECTION: usize = 16;
const SIGNED_TRAILER: usize = 16;

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_str(b: &mut [u8], s: &str) {
    let n = s.len().min(b.len() - 1);
    b[..n].copy_from_slice(&s.as_bytes()[..n]);
    b[n] = 0;
}

/// As strtoul() of base 10, which the C helper called: the leading
/// digits, 0 for none.
fn number(text: &CStr) -> u64 {
    let t = text.to_bytes();
    let n = t.iter().take_while(|c| c.is_ascii_digit()).count();
    std::str::from_utf8(&t[..n])
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(0)
}

/// A decoder artifact made for the case, removed when it goes.
struct Decoder(CString);

impl Drop for Decoder {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(OsStr::from_bytes(self.0.to_bytes()));
    }
}

/// The smallest valid artifact carrying a decoder, for offline tests: a
/// log decoder, a gauge or counter metric decoder, or one that hands its
/// input back for a snapshot. Its sections start at odd offsets, after a
/// one-byte signature.
fn make_decoder(metric: bool, counter: bool, snapshot: bool) -> Result<Decoder, c_int> {
    const LOG: &str = "function decode(input)\n\treturn { data = { entries = {{ values_per_cpu = { \"5\", \"7\" }, sum = \"12\" }} } }\nend\n";
    const SNAPSHOT: &str = "function decode(input)\n\treturn input\nend\n";
    const GAUGE: &str = "function decode(input)\n\treturn {{ name = \"shirudo.test.hits\", unit = \"1\", gauge = { dataPoints = {{ asInt = \"12\" }} } }}\nend\n";
    const COUNTER: &str = "function decode(input)\n\treturn {{ name = \"shirudo.test.hits\", unit = \"1\", sum = { aggregationTemporality = 2, isMonotonic = true, dataPoints = {{ startTimeUnixNano = \"1544712660300000000\", timeUnixNano = \"1700000000000000000\", asInt = \"12\" }} } }}\nend\n";
    let source = match (snapshot, metric, counter) {
        (true, _, _) => SNAPSHOT,
        (false, true, true) => COUNTER,
        (false, true, false) => GAUGE,
        _ => LOG,
    };
    let entries_end = DECODER_BLOB + DECODER_ENTRY;
    let decoder_len = entries_end + source.len();
    let dir_off = (decoder_len + 7) & !7;
    let data_len = dir_off + SIGNED_SECTION + SIGNED_TRAILER;
    let loader_off = HEADER_SIZE;
    let sig_off = loader_off + 8;
    let data_off = sig_off + 1;
    let file_len = data_off + data_len;
    if file_len > u32::MAX as usize {
        return Err(-EOVERFLOW);
    }
    let mut f = vec![0u8; file_len];
    f[..8].copy_from_slice(&MAGIC.to_le_bytes());
    put32(&mut f, 8, VERSION);
    put_str(&mut f[16..16 + 256], "test-upatch");
    for (i, v) in [loader_off, 8, sig_off, 1, 0, 0, data_off, data_len]
        .into_iter()
        .enumerate()
    {
        put32(&mut f, 304 + 4 * i, v as u32);
    }
    put32(&mut f, HEADER_SIZE - 8, TYPE_BPF);
    let d = data_off;
    for (i, v) in [DECODER_MAGIC, 1, 1].into_iter().enumerate() {
        put32(&mut f, d + 4 * i, v);
    }
    let e = d + DECODER_BLOB;
    let export = if metric {
        DECODER_EXPORT_METRIC
    } else {
        DECODER_EXPORT_LOG
    };
    for (i, v) in [DECODER_LANG_LUA, 1, DECODER_INPUT_MAP_V1, export]
        .into_iter()
        .enumerate()
    {
        put32(&mut f, e + 4 * i, v);
    }
    put_str(&mut f[e + 16..e + 80], "test-upatch");
    put_str(&mut f[e + 80..e + 96], "hits_total");
    put_str(&mut f[e + 96..e + 160], "test.lua");
    put_str(&mut f[e + 160..e + 192], "decode");
    put32(&mut f, e + 192, entries_end as u32);
    put32(&mut f, e + 196, source.len() as u32);
    f[d + entries_end..d + entries_end + source.len()].copy_from_slice(source.as_bytes());
    let s = d + dir_off;
    put32(&mut f, s, SECTION_DECODERS);
    put32(&mut f, s + 12, decoder_len as u32);
    for (i, v) in [SIGNED_TRAILER_MAGIC, SIGNED_VERSION, dir_off as u32, 1]
        .into_iter()
        .enumerate()
    {
        put32(&mut f, s + SIGNED_SECTION + 4 * i, v);
    }

    let mut template = *b"/tmp/test-otel-map-decoder-XXXXXX\0";
    // SAFETY: a template mkstemp() fills in place.
    let fd = unsafe { libc::mkstemp(template.as_mut_ptr().cast()) };
    if fd < 0 {
        return Err(-std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO));
    }
    let path = Decoder(
        CStr::from_bytes_with_nul(&template)
            .map_err(|_| -EINVAL)?
            .to_owned(),
    );
    // SAFETY: the file mkstemp() made, written and closed once.
    let ret = unsafe {
        let ret = crate::util::io::write_complete(fd, f.as_ptr().cast(), f.len());
        if libc::close(fd) != 0 && ret == 0 {
            -std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::EIO)
        } else {
            ret
        }
    };
    if ret != 0 { Err(ret) } else { Ok(path) }
}

/// A map of one entry, 5 and 7 on two CPUs with a poisoned pad between,
/// and its BTF when asked.
fn fixture(map_type: u32, is_signed: bool, with_btf: bool) -> Option<MapView> {
    let array = map_type == BPF_MAP_TYPE_ARRAY;
    let (value_stride, n_cpus) = if array { (4, 1) } else { (8, 2) };
    let mut values = [0u8; 16];
    values[..4].copy_from_slice(&5u32.to_ne_bytes());
    values[4..8].copy_from_slice(&0xdead_beef_u32.to_ne_bytes());
    values[8..12].copy_from_slice(&7u32.to_ne_bytes());
    let mut f = MapView {
        ty: map_type,
        type_name: Some(if array { c"array" } else { c"percpu_array" }),
        key_size: 4,
        value_size: 4,
        value_stride,
        max_entries: 1,
        n_cpus,
        lifetime_start_ns: 1_544_712_660_300_000_000,
        entries: vec![MapEntry {
            key: 0u32.to_ne_bytes().to_vec(),
            value: values[..(value_stride * n_cpus) as usize].to_vec(),
        }],
        ..MapView::default()
    };
    put_str(&mut f.upatch, "test-upatch");
    put_str(&mut f.name, "hits_total");
    put_str(&mut f.location, "fentry/test_hook");
    if !with_btf {
        return Some(f);
    }
    let mut b = BtfBuilder::new();
    let key_int = b.int("unsigned int", 4, 0);
    let value_int = b.int(
        if is_signed { "int" } else { "unsigned int" },
        4,
        u32::from(is_signed),
    );
    let key_type = b.typedef("__u32", key_int);
    let value_type = b.typedef(if is_signed { "__s32" } else { "__u32" }, value_int);
    // The view reads BTF as shirudo parses it.
    f.btf = Some(b.parse().ok()?);
    f.key_type_id = key_type;
    f.value_type_id = value_type;
    put_str(&mut f.btf_key_type, "__u32");
    put_str(
        &mut f.btf_value_type,
        if is_signed { "__s32" } else { "__u32" },
    );
    Some(f)
}

/// One serialized page of 1024 bytes in place of the entries.
fn large_serialized(f: &mut MapView) {
    const BYTES: u32 = 1024;
    f.serialized = true;
    f.entries.clear();
    f.serial_pages = vec![SerialPage {
        page_index: 0,
        cursor: 0,
        next_cursor: 1,
        flags: 1,
        chunks: 128,
        done: true,
        data: vec![b'A'; BYTES as usize],
    }];
    f.serial_bytes_total = u64::from(BYTES);
}

fn opts() -> OtelOpts {
    OtelOpts {
        endpoint: core::ptr::null(),
        tenant_id: core::ptr::null(),
        s3_uri: core::ptr::null(),
        allow_insecure: false,
        retries: 0,
        log_record_max_bytes: 0,
        otlp_max_bytes: 0,
    }
}

fn exit(ret: c_int) -> c_int {
    c_int::from(ret != 0)
}

fn print_classification(ty: u32, is_signed: bool, with_btf: bool, serialized: bool) -> c_int {
    let Some(mut f) = fixture(ty, is_signed, with_btf) else {
        return 1;
    };
    f.serialized = serialized;
    let (signal, reason) = classify(&f);
    out(&format!(
        "{}:{reason}\n",
        if signal == METRIC { "metric" } else { "log" }
    ));
    0
}

fn print_payload(metric: bool, counter: bool, with_location: bool) -> c_int {
    let Some(mut f) = fixture(BPF_MAP_TYPE_PERCPU_ARRAY, false, true) else {
        return 1;
    };
    if !with_location {
        f.location[0] = 0;
    }
    let payload = make_decoder(metric, counter, false).and_then(|d| payload_file(&d.0, &f, metric));
    match payload {
        Ok(p) => {
            out_bytes(&p);
            0
        }
        Err(_) => 1,
    }
}

fn print_local_json() -> c_int {
    let Some(f) = fixture(BPF_MAP_TYPE_PERCPU_ARRAY, false, true) else {
        return 1;
    };
    let mut buf = [0u8; 4096];
    let mut e = JsonEmit::fixed(&mut buf);
    e.obj_open();
    emit_json_fields(&mut e, &f);
    e.obj_close();
    let err = e.err();
    if err == 0 {
        out_bytes(crate::text::cstr(&buf));
    }
    exit(err)
}

/// The fixture sent through a decoder made for it, as `mode` says.
fn send(
    f: &MapView,
    metric: bool,
    counter: bool,
    snapshot: bool,
    mode: c_int,
    o: &OtelOpts,
) -> c_int {
    match make_decoder(metric, counter, snapshot) {
        Ok(d) => send_file(Some(&d.0), f, mode, Some(o)),
        Err(e) => e,
    }
}

fn send_percpu(metric: bool, mode: c_int, o: &OtelOpts) -> c_int {
    match fixture(BPF_MAP_TYPE_PERCPU_ARRAY, false, true) {
        Some(f) => exit(send(&f, metric, false, false, mode, o)),
        None => 1,
    }
}

fn print_record_size() -> c_int {
    let Some(f) = fixture(BPF_MAP_TYPE_PERCPU_ARRAY, false, true) else {
        return 1;
    };
    let d = match make_decoder(false, false, false) {
        Ok(d) => d,
        Err(_) => return 1,
    };
    let ret = match decode_map(&f, Some(&d.0), true, JSON_MAX) {
        Ok(decoded) => {
            out(&format!("{}\n", decoded.len()));
            0
        }
        Err(ret) => ret,
    };
    exit(ret)
}

fn send_auto(base: &CStr, is_signed: bool) -> c_int {
    let Some(f) = fixture(BPF_MAP_TYPE_PERCPU_ARRAY, is_signed, true) else {
        return 1;
    };
    let o = OtelOpts {
        endpoint: base.as_ptr(),
        ..opts()
    };
    exit(send(&f, !is_signed, !is_signed, false, AUTO, &o))
}

fn send_keepalive(url: &CStr, verdict: &CStr, body_path: &CStr, quote: &CStr) -> c_int {
    let mut body = Vec::new();
    let read = std::fs::File::open(OsStr::from_bytes(body_path.to_bytes()))
        .and_then(|f| f.take(KEEPALIVE_BODY_FILE_MAX + 1).read_to_end(&mut body));
    if read.is_err() || body.len() as u64 > KEEPALIVE_BODY_FILE_MAX {
        return 1;
    }
    let (severity, text) = status_severity(verdict.to_bytes());
    let o = OtelOpts {
        endpoint: url.as_ptr(),
        ..opts()
    };
    exit(send_log_string(
        Some(&o),
        b"shirudo.keepalive",
        b"shirudo.keepalive",
        severity,
        text.to_bytes(),
        &body,
        b"shirudo.quote",
        quote.to_bytes(),
    ))
}

/// Sets the environment variable, as the C helper's setenv() did.
fn set(name: &str, value: impl AsRef<OsStr>) {
    // SAFETY: the environment, which this one thread alone touches.
    unsafe { std::env::set_var(name, value) };
}

fn unset(name: &str) {
    // SAFETY: as set().
    unsafe { std::env::remove_var(name) };
}

fn send_s3(endpoint: &CStr, retries: u32, large: bool) -> c_int {
    let uri = std::env::var_os("SHIRUDO_TEST_S3_URI")
        .and_then(|u| CString::new(u.as_bytes()).ok())
        .unwrap_or_else(|| c"s3://test-bucket/prefix".to_owned());
    let o = OtelOpts {
        s3_uri: uri.as_ptr(),
        tenant_id: if large {
            core::ptr::null()
        } else {
            c"tenant-uuid-1234".as_ptr()
        },
        otlp_max_bytes: if large { 1024 } else { 0 },
        retries,
        ..opts()
    };
    set(
        "AWS_ENDPOINT_URL_S3",
        OsStr::from_bytes(endpoint.to_bytes()),
    );
    let Some(mut f) = fixture(BPF_MAP_TYPE_PERCPU_ARRAY, false, true) else {
        return 1;
    };
    if large {
        large_serialized(&mut f);
    }
    exit(send(&f, false, false, true, S3, &o))
}

fn tenant_validation() -> c_int {
    let Some(f) = fixture(BPF_MAP_TYPE_PERCPU_ARRAY, false, true) else {
        return 1;
    };
    let mut o = OtelOpts {
        endpoint: c"http://127.0.0.1:1".as_ptr(),
        ..opts()
    };
    let send = |o: &OtelOpts| send_file(None, &f, FORCE_LOG, Some(o));
    let mut failed = 0;
    o.tenant_id = c"bad tenant".as_ptr();
    failed += u32::from(send(&o) != -EINVAL);
    o.tenant_id = core::ptr::null();
    set(
        "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        "X-Tenant-ID=bad%20tenant",
    );
    failed += u32::from(send(&o) != -EINVAL);
    set(
        "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        "X-Tenant-ID=one,x-tenant-id=two",
    );
    failed += u32::from(send(&o) != -EINVAL);
    o.tenant_id = c"tenant-cli-1234".as_ptr();
    set(
        "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
        "X-Tenant-ID=ignored%20invalid",
    );
    failed += u32::from(send(&o) == -EINVAL);
    unset("OTEL_EXPORTER_OTLP_LOGS_HEADERS");
    c_int::from(failed > 0)
}

fn s3_validation() -> c_int {
    let Some(mut f) = fixture(BPF_MAP_TYPE_PERCPU_ARRAY, false, true) else {
        return 1;
    };
    let mut o = OtelOpts {
        s3_uri: c"s3://test-bucket/prefix".as_ptr(),
        ..opts()
    };
    set("AWS_ENDPOINT_URL_S3", "http://127.0.0.1:1");
    for name in [
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_CA_BUNDLE",
    ] {
        unset(name);
    }
    let send = |f: &MapView, o: &OtelOpts| send_file(None, f, S3, Some(o));
    let checks = [
        (send(&f, &o), -EACCES),
        (
            {
                set("AWS_ACCESS_KEY_ID", "test");
                set("AWS_SECRET_ACCESS_KEY", "bad\nsecret");
                send(&f, &o)
            },
            -EACCES,
        ),
        (
            {
                set("AWS_SECRET_ACCESS_KEY", "secret");
                set("AWS_ACCESS_KEY_ID", "bad:key");
                send(&f, &o)
            },
            -EACCES,
        ),
        (
            {
                set("AWS_ACCESS_KEY_ID", "test");
                set("AWS_REGION", "not_a_region");
                send(&f, &o)
            },
            -EINVAL,
        ),
    ];
    if checks.iter().any(|&(got, want)| got != want) {
        return 1;
    }
    unset("AWS_REGION");
    for uri in [
        c"s3://test-bucket/../escape",
        c"s3://test-bucket/prefix?query",
        c"s3://BAD_BUCKET/prefix",
    ] {
        o.s3_uri = uri.as_ptr();
        if send(&f, &o) != -EINVAL {
            return 1;
        }
    }
    o.s3_uri = c"s3://test-bucket/prefix".as_ptr();
    f.truncated = true;
    let truncated = send(&f, &o);
    f.truncated = false;
    f.skipped = true;
    let skipped = send(&f, &o);
    f.skipped = false;
    if truncated != -E2BIG || skipped != -EOPNOTSUPP {
        return 1;
    }
    set("AWS_ENDPOINT_URL_S3", "http://storage.example");
    c_int::from(send(&f, &o) != -EPERM)
}

fn security_check() -> c_int {
    let Some(f) = fixture(BPF_MAP_TYPE_PERCPU_ARRAY, false, true) else {
        return 1;
    };
    let o = OtelOpts {
        endpoint: c"http://collector.example".as_ptr(),
        ..opts()
    };
    c_int::from(send_file(None, &f, FORCE_LOG, Some(&o)) != -EPERM)
}

fn run(args: &[&CStr]) -> c_int {
    let n = args.len();
    let a = |i: usize| args[i];
    let how = args.get(1).map_or(&b""[..], |h| h.to_bytes());
    let u32_of = |i: usize| number(a(i)) as u32;
    match (how, n) {
        (b"record-size", 2) => print_record_size(),
        (b"send-log-limits", 6) => {
            let o = OtelOpts {
                endpoint: a(2).as_ptr(),
                retries: u32_of(3),
                log_record_max_bytes: u32_of(4),
                otlp_max_bytes: u32_of(5),
                ..opts()
            };
            send_percpu(false, FORCE_LOG, &o)
        }
        (b"send-log-env", 3) => send_percpu(
            false,
            FORCE_LOG,
            &OtelOpts {
                retries: u32_of(2),
                ..opts()
            },
        ),
        (b"send-metric-env", 2) => send_percpu(true, FORCE_METRIC, &opts()),
        (b"send-keepalive", 6) => send_keepalive(a(2), a(3), a(4), a(5)),
        (b"retry-after", 4) => {
            let t = a(3).to_bytes();
            let digits = t
                .iter()
                .enumerate()
                .take_while(|&(i, c)| c.is_ascii_digit() || (i == 0 && *c == b'-'))
                .count();
            let now = std::str::from_utf8(&t[..digits])
                .ok()
                .and_then(|d| d.parse().ok())
                .unwrap_or(0);
            match retry_after(a(2).to_bytes(), now) {
                Ok(seconds) => {
                    out(&format!("{seconds}\n"));
                    0
                }
                Err(_) => 1,
            }
        }
        (_, 0 | 1) => 2,
        (b"classify-unsigned", _) => {
            print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, false, true, false)
        }
        (b"classify-signed", _) => {
            print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, true, true, false)
        }
        (b"classify-array", _) => print_classification(BPF_MAP_TYPE_ARRAY, false, true, false),
        (b"classify-hash", _) => print_classification(BPF_MAP_TYPE_PERCPU_HASH, false, true, false),
        (b"classify-lru-hash", _) => {
            print_classification(BPF_MAP_TYPE_LRU_PERCPU_HASH, false, true, false)
        }
        (b"classify-no-btf", _) => {
            print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, false, false, false)
        }
        (b"classify-serialized", _) => {
            print_classification(BPF_MAP_TYPE_PERCPU_ARRAY, false, true, true)
        }
        (b"log", _) => print_payload(false, false, true),
        (b"log-no-location", _) => print_payload(false, false, false),
        (b"metric", _) => print_payload(true, false, true),
        (b"counter", _) => print_payload(true, true, true),
        (b"local-json", _) => print_local_json(),
        (b"send-log", 4) => send_percpu(
            false,
            FORCE_LOG,
            &OtelOpts {
                endpoint: a(2).as_ptr(),
                retries: u32_of(3),
                ..opts()
            },
        ),
        (b"send-log-insecure", 4) => send_percpu(
            false,
            FORCE_LOG,
            &OtelOpts {
                endpoint: a(2).as_ptr(),
                retries: u32_of(3),
                allow_insecure: true,
                ..opts()
            },
        ),
        (b"send-auto-log", 3) => send_auto(a(2), true),
        (b"send-auto-metric", 3) => send_auto(a(2), false),
        (b"send-metric", 3) => send_percpu(
            true,
            FORCE_METRIC,
            &OtelOpts {
                endpoint: a(2).as_ptr(),
                ..opts()
            },
        ),
        (b"send-s3", 4) => send_s3(a(2), u32_of(3), false),
        (b"send-s3-large", 4) => send_s3(a(2), u32_of(3), true),
        (b"s3-validation", _) => s3_validation(),
        (b"tenant-validation", _) => tenant_validation(),
        (b"security", _) => security_check(),
        _ => 2,
    }
}
