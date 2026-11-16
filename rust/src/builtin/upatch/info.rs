// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch info`: an upatch file described offline, its header,
//! signature, payload digest, signed sections and decoders. No signature
//! is checked, so the names it shows are as the file has them: made
//! printable, and in JSON lossy UTF-8.

use core::ffi::c_int;
use std::ffi::CString;

use super::{JSON_MAX, err, help, hex, log_err, out, print_json, strerr};
use crate::sys::string::text_sanitize;
use crate::text::cstr;
use crate::util::help::is_help;
use crate::util::json::JsonEmit;
use crate::util::upatch::{self, DecoderView, NAME_MAX, Opened, Upatch};
/// UPATCH_DECODER_LANG_LUA, _INPUT_MAP_V1, _EXPORT_LOG and _METRIC.
const LANG_LUA: u32 = 1;
const INPUT_MAP_V1: u32 = 1;
const EXPORT_LOG: u32 = 1;
const EXPORT_METRIC: u32 = 2;

fn usage() {
    help(
        c"shirudo upatch info [--json] <file.upatch>",
        c"Describe a .upatch file: header, signature, payload digest,\nattach metadata and signed decoders. Offline: no kernel state\nread, runs on any host. For the program as actually loaded\n(authoritative, via kernel BTF line_info) use `shirudo upatch get`.",
        &[],
        Some(c"Examples:\n  shirudo upatch info cve-2026-31431.upatch\n  shirudo upatch info --json /var/lib/shirudo/upatches/foo.upatch"),
    );
}

fn language(l: u32) -> &'static [u8] {
    if l == LANG_LUA { b"lua" } else { b"unknown" }
}

fn input(f: u32) -> &'static [u8] {
    if f == INPUT_MAP_V1 {
        b"shirudo.map.v1"
    } else {
        b"unknown"
    }
}

fn signal(s: u32) -> &'static [u8] {
    match s {
        EXPORT_LOG => b"log",
        EXPORT_METRIC => b"metric",
        _ => b"unknown",
    }
}

/// The bytes up to a NUL made printable, as the C library's
/// text_sanitize() makes them.
fn printable(s: &[u8]) -> Vec<u8> {
    let mut buf = CString::new(cstr(s))
        .unwrap_or_default()
        .into_bytes_with_nul();
    let len = buf.len() - 1;
    // SAFETY: the C string and its length.
    unsafe { text_sanitize(buf.as_mut_ptr().cast(), len, false) };
    buf.truncate(len);
    buf
}

/// What printable() shows, as JSON escapes it and U+FFFD for a stray
/// byte.
fn unverified(e: &mut JsonEmit, key: &[u8], val: &[u8]) {
    e.key(key);
    e.str_lossy(cstr(val));
}

/// The container's decoders, each that reads as a view.
fn decoders(u: &Upatch) -> Vec<DecoderView> {
    (0..u.nr_decoders)
        .filter_map(|i| {
            // SAFETY: an all-zero view, which the call fills.
            let mut d: DecoderView = unsafe { core::mem::zeroed() };
            (upatch::decoder_view(u, i, &mut d) == 0).then_some(d)
        })
        .collect()
}

/// The container's signed name, its header's size of it.
fn signed_name(u: &Upatch, name: &mut [u8; NAME_MAX + 1]) -> bool {
    let p = upatch::signed_name(u);
    if p.is_null() {
        return false;
    }
    // SAFETY: the signed section's name of the header's size.
    let signed = unsafe { crate::ffi::slice(p.cast::<u8>(), NAME_MAX) };
    name[..NAME_MAX].copy_from_slice(signed);
    true
}

fn json(u: &Upatch, path: &[u8], name: &mut [u8; NAME_MAX + 1]) -> c_int {
    let mut e = JsonEmit::growing(JSON_MAX);
    let h = &u.hdr;

    e.obj_open();
    e.kv_int(b"schema", 1);
    unverified(&mut e, b"path", path);
    unverified(&mut e, b"name", name);
    e.kv_string(
        b"type",
        if upatch::is_unload(u) {
            b"unload"
        } else {
            b"load"
        },
    );
    e.kv_string(b"payload_type", upatch::payload_type(u));
    e.kv_int(b"version", i64::from(h.version));
    e.kv_string(b"payload_sha256", &hex(&h.payload_sha256));
    e.kv_int(b"loader_insns_len", i64::from(h.loader_insns_len));
    e.kv_int(b"signature_len", i64::from(h.signature_len));
    e.kv_int(b"metadata_len", i64::from(h.metadata_len));
    e.kv_int(b"data_len", i64::from(h.data_len));
    e.kv_int(b"log_buf_sz", i64::from(h.log_buf_sz));
    e.kv_int(b"file_size", u.map_size as i64);
    if signed_name(u, name) {
        unverified(&mut e, b"signed_name", name);
    } else {
        e.kv_null(b"signed_name");
    }
    e.kv_int(
        b"attach_metadata_len",
        i64::from(upatch::signed_attach_len(u)),
    );
    match upatch::signed_unload_payload(u) {
        Some(p) => e.kv_string(b"unload_payload_sha256", &hex(p)),
        None => e.kv_null(b"unload_payload_sha256"),
    }
    e.arr_open(b"decoders");
    for d in decoders(u) {
        e.obj_open();
        e.kv_string(b"language", language(d.language));
        e.kv_int(b"api_version", i64::from(d.api_version));
        e.kv_string(b"input_format", input(d.input_format));
        e.kv_string(b"export_signal", signal(d.export_signal));
        unverified(&mut e, b"upatch", &d.upatch);
        unverified(&mut e, b"map", &d.map);
        unverified(&mut e, b"source_file", &d.source_name);
        unverified(&mut e, b"entrypoint", &d.entrypoint);
        e.kv_int(b"source_len", i64::from(d.source_len));
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    print_json(e, b"upatch info")
}

fn line(label: &str, value: &[u8]) -> Vec<u8> {
    [format!("{label:<23}").as_bytes(), value, b"\n"].concat()
}

fn section(label: &str, value: &[u8]) -> Vec<u8> {
    [format!("  {label:<22} ").as_bytes(), value, b"\n"].concat()
}

fn text(u: &Upatch, path: &[u8], name: &mut [u8; NAME_MAX + 1]) {
    let h = &u.hdr;
    let attach_len = upatch::signed_attach_len(u);
    let mut t = Vec::new();

    t.extend(line("File:", &printable(path)));
    t.extend(line("Name:", &printable(name)));
    t.extend(line(
        "Type:",
        if upatch::is_unload(u) {
            b"UNLOAD-directive"
        } else {
            b"LOAD"
        },
    ));
    t.extend(line("Payload type:", upatch::payload_type(u)));
    t.extend(line("Version:", h.version.to_string().as_bytes()));
    t.extend(line("Payload sha256:", &hex(&h.payload_sha256)));
    t.extend(line(
        "File size:",
        format!("{} bytes", u.map_size).as_bytes(),
    ));

    t.extend_from_slice(b"\nLoader:\n");
    t.extend(section(
        "Instructions:",
        format!("off={} len={}", h.loader_insns_off, h.loader_insns_len).as_bytes(),
    ));
    t.extend(section(
        "Log buffer size:",
        h.log_buf_sz.to_string().as_bytes(),
    ));
    for (label, off, len) in [
        ("Metadata:", h.metadata_off, h.metadata_len),
        ("Data:", h.data_off, h.data_len),
    ] {
        let v = if len != 0 {
            format!("off={off} len={len}")
        } else {
            "(none)".into()
        };
        t.extend(section(label, v.as_bytes()));
    }

    t.extend_from_slice(b"\nSignature:\n");
    t.extend(section("Offset:", h.signature_off.to_string().as_bytes()));
    t.extend(section(
        "Length:",
        format!("{} bytes", h.signature_len).as_bytes(),
    ));

    t.extend_from_slice(b"\nSigned sections:\n");
    if signed_name(u, name) {
        t.extend(section("Name:", &printable(name)));
    } else {
        t.extend(section("Name:", b"(none)"));
    }
    let attach = if attach_len != 0 {
        format!("{attach_len} bytes")
    } else {
        "(none)".into()
    };
    t.extend(section("Attach metadata:", attach.as_bytes()));
    match upatch::signed_unload_payload(u) {
        Some(p) => t.extend(section("Unload payload:", &hex(p))),
        None => t.extend(section("Unload payload:", b"(none)")),
    }

    t.extend_from_slice(b"\nDecoders:\n");
    if !upatch::has_decoders(u) {
        t.extend_from_slice(b"  (none)\n");
    } else {
        for d in decoders(u) {
            t.extend(section(
                "Target:",
                &[&printable(&d.upatch)[..], b"/", &printable(&d.map)].concat(),
            ));
            let sub =
                |label: &str, v: &[u8]| [format!("    {label:<20} ").as_bytes(), v, b"\n"].concat();
            t.extend(sub(
                "Language:",
                &[
                    language(d.language),
                    format!(" (api={})", d.api_version).as_bytes(),
                ]
                .concat(),
            ));
            t.extend(sub("Input:", input(d.input_format)));
            t.extend(sub("Export signal:", signal(d.export_signal)));
            t.extend(sub(
                "Source:",
                &[
                    &printable(&d.source_name)[..],
                    b":",
                    &printable(&d.entrypoint),
                    format!(" ({} bytes)", d.source_len).as_bytes(),
                ]
                .concat(),
            ));
        }
    }
    out(&t);
}

/// `upatch info`, from `info` on.
pub(super) fn run(args: &[&[u8]]) -> c_int {
    let mut json_out = false;
    let mut path: Option<&[u8]> = None;

    for &a in &args[1..] {
        if a == b"--json" {
            json_out = true;
        } else if is_help(Some(a)) {
            usage();
            return 0;
        } else if a.first() == Some(&b'-') {
            err(&[b"upatch info: unknown option '", a, b"'\n"].concat());
            return 2;
        } else if path.is_none() {
            path = Some(a);
        } else {
            err(&[b"upatch info: unexpected argument '", a, b"'\n"].concat());
            return 2;
        }
    }
    let Some(path) = path else {
        usage();
        return 2;
    };
    let u = match Opened::open(&CString::new(path).unwrap_or_default()) {
        Ok(u) => u,
        Err(e) => {
            log_err(&[b"upatch info: ", path, b": ", strerr(-e)].concat());
            return 1;
        }
    };
    let mut name = [0u8; NAME_MAX + 1];
    upatch::header_name(&u, &mut name);
    if json_out {
        json(&u, path, &mut name)
    } else {
        text(&u, path, &mut name);
        0
    }
}
