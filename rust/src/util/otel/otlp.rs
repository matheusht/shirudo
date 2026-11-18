// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! OTLP/JSON documents: the log a map or a status becomes, the metrics a
//! decoder makes of a map, and the reference to a snapshot in S3.

use core::ffi::{CStr, c_int};
use std::time::{SystemTime, UNIX_EPOCH};

use super::{Buffer, Decoded, cstr_or_empty, hex_lower, is_c_space};
use crate::errno::{E2BIG, EBADMSG, EINVAL, ENODATA, ENOMEM};
use crate::sys::libc::gethostname;
use crate::sys::upatch_maps::MapView;
use crate::text::cstr;
use crate::util::decode::{
    upatch_decode_map_file_json, upatch_decode_map_file_otel, upatch_decode_map_json,
    upatch_decode_map_otel,
};
use crate::util::json::JsonEmit;
use crate::util::map_format;

/// JSON_MAX_BYTES: the largest document the emitter makes.
pub(super) const JSON_MAX: usize = 8 * 1024 * 1024;
/// S3_REFERENCE_MAX.
pub(super) const REFERENCE_MAX: usize = 64 * 1024;

pub(super) fn kv_string(e: &mut JsonEmit, key: &[u8], value: &[u8]) {
    e.obj_open();
    e.kv_string(b"key", key);
    e.obj_open_key(b"value");
    e.kv_string(b"stringValue", value);
    e.obj_close();
    e.obj_close();
}

pub(super) fn kv_int(e: &mut JsonEmit, key: &[u8], value: i64) {
    e.obj_open();
    e.kv_string(b"key", key);
    e.obj_open_key(b"value");
    e.kv_string(b"intValue", value.to_string().as_bytes());
    e.obj_close();
    e.obj_close();
}

fn kv_bool(e: &mut JsonEmit, key: &[u8], value: bool) {
    e.obj_open();
    e.kv_string(b"key", key);
    e.obj_open_key(b"value");
    e.kv_bool(b"boolValue", value);
    e.obj_close();
    e.obj_close();
}

/// `{"key": key, "value": {<what>: {"values": [` ... closed by
/// [`list_end`].
fn list_begin(e: &mut JsonEmit, key: &[u8], what: &[u8]) {
    e.obj_open();
    e.kv_string(b"key", key);
    e.obj_open_key(b"value");
    e.obj_open_key(what);
    e.arr_open(b"values");
}

fn list_end(e: &mut JsonEmit) {
    e.arr_close();
    e.obj_close();
    e.obj_close();
    e.obj_close();
}

fn array_string(e: &mut JsonEmit, value: &[u8]) {
    e.obj_open();
    e.kv_string(b"stringValue", value);
    e.obj_close();
}

fn array_kvlist_begin(e: &mut JsonEmit) {
    e.obj_open();
    e.obj_open_key(b"kvlistValue");
    e.arr_open(b"values");
}

fn array_kvlist_end(e: &mut JsonEmit) {
    e.arr_close();
    e.obj_close();
    e.obj_close();
}

/// The host's name, `unknown` when it has none to give.
pub(super) fn hostname() -> Vec<u8> {
    let mut name = [0u8; 256];
    // SAFETY: the room for the name, its last byte kept for the NUL.
    if unsafe { gethostname(name.as_mut_ptr().cast(), name.len()) } != 0 {
        return b"unknown".to_vec();
    }
    name[255] = 0;
    cstr(&name).to_vec()
}

fn version() -> &'static [u8] {
    // SAFETY: the version, a C string.
    unsafe { crate::ffi::c_str(&raw const crate::sys::version::shirudo_version) }
}

fn realtime_ns() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| {
        d.as_secs()
            .wrapping_mul(1_000_000_000)
            .wrapping_add(u64::from(d.subsec_nanos()))
    })
}

/// An OTLP document down to its scope; [`otlp_close`] ends it.
fn otlp_open(e: &mut JsonEmit, resource_key: &[u8], scope_key: &[u8], scope_name: &[u8]) {
    e.obj_open();
    e.arr_open(resource_key);
    e.obj_open();
    e.obj_open_key(b"resource");
    e.arr_open(b"attributes");
    kv_string(e, b"service.name", b"shirudo");
    kv_string(e, b"service.version", version());
    kv_string(e, b"host.name", &hostname());
    e.arr_close();
    e.obj_close();
    e.arr_open(scope_key);
    e.obj_open();
    e.obj_open_key(b"scope");
    e.kv_string(b"name", scope_name);
    e.kv_string(b"version", version());
    e.obj_close();
}

fn otlp_close(e: &mut JsonEmit) {
    e.obj_close();
    e.arr_close();
    e.obj_close();
    e.arr_close();
    e.obj_close();
}

/// A logs document with its one record open; [`log_close`] ends both.
fn log_open(
    e: &mut JsonEmit,
    scope_name: &[u8],
    severity_number: i64,
    severity_text: &[u8],
    event_name: &[u8],
) {
    let now = realtime_ns().to_string();

    otlp_open(e, b"resourceLogs", b"scopeLogs", scope_name);
    e.arr_open(b"logRecords");
    e.obj_open();
    e.kv_string(b"timeUnixNano", now.as_bytes());
    e.kv_string(b"observedTimeUnixNano", now.as_bytes());
    e.kv_int(b"severityNumber", severity_number);
    e.kv_string(b"severityText", severity_text);
    e.kv_string(b"eventName", event_name);
}

fn log_close(e: &mut JsonEmit) {
    e.obj_close();
    e.arr_close();
    otlp_close(e);
}

pub(super) fn map_attributes(e: &mut JsonEmit, v: &MapView) {
    kv_string(e, b"shirudo.upatch.name", cstr(&v.upatch));
    kv_string(e, b"shirudo.upatch.location", cstr(&v.location));
    kv_string(e, b"shirudo.map.name", cstr(&v.name));
    kv_string(e, b"shirudo.map.type", cstr_or_empty(v.type_name));
    kv_int(e, b"shirudo.map.max_entries", i64::from(v.max_entries));
    kv_int(e, b"shirudo.map.n_entries", i64::from(v.n_entries));
    kv_int(e, b"shirudo.map.n_cpus", i64::from(v.n_cpus));
    kv_bool(e, b"shirudo.map.serialized", v.serialized);
    kv_bool(e, b"shirudo.map.truncated", v.truncated);
}

/// One cell as the map's BTF spells it, empty when it cannot.
fn cell(
    v: &MapView,
    type_id: u32,
    value: *const core::ffi::c_void,
    size: u32,
    btf_type: &[u8; 64],
) -> Vec<u8> {
    // SAFETY: a value of the view of `size` bytes.
    let value = unsafe { crate::ffi::slice(value.cast::<u8>(), size as usize) };
    map_format::format_cell(v, type_id, value, cstr(btf_type))
}

/// The map itself as the body of a log, when no decoder speaks for it.
fn log_map_data(e: &mut JsonEmit, v: &MapView) {
    let percpu = map_format::is_percpu(v.ty);

    kv_string(e, b"name", cstr(&v.name));
    kv_string(e, b"type", cstr_or_empty(v.type_name));
    kv_int(e, b"max_entries", i64::from(v.max_entries));
    kv_int(e, b"n_entries", i64::from(v.n_entries));
    if percpu {
        kv_int(e, b"n_cpus", i64::from(v.n_cpus));
    }
    if v.serialized {
        kv_bool(e, b"serialized", true);
        kv_int(e, b"serialized_pages", i64::from(v.n_serial_pages));
        kv_int(e, b"serialized_bytes", v.serial_bytes_total as i64);
        list_begin(e, b"pages", b"arrayValue");
        for p in 0..v.n_serial_pages as usize {
            // SAFETY: one of the view's n_serial_pages pages.
            let page = unsafe { &*v.serial_pages.add(p) };
            let data = if page.data.is_null() || page.bytes == 0 {
                &[][..]
            } else {
                // SAFETY: the page's bytes.
                unsafe { crate::ffi::slice(page.data.cast::<u8>(), page.bytes as usize) }
            };
            array_kvlist_begin(e);
            kv_int(e, b"page_index", i64::from(page.page_index));
            kv_int(e, b"cursor", page.cursor as i64);
            kv_int(e, b"next_cursor", page.next_cursor as i64);
            kv_bool(e, b"done", page.done);
            kv_int(e, b"flags", i64::from(page.flags));
            kv_int(e, b"chunks", i64::from(page.chunks));
            kv_int(e, b"bytes", i64::from(page.bytes));
            kv_string(e, b"data_hex", &hex_lower(data));
            array_kvlist_end(e);
        }
        list_end(e);
        return;
    }
    kv_bool(e, b"serialized", false);
    if v.skipped {
        kv_string(e, b"skipped", cstr_or_empty(v.skipped_reason));
        return;
    }
    kv_bool(e, b"truncated", v.truncated);
    if v.truncated {
        kv_int(e, b"n_truncated_at", i64::from(v.n_truncated_at));
    }
    if v.btf_key_type[0] != 0 || v.btf_value_type[0] != 0 {
        list_begin(e, b"btf", b"kvlistValue");
        kv_string(e, b"key_type", cstr(&v.btf_key_type));
        kv_string(e, b"value_type", cstr(&v.btf_value_type));
        if v.key_type_def[0] != 0 {
            kv_string(e, b"key_type_def", cstr(&v.key_type_def));
        }
        if v.value_type_def[0] != 0 {
            kv_string(e, b"value_type_def", cstr(&v.value_type_def));
        }
        list_end(e);
    }
    list_begin(e, b"entries", b"arrayValue");
    for i in 0..v.n_entries as usize {
        // SAFETY: one of the view's n_entries entries.
        let en = unsafe { &*v.entries.add(i) };
        let key = cell(v, v.key_type_id, en.key, v.key_size, &v.btf_key_type);

        array_kvlist_begin(e);
        kv_string(e, b"key", &key);
        if percpu {
            let stride = map_format::value_stride(v) as usize;
            // SAFETY: the entry's values, one per CPU.
            let values =
                unsafe { crate::ffi::slice(en.value.cast::<u8>(), stride * v.n_cpus as usize) };
            let sum = map_format::percpu_sum(v, values);
            list_begin(e, b"values_per_cpu", b"arrayValue");
            for cpu in 0..v.n_cpus as usize {
                // SAFETY: the value of one CPU, within the entry's values.
                let one = unsafe { en.value.cast::<u8>().add(cpu * stride) };
                let text = cell(
                    v,
                    v.value_type_id,
                    one.cast(),
                    v.value_size,
                    &v.btf_value_type,
                );
                array_string(e, &text);
            }
            list_end(e);
            kv_string(e, b"sum", &sum);
        } else {
            let value = cell(
                v,
                v.value_type_id,
                en.value,
                v.value_size,
                &v.btf_value_type,
            );
            kv_string(e, b"value", &value);
        }
        array_kvlist_end(e);
    }
    list_end(e);
}

/// What the map's decoder makes of it for a log or for metrics, from the
/// upatch or the artifact at `path`.
fn decode(path: Option<&CStr>, v: &MapView, otel: bool) -> Result<Decoded, c_int> {
    let (mut out, mut len) = (core::ptr::null_mut(), 0usize);
    // SAFETY: a C string or none, the view and rooms for the output.
    let ret = unsafe {
        match (path, otel) {
            (Some(p), true) => upatch_decode_map_file_otel(p.as_ptr(), v, &mut out, &mut len),
            (None, true) => upatch_decode_map_otel(v, &mut out, &mut len),
            (Some(p), false) => upatch_decode_map_file_json(p.as_ptr(), v, &mut out, &mut len),
            (None, false) => upatch_decode_map_json(v, &mut out, &mut len),
        }
    };
    let decoded = Decoded { ptr: out, len };
    if ret != 0 { Err(ret) } else { Ok(decoded) }
}

/// A map as one log record: what its decoder makes of it, at most
/// `record_max` bytes of it when that is not 0, or the map itself
/// without a decoder.
pub(super) fn log_payload(
    path: Option<&CStr>,
    v: &MapView,
    record_max: usize,
) -> Result<Buffer, c_int> {
    let mut buf = Buffer::alloc(JSON_MAX).ok_or(-ENOMEM)?;
    let mut e = JsonEmit::fixed(buf.ptr.cast(), buf.cap);

    log_open(
        &mut e,
        b"shirudo.upatch.maps",
        9,
        b"INFO",
        b"shirudo.bpf.map.snapshot",
    );
    match decode(path, v, true) {
        Ok(d) if record_max != 0 && d.len > record_max => return Err(-E2BIG),
        Ok(d) => e.kv_raw(b"body", d.bytes()),
        Err(err) if err == -ENODATA => {
            e.obj_open_key(b"body");
            e.obj_open_key(b"kvlistValue");
            e.arr_open(b"values");
            log_map_data(&mut e, v);
            e.arr_close();
            e.obj_close();
            e.obj_close();
        }
        Err(err) => return Err(err),
    }
    e.arr_open(b"attributes");
    map_attributes(&mut e, v);
    e.arr_close();
    log_close(&mut e);
    if e.err() != 0 {
        return Err(e.err());
    }
    buf.len = e.written();
    Ok(buf)
}

/// A map as the metrics its decoder makes of it, which must be a JSON
/// array.
pub(super) fn metric_payload(path: Option<&CStr>, v: &MapView) -> Result<Buffer, c_int> {
    let decoded = decode(path, v, false)?;
    let mut metrics = decoded.bytes();
    while let Some((&c, rest)) = metrics.split_first() {
        if !is_c_space(c) {
            break;
        }
        metrics = rest;
    }
    if metrics.first() != Some(&b'[') {
        return Err(-EINVAL);
    }
    let mut buf = Buffer::alloc(JSON_MAX).ok_or(-ENOMEM)?;
    let mut e = JsonEmit::fixed(buf.ptr.cast(), buf.cap);
    otlp_open(
        &mut e,
        b"resourceMetrics",
        b"scopeMetrics",
        b"shirudo.upatch.maps",
    );
    e.kv_raw(b"metrics", metrics);
    otlp_close(&mut e);
    if e.err() != 0 {
        return Err(e.err());
    }
    buf.len = e.written();
    Ok(buf)
}

/// What a log of [`super::send_log_string`] says: a body the receiver
/// decodes to the very bytes given, and one string attribute.
pub(super) struct StringRecord<'a> {
    pub(super) scope_name: &'a [u8],
    pub(super) event_name: &'a [u8],
    pub(super) severity_number: c_int,
    pub(super) severity_text: &'a [u8],
    pub(super) body: &'a [u8],
    pub(super) attr_key: &'a [u8],
    pub(super) attr_value: &'a [u8],
}

/// The body as a string, so that no collector can re-encode it and the
/// bytes a signature covers arrive as they were signed. JSON cannot
/// carry a NUL or malformed UTF-8 unchanged: either is -EILSEQ.
pub(super) fn string_log_payload(r: &StringRecord<'_>) -> Result<Buffer, c_int> {
    let mut e = JsonEmit::growing(JSON_MAX);

    log_open(
        &mut e,
        r.scope_name,
        i64::from(r.severity_number),
        r.severity_text,
        r.event_name,
    );
    e.obj_open_key(b"body");
    e.kv_string(b"stringValue", r.body);
    e.obj_close();
    e.arr_open(b"attributes");
    kv_string(&mut e, r.attr_key, r.attr_value);
    e.arr_close();
    log_close(&mut e);
    let buf = Buffer::from_emitter(&e);
    if e.err() != 0 {
        return Err(e.err());
    }
    Ok(buf)
}

/// The log that points at a map's snapshot in S3.
pub(super) fn s3_reference(
    v: &MapView,
    snapshot: &super::s3::Snapshot,
    uri: &[u8],
) -> Result<Buffer, c_int> {
    let description = [&b"BPF map snapshot stored in S3: "[..], uri].concat();
    if description.len() >= super::s3::URL_MAX + 64 {
        return Err(-E2BIG);
    }
    let mut buf = Buffer::alloc(REFERENCE_MAX).ok_or(-ENOMEM)?;
    let mut e = JsonEmit::fixed(buf.ptr.cast(), buf.cap);

    log_open(
        &mut e,
        b"shirudo.upatch.maps",
        9,
        b"INFO",
        b"shirudo.bpf.map.snapshot.reference",
    );
    e.obj_open_key(b"body");
    e.kv_string(b"stringValue", &description);
    e.obj_close();
    e.arr_open(b"attributes");
    map_attributes(&mut e, v);
    kv_string(&mut e, b"shirudo.map.snapshot.uri", uri);
    kv_string(
        &mut e,
        b"shirudo.map.snapshot.format",
        b"shirudo.map.v1+json",
    );
    kv_string(
        &mut e,
        b"shirudo.map.snapshot.content_type",
        b"application/json",
    );
    kv_string(&mut e, b"shirudo.map.snapshot.content_encoding", b"gzip");
    kv_int(
        &mut e,
        b"shirudo.map.snapshot.size_bytes",
        snapshot.object_bytes as i64,
    );
    kv_int(
        &mut e,
        b"shirudo.map.snapshot.uncompressed_size_bytes",
        snapshot.json_bytes as i64,
    );
    kv_string(
        &mut e,
        b"shirudo.map.snapshot.sha256",
        snapshot.sha256_hex.as_bytes(),
    );
    e.arr_close();
    log_close(&mut e);
    if e.err() != 0 {
        return Err(e.err());
    }
    if e.depth() != 0 {
        return Err(-EBADMSG);
    }
    buf.len = e.written();
    Ok(buf)
}
