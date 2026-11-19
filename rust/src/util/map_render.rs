// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Pinned maps as `shirudo upatch map`, `get` and `status` show them:
//! the table of maps, one map's detail with its types and contents or
//! its serialized pages, and the same as JSON.

use core::ffi::CStr;

use crate::sys::libc::{fwrite, stdout};
use crate::sys::upatch::MapSummary;
use crate::sys::upatch_maps::{MapEntry, MapView};
use crate::text::cstr;
use crate::util::json::JsonEmit;
use crate::util::map_format::{cpu_values, format_cell, is_percpu, percpu_sum};

/// Text to the C library's stdout, where the rest of a report goes.
fn out(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

/// `s` padded with spaces to `width` bytes, as printf's %-Ns pads it.
fn pad(s: &[u8], width: usize) -> Vec<u8> {
    let mut v = s.to_vec();
    v.resize(width.max(s.len()), b' ');
    v
}

/// A label of 22 bytes and its value, as the reports line them up.
fn field(label: &[u8], value: &[u8]) -> Vec<u8> {
    [&pad(label, 22)[..], b" ", value, b"\n"].concat()
}

/// A name of the view, or "(null)" for none, as glibc printed NULL.
fn c_or_null(s: Option<&'static CStr>) -> &'static [u8] {
    s.map_or(b"(null)", CStr::to_bytes)
}

/// The key of entry `en`, its value or each CPU's, and the per-CPU sum.
struct Cells {
    key: Vec<u8>,
    value: Option<Vec<u8>>,
    per_cpu: Vec<Vec<u8>>,
    sum: Vec<u8>,
}

fn cells(v: &MapView, en: &MapEntry) -> Cells {
    let key = format_cell(v, v.key_type_id, &en.key, cstr(&v.btf_key_type));
    let vtype = cstr(&v.btf_value_type);
    if !is_percpu(v.ty) {
        return Cells {
            key,
            value: Some(format_cell(v, v.value_type_id, &en.value, vtype)),
            per_cpu: Vec::new(),
            sum: Vec::new(),
        };
    }
    let per_cpu = cpu_values(v, &en.value)
        .map(|one| format_cell(v, v.value_type_id, one, vtype))
        .collect();
    Cells {
        key,
        value: None,
        per_cpu,
        sum: percpu_sum(v, &en.value),
    }
}

/// The pinned maps as a table.
pub(crate) fn print_summary(list: &[MapSummary]) {
    let mut t = format!("Pinned maps ({}):\n", list.len()).into_bytes();
    if list.is_empty() {
        t.extend_from_slice(b"  none\n");
        out(&t);
        return;
    }
    t.extend(
        [
            &b"  "[..],
            &pad(b"UPATCH", 22),
            b" ",
            &pad(b"MAP", 16),
            b" ",
            &pad(b"TYPE", 18),
            b" ENTRIES\n",
        ]
        .concat(),
    );
    for m in list {
        t.extend(
            [
                &b"  "[..],
                &pad(cstr(&m.upatch), 22),
                b" ",
                &pad(cstr(&m.name), 16),
                b" ",
                &pad(c_or_null(m.type_name), 18),
                format!(" max={}", m.max_entries).as_bytes(),
                if m.n_cpus > 1 { b"  (per-cpu)" } else { b"" },
                b"\n",
            ]
            .concat(),
        );
    }
    out(&t);
}

/// A type definition under its label, its later lines indented to the
/// value column, and its size.
fn type_def(label: &[u8], def: &[u8], size: u32) -> Vec<u8> {
    let mut t = [&pad(label, 22)[..], b" "].concat();
    let mut lines = def.split(|&c| c == b'\n').peekable();
    while let Some(line) = lines.next() {
        t.extend_from_slice(line);
        if lines.peek().is_some() {
            t.push(b'\n');
            t.extend(pad(b"", 22));
            t.push(b' ');
        }
    }
    t.extend(format!(" ({size} B)\n").as_bytes());
    t
}

/// A serialized page's bytes as hex, 16 to a line in pairs.
fn hex_dump(data: &[u8]) -> Vec<u8> {
    let mut t = Vec::new();
    for (i, b) in data.iter().enumerate() {
        if i % 16 == 0 {
            t.extend(format!("  {i:08x}: ").as_bytes());
        }
        t.extend(format!("{b:02x}").as_bytes());
        if i % 16 == 15 || i + 1 == data.len() {
            t.push(b'\n');
        } else if i % 2 == 1 {
            t.push(b' ');
        }
    }
    t
}

/// One map: what it is, and its serialized pages, its types and
/// contents, or why it was skipped.
pub(crate) fn print_detail(v: &MapView) {
    let ty = c_or_null(v.type_name);
    let mut t = field(b"Name:", cstr(&v.upatch));
    t.extend(field(b"Map:", cstr(&v.name)));
    if is_percpu(v.ty) {
        t.extend(field(
            b"Type:",
            &[ty, format!(" ({} CPUs)", v.n_cpus).as_bytes()].concat(),
        ));
    } else {
        t.extend(field(b"Type:", ty));
    }
    t.extend(field(b"Max entries:", v.max_entries.to_string().as_bytes()));
    if v.skipped {
        let reason = if v.skipped_reason.is_none() {
            &b"(no reason)"[..]
        } else {
            c_or_null(v.skipped_reason)
        };
        t.extend(field(b"Status:", &[&b"skipped: "[..], reason].concat()));
        out(&t);
        return;
    }
    if v.serialized {
        t.extend(field(b"Status:", b"serialized"));
        t.extend(field(
            b"Serialized pages:",
            v.n_serial_pages().to_string().as_bytes(),
        ));
        t.extend(field(
            b"Serialized bytes:",
            v.serial_bytes_total.to_string().as_bytes(),
        ));
        for page in &v.serial_pages {
            let sub = |label: &[u8], value: &[u8]| [&b"  "[..], &field(label, value)].concat();
            t.extend(format!("\nPage {}:\n", page.page_index).as_bytes());
            t.extend(sub(b"Cursor:", page.cursor.to_string().as_bytes()));
            t.extend(sub(
                b"Next cursor:",
                page.next_cursor.to_string().as_bytes(),
            ));
            t.extend(sub(b"Done:", if page.done { b"true" } else { b"false" }));
            t.extend(sub(b"Flags:", format!("0x{:x}", page.flags).as_bytes()));
            t.extend(sub(b"Chunks:", page.chunks.to_string().as_bytes()));
            t.extend(sub(b"Bytes:", page.bytes().to_string().as_bytes()));
            if !page.data.is_empty() {
                t.extend_from_slice(b"\n  Data (hex):\n");
                t.extend(hex_dump(&page.data));
            }
        }
        out(&t);
        return;
    }
    let truncated: &[u8] = if v.truncated {
        b"  (truncated; use --show-full)"
    } else {
        b""
    };
    t.extend(field(
        b"Entries:",
        &[
            format!("{} of {}", v.n_entries(), v.max_entries).as_bytes(),
            truncated,
        ]
        .concat(),
    ));
    let (kdef, ktype) = (cstr(&v.key_type_def), cstr(&v.btf_key_type));
    if !kdef.is_empty() {
        t.extend(type_def(b"Key type:", kdef, v.key_size));
    } else if !ktype.is_empty() {
        t.extend(field(
            b"Key type:",
            &[ktype, format!(" ({} B)", v.key_size).as_bytes()].concat(),
        ));
    } else {
        t.extend(field(
            b"Key size:",
            format!("{} B  (no BTF)", v.key_size).as_bytes(),
        ));
    }
    let (vdef, vtype) = (cstr(&v.value_type_def), cstr(&v.btf_value_type));
    if !vdef.is_empty() {
        t.extend(type_def(b"Value type:", vdef, v.value_size));
    } else if !vtype.is_empty() {
        t.extend(field(
            b"Value type:",
            &[vtype, format!(" ({} B per CPU)", v.value_size).as_bytes()].concat(),
        ));
    } else {
        t.extend(field(
            b"Value size:",
            format!("{} B  (no BTF)", v.value_size).as_bytes(),
        ));
    }
    if v.entries.is_empty() {
        out(&t);
        return;
    }
    t.extend_from_slice(b"\nContents:\n");
    for en in &v.entries {
        let c = cells(v, en);
        match c.value {
            Some(value) => {
                t.extend([&b"  key = "[..], &c.key, b"\n     -> ", &value, b"\n"].concat())
            }
            None => {
                t.extend([&b"  key="[..], &c.key, b": sum=", &c.sum, b"\n"].concat());
                for (j, one) in c.per_cpu.iter().enumerate() {
                    if j % 4 == 0 {
                        t.extend_from_slice(b"    ");
                    }
                    t.extend([format!("cpu{j}=").as_bytes(), &pad(one, 7), b"  "].concat());
                    if (j + 1) % 4 == 0 {
                        t.push(b'\n');
                    }
                }
                if v.n_cpus % 4 != 0 {
                    t.push(b'\n');
                }
            }
        }
    }
    out(&t);
}

fn hex(data: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    data.iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

/// One map's fields as JSON, the shape status reports carry.
pub(crate) fn emit_json_fields(e: &mut JsonEmit, v: &MapView) {
    e.kv_string(b"name", cstr(&v.name));
    e.kv_string(b"type", c_or_null(v.type_name));
    e.kv_int(b"max_entries", i64::from(v.max_entries));
    e.kv_int(b"n_entries", i64::from(v.n_entries()));
    if is_percpu(v.ty) {
        e.kv_int(b"n_cpus", i64::from(v.n_cpus));
    }
    if v.serialized {
        e.kv_bool(b"serialized", true);
        e.kv_int(b"serialized_pages", i64::from(v.n_serial_pages()));
        e.kv_int(b"serialized_bytes", v.serial_bytes_total as i64);
        e.arr_open(b"pages");
        for page in &v.serial_pages {
            e.obj_open();
            e.kv_int(b"page_index", i64::from(page.page_index));
            e.kv_int(b"cursor", page.cursor as i64);
            e.kv_int(b"next_cursor", page.next_cursor as i64);
            e.kv_bool(b"done", page.done);
            e.kv_int(b"flags", i64::from(page.flags));
            e.kv_int(b"chunks", i64::from(page.chunks));
            e.kv_int(b"bytes", i64::from(page.bytes()));
            e.kv_string(b"data_hex", &hex(&page.data));
            e.obj_close();
        }
        e.arr_close();
        return;
    }
    e.kv_bool(b"serialized", false);
    if v.skipped {
        let reason = if v.skipped_reason.is_none() {
            &b""[..]
        } else {
            c_or_null(v.skipped_reason)
        };
        e.kv_string(b"skipped", reason);
        return;
    }
    e.kv_bool(b"truncated", v.truncated);
    if v.truncated {
        e.kv_int(b"n_truncated_at", i64::from(v.n_truncated_at));
    }
    let (ktype, vtype) = (cstr(&v.btf_key_type), cstr(&v.btf_value_type));
    if !ktype.is_empty() || !vtype.is_empty() {
        e.obj_open_key(b"btf");
        e.kv_string(b"key_type", ktype);
        e.kv_string(b"value_type", vtype);
        let (kdef, vdef) = (cstr(&v.key_type_def), cstr(&v.value_type_def));
        if !kdef.is_empty() {
            e.kv_string(b"key_type_def", kdef);
        }
        if !vdef.is_empty() {
            e.kv_string(b"value_type_def", vdef);
        }
        e.obj_close();
    }
    e.arr_open(b"entries");
    for en in &v.entries {
        let c = cells(v, en);
        e.obj_open();
        e.kv_string(b"key", &c.key);
        match c.value {
            Some(value) => e.kv_string(b"value", &value),
            None => {
                e.arr_open(b"values_per_cpu");
                for one in &c.per_cpu {
                    e.str(one);
                }
                e.arr_close();
                e.kv_string(b"sum", &c.sum);
            }
        }
        e.obj_close();
    }
    e.arr_close();
}

/// One map as a JSON object.
pub(crate) fn emit_json_object(e: &mut JsonEmit, v: &MapView) {
    e.obj_open();
    emit_json_fields(e, v);
    e.obj_close();
}
