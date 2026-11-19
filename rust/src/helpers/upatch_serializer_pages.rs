// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-upatch-serializer-pages: the paged serializer's contract with
//! the map view checked offline: its chunk layout and invocation nonce,
//! its per-map locks, and the JSON a paged map renders as. Prints ok
//! when all hold.
//!
//! The BPF side's struct serialize_ctx, which the C helper sized, is
//! checked where it is defined, by bpf/lib/serializer.h's BUILD_BUG_ON.

use core::ffi::{CStr, c_int};
use std::os::unix::ffi::OsStrExt;

use super::{err, helper_main, out};
use crate::errno::{EBADMSG, EBUSY};
use crate::sys::libc::Zeroed;
use crate::sys::upatch_maps::{MapView, SerialPage};
use crate::util::json::JsonEmit;
use crate::util::map_render::{emit_json_fields, emit_json_object};
use crate::util::serializer::{
    SERIAL_CHUNK_PAYLOAD, SERIAL_MAGIC, SERIAL_VERSION, SerialChunk, chunk_validate,
    lock_acquire_at, new_invocation_id,
};

helper_main!(shirudo_helper_test_upatch_serializer_pages, run);

fn abi_and_nonce() -> Result<(), &'static str> {
    let mut chunk = Box::new(SerialChunk::zeroed());
    chunk.magic = SERIAL_MAGIC;
    chunk.version = SERIAL_VERSION;
    chunk.chunk_index = 1;
    chunk.total_chunks = 2;
    chunk.bytes_total = 1;
    chunk.bytes_in_chunk = 1;
    chunk.page_index = 3;
    chunk.cursor = 10;
    chunk.next_cursor = 11;
    chunk.invocation_id = 0x1234_5678;
    if SERIAL_VERSION != 1 || size_of::<SerialChunk>() != 4096 || SERIAL_CHUNK_PAYLOAD != 4032 {
        return Err("serializer v1 ABI layout mismatch");
    }
    if chunk_validate(&chunk, 1, 2, 3, 10, 11, 0x1234_5678).is_err() {
        return Err("valid serializer nonce rejected");
    }
    if chunk_validate(&chunk, 1, 2, 3, 10, 11, 0x8765_4321) != Err(-EBADMSG) {
        return Err("serializer nonce mismatch accepted");
    }
    if !new_invocation_id().is_ok_and(|id| id != 0) {
        return Err("serializer invocation ID generation failed");
    }
    Ok(())
}

/// A map's lock held, then refused to a second taker, other maps' locks
/// independent, and the lock free again once its fd closes.
fn map_locks() -> Result<(), &'static str> {
    let mut template = *b"/tmp/shirudo-serializer-lock-XXXXXX\0";
    // SAFETY: a template mkdtemp() fills in place.
    if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
        return Err("mkdtemp failed");
    }
    let dir = CStr::from_bytes_with_nul(&template).map_err(|_| "mkdtemp failed")?;
    let lock = |id| lock_acquire_at(dir, id);
    let ret = (|| {
        let first = lock(101).map_err(|_| "first serializer lock failed")?;
        if lock(101).err() != Some(-EBUSY) {
            return Err("contended serializer lock did not return EBUSY");
        }
        let _other = lock(202).map_err(|_| "independent serializer map lock failed")?;
        drop(first);
        lock(101)
            .map(drop)
            .map_err(|_| "released serializer lock could not be reacquired")
    })();
    let dir = std::path::Path::new(std::ffi::OsStr::from_bytes(dir.to_bytes()));
    for name in ["serializer-map-101.lock", "serializer-map-202.lock"] {
        let _ = std::fs::remove_file(dir.join(name));
    }
    let _ = std::fs::remove_dir(dir);
    ret
}

/// The JSON `emit` makes into a buffer of `cap` bytes, or None when it
/// fails.
fn emitted(cap: usize, emit: impl FnOnce(&mut JsonEmit)) -> Option<String> {
    let mut buf = vec![0u8; cap];
    let mut e = JsonEmit::fixed(&mut buf[..cap]);
    emit(&mut e);
    if e.err() != 0 {
        return None;
    }
    Some(String::from_utf8_lossy(crate::text::cstr(&buf)).into_owned())
}

fn json(v: &MapView) -> Result<(), &'static str> {
    let buf = emitted(2048, |e| emit_json_object(e, v)).ok_or("json emit failed")?;
    let has_all = |needles: &[&str]| needles.iter().all(|n| buf.contains(n));
    let checks: [(&[&str], &str); 6] = [
        (&["\"serialized\":true"], "missing serialized flag"),
        (&["\"serialized_pages\":2"], "missing page count"),
        (&["\"serialized_bytes\":3"], "missing byte count"),
        (&["\"pages\":["], "missing pages array"),
        (
            &[
                "\"page_index\":0",
                "\"cursor\":0",
                "\"next_cursor\":128",
                "\"done\":false",
                "\"data_hex\":\"aabb\"",
            ],
            "missing first page fields",
        ),
        (
            &[
                "\"page_index\":1",
                "\"cursor\":128",
                "\"next_cursor\":129",
                "\"done\":true",
                "\"flags\":1",
                "\"data_hex\":\"cc\"",
            ],
            "missing final page fields",
        ),
    ];
    for (needles, failure) in checks {
        if !has_all(needles) {
            return Err(failure);
        }
    }
    if buf.contains("\"serialized_chunks\"") {
        return Err("old chunk field still emitted");
    }

    let doc = emitted(4096, |e| {
        e.obj_open();
        e.kv_int(b"schema", 1);
        e.kv_string(b"upatch", b"exec-uid-arena");
        e.kv_string(b"map", b"tree_arena");
        e.obj_open_key(b"data");
        emit_json_fields(e, v);
        e.obj_close();
        e.obj_close();
    })
    .ok_or("wrapped json emit failed")?;
    if doc.contains("\"data\":{{") {
        return Err("wrapped map JSON emitted nested data object");
    }
    if !doc.contains("\"data\":{\"name\":\"tree_arena\"") {
        return Err("wrapped map JSON missing single data object");
    }
    Ok(())
}

fn run(_: &[&CStr]) -> c_int {
    let pages = vec![
        SerialPage {
            page_index: 0,
            cursor: 0,
            next_cursor: 128,
            flags: 0,
            chunks: 1,
            done: false,
            data: vec![0xaa, 0xbb],
        },
        SerialPage {
            page_index: 1,
            cursor: 128,
            next_cursor: 129,
            flags: 1,
            chunks: 1,
            done: true,
            data: vec![0xcc],
        },
    ];
    let mut v = MapView {
        type_name: Some(c"arena"),
        max_entries: 32,
        serialized: true,
        serial_bytes_total: pages.iter().map(|p| u64::from(p.bytes())).sum(),
        serial_pages: pages,
        ..MapView::default()
    };
    v.name[..10].copy_from_slice(b"tree_arena");

    match abi_and_nonce().and_then(|()| map_locks()) {
        Err(failure) => {
            err(&format!("{failure}\n"));
            1
        }
        Ok(()) => match json(&v) {
            Err(failure) => {
                err(&format!("{failure}\n"));
                1
            }
            Ok(()) => {
                out("ok\n");
                0
            }
        },
    }
}
