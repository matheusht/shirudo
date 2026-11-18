// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-decoder: the map data a signed Lua decoder reads through the
//! host API, a page at a cursor and array entries made of the input,
//! under the kernel-obs decoders and the fixture that reads fixed
//! records, which it reads from the tree the library was built from.
//!
//! The input is the decoder's index, the page's cursor, eight bytes,
//! then the page.

use core::ffi::c_char;
use std::sync::OnceLock;

use crate::fuzzing::fuzz_target;
use crate::sys::upatch_maps::{MapEntry, MapView, SerialPage};
use crate::util::json::MAX_BYTES;
use crate::util::serializer::SERIAL_CHUNK_PAYLOAD;
use crate::util::upatch::DecoderView;

const SOURCES: [&str; 9] = [
    "upatches/kernel-obs/decoders/dns.lua",
    "upatches/kernel-obs/decoders/exec.lua",
    "upatches/kernel-obs/decoders/file.lua",
    "upatches/kernel-obs/decoders/listen.lua",
    "upatches/kernel-obs/decoders/net.lua",
    "upatches/kernel-obs/decoders/priv.lua",
    "upatches/kernel-obs/decoders/watch.lua",
    "upatches/kernel-obs/decoders/watch_stat.lua",
    "testing/fixtures/decoders/counters.lua",
];

/// The decoders, each over its source, which the process keeps.
struct Views(Vec<DecoderView>);

// SAFETY: made once, then only read, by the fuzzer's one thread.
unsafe impl Sync for Views {}
// SAFETY: as Sync.
unsafe impl Send for Views {}

static VIEWS: OnceLock<Views> = OnceLock::new();

fn init() {
    let tree = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let views = SOURCES
        .iter()
        .map(|rel| {
            let Ok(source) = std::fs::read(tree.join(rel)) else {
                std::process::abort();
            };
            let source = Box::leak(source.into_boxed_slice());
            // SAFETY: a view of nothing, for which zeros are the value.
            let mut d: DecoderView = unsafe { core::mem::zeroed() };
            d.source = source.as_ptr().cast::<c_char>();
            d.source_len = source.len() as u32;
            let name = rel.rsplit('/').next().unwrap_or(rel).as_bytes();
            let n = name.len().min(d.source_name.len() - 1);
            d.source_name[..n].copy_from_slice(&name[..n]);
            d.entrypoint[..6].copy_from_slice(b"decode");
            d
        })
        .collect();
    let _ = VIEWS.set(Views(views));
}

fuzz_target!(
    shirudo_fuzz_decoder,
    shirudo_fuzz_decoder_init,
    |data| {
        let (Some(views), [index, cursor @ ..]) = (VIEWS.get(), data) else {
            return;
        };
        if data.len() < 9 {
            return;
        }
        let d = &views.0[usize::from(*index) % views.0.len()];
        let mut page_data = data[9..].to_vec();
        page_data.push(0);
        let size = data.len() - 9;
        // SAFETY: a page of nothing, for which zeros are the value.
        let mut page: SerialPage = unsafe { core::mem::zeroed() };
        page.cursor = u64::from_ne_bytes(cursor[..8].try_into().unwrap_or_default());
        page.data = page_data.as_mut_ptr().cast();
        page.bytes = size as u32;
        page.chunks = if size == 0 {
            1
        } else {
            ((size - 1) / SERIAL_CHUNK_PAYLOAD as usize + 1) as u32
        };
        page.done = true;
        let mut entries: [MapEntry; 32] = core::array::from_fn(|_| MapEntry {
            key: core::ptr::null_mut(),
            value: core::ptr::null_mut(),
        });
        // SAFETY: a view of nothing, for which zeros are the value, filled
        // as the C target set it.
        let mut v: Box<MapView> = Box::new(unsafe { core::mem::zeroed() });
        v.type_name = Some(c"array");
        v.key_size = 4;
        v.value_size = 8;
        v.value_stride = 8;
        v.n_cpus = 1;
        v.max_entries = entries.len() as u32;
        v.serialized = true;
        v.n_serial_pages = 1;
        v.upatch[..4].copy_from_slice(b"fuzz");
        v.name[..8].copy_from_slice(b"fuzz_map");
        v.serial_pages = &raw mut page;
        v.serial_bytes_total = size as u64;
        let mut n = 0;
        while n < entries.len() && (n + 1) * 12 <= size {
            // SAFETY: twelve bytes of the page for the entry.
            unsafe {
                entries[n].key = page_data.as_mut_ptr().add(n * 12).cast();
                entries[n].value = page_data.as_mut_ptr().add(n * 12 + 4).cast();
            }
            n += 1;
        }
        v.n_entries = n as u32;
        v.entries = entries.as_mut_ptr();
        for otel in [false, true] {
            let _ = super::run(d, &v, otel, MAX_BYTES);
        }
    },
    init
);
