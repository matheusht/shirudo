// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::testutil::{TempDir, serial};
use crate::util::upatch::{
    DECODER_MAGIC, HEADER_SIZE, MAGIC, SECTION_DECODERS, SIGNED_TRAILER_MAGIC, TYPE_BPF,
};
use std::os::fd::AsRawFd;
use std::sync::{Mutex, MutexGuard};

/// The container testing/unit/upatch_decode.c built as a struct: a
/// header, one exiting instruction, a signature, then the data: a decoder
/// blob of one Lua decoder, its source, the section directory and the
/// trailer.
const LOADER: usize = HEADER_SIZE;
const SIGNATURE: usize = LOADER + 8;
const DATA: usize = SIGNATURE + 8;
const ENTRY: usize = DATA + 16;
const SOURCE: usize = ENTRY + 200;
const SECTION: usize = SOURCE + 256;
const TRAILER: usize = SECTION + 16;
const END: usize = TRAILER + 16;

fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn put_bytes(b: &mut [u8], off: usize, s: &[u8]) {
    b[off..off + s.len()].copy_from_slice(s);
}

fn put_str(b: &mut [u8], off: usize, s: &str) {
    put_bytes(b, off, s.as_bytes());
}

/// A container of one decoder of upatch "unit-decoder" for map
/// "records", whose Lua is `source`.
fn container(upatch: &[u8], decoder_upatch: &[u8], source: &str) -> Vec<u8> {
    let mut b = vec![0u8; END];

    b[..8].copy_from_slice(&MAGIC.to_le_bytes());
    put32(&mut b, 8, 1);
    put_bytes(&mut b, 16, upatch);
    let header = 16 + 256 + 32;
    for (i, v) in [LOADER, 8, SIGNATURE, 8, 0, 0, DATA, END - DATA]
        .iter()
        .enumerate()
    {
        put32(&mut b, header + 4 * i, *v as u32);
    }
    put32(&mut b, HEADER_SIZE - 8, TYPE_BPF);
    // BPF_JMP | BPF_EXIT.
    b[LOADER] = 0x95;
    for (i, v) in [DECODER_MAGIC, 1, 1].iter().enumerate() {
        put32(&mut b, DATA + 4 * i, *v);
    }
    // Lua, API 1, map input 1, exported as a log.
    for i in 0..4 {
        put32(&mut b, ENTRY + 4 * i, 1);
    }
    put_bytes(&mut b, ENTRY + 16, decoder_upatch);
    put_str(&mut b, ENTRY + 80, "records");
    put_str(&mut b, ENTRY + 96, "unit.lua");
    put_str(&mut b, ENTRY + 160, "decode");
    put32(&mut b, ENTRY + 192, (SOURCE - DATA) as u32);
    put32(&mut b, ENTRY + 196, source.len() as u32);
    put_str(&mut b, SOURCE, source);
    put32(&mut b, SECTION, SECTION_DECODERS);
    put32(&mut b, SECTION + 12, (16 + 200 + source.len()) as u32);
    for (i, v) in [SIGNED_TRAILER_MAGIC, 1, (SECTION - DATA) as u32, 1]
        .iter()
        .enumerate()
    {
        put32(&mut b, TRAILER + 4 * i, *v);
    }
    b
}

/// Held while a decoder runs, so the tests run one at a time, as shirudo
/// does: one decoder per process. On riscv64, LuaJIT (Debian's OpenResty
/// 2.1 build, under qemu-user in CI) crashes when Lua states on two threads
/// raise errors at once; a C program with no Rust in it, four threads each
/// making a state, a count hook that raises and a C function that raises,
/// crashes the same way, so the fault is not this crate's.
fn one_decoder() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// What the decoder of `source`, whose entry names `decoder_upatch`,
/// makes of map "records" belonging to `upatch`: its JSON, or error.
fn decoded_named(upatch: &[u8], decoder_upatch: &[u8], source: &str) -> Result<Vec<u8>, c_int> {
    let _one = one_decoder();
    let dir = TempDir::new();
    std::fs::write(dir.join("u"), container(upatch, decoder_upatch, source)).unwrap();
    let mut view = MapView {
        serialized: true,
        max_entries: 1,
        type_name: Some(c"array"),
        ..MapView::default()
    };
    put_bytes(&mut view.upatch, 0, upatch);
    put_str(&mut view.name, 0, "records");
    decode_map(&view, Some(&dir.cpath("u")), false, JSON_MAX)
}

fn decoded(source: &str) -> Result<Vec<u8>, c_int> {
    decoded_named(b"unit-decoder", b"unit-decoder", source)
}

#[test]
fn decoder_initializes_and_returns_json() {
    assert_eq!(
        decoded("function decode(input) return {value = 42} end"),
        Ok(br#"{"value":42}"#.to_vec())
    );
}

#[test]
fn decoder_of_a_upatch_with_the_longest_name_runs() {
    let name = [b'n'; crate::util::upatch::NAME_MAX - 1];

    assert_eq!(
        decoded_named(
            &name,
            b"",
            "function decode(input) return {len = #input.upatch} end"
        ),
        Ok(br#"{"len":255}"#.to_vec())
    );
}

#[test]
fn decoder_instruction_limit_is_enforced() {
    assert_eq!(
        decoded("function decode(input) while true do end end"),
        Err(-EINVAL)
    );
}

#[test]
fn decoder_memory_limit_is_enforced() {
    assert_eq!(
        decoded("function decode(input) return string.rep('x', 64 * 1024 * 1024) end"),
        Err(-EINVAL)
    );
}

#[test]
fn decoder_protected_loops_hit_the_limit() {
    assert_eq!(
        decoded(
            "function decode(input) while true do pcall(function() while true do end end) end end"
        ),
        Err(-EINVAL)
    );
    assert_eq!(
        decoded(
            "function decode(input) local co = coroutine.wrap(function() \
             while true do pcall(function() while true do end end) \
             coroutine.yield() end end) \
             while true do pcall(co) end end"
        ),
        Err(-EINVAL)
    );
}

#[test]
fn decoder_cannot_reach_unbudgeted_code() {
    assert_eq!(
        decoded(
            "function decode(input) return {reach = tostring(newproxy) .. \
             tostring(xpcall) .. tostring(print) .. tostring(string.find) .. \
             tostring(string.match) .. tostring(string.gmatch) .. \
             tostring(string.gsub)} end"
        ),
        Ok(br#"{"reach":"nilnilnilnilnilnilnil"}"#.to_vec())
    );
    assert_eq!(
        decoded(
            "function decode(input) local s = shirudo.page_slots(\
             {chunks = '1', data_hex = string.rep('00', 64)}, 8) \
             return {mt = getmetatable(s[1])} end"
        ),
        Ok(br#"{"mt":"shirudo.slot"}"#.to_vec())
    );
}

#[test]
fn fixed_records_keep_the_first_slot_of_a_chunked_page() {
    assert_eq!(
        decoded(
            "function decode(input) local r = shirudo.fixed_records({{\
             cursor = '0', chunks = '2', \
             data_hex = '07' .. string.rep('00', 4041)}}, 5) \
             return {got = tostring(r[1] and r[1]:u8(0)) .. ',' .. \
             tostring(r[807] ~= nil)} end"
        ),
        Ok(br#"{"got":"7,true"}"#.to_vec())
    );
}

#[test]
fn decoder_entrypoint_lookup_is_protected() {
    assert_eq!(
        decoded("return setmetatable({}, {__index = function() error('lookup', 0) end})"),
        Err(-EINVAL)
    );
    assert_eq!(
        decoded("return setmetatable({}, {__index = function() while true do end end})"),
        Err(-EINVAL)
    );
    assert_eq!(
        decoded("setmetatable(_G, {__index = function() error('global', 0) end})"),
        Err(-EINVAL)
    );
}

#[test]
fn decoder_error_is_sanitized() {
    let _serial = serial();
    let dir = TempDir::new();
    let capture = std::fs::File::create(dir.join("stderr")).unwrap();

    // SAFETY: standard error saved, pointed at the capture for the
    // decode, and put back.
    let saved = unsafe { libc::dup(2) };
    assert!(saved >= 0);
    // SAFETY: as above.
    assert_eq!(unsafe { libc::dup2(capture.as_raw_fd(), 2) }, 2);
    let ret = decoded("function decode(input) error('\\27]0;title\\7', 0) end");
    // SAFETY: as above.
    unsafe {
        assert_eq!(libc::dup2(saved, 2), 2);
        libc::close(saved);
    }
    assert_eq!(ret, Err(-EINVAL));
    let output = std::fs::read(dir.join("stderr")).unwrap();
    assert!(
        crate::text::find(&output, b"decoder failed: ?]0;title?\n").is_some(),
        "{output:?}"
    );
    assert!(!output.contains(&0x1b));
}
