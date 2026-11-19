// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-upatch-decode: what the decoder an upatch artifact carries
//! makes of a map, or the bytecode LuaJIT makes of a decoder's source.
//!
//!   test-upatch-decode json|otel|loop|memory|utf8 <file.upatch>
//!   test-upatch-decode dump <decoder.lua>
//!
//! loop, memory and utf8 are JSON decodes of a map whose serialized size
//! tells the test's decoder which of its misbehaviours to show.

use core::ffi::{CStr, c_char, c_int, c_void};

use super::{err, helper_main, out_bytes};
use crate::sys::luajit::{LuaState, lua_close, luaL_newstate};
use crate::sys::upatch_maps::MapView;
use crate::util::decode::{JSON_MAX, decode_map};

helper_main!(shirudo_helper_test_upatch_decode, run);

type LuaWriter =
    unsafe extern "C-unwind" fn(*mut LuaState, *const c_void, usize, *mut c_void) -> c_int;

unsafe extern "C-unwind" {
    fn luaL_loadfile(l: *mut LuaState, path: *const c_char) -> c_int;
    fn lua_dump(l: *mut LuaState, writer: LuaWriter, data: *mut c_void) -> c_int;
}

/// A chunk of the dump, written to standard output.
unsafe extern "C-unwind" fn dump_chunk(
    _: *mut LuaState,
    p: *const c_void,
    n: usize,
    _: *mut c_void,
) -> c_int {
    // SAFETY: the n bytes LuaJIT hands over.
    c_int::from(!out_bytes(unsafe { crate::ffi::slice(p.cast(), n) }))
}

/// The bytecode LuaJIT makes of a source file, for a decoder that is
/// none.
fn dump(source: &CStr) -> c_int {
    // SAFETY: a state of its own, loaded, dumped and closed here.
    unsafe {
        let l = luaL_newstate();
        if l.is_null() {
            return 1;
        }
        let ret = match luaL_loadfile(l, source.as_ptr()) {
            0 => lua_dump(l, dump_chunk, core::ptr::null_mut()),
            _ => 1,
        };
        lua_close(l);
        c_int::from(ret != 0)
    }
}

fn run(args: &[&CStr]) -> c_int {
    let (how, file) = match args {
        [_, how, file] => (how.to_bytes(), *file),
        _ => (&b""[..], c""),
    };
    if how == b"dump" {
        return dump(file);
    }
    let serial_bytes_total = match how {
        b"json" | b"otel" => 0,
        b"memory" => 997,
        b"utf8" => 998,
        b"loop" => 999,
        _ => {
            let me = args
                .first()
                .map_or("test-upatch-decode".into(), |a| a.to_string_lossy());
            err(&format!(
                "usage: {me} <json|otel|loop|memory|utf8> <file.upatch>\n       {me} dump <decoder.lua>\n"
            ));
            return 2;
        }
    };
    let mut view = MapView {
        serialized: true,
        max_entries: 1,
        type_name: Some(c"array"),
        serial_bytes_total,
        ..MapView::default()
    };
    view.upatch[..5].copy_from_slice(b"t3002");
    view.name[..9].copy_from_slice(b"t0005_map");

    match decode_map(&view, Some(file), how == b"otel", JSON_MAX) {
        Ok(out) => c_int::from(!out_bytes(&out)),
        Err(ret) => {
            err(&format!("decode: {ret}\n"));
            1
        }
    }
}
