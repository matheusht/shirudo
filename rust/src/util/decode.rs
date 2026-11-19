// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The signed decoders of an upatch: Lua source that turns a map's raw
//! bytes into JSON or an OTLP AnyValue, run in a LuaJIT sandbox. The
//! sandbox has no io, os, package, debug, jit, ffi, load or garbage
//! collector control; it has 32 MiB of memory, scrubbed when freed, and
//! a budget of a million instructions with the JIT off so the budget
//! sees each; and its host API reads fixed-size records out of a
//! serializer's pages and does exact 64-bit arithmetic on decimal
//! strings.

use core::cell::Cell;
use core::ffi::{CStr, c_int, c_void};
use core::ptr;
use std::ffi::CString;
use std::os::fd::AsRawFd;

use crate::errno::{E2BIG, EINVAL, ENAMETOOLONG, ENODATA, ENOENT, ENOMEM, ERANGE, ESTALE, text};
use crate::ffi;
use crate::sys::libc::{explicit_bzero, snprintf};
use crate::sys::luajit::{
    Allocator, LUA_MASKCOUNT, LUA_REGISTRYINDEX, LUA_TFUNCTION, LUA_TSTRING, LUA_TTABLE,
    LUAJIT_MODE_ENGINE, LUAJIT_MODE_OFF, Lua, LuaDebug, LuaState, LuaType, Stack, lua_getfield,
    lua_getglobal, lua_gettop, lua_newtable, lua_newuserdata, lua_objlen, lua_pcall, lua_pop,
    lua_pushcclosure, lua_pushcfunction, lua_pushinteger, lua_pushlightuserdata, lua_pushlstring,
    lua_pushnil, lua_pushnumber, lua_pushstring, lua_pushvalue, lua_rawgeti, lua_rawseti,
    lua_remove, lua_setfield, lua_setglobal, lua_sethook, lua_setmetatable, lua_tolstring,
    lua_tonumber, lua_touserdata, lua_type, lua_upvalueindex, luaJIT_setmode, luaL_argerror,
    luaL_checkinteger, luaL_checklstring, luaL_checktype, luaL_checkudata, luaL_error,
    luaL_loadbufferx, luaL_newmetatable, luaL_openlibs, lual_getmetatable,
};
use crate::sys::upatch_maps::MapView;
use crate::text::cstr;
use crate::util::chain::memneq_explicit;
use crate::util::json::JsonEmit;
use crate::util::seal;
use crate::util::upatch::{self, DecoderView, Opened, upatch_decoder_view};
use crate::util::upatch_verify::payload_digest;

const INSN_LIMIT: c_int = 1_000_000;
const HOOK_COUNT: c_int = 10_000;
const MEMORY_LIMIT: usize = 32 * 1024 * 1024;
const JSON_MAX_DEPTH: c_int = 32;
pub(crate) const JSON_MAX: usize = 8 * 1024 * 1024;
const SLOT_MT: &CStr = c"shirudo.slot";
/// SERIAL_CHUNK_PAYLOAD of bpf/lib/serializer.h.
const CHUNK_PAYLOAD: usize = 4032;
/// The largest integer a double holds exactly.
const MAX_EXACT: f64 = 9_007_199_254_740_991.0;
const UPATCHES_DIR: &str = "/var/lib/shirudo/upatches";
const PATH_MAX: usize = 4096;
/// UPATCH_DECODER_LANG_LUA, _INPUT_MAP_V1 and _EXPORT_LOG and _METRIC.
const LANG_LUA: u32 = 1;
const INPUT_MAP_V1: u32 = 1;
const EXPORT_LOG: u32 = 1;
const EXPORT_METRIC: u32 = 2;

/// isspace() of the C locale.
fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// A double as printf() spells it with `fmt`, which takes one.
fn printf_double(fmt: &CStr, v: f64) -> Vec<u8> {
    let mut buf = [0u8; 64];
    // SAFETY: the room for the text and a format of one double.
    let n = unsafe { snprintf(buf.as_mut_ptr().cast(), buf.len(), fmt.as_ptr(), v) };
    buf[..(n.max(0) as usize).min(buf.len() - 1)].to_vec()
}

/// lua_absindex(), which the 5.1 API lacks.
///
/// # Safety
///
/// `l` is a state.
unsafe fn absindex(l: *mut LuaState, idx: c_int) -> c_int {
    if idx > 0 || idx <= LUA_REGISTRYINDEX {
        return idx;
    }
    // SAFETY: the caller's state.
    unsafe { lua_gettop(l) + idx + 1 }
}

/// The string at `idx` and its length, or None.
///
/// # Safety
///
/// `l` is a state; the bytes live while the value stays on the stack.
unsafe fn to_bytes<'a>(l: *mut LuaState, idx: c_int) -> Option<&'a [u8]> {
    let mut n = 0usize;
    // SAFETY: the caller's state and room for the length.
    let s = unsafe { lua_tolstring(l, idx, &mut n) };
    // SAFETY: Lua's n bytes.
    (!s.is_null()).then(|| unsafe { crate::ffi::slice(s.cast::<u8>(), n) })
}

/// What the decoder's memory has used, against its limit.
struct Memory<'a> {
    inner: Option<Allocator<'a>>,
    used: usize,
}

/// The decoder's allocator: LuaJIT's own, as a GC64 state must live
/// below 2^47, which LuaJIT's allocator guarantees and a PIE's heap on
/// arm64 does not meet; held to the limit, and what is freed scrubbed
/// first.
///
/// # Safety
///
/// `ud` holds this state's memory record. A non-null `p` is a block
/// of `old` bytes from its allocator.
unsafe extern "C" fn limited_alloc(
    ud: *mut c_void,
    p: *mut c_void,
    old: usize,
    new: usize,
) -> *mut c_void {
    // SAFETY: the caller passes the live, exclusive memory record.
    let m = unsafe { &mut *ud.cast::<Memory<'_>>() };
    let Some(inner) = &m.inner else {
        return ptr::null_mut();
    };
    let base = if !p.is_null() && m.used >= old {
        m.used - old
    } else {
        m.used
    };
    if new == 0 {
        if !p.is_null() {
            // SAFETY: p is writable for the old allocation's full size.
            unsafe { explicit_bzero(p, old) };
            // SAFETY: p is the allocator's live block of old bytes.
            unsafe { inner.resize(p, old, 0) };
            m.used = base;
        }
        return ptr::null_mut();
    }
    let Some(total) = base.checked_add(new).filter(|&t| t <= MEMORY_LIMIT) else {
        return ptr::null_mut();
    };
    // SAFETY: a null pointer requests a fresh block.
    let next = unsafe { inner.resize(ptr::null_mut(), 0, new) };
    if next.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the allocator gave us a writable block of new bytes.
    unsafe { next.cast::<u8>().write_bytes(0, new) };
    if !p.is_null() {
        // SAFETY: the old and new allocations are disjoint and this fits both.
        unsafe { ptr::copy_nonoverlapping(p.cast::<u8>(), next.cast::<u8>(), old.min(new)) };
        // SAFETY: p is writable for the old allocation's full size.
        unsafe { explicit_bzero(p, old) };
        // SAFETY: p is the allocator's live block of old bytes.
        unsafe { inner.resize(p, old, 0) };
    }
    m.used = total;
    next
}

/// Where a table key stands in an array: a whole number from 1 to the
/// largest int.
fn array_index(key: f64) -> Option<c_int> {
    // `as` saturates, and only a whole number in range comes back equal.
    let index = key as c_int;
    (index >= 1 && f64::from(index) == key).then_some(index)
}

/// Whether the table at `idx` is an array, 1 to its length with no
/// other key, and that length.
fn table_array_len(s: &mut Stack<'_>, idx: c_int) -> Option<c_int> {
    let idx = s.abs_index(idx)?;
    let (mut count, mut max, mut array) = (0, 0, true);
    s.push_nil();
    while s.next(idx) {
        let index = (s.type_of(-2) == LuaType::Number)
            .then(|| array_index(s.to_number(-2)))
            .flatten();
        match index {
            Some(index) => {
                max = max.max(index);
                count += 1;
            }
            None => array = false,
        }
        s.pop(1);
    }
    (array && count == max).then_some(max)
}

/// Whether a value of the type can be a key in the JSON.
fn is_key(t: LuaType) -> bool {
    matches!(t, LuaType::String | LuaType::Number | LuaType::Boolean)
}

/// A table key as text: a string as it is, a number and a boolean
/// spelled out. A name the kernel hands over is raw bytes, cut at a
/// fixed length mid-character as often as not, and one bad byte must
/// not cost the whole snapshot: the lossy writers make it U+FFFD.
fn emit_key(s: &Stack<'_>, idx: c_int, e: &mut JsonEmit, as_key: bool) {
    let number;
    let text: &[u8] = match s.type_of(idx) {
        LuaType::String => s.to_bytes(idx).unwrap_or_default(),
        LuaType::Number => {
            number = printf_double(c"%.17g", s.to_number(idx));
            &number
        }
        LuaType::Boolean if s.to_bool(idx) => b"true",
        LuaType::Boolean => b"false",
        _ => b"unsupported_key",
    };
    if as_key {
        e.key_lossy(text)
    } else {
        e.str_lossy(text)
    }
}

/// The Lua value at `idx` as JSON, into `e`, whose error says whether it
/// could be.
fn json_value(s: &mut Stack<'_>, idx: c_int, e: &mut JsonEmit, depth: c_int) {
    if depth > JSON_MAX_DEPTH {
        e.set_err(-E2BIG);
        return;
    }
    match s.type_of(idx) {
        LuaType::Nil => e.raw_value(b"null"),
        LuaType::Boolean if s.to_bool(idx) => e.raw_value(b"true"),
        LuaType::Boolean => e.raw_value(b"false"),
        LuaType::Number => {
            let v = s.to_number(idx);
            if !v.is_finite() {
                e.set_err(-EINVAL);
            } else {
                e.raw_value(&printf_double(c"%.17g", v));
            }
        }
        LuaType::String => e.str_lossy(s.to_bytes(idx).unwrap_or_default()),
        LuaType::Table => json_table(s, idx, e, depth),
        _ => e.set_err(-EINVAL),
    }
}

fn json_table(s: &mut Stack<'_>, idx: c_int, e: &mut JsonEmit, depth: c_int) {
    let Some(idx) = s.abs_index(idx) else {
        e.set_err(-EINVAL);
        return;
    };
    if let Some(len) = table_array_len(s, idx) {
        e.arr_open_value();
        for i in 1..=len {
            if e.err() != 0 {
                break;
            }
            s.raw_get_index(idx, i);
            json_value(s, -1, e, depth + 1);
            s.pop(1);
        }
        e.arr_close();
        return;
    }
    e.obj_value_open();
    s.push_nil();
    while s.next(idx) {
        if !is_key(s.type_of(-2)) {
            e.set_err(-EINVAL);
            s.pop(2);
            break;
        }
        emit_key(s, -2, e, true);
        json_value(s, -1, e, depth + 1);
        s.pop(1);
        if e.err() != 0 {
            s.pop(1);
            break;
        }
    }
    e.obj_close();
}

/// The Lua value at `idx` as the OTLP JSON form of an AnyValue, into
/// `e`, whose error says whether it could be.
fn otel_value(s: &mut Stack<'_>, idx: c_int, e: &mut JsonEmit, depth: c_int) {
    if depth > JSON_MAX_DEPTH {
        e.set_err(-E2BIG);
        return;
    }
    match s.type_of(idx) {
        // An empty AnyValue is the OTLP form of nil.
        LuaType::Nil => {
            e.obj_value_open();
            e.obj_close();
        }
        LuaType::Boolean => {
            e.obj_value_open();
            e.kv_bool(b"boolValue", s.to_bool(idx));
            e.obj_close();
        }
        LuaType::Number => {
            let v = s.to_number(idx);
            if !v.is_finite() {
                e.set_err(-EINVAL);
            } else {
                e.obj_value_open();
                if v.trunc() == v && v.abs() <= MAX_EXACT {
                    e.kv_string(
                        b"intValue",
                        &printf_double(c"%.0f", if v == 0.0 { 0.0 } else { v }),
                    );
                } else {
                    e.kv_raw(b"doubleValue", &printf_double(c"%.17g", v));
                }
                e.obj_close();
            }
        }
        LuaType::String => {
            e.obj_value_open();
            e.key(b"stringValue");
            e.str_lossy(s.to_bytes(idx).unwrap_or_default());
            e.obj_close();
        }
        LuaType::Table => otel_table(s, idx, e, depth),
        _ => e.set_err(-EINVAL),
    }
}

fn otel_table(s: &mut Stack<'_>, idx: c_int, e: &mut JsonEmit, depth: c_int) {
    let Some(idx) = s.abs_index(idx) else {
        e.set_err(-EINVAL);
        return;
    };
    e.obj_value_open();
    if let Some(len) = table_array_len(s, idx) {
        e.obj_open_key(b"arrayValue");
        e.arr_open(b"values");
        for i in 1..=len {
            if e.err() != 0 {
                break;
            }
            s.raw_get_index(idx, i);
            otel_value(s, -1, e, depth + 1);
            s.pop(1);
        }
        e.arr_close();
        e.obj_close();
        e.obj_close();
        return;
    }
    e.obj_open_key(b"kvlistValue");
    e.arr_open(b"values");
    s.push_nil();
    while s.next(idx) {
        if !is_key(s.type_of(-2)) {
            e.set_err(-EINVAL);
            s.pop(2);
            break;
        }
        e.obj_value_open();
        e.key(b"key");
        emit_key(s, -2, e, false);
        e.key(b"value");
        otel_value(s, -1, e, depth + 1);
        e.obj_close();
        s.pop(1);
        if e.err() != 0 {
            s.pop(1);
            break;
        }
    }
    e.arr_close();
    e.obj_close();
    e.obj_close();
}

/// The hex at `hex` decoded into a userdata pushed on the stack, which
/// the collector frees: a Lua error raised while the bytes are in use
/// would leak a buffer of our own. Blanks between digits are skipped.
///
/// # Safety
///
/// `l` is a state; `hex` stays valid meanwhile.
unsafe fn hex_decode_push(l: *mut LuaState, hex: &[u8]) -> Option<(*const u8, usize)> {
    let digits = hex.iter().filter(|&&c| !is_c_space(c)).count();
    if digits % 2 != 0 {
        return None;
    }
    // SAFETY: the caller's state; a userdata of digits / 2 bytes.
    let buf = unsafe { lua_newuserdata(l, digits / 2) }.cast::<u8>();
    let (mut i, mut off) = (0, 0);
    let skip = |i: &mut usize| {
        while *i < hex.len() && is_c_space(hex[*i]) {
            *i += 1;
        }
    };
    loop {
        skip(&mut i);
        if i >= hex.len() {
            break;
        }
        let hi = hex_nibble(hex[i]);
        i += 1;
        skip(&mut i);
        let lo = if i < hex.len() {
            hex_nibble(hex[i])
        } else {
            None
        };
        let (Some(hi), Some(lo)) = (hi, lo) else {
            // SAFETY: the userdata pushed above.
            unsafe { lua_pop(l, 1) };
            return None;
        };
        i += 1;
        // SAFETY: within the digits / 2 bytes of the userdata.
        unsafe { *buf.add(off) = hi << 4 | lo };
        off += 1;
    }
    Some((buf, off))
}

/// A slot: a userdata of a length and the bytes of one record.
///
/// # Safety
///
/// `l` is a state.
unsafe fn push_slot(l: *mut LuaState, data: *const u8, len: usize) {
    // SAFETY: the caller's state; a userdata of the length and the bytes,
    // given the slot metatable.
    unsafe {
        let slot = lua_newuserdata(l, 4 + len).cast::<u8>();
        slot.cast::<u32>().write_unaligned(len as u32);
        ptr::copy_nonoverlapping(data, slot.add(4), len);
        lual_getmetatable(l, SLOT_MT.as_ptr());
        lua_setmetatable(l, -2);
    }
}

/// The slot the method is called on, its bytes.
///
/// # Safety
///
/// `l` is a state in a slot method; raises when argument 1 is not one.
unsafe fn check_slot<'a>(l: *mut LuaState) -> &'a [u8] {
    // SAFETY: the caller's state; a slot userdata, its length first.
    unsafe {
        let slot = luaL_checkudata(l, 1, SLOT_MT.as_ptr()).cast::<u8>();
        let len = slot.cast::<u32>().read_unaligned() as usize;
        crate::ffi::slice(slot.add(4), len)
    }
}

/// An int argument, raising for one out of range.
///
/// # Safety
///
/// `l` is a state in a C function.
unsafe fn check_c_int(l: *mut LuaState, arg: c_int) -> c_int {
    // SAFETY: the caller's state.
    let v = unsafe { luaL_checkinteger(l, arg) };
    if v < c_int::MIN as isize || v > c_int::MAX as isize {
        // SAFETY: as above; this raises.
        unsafe { luaL_argerror(l, arg, c"integer out of range".as_ptr()) }
    }
    v as c_int
}

fn read_le(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0u64, |v, &b| v << 8 | u64::from(b))
}

/// The `width` bytes at `off` of the slot, little-endian, or 0 past it.
fn slot_word(slot: &[u8], off: c_int, width: usize) -> u64 {
    if off < 0 || off as i64 > slot.len() as i64 - width as i64 {
        return 0;
    }
    read_le(&slot[off as usize..off as usize + width])
}

unsafe extern "C-unwind" fn slot_u8(l: *mut LuaState) -> c_int {
    // SAFETY: the method's state.
    unsafe {
        let slot = check_slot(l);
        let off = check_c_int(l, 2);
        lua_pushinteger(l, slot_word(slot, off, 1) as isize);
    }
    1
}

unsafe extern "C-unwind" fn slot_u16(l: *mut LuaState) -> c_int {
    // SAFETY: the method's state.
    unsafe {
        let slot = check_slot(l);
        let off = check_c_int(l, 2);
        lua_pushinteger(l, slot_word(slot, off, 2) as isize);
    }
    1
}

unsafe extern "C-unwind" fn slot_u32(l: *mut LuaState) -> c_int {
    // SAFETY: the method's state.
    unsafe {
        let slot = check_slot(l);
        let off = check_c_int(l, 2);
        lua_pushnumber(l, slot_word(slot, off, 4) as f64);
    }
    1
}

unsafe extern "C-unwind" fn slot_u64(l: *mut LuaState) -> c_int {
    // SAFETY: the method's state.
    unsafe {
        let slot = check_slot(l);
        let off = check_c_int(l, 2);
        push_u64_string(&mut Stack::from_raw(l), slot_word(slot, off, 8));
    }
    1
}

/// The NUL-terminated string at `off`, of `len` bytes at most and of
/// `max` when `len` is not in 1 to `max`, within the slot.
unsafe extern "C-unwind" fn slot_cstring(l: *mut LuaState) -> c_int {
    // SAFETY: the method's state.
    unsafe {
        let slot = check_slot(l);
        let off = check_c_int(l, 2);
        let mut len = if lua_gettop(l) >= 3 {
            check_c_int(l, 3)
        } else {
            0
        };
        let max = if lua_gettop(l) >= 4 {
            check_c_int(l, 4)
        } else {
            len
        };
        if off < 0 || off as usize >= slot.len() || max <= 0 {
            lua_pushlstring(l, c"".as_ptr(), 0);
            return 1;
        }
        if len <= 0 || len > max {
            len = max;
        }
        let len = (len as usize).min(slot.len() - off as usize);
        let s = &slot[off as usize..off as usize + len];
        let n = s.iter().position(|&c| c == 0).unwrap_or(len);
        lua_pushlstring(l, s.as_ptr().cast(), n);
    }
    1
}

/// A page's numeric field, 0 unless it is a whole number a double holds
/// exactly.
///
/// # Safety
///
/// `l` is a state with a table at `idx`.
unsafe fn page_u64(l: *mut LuaState, idx: c_int, field: &CStr) -> u64 {
    // SAFETY: the caller's state and table.
    let n = unsafe {
        let idx = absindex(l, idx);
        lua_getfield(l, idx, field.as_ptr());
        let n = lua_tonumber(l, -1);
        lua_pop(l, 1);
        n
    };
    if !n.is_finite() || !(0.0..=MAX_EXACT).contains(&n) {
        0
    } else {
        n as u64
    }
}

/// The record at absolute index `abs` into the slots table.
///
/// # Safety
///
/// `l` is a state with the slots table at `slots`; raises for an index
/// past an int.
unsafe fn store_slot(l: *mut LuaState, slots: c_int, abs: u64, data: *const u8, size: usize) {
    // SAFETY: the caller's state.
    unsafe {
        if abs >= c_int::MAX as u64 {
            luaL_error(l, c"slot index too large".as_ptr());
        }
        push_slot(l, data, size);
        lua_rawseti(l, slots, abs as c_int + 1);
    }
}

/// A page's records into the slots table by their absolute index: the
/// serializer packs whole records into each chunk, so a record size that
/// does not divide the chunk leaves a gap at each chunk's end.
///
/// # Safety
///
/// `l` is a state with the slots table at `slots`; `data` holds `len`
/// bytes.
unsafe fn split_page_slots(
    l: *mut LuaState,
    slots: c_int,
    data: *const u8,
    len: usize,
    cursor: u64,
    chunks: u64,
    size: usize,
) {
    let per_chunk = CHUNK_PAYLOAD / size;
    // SAFETY: the caller's state, table and bytes.
    unsafe {
        if chunks > 1 && per_chunk > 0 && CHUNK_PAYLOAD % size != 0 {
            let mut off = 0;
            let mut chunk = 0u64;
            while chunk < chunks && off < len {
                let chunk_bytes = (len - off).min(CHUNK_PAYLOAD);
                let local = (chunk_bytes / size).min(per_chunk);
                for i in 0..local {
                    let page_slot = chunk * per_chunk as u64 + i as u64;
                    if page_slot == 0 {
                        continue;
                    }
                    store_slot(
                        l,
                        slots,
                        cursor.wrapping_add(page_slot),
                        data.add(off + i * size),
                        size,
                    );
                }
                off += chunk_bytes;
                chunk += 1;
            }
            return;
        }
        let mut i = 0;
        while i + size <= len {
            store_slot(
                l,
                slots,
                cursor.wrapping_add((i / size) as u64),
                data.add(i),
                size,
            );
            i += size;
        }
    }
}

/// `shirudo.page_slots(page, size)`: one page's records, in order.
unsafe extern "C-unwind" fn page_slots(l: *mut LuaState) -> c_int {
    // SAFETY: the function's state.
    unsafe {
        luaL_checktype(l, 1, LUA_TTABLE);
        let size = check_c_int(l, 2);
        if size <= 0 || size as usize > CHUNK_PAYLOAD {
            luaL_error(l, c"invalid slot size".as_ptr());
        }
        let size = size as usize;
        let chunks = page_u64(l, 1, c"chunks");
        lua_getfield(l, 1, c"data_hex".as_ptr());
        let Some(hex) = to_bytes(l, -1) else {
            lua_pop(l, 1);
            lua_newtable(l);
            return 1;
        };
        let Some((data, len)) = hex_decode_push(l, hex) else {
            luaL_error(l, c"invalid page data_hex".as_ptr());
        };
        let per_chunk = CHUNK_PAYLOAD / size;
        lua_newtable(l);
        let (mut off, mut n) = (0usize, 0 as c_int);
        while off < len {
            let mut chunk_bytes = len - off;
            if chunks > 1 && chunk_bytes > CHUNK_PAYLOAD {
                chunk_bytes = CHUNK_PAYLOAD;
            }
            let mut local = chunk_bytes / size;
            if chunks > 1 && local > per_chunk {
                local = per_chunk;
            }
            for i in 0..local {
                push_slot(l, data.add(off + i * size), size);
                n += 1;
                lua_rawseti(l, -2, n);
            }
            if local == 0 {
                break;
            }
            off += chunk_bytes;
        }
    }
    1
}

/// A decimal u64 string argument, raising for anything else.
///
/// # Safety
///
/// `l` is a state in a C function.
unsafe fn check_u64_string(l: *mut LuaState, arg: c_int) -> u64 {
    let mut len = 0usize;
    // SAFETY: the caller's state; the string lives on its stack.
    let s = unsafe { crate::ffi::slice(luaL_checklstring(l, arg, &mut len).cast::<u8>(), len) };
    match crate::text::parse_u64(s, u64::MAX) {
        Ok(v) => v,
        // SAFETY: as above; these raise.
        Err(err) if err == -ERANGE => unsafe {
            luaL_argerror(l, arg, c"u64 string out of range".as_ptr())
        },
        // SAFETY: as above.
        Err(_) => unsafe { luaL_argerror(l, arg, c"expected a decimal u64 string".as_ptr()) },
    }
}

/// `shirudo.u64_add(a, b)`: exact, saturating; Lua numbers lose
/// nanoseconds.
unsafe extern "C-unwind" fn u64_add(l: *mut LuaState) -> c_int {
    // SAFETY: the function's state.
    unsafe {
        let a = check_u64_string(l, 1);
        let b = check_u64_string(l, 2);
        push_u64_string(&mut Stack::from_raw(l), a.saturating_add(b));
    }
    1
}

/// `shirudo.u64_sub(a, b)`: exact, at least 0.
unsafe extern "C-unwind" fn u64_sub(l: *mut LuaState) -> c_int {
    // SAFETY: the function's state.
    unsafe {
        let a = check_u64_string(l, 1);
        let b = check_u64_string(l, 2);
        push_u64_string(&mut Stack::from_raw(l), a.saturating_sub(b));
    }
    1
}

/// `shirudo.hex_u64(hex, off)`: the little-endian u64 at byte `off` of
/// the hex, "0" when it is not there or not hex.
unsafe extern "C-unwind" fn hex_u64(l: *mut LuaState) -> c_int {
    // SAFETY: the function's state; the string lives on its stack.
    unsafe {
        let off = check_c_int(l, 2);
        let mut len = 0usize;
        let hex = crate::ffi::slice(luaL_checklstring(l, 1, &mut len).cast::<u8>(), len);
        let start = (off as usize).wrapping_mul(2);
        if off < 0 || start + 16 > hex.len() {
            push_u64_string(&mut Stack::from_raw(l), 0);
            return 1;
        }
        let mut v = 0u64;
        for i in (0..8).rev() {
            let p = &hex[start + i * 2..];
            match (hex_nibble(p[0]), hex_nibble(p[1])) {
                (Some(hi), Some(lo)) => v = v << 8 | u64::from(hi << 4 | lo),
                _ => {
                    push_u64_string(&mut Stack::from_raw(l), 0);
                    return 1;
                }
            }
        }
        push_u64_string(&mut Stack::from_raw(l), v);
    }
    1
}

/// `shirudo.fixed_records(pages, size)`: the records of every page by
/// their absolute index, from each page's cursor.
unsafe extern "C-unwind" fn fixed_records(l: *mut LuaState) -> c_int {
    // SAFETY: the function's state.
    unsafe {
        luaL_checktype(l, 1, LUA_TTABLE);
        let size = check_c_int(l, 2);
        if size <= 0 {
            luaL_error(l, c"invalid slot size".as_ptr());
        }
        let pages = absindex(l, 1);
        lua_newtable(l);
        let slots = absindex(l, -1);
        let n_pages = lua_objlen(l, pages);
        for i in 1..=n_pages {
            lua_rawgeti(l, pages, i as c_int);
            if lua_type(l, -1) != LUA_TTABLE {
                lua_pop(l, 1);
                continue;
            }
            let cursor = page_u64(l, -1, c"cursor");
            let chunks = page_u64(l, -1, c"chunks");
            lua_getfield(l, -1, c"data_hex".as_ptr());
            let Some(hex) = to_bytes(l, -1) else {
                lua_pop(l, 2);
                continue;
            };
            let Some((data, len)) = hex_decode_push(l, hex) else {
                lua_pop(l, 2);
                luaL_error(l, c"invalid page data_hex".as_ptr());
            };
            split_page_slots(l, slots, data, len, cursor, chunks, size as usize);
            lua_pop(l, 3);
        }
    }
    1
}

/// Pushes `v` as a decimal string, which a Lua number would round.
fn push_u64_string(s: &mut Stack<'_>, v: u64) {
    let mut digits = [0; 20];
    s.push_bytes(crate::text::decimal(v, &mut digits));
}

/// Pushes the bytes as lowercase hex, made in a userdata the collector
/// owns: a Lua error on an allocation would leak a buffer of our own.
fn push_hex(s: &mut Stack<'_>, bytes: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // The hex and a NUL.
    s.push_userdata_with(bytes.len() * 2 + 1, |hex| {
        for (pair, b) in hex.chunks_exact_mut(2).zip(bytes) {
            pair.copy_from_slice(&[HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]]);
        }
    });
    {
        let (held, mut above) = s.split();
        above.push_bytes(cstr(held.userdata(-1).unwrap_or_default()));
    }
    s.remove(-2);
}

/// Sets field `key` of the table on top to `v`.
fn set_number(s: &mut Stack<'_>, key: &CStr, v: f64) {
    s.push_number(v);
    s.set_field(-2, key);
}

/// Sets field `key` of the table on top to `v`.
fn set_bool(s: &mut Stack<'_>, key: &CStr, v: bool) {
    s.push_bool(v);
    s.set_field(-2, key);
}

fn realtime_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| {
            d.as_secs()
                .wrapping_mul(1_000_000_000)
                .wrapping_add(u64::from(d.subsec_nanos()))
        })
}

/// The decoder's input, the map as raw bytes and its shape: the same
/// whether BTF can render it or not.
fn push_map_input(s: &mut Stack<'_>, v: &MapView) {
    let now = realtime_ns();
    let start = if v.lifetime_start_ns != 0 {
        v.lifetime_start_ns
    } else {
        now
    };
    s.new_table();
    s.push_integer(1);
    s.set_field(-2, c"schema");
    s.push_bytes(cstr(&v.upatch));
    s.set_field(-2, c"upatch");
    s.push_bytes(cstr(&v.name));
    s.set_field(-2, c"map");
    // OTLP wall-clock times, as decimal strings: a Lua number cannot
    // hold nanoseconds since the epoch.
    push_u64_string(s, start);
    s.set_field(-2, c"startTimeUnixNano");
    push_u64_string(s, now);
    s.set_field(-2, c"timeUnixNano");
    push_map_data(s, v);
    s.set_field(-2, c"data");
}

/// The input's `data`: the map's shape, its entries and its serialized
/// pages.
fn push_map_data(s: &mut Stack<'_>, v: &MapView) {
    s.new_table();
    s.push_bytes(cstr(&v.name));
    s.set_field(-2, c"name");
    s.push_bytes(v.type_name.unwrap_or(c"").to_bytes());
    s.set_field(-2, c"type");
    set_number(s, c"max_entries", f64::from(v.max_entries));
    set_number(s, c"n_entries", f64::from(v.n_entries));
    set_bool(s, c"serialized", v.serialized);
    set_number(s, c"serialized_pages", f64::from(v.n_serial_pages));
    set_number(s, c"serialized_bytes", v.serial_bytes_total as f64);
    set_number(s, c"key_size", f64::from(v.key_size));
    set_number(s, c"value_size", f64::from(v.value_size));
    set_number(s, c"n_cpus", f64::from(v.n_cpus));
    set_bool(s, c"truncated", v.truncated);
    push_entries(s, v);
    s.set_field(-2, c"entries");
    push_pages(s, v);
    s.set_field(-2, c"pages");
}

/// A length the view holds, as one: 0 for one no slice can have.
fn view_len(n: u64) -> usize {
    usize::try_from(n).unwrap_or(0)
}

/// The entries of the view, each its key and its value on every CPU as
/// hex.
fn push_entries(s: &mut Stack<'_>, v: &MapView) {
    let key_len = view_len(u64::from(v.key_size));
    let value_len = view_len(u64::from(v.value_stride) * u64::from(v.n_cpus));
    // SAFETY: map_read() points the view's entries at n_entries of them,
    // which live as it does.
    let entries = unsafe { ffi::slice(v.entries, view_len(u64::from(v.n_entries))) };
    s.new_table();
    for (n, entry) in (1..=c_int::MAX).zip(entries) {
        s.new_table();
        // SAFETY: map_read() points an entry's key at key_size bytes,
        // which live as the view does.
        push_hex(s, unsafe { ffi::slice(entry.key.cast::<u8>(), key_len) });
        s.set_field(-2, c"key_hex");
        // SAFETY: and its value at value_stride bytes for each CPU.
        push_hex(s, unsafe {
            ffi::slice(entry.value.cast::<u8>(), value_len)
        });
        s.set_field(-2, c"value_hex");
        s.raw_set_index(-2, n);
    }
}

/// The serialized pages of the view, each its place, its cursors and
/// flags, and its bytes as hex.
fn push_pages(s: &mut Stack<'_>, v: &MapView) {
    // SAFETY: map_read() points the view's pages at n_serial_pages of
    // them, which live as it does.
    let pages = unsafe { ffi::slice(v.serial_pages, view_len(u64::from(v.n_serial_pages))) };
    s.new_table();
    for (n, page) in (1..=c_int::MAX).zip(pages) {
        s.new_table();
        set_number(s, c"page_index", f64::from(page.page_index));
        set_number(s, c"cursor", page.cursor as f64);
        set_number(s, c"next_cursor", page.next_cursor as f64);
        set_bool(s, c"done", page.done);
        set_number(s, c"flags", f64::from(page.flags));
        set_number(s, c"chunks", f64::from(page.chunks));
        set_number(s, c"bytes", f64::from(page.bytes));
        // SAFETY: map_read() points a page's data at its bytes, which live
        // as the view does.
        push_hex(s, unsafe {
            ffi::slice(page.data.cast::<u8>(), view_len(u64::from(page.bytes)))
        });
        s.set_field(-2, c"data_hex");
        s.raw_set_index(-2, n);
    }
}

/// The decoder's entrypoint: a function of the table its chunk returned,
/// the function it returned, or a global of the name.
///
/// # Safety
///
/// `l` is a state with the chunk's result on top.
unsafe fn get_entrypoint(l: *mut LuaState, entrypoint: &CStr) -> bool {
    // SAFETY: the caller's state.
    unsafe {
        if lua_type(l, -1) == LUA_TTABLE {
            lua_getfield(l, -1, entrypoint.as_ptr());
            if lua_type(l, -1) == LUA_TFUNCTION {
                lua_remove(l, -2);
                return true;
            }
            lua_pop(l, 1);
        }
        if lua_type(l, -1) == LUA_TFUNCTION {
            return true;
        }
        lua_pop(l, 1);
        lua_getglobal(l, entrypoint.as_ptr());
        lua_type(l, -1) == LUA_TFUNCTION
    }
}

/// What the closure a decoder runs in reads and writes.
struct Call<'a, 'b> {
    view: &'a MapView,
    e: &'a mut JsonEmit<'b>,
    otel: bool,
    ret: c_int,
}

/// The closure the decoder runs in: its entrypoint, upvalue 2, called
/// with the input of the view of the call, upvalue 1. The result is
/// encoded under the same pcall, as that may run out of memory.
unsafe extern "C-unwind" fn call_decoder(l: *mut LuaState) -> c_int {
    // SAFETY: the closure's state and upvalues, the call live across the
    // pcall that runs this.
    let call = unsafe {
        let call = &mut *lua_touserdata(l, lua_upvalueindex(1)).cast::<Call<'_, '_>>();
        lua_pushvalue(l, lua_upvalueindex(2));
        call
    };
    // SAFETY: LuaJIT called this C function with the state, and this is
    // the one Stack of its frame.
    let mut s = unsafe { Stack::from_raw(l) };
    push_map_input(&mut s, call.view);
    s.call(1, 1);
    if call.otel {
        otel_value(&mut s, -1, call.e, 0);
    } else {
        json_value(&mut s, -1, call.e, 0);
    }
    call.ret = call.e.err();
    0
}

fn log_err(text: &[u8]) {
    let text = CString::new(
        text.iter()
            .copied()
            .filter(|&c| c != 0)
            .collect::<Vec<u8>>(),
    )
    .unwrap_or_default();
    crate::log::err(text.to_bytes());
}

/// The error on top of the state, under `what`. The message is the
/// decoder's and may carry what a map recorded, so it is cut to 255 bytes
/// and its control characters replaced.
///
/// # Safety
///
/// `l` is a live state with the error on top of its stack.
unsafe fn report(l: *mut LuaState, what: &str) {
    // SAFETY: the state, with the error on top; a number is not shown.
    let message = unsafe {
        (lua_type(l, -1) == LUA_TSTRING)
            .then(|| to_bytes(l, -1))
            .flatten()
    };
    let message = message.unwrap_or(b"unknown Lua error");
    let mut shown = cstr(message)[..cstr(message).len().min(255)].to_vec();
    crate::text::sanitize(&mut shown, false);
    log_err(&[b"upatch map: ", what.as_bytes(), b": ", &shown].concat());
}

thread_local! {
    /// The instruction budget of the decoder running, in hook calls.
    static BUDGET: Cell<c_int> = const { Cell::new(0) };
}

unsafe extern "C-unwind" fn budget_hook(l: *mut LuaState, _ar: *mut LuaDebug) {
    let left = BUDGET.with(|b| {
        b.set(b.get() - 1);
        b.get()
    });
    if left <= 0 {
        // pcall() catches the error, so once the budget is spent every
        // instruction raises it again: no protected call runs past it.
        // SAFETY: the hooked state; this raises.
        unsafe {
            lua_sethook(l, Some(budget_hook), LUA_MASKCOUNT, 1);
            luaL_error(l, c"decoder instruction limit exceeded".as_ptr());
        }
    }
}

/// The host API: the slot methods and the `shirudo` table, with the
/// globals that reach outside the sandbox or past its budget removed.
/// LuaJIT runs a finalizer with hooks off, so newproxy(), which makes a
/// userdata that takes one, would run code past the budget, and so does
/// the handler xpcall() calls for the error the budget hook raises, from
/// inside the hook. A pattern match is one C call the count hook never
/// interrupts, and backtracks for as long as the subject, a string a map
/// recorded, makes it. print() writes where --json does.
///
/// # Safety
///
/// `l` is a state with its libraries open.
unsafe fn install_host_api(l: *mut LuaState) {
    const DENY: [&CStr; 16] = [
        c"io",
        c"os",
        c"package",
        c"require",
        c"debug",
        c"jit",
        c"ffi",
        c"dofile",
        c"loadfile",
        c"load",
        c"loadstring",
        c"module",
        c"collectgarbage",
        c"newproxy",
        c"xpcall",
        c"print",
    ];
    const PATTERNS: [&CStr; 4] = [c"find", c"match", c"gmatch", c"gsub"];
    type Fns<'a> = &'a [(&'a CStr, crate::sys::luajit::LuaCFunction)];
    // SAFETY: the caller's state.
    unsafe {
        for name in DENY {
            lua_pushnil(l);
            lua_setglobal(l, name.as_ptr());
        }
        lua_getglobal(l, c"string".as_ptr());
        for name in PATTERNS {
            lua_pushnil(l);
            lua_setfield(l, -2, name.as_ptr());
        }
        lua_pop(l, 1);
        let set = |fns: Fns<'_>| {
            for (name, f) in fns {
                lua_pushcfunction(l, *f);
                lua_setfield(l, -2, name.as_ptr());
            }
        };
        luaL_newmetatable(l, SLOT_MT.as_ptr());
        lua_newtable(l);
        set(&[
            (c"u8", slot_u8),
            (c"u16", slot_u16),
            (c"u32", slot_u32),
            (c"u64", slot_u64),
            (c"cstring", slot_cstring),
        ]);
        lua_setfield(l, -2, c"__index".as_ptr());
        // A __gc a decoder added to it would run with hooks off.
        lua_pushstring(l, SLOT_MT.as_ptr());
        lua_setfield(l, -2, c"__metatable".as_ptr());
        lua_pop(l, 1);
        lua_newtable(l);
        set(&[
            (c"fixed_records", fixed_records),
            (c"page_slots", page_slots),
            (c"u64_add", u64_add),
            (c"u64_sub", u64_sub),
            (c"hex_u64", hex_u64),
        ]);
        lua_setglobal(l, c"shirudo".as_ptr());
    }
}

/// Disables the hook before the decoder state closes.
struct Decoder<'a>(Lua<'a>);

impl Drop for Decoder<'_> {
    fn drop(&mut self) {
        // SAFETY: the decoder's state lives until the field is dropped.
        unsafe { lua_sethook(self.0.as_ptr(), None, 0, 0) };
    }
}

struct ResetBudget;

impl Drop for ResetBudget {
    fn drop(&mut self) {
        BUDGET.with(|b| b.set(0));
    }
}

/// Runs the decoder on the view: the JSON, or the AnyValue with `otel`,
/// of what it returns, at most `max` bytes.
pub(crate) fn run(d: &DecoderView, v: &MapView, otel: bool, max: usize) -> Result<Vec<u8>, c_int> {
    let _budget;
    let allocator = Lua::new().ok_or(-ENOMEM)?;
    _budget = ResetBudget;
    let mut memory = Memory {
        inner: allocator.allocator(),
        used: 0,
    };
    // SAFETY: limited_alloc receives this memory record. It borrows the
    // native allocator, so both outlive the decoder through lua_close.
    let lua = unsafe { Lua::with_allocator(limited_alloc, &mut memory) }.ok_or(-ENOMEM)?;
    let decoder = Decoder(lua);
    let l = decoder.0.as_ptr();
    let mut e = JsonEmit::growing(max);
    let source_name = CString::new(cstr(&d.source_name)).unwrap_or_default();
    let entrypoint = CString::new(cstr(&d.entrypoint)).unwrap_or_default();
    // SAFETY: the decoder's state, its source and the view, which
    // outlive it.
    let ret = unsafe {
        luaL_openlibs(l);
        // Instruction hooks must see every instruction: no traces.
        if luaJIT_setmode(l, 0, LUAJIT_MODE_ENGINE | LUAJIT_MODE_OFF) == 0 {
            return Err(-EINVAL);
        }
        install_host_api(l);
        BUDGET.with(|b| b.set(INSN_LIMIT / HOOK_COUNT));
        lua_sethook(l, Some(budget_hook), LUA_MASKCOUNT, HOOK_COUNT);
        // LuaJIT checks no bytecode it loads: a decoder is source text.
        if luaL_loadbufferx(
            l,
            d.source,
            d.source_len as usize,
            source_name.as_ptr(),
            c"t".as_ptr(),
        ) != 0
            || lua_pcall(l, 0, 1, 0) != 0
        {
            report(l, "decoder load failed");
            -EINVAL
        } else if !get_entrypoint(l, &entrypoint) {
            log_err(
                &[
                    &b"upatch map: decoder entrypoint "[..],
                    entrypoint.to_bytes(),
                    b" not found",
                ]
                .concat(),
            );
            -ENOENT
        } else {
            let mut call = Call {
                view: v,
                e: &mut e,
                otel,
                ret: 0,
            };
            lua_pushlightuserdata(l, (&raw mut call).cast());
            lua_pushvalue(l, -2);
            lua_pushcclosure(l, call_decoder, 2);
            lua_remove(l, -2);
            if lua_pcall(l, 0, 0, 0) != 0 {
                report(l, "decoder failed");
                -EINVAL
            } else {
                if call.ret != 0 {
                    log_err(
                        format!("upatch map: decoder encode failed: {}", text(call.ret)).as_bytes(),
                    );
                }
                call.ret
            }
        }
    };
    if ret != 0 {
        return Err(ret);
    }
    e.finish()
}

/// Whether the decoder is a Lua one of API 1 on map input, exporting a
/// log or metrics, for this upatch's map.
fn matches(d: &DecoderView, v: &MapView) -> bool {
    d.language == LANG_LUA
        && d.api_version == 1
        && d.input_format == INPUT_MAP_V1
        && (d.export_signal == EXPORT_LOG || d.export_signal == EXPORT_METRIC)
        && cstr(&d.upatch) == cstr(&v.upatch)
        && cstr(&d.map) == cstr(&v.name)
}

/// The artifact the decoders come from, opened as sealed state when it
/// is the archive's: an entry there that is not shirudo's own is refused
/// rather than run, signed or not, and so is an archive whose bytes are
/// not the payload the pin directory says was loaded.
fn open_artifact(path: &CStr, archived: bool, v: &MapView) -> Result<Opened, c_int> {
    let u = if archived {
        let fd = seal::open_read(path.to_bytes())?;
        Opened::open_fd(fd.as_raw_fd())?
    } else {
        Opened::open(path)?
    };
    if archived {
        let loaded = payload_digest(&u).map(|digest| {
            v.has_payload
                && !memneq_explicit(&digest, &v.payload)
                && !memneq_explicit(&u.hdr.payload_sha256, &v.payload)
        })?;
        if !loaded {
            log_err(
                &[
                    &b"upatch map: the archive of "[..],
                    cstr(&v.upatch),
                    b" is not the upatch loaded; its decoders do not run",
                ]
                .concat(),
            );
            return Err(-ESTALE);
        }
    }
    Ok(u)
}

/// The decoders of the open artifact, each as a view, the bad ones left
/// out.
fn decoders(u: &Opened) -> impl Iterator<Item = DecoderView> + '_ {
    (0..u.nr_decoders).filter_map(move |i| {
        // SAFETY: an all-zero view, which the call fills.
        let mut d: DecoderView = unsafe { core::mem::zeroed() };
        // SAFETY: the container and room for the view.
        (unsafe { upatch_decoder_view(&**u, i, &mut d) } == 0).then_some(d)
    })
}

fn decode_open(
    path: &CStr,
    archived: bool,
    v: &MapView,
    otel: bool,
    max: usize,
) -> Result<Vec<u8>, c_int> {
    if !upatch::name_valid(Some(cstr(&v.upatch))) {
        return Err(-EINVAL);
    }
    let u = open_artifact(path, archived, v)?;
    match decoders(&u).find(|d| matches(d, v)) {
        Some(d) => run(&d, v, otel, max),
        None => Err(-ENODATA),
    }
}

fn archive_path(v: &MapView) -> Result<CString, c_int> {
    let path = [UPATCHES_DIR.as_bytes(), b"/", cstr(&v.upatch), b".upatch"].concat();
    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(path).map_err(|_| -EINVAL)
}

/// What the decoder makes of the view `v`, at most `max` bytes of it:
/// the signed one in its upatch's archive, or the artifact's at
/// `artifact`; as JSON, or with `otel` as an OTLP AnyValue. -ENODATA
/// without a decoder for the map, or -errno.
pub(crate) fn decode_map(
    v: &MapView,
    artifact: Option<&CStr>,
    otel: bool,
    max: usize,
) -> Result<Vec<u8>, c_int> {
    if max == 0 {
        return Err(-EINVAL);
    }
    match artifact {
        None => decode_open(&archive_path(v)?, true, v, otel, max),
        Some(path) => decode_open(path, false, v, otel, max),
    }
}

/// What the decoder in the upatch's archive makes of the map, as JSON.
pub(crate) fn map_json(v: &MapView) -> Result<Vec<u8>, c_int> {
    decode_map(v, None, false, JSON_MAX)
}

/// The signal the map's decoder exports, from the upatch's archive.
pub(crate) fn signal(v: &MapView) -> Result<u32, c_int> {
    if !upatch::name_valid(Some(cstr(&v.upatch))) {
        return Err(-EINVAL);
    }
    let path = archive_path(v)?;
    let u = open_artifact(&path, true, v)?;
    decoders(&u)
        .find(|d| matches(d, v))
        .map(|d| d.export_signal)
        .ok_or(-ENODATA)
}

#[cfg(shirudo_fuzz)]
mod fuzz;
#[cfg(test)]
mod tests;
