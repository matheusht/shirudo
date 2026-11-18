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
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;
use std::ffi::CString;

use crate::errno::{E2BIG, EINVAL, ENAMETOOLONG, ENODATA, ENOENT, ENOMEM, ERANGE, ESTALE};
use crate::sys::libc::{close, explicit_bzero, snprintf};
use crate::sys::luajit::{
    LUA_MASKCOUNT, LUA_REGISTRYINDEX, LUA_TBOOLEAN, LUA_TFUNCTION, LUA_TNIL, LUA_TNUMBER,
    LUA_TSTRING, LUA_TTABLE, LUAJIT_MODE_ENGINE, LUAJIT_MODE_OFF, LuaAlloc, LuaDebug, LuaState,
    lua_call, lua_close, lua_getallocf, lua_getfield, lua_getglobal, lua_gettop, lua_newstate,
    lua_newtable, lua_newuserdata, lua_next, lua_objlen, lua_pcall, lua_pop, lua_pushboolean,
    lua_pushcclosure, lua_pushcfunction, lua_pushinteger, lua_pushlightuserdata, lua_pushlstring,
    lua_pushnil, lua_pushnumber, lua_pushstring, lua_pushvalue, lua_rawgeti, lua_rawseti,
    lua_remove, lua_setfield, lua_setglobal, lua_sethook, lua_setmetatable, lua_toboolean,
    lua_tolstring, lua_tonumber, lua_touserdata, lua_type, lua_upvalueindex, luaJIT_setmode,
    luaL_argerror, luaL_checkinteger, luaL_checklstring, luaL_checktype, luaL_checkudata,
    luaL_error, luaL_loadbufferx, luaL_newmetatable, luaL_newstate, luaL_openlibs,
    lual_getmetatable,
};
use crate::sys::upatch_maps::MapView;
use crate::text::cstr;
use crate::util::chain::memneq_explicit;
use crate::util::json::JsonEmit;
use crate::util::seal::seal_open_read;
use crate::util::upatch::{
    self, DecoderView, Upatch, upatch_close, upatch_decoder_view, upatch_open, upatch_open_fd,
};
use crate::util::upatch_verify::payload_digest;

const INSN_LIMIT: c_int = 1_000_000;
const HOOK_COUNT: c_int = 10_000;
const MEMORY_LIMIT: usize = 32 * 1024 * 1024;
const JSON_MAX_DEPTH: c_int = 32;
const JSON_MAX: usize = 8 * 1024 * 1024;
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
struct Memory {
    inner: Option<LuaAlloc>,
    inner_ud: *mut c_void,
    used: usize,
    limit: usize,
}

/// The decoder's allocator: LuaJIT's own, as a GC64 state must live
/// below 2^47, which LuaJIT's allocator guarantees and a PIE's heap on
/// arm64 does not meet; held to the limit, and what is freed scrubbed
/// first.
unsafe extern "C" fn limited_alloc(
    ud: *mut c_void,
    p: *mut c_void,
    old: usize,
    new: usize,
) -> *mut c_void {
    // SAFETY: the memory record the state was made with.
    let m = unsafe { &mut *ud.cast::<Memory>() };
    let Some(inner) = m.inner else {
        return ptr::null_mut();
    };
    let base = if !p.is_null() && m.used >= old {
        m.used - old
    } else {
        m.used
    };
    if new == 0 {
        if !p.is_null() {
            // SAFETY: the block of old bytes, scrubbed and handed back.
            unsafe {
                explicit_bzero(p, old);
                inner(m.inner_ud, p, old, 0);
            }
            m.used = base;
        }
        return ptr::null_mut();
    }
    let Some(total) = base.checked_add(new).filter(|&t| t <= m.limit) else {
        return ptr::null_mut();
    };
    // SAFETY: a new block from the inner allocator.
    let next = unsafe { inner(m.inner_ud, ptr::null_mut(), 0, new) };
    if next.is_null() {
        return ptr::null_mut();
    }
    // SAFETY: the new block of `new` bytes, and the old one of `old`.
    unsafe {
        next.cast::<u8>().write_bytes(0, new);
        if !p.is_null() {
            ptr::copy_nonoverlapping(p.cast::<u8>(), next.cast::<u8>(), old.min(new));
            explicit_bzero(p, old);
            inner(m.inner_ud, p, old, 0);
        }
    }
    m.used = total;
    next
}

/// Whether the table at `idx` is an array, 1 to its length with no
/// other key, and that length.
///
/// # Safety
///
/// `l` is a state with a table at `idx`.
unsafe fn table_array_len(l: *mut LuaState, idx: c_int) -> Option<usize> {
    // SAFETY: the caller's state and table, walked with lua_next().
    unsafe {
        let idx = absindex(l, idx);
        let (mut count, mut max, mut array) = (0usize, 0usize, true);
        lua_pushnil(l);
        while lua_next(l, idx) != 0 {
            if lua_type(l, -2) == LUA_TNUMBER {
                let n = lua_tonumber(l, -2);
                if !n.is_finite() || n < 1.0 || n > f64::from(c_int::MAX) {
                    array = false;
                } else {
                    let k = n as usize;
                    if k as f64 != n {
                        array = false;
                        lua_pop(l, 1);
                        continue;
                    }
                    max = max.max(k);
                    count += 1;
                }
            } else {
                array = false;
            }
            lua_pop(l, 1);
        }
        (array && count == max).then_some(max)
    }
}

/// A table key as text: a string as it is, a number and a boolean
/// spelled out. A name the kernel hands over is raw bytes, cut at a
/// fixed length mid-character as often as not, and one bad byte must
/// not cost the whole snapshot: the lossy writers make it U+FFFD.
///
/// # Safety
///
/// `l` is a state with a value at `idx`.
unsafe fn emit_key(l: *mut LuaState, idx: c_int, e: &mut JsonEmit, as_key: bool) {
    // SAFETY: the caller's state.
    let text: Vec<u8> = unsafe {
        match lua_type(l, idx) {
            LUA_TSTRING => to_bytes(l, idx).unwrap_or_default().to_vec(),
            LUA_TNUMBER => printf_double(c"%.17g", lua_tonumber(l, idx)),
            LUA_TBOOLEAN => {
                if lua_toboolean(l, idx) != 0 {
                    b"true".to_vec()
                } else {
                    b"false".to_vec()
                }
            }
            _ => b"unsupported_key".to_vec(),
        }
    };
    if as_key {
        e.key_lossy(&text)
    } else {
        e.str_lossy(&text)
    }
}

/// The Lua value at `idx` as JSON.
///
/// # Safety
///
/// `l` is a state with a value at `idx`.
unsafe fn json_value(l: *mut LuaState, idx: c_int, e: &mut JsonEmit, depth: c_int) -> c_int {
    if depth > JSON_MAX_DEPTH {
        e.set_err(-E2BIG);
        return e.err();
    }
    // SAFETY: the caller's state.
    unsafe {
        match lua_type(l, idx) {
            LUA_TNIL => e.raw_value(b"null"),
            LUA_TBOOLEAN => e.raw_value(if lua_toboolean(l, idx) != 0 {
                b"true"
            } else {
                b"false"
            }),
            LUA_TNUMBER => {
                let v = lua_tonumber(l, idx);
                if !v.is_finite() {
                    e.set_err(-EINVAL);
                } else {
                    e.raw_value(&printf_double(c"%.17g", v));
                }
            }
            LUA_TSTRING => e.str_lossy(to_bytes(l, idx).unwrap_or_default()),
            LUA_TTABLE => {
                json_table(l, idx, e, depth);
            }
            _ => e.set_err(-EINVAL),
        }
    }
    e.err()
}

/// # Safety
///
/// `l` is a state with a table at `idx`.
unsafe fn json_table(l: *mut LuaState, idx: c_int, e: &mut JsonEmit, depth: c_int) -> c_int {
    // SAFETY: the caller's state and table.
    unsafe {
        let idx = absindex(l, idx);
        if let Some(len) = table_array_len(l, idx) {
            e.arr_open_value();
            let mut i = 1;
            while i <= len && e.err() == 0 {
                lua_rawgeti(l, idx, i as c_int);
                json_value(l, -1, e, depth + 1);
                lua_pop(l, 1);
                i += 1;
            }
            e.arr_close();
            return e.err();
        }
        e.obj_value_open();
        lua_pushnil(l);
        while lua_next(l, idx) != 0 {
            if !matches!(lua_type(l, -2), LUA_TSTRING | LUA_TNUMBER | LUA_TBOOLEAN) {
                e.set_err(-EINVAL);
                lua_pop(l, 2);
                break;
            }
            emit_key(l, -2, e, true);
            json_value(l, -1, e, depth + 1);
            lua_pop(l, 1);
            if e.err() != 0 {
                lua_pop(l, 1);
                break;
            }
        }
        e.obj_close();
    }
    e.err()
}

/// The Lua value at `idx` as the OTLP JSON form of an AnyValue.
///
/// # Safety
///
/// `l` is a state with a value at `idx`.
unsafe fn otel_value(l: *mut LuaState, idx: c_int, e: &mut JsonEmit, depth: c_int) -> c_int {
    if depth > JSON_MAX_DEPTH {
        e.set_err(-E2BIG);
        return e.err();
    }
    // SAFETY: the caller's state.
    unsafe {
        match lua_type(l, idx) {
            // An empty AnyValue is the OTLP form of nil.
            LUA_TNIL => {
                e.obj_value_open();
                e.obj_close();
            }
            LUA_TBOOLEAN => {
                e.obj_value_open();
                e.kv_bool(b"boolValue", lua_toboolean(l, idx) != 0);
                e.obj_close();
            }
            LUA_TNUMBER => {
                let v = lua_tonumber(l, idx);
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
            LUA_TSTRING => {
                e.obj_value_open();
                e.key(b"stringValue");
                e.str_lossy(to_bytes(l, idx).unwrap_or_default());
                e.obj_close();
            }
            LUA_TTABLE => {
                otel_table(l, idx, e, depth);
            }
            _ => e.set_err(-EINVAL),
        }
    }
    e.err()
}

/// # Safety
///
/// `l` is a state with a table at `idx`.
unsafe fn otel_table(l: *mut LuaState, idx: c_int, e: &mut JsonEmit, depth: c_int) -> c_int {
    // SAFETY: the caller's state and table.
    unsafe {
        let idx = absindex(l, idx);
        e.obj_value_open();
        if let Some(len) = table_array_len(l, idx) {
            e.obj_open_key(b"arrayValue");
            e.arr_open(b"values");
            let mut i = 1;
            while i <= len && e.err() == 0 {
                lua_rawgeti(l, idx, i as c_int);
                otel_value(l, -1, e, depth + 1);
                lua_pop(l, 1);
                i += 1;
            }
            e.arr_close();
            e.obj_close();
            e.obj_close();
            return e.err();
        }
        e.obj_open_key(b"kvlistValue");
        e.arr_open(b"values");
        lua_pushnil(l);
        while lua_next(l, idx) != 0 {
            if !matches!(lua_type(l, -2), LUA_TSTRING | LUA_TNUMBER | LUA_TBOOLEAN) {
                e.set_err(-EINVAL);
                lua_pop(l, 2);
                break;
            }
            e.obj_value_open();
            e.key(b"key");
            emit_key(l, -2, e, false);
            e.key(b"value");
            otel_value(l, -1, e, depth + 1);
            e.obj_close();
            lua_pop(l, 1);
            if e.err() != 0 {
                lua_pop(l, 1);
                break;
            }
        }
        e.arr_close();
        e.obj_close();
        e.obj_close();
    }
    e.err()
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
        return unsafe { luaL_argerror(l, arg, c"integer out of range".as_ptr()) };
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
        push_u64_string(l, slot_word(slot, off, 8));
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
            return;
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
            return luaL_error(l, c"invalid slot size".as_ptr());
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
            return luaL_error(l, c"invalid page data_hex".as_ptr());
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
            luaL_argerror(l, arg, c"u64 string out of range".as_ptr()) as u64
        },
        // SAFETY: as above.
        Err(_) => unsafe {
            luaL_argerror(l, arg, c"expected a decimal u64 string".as_ptr()) as u64
        },
    }
}

/// `shirudo.u64_add(a, b)`: exact, saturating; Lua numbers lose
/// nanoseconds.
unsafe extern "C-unwind" fn u64_add(l: *mut LuaState) -> c_int {
    // SAFETY: the function's state.
    unsafe {
        let a = check_u64_string(l, 1);
        let b = check_u64_string(l, 2);
        push_u64_string(l, a.saturating_add(b));
    }
    1
}

/// `shirudo.u64_sub(a, b)`: exact, at least 0.
unsafe extern "C-unwind" fn u64_sub(l: *mut LuaState) -> c_int {
    // SAFETY: the function's state.
    unsafe {
        let a = check_u64_string(l, 1);
        let b = check_u64_string(l, 2);
        push_u64_string(l, a.saturating_sub(b));
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
            push_u64_string(l, 0);
            return 1;
        }
        let mut v = 0u64;
        for i in (0..8).rev() {
            let p = &hex[start + i * 2..];
            match (hex_nibble(p[0]), hex_nibble(p[1])) {
                (Some(hi), Some(lo)) => v = v << 8 | u64::from(hi << 4 | lo),
                _ => {
                    push_u64_string(l, 0);
                    return 1;
                }
            }
        }
        push_u64_string(l, v);
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
            return luaL_error(l, c"invalid slot size".as_ptr());
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
                return luaL_error(l, c"invalid page data_hex".as_ptr());
            };
            split_page_slots(l, slots, data, len, cursor, chunks, size as usize);
            lua_pop(l, 3);
        }
    }
    1
}

/// # Safety
///
/// `l` is a state.
unsafe fn push_u64_string(l: *mut LuaState, v: u64) {
    let s = CString::new(v.to_string()).unwrap_or_default();
    // SAFETY: the caller's state and a C string, which Lua copies.
    unsafe { lua_pushstring(l, s.as_ptr()) };
}

/// The bytes as lowercase hex, made in a userdata the collector owns: a
/// Lua error on an allocation would leak a buffer of our own.
///
/// # Safety
///
/// `l` is a state; `data` holds `len` bytes.
unsafe fn push_hex(l: *mut LuaState, data: *const u8, len: usize) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    // SAFETY: the caller's state and bytes; a userdata of the hex and a
    // NUL, removed once the string is made of it.
    unsafe {
        let out = lua_newuserdata(l, len * 2 + 1).cast::<u8>();
        for i in 0..len {
            let b = *data.add(i);
            *out.add(2 * i) = HEX[usize::from(b >> 4)];
            *out.add(2 * i + 1) = HEX[usize::from(b & 0xf)];
        }
        *out.add(len * 2) = 0;
        lua_pushstring(l, out.cast());
        lua_remove(l, -2);
    }
}

/// # Safety
///
/// `l` is a state with a table on top.
unsafe fn set_number(l: *mut LuaState, key: &CStr, v: f64) {
    // SAFETY: the caller's state and table.
    unsafe {
        lua_pushnumber(l, v);
        lua_setfield(l, -2, key.as_ptr());
    }
}

/// # Safety
///
/// `l` is a state with a table on top.
unsafe fn set_bool(l: *mut LuaState, key: &CStr, v: bool) {
    // SAFETY: the caller's state and table.
    unsafe {
        lua_pushboolean(l, c_int::from(v));
        lua_setfield(l, -2, key.as_ptr());
    }
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
///
/// # Safety
///
/// `l` is a state; `v` a view whose entries and pages it holds.
unsafe fn push_map_input(l: *mut LuaState, v: &MapView) {
    let now = realtime_ns();
    let start = if v.lifetime_start_ns != 0 {
        v.lifetime_start_ns
    } else {
        now
    };
    let name = CString::new(cstr(&v.name)).unwrap_or_default();
    let upatch = CString::new(cstr(&v.upatch)).unwrap_or_default();
    let type_name = if v.type_name.is_null() {
        c""
    } else {
        // SAFETY: the view's C string.
        unsafe { CStr::from_ptr(v.type_name) }
    };
    // SAFETY: the caller's state and view.
    unsafe {
        lua_newtable(l);
        lua_pushinteger(l, 1);
        lua_setfield(l, -2, c"schema".as_ptr());
        lua_pushstring(l, upatch.as_ptr());
        lua_setfield(l, -2, c"upatch".as_ptr());
        lua_pushstring(l, name.as_ptr());
        lua_setfield(l, -2, c"map".as_ptr());
        // OTLP wall-clock times, as decimal strings: a Lua number cannot
        // hold nanoseconds since the epoch.
        push_u64_string(l, start);
        lua_setfield(l, -2, c"startTimeUnixNano".as_ptr());
        push_u64_string(l, now);
        lua_setfield(l, -2, c"timeUnixNano".as_ptr());

        lua_newtable(l);
        lua_pushstring(l, name.as_ptr());
        lua_setfield(l, -2, c"name".as_ptr());
        lua_pushstring(l, type_name.as_ptr());
        lua_setfield(l, -2, c"type".as_ptr());
        set_number(l, c"max_entries", f64::from(v.max_entries));
        set_number(l, c"n_entries", f64::from(v.n_entries));
        set_bool(l, c"serialized", v.serialized);
        set_number(l, c"serialized_pages", f64::from(v.n_serial_pages));
        set_number(l, c"serialized_bytes", v.serial_bytes_total as f64);
        set_number(l, c"key_size", f64::from(v.key_size));
        set_number(l, c"value_size", f64::from(v.value_size));
        set_number(l, c"n_cpus", f64::from(v.n_cpus));
        set_bool(l, c"truncated", v.truncated);

        lua_newtable(l);
        for i in 0..v.n_entries as usize {
            let entry = &*v.entries.add(i);
            lua_newtable(l);
            push_hex(l, entry.key.cast(), v.key_size as usize);
            lua_setfield(l, -2, c"key_hex".as_ptr());
            push_hex(
                l,
                entry.value.cast(),
                v.value_stride as usize * v.n_cpus as usize,
            );
            lua_setfield(l, -2, c"value_hex".as_ptr());
            lua_rawseti(l, -2, i as c_int + 1);
        }
        lua_setfield(l, -2, c"entries".as_ptr());

        lua_newtable(l);
        for p in 0..v.n_serial_pages as usize {
            let page = &*v.serial_pages.add(p);
            lua_newtable(l);
            set_number(l, c"page_index", f64::from(page.page_index));
            set_number(l, c"cursor", page.cursor as f64);
            set_number(l, c"next_cursor", page.next_cursor as f64);
            set_bool(l, c"done", page.done);
            set_number(l, c"flags", f64::from(page.flags));
            set_number(l, c"chunks", f64::from(page.chunks));
            set_number(l, c"bytes", f64::from(page.bytes));
            push_hex(l, page.data.cast(), page.bytes as usize);
            lua_setfield(l, -2, c"data_hex".as_ptr());
            lua_rawseti(l, -2, p as c_int + 1);
        }
        lua_setfield(l, -2, c"pages".as_ptr());
        lua_setfield(l, -2, c"data".as_ptr());
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
struct Call<'a> {
    view: &'a MapView,
    e: &'a mut JsonEmit,
    otel: bool,
    ret: c_int,
}

/// The closure the decoder runs in: its entrypoint, upvalue 2, called
/// with the input of the view of the call, upvalue 1. The result is
/// encoded under the same pcall, as that may run out of memory.
unsafe extern "C-unwind" fn call_decoder(l: *mut LuaState) -> c_int {
    // SAFETY: the closure's state and upvalues, the call live across the
    // pcall that runs this.
    unsafe {
        let call = &mut *lua_touserdata(l, lua_upvalueindex(1)).cast::<Call<'_>>();
        lua_pushvalue(l, lua_upvalueindex(2));
        push_map_input(l, call.view);
        lua_call(l, 1, 1);
        call.ret = if call.otel {
            otel_value(l, -1, call.e, 0)
        } else {
            json_value(l, -1, call.e, 0)
        };
    }
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
    // SAFETY: a "%s" format with a C string.
    unsafe { crate::log::log_c!(crate::log::err, c"%s".as_ptr(), text.as_ptr()) };
}

/// The error on top of the state, under `what`. The message is the
/// decoder's and may carry what a map recorded, so it is cut to 255 bytes
/// and its control characters replaced.
fn report(l: *mut LuaState, what: &str) {
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

/// A decoder's output, `len` bytes and a NUL in an allocation for
/// `xfree(out, len + 1)`.
pub(crate) struct Output {
    pub(crate) ptr: *mut c_char,
    pub(crate) len: usize,
}

/// Two states: one that owns LuaJIT's own allocator, and the decoder's
/// over it, closed in that order when they go. Restoring the native
/// allocator before close would let finalizers bypass the limit and the
/// scrubbing.
struct States {
    allocator: *mut LuaState,
    l: *mut LuaState,
}

impl Drop for States {
    fn drop(&mut self) {
        // SAFETY: the states, closed once, the decoder's first.
        unsafe {
            if !self.l.is_null() {
                lua_sethook(self.l, None, 0, 0);
                lua_close(self.l);
            }
            lua_close(self.allocator);
        }
        BUDGET.with(|b| b.set(0));
    }
}

/// Runs the decoder on the view: the JSON, or the AnyValue with `otel`,
/// of what it returns, at most `max` bytes.
pub(crate) fn run(d: &DecoderView, v: &MapView, otel: bool, max: usize) -> Result<Output, c_int> {
    let mut memory = Memory {
        inner: None,
        inner_ud: ptr::null_mut(),
        used: 0,
        limit: MEMORY_LIMIT,
    };
    // SAFETY: a new state.
    let allocator = unsafe { luaL_newstate() };
    if allocator.is_null() {
        return Err(-ENOMEM);
    }
    let mut states = States {
        allocator,
        l: ptr::null_mut(),
    };
    // SAFETY: the allocator state and room for its allocator's data.
    memory.inner = unsafe { lua_getallocf(allocator, &mut memory.inner_ud) };
    // SAFETY: the limited allocator over the memory record, which
    // outlives the state.
    let l = unsafe { lua_newstate(limited_alloc, (&raw mut memory).cast()) };
    if l.is_null() {
        return Err(-ENOMEM);
    }
    states.l = l;
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
                        format!("upatch map: decoder encode failed: {}", strerror(call.ret))
                            .as_bytes(),
                    );
                }
                call.ret
            }
        }
    };
    let (buf, cap, len) = e.parts();
    if ret != 0 || e.err() != 0 {
        // SAFETY: the emitter's buffer, or NULL.
        unsafe { crate::heap::xfree(buf.cast(), cap) };
        return Err(if ret != 0 { ret } else { e.err() });
    }
    drop(states);
    Ok(Output { ptr: buf, len })
}

fn strerror(err: c_int) -> String {
    let e = std::io::Error::from_raw_os_error(-err).to_string();
    e.split(" (os error").next().unwrap_or_default().to_owned()
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

/// An upatch container, closed when it goes.
struct Opened(Box<Upatch>);

impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: the container, closed once.
        unsafe { upatch_close(&mut *self.0) };
    }
}

/// The artifact the decoders come from, opened as sealed state when it
/// is the archive's: an entry there that is not shirudo's own is refused
/// rather than run, signed or not, and so is an archive whose bytes are
/// not the payload the pin directory says was loaded.
fn open_artifact(path: &CStr, archived: bool, v: &MapView) -> Result<Opened, c_int> {
    // SAFETY: an all-zero container is a closed one.
    let mut u = Opened(Box::new(unsafe { core::mem::zeroed() }));
    let ret = if !archived {
        // SAFETY: a C string and the container to fill.
        unsafe { upatch_open(path.as_ptr(), &mut *u.0) }
    } else {
        // SAFETY: a C string.
        let fd = unsafe { seal_open_read(path.as_ptr()) };
        if fd < 0 {
            return Err(fd);
        }
        // SAFETY: the open file and the container to fill.
        let ret = unsafe { upatch_open_fd(fd, &mut *u.0) };
        // SAFETY: the descriptor, closed once.
        unsafe { close(fd) };
        ret
    };
    if ret != 0 {
        core::mem::forget(u);
        return Err(ret);
    }
    if archived {
        let loaded = payload_digest(&u.0).map(|digest| {
            v.has_payload
                && !memneq_explicit(&digest, &v.payload)
                && !memneq_explicit(&u.0.hdr.payload_sha256, &v.payload)
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
    (0..u.0.nr_decoders).filter_map(move |i| {
        // SAFETY: an all-zero view, which the call fills.
        let mut d: DecoderView = unsafe { core::mem::zeroed() };
        // SAFETY: the container and room for the view.
        (unsafe { upatch_decoder_view(&*u.0, i, &mut d) } == 0).then_some(d)
    })
}

fn decode_open(
    path: &CStr,
    archived: bool,
    v: &MapView,
    otel: bool,
    max: usize,
) -> Result<Output, c_int> {
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

/// What the decoder in the upatch's archive makes of the map, as JSON.
pub(crate) fn map_json(v: &MapView) -> Result<Output, c_int> {
    decode_open(&archive_path(v)?, true, v, false, JSON_MAX)
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

mod capi {
    use core::ffi::{CStr, c_char, c_int};

    use super::Output;
    use crate::errno::EINVAL;
    use crate::sys::upatch_maps::MapView;

    const JSON_MAX: usize = super::JSON_MAX;

    /// The result into the caller's rooms: empty, then the output.
    ///
    /// # Safety
    ///
    /// `out` and `out_len` are rooms.
    unsafe fn hand(r: Result<Output, c_int>, out: *mut *mut c_char, out_len: *mut usize) -> c_int {
        match r {
            Ok(o) => {
                // SAFETY: the caller's rooms.
                unsafe {
                    *out = o.ptr;
                    *out_len = o.len;
                }
                0
            }
            Err(err) => err,
        }
    }

    /// The archive's decoder, or the artifact's at `path`, on the view.
    ///
    /// # Safety
    ///
    /// `path` is a C string or NULL, `v` a view or NULL, `out` and
    /// `out_len` rooms or NULL.
    unsafe fn decode(
        path: *const c_char,
        v: *const MapView,
        otel: bool,
        max: usize,
        out: *mut *mut c_char,
        out_len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller's view.
        let Some(v) = (unsafe { v.as_ref() }) else {
            return -EINVAL;
        };
        if out.is_null() || out_len.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller's rooms, emptied first.
        unsafe {
            *out = core::ptr::null_mut();
            *out_len = 0;
        }
        let r = if path.is_null() {
            match super::archive_path(v) {
                Ok(p) => super::decode_open(&p, true, v, otel, max),
                Err(err) => Err(err),
            }
        } else {
            // SAFETY: the caller's C string.
            super::decode_open(unsafe { CStr::from_ptr(path) }, false, v, otel, max)
        };
        // SAFETY: the caller's rooms.
        unsafe { hand(r, out, out_len) }
    }

    /// What the map's signed decoder in its upatch's archive makes of
    /// it, as JSON: the buffer for xfree(out, *out_len + 1), -ENODATA
    /// without a decoder for the map, or -errno.
    ///
    /// # Safety
    ///
    /// `v` is a view or NULL; `out` and `out_len` rooms or NULL.
    pub unsafe extern "C" fn upatch_decode_map_json(
        v: *const MapView,
        out: *mut *mut c_char,
        out_len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller's arguments.
        unsafe { decode(core::ptr::null(), v, false, JSON_MAX, out, out_len) }
    }

    /// As upatch_decode_map_json(), at most `max_bytes` of it.
    ///
    /// # Safety
    ///
    /// As upatch_decode_map_json().
    pub unsafe extern "C" fn upatch_decode_map_json_limit(
        v: *const MapView,
        max_bytes: usize,
        out: *mut *mut c_char,
        out_len: *mut usize,
    ) -> c_int {
        if max_bytes == 0 {
            return -EINVAL;
        }
        // SAFETY: the caller's arguments.
        unsafe { decode(core::ptr::null(), v, false, max_bytes, out, out_len) }
    }

    /// As upatch_decode_map_json(), as an OTLP AnyValue.
    ///
    /// # Safety
    ///
    /// As upatch_decode_map_json().
    pub unsafe extern "C" fn upatch_decode_map_otel(
        v: *const MapView,
        out: *mut *mut c_char,
        out_len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller's arguments.
        unsafe { decode(core::ptr::null(), v, true, JSON_MAX, out, out_len) }
    }

    /// As upatch_decode_map_json(), with the decoder of the artifact at
    /// `path`.
    ///
    /// # Safety
    ///
    /// `path` is a C string or NULL; otherwise as upatch_decode_map_json().
    pub unsafe extern "C" fn upatch_decode_map_file_json(
        path: *const c_char,
        v: *const MapView,
        out: *mut *mut c_char,
        out_len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller's arguments.
        unsafe { upatch_decode_map_file_json_limit(path, v, JSON_MAX, out, out_len) }
    }

    /// # Safety
    ///
    /// As upatch_decode_map_file_json().
    pub unsafe extern "C" fn upatch_decode_map_file_json_limit(
        path: *const c_char,
        v: *const MapView,
        max_bytes: usize,
        out: *mut *mut c_char,
        out_len: *mut usize,
    ) -> c_int {
        if max_bytes == 0 || path.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller's arguments.
        unsafe { decode(path, v, false, max_bytes, out, out_len) }
    }

    /// # Safety
    ///
    /// As upatch_decode_map_file_json().
    pub unsafe extern "C" fn upatch_decode_map_file_otel(
        path: *const c_char,
        v: *const MapView,
        out: *mut *mut c_char,
        out_len: *mut usize,
    ) -> c_int {
        if path.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller's arguments.
        unsafe { decode(path, v, true, JSON_MAX, out, out_len) }
    }
}

pub(crate) use capi::{
    upatch_decode_map_file_json, upatch_decode_map_file_json_limit, upatch_decode_map_file_otel,
    upatch_decode_map_json, upatch_decode_map_json_limit, upatch_decode_map_otel,
};
