// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The LuaJIT 2.1 API the decoder sandbox uses, and its macros.
//!
//! LuaJIT raises an error by unwinding the stack to the lua_pcall() that
//! catches it, through every frame between, so each function that can
//! raise, and each Rust function Lua calls, is `C-unwind`. A Rust frame
//! the unwind may cross holds nothing that must be dropped.

use core::ffi::{c_char, c_int, c_void};

/// `lua_State`.
pub enum LuaState {}
/// `lua_Debug`, which a hook is handed and the sandbox does not read.
pub enum LuaDebug {}

pub type LuaNumber = f64;
pub type LuaInteger = isize;
pub type LuaCFunction = unsafe extern "C-unwind" fn(l: *mut LuaState) -> c_int;
pub type LuaAlloc = unsafe extern "C" fn(
    ud: *mut c_void,
    ptr: *mut c_void,
    osize: usize,
    nsize: usize,
) -> *mut c_void;
pub type LuaHook = unsafe extern "C-unwind" fn(l: *mut LuaState, ar: *mut LuaDebug);

pub const LUA_REGISTRYINDEX: c_int = -10000;
pub const LUA_GLOBALSINDEX: c_int = -10002;
pub const LUA_TNIL: c_int = 0;
pub const LUA_TBOOLEAN: c_int = 1;
pub const LUA_TNUMBER: c_int = 3;
pub const LUA_TSTRING: c_int = 4;
pub const LUA_TTABLE: c_int = 5;
pub const LUA_TFUNCTION: c_int = 6;
/// `1 << LUA_HOOKCOUNT`.
pub const LUA_MASKCOUNT: c_int = 8;
pub const LUAJIT_MODE_ENGINE: c_int = 0;
pub const LUAJIT_MODE_OFF: c_int = 0;

unsafe extern "C-unwind" {
    pub fn luaL_newstate() -> *mut LuaState;
    pub fn lua_newstate(f: LuaAlloc, ud: *mut c_void) -> *mut LuaState;
    pub fn lua_getallocf(l: *mut LuaState, ud: *mut *mut c_void) -> Option<LuaAlloc>;
    pub fn lua_close(l: *mut LuaState);
    pub fn luaL_openlibs(l: *mut LuaState);
    pub fn luaJIT_setmode(l: *mut LuaState, idx: c_int, mode: c_int) -> c_int;
    pub fn luaL_loadbufferx(
        l: *mut LuaState,
        buf: *const c_char,
        size: usize,
        name: *const c_char,
        mode: *const c_char,
    ) -> c_int;
    pub fn lua_pcall(l: *mut LuaState, nargs: c_int, nresults: c_int, errfunc: c_int) -> c_int;
    pub fn lua_call(l: *mut LuaState, nargs: c_int, nresults: c_int);
    pub fn lua_sethook(l: *mut LuaState, f: Option<LuaHook>, mask: c_int, count: c_int) -> c_int;

    pub fn lua_gettop(l: *mut LuaState) -> c_int;
    pub fn lua_settop(l: *mut LuaState, idx: c_int);
    pub fn lua_pushvalue(l: *mut LuaState, idx: c_int);
    pub fn lua_remove(l: *mut LuaState, idx: c_int);
    pub fn lua_type(l: *mut LuaState, idx: c_int) -> c_int;
    pub fn lua_tonumber(l: *mut LuaState, idx: c_int) -> LuaNumber;
    pub fn lua_toboolean(l: *mut LuaState, idx: c_int) -> c_int;
    pub fn lua_tolstring(l: *mut LuaState, idx: c_int, len: *mut usize) -> *const c_char;
    pub fn lua_objlen(l: *mut LuaState, idx: c_int) -> usize;
    pub fn lua_touserdata(l: *mut LuaState, idx: c_int) -> *mut c_void;

    pub fn lua_pushnil(l: *mut LuaState);
    pub fn lua_pushnumber(l: *mut LuaState, n: LuaNumber);
    pub fn lua_pushinteger(l: *mut LuaState, n: LuaInteger);
    pub fn lua_pushlstring(l: *mut LuaState, s: *const c_char, len: usize);
    pub fn lua_pushstring(l: *mut LuaState, s: *const c_char);
    pub fn lua_pushcclosure(l: *mut LuaState, f: LuaCFunction, n: c_int);
    pub fn lua_pushboolean(l: *mut LuaState, b: c_int);
    pub fn lua_pushlightuserdata(l: *mut LuaState, p: *mut c_void);

    pub fn lua_getfield(l: *mut LuaState, idx: c_int, k: *const c_char);
    pub fn lua_rawgeti(l: *mut LuaState, idx: c_int, n: c_int);
    pub fn lua_createtable(l: *mut LuaState, narr: c_int, nrec: c_int);
    pub fn lua_newuserdata(l: *mut LuaState, size: usize) -> *mut c_void;
    pub fn lua_setfield(l: *mut LuaState, idx: c_int, k: *const c_char);
    pub fn lua_rawseti(l: *mut LuaState, idx: c_int, n: c_int);
    pub fn lua_setmetatable(l: *mut LuaState, idx: c_int) -> c_int;
    pub fn lua_next(l: *mut LuaState, idx: c_int) -> c_int;

    pub fn luaL_error(l: *mut LuaState, fmt: *const c_char, ...) -> c_int;
    pub fn luaL_argerror(l: *mut LuaState, numarg: c_int, extramsg: *const c_char) -> c_int;
    pub fn luaL_checkinteger(l: *mut LuaState, narg: c_int) -> LuaInteger;
    pub fn luaL_checklstring(l: *mut LuaState, narg: c_int, len: *mut usize) -> *const c_char;
    pub fn luaL_checktype(l: *mut LuaState, narg: c_int, t: c_int);
    pub fn luaL_checkudata(l: *mut LuaState, ud: c_int, tname: *const c_char) -> *mut c_void;
    pub fn luaL_newmetatable(l: *mut LuaState, tname: *const c_char) -> c_int;
}

/// lua_upvalueindex().
pub const fn lua_upvalueindex(i: c_int) -> c_int {
    LUA_GLOBALSINDEX - i
}

/// lua_pop().
///
/// # Safety
///
/// `l` is a state with `n` values on its stack.
pub unsafe fn lua_pop(l: *mut LuaState, n: c_int) {
    // SAFETY: the caller's state.
    unsafe { lua_settop(l, -n - 1) };
}

/// lua_newtable().
///
/// # Safety
///
/// `l` is a state.
pub unsafe fn lua_newtable(l: *mut LuaState) {
    // SAFETY: the caller's state.
    unsafe { lua_createtable(l, 0, 0) };
}

/// lua_pushcfunction().
///
/// # Safety
///
/// `l` is a state.
pub unsafe fn lua_pushcfunction(l: *mut LuaState, f: LuaCFunction) {
    // SAFETY: the caller's state.
    unsafe { lua_pushcclosure(l, f, 0) };
}

/// lua_setglobal().
///
/// # Safety
///
/// `l` is a state with a value on its stack; `name` a C string.
pub unsafe fn lua_setglobal(l: *mut LuaState, name: *const c_char) {
    // SAFETY: the caller's state and C string.
    unsafe { lua_setfield(l, LUA_GLOBALSINDEX, name) };
}

/// lua_getglobal().
///
/// # Safety
///
/// `l` is a state; `name` a C string.
pub unsafe fn lua_getglobal(l: *mut LuaState, name: *const c_char) {
    // SAFETY: the caller's state and C string.
    unsafe { lua_getfield(l, LUA_GLOBALSINDEX, name) };
}

/// luaL_getmetatable().
///
/// # Safety
///
/// `l` is a state; `name` a C string.
pub unsafe fn lual_getmetatable(l: *mut LuaState, name: *const c_char) {
    // SAFETY: the caller's state and C string.
    unsafe { lua_getfield(l, LUA_REGISTRYINDEX, name) };
}
