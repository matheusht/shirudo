// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The LuaJIT 2.1 API the decoder sandbox uses, and its macros.
//!
//! LuaJIT raises an error by unwinding the stack to the lua_pcall() that
//! catches it, through every frame between, so each function that can
//! raise, and each Rust function Lua calls, is `C-unwind`. A Rust frame
//! the unwind may cross holds nothing that must be dropped.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::marker::PhantomData;
use core::ptr::{self, NonNull};

use crate::ffi;

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
const LUA_TNONE: c_int = -1;
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

// The binaries link LuaJIT themselves; the crate's tests, which rustc
// links, name it.
#[cfg_attr(test, link(name = "luajit-5.1"))]
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

    pub fn luaL_error(l: *mut LuaState, fmt: *const c_char, ...) -> !;
    pub fn luaL_argerror(l: *mut LuaState, numarg: c_int, extramsg: *const c_char) -> !;
    pub fn luaL_checkinteger(l: *mut LuaState, narg: c_int) -> LuaInteger;
    pub fn luaL_checklstring(l: *mut LuaState, narg: c_int, len: *mut usize) -> *const c_char;
    pub fn luaL_checktype(l: *mut LuaState, narg: c_int, t: c_int);
    pub fn luaL_checkudata(l: *mut LuaState, ud: c_int, tname: *const c_char) -> *mut c_void;
    pub fn luaL_newmetatable(l: *mut LuaState, tname: *const c_char) -> c_int;
}

/// Owns a Lua state and borrows any allocator data it depends on.
pub(crate) struct Lua<'a> {
    state: NonNull<LuaState>,
    data: PhantomData<&'a mut ()>,
}

impl Lua<'static> {
    pub(crate) fn new() -> Option<Self> {
        // SAFETY: this creates an independent state with LuaJIT's allocator.
        let state = NonNull::new(unsafe { luaL_newstate() })?;
        Some(Self {
            state,
            data: PhantomData,
        })
    }
}

impl<'a> Lua<'a> {
    /// # Safety
    ///
    /// `allocate` must implement Lua's allocator contract and accept a
    /// pointer to `data` as its context.
    pub(crate) unsafe fn with_allocator<T>(allocate: LuaAlloc, data: &'a mut T) -> Option<Self> {
        // SAFETY: the caller supplies a matching allocator and context.
        let state = NonNull::new(unsafe { lua_newstate(allocate, ptr::from_mut(data).cast()) })?;
        Some(Self {
            state,
            data: PhantomData,
        })
    }

    pub(crate) fn as_ptr(&self) -> *mut LuaState {
        self.state.as_ptr()
    }

    pub(crate) fn allocator(&self) -> Option<Allocator<'_>> {
        let mut context = ptr::null_mut();
        // SAFETY: the state is live and context can hold the allocator data.
        let allocate = unsafe { lua_getallocf(self.as_ptr(), &mut context) }?;
        Some(Allocator {
            allocate,
            context,
            owner: PhantomData,
        })
    }
}

impl Drop for Lua<'_> {
    fn drop(&mut self) {
        // SAFETY: this owner closes the live state once, before its allocator goes.
        unsafe { lua_close(self.as_ptr()) };
    }
}

/// Borrows the allocator of a live Lua state.
pub(crate) struct Allocator<'a> {
    allocate: LuaAlloc,
    context: *mut c_void,
    owner: PhantomData<&'a Lua<'a>>,
}

impl Allocator<'_> {
    /// # Safety
    ///
    /// `block` is null for a new allocation, or this allocator's live
    /// allocation of `old` bytes. A size of zero releases it.
    pub(crate) unsafe fn resize(&self, block: *mut c_void, old: usize, new: usize) -> *mut c_void {
        // SAFETY: the caller supplies the block as the Lua allocator requires.
        unsafe { (self.allocate)(self.context, block, old, new) }
    }
}

/// What a Lua value is, as lua_type() tells it.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum LuaType {
    /// What an index that names no slot holds.
    None,
    Nil,
    Boolean,
    Number,
    String,
    Table,
    Function,
    /// A userdata, a thread, or what else LuaJIT has.
    Other,
}

/// The stack of a live Lua state, in the frame of the C function or the
/// hook LuaJIT called. An index counts up from 1 at the bottom of the
/// frame or down from -1 at its top. What a read finds in a slot borrows
/// the Stack, and what pops a slot takes it, so the one cannot outlive
/// the other.
///
/// Any call may raise a Lua error, which unwinds to the lua_pcall() that
/// catches it: when memory runs out, an argument check fails, or a call
/// misuses the stack, with an index that names no slot or no table where
/// one is needed, or a pop of more than the frame holds. LuaJIT does not
/// check those, and the Stack does so that a misuse is not undefined.
pub(crate) struct Stack<'s> {
    l: *mut LuaState,
    frame: PhantomData<&'s mut LuaState>,
}

impl Stack<'_> {
    /// The stack of the frame LuaJIT runs `l` in.
    ///
    /// # Safety
    ///
    /// `l` is the live state LuaJIT called a C function or a hook with,
    /// and the Stack is used only during that call, as the only one of
    /// that frame.
    pub(crate) unsafe fn from_raw(l: *mut LuaState) -> Self {
        Self {
            l,
            frame: PhantomData,
        }
    }

    /// How many values the frame holds.
    pub(crate) fn top(&self) -> c_int {
        // SAFETY: the state is live.
        unsafe { lua_gettop(self.l) }
    }

    /// The slot `idx` names, counted from 1, if it names one.
    pub(crate) fn abs_index(&self, idx: c_int) -> Option<c_int> {
        let top = self.top();
        let abs = if idx < 0 {
            top.checked_add(idx)?.checked_add(1)?
        } else {
            idx
        };
        (1..=top).contains(&abs).then_some(abs)
    }

    /// `idx` as LuaJIT may take it: the slot it names, else the one past
    /// the top, which LuaJIT reads as no value.
    fn slot_or_none(&self, idx: c_int) -> c_int {
        self.abs_index(idx)
            .unwrap_or_else(|| self.top().saturating_add(1))
    }

    /// The slot of the table at `idx`.
    fn table(&self, idx: c_int) -> c_int {
        match self.abs_index(idx) {
            Some(t) if self.type_of(t) == LuaType::Table => t,
            _ => self.error(c"no table at the stack index"),
        }
    }

    /// Raises an error unless the frame holds `n` values.
    fn need(&self, n: c_int) {
        if !(0..=self.top()).contains(&n) {
            self.error(c"too few values on the stack");
        }
    }

    pub(crate) fn type_of(&self, idx: c_int) -> LuaType {
        // SAFETY: the state is live, and the index a slot of the frame or
        // one LuaJIT reads as none.
        match unsafe { lua_type(self.l, self.slot_or_none(idx)) } {
            LUA_TNONE => LuaType::None,
            LUA_TNIL => LuaType::Nil,
            LUA_TBOOLEAN => LuaType::Boolean,
            LUA_TNUMBER => LuaType::Number,
            LUA_TSTRING => LuaType::String,
            LUA_TTABLE => LuaType::Table,
            LUA_TFUNCTION => LuaType::Function,
            _ => LuaType::Other,
        }
    }

    /// The number at `idx`, or a string that spells one; 0 for another
    /// value.
    pub(crate) fn to_number(&self, idx: c_int) -> f64 {
        // SAFETY: as in type_of().
        unsafe { lua_tonumber(self.l, self.slot_or_none(idx)) }
    }

    /// Whether the value at `idx` is true, as Lua tests it.
    pub(crate) fn to_bool(&self, idx: c_int) -> bool {
        // SAFETY: as in type_of().
        unsafe { lua_toboolean(self.l, self.slot_or_none(idx)) != 0 }
    }

    /// The string at `idx`, or the number there, which LuaJIT makes a
    /// string in its slot; none for another value.
    pub(crate) fn to_bytes(&self, idx: c_int) -> Option<&[u8]> {
        // SAFETY: as in type_of(); the text lives while the slot holds it,
        // which the borrow of the Stack keeps.
        unsafe { bytes_at(self.l, self.slot_or_none(idx)) }
    }

    pub(crate) fn push_nil(&mut self) {
        // SAFETY: the state is live; LuaJIT grows the stack.
        unsafe { lua_pushnil(self.l) };
    }

    /// Pushes element `n` of the table at `idx`, without metamethods.
    pub(crate) fn raw_get_index(&mut self, idx: c_int, n: c_int) {
        let table = self.table(idx);
        // SAFETY: the state is live and the slot a table.
        unsafe { lua_rawgeti(self.l, table, n) };
    }

    /// Replaces the key on top with the next key of the table at `idx`
    /// and pushes its value; pops the key and is false after the last.
    pub(crate) fn next(&mut self, idx: c_int) -> bool {
        let table = self.table(idx);
        self.need(1);
        // SAFETY: the state is live, the slot a table and a key on top.
        unsafe { lua_next(self.l, table) != 0 }
    }

    /// Pops `n` values.
    pub(crate) fn pop(&mut self, n: c_int) {
        self.need(n);
        // SAFETY: the state is live and holds n values.
        unsafe { lua_settop(self.l, -n - 1) };
    }

    /// Raises `msg` as a Lua error, after where the running function is.
    pub(crate) fn error(&self, msg: &CStr) -> ! {
        // SAFETY: the state is live; the format takes msg as its string.
        unsafe { luaL_error(self.l, c"%s".as_ptr(), msg.as_ptr()) }
    }
}

/// The string at `idx` of the state, or the number there made one.
///
/// # Safety
///
/// `l` is live and `idx` a slot of its frame or one LuaJIT reads as none,
/// which holds the value for `'a`.
unsafe fn bytes_at<'a>(l: *mut LuaState, idx: c_int) -> Option<&'a [u8]> {
    let mut len = 0;
    // SAFETY: the caller's state and index; room for the length.
    let text = unsafe { lua_tolstring(l, idx, &mut len) };
    // SAFETY: the string's len bytes, which live as its slot holds it.
    (!text.is_null()).then(|| unsafe { ffi::slice(text.cast::<u8>(), len) })
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
