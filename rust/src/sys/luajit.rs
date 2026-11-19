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
const LUA_TUSERDATA: c_int = 7;
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
/// the Stack, and what pushes or pops takes it, so the one cannot outlive
/// the other; split() holds slots for longer.
///
/// Any call may raise a Lua error, which unwinds to the lua_pcall() that
/// catches it: when memory runs out, an argument check fails, or a call
/// misuses the stack, with an index that names no slot or no table where
/// one is needed, or a pop of more than the frame holds above its split.
/// LuaJIT does not check those, and the Stack does so that a misuse is
/// not undefined.
pub(crate) struct Stack<'s> {
    l: *mut LuaState,
    /// The slots up to it are held by a split, and stay.
    base: c_int,
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
            base: 0,
            frame: PhantomData,
        }
    }

    /// Splits the stack at its top: the Held reads the slots up to there,
    /// which stay as they are while the split lasts, and the new Stack
    /// works above them.
    pub(crate) fn split(&mut self) -> (Held<'_>, Stack<'_>) {
        let top = self.top();
        let held = Held {
            l: self.l,
            top,
            split: PhantomData,
        };
        let above = Stack {
            l: self.l,
            base: top,
            frame: PhantomData,
        };
        (held, above)
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

    /// `arg` for an argument check: an argument's place as it is, as
    /// LuaJIT reads one past the top as none, else the slot it names.
    fn arg(&self, arg: c_int) -> c_int {
        if arg > 0 { arg } else { self.slot_or_none(arg) }
    }

    /// The slot of the table at `idx`.
    fn table(&self, idx: c_int) -> c_int {
        match self.abs_index(idx) {
            Some(t) if self.type_of(t) == LuaType::Table => t,
            _ => self.error(c"no table at the stack index"),
        }
    }

    /// Raises an error unless the frame holds `n` values above its split.
    fn need(&self, n: c_int) {
        if !(0..=self.top() - self.base).contains(&n) {
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

    /// The length of the value at `idx` without metamethods: a string's
    /// bytes, a table's border, a userdata's size; 0 for another value.
    pub(crate) fn length(&self, idx: c_int) -> usize {
        // SAFETY: as in type_of().
        unsafe { lua_objlen(self.l, self.slot_or_none(idx)) }
    }

    /// Argument `arg` as an integer; raises an error unless it is a
    /// number or a string that spells one.
    pub(crate) fn check_integer(&self, arg: c_int) -> isize {
        // SAFETY: the state is live, and an argument's place one LuaJIT
        // reads as none past the top.
        unsafe { luaL_checkinteger(self.l, self.arg(arg)) }
    }

    /// Argument `arg` as a string, a number made one in its slot; raises
    /// an error for another value.
    pub(crate) fn check_bytes(&self, arg: c_int) -> &[u8] {
        let mut len = 0;
        // SAFETY: as in check_integer(); room for the length.
        let text = unsafe { luaL_checklstring(self.l, self.arg(arg), &mut len) };
        // SAFETY: the string's len bytes, which live while the slot holds
        // it, which the borrow of the Stack keeps.
        unsafe { ffi::slice(text.cast::<u8>(), len) }
    }

    /// Raises an error unless argument `arg` is a table.
    pub(crate) fn check_table(&self, arg: c_int) {
        // SAFETY: as in check_integer().
        unsafe { luaL_checktype(self.l, self.arg(arg), LUA_TTABLE) };
    }

    /// The bytes of argument `arg`, a userdata with the metatable
    /// registered as `name`; raises an error for another value.
    pub(crate) fn check_userdata(&self, arg: c_int, name: &CStr) -> &[u8] {
        let arg = self.arg(arg);
        // SAFETY: as in check_integer().
        let data = unsafe { luaL_checkudata(self.l, arg, name.as_ptr()) }.cast::<u8>();
        // SAFETY: the state is live and the slot a userdata.
        let len = unsafe { lua_objlen(self.l, arg) };
        // SAFETY: the userdata's len bytes, which live while the slot holds
        // it, which the borrow of the Stack keeps; only
        // push_userdata_with() writes one, as it makes it.
        unsafe { ffi::slice(data, len) }
    }

    /// Raises an error that argument `arg` is bad, saying `msg`.
    pub(crate) fn arg_error(&self, arg: c_int, msg: &CStr) -> ! {
        // SAFETY: the state is live.
        unsafe { luaL_argerror(self.l, arg, msg.as_ptr()) }
    }

    pub(crate) fn push_nil(&mut self) {
        // SAFETY: the state is live; LuaJIT grows the stack.
        unsafe { lua_pushnil(self.l) };
    }

    pub(crate) fn push_bool(&mut self, b: bool) {
        // SAFETY: as in push_nil().
        unsafe { lua_pushboolean(self.l, c_int::from(b)) };
    }

    pub(crate) fn push_integer(&mut self, n: i32) {
        // SAFETY: as in push_nil(); a lua_Integer is a ptrdiff_t, which
        // holds an i32 on every target LuaJIT runs on.
        unsafe { lua_pushinteger(self.l, n as LuaInteger) };
    }

    pub(crate) fn push_number(&mut self, n: f64) {
        // SAFETY: as in push_nil().
        unsafe { lua_pushnumber(self.l, n) };
    }

    /// Pushes a string of the bytes.
    pub(crate) fn push_bytes(&mut self, bytes: &[u8]) {
        // SAFETY: as in push_nil(); LuaJIT copies the bytes.
        unsafe { lua_pushlstring(self.l, bytes.as_ptr().cast(), bytes.len()) };
    }

    pub(crate) fn new_table(&mut self) {
        // SAFETY: as in push_nil().
        unsafe { lua_createtable(self.l, 0, 0) };
    }

    /// Pushes a userdata of `len` bytes, zeroed, for `fill` to write before
    /// anything can read them; what `fill` returns.
    pub(crate) fn push_userdata_with<R>(
        &mut self,
        len: usize,
        fill: impl FnOnce(&mut [u8]) -> R,
    ) -> R {
        // SAFETY: as in push_nil(); LuaJIT raises an error for a size it
        // cannot make.
        let data = unsafe { lua_newuserdata(self.l, len) }.cast::<u8>();
        // SAFETY: the len bytes LuaJIT made, which it does not clear.
        unsafe { data.write_bytes(0, len) };
        // SAFETY: the len bytes, which nothing else reaches until fill
        // returns: a userdata is read through a Held, which sees no slot
        // pushed after its split, and the Stack is borrowed meanwhile.
        fill(unsafe { ffi::bytes_mut(data, len) })
    }

    /// Pushes field `k` of the value at `idx`, as `t[k]` reads it,
    /// metamethods and all.
    pub(crate) fn get_field(&mut self, idx: c_int, k: &CStr) {
        let target = self.slot_or_none(idx);
        // SAFETY: as in type_of(); LuaJIT raises an error for a value it
        // cannot index.
        unsafe { lua_getfield(self.l, target, k.as_ptr()) };
    }

    /// Pushes the metatable registered as `name`, or nil.
    pub(crate) fn push_metatable(&mut self, name: &CStr) {
        // SAFETY: the state is live, and its registry always there.
        unsafe { lua_getfield(self.l, LUA_REGISTRYINDEX, name.as_ptr()) };
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

    /// Pops the value on top into field `k` of the value at `idx`, as
    /// `t[k] = v` does, metamethods and all.
    pub(crate) fn set_field(&mut self, idx: c_int, k: &CStr) {
        self.need(1);
        let target = self.slot_or_none(idx);
        // SAFETY: the state is live with a value on top, and the index as
        // in type_of(); LuaJIT raises an error for a value it cannot index.
        unsafe { lua_setfield(self.l, target, k.as_ptr()) };
    }

    /// Pops the value on top into element `n` of the table at `idx`,
    /// without metamethods.
    pub(crate) fn raw_set_index(&mut self, idx: c_int, n: c_int) {
        let table = self.table(idx);
        self.need(1);
        // SAFETY: the state is live, the slot a table and a value on top.
        unsafe { lua_rawseti(self.l, table, n) };
    }

    /// Pops the table or nil on top as the metatable of the value at
    /// `idx`.
    pub(crate) fn set_metatable(&mut self, idx: c_int) {
        self.need(1);
        match (self.abs_index(idx), self.type_of(-1)) {
            (Some(target), LuaType::Table | LuaType::Nil) => {
                // SAFETY: the state is live, the slot one of its frame, and
                // a table or nil on top.
                unsafe { lua_setmetatable(self.l, target) };
            }
            _ => self.error(c"no metatable for a value at the stack index"),
        }
    }

    /// Removes the value at `idx` above the split, those above it moving
    /// down.
    pub(crate) fn remove(&mut self, idx: c_int) {
        match self.abs_index(idx) {
            // SAFETY: the state is live and the slot one of its frame.
            Some(slot) if slot > self.base => unsafe { lua_remove(self.l, slot) },
            _ => self.error(c"no slot to remove at the stack index"),
        }
    }

    /// Calls the function under the `nargs` arguments on top, popping
    /// them, and pushes `nresults` of its results.
    pub(crate) fn call(&mut self, nargs: c_int, nresults: c_int) {
        self.need(nargs.saturating_add(1));
        if nresults < 0 {
            self.error(c"no count of results");
        }
        // SAFETY: the state is live, with the function and its arguments
        // above the split; LuaJIT raises an error for a value it cannot
        // call, and what the function raises unwinds through here.
        unsafe { lua_call(self.l, nargs, nresults) };
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

/// The slots of a stack up to where it was split, to read: they stay as
/// they are while the split lasts, and so does what is read of them.
pub(crate) struct Held<'h> {
    l: *mut LuaState,
    top: c_int,
    split: PhantomData<&'h LuaState>,
}

impl<'h> Held<'h> {
    /// The string at `idx`, or the number there made one in its slot.
    pub(crate) fn to_bytes(&self, idx: c_int) -> Option<&'h [u8]> {
        // SAFETY: the state is live and the slot one of its frame, which
        // holds the value while the split lasts.
        unsafe { bytes_at(self.l, self.slot(idx)?) }
    }

    /// The held slot `idx` names, counted from 1 up, or from -1 down at
    /// the split.
    fn slot(&self, idx: c_int) -> Option<c_int> {
        let abs = if idx < 0 {
            self.top.checked_add(idx)?.checked_add(1)?
        } else {
            idx
        };
        (1..=self.top).contains(&abs).then_some(abs)
    }

    /// The bytes of the userdata at `idx`.
    pub(crate) fn userdata(&self, idx: c_int) -> Option<&'h [u8]> {
        let slot = self.slot(idx)?;
        // SAFETY: the state is live and the slot one of its frame.
        if unsafe { lua_type(self.l, slot) } != LUA_TUSERDATA {
            return None;
        }
        // SAFETY: as above, and a full userdata there.
        let data = unsafe { lua_touserdata(self.l, slot) }.cast::<u8>();
        // SAFETY: as above.
        let len = unsafe { lua_objlen(self.l, slot) };
        // SAFETY: the userdata's len bytes, which live while the split
        // holds its slot; only push_userdata_with() writes one, as it makes
        // it, above any split.
        Some(unsafe { ffi::slice(data, len) })
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
