// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The JSON readers. json_parse() dispatches the declared keys of a
//! schema and parses and discards the rest, json_walk() reports every
//! token, and both check a document through the one grammar json.h
//! describes, so that a single parser checks every document shirudo reads.

use alloc::vec::Vec;
use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use super::{MAX_BYTES, MAX_DEPTH, MAX_FIELDS, MAX_STRING_BYTES, utf8_width};
use crate::errno::{E2BIG, EINVAL, ENOMEM, ENOSPC};

/// A negative errno, or the non-zero value a callback returned.
type Result<T = ()> = core::result::Result<T, c_int>;

const T_STRING: c_int = 0;
const T_INT: c_int = 1;
const T_BOOL: c_int = 2;
const T_OBJECT: c_int = 3;
const T_ARRAY: c_int = 4;
const T_MAP: c_int = 5;

/// `struct json_field`: a declared key, where its value goes, and for an
/// object, array or map the schema of what it holds.
#[repr(C)]
pub struct JsonField {
    key: *const c_char,
    ty: c_int,
    dst: *mut c_void,
    dst_cap: usize,
    seen: c_int,
    sub: *mut JsonField,
    n_sub: usize,
}

/// `struct json_array`: what an array field calls after each element.
#[repr(C)]
pub struct JsonArray {
    on_elem: Option<unsafe extern "C" fn(ctx: *mut c_void) -> c_int>,
    ctx: *mut c_void,
}

/// The fields of a schema that Rust code builds in C's layout, for the
/// callers of json_parse() that moved to Rust before the schemas did.
impl JsonField {
    const fn new(key: &'static CStr, ty: c_int, dst: *mut c_void, dst_cap: usize) -> Self {
        JsonField {
            key: key.as_ptr(),
            ty,
            dst,
            dst_cap,
            seen: 0,
            sub: ptr::null_mut(),
            n_sub: 0,
        }
    }

    /// A string, decoded into the `cap` bytes at `dst`.
    /// This field without its key, which no member of an object matches.
    pub(crate) const fn keyless(mut self) -> Self {
        self.key = ptr::null();
        self
    }

    pub(crate) const fn string(key: &'static CStr, dst: *mut u8, cap: usize) -> Self {
        Self::new(key, T_STRING, dst.cast(), cap)
    }

    pub(crate) const fn int(key: &'static CStr, dst: *mut i64) -> Self {
        Self::new(key, T_INT, dst.cast(), 0)
    }

    /// An object whose own declared keys are the `n` fields at `sub`.
    pub(crate) const fn object(key: &'static CStr, sub: *mut JsonField, n: usize) -> Self {
        let mut f = Self::new(key, T_OBJECT, ptr::null_mut(), 0);

        f.sub = sub;
        f.n_sub = n;
        f
    }

    /// An array of objects with the `n` fields at `sub`, each of which
    /// `sink` hears about.
    pub(crate) const fn array(
        key: &'static CStr,
        sink: *mut JsonArray,
        sub: *mut JsonField,
        n: usize,
    ) -> Self {
        let mut f = Self::new(key, T_ARRAY, sink.cast(), 0);

        f.sub = sub;
        f.n_sub = n;
        f
    }

    pub(crate) fn seen(&self) -> bool {
        self.seen != 0
    }
}

impl JsonArray {
    pub(crate) const fn new(
        on_elem: unsafe extern "C" fn(*mut c_void) -> c_int,
        ctx: *mut c_void,
    ) -> Self {
        JsonArray {
            on_elem: Some(on_elem),
            ctx,
        }
    }
}

/// `struct json_map`: what a map field calls after each member.
#[repr(C)]
struct JsonMap {
    on_member: Option<unsafe extern "C" fn(ctx: *mut c_void, key: *const c_char) -> c_int>,
    ctx: *mut c_void,
}

/// `struct json_visitor`: what a walk calls for each token.
#[repr(C)]
pub struct JsonVisitor {
    open: Option<unsafe extern "C" fn(ctx: *mut c_void, array: bool) -> c_int>,
    close: Option<unsafe extern "C" fn(ctx: *mut c_void, array: bool) -> c_int>,
    key: Option<unsafe extern "C" fn(ctx: *mut c_void, key: *const c_char) -> c_int>,
    string: Option<unsafe extern "C" fn(ctx: *mut c_void, s: *const c_char) -> c_int>,
    number: Option<
        unsafe extern "C" fn(
            ctx: *mut c_void,
            text: *const c_char,
            len: usize,
            integer: bool,
        ) -> c_int,
    >,
    literal: Option<unsafe extern "C" fn(ctx: *mut c_void, value: c_int) -> c_int>,
}

fn status(ret: c_int) -> Result {
    if ret != 0 { Err(ret) } else { Ok(()) }
}

fn errno(ret: Result) -> c_int {
    ret.err().unwrap_or(0)
}

/// What a walk reports: decoded keys and strings, numbers as their text,
/// with `integer` set when it has no fraction or exponent, and literals
/// as 1 for true, 0 for false and -1 for null.
trait Visit {
    fn open(&mut self, array: bool) -> Result;
    fn close(&mut self, array: bool) -> Result;
    fn key(&mut self, key: &CStr) -> Result;
    fn string(&mut self, s: &CStr) -> Result;
    fn number(&mut self, text: &[u8], integer: bool) -> Result;
    fn literal(&mut self, value: c_int) -> Result;
}

/// One level of a C schema: `n` fields at `ptr`.
///
/// json_parse() takes a schema whose fields, and those their `sub`
/// pointers name, stay valid for the parse and are touched meanwhile only
/// by the callbacks it calls. A view reads and writes through raw
/// pointers alone, holding no reference across a callback, so a callback
/// may change what it points to between two reads, as in C.
#[derive(Clone, Copy)]
struct Fields {
    ptr: *mut JsonField,
    n: usize,
}

#[derive(Clone, Copy)]
struct Field(*mut JsonField);

impl Fields {
    const NONE: Fields = Fields {
        ptr: ptr::null_mut(),
        n: 0,
    };

    fn get(self, i: usize) -> Field {
        assert!(i < self.n);
        // SAFETY: the schema holds n fields at ptr, and i < n.
        Field(unsafe { self.ptr.add(i) })
    }

    /// The index of the first field named `key`.
    fn find(self, key: &[u8]) -> Option<usize> {
        (0..self.n).find(|&i| self.get(i).is_named(key))
    }

    fn reset_seen(self) {
        for i in 0..self.n {
            let f = self.get(i);

            f.set_seen(0);
            if matches!(f.ty(), T_OBJECT | T_ARRAY | T_MAP) {
                f.sub().reset_seen();
            }
        }
    }
}

impl Field {
    fn ty(self) -> c_int {
        // SAFETY: a field of the schema, which stays valid.
        unsafe { (*self.0).ty }
    }

    fn set_seen(self, seen: c_int) {
        // SAFETY: a field of the schema, which stays valid.
        unsafe { (*self.0).seen = seen };
    }

    fn sub(self) -> Fields {
        // SAFETY: a field of the schema, which stays valid; its sub
        // fields are the schema's too.
        unsafe {
            Fields {
                ptr: (*self.0).sub,
                n: (*self.0).n_sub,
            }
        }
    }

    fn dst(self) -> *mut c_void {
        // SAFETY: a field of the schema, which stays valid.
        unsafe { (*self.0).dst }
    }

    fn key(self) -> *const c_char {
        // SAFETY: a field of the schema, which stays valid.
        unsafe { (*self.0).key }
    }

    fn is_named(self, name: &[u8]) -> bool {
        let key = self.key();

        // SAFETY: a key the schema names is a C string.
        !key.is_null() && unsafe { CStr::from_ptr(key) }.to_bytes() == name
    }

    /// A field with no key, or an empty one, which takes each element of
    /// an array of scalars.
    fn is_unnamed(self) -> bool {
        let key = self.key();

        // SAFETY: a key the schema names is a C string.
        key.is_null() || unsafe { *key } == 0
    }

    fn set_int(self, v: i64) {
        let dst = self.dst().cast::<i64>();

        if !dst.is_null() {
            // SAFETY: an integer field's dst is a __s64.
            unsafe { dst.write_unaligned(v) };
        }
    }

    fn set_bool(self, v: c_int) {
        let dst = self.dst().cast::<c_int>();

        if !dst.is_null() {
            // SAFETY: a bool field's dst is an int.
            unsafe { dst.write_unaligned(v) };
        }
    }

    /// The string field's buffer, for the decoding of one string, during
    /// which no callback runs; none when dst is NULL, which discards it.
    fn string_dst<'a>(self) -> Option<&'a mut [u8]> {
        let dst = self.dst().cast::<u8>();

        if dst.is_null() {
            return None;
        }
        // SAFETY: a string field's dst holds dst_cap bytes, which nothing
        // else touches while the string is decoded.
        Some(unsafe { core::slice::from_raw_parts_mut(dst, (*self.0).dst_cap) })
    }
}

/// Calls an array field's `on_elem`, read afresh as C reads it.
fn call_on_elem(sink: *const JsonArray) -> Result {
    if sink.is_null() {
        return Ok(());
    }
    // SAFETY: an array field's dst, when set, is a struct json_array.
    let (on_elem, ctx) = unsafe { ((*sink).on_elem, (*sink).ctx) };
    match on_elem {
        // SAFETY: the callback takes the context it comes with.
        Some(f) => status(unsafe { f(ctx) }),
        None => Ok(()),
    }
}

/// Calls a map field's `on_member` with the member's key.
fn call_on_member(sink: *const JsonMap, key: &CStr) -> Result {
    if sink.is_null() {
        return Ok(());
    }
    // SAFETY: a map field's dst, when set, is a struct json_map.
    let (on_member, ctx) = unsafe { ((*sink).on_member, (*sink).ctx) };
    match on_member {
        // SAFETY: the callback takes the context it comes with and a C
        // string it may not keep.
        Some(f) => status(unsafe { f(ctx, key.as_ptr()) }),
        None => Ok(()),
    }
}

/// Appends a decoded byte, to `dst` when there is one, which keeps room
/// for the NUL.
fn emit_byte(dst: &mut Option<&mut [u8]>, len: &mut usize, b: u8) -> Result {
    let n = *len;

    if n >= MAX_STRING_BYTES {
        return Err(-E2BIG);
    }
    if let Some(buf) = dst {
        if n + 1 >= buf.len() {
            return Err(-ENOSPC);
        }
        buf[n] = b;
    }
    *len = n + 1;
    Ok(())
}

fn utf8_emit(dst: &mut Option<&mut [u8]>, len: &mut usize, cp: u32) -> Result {
    let mut buf = [0; 4];
    let c = char::from_u32(cp).ok_or(-EINVAL)?;

    for &b in c.encode_utf8(&mut buf).as_bytes() {
        emit_byte(dst, len, b)?;
    }
    Ok(())
}

fn hex4(s: &[u8]) -> Option<u32> {
    s.iter()
        .try_fold(0, |v, &c| char::from(c).to_digit(16).map(|d| (v << 4) | d))
}

/// The NUL-terminated string a decode left at the start of `buf`.
fn decoded(buf: &[u8]) -> Result<&CStr> {
    CStr::from_bytes_until_nul(buf).map_err(|_| -EINVAL)
}

/// The position in a document.
struct Cursor<'d> {
    data: &'d [u8],
    pos: usize,
}

impl<'d> Cursor<'d> {
    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.pos += 1;
        }
    }

    fn lit(&mut self, s: &[u8]) -> Result {
        if !self.data[self.pos..].starts_with(s) {
            return Err(-EINVAL);
        }
        self.pos += s.len();
        Ok(())
    }

    fn skip_digits(&mut self) -> Result {
        let n = self.data[self.pos..]
            .iter()
            .take_while(|c| c.is_ascii_digit())
            .count();

        self.pos += n;
        if n != 0 { Ok(()) } else { Err(-EINVAL) }
    }

    /// Scans a number as JSON spells one,
    /// `-?(0|[1-9][0-9]*)(.[0-9]+)?([eE][+-]?[0-9]+)?`, and returns where
    /// its integer part ends.
    fn number(&mut self) -> Result<usize> {
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        if self.peek() == Some(b'0') {
            self.pos += 1;
        } else {
            self.skip_digits()?;
        }
        let int_end = self.pos;
        if self.peek() == Some(b'.') {
            self.pos += 1;
            self.skip_digits()?;
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.pos += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.pos += 1;
            }
            self.skip_digits()?;
        }
        Ok(int_end)
    }

    fn unicode_escape(&mut self, dst: &mut Option<&mut [u8]>, len: &mut usize) -> Result {
        let hi = self.data[self.pos..].get(..4).and_then(hex4);
        // A NUL would end the string short of its value.
        let Some(hi) = hi.filter(|&cp| cp > 0) else {
            return Err(-EINVAL);
        };

        self.pos += 4;
        let cp = match hi {
            0xd800..=0xdbff => {
                let rest = &self.data[self.pos..];

                if rest.len() < 6 || rest[0] != b'\\' || rest[1] != b'u' {
                    return Err(-EINVAL);
                }
                let lo = hex4(&rest[2..6])
                    .filter(|lo| (0xdc00..=0xdfff).contains(lo))
                    .ok_or(-EINVAL)?;
                self.pos += 6;
                0x10000 + ((hi - 0xd800) << 10) + (lo - 0xdc00)
            }
            0xdc00..=0xdfff => return Err(-EINVAL),
            _ => hi,
        };
        utf8_emit(dst, len, cp)
    }

    /// Decodes a string into `dst`, NUL-terminated, or checks it alone
    /// when there is none; returns its decoded length.
    fn string(&mut self, mut dst: Option<&mut [u8]>) -> Result<usize> {
        let mut len = 0;

        if self.peek() != Some(b'"') {
            return Err(-EINVAL);
        }
        self.pos += 1;
        loop {
            let Some(ch) = self.peek() else {
                return Err(-EINVAL);
            };

            self.pos += 1;
            match ch {
                b'"' => break,
                b'\\' => {
                    let Some(escape) = self.peek() else {
                        return Err(-EINVAL);
                    };

                    self.pos += 1;
                    match escape {
                        b'"' | b'\\' | b'/' => emit_byte(&mut dst, &mut len, escape)?,
                        b'b' => emit_byte(&mut dst, &mut len, 0x08)?,
                        b'f' => emit_byte(&mut dst, &mut len, 0x0c)?,
                        b'n' => emit_byte(&mut dst, &mut len, b'\n')?,
                        b'r' => emit_byte(&mut dst, &mut len, b'\r')?,
                        b't' => emit_byte(&mut dst, &mut len, b'\t')?,
                        b'u' => self.unicode_escape(&mut dst, &mut len)?,
                        _ => return Err(-EINVAL),
                    }
                }
                0x00..=0x1f => return Err(-EINVAL),
                _ => {
                    let width = utf8_width(&self.data[self.pos - 1..]);

                    if width == 0 {
                        return Err(-EINVAL);
                    }
                    emit_byte(&mut dst, &mut len, ch)?;
                    for _ in 1..width {
                        emit_byte(&mut dst, &mut len, self.data[self.pos])?;
                        self.pos += 1;
                    }
                }
            }
        }
        if let Some(buf) = dst {
            if buf.is_empty() {
                return Err(-ENOSPC);
            }
            buf[len] = 0;
        }
        Ok(len)
    }

    /// After a member or an element: `,` goes on, `close` ends the
    /// container, true then.
    fn next_or_end(&mut self, close: u8) -> Result<bool> {
        self.skip_ws();
        match self.peek() {
            Some(b',') => {
                self.pos += 1;
                Ok(false)
            }
            Some(c) if c == close => {
                self.pos += 1;
                Ok(true)
            }
            _ => Err(-EINVAL),
        }
    }
}

/// A walk's visitor, and the buffer it decodes strings and keys into.
struct Walk<'w> {
    visitor: &'w mut dyn Visit,
    scratch: Vec<u8>,
}

struct Parser<'d, 'w> {
    cur: Cursor<'d>,
    depth: u32,
    fields: Fields,
    walk: Option<Walk<'w>>,
}

impl Parser<'_, '_> {
    fn visit_open(&mut self, array: bool) -> Result {
        match &mut self.walk {
            Some(w) => w.visitor.open(array),
            None => Ok(()),
        }
    }

    fn visit_close(&mut self, array: bool) -> Result {
        match &mut self.walk {
            Some(w) => w.visitor.close(array),
            None => Ok(()),
        }
    }

    fn visit_literal(&mut self, value: c_int) -> Result {
        match &mut self.walk {
            Some(w) => w.visitor.literal(value),
            None => Ok(()),
        }
    }

    /// The opening of a container: one level deeper and past its bracket.
    fn enter(&mut self) -> Result {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(-E2BIG);
        }
        self.cur.pos += 1;
        Ok(())
    }

    /// Whether the container just entered is empty, `close` taken if so.
    fn empty(&mut self, close: u8) -> bool {
        self.cur.skip_ws();
        if self.cur.peek() != Some(close) {
            return false;
        }
        self.cur.pos += 1;
        self.depth -= 1;
        true
    }

    fn object(&mut self) -> Result {
        let mut buf = [0; 256];
        let mut named = 0u64;

        if self.fields.n > MAX_FIELDS {
            self.depth += 1;
            return Err(-E2BIG);
        }
        self.enter()?;
        self.visit_open(false)?;
        if self.empty(b'}') {
            return self.visit_close(false);
        }
        loop {
            self.cur.skip_ws();
            let found = match &mut self.walk {
                Some(w) => {
                    self.cur.string(Some(&mut w.scratch))?;
                    w.visitor.key(decoded(&w.scratch)?)?;
                    None
                }
                None => {
                    let len = self.cur.string(Some(&mut buf))?;

                    self.fields.find(&buf[..len])
                }
            };
            self.cur.skip_ws();
            if self.cur.peek() != Some(b':') {
                return Err(-EINVAL);
            }
            self.cur.pos += 1;
            // Readers that take the first or the last would differ.
            if let Some(i) = found {
                if named & (1 << i) != 0 {
                    return Err(-EINVAL);
                }
                named |= 1 << i;
            }
            self.value(found.map(|i| self.fields.get(i)))?;
            if self.cur.next_or_end(b'}')? {
                break;
            }
        }
        self.depth -= 1;
        self.visit_close(false)
    }

    /// An object with the schema `fields` in place of the current one.
    fn object_with(&mut self, fields: Fields) -> Result {
        let saved = self.fields;

        self.fields = fields;
        let ret = self.object();
        self.fields = saved;
        ret
    }

    fn array(&mut self) -> Result {
        self.enter()?;
        self.visit_open(true)?;
        if self.empty(b']') {
            return self.visit_close(true);
        }
        loop {
            // Elements are never dispatched.
            self.value(None)?;
            if self.cur.next_or_end(b']')? {
                break;
            }
        }
        self.depth -= 1;
        self.visit_close(true)
    }

    fn array_into(&mut self, f: Field) -> Result {
        let sink = f.dst().cast::<JsonArray>().cast_const();

        self.enter()?;
        if self.empty(b']') {
            f.set_seen(1);
            return Ok(());
        }
        loop {
            let sub = f.sub();

            sub.reset_seen();
            self.cur.skip_ws();
            let Some(c) = self.cur.peek() else {
                return Err(-EINVAL);
            };
            if sub.n == 1 && sub.get(0).is_unnamed() {
                self.value(Some(sub.get(0)))?;
            } else if c == b'{' {
                self.object_with(sub)?;
            } else if sub.n == 0 {
                self.value(None)?;
            } else {
                // Not an object, as the sub fields ask.
                return Err(-EINVAL);
            }
            call_on_elem(sink)?;
            if self.cur.next_or_end(b']')? {
                break;
            }
        }
        self.depth -= 1;
        f.set_seen(1);
        Ok(())
    }

    fn map(&mut self, f: Field) -> Result {
        let sink = f.dst().cast::<JsonMap>().cast_const();
        let mut key = [0; 256];

        self.enter()?;
        if self.empty(b'}') {
            f.set_seen(1);
            return Ok(());
        }
        loop {
            let sub = f.sub();

            sub.reset_seen();
            self.cur.skip_ws();
            self.cur.string(Some(&mut key))?;
            self.cur.skip_ws();
            if self.cur.peek() != Some(b':') {
                return Err(-EINVAL);
            }
            self.cur.pos += 1;
            self.value(if sub.n != 0 { Some(sub.get(0)) } else { None })?;
            call_on_member(sink, decoded(&key)?)?;
            if self.cur.next_or_end(b'}')? {
                break;
            }
        }
        self.depth -= 1;
        f.set_seen(1);
        Ok(())
    }

    fn number(&mut self, f: Option<Field>) -> Result {
        let data = self.cur.data;
        let start = self.cur.pos;
        let int_end = self.cur.number()?;
        let integer = self.cur.pos == int_end;

        let Some(f) = f else {
            return match &mut self.walk {
                Some(w) => w.visitor.number(&data[start..self.cur.pos], integer),
                None => Ok(()),
            };
        };
        if f.ty() != T_INT || !integer {
            return Err(-EINVAL);
        }
        // An integer field takes the integer part alone, within __s64.
        let value = core::str::from_utf8(&data[start..int_end])
            .ok()
            .and_then(|text| text.parse::<i64>().ok())
            .ok_or(-EINVAL)?;
        f.set_int(value);
        f.set_seen(1);
        Ok(())
    }

    fn string(&mut self, f: Option<Field>) -> Result {
        match f {
            Some(f) if f.ty() != T_STRING => Err(-EINVAL),
            Some(f) => {
                self.cur.string(f.string_dst())?;
                f.set_seen(1);
                Ok(())
            }
            None => match &mut self.walk {
                Some(w) => {
                    self.cur.string(Some(&mut w.scratch))?;
                    w.visitor.string(decoded(&w.scratch)?)
                }
                None => self.cur.string(None).map(drop),
            },
        }
    }

    fn literal(&mut self, f: Option<Field>, text: &[u8], value: c_int) -> Result {
        self.cur.lit(text)?;
        match f {
            // Null is never dispatched, whatever the field's type.
            Some(_) if value < 0 => Ok(()),
            Some(f) if f.ty() != T_BOOL => Err(-EINVAL),
            Some(f) => {
                f.set_bool(value);
                f.set_seen(1);
                Ok(())
            }
            None => self.visit_literal(value),
        }
    }

    fn value(&mut self, f: Option<Field>) -> Result {
        self.cur.skip_ws();
        let Some(c) = self.cur.peek() else {
            return Err(-EINVAL);
        };

        match c {
            b'{' => match f {
                Some(f) if f.ty() == T_MAP => self.map(f),
                Some(f) if f.ty() != T_OBJECT => Err(-EINVAL),
                Some(f) => {
                    self.object_with(f.sub())?;
                    f.set_seen(1);
                    Ok(())
                }
                // A discarded object takes an empty schema, so that its
                // keys cannot dispatch into the enclosing one.
                None => self.object_with(Fields::NONE),
            },
            b'[' => match f {
                Some(f) if f.ty() != T_ARRAY => Err(-EINVAL),
                Some(f) => self.array_into(f),
                None => self.array(),
            },
            b'"' => self.string(f),
            b't' => self.literal(f, b"true", 1),
            b'f' => self.literal(f, b"false", 0),
            b'n' => self.literal(f, b"null", -1),
            _ => self.number(f),
        }
    }
}

fn parse(data: &[u8], fields: Fields) -> Result {
    if data.len() > MAX_BYTES {
        return Err(-E2BIG);
    }
    fields.reset_seen();

    let mut p = Parser {
        cur: Cursor { data, pos: 0 },
        depth: 0,
        fields,
        walk: None,
    };
    p.cur.skip_ws();
    if p.cur.peek() != Some(b'{') {
        return Err(-EINVAL);
    }
    p.object()?;
    p.cur.skip_ws();
    if p.cur.pos != data.len() {
        return Err(-EINVAL);
    }
    Ok(())
}

fn walk(data: &[u8], visitor: &mut dyn Visit) -> Result {
    let mut scratch = Vec::new();

    if data.len() > MAX_BYTES {
        return Err(-E2BIG);
    }
    // A decoded string is never longer than its encoding.
    scratch
        .try_reserve_exact(data.len() + 1)
        .map_err(|_| -ENOMEM)?;
    scratch.resize(data.len() + 1, 0);

    let mut p = Parser {
        cur: Cursor { data, pos: 0 },
        depth: 0,
        fields: Fields::NONE,
        walk: Some(Walk { visitor, scratch }),
    };
    p.value(None)?;
    p.cur.skip_ws();
    if p.cur.pos != data.len() {
        return Err(-EINVAL);
    }
    Ok(())
}

/// json_parse() for Rust code, on a schema of C layout.
///
/// # Safety
///
/// The `n` fields at `fields`, and the sub fields, destinations and
/// sinks they point to, are valid as json.h describes them, and nothing
/// but the sinks' callbacks touches them during the parse.
pub(crate) unsafe fn parse_schema(data: &[u8], fields: *mut JsonField, n: usize) -> c_int {
    errno(parse(data, Fields { ptr: fields, n }))
}

mod capi {
    use core::ffi::{CStr, c_char, c_int, c_void};

    use super::{Fields, JsonField, JsonVisitor, MAX_BYTES, Result, Visit, errno, status};
    use crate::errno::{E2BIG, EINVAL};
    use crate::ffi;

    /// A C visitor and the context its callbacks take.
    struct CVisitor {
        v: *const JsonVisitor,
        ctx: *mut c_void,
    }

    impl CVisitor {
        fn visitor(&self) -> &JsonVisitor {
            // SAFETY: json_walk()'s caller passes a valid visitor, which
            // stays valid for the walk.
            unsafe { &*self.v }
        }
    }

    impl Visit for CVisitor {
        fn open(&mut self, array: bool) -> Result {
            match self.visitor().open {
                // SAFETY: a callback of the visitor, with its context.
                Some(f) => status(unsafe { f(self.ctx, array) }),
                None => Ok(()),
            }
        }

        fn close(&mut self, array: bool) -> Result {
            match self.visitor().close {
                // SAFETY: a callback of the visitor, with its context.
                Some(f) => status(unsafe { f(self.ctx, array) }),
                None => Ok(()),
            }
        }

        fn key(&mut self, key: &CStr) -> Result {
            match self.visitor().key {
                // SAFETY: a callback of the visitor, with its context and
                // a C string it may not keep.
                Some(f) => status(unsafe { f(self.ctx, key.as_ptr()) }),
                None => Ok(()),
            }
        }

        fn string(&mut self, s: &CStr) -> Result {
            match self.visitor().string {
                // SAFETY: a callback of the visitor, with its context and
                // a C string it may not keep.
                Some(f) => status(unsafe { f(self.ctx, s.as_ptr()) }),
                None => Ok(()),
            }
        }

        fn number(&mut self, text: &[u8], integer: bool) -> Result {
            let Some(f) = self.visitor().number else {
                return Ok(());
            };

            // SAFETY: a callback of the visitor, with its context and the
            // text of the number in the caller's document.
            status(unsafe { f(self.ctx, text.as_ptr().cast(), text.len(), integer) })
        }

        fn literal(&mut self, value: c_int) -> Result {
            match self.visitor().literal {
                // SAFETY: a callback of the visitor, with its context.
                Some(f) => status(unsafe { f(self.ctx, value) }),
                None => Ok(()),
            }
        }
    }

    /// # Safety
    ///
    /// `data` holds `len` bytes, and `fields` holds `n_fields` fields of
    /// a valid schema, as json.h describes them.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_parse(
        data: *const c_char,
        len: usize,
        fields: *mut JsonField,
        n_fields: usize,
    ) -> c_int {
        if len > MAX_BYTES {
            return -E2BIG;
        }
        // SAFETY: the caller passes len bytes at data.
        let data = unsafe { ffi::slice(data.cast::<u8>(), len) };
        let fields = Fields {
            ptr: fields,
            n: n_fields,
        };

        errno(super::parse(data, fields))
    }

    /// # Safety
    ///
    /// `data` holds `len` bytes, and `v` is NULL or a valid visitor whose
    /// callbacks take `ctx`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_walk(
        data: *const c_char,
        len: usize,
        v: *const JsonVisitor,
        ctx: *mut c_void,
    ) -> c_int {
        if len > MAX_BYTES {
            return -E2BIG;
        }
        if v.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller passes len bytes at data.
        let data = unsafe { ffi::slice(data.cast::<u8>(), len) };

        errno(super::walk(data, &mut CVisitor { v, ctx }))
    }
}
