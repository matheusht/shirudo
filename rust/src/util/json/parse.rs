// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The JSON readers. parse_schema() dispatches the declared keys of a
//! schema into the state it is given and parses and discards the rest,
//! walk() reports every token, and both check a document through the one
//! grammar json.h describes, so that a single parser checks every
//! document shirudo reads.

use alloc::vec::Vec;
use core::cell::Cell;
use core::ffi::{CStr, c_int};
use core::slice;

use super::{MAX_BYTES, MAX_DEPTH, MAX_FIELDS, MAX_STRING_BYTES, utf8_width};
use crate::errno::{E2BIG, EINVAL, ENOSPC};

/// A negative errno, or the error a sink returned.
type Result<T = ()> = core::result::Result<T, c_int>;

/// What an array calls with the state after each element.
type OnElem<'a, S> = &'a dyn Fn(&mut S) -> Result;

/// What a map calls with the state and the key after each member.
type OnMember<'a, S> = &'a dyn Fn(&mut S, &CStr) -> Result;

/// Where a declared key's value goes: a place in the state for a
/// scalar; the fields of an object; the fields of each element of an
/// array, or the one field of each member's value of a map, with the
/// sink that takes each.
enum Value<'a, S> {
    String(fn(&mut S) -> &mut [u8]),
    Int(fn(&mut S) -> &mut i64),
    Bool(fn(&mut S) -> &mut bool),
    Object(&'a [JsonField<'a, S>]),
    Array(&'a [JsonField<'a, S>], OnElem<'a, S>),
    Map(&'a JsonField<'a, S>, OnMember<'a, S>),
}

impl<S> Clone for Value<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for Value<'_, S> {}

/// A declared key of a schema and where its value goes in the state of
/// type `S` that [`parse_schema`] fills.
pub(crate) struct JsonField<'a, S> {
    key: Option<&'static CStr>,
    value: Value<'a, S>,
    seen: Cell<bool>,
}

impl<'a, S> JsonField<'a, S> {
    const fn new(key: &'static CStr, value: Value<'a, S>) -> Self {
        JsonField {
            key: Some(key),
            value,
            seen: Cell::new(false),
        }
    }

    /// A string, decoded into the buffer `dst` gives with a NUL after it:
    /// -ENOSPC for one the buffer cannot hold with its NUL.
    pub(crate) const fn string(key: &'static CStr, dst: fn(&mut S) -> &mut [u8]) -> Self {
        Self::new(key, Value::String(dst))
    }

    pub(crate) const fn int(key: &'static CStr, dst: fn(&mut S) -> &mut i64) -> Self {
        Self::new(key, Value::Int(dst))
    }

    pub(crate) const fn boolean(key: &'static CStr, dst: fn(&mut S) -> &mut bool) -> Self {
        Self::new(key, Value::Bool(dst))
    }

    /// An object whose own declared keys are `fields`.
    pub(crate) const fn object(key: &'static CStr, fields: &'a [JsonField<'a, S>]) -> Self {
        Self::new(key, Value::Object(fields))
    }

    /// An array of objects with the declared keys `fields`, or of the
    /// values the one field of `fields` with an empty key takes, each of
    /// which `on_elem` takes from the state.
    pub(crate) const fn array(
        key: &'static CStr,
        fields: &'a [JsonField<'a, S>],
        on_elem: OnElem<'a, S>,
    ) -> Self {
        Self::new(key, Value::Array(fields, on_elem))
    }

    /// A map whose members' values `value` takes, each of which
    /// `on_member` takes from the state with its key.
    pub(crate) const fn map(
        key: &'static CStr,
        value: &'a JsonField<'a, S>,
        on_member: OnMember<'a, S>,
    ) -> Self {
        Self::new(key, Value::Map(value, on_member))
    }

    /// This field without its key, which no member of an object matches.
    pub(crate) const fn keyless(mut self) -> Self {
        self.key = None;
        self
    }

    /// Whether the document gave the field; for one an array or a map
    /// holds, the element or member last parsed.
    pub(crate) fn seen(&self) -> bool {
        self.seen.get()
    }

    fn is_named(&self, name: &[u8]) -> bool {
        self.key.is_some_and(|key| key.to_bytes() == name)
    }

    /// A field with no key, or an empty one, which takes each element of
    /// an array of scalars.
    fn is_unnamed(&self) -> bool {
        self.key.is_none_or(CStr::is_empty)
    }
}

/// Clears whether the document gave `fields`, and the fields they hold.
fn reset_seen<S>(fields: &[JsonField<'_, S>]) {
    for f in fields {
        f.seen.set(false);
        match f.value {
            Value::Object(sub) | Value::Array(sub, _) => reset_seen(sub),
            Value::Map(value, _) => reset_seen(slice::from_ref(value)),
            Value::String(_) | Value::Int(_) | Value::Bool(_) => {}
        }
    }
}

/// What a walk reports: decoded keys and strings, numbers as their text,
/// with `integer` set when it has no fraction or exponent, and literals
/// as 1 for true, 0 for false and -1 for null.
pub(crate) trait Visit {
    fn open(&mut self, array: bool) -> Result;
    fn close(&mut self, array: bool) -> Result;
    fn key(&mut self, key: &CStr) -> Result;
    fn string(&mut self, s: &CStr) -> Result;
    fn number(&mut self, text: &[u8], integer: bool) -> Result;
    fn literal(&mut self, value: c_int) -> Result;
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

struct Parser<'d, 'w, 'a, S> {
    cur: Cursor<'d>,
    depth: u32,
    fields: &'a [JsonField<'a, S>],
    state: &'w mut S,
    walk: Option<Walk<'w>>,
}

impl<'a, S> Parser<'_, '_, 'a, S> {
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
        let fields = self.fields;
        let mut buf = [0; 256];
        let mut named = 0u64;

        if fields.len() > MAX_FIELDS {
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

                    fields
                        .iter()
                        .enumerate()
                        .find(|(_, f)| f.is_named(&buf[..len]))
                }
            };
            self.cur.skip_ws();
            if self.cur.peek() != Some(b':') {
                return Err(-EINVAL);
            }
            self.cur.pos += 1;
            // Readers that take the first or the last would differ.
            if let Some((i, _)) = found {
                if named & (1 << i) != 0 {
                    return Err(-EINVAL);
                }
                named |= 1 << i;
            }
            self.value(found.map(|(_, f)| f))?;
            if self.cur.next_or_end(b'}')? {
                break;
            }
        }
        self.depth -= 1;
        self.visit_close(false)
    }

    /// An object with the schema `fields` in place of the current one.
    fn object_with(&mut self, fields: &'a [JsonField<'a, S>]) -> Result {
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

    fn array_into(
        &mut self,
        f: &JsonField<'a, S>,
        fields: &'a [JsonField<'a, S>],
        on_elem: OnElem<'a, S>,
    ) -> Result {
        self.enter()?;
        if self.empty(b']') {
            f.seen.set(true);
            return Ok(());
        }
        loop {
            reset_seen(fields);
            self.cur.skip_ws();
            let Some(c) = self.cur.peek() else {
                return Err(-EINVAL);
            };
            match fields {
                [scalar] if scalar.is_unnamed() => self.value(Some(scalar))?,
                _ if c == b'{' => self.object_with(fields)?,
                [] => self.value(None)?,
                // Not an object, as the fields ask.
                _ => return Err(-EINVAL),
            }
            on_elem(self.state)?;
            if self.cur.next_or_end(b']')? {
                break;
            }
        }
        self.depth -= 1;
        f.seen.set(true);
        Ok(())
    }

    fn map(
        &mut self,
        f: &JsonField<'a, S>,
        value: &'a JsonField<'a, S>,
        on_member: OnMember<'a, S>,
    ) -> Result {
        let mut key = [0; 256];

        self.enter()?;
        if self.empty(b'}') {
            f.seen.set(true);
            return Ok(());
        }
        loop {
            reset_seen(slice::from_ref(value));
            self.cur.skip_ws();
            self.cur.string(Some(&mut key))?;
            self.cur.skip_ws();
            if self.cur.peek() != Some(b':') {
                return Err(-EINVAL);
            }
            self.cur.pos += 1;
            self.value(Some(value))?;
            on_member(self.state, decoded(&key)?)?;
            if self.cur.next_or_end(b'}')? {
                break;
            }
        }
        self.depth -= 1;
        f.seen.set(true);
        Ok(())
    }

    fn number(&mut self, f: Option<&JsonField<'a, S>>) -> Result {
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
        let (Value::Int(dst), true) = (f.value, integer) else {
            return Err(-EINVAL);
        };
        // An integer field takes the integer part alone, within __s64.
        let value = core::str::from_utf8(&data[start..int_end])
            .ok()
            .and_then(|text| text.parse::<i64>().ok())
            .ok_or(-EINVAL)?;
        *dst(self.state) = value;
        f.seen.set(true);
        Ok(())
    }

    fn string(&mut self, f: Option<&JsonField<'a, S>>) -> Result {
        let Some(f) = f else {
            return match &mut self.walk {
                Some(w) => {
                    self.cur.string(Some(&mut w.scratch))?;
                    w.visitor.string(decoded(&w.scratch)?)
                }
                None => self.cur.string(None).map(drop),
            };
        };
        let Value::String(dst) = f.value else {
            return Err(-EINVAL);
        };
        self.cur.string(Some(dst(self.state)))?;
        f.seen.set(true);
        Ok(())
    }

    fn literal(&mut self, f: Option<&JsonField<'a, S>>, text: &[u8], value: c_int) -> Result {
        self.cur.lit(text)?;
        let Some(f) = f else {
            return self.visit_literal(value);
        };
        // Null is never dispatched, whatever the field's type.
        if value < 0 {
            return Ok(());
        }
        let Value::Bool(dst) = f.value else {
            return Err(-EINVAL);
        };
        *dst(self.state) = value != 0;
        f.seen.set(true);
        Ok(())
    }

    fn value(&mut self, f: Option<&'a JsonField<'a, S>>) -> Result {
        self.cur.skip_ws();
        let Some(c) = self.cur.peek() else {
            return Err(-EINVAL);
        };

        match c {
            b'{' => match f.map(|f| (f, f.value)) {
                Some((f, Value::Map(value, on_member))) => self.map(f, value, on_member),
                Some((f, Value::Object(fields))) => {
                    self.object_with(fields)?;
                    f.seen.set(true);
                    Ok(())
                }
                Some(_) => Err(-EINVAL),
                // A discarded object takes an empty schema, so that its
                // keys cannot dispatch into the enclosing one.
                None => self.object_with(&[]),
            },
            b'[' => match f.map(|f| (f, f.value)) {
                Some((f, Value::Array(fields, on_elem))) => self.array_into(f, fields, on_elem),
                Some(_) => Err(-EINVAL),
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

/// Parses the object `data` holds against the schema `fields`: each
/// value they declare into its place in `state`, and each element of an
/// array or member of a map to its sink, with the state, once parsed.
/// What `fields` do not declare is checked and discarded. A sink's error
/// ends the parse and is its result; the rest are negative errnos.
pub(crate) fn parse_schema<'a, S>(
    data: &[u8],
    fields: &'a [JsonField<'a, S>],
    state: &mut S,
) -> Result {
    if data.len() > MAX_BYTES {
        return Err(-E2BIG);
    }
    reset_seen(fields);

    let mut p = Parser {
        cur: Cursor { data, pos: 0 },
        depth: 0,
        fields,
        state,
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

#[cfg(any(test, shirudo_fuzz))]
pub(crate) fn walk(data: &[u8], visitor: &mut dyn Visit) -> Result {
    let mut scratch = Vec::new();

    if data.len() > MAX_BYTES {
        return Err(-E2BIG);
    }
    // A decoded string is never longer than its encoding.
    scratch
        .try_reserve_exact(data.len() + 1)
        .map_err(|_| -crate::errno::ENOMEM)?;
    scratch.resize(data.len() + 1, 0);

    let mut p = Parser {
        cur: Cursor { data, pos: 0 },
        depth: 0,
        fields: &[],
        state: &mut (),
        walk: Some(Walk { visitor, scratch }),
    };
    p.value(None)?;
    p.cur.skip_ws();
    if p.cur.pos != data.len() {
        return Err(-EINVAL);
    }
    Ok(())
}
