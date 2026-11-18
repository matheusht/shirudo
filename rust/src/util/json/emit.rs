// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The JSON emitter. Commas and escaping are automatic; the first error
//! latches in `err`, after which every call does nothing, so a caller
//! checks it once after the final close.

use core::ffi::{c_char, c_int};

use super::{EMIT_MAX_DEPTH, utf8_width};
use crate::errno::{E2BIG, EILSEQ, ENOMEM, ENOSPC};

/// Where an emitter writes: a caller's buffer, which it does not grow
/// and keeps NUL-terminated, or its own, which grows while the document
/// and a NUL would fit in `max` bytes.
enum Room<'a> {
    Fixed(&'a mut [u8]),
    Growing { buf: Vec<u8>, max: usize },
}

/// A JSON document being written.
pub struct JsonEmit<'a> {
    room: Room<'a>,
    len: usize,
    err: c_int,
    depth: u32,
    nonempty: [u64; EMIT_MAX_DEPTH as usize / 64],
    value_pending: bool,
}

/// The `\u00XX` escape of a control character.
fn control_escape(c: u8) -> [u8; 6] {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    [
        b'\\',
        b'u',
        b'0',
        b'0',
        HEX[usize::from(c >> 4)],
        HEX[usize::from(c & 0xf)],
    ]
}

/// The decimal digits of `v`, as `%lld` writes them, at the end of `buf`.
/// The decimal digits of `n`, at the end of `buf`, one byte left
/// before them for a sign.
fn format_u64(mut n: u64, buf: &mut [u8; 21]) -> usize {
    let mut pos = buf.len();

    loop {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            return pos;
        }
    }
}

fn format_s64(v: i64, buf: &mut [u8; 21]) -> &[u8] {
    let mut pos = format_u64(v.unsigned_abs(), buf);

    if v < 0 {
        pos -= 1;
        buf[pos] = b'-';
    }
    &buf[pos..]
}

/// The decimal digits of a full unsigned 64-bit value.
fn format_u64_full(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
    let mut pos = buf.len();

    loop {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    &buf[pos..]
}

impl<'a> JsonEmit<'a> {
    fn new(room: Room<'a>) -> Self {
        JsonEmit {
            room,
            len: 0,
            err: 0,
            depth: 0,
            nonempty: [0; EMIT_MAX_DEPTH as usize / 64],
            value_pending: false,
        }
    }

    /// An emitter into `buf`, which it does not grow.
    pub(crate) fn fixed(buf: &'a mut [u8]) -> Self {
        Self::new(Room::Fixed(buf))
    }

    /// An emitter into the `cap` bytes at `buf`, which it does not grow,
    /// as a C-shaped caller hands one over.
    ///
    /// # Safety
    ///
    /// `buf` is valid for writes of `cap` bytes for as long as the
    /// emitter lives, and nothing else reads or writes them meanwhile.
    pub(crate) unsafe fn fixed_raw(buf: *mut c_char, cap: usize) -> Self {
        if buf.is_null() || cap == 0 {
            return Self::fixed(&mut []);
        }
        // SAFETY: the caller's cap bytes, lent to the emitter alone.
        Self::fixed(unsafe { core::slice::from_raw_parts_mut(buf.cast::<u8>(), cap) })
    }

    /// An emitter that grows its own buffer while the document and a NUL
    /// would fit in `max` bytes.
    pub(crate) fn growing(max: usize) -> Self {
        Self::new(Room::Growing {
            buf: Vec::new(),
            max,
        })
    }

    /// What the emitter has written.
    pub(crate) fn output(&self) -> &[u8] {
        match &self.room {
            Room::Fixed(buf) => &buf[..self.len],
            Room::Growing { buf, .. } => buf,
        }
    }

    /// The bytes the emitter holds, written or not.
    #[cfg(test)]
    pub(crate) fn allocated(&self) -> usize {
        match &self.room {
            Room::Fixed(buf) => buf.len(),
            Room::Growing { buf, .. } => buf.capacity(),
        }
    }

    /// The document, or the first error.
    pub(crate) fn finish(self) -> Result<Vec<u8>, c_int> {
        if self.err != 0 {
            return Err(self.err);
        }
        Ok(match self.room {
            Room::Fixed(buf) => buf[..self.len].to_vec(),
            Room::Growing { buf, .. } => buf,
        })
    }

    /// How many containers are open.
    pub(crate) fn depth(&self) -> u32 {
        self.depth
    }

    /// The first error, which stopped the emitter, or 0.
    pub(crate) fn err(&self) -> c_int {
        self.err
    }

    /// Stop the emitter with `err`, over any error before it, as a C
    /// caller's `e->err = err` does.
    pub(crate) fn set_err(&mut self, err: c_int) {
        self.err = err;
    }

    /// The bytes written so far, before the NUL that ends them.
    pub(crate) fn written(&self) -> usize {
        self.len
    }

    fn put(&mut self, c: u8) {
        if self.err != 0 {
            return;
        }
        match &mut self.room {
            Room::Fixed(buf) => match buf.get_mut(self.len..self.len + 2) {
                Some(at) => {
                    at[0] = c;
                    at[1] = 0;
                }
                None => {
                    self.err = -ENOSPC;
                    return;
                }
            },
            Room::Growing { buf, max } => {
                if self.len + 1 >= *max {
                    self.err = -E2BIG;
                    return;
                }
                // Doubling from 4 KiB, as the C did, and never past max.
                if buf.len() == buf.capacity() {
                    let cap = buf.capacity().saturating_mul(2).max(4096).min(*max);
                    if buf.try_reserve_exact(cap - buf.len()).is_err() {
                        self.err = -ENOMEM;
                        return;
                    }
                }
                buf.push(c);
            }
        }
        self.len += 1;
    }

    fn put_raw(&mut self, s: &[u8]) {
        for &c in s {
            if self.err != 0 {
                break;
            }
            self.put(c);
        }
    }

    /// Malformed UTF-8 is -EILSEQ, so a stray byte can never produce
    /// invalid JSON; lossy writes U+FFFD for it, and for a NUL, instead.
    fn put_string(&mut self, s: &[u8], lossy: bool) {
        let mut i = 0;

        self.put(b'"');
        while i < s.len() && self.err == 0 {
            let c = s[i];

            match c {
                b'"' | b'\\' => {
                    self.put(b'\\');
                    self.put(c);
                }
                b'\n' => self.put_raw(b"\\n"),
                b'\r' => self.put_raw(b"\\r"),
                b'\t' => self.put_raw(b"\\t"),
                0x01..=0x1f => self.put_raw(&control_escape(c)),
                0x20..=0x7f => self.put(c),
                _ => {
                    let width = if c != 0 {
                        utf8_width(&s[i..s.len().min(i + 4)])
                    } else {
                        0
                    };

                    if width == 0 {
                        if !lossy {
                            self.err = -EILSEQ;
                            return;
                        }
                        self.put_raw(b"\\ufffd");
                    } else {
                        for &b in &s[i..i + width] {
                            self.put(b);
                        }
                        i += width;
                        continue;
                    }
                }
            }
            i += 1;
        }
        self.put(b'"');
    }

    fn sep(&mut self) {
        let bit = 1u64 << (self.depth % 64);
        let word = (self.depth / 64) as usize;

        if self.err != 0 {
            return;
        }
        if self.nonempty[word] & bit != 0 {
            self.put(b',');
        } else {
            self.nonempty[word] |= bit;
        }
    }

    fn enter(&mut self) {
        if self.err != 0 {
            return;
        }
        if self.depth + 1 >= EMIT_MAX_DEPTH {
            self.err = -E2BIG;
            return;
        }
        self.depth += 1;
        self.nonempty[(self.depth / 64) as usize] &= !(1u64 << (self.depth % 64));
    }

    fn leave(&mut self) {
        if self.depth != 0 {
            self.depth -= 1;
        }
    }

    fn value_begin(&mut self) {
        if self.value_pending {
            self.value_pending = false;
        } else {
            self.sep();
        }
    }

    fn member(&mut self, key: &[u8]) {
        self.sep();
        self.put_string(key, false);
        self.put(b':');
    }

    pub(crate) fn obj_open(&mut self) {
        self.sep();
        self.put(b'{');
        self.enter();
    }

    pub(crate) fn obj_open_key(&mut self, key: &[u8]) {
        self.member(key);
        self.put(b'{');
        self.enter();
    }

    pub(crate) fn obj_value_open(&mut self) {
        self.value_begin();
        self.put(b'{');
        self.enter();
    }

    pub(crate) fn obj_close(&mut self) {
        self.put(b'}');
        self.leave();
    }

    pub(crate) fn arr_open(&mut self, key: &[u8]) {
        self.member(key);
        self.put(b'[');
        self.enter();
    }

    pub(crate) fn arr_open_value(&mut self) {
        self.value_begin();
        self.put(b'[');
        self.enter();
    }

    pub(crate) fn arr_close(&mut self) {
        self.put(b']');
        self.leave();
    }

    pub(crate) fn key(&mut self, key: &[u8]) {
        self.member(key);
        self.value_pending = true;
    }

    pub(crate) fn kv_string(&mut self, key: &[u8], val: &[u8]) {
        self.member(key);
        self.put_string(val, false);
    }

    pub(crate) fn kv_int(&mut self, key: &[u8], val: i64) {
        let mut buf = [0; 21];
        let digits = format_s64(val, &mut buf);

        self.member(key);
        self.put_raw(digits);
    }

    pub(crate) fn u64_value(&mut self, val: u64) {
        let mut buf = [0; 20];
        let digits = format_u64_full(val, &mut buf);
        self.raw_value(digits);
    }

    pub(crate) fn kv_u64(&mut self, key: &[u8], val: u64) {
        self.key(key);
        self.u64_value(val);
    }

    pub(crate) fn kv_bool(&mut self, key: &[u8], val: bool) {
        self.member(key);
        self.put_raw(if val { b"true" } else { b"false" });
    }

    pub(crate) fn kv_null(&mut self, key: &[u8]) {
        self.member(key);
        self.put_raw(b"null");
    }

    pub(crate) fn kv_raw(&mut self, key: &[u8], value: &[u8]) {
        self.member(key);
        self.put_raw(value);
    }

    pub(crate) fn str(&mut self, val: &[u8]) {
        self.sep();
        self.put_string(val, false);
    }

    pub(crate) fn str_value(&mut self, val: &[u8]) {
        self.value_begin();
        self.put_string(val, false);
    }

    pub(crate) fn raw_value(&mut self, value: &[u8]) {
        self.value_begin();
        self.put_raw(value);
    }

    pub(crate) fn raw(&mut self, value: &[u8]) {
        self.sep();
        self.put_raw(value);
    }

    pub(crate) fn str_lossy(&mut self, s: &[u8]) {
        self.value_begin();
        self.put_string(s, true);
    }

    pub(crate) fn key_lossy(&mut self, s: &[u8]) {
        self.sep();
        self.put_string(s, true);
        self.put(b':');
        self.value_pending = true;
    }
}
