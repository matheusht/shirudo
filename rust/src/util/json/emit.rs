// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The JSON emitter. Commas and escaping are automatic; the first error
//! latches in `err`, after which every call does nothing, so a caller
//! checks it once after the final close.

use core::ffi::{c_char, c_int};

use super::{EMIT_MAX_DEPTH, utf8_width};
use crate::errno::{E2BIG, EILSEQ, ENOMEM, ENOSPC};
use crate::heap::xreallocarray;

/// `struct json_emit`, which C callers set up and read. `buf` and `cap`
/// are the caller's, or with `max` set the emitter's: it grows `buf`,
/// which the caller frees with `xfree(buf, cap)`.
#[repr(C)]
pub struct JsonEmit {
    buf: *mut c_char,
    cap: usize,
    len: usize,
    max: usize,
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

impl JsonEmit {
    /// An emitter into the `cap` bytes at `buf`, which it does not grow,
    /// as a C caller sets one up.
    pub(crate) fn fixed(buf: *mut c_char, cap: usize) -> Self {
        JsonEmit {
            buf,
            cap,
            len: 0,
            max: 0,
            err: 0,
            depth: 0,
            nonempty: [0; EMIT_MAX_DEPTH as usize / 64],
            value_pending: false,
        }
    }

    /// An emitter that grows its own buffer up to `max` bytes, as a C
    /// caller sets one up with only `max`; parts() hands the buffer over
    /// for `xfree(buf, cap)`.
    pub(crate) fn growing(max: usize) -> Self {
        JsonEmit {
            buf: core::ptr::null_mut(),
            cap: 0,
            len: 0,
            max,
            err: 0,
            depth: 0,
            nonempty: [0; EMIT_MAX_DEPTH as usize / 64],
            value_pending: false,
        }
    }

    /// The buffer, its capacity and the bytes written into it.
    pub(crate) fn parts(&self) -> (*mut c_char, usize, usize) {
        (self.buf, self.cap, self.len)
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

    fn grow(&mut self) -> bool {
        let cap = if self.cap != 0 {
            self.cap.saturating_mul(2)
        } else {
            4096
        };

        if self.max == 0 || self.cap >= self.max {
            self.err = if self.max != 0 { -E2BIG } else { -ENOSPC };
            return false;
        }
        let cap = cap.min(self.max);
        // put() writes a byte and the NUL behind it.
        if cap <= self.len + 1 {
            self.err = -E2BIG;
            return false;
        }
        // SAFETY: with max set, buf is NULL or the cap bytes the xmalloc
        // family gave, as json.h asks, and a failed call leaves it alone.
        let buf = unsafe { xreallocarray(self.buf.cast(), self.cap, cap, 1) };
        if buf.is_null() {
            self.err = -ENOMEM;
            return false;
        }
        self.buf = buf.cast();
        self.cap = cap;
        true
    }

    fn put(&mut self, c: u8) {
        if self.err != 0 {
            return;
        }
        if self.len + 1 >= self.cap && !self.grow() {
            return;
        }
        // SAFETY: buf holds cap bytes, and len + 1 < cap.
        unsafe {
            self.buf.add(self.len).write(c as c_char);
            self.buf.add(self.len + 1).write(0);
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
