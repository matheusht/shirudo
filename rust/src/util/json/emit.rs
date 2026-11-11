// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The JSON emitter. Commas and escaping are automatic; the first error
//! latches in `err`, after which every call does nothing, so a caller
//! checks it once after the final close.

use core::ffi::{c_char, c_int};

use super::{EMIT_MAX_DEPTH, utf8_width};
use crate::errno::{E2BIG, EILSEQ, ENOMEM, ENOSPC};
use crate::sys::malloc::xreallocarray;

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
fn format_s64(v: i64, buf: &mut [u8; 20]) -> &[u8] {
    let mut pos = buf.len();
    let mut n = v.unsigned_abs();

    loop {
        pos -= 1;
        buf[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if v < 0 {
        pos -= 1;
        buf[pos] = b'-';
    }
    &buf[pos..]
}

/// The decimal digits of a full unsigned 64-bit value.
fn format_u64(mut n: u64, buf: &mut [u8; 20]) -> &[u8] {
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

    fn obj_value_open(&mut self) {
        self.value_begin();
        self.put(b'{');
        self.enter();
    }

    pub(crate) fn obj_close(&mut self) {
        self.put(b'}');
        self.leave();
    }

    fn arr_open(&mut self, key: &[u8]) {
        self.member(key);
        self.put(b'[');
        self.enter();
    }

    fn arr_open_value(&mut self) {
        self.value_begin();
        self.put(b'[');
        self.enter();
    }

    fn arr_close(&mut self) {
        self.put(b']');
        self.leave();
    }

    fn key(&mut self, key: &[u8]) {
        self.member(key);
        self.value_pending = true;
    }

    pub(crate) fn kv_string(&mut self, key: &[u8], val: &[u8]) {
        self.member(key);
        self.put_string(val, false);
    }

    pub(crate) fn kv_int(&mut self, key: &[u8], val: i64) {
        let mut buf = [0; 20];
        let digits = format_s64(val, &mut buf);

        self.member(key);
        self.put_raw(digits);
    }

    fn u64_value(&mut self, val: u64) {
        let mut buf = [0; 20];
        let digits = format_u64(val, &mut buf);
        self.raw_value(digits);
    }

    fn kv_bool(&mut self, key: &[u8], val: bool) {
        self.member(key);
        self.put_raw(if val { b"true" } else { b"false" });
    }

    fn kv_null(&mut self, key: &[u8]) {
        self.member(key);
        self.put_raw(b"null");
    }

    fn kv_raw(&mut self, key: &[u8], value: &[u8]) {
        self.member(key);
        self.put_raw(value);
    }

    fn str(&mut self, val: &[u8]) {
        self.sep();
        self.put_string(val, false);
    }

    fn str_value(&mut self, val: &[u8]) {
        self.value_begin();
        self.put_string(val, false);
    }

    fn raw_value(&mut self, value: &[u8]) {
        self.value_begin();
        self.put_raw(value);
    }

    fn raw(&mut self, value: &[u8]) {
        self.sep();
        self.put_raw(value);
    }

    fn str_lossy(&mut self, s: &[u8]) {
        self.value_begin();
        self.put_string(s, true);
    }

    fn key_lossy(&mut self, s: &[u8]) {
        self.sep();
        self.put_string(s, true);
        self.put(b':');
        self.value_pending = true;
    }
}

mod capi {
    use core::ffi::{c_char, c_int};

    use super::JsonEmit;
    use crate::ffi;

    /// The emitter `e` a C caller lends for one call.
    ///
    /// # Safety
    ///
    /// `e` points to a `struct json_emit` that nothing else accesses for
    /// `'a`, with a `buf` as json.h describes it.
    unsafe fn emitter<'a>(e: *mut JsonEmit) -> &'a mut JsonEmit {
        // SAFETY: the caller lends a valid emitter it does not touch.
        unsafe { &mut *e }
    }

    /// # Safety
    ///
    /// `e` is a valid emitter.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_obj_open(e: *mut JsonEmit) {
        // SAFETY: the caller passes a valid emitter.
        unsafe { emitter(e) }.obj_open();
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `key` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_obj_open_key(e: *mut JsonEmit, key: *const c_char) {
        // SAFETY: the caller passes a valid emitter and a C string.
        unsafe { emitter(e).obj_open_key(ffi::c_str(key)) };
    }

    /// # Safety
    ///
    /// `e` is a valid emitter.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_obj_value_open(e: *mut JsonEmit) {
        // SAFETY: the caller passes a valid emitter.
        unsafe { emitter(e) }.obj_value_open();
    }

    /// # Safety
    ///
    /// `e` is a valid emitter.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_obj_close(e: *mut JsonEmit) {
        // SAFETY: the caller passes a valid emitter.
        unsafe { emitter(e) }.obj_close();
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `key` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_arr_open(e: *mut JsonEmit, key: *const c_char) {
        // SAFETY: the caller passes a valid emitter and a C string.
        unsafe { emitter(e).arr_open(ffi::c_str(key)) };
    }

    /// # Safety
    ///
    /// `e` is a valid emitter.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_arr_open_value(e: *mut JsonEmit) {
        // SAFETY: the caller passes a valid emitter.
        unsafe { emitter(e) }.arr_open_value();
    }

    /// # Safety
    ///
    /// `e` is a valid emitter.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_arr_close(e: *mut JsonEmit) {
        // SAFETY: the caller passes a valid emitter.
        unsafe { emitter(e) }.arr_close();
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `key` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_key(e: *mut JsonEmit, key: *const c_char) {
        // SAFETY: the caller passes a valid emitter and a C string.
        unsafe { emitter(e).key(ffi::c_str(key)) };
    }

    /// # Safety
    ///
    /// `e` is a valid emitter, and `key` and `val` are C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_kv_string(
        e: *mut JsonEmit,
        key: *const c_char,
        val: *const c_char,
    ) {
        // SAFETY: the caller passes a valid emitter and two C strings.
        unsafe { emitter(e).kv_string(ffi::c_str(key), ffi::c_str(val)) };
    }

    /// # Safety
    ///
    /// e is a valid emitter, key a C string, and val holds len bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_kv_string_n(
        e: *mut JsonEmit,
        key: *const c_char,
        val: *const c_char,
        len: usize,
    ) {
        // SAFETY: the caller lends a valid emitter.
        let e = unsafe { emitter(e) };
        // SAFETY: the caller passes a C string.
        let key = unsafe { ffi::c_str(key) };
        // SAFETY: the caller passes len bytes at val.
        let val = unsafe { ffi::slice(val.cast(), len) };
        e.kv_string(key, val);
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `key` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_kv_int(e: *mut JsonEmit, key: *const c_char, val: i64) {
        // SAFETY: the caller passes a valid emitter and a C string.
        unsafe { emitter(e).kv_int(ffi::c_str(key), val) };
    }

    /// # Safety
    ///
    /// e is a valid emitter.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_u64_value(e: *mut JsonEmit, val: u64) {
        // SAFETY: the caller lends a valid emitter.
        unsafe { emitter(e) }.u64_value(val);
    }

    /// # Safety
    ///
    /// e is a valid emitter and key a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_kv_u64(e: *mut JsonEmit, key: *const c_char, val: u64) {
        // SAFETY: the caller lends a valid emitter.
        let e = unsafe { emitter(e) };
        // SAFETY: the caller passes a C string.
        let key = unsafe { ffi::c_str(key) };
        e.key(key);
        e.u64_value(val);
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `key` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_kv_bool(e: *mut JsonEmit, key: *const c_char, val: c_int) {
        // SAFETY: the caller passes a valid emitter and a C string.
        unsafe { emitter(e).kv_bool(ffi::c_str(key), val != 0) };
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `key` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_kv_null(e: *mut JsonEmit, key: *const c_char) {
        // SAFETY: the caller passes a valid emitter and a C string.
        unsafe { emitter(e).kv_null(ffi::c_str(key)) };
    }

    /// # Safety
    ///
    /// `e` is a valid emitter, `key` a C string and `value` holds
    /// `value_len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_kv_raw(
        e: *mut JsonEmit,
        key: *const c_char,
        value: *const c_char,
        value_len: usize,
    ) {
        // SAFETY: the caller passes a valid emitter, a C string and
        // value_len bytes at value.
        unsafe {
            emitter(e).kv_raw(ffi::c_str(key), ffi::slice(value.cast(), value_len));
        }
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `val` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_str(e: *mut JsonEmit, val: *const c_char) {
        // SAFETY: the caller passes a valid emitter and a C string.
        unsafe { emitter(e).str(ffi::c_str(val)) };
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `val` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_str_value(e: *mut JsonEmit, val: *const c_char) {
        // SAFETY: the caller passes a valid emitter and a C string.
        unsafe { emitter(e).str_value(ffi::c_str(val)) };
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `value` holds `value_len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_raw_value(
        e: *mut JsonEmit,
        value: *const c_char,
        value_len: usize,
    ) {
        // SAFETY: the caller passes a valid emitter and value_len bytes.
        unsafe { emitter(e).raw_value(ffi::slice(value.cast(), value_len)) };
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `value` holds `value_len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_raw(e: *mut JsonEmit, value: *const c_char, value_len: usize) {
        // SAFETY: the caller passes a valid emitter and value_len bytes.
        unsafe { emitter(e).raw(ffi::slice(value.cast(), value_len)) };
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `s` holds `n` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_str_lossy(e: *mut JsonEmit, s: *const c_char, n: usize) {
        // SAFETY: the caller passes a valid emitter and n bytes at s.
        unsafe { emitter(e).str_lossy(ffi::slice(s.cast(), n)) };
    }

    /// # Safety
    ///
    /// e is a valid emitter, and key and val are C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_kv_string_lossy(
        e: *mut JsonEmit,
        key: *const c_char,
        val: *const c_char,
    ) {
        // SAFETY: the caller lends a valid emitter.
        let e = unsafe { emitter(e) };
        // SAFETY: the caller passes a C string.
        let key = unsafe { ffi::c_str(key) };
        // SAFETY: the caller passes a C string.
        let val = unsafe { ffi::c_str(val) };
        e.key(key);
        e.str_lossy(val);
    }

    /// # Safety
    ///
    /// `e` is a valid emitter and `s` holds `n` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn json_key_lossy(e: *mut JsonEmit, s: *const c_char, n: usize) {
        // SAFETY: the caller passes a valid emitter and n bytes at s.
        unsafe { emitter(e).key_lossy(ffi::slice(s.cast(), n)) };
    }
}
