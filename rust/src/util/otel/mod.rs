// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The OpenTelemetry export of shirudo: a BPF map as an OTLP log or as
//! the metrics its signed decoder makes of it, a map too large for OTLP
//! as a snapshot in S3 that a log points at, and the status keepalive,
//! sent over OTLP/HTTP JSON with the OTEL_EXPORTER_OTLP_* settings.

mod http;
mod otlp;
mod s3;

use core::ffi::{CStr, c_char, c_int};

use crate::errno::{E2BIG, EINVAL, ENODATA, EOPNOTSUPP};
use crate::sys::btf::{
    BtfType, KIND_INT, KIND_TYPEDEF, btf__type_by_id, int_bits, int_encoding, int_offset,
};
use crate::sys::libc::{fwrite, stderr};
use crate::sys::malloc::{xfree, xmalloc};
use crate::sys::upatch_maps::{MapView, upatch_map_is_percpu};
use crate::util::json::JsonEmit;

/// `enum otel_signal`, the values of SHIRUDO_UPATCH_DECODER_EXPORT_*.
pub(crate) const LOG: c_int = 1;
pub(crate) const METRIC: c_int = 2;

/// `enum otel_mode`.
const AUTO: c_int = 0;
const FORCE_LOG: c_int = 1;
const FORCE_METRIC: c_int = 2;
const S3: c_int = 3;

/// The deepest a BTF type's typedefs and modifiers are followed.
const MAX_TYPE_UNWRAP: usize = 32;

/// `struct otel_opts`: where and how to export, NULL strings for none.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OtelOpts {
    pub endpoint: *const c_char,
    pub tenant_id: *const c_char,
    pub s3_uri: *const c_char,
    pub allow_insecure: bool,
    pub retries: u32,
    pub log_record_max_bytes: u32,
    pub otlp_max_bytes: u32,
}

const _: () = assert!(size_of::<OtelOpts>() == 40);

impl OtelOpts {
    /// What a caller without options gets: 3 retries.
    const fn defaults() -> Self {
        OtelOpts {
            endpoint: core::ptr::null(),
            tenant_id: core::ptr::null(),
            s3_uri: core::ptr::null(),
            allow_insecure: false,
            retries: 3,
            log_record_max_bytes: 0,
            otlp_max_bytes: 0,
        }
    }

    fn endpoint(&self) -> Option<&CStr> {
        opt_cstr(self.endpoint)
    }

    fn tenant_id(&self) -> Option<&CStr> {
        opt_cstr(self.tenant_id)
    }

    fn s3_uri(&self) -> Option<&CStr> {
        opt_cstr(self.s3_uri)
    }
}

fn opt_cstr<'a>(p: *const c_char) -> Option<&'a CStr> {
    // SAFETY: the options' strings outlive the export.
    (!p.is_null()).then(|| unsafe { CStr::from_ptr(p) })
}

/// A C string the maps code holds, empty for NULL.
fn cstr_or_empty<'a>(p: *const c_char) -> &'a [u8] {
    opt_cstr(p).map_or(&[], CStr::to_bytes)
}

/// isspace() of the C locale, `\v` and `\f` with the rest.
fn is_c_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

fn hex_lower(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

/// A diagnostic to the C library's stderr, as the rest of the command
/// writes them.
fn eprint(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stderr.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stderr) };
}

/// A document in an xmalloc() buffer of `cap` bytes, `len` of them
/// written, freed when it goes unless handed to C.
struct Buffer {
    ptr: *mut u8,
    cap: usize,
    len: usize,
}

impl Buffer {
    fn alloc(cap: usize) -> Option<Self> {
        // SAFETY: an allocation of cap bytes.
        let ptr = unsafe { xmalloc(cap) }.cast::<u8>();
        (!ptr.is_null()).then_some(Buffer { ptr, cap, len: 0 })
    }

    /// The buffer a growing emitter made.
    fn from_emitter(e: &JsonEmit) -> Self {
        let (ptr, cap, len) = e.parts();
        Buffer {
            ptr: ptr.cast(),
            cap,
            len,
        }
    }

    fn bytes(&self) -> &[u8] {
        if self.ptr.is_null() {
            return &[];
        }
        // SAFETY: the len bytes written.
        unsafe { crate::ffi::slice(self.ptr, self.len) }
    }

    /// The buffer, its length, for C to xfree() with the size it knows.
    fn into_raw(self) -> (*mut u8, usize) {
        let out = (self.ptr, self.len);
        core::mem::forget(self);
        out
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: the allocation, freed once with its size.
            unsafe { xfree(self.ptr.cast(), self.cap) };
        }
    }
}

/// What a decoder returned: `len` bytes and a NUL, freed when it goes.
struct Decoded {
    ptr: *mut c_char,
    len: usize,
}

impl Decoded {
    fn bytes(&self) -> &[u8] {
        if self.ptr.is_null() {
            return &[];
        }
        // SAFETY: the decoder's len bytes.
        unsafe { crate::ffi::slice(self.ptr.cast::<u8>(), self.len) }
    }
}

impl Drop for Decoded {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: the decoder's allocation, freed once with its size.
            unsafe { xfree(self.ptr.cast(), self.len + 1) };
        }
    }
}

/// The value's BTF type with its typedefs and modifiers followed.
fn unwrap_btf_type(v: &MapView, mut id: u32) -> Option<&BtfType> {
    for _ in 0..MAX_TYPE_UNWRAP {
        // SAFETY: the view's BTF.
        let t = unsafe { btf__type_by_id(v.btf, id) };
        if t.is_null() {
            return None;
        }
        // SAFETY: a type of the BTF, which the view holds.
        let t = unsafe { &*t };
        if t.kind() != KIND_TYPEDEF && !t.is_mod() {
            return Some(t);
        }
        id = t.size_type;
    }
    None
}

/// Whether the map's value is an integer scalar of 1, 2, 4 or 8 bytes,
/// and signed: -ENODATA without BTF, -EOPNOTSUPP for another value.
fn metric_type(v: &MapView) -> Result<(bool, u32), c_int> {
    if v.btf.is_null() || v.value_type_id == 0 {
        return Err(-ENODATA);
    }
    let t = unwrap_btf_type(v, v.value_type_id).ok_or(-EOPNOTSUPP)?;
    if t.kind() != KIND_INT || t.size_type != v.value_size || !matches!(t.size_type, 1 | 2 | 4 | 8)
    {
        return Err(-EOPNOTSUPP);
    }
    // SAFETY: an integer type of the BTF, followed by its encoding.
    let (offset, bits, enc) = unsafe { (int_offset(t), int_bits(t), int_encoding(t)) };
    if offset != 0 || u32::from(bits) != t.size_type * 8 {
        return Err(-EOPNOTSUPP);
    }
    Ok((enc & crate::sys::btf::INT_SIGNED != 0, t.size_type))
}

/// The signal a map exports as without a decoder: a metric only for an
/// unsigned per-CPU integer, which sums across CPUs, else a log; and
/// why.
fn classify(v: &MapView) -> (c_int, String) {
    if v.serialized {
        return (LOG, "map uses a serializer".into());
    }
    if v.skipped {
        return (LOG, "map type is not generically readable".into());
    }
    // SAFETY: the view's map type.
    if !unsafe { upatch_map_is_percpu(v.ty) } {
        return (LOG, "map is not per-CPU".into());
    }
    match metric_type(v) {
        Err(_) => (LOG, "value is not a BTF integer scalar".into()),
        Ok((true, _)) => (LOG, "value is signed".into()),
        Ok((false, width)) => (METRIC, format!("unsigned per-CPU {}-bit scalar", width * 8)),
    }
}

/// Exports the map as `mode` says, through the decoder at `decoder_path`
/// or the upatch's.
fn send_file(
    decoder_path: Option<&CStr>,
    v: &MapView,
    mode: c_int,
    opts: Option<&OtelOpts>,
) -> c_int {
    if mode == S3 {
        let Some(uri) = opts.and_then(OtelOpts::s3_uri) else {
            return -EINVAL;
        };
        return s3::send(uri, v, opts, decoder_path);
    }
    let signal = match mode {
        FORCE_METRIC => METRIC,
        FORCE_LOG | AUTO => LOG,
        _ => return -EINVAL,
    };
    let endpoint = opts.and_then(OtelOpts::endpoint);
    match http::open_for_map(endpoint, v, opts, mode == AUTO, signal, decoder_path) {
        Ok(mut t) => t.emit(v),
        Err(err) => err,
    }
}

/// Exports the map as a log or metric, as its shape suggests.
pub(crate) fn send_auto(v: &MapView, opts: Option<&OtelOpts>) -> c_int {
    send_file(None, v, AUTO, opts)
}

/// Exports the map as its decoder's signed signal selection says, and a
/// log too large for OTLP as a snapshot in S3 when there is a bucket.
pub(crate) fn send_decoded(v: &MapView, signal: c_int, opts: Option<&OtelOpts>) -> c_int {
    let mode = match signal {
        LOG => FORCE_LOG,
        METRIC => FORCE_METRIC,
        _ => return -EINVAL,
    };
    let ret = send_file(None, v, mode, opts);
    if ret == -E2BIG && opts.and_then(OtelOpts::s3_uri).is_some() {
        return send_file(None, v, S3, opts);
    }
    ret
}

/// The OTLP severity of a status verdict, and its text.
fn status_severity(status: &[u8]) -> (c_int, &'static CStr) {
    match status {
        b"ok" => (9, c"INFO"),
        b"degraded" | b"init-pending" | b"reboot-pending" => (13, c"WARN"),
        _ => (17, c"ERROR"),
    }
}

mod capi {
    use core::ffi::{CStr, c_char, c_int};

    use super::{OtelOpts, http, otlp};
    use crate::sys::curl::CurlSlist;
    use crate::sys::upatch_maps::MapView;
    use crate::util::json::JsonEmit;

    fn opts<'a>(p: *const OtelOpts) -> Option<&'a OtelOpts> {
        // SAFETY: the caller's options, or NULL.
        unsafe { p.as_ref() }
    }

    fn path<'a>(p: *const c_char) -> Option<&'a CStr> {
        super::opt_cstr(p)
    }

    /// The signal of [`super::classify`] into `signal`, and why into the
    /// `reason_sz` bytes at `reason`: 0, -EINVAL, or -E2BIG when the
    /// reason for a metric does not fit.
    ///
    /// # Safety
    ///
    /// `v` is a view, `signal` room for one and `reason` for `reason_sz`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_maps_otel_classify(
        v: *const MapView,
        signal: *mut c_int,
        reason: *mut c_char,
        reason_sz: usize,
    ) -> c_int {
        if v.is_null() || signal.is_null() {
            return -crate::errno::EINVAL;
        }
        // SAFETY: the caller's view.
        let (sig, why) = super::classify(unsafe { &*v });
        // SAFETY: the caller's room.
        unsafe { *signal = sig };
        if reason_sz == 0 {
            return if sig == super::METRIC {
                -crate::errno::E2BIG
            } else {
                0
            };
        }
        let fits = why.len() < reason_sz;
        // A metric's reason is all or nothing, as strsprintf() writes it.
        let n = if fits {
            why.len()
        } else if sig == super::METRIC {
            0
        } else {
            reason_sz - 1
        };
        // SAFETY: the caller's room for reason_sz bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(why.as_ptr(), reason.cast::<u8>(), n);
            *reason.add(n) = 0;
        }
        if !fits && sig == super::METRIC {
            -crate::errno::E2BIG
        } else {
            0
        }
    }

    fn build(
        p: *const c_char,
        v: *const MapView,
        out: *mut *mut c_char,
        out_len: *mut usize,
        f: impl FnOnce(&CStr, &MapView) -> Result<super::Buffer, c_int>,
    ) -> c_int {
        let Some(p) = path(p) else {
            return -crate::errno::EINVAL;
        };
        // SAFETY: the caller's view.
        match f(p, unsafe { &*v }) {
            Ok(buf) => {
                let (ptr, len) = buf.into_raw();
                // SAFETY: the caller's rooms; it frees the buffer with
                // xfree(buf, JSON_MAX_BYTES).
                unsafe {
                    *out = ptr.cast();
                    *out_len = len;
                }
                0
            }
            Err(err) => err,
        }
    }

    /// The log a map becomes through the decoder at `path`, for offline
    /// use: the buffer for xfree(buf, JSON_MAX_BYTES).
    ///
    /// # Safety
    ///
    /// `path` is a C string or NULL, `v` a view, `out` and `out_len`
    /// rooms.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_maps_otel_build_log_file(
        path: *const c_char,
        v: *const MapView,
        out: *mut *mut c_char,
        out_len: *mut usize,
    ) -> c_int {
        build(path, v, out, out_len, |p, v| {
            otlp::log_payload(Some(p), v, 0)
        })
    }

    /// The metrics a map becomes through the decoder at `path`.
    ///
    /// # Safety
    ///
    /// As upatch_maps_otel_build_log_file().
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_maps_otel_build_metric_file(
        path: *const c_char,
        v: *const MapView,
        out: *mut *mut c_char,
        out_len: *mut usize,
    ) -> c_int {
        build(path, v, out, out_len, |p, v| {
            otlp::metric_payload(Some(p), v)
        })
    }

    /// # Safety
    ///
    /// `v` is a view or NULL, `opts` options or NULL.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_maps_otel_send(
        v: *const MapView,
        mode: c_int,
        opts: *const OtelOpts,
    ) -> c_int {
        // SAFETY: the caller's view.
        match unsafe { v.as_ref() } {
            Some(v) => super::send_file(None, v, mode, self::opts(opts)),
            None => -crate::errno::EINVAL,
        }
    }

    /// # Safety
    ///
    /// `path` is a C string or NULL, `v` a view or NULL, `opts` options
    /// or NULL.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_maps_otel_send_file(
        path: *const c_char,
        v: *const MapView,
        mode: c_int,
        opts: *const OtelOpts,
    ) -> c_int {
        // SAFETY: the caller's view.
        match unsafe { v.as_ref() } {
            Some(v) => super::send_file(self::path(path), v, mode, self::opts(opts)),
            None => -crate::errno::EINVAL,
        }
    }

    /// # Safety
    ///
    /// `v` is a view or NULL, `opts` options or NULL.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_maps_otel_send_decoded(
        v: *const MapView,
        signal: c_int,
        opts: *const OtelOpts,
    ) -> c_int {
        // SAFETY: the caller's view.
        match unsafe { v.as_ref() } {
            Some(v) => super::send_decoded(v, signal, self::opts(opts)),
            None => -crate::errno::EINVAL,
        }
    }

    /// Sends the `body_len` bytes of the JSON object at `body_json` as
    /// the body of one OTLP log; a `tamper_attempts` of 0 or more rides
    /// along as an attribute. 0 or -errno.
    ///
    /// # Safety
    ///
    /// `opts` is options or NULL; the strings are C strings, `status`
    /// and `version_id` or NULL; `body_json` holds `body_len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn otel_send_log_json(
        opts: *const OtelOpts,
        scope_name: *const c_char,
        event_name: *const c_char,
        severity_number: c_int,
        severity_text: *const c_char,
        status: *const c_char,
        version_id: *const c_char,
        tamper_attempts: i64,
        body_json: *const c_char,
        body_len: usize,
    ) -> c_int {
        let (Some(scope), Some(event), Some(text)) =
            (path(scope_name), path(event_name), path(severity_text))
        else {
            return -crate::errno::EINVAL;
        };
        if body_json.is_null() {
            return -crate::errno::EINVAL;
        }
        let record = otlp::Record {
            scope_name: scope.to_bytes(),
            event_name: event.to_bytes(),
            severity_number,
            severity_text: text.to_bytes(),
            status: path(status).map(CStr::to_bytes),
            version_id: path(version_id).map(CStr::to_bytes),
            tamper_attempts,
            // SAFETY: the caller's body_len bytes.
            body: unsafe { crate::ffi::slice(body_json.cast(), body_len) },
        };
        http::send_log_json(self::opts(opts), &record)
    }

    /// The seconds a Retry-After of `value` asks to wait from `now`, at
    /// most 30: 0 or -EINVAL.
    ///
    /// # Safety
    ///
    /// `value` is a C string or NULL and `seconds` room or NULL.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn otel_retry_after(
        value: *const c_char,
        now: i64,
        seconds: *mut u64,
    ) -> c_int {
        let Some(value) = path(value) else {
            return -crate::errno::EINVAL;
        };
        if seconds.is_null() {
            return -crate::errno::EINVAL;
        }
        match http::retry_after(value.to_bytes(), now) {
            Ok(s) => {
                // SAFETY: the caller's room.
                unsafe { *seconds = s };
                0
            }
            Err(err) => err,
        }
    }

    /// The OTLP severity of a status verdict, its text into `text`.
    ///
    /// # Safety
    ///
    /// `status` is a C string and `text` room for a pointer.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn status_otel_severity(
        status: *const c_char,
        text: *mut *const c_char,
    ) -> c_int {
        // SAFETY: the caller's C string.
        let (n, t) = super::status_severity(unsafe { CStr::from_ptr(status) }.to_bytes());
        // SAFETY: the caller's room.
        unsafe { *text = t.as_ptr() };
        n
    }

    /// For the fuzzer: what the header callback makes of one response
    /// header line of `len` bytes, 1 with a Retry-After into `seconds`.
    ///
    /// # Safety
    ///
    /// `line` holds `len` bytes and `seconds` is room.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn otel_header_retry_after(
        line: *const c_char,
        len: usize,
        seconds: *mut u64,
    ) -> c_int {
        // SAFETY: the caller's bytes.
        match http::header_retry_after(unsafe { crate::ffi::slice(line.cast(), len) }) {
            Some(s) => {
                // SAFETY: the caller's room.
                unsafe { *seconds = s };
                1
            }
            None => 0,
        }
    }

    /// For the fuzzer: the check a collector's 200 body gets for a
    /// partial success of `signal`: 0, -EREMOTEIO or -EBADMSG.
    ///
    /// # Safety
    ///
    /// `body` holds `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn otel_partial_success(
        signal: c_int,
        body: *const c_char,
        len: usize,
    ) -> c_int {
        // SAFETY: the caller's bytes.
        http::check_partial_success(signal, unsafe { crate::ffi::slice(body.cast(), len) })
    }

    /// For the fuzzer: the JSON document at `json` as an AnyValue into
    /// the emitter, as a status body is.
    ///
    /// # Safety
    ///
    /// `e` is an emitter and `json` holds `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn otel_anyvalue_from_json(
        e: *mut JsonEmit,
        json: *const c_char,
        len: usize,
        wrap: bool,
    ) -> c_int {
        // SAFETY: the caller's emitter and bytes.
        unsafe { otlp::anyvalue_from_document(&mut *e, crate::ffi::slice(json.cast(), len), wrap) }
    }

    /// For the fuzzer: the header lines OTEL_EXPORTER_OTLP_HEADERS of
    /// `input` makes, into `*out` for curl_slist_free_all(): 0 or -errno.
    ///
    /// # Safety
    ///
    /// `input` is a C string and `out` room for a list.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn otel_configured_headers(
        input: *const c_char,
        out: *mut *mut CurlSlist,
    ) -> c_int {
        // SAFETY: the caller's C string.
        let input = unsafe { CStr::from_ptr(input) }.to_bytes();
        let mut list = http::Slist::default();
        let ret = http::configured_headers(&mut list, input, false);
        // SAFETY: the caller's room, the list handed over.
        unsafe { *out = list.into_raw() };
        ret
    }

    /// For the fuzzer: whether `s` is an HTTP field name.
    ///
    /// # Safety
    ///
    /// `s` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn otel_header_name_ok(s: *const c_char) -> bool {
        // SAFETY: the caller's C string.
        http::header_name_ok(unsafe { CStr::from_ptr(s) }.to_bytes())
    }

    /// For the fuzzer: whether `s` is an HTTP field value.
    ///
    /// # Safety
    ///
    /// `s` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn otel_header_value_ok(s: *const c_char) -> bool {
        // SAFETY: the caller's C string.
        http::header_value_ok(unsafe { CStr::from_ptr(s) }.to_bytes())
    }
}

pub(crate) use capi::{otel_send_log_json, status_otel_severity};
