// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! OTLP over HTTP with JSON: the endpoint, TLS, compression and headers
//! of the OTEL_EXPORTER_OTLP_* settings, and a POST retried on the
//! failures a retry can mend, as long as a Retry-After asks.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::ffi::CString;

use super::{LOG, MapView, OtelOpts, eprint, is_c_space, otlp};
use crate::errno::{
    E2BIG, EBADMSG, EFBIG, EHOSTUNREACH, EINVAL, EIO, ENAMETOOLONG, ENOMEM, EPERM, EPROTONOSUPPORT,
    EREMOTEIO, ETIMEDOUT,
};
use crate::sys::curl::{
    CURL_GLOBAL_DEFAULT, CURLE_OK, CURLINFO_RESPONSE_CODE, CURLOPT_HEADERDATA,
    CURLOPT_HEADERFUNCTION, CURLOPT_HTTPHEADER, CURLOPT_NOSIGNAL, CURLOPT_POSTFIELDS,
    CURLOPT_POSTFIELDSIZE_LARGE, CURLOPT_SSL_VERIFYHOST, CURLOPT_SSL_VERIFYPEER, CURLOPT_URL,
    CURLOPT_WRITEDATA, CURLOPT_WRITEFUNCTION, CURLUPART_HOST, CURLUPART_SCHEME, CURLUPART_URL,
    Curl, CurlCode, CurlSlist, curl_easy_cleanup, curl_easy_getinfo, curl_easy_init,
    curl_easy_perform, curl_easy_strerror, curl_free, curl_global_cleanup, curl_global_init,
    curl_slist_append, curl_slist_free_all, curl_url, curl_url_cleanup, curl_url_get, curl_url_set,
    set_callback, set_long, set_off, set_ptr,
};
use crate::sys::libc::{Tm, getrandom, strptime, timegm};
use crate::sys::zlib::{ZStream, compressBound, deflate, deflateEnd, deflateInit2_};
use crate::text::parse_s64;
use crate::util::json::{JsonField, parse_schema};
use crate::util::tls_openssl::tls_curl_policy;

/// OTEL_ENDPOINT_MAX, OTEL_RESPONSE_MAX and the rest of the C's limits.
pub(super) const ENDPOINT_MAX: usize = 2048;
const RESPONSE_MAX: usize = 64 * 1024;
pub(super) const DEFAULT_TIMEOUT_MS: c_long = 10_000;
const MAX_TIMEOUT_MS: u64 = 120_000;
const MAX_HEADER_BYTES: usize = 16384;
const HOST_MAX: usize = 256;
const TENANT_ID_MAX: usize = 128;
const LOG_RECORD_MAX_DEFAULT: u32 = 1024 * 1024;
const OTLP_MAX_DEFAULT: u32 = 4 * 1024 * 1024;

pub(super) const CURLOPT_USERAGENT: c_int = 10018;
pub(super) const CURLOPT_TIMEOUT_MS: c_int = 155;
pub(super) const CURLOPT_CAINFO: c_int = 10065;
const CURLOPT_POST: c_int = 47;
const CURLOPT_SSLCERT: c_int = 10025;
const CURLOPT_SSLKEY: c_int = 10087;
const CURLUPART_USER: c_int = 2;
const CURLUPART_PASSWORD: c_int = 3;
const CURLE_OPERATION_TIMEDOUT: CurlCode = 28;

const Z_FINISH: c_int = 4;
const Z_STREAM_END: c_int = 1;
const Z_DEFAULT_COMPRESSION: c_int = -1;
const Z_DEFLATED: c_int = 8;

fn say(text: String) {
    let text = CString::new(text).unwrap_or_default();

    // SAFETY: a "%s" format with a C string.
    unsafe { crate::log::log_c!(crate::log::err, c"%s".as_ptr(), text.as_ptr()) };
}

fn shown(b: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(b)
}

/// A curl header list, freed when it goes.
pub(crate) struct Slist(*mut CurlSlist);

impl Default for Slist {
    fn default() -> Self {
        Slist(core::ptr::null_mut())
    }
}

impl Slist {
    pub(super) fn append(&mut self, line: &[u8]) -> c_int {
        let Ok(line) = CString::new(line) else {
            return -EINVAL;
        };
        // SAFETY: the list or NULL, and a C string, which curl copies.
        let next = unsafe { curl_slist_append(self.0, line.as_ptr()) };
        if next.is_null() {
            return -ENOMEM;
        }
        self.0 = next;
        0
    }

    pub(super) fn raw(&self) -> *mut CurlSlist {
        self.0
    }

    pub(crate) fn into_raw(self) -> *mut CurlSlist {
        let p = self.0;
        core::mem::forget(self);
        p
    }
}

impl Drop for Slist {
    fn drop(&mut self) {
        // SAFETY: the list, or NULL, freed once.
        unsafe { curl_slist_free_all(self.0) };
    }
}

/// An environment setting, unset when empty.
fn env(name: &str) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStringExt;

    std::env::var_os(name)
        .map(OsStringExt::into_vec)
        .filter(|v| !v.is_empty())
}

fn signal_name(signal: c_int) -> &'static str {
    if signal == LOG { "LOGS" } else { "METRICS" }
}

fn signal_path(signal: c_int) -> &'static [u8] {
    if signal == LOG {
        b"v1/logs"
    } else {
        b"v1/metrics"
    }
}

/// OTEL_EXPORTER_OTLP_<signal>_<suffix>.
fn signal_env(signal: c_int, suffix: &str) -> Option<Vec<u8>> {
    env(&format!(
        "OTEL_EXPORTER_OTLP_{}_{suffix}",
        signal_name(signal)
    ))
}

/// The signal's setting, else the one for every signal.
fn otel_env(signal: c_int, suffix: &str) -> Option<Vec<u8>> {
    signal_env(signal, suffix).or_else(|| env(&format!("OTEL_EXPORTER_OTLP_{suffix}")))
}

/// `base` with the signal's path appended, before its query or fragment.
fn append_signal_path(base: &[u8], signal: c_int) -> Result<Vec<u8>, c_int> {
    let tail = base.iter().position(|&c| c == b'?' || c == b'#');
    let prefix_len = tail.unwrap_or(base.len());
    if prefix_len == 0 {
        return Err(-EINVAL);
    }
    let slash: &[u8] = if base[prefix_len - 1] == b'/' {
        b""
    } else {
        b"/"
    };
    let out = [
        &base[..prefix_len],
        slash,
        signal_path(signal),
        &base[prefix_len..],
    ]
    .concat();
    if out.len() >= ENDPOINT_MAX {
        return Err(-ENAMETOOLONG);
    }
    Ok(out)
}

pub(super) fn loopback_host(host: &[u8]) -> bool {
    host.eq_ignore_ascii_case(b"localhost") || host == b"127.0.0.1" || host == b"[::1]"
}

/// A URL's scheme and host as curl reads them: -EINVAL for one that does
/// not parse or carries credentials.
pub(super) fn url_parts(url: &[u8]) -> Result<(Vec<u8>, Vec<u8>), c_int> {
    struct Url(*mut crate::sys::curl::CurlU);
    impl Drop for Url {
        fn drop(&mut self) {
            // SAFETY: the handle, freed once.
            unsafe { curl_url_cleanup(self.0) };
        }
    }
    fn part(u: &Url, what: c_int) -> (bool, Vec<u8>) {
        let mut p: *mut c_char = core::ptr::null_mut();
        // SAFETY: the handle and room for the part.
        let ok = unsafe { curl_url_get(u.0, what, &mut p, 0) } == 0;
        if p.is_null() {
            return (ok, Vec::new());
        }
        // SAFETY: curl's C string, freed once.
        let v = unsafe { CStr::from_ptr(p) }.to_bytes().to_vec();
        // SAFETY: as above.
        unsafe { curl_free(p.cast()) };
        (ok, v)
    }

    // SAFETY: a new handle.
    let u = Url(unsafe { curl_url() });
    if u.0.is_null() {
        return Err(-ENOMEM);
    }
    let c = CString::new(url).map_err(|_| -EINVAL)?;
    // SAFETY: the handle and a C string.
    if unsafe { curl_url_set(u.0, CURLUPART_URL, c.as_ptr(), 0) } != 0 {
        return Err(-EINVAL);
    }
    let (scheme_ok, scheme) = part(&u, CURLUPART_SCHEME);
    let (host_ok, host) = part(&u, CURLUPART_HOST);
    if !scheme_ok || !host_ok {
        return Err(-EINVAL);
    }
    let (_, user) = part(&u, CURLUPART_USER);
    let (_, password) = part(&u, CURLUPART_PASSWORD);
    if !user.is_empty() || !password.is_empty() {
        return Err(-EINVAL);
    }
    Ok((scheme, host))
}

/// A setting of milliseconds, 1 to 120000; 10000 unset. curl takes 0 as
/// no limit at all, which would let a run hang.
fn parse_timeout(value: Option<&[u8]>) -> Result<c_long, c_int> {
    let Some(value) = value else {
        return Ok(DEFAULT_TIMEOUT_MS);
    };
    match crate::text::parse_u64(value, MAX_TIMEOUT_MS) {
        Ok(n) if n != 0 => Ok(n as c_long),
        _ => Err(-EINVAL),
    }
}

/// Headers curl or the exporter set, which the settings may not.
fn reserved_header(name: &[u8]) -> bool {
    [
        &b"content-type"[..],
        b"content-encoding",
        b"content-length",
        b"host",
        b"user-agent",
    ]
    .iter()
    .any(|r| name.eq_ignore_ascii_case(r))
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The value's percent escapes decoded; a NUL would cut it short.
fn percent_decode(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'%' {
            let (hi, lo) = (hex_nibble(*s.get(i + 1)?)?, hex_nibble(*s.get(i + 2)?)?);
            if hi | lo == 0 {
                return None;
            }
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(s[i]);
            i += 1;
        }
    }
    Some(out)
}

/// RFC 9110, 5.6.2: a field name is a token.
pub(super) fn header_name_ok(s: &[u8]) -> bool {
    !s.is_empty()
        && s.iter()
            .all(|&c| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c))
}

/// RFC 9110, 5.5: a field value holds no control character but tab.
pub(super) fn header_value_ok(s: &[u8]) -> bool {
    s.iter().all(|&c| (c >= 0x20 || c == b'\t') && c != 0x7f)
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let Some((&c, rest)) = s.split_first() {
        if !is_c_space(c) {
            break;
        }
        s = rest;
    }
    while let Some((&c, rest)) = s.split_last() {
        if !is_c_space(c) {
            break;
        }
        s = rest;
    }
    s
}

fn tenant_id_valid(id: &[u8]) -> bool {
    !id.is_empty()
        && id.len() <= TENANT_ID_MAX
        && id
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// The `name=value,...` of OTEL_EXPORTER_OTLP_HEADERS as header lines,
/// the values percent-decoded. A tenant ID the options give wins over
/// the setting's, which then is skipped.
pub(super) fn configured_headers(list: &mut Slist, input: &[u8], tenant_given: bool) -> c_int {
    if input.len() > MAX_HEADER_BYTES {
        return -E2BIG;
    }
    let mut tenant_seen = false;
    for pair in input.split(|&c| c == b',').filter(|p| !p.is_empty()) {
        let Some(eq) = pair.iter().position(|&c| c == b'=') else {
            return -EINVAL;
        };
        let (name, value) = (trim(&pair[..eq]), trim(&pair[eq + 1..]));
        let tenant = name.eq_ignore_ascii_case(b"x-tenant-id");
        if !header_name_ok(name) || reserved_header(name) {
            return -EINVAL;
        }
        let Some(mut value) = percent_decode(value) else {
            return -EINVAL;
        };
        if !header_value_ok(&value) {
            return -EINVAL;
        }
        if tenant {
            if tenant_given {
                continue;
            }
            if tenant_seen || !tenant_id_valid(&value) {
                return -EINVAL;
            }
            tenant_seen = true;
        }
        let header: &[u8] = if tenant { b"X-Tenant-ID" } else { name };
        let mut line = [header, b": ", &value].concat();
        let ret = list.append(&line);
        line.fill(0);
        value.fill(0);
        if ret != 0 {
            return ret;
        }
    }
    0
}

/// What a response brought back: its body, and a Retry-After it asked.
pub(super) struct Response {
    body: Vec<u8>,
    retry_after: Option<u64>,
}

impl Response {
    /// The seconds a Retry-After of the response asked to wait.
    pub(super) fn retry_after(&self) -> Option<u64> {
        self.retry_after
    }

    pub(super) fn new() -> Self {
        Response {
            body: Vec::new(),
            retry_after: None,
        }
    }
}

/// curl's write callback: the body, refused past 64 KiB.
pub(super) unsafe extern "C" fn response_write(
    ptr: *mut c_char,
    size: usize,
    n: usize,
    ctx: *mut c_void,
) -> usize {
    // SAFETY: the response the transfer was given.
    let r = unsafe { &mut *ctx.cast::<Response>() };
    match size.checked_mul(n) {
        Some(len) if len <= RESPONSE_MAX - 1 - r.body.len() => {
            // SAFETY: curl's len bytes.
            r.body
                .extend_from_slice(unsafe { crate::ffi::slice(ptr.cast::<u8>(), len) });
            len
        }
        _ => 0,
    }
}

/// The seconds a `Retry-After:` header line asks, if it is one that
/// parses.
pub(super) fn header_retry_after(line: &[u8]) -> Option<u64> {
    const PREFIX: &[u8] = b"Retry-After:";
    if line.len() <= PREFIX.len() || !line[..PREFIX.len()].eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let value = trim(&line[PREFIX.len()..]);
    if value.len() >= 128 {
        return None;
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    retry_after(value, now).ok()
}

/// curl's header callback, one line at a time.
pub(super) unsafe extern "C" fn response_header(
    ptr: *mut c_char,
    size: usize,
    n: usize,
    ctx: *mut c_void,
) -> usize {
    let Some(len) = size.checked_mul(n) else {
        return 0;
    };
    // SAFETY: the response the transfer was given, and curl's bytes.
    let (r, line) = unsafe {
        (
            &mut *ctx.cast::<Response>(),
            crate::ffi::slice(ptr.cast::<u8>(), len),
        )
    };
    if let Some(s) = header_retry_after(line) {
        r.retry_after = Some(s);
    }
    len
}

/// Retry-After, seconds or an HTTP date, as the seconds to wait from
/// `now`: at most 30.
pub(super) fn retry_after(value: &[u8], now: i64) -> Result<u64, c_int> {
    if value.is_empty() || value.contains(&0) {
        return Err(-EINVAL);
    }
    if value.iter().all(u8::is_ascii_digit) {
        let delay = value.iter().fold(0u64, |d, &c| {
            if d < 31 {
                d * 10 + u64::from(c - b'0')
            } else {
                d
            }
        });
        return Ok(delay.min(30));
    }
    let c = CString::new(value).map_err(|_| -EINVAL)?;
    let formats: [&CStr; 3] = [
        c"%a, %d %b %Y %H:%M:%S GMT",
        c"%A, %d-%b-%y %H:%M:%S GMT",
        c"%a %b %e %H:%M:%S %Y",
    ];
    for fmt in formats {
        let mut tm = Tm::zeroed();
        // SAFETY: two C strings and the time to fill.
        let end = unsafe { strptime(c.as_ptr(), fmt.as_ptr(), &mut tm) };
        if end.is_null() {
            continue;
        }
        // SAFETY: what strptime() left of the value, a C string.
        let rest = unsafe { CStr::from_ptr(end) }.to_bytes();
        if !rest
            .iter()
            .all(|&b| matches!(b, b' ' | b'\t' | b'\r' | b'\n'))
        {
            return Err(-EINVAL);
        }
        // SAFETY: the time strptime() filled.
        let at = unsafe { timegm(&mut tm) };
        return Ok(if at <= now {
            0
        } else {
            ((at - now) as u64).min(30)
        });
    }
    Err(-EINVAL)
}

/// The proto3 JSON mapping lets a receiver send the rejected count as a
/// string or a number, and the message is advisory: one that does not
/// fit is left out rather than failing an export the collector took.
pub(super) fn check_partial_success(signal: c_int, body: &[u8]) -> c_int {
    if body.is_empty() {
        return 0;
    }
    let count: &'static CStr = if signal == LOG {
        c"rejectedLogRecords"
    } else {
        c"rejectedDataPoints"
    };
    let mut text = [0u8; 32];
    let mut rejected: i64 = 0;
    let mut partial = [JsonField::string(count, text.as_mut_ptr(), text.len())];
    let mut root = [JsonField::object(
        c"partialSuccess",
        partial.as_mut_ptr(),
        1,
    )];
    // SAFETY: the schema and its destinations, which outlive the parse.
    if unsafe { parse_schema(body, root.as_mut_ptr(), 1) } != 0 {
        partial[0] = JsonField::int(count, &mut rejected);
        root[0] = JsonField::object(c"partialSuccess", partial.as_mut_ptr(), 1);
        // SAFETY: as above.
        if unsafe { parse_schema(body, root.as_mut_ptr(), 1) } != 0 {
            return -EBADMSG;
        }
    } else if partial[0].seen() {
        match parse_s64(crate::text::cstr(&text), 0, i64::MAX) {
            Ok(v) => rejected = v,
            Err(_) => return -EBADMSG,
        }
    }
    if rejected < 0 {
        return -EBADMSG;
    }
    if rejected == 0 {
        return 0;
    }
    let mut error = [0u8; 256];
    partial[0] = JsonField::string(c"errorMessage", error.as_mut_ptr(), error.len());
    root[0] = JsonField::object(c"partialSuccess", partial.as_mut_ptr(), 1);
    // SAFETY: as above.
    if unsafe { parse_schema(body, root.as_mut_ptr(), 1) } != 0 {
        error[0] = 0;
    }
    let error = crate::text::cstr(&error);
    let what = if signal == LOG {
        "log record(s)"
    } else {
        "data point(s)"
    };
    let sep = if error.is_empty() { "" } else { ": " };
    say(format!(
        "otel: Collector partially rejected {rejected} {what}{sep}{}",
        shown(error)
    ));
    -EREMOTEIO
}

fn random_below(limit: u32) -> u32 {
    if limit == 0 {
        return 0;
    }
    let mut value = 0u32;
    // SAFETY: room for four bytes.
    if unsafe { getrandom((&raw mut value).cast(), 4, 0) } != 4 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        value = (now as u32) ^ std::process::id();
    }
    value % limit
}

/// Waits before attempt `retry` + 1: the Retry-After asked, else a
/// random time up to a cap that doubles from 250 ms to 5 s.
pub(super) fn retry_wait(retry: u32, retry_after: Option<u64>) {
    let cap_ms = (250u32 << retry.min(4)).min(5000);
    let delay_ms = retry_after.map_or_else(
        || random_below(cap_ms + 1),
        |s| (s as u32).wrapping_mul(1000),
    );
    std::thread::sleep(std::time::Duration::from_millis(u64::from(delay_ms)));
}

pub(super) fn retryable_curl(code: CurlCode) -> bool {
    // COULDNT_RESOLVE_HOST, COULDNT_CONNECT, OPERATION_TIMEDOUT,
    // SEND_ERROR, RECV_ERROR, GOT_NOTHING, PARTIAL_FILE, HTTP2, AGAIN.
    matches!(code, 6 | 7 | 28 | 55 | 56 | 52 | 18 | 16 | 81)
}

pub(super) fn retryable_http(code: c_long) -> bool {
    matches!(code, 429 | 502 | 503 | 504)
}

pub(super) fn curl_error(code: CurlCode) -> String {
    // SAFETY: curl's static C string.
    unsafe { CStr::from_ptr(curl_easy_strerror(code)) }
        .to_string_lossy()
        .into_owned()
}

/// What a failed attempt returns: a timeout, a transport failure, or a
/// status the collector answered with.
pub(super) fn attempt_error(code: CurlCode) -> c_int {
    match code {
        CURLE_OPERATION_TIMEDOUT => -ETIMEDOUT,
        CURLE_OK => -EREMOTEIO,
        _ => -EHOSTUNREACH,
    }
}

/// The JSON gzipped as one stream.
fn gzip(data: &[u8]) -> Result<Vec<u8>, c_int> {
    // zlib counts in uInt; a longer input would be cut short silently.
    if data.len() > u32::MAX as usize {
        return Err(-EFBIG);
    }
    // SAFETY: a computation.
    let cap = (unsafe { compressBound(data.len() as _) } as usize).saturating_add(32);
    if cap > u32::MAX as usize {
        return Err(-EFBIG);
    }
    let mut out = vec![0u8; cap];
    let mut z = ZStream::zeroed();
    // SAFETY: the stream, gzip framing, and the zlib it was built for.
    if unsafe {
        deflateInit2_(
            &mut z,
            Z_DEFAULT_COMPRESSION,
            Z_DEFLATED,
            15 + 16,
            8,
            0,
            crate::sys::zlib::ZLIB_VERSION.as_ptr(),
            size_of::<ZStream>() as c_int,
        )
    } != 0
    {
        return Err(-EIO);
    }
    z.next_in = data.as_ptr().cast_mut();
    z.avail_in = data.len() as u32;
    z.next_out = out.as_mut_ptr();
    z.avail_out = cap as u32;
    // SAFETY: the stream, its input and output set above.
    let zr = unsafe { deflate(&mut z, Z_FINISH) };
    let total = z.total_out as usize;
    // SAFETY: the stream, ended once.
    unsafe { deflateEnd(&mut z) };
    if zr != Z_STREAM_END {
        return Err(-EIO);
    }
    out.truncate(total);
    Ok(out)
}

/// An OTLP endpoint for one signal, set up from the options and the
/// settings, curl's global state held until it goes.
pub(super) struct Transport {
    signal: c_int,
    opts: OtelOpts,
    decoder_path: Option<CString>,
    endpoint: CString,
    ca_file: Option<CString>,
    client_cert: Option<CString>,
    client_key: Option<CString>,
    timeout_ms: c_long,
    gzip: bool,
    insecure_tls: bool,
    /// The log points at a snapshot in S3, so it is not held to the
    /// OTLP size limit of a map's own log.
    pub(super) s3_reference: bool,
    headers: Slist,
    global: bool,
}

impl Drop for Transport {
    fn drop(&mut self) {
        if self.global {
            // SAFETY: the curl_global_init() this transport made.
            unsafe { curl_global_cleanup() };
        }
    }
}

fn cstring(v: Vec<u8>) -> Option<CString> {
    CString::new(v).ok()
}

impl Transport {
    fn open(
        signal: c_int,
        spec: Option<&CStr>,
        opts: Option<&OtelOpts>,
        decoder_path: Option<&CStr>,
    ) -> Result<Box<Self>, c_int> {
        let mut opts = opts.copied().unwrap_or(OtelOpts::defaults());
        // Callers without the configuration leave the limits at 0.
        if opts.otlp_max_bytes == 0 {
            opts.otlp_max_bytes = OTLP_MAX_DEFAULT;
        }
        if opts.log_record_max_bytes == 0 {
            opts.log_record_max_bytes = LOG_RECORD_MAX_DEFAULT;
        }
        let mut t = Box::new(Transport {
            signal,
            opts,
            decoder_path: decoder_path.map(CStr::to_owned),
            endpoint: CString::default(),
            ca_file: None,
            client_cert: None,
            client_key: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            gzip: false,
            insecure_tls: false,
            s3_reference: false,
            headers: Slist::default(),
            global: false,
        });
        // SAFETY: curl's global setup, undone when the transport goes.
        if unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) } != CURLE_OK {
            return Err(-EIO);
        }
        t.global = true;
        // Explicit endpoints are base URLs for the selected signal.
        t.configure(spec.map(CStr::to_bytes))?;
        Ok(t)
    }

    fn endpoint_from(&self, spec: Option<&[u8]>) -> Result<Vec<u8>, c_int> {
        if let Some(spec) = spec.filter(|s| !s.is_empty()) {
            return append_signal_path(spec, self.signal);
        }
        if let Some(e) = signal_env(self.signal, "ENDPOINT") {
            if e.len() >= ENDPOINT_MAX {
                return Err(-ENAMETOOLONG);
            }
            return Ok(e);
        }
        let generic =
            env("OTEL_EXPORTER_OTLP_ENDPOINT").unwrap_or_else(|| b"http://localhost:4318".to_vec());
        append_signal_path(&generic, self.signal)
    }

    /// Whether the endpoint may carry the data: TLS, or plain HTTP to
    /// the loopback, or either with the operator's --otel-insecure.
    fn validate_endpoint(&mut self) -> Result<(), c_int> {
        let (scheme, host) = url_parts(self.endpoint.as_bytes())?;
        if host.len() >= HOST_MAX {
            return Err(-ENAMETOOLONG);
        }
        let host_s = shown(&host);
        match &scheme[..] {
            b"http" => {
                if !loopback_host(&host) && !self.opts.allow_insecure {
                    return Err(-EPERM);
                }
                if self.opts.allow_insecure {
                    eprint(
                        format!(
                            "WARNING: --otel-insecure sends OTLP data to http://{host_s} without encryption; \
                             data and credentials may be intercepted or modified\n"
                        )
                        .as_bytes(),
                    );
                }
            }
            b"https" => {
                self.insecure_tls = self.opts.allow_insecure;
                if self.insecure_tls {
                    eprint(
                        format!(
                            "WARNING: --otel-insecure disables TLS certificate and hostname verification for \
                             {host_s}; the Collector's identity is not verified\n"
                        )
                        .as_bytes(),
                    );
                }
            }
            _ => return Err(-EPROTONOSUPPORT),
        }
        Ok(())
    }

    fn configure(&mut self, spec: Option<&[u8]>) -> Result<(), c_int> {
        let protocol = otel_env(self.signal, "PROTOCOL");
        let compression = otel_env(self.signal, "COMPRESSION");
        let headers = otel_env(self.signal, "HEADERS");

        if protocol.is_some_and(|p| p != b"http/json") {
            return Err(-EPROTONOSUPPORT);
        }
        if compression
            .as_deref()
            .is_some_and(|c| c != b"none" && c != b"gzip")
        {
            return Err(-EINVAL);
        }
        self.gzip = compression.as_deref() == Some(b"gzip");
        self.ca_file = otel_env(self.signal, "CERTIFICATE").and_then(cstring);
        self.client_cert = otel_env(self.signal, "CLIENT_CERTIFICATE").and_then(cstring);
        self.client_key = otel_env(self.signal, "CLIENT_KEY").and_then(cstring);
        if self.client_cert.is_some() != self.client_key.is_some() {
            return Err(-EINVAL);
        }
        self.timeout_ms = parse_timeout(otel_env(self.signal, "TIMEOUT").as_deref())?;
        self.endpoint = CString::new(self.endpoint_from(spec)?).map_err(|_| -EINVAL)?;
        self.validate_endpoint()?;
        let ret = self.headers.append(b"Content-Type: application/json");
        if ret != 0 {
            return Err(ret);
        }
        if self.gzip {
            let ret = self.headers.append(b"Content-Encoding: gzip");
            if ret != 0 {
                return Err(ret);
            }
        }
        let tenant = self.opts.tenant_id().map(CStr::to_bytes);
        if let Some(h) = headers {
            let ret = configured_headers(&mut self.headers, &h, tenant.is_some());
            if ret != 0 {
                return Err(ret);
            }
        }
        let Some(tenant) = tenant else {
            return Ok(());
        };
        if !tenant_id_valid(tenant) {
            return Err(-EINVAL);
        }
        match self.headers.append(&[b"X-Tenant-ID: ", tenant].concat()) {
            0 => Ok(()),
            err => Err(err),
        }
    }

    /// POSTs the document, retrying what a retry can mend.
    pub(super) fn post(&self, json: &[u8]) -> c_int {
        let Some(max_attempts) = self.opts.retries.checked_add(1) else {
            return -EINVAL;
        };
        if !self.s3_reference
            && self.opts.otlp_max_bytes != 0
            && json.len() > self.opts.otlp_max_bytes as usize
        {
            return -E2BIG;
        }
        let compressed;
        let body: &[u8] = if self.gzip {
            compressed = match gzip(json) {
                Ok(c) => c,
                Err(err) => return err,
            };
            &compressed
        } else {
            json
        };
        let mut ret = -EIO;
        for attempt in 0..max_attempts {
            let mut response = Response::new();
            // SAFETY: a new handle.
            let curl = unsafe { curl_easy_init() };
            if curl.is_null() {
                ret = -ENOMEM;
                break;
            }
            let (code, status) = self.perform(curl, body, &mut response);
            if let Err(err) = code {
                // SAFETY: the handle, freed once.
                unsafe { curl_easy_cleanup(curl) };
                ret = err;
                break;
            }
            let code = code.unwrap_or(CURLE_OK);
            // SAFETY: the handle, freed once.
            unsafe { curl_easy_cleanup(curl) };
            if code == CURLE_OK && status == 200 {
                ret = check_partial_success(self.signal, &response.body);
                break;
            }
            let retry = if code != CURLE_OK {
                retryable_curl(code)
            } else {
                retryable_http(status)
            };
            if code != CURLE_OK {
                eprint(
                    format!(
                        "otel: export attempt {}/{max_attempts} failed: {}\n",
                        attempt + 1,
                        curl_error(code)
                    )
                    .as_bytes(),
                );
            } else {
                eprint(
                    format!(
                        "otel: export attempt {}/{max_attempts} received HTTP {status}\n",
                        attempt + 1
                    )
                    .as_bytes(),
                );
            }
            ret = attempt_error(code);
            if !retry || attempt + 1 == max_attempts {
                break;
            }
            retry_wait(attempt, response.retry_after);
        }
        ret
    }

    /// One attempt on `curl`: curl's code and the HTTP status, or the
    /// error of a TLS policy curl does not take.
    fn perform(
        &self,
        curl: *mut Curl,
        body: &[u8],
        response: &mut Response,
    ) -> (Result<CurlCode, c_int>, c_long) {
        let ctx: *mut Response = response;
        // SAFETY: the handle, and options whose values outlive the
        // transfer: the endpoint, the body, the headers, the response.
        unsafe {
            set_ptr(curl, CURLOPT_URL, self.endpoint.as_ptr());
            set_long(curl, CURLOPT_POST, 1);
            set_ptr(curl, CURLOPT_POSTFIELDS, body.as_ptr());
            set_off(curl, CURLOPT_POSTFIELDSIZE_LARGE, body.len() as i64);
            set_ptr(curl, CURLOPT_HTTPHEADER, self.headers.raw());
            set_ptr(
                curl,
                CURLOPT_USERAGENT,
                c"shirudo OTel-OTLP-Exporter-C/1".as_ptr(),
            );
            set_callback(curl, CURLOPT_WRITEFUNCTION, response_write);
            set_ptr(curl, CURLOPT_WRITEDATA, ctx);
            set_callback(curl, CURLOPT_HEADERFUNCTION, response_header);
            set_ptr(curl, CURLOPT_HEADERDATA, ctx);
            set_long(curl, CURLOPT_NOSIGNAL, 1);
            set_long(curl, CURLOPT_TIMEOUT_MS, self.timeout_ms);
            set_long(
                curl,
                CURLOPT_SSL_VERIFYPEER,
                if self.insecure_tls { 0 } else { 1 },
            );
            set_long(
                curl,
                CURLOPT_SSL_VERIFYHOST,
                if self.insecure_tls { 0 } else { 2 },
            );
            if tls_curl_policy(curl, core::ptr::null_mut()) != 0 {
                return (Err(-EINVAL), 0);
            }
            for (opt, v) in [
                (CURLOPT_CAINFO, &self.ca_file),
                (CURLOPT_SSLCERT, &self.client_cert),
                (CURLOPT_SSLKEY, &self.client_key),
            ] {
                if let Some(v) = v {
                    set_ptr(curl, opt, v.as_ptr());
                }
            }
            let code = curl_easy_perform(curl);
            let mut status: c_long = 0;
            if code == CURLE_OK {
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &mut status);
            }
            (Ok(code), status)
        }
    }

    /// Builds the map's document for the signal and posts it.
    pub(super) fn emit(&mut self, v: &MapView) -> c_int {
        let path = self.decoder_path.as_deref();
        let payload = if self.signal == LOG {
            otlp::log_payload(path, v, self.opts.log_record_max_bytes as usize)
        } else {
            otlp::metric_payload(path, v)
        };
        match payload {
            Ok(p) => self.post(p.bytes()),
            Err(err) => err,
        }
    }

    pub(super) fn decoder_path(&self) -> Option<&CStr> {
        self.decoder_path.as_deref()
    }
}

/// The transport for a map's export: the signal the map classifies as
/// when `automatic`, which it says, else `forced`.
pub(super) fn open_for_map(
    spec: Option<&CStr>,
    v: &MapView,
    opts: Option<&OtelOpts>,
    automatic: bool,
    forced: c_int,
    decoder_path: Option<&CStr>,
) -> Result<Box<Transport>, c_int> {
    let signal = if automatic {
        let (signal, reason) = super::classify(v);
        eprint(
            format!(
                "otel: selected {} for {} map {}: {reason}\n",
                if signal == LOG { "log" } else { "metric" },
                shown(super::cstr_or_empty(v.type_name)),
                shown(crate::text::cstr(&v.name)),
            )
            .as_bytes(),
        );
        signal
    } else {
        forced
    };
    Transport::open(signal, spec, opts, decoder_path)
}

/// One structured log, as `shirudo status` sends its keepalive.
pub(super) fn send_log_json(opts: Option<&OtelOpts>, r: &otlp::Record<'_>) -> c_int {
    let t = match Transport::open(LOG, opts.and_then(OtelOpts::endpoint), opts, None) {
        Ok(t) => t,
        Err(err) => return err,
    };
    match otlp::generic_log_payload(r) {
        Ok(p) => t.post(p.bytes()),
        Err(err) => err,
    }
}
