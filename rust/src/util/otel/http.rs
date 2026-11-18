// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! OTLP over HTTP with JSON: the endpoint, TLS, compression and headers
//! of the OTEL_EXPORTER_OTLP_* settings, and a POST retried on the
//! failures a retry can mend, as long as a Retry-After asks.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::ffi::CString;

use super::{LOG, MapView, OtelOpts, eprint, is_c_space, otlp};
use crate::errno::{
    E2BIG, EBADMSG, EFBIG, EHOSTUNREACH, EINVAL, EIO, ENAMETOOLONG, EPERM, EPROTONOSUPPORT,
    EREMOTEIO, ETIMEDOUT,
};
use crate::sys::curl::{
    CURL_GLOBAL_DEFAULT, CURLE_OK, CURLOPT_CAINFO, CURLOPT_NOSIGNAL, CURLOPT_POST,
    CURLOPT_SSL_VERIFYHOST, CURLOPT_SSL_VERIFYPEER, CURLOPT_SSLCERT, CURLOPT_SSLKEY,
    CURLOPT_TIMEOUT_MS, CURLOPT_URL, CURLOPT_USERAGENT, CURLUPART_HOST, CURLUPART_PASSWORD,
    CURLUPART_SCHEME, CURLUPART_USER, CurlCode, curl_global_cleanup, curl_global_init,
};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{Tm, getrandom, strptime, timegm};
use crate::text::parse_s64;
use crate::util::curl::{Easy, Slist, Url, strerror};
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

const CURLE_OPERATION_TIMEDOUT: CurlCode = 28;

fn say(text: String) {
    let text = CString::new(text).unwrap_or_default();

    crate::log::err(text.to_bytes());
}

fn shown(b: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(b)
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
    let u = Url::parse(url)?;
    let scheme = u.part(CURLUPART_SCHEME);
    let host = u.part(CURLUPART_HOST);
    let (Some(scheme), Some(host)) = (scheme, host) else {
        return Err(-EINVAL);
    };
    let user = u.part(CURLUPART_USER).unwrap_or_default();
    let password = u.part(CURLUPART_PASSWORD).unwrap_or_default();
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

/// What a partial success holds: the rejected count, as a string or as
/// a number, and the message.
struct Partial {
    text: [u8; 32],
    rejected: i64,
    error: [u8; 256],
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
    let mut partial = Partial {
        text: [0; 32],
        rejected: 0,
        error: [0; 256],
    };
    let as_text = [JsonField::string(count, |p: &mut Partial| &mut p.text)];
    let as_number = [JsonField::int(count, |p: &mut Partial| &mut p.rejected)];
    let message = [JsonField::string(c"errorMessage", |p: &mut Partial| {
        &mut p.error
    })];
    let root = [JsonField::object(c"partialSuccess", &as_text)];

    if parse_schema(body, &root, &mut partial).is_err() {
        let root = [JsonField::object(c"partialSuccess", &as_number)];

        if parse_schema(body, &root, &mut partial).is_err() {
            return -EBADMSG;
        }
    } else if as_text[0].seen() {
        match parse_s64(crate::text::cstr(&partial.text), 0, i64::MAX) {
            Ok(v) => partial.rejected = v,
            Err(_) => return -EBADMSG,
        }
    }
    let rejected = partial.rejected;
    if rejected < 0 {
        return -EBADMSG;
    }
    if rejected == 0 {
        return 0;
    }
    let root = [JsonField::object(c"partialSuccess", &message)];
    if parse_schema(body, &root, &mut partial).is_err() {
        partial.error[0] = 0;
    }
    let error = crate::text::cstr(&partial.error);
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
    strerror(code).to_string_lossy().into_owned()
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
    if data.len() > u32::MAX as usize {
        return Err(-EFBIG);
    }
    crate::util::gzip::gzip(data).map_err(|_| -EIO)
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
            let mut easy = match Easy::new() {
                Ok(easy) => easy,
                Err(err) => {
                    ret = err;
                    break;
                }
            };
            let done = self.perform(&mut easy, body, &mut response);
            drop(easy);
            let (code, status) = match done {
                Ok(done) => done,
                Err(err) => {
                    ret = err;
                    break;
                }
            };
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

    /// One attempt on `easy`: curl's code and the HTTP status, or the
    /// error of a TLS policy curl does not take.
    fn perform<'a>(
        &'a self,
        easy: &mut Easy<'a>,
        body: &'a [u8],
        response: &mut Response,
    ) -> Result<(CurlCode, c_long), c_int> {
        let ctx: *mut Response = response;

        easy.set_str(CURLOPT_URL, &self.endpoint);
        easy.set_long(CURLOPT_POST, 1);
        easy.set_post_fields(body);
        easy.set_headers(&self.headers);
        easy.set_str(CURLOPT_USERAGENT, c"shirudo OTel-OTLP-Exporter-C/1");
        // SAFETY: response_write() takes its data for the response, which
        // outlives the handle and which only the callbacks touch while
        // the transfer runs.
        unsafe { easy.set_write(response_write, ctx) };
        // SAFETY: response_header() takes its data for the response, as
        // above.
        unsafe { easy.set_header(response_header, ctx) };
        easy.set_long(CURLOPT_NOSIGNAL, 1);
        easy.set_long(CURLOPT_TIMEOUT_MS, self.timeout_ms);
        easy.set_long(
            CURLOPT_SSL_VERIFYPEER,
            if self.insecure_tls { 0 } else { 1 },
        );
        easy.set_long(
            CURLOPT_SSL_VERIFYHOST,
            if self.insecure_tls { 0 } else { 2 },
        );
        tls_curl_policy(easy, None)?;
        for (option, value) in [
            (CURLOPT_CAINFO, &self.ca_file),
            (CURLOPT_SSLCERT, &self.client_cert),
            (CURLOPT_SSLKEY, &self.client_key),
        ] {
            if let Some(value) = value {
                easy.set_str(option, value);
            }
        }
        let code = easy.perform();
        let status = if code == CURLE_OK {
            easy.response_code().unwrap_or(0)
        } else {
            0
        };
        Ok((code, status))
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
            Ok(p) => self.post(&p),
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
                shown(super::name_or_empty(v.type_name)),
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

/// One log with a string body and one attribute, the payload made
/// before any connection, so that a body JSON cannot carry goes nowhere.
pub(super) fn send_log_string(opts: Option<&OtelOpts>, r: &otlp::StringRecord<'_>) -> c_int {
    let payload = match otlp::string_log_payload(r) {
        Ok(p) => p,
        Err(err) => return err,
    };
    match Transport::open(LOG, opts.and_then(OtelOpts::endpoint), opts, None) {
        Ok(t) => t.post(&payload),
        Err(err) => err,
    }
}
