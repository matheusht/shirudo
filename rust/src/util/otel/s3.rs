// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! A map too large for OTLP goes to S3 as a gzipped snapshot of what its
//! decoder makes of it, content-addressed and never overwritten, and an
//! OTLP log points at it.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use std::ffi::CString;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::FromRawFd;
use std::os::unix::ffi::OsStringExt;

use super::http::{
    self, CURLOPT_CAINFO, CURLOPT_TIMEOUT_MS, CURLOPT_USERAGENT, DEFAULT_TIMEOUT_MS, ENDPOINT_MAX,
    Response, Slist, Transport, attempt_error, curl_error, loopback_host, response_header,
    response_write, retry_wait, retryable_curl, retryable_http, url_parts,
};
use super::{Decoded, LOG, MapView, OtelOpts, eprint, otlp};
use crate::errno::{
    E2BIG, EACCES, EINVAL, EIO, ENAMETOOLONG, ENOMEM, EOPNOTSUPP, EOVERFLOW, EPERM, EPROTONOSUPPORT,
};
use crate::sys::curl::{
    CURLE_OK, CURLINFO_RESPONSE_CODE, CURLOPT_HEADERDATA, CURLOPT_HEADERFUNCTION,
    CURLOPT_HTTPHEADER, CURLOPT_NOSIGNAL, CURLOPT_SSL_VERIFYHOST, CURLOPT_SSL_VERIFYPEER,
    CURLOPT_URL, CURLOPT_WRITEDATA, CURLOPT_WRITEFUNCTION, Curl, CurlCode, curl_easy_cleanup,
    curl_easy_getinfo, curl_easy_init, curl_easy_perform, set_callback, set_long, set_off, set_ptr,
};
use crate::sys::libc::{fchmod, mkstemp, unlink};
use crate::sys::zlib::{GzHeader, ZStream, deflate, deflateEnd, deflateInit2_, deflateSetHeader};
use crate::util::crypto_openssl::{
    Sha256Ctx, base64_encode, sha256_final, sha256_free, sha256_init, sha256_update,
};
use crate::util::decode::{upatch_decode_map_file_json_limit, upatch_decode_map_json_limit};
use crate::util::tls_openssl::tls_curl_policy;

/// S3_URL_MAX and the rest of the C's limits.
pub(super) const URL_MAX: usize = 4096;
const BUCKET_MAX: usize = 63;
const PREFIX_MAX: usize = 512;
const REGION_MAX: usize = 64;
const KEY_MAX: usize = 1024;
const HOST_MAX: usize = 256;
const DECODER_JSON_MAX: usize = 64 * 1024 * 1024;
const GZIP_BUFFER: usize = 64 * 1024;
const PATH_MAX: usize = 4096;

const CURLOPT_UPLOAD: c_int = 46;
const CURLOPT_READDATA: c_int = 10009;
const CURLOPT_READFUNCTION: c_int = 20012;
const CURLOPT_INFILESIZE_LARGE: c_int = 30115;
const CURLOPT_USERPWD: c_int = 10005;
const CURLOPT_AWS_SIGV4: c_int = 10305;

const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_NO_FLUSH: c_int = 0;
const Z_FINISH: c_int = 4;

fn env(name: &str) -> Option<Vec<u8>> {
    std::env::var_os(name)
        .map(OsStringExt::into_vec)
        .filter(|v| !v.is_empty())
}

fn shown(b: &[u8]) -> std::borrow::Cow<'_, str> {
    String::from_utf8_lossy(b)
}

/// A map's snapshot as it goes to S3: gzipped in an unlinked temporary
/// file, and the sizes and SHA-256 of the object.
pub(super) struct Snapshot {
    file: File,
    pub(super) json_bytes: u64,
    pub(super) object_bytes: u64,
    pub(super) sha256_hex: String,
    sha256_b64: String,
}

/// A temporary file no one else can open: made 0600 and unlinked.
fn temp_file() -> Result<File, c_int> {
    let dir = env("TMPDIR").unwrap_or_else(|| b"/tmp".to_vec());
    let path = [&dir[..], b"/shirudo-map-snapshot.XXXXXX"].concat();
    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    let mut path = CString::new(path)
        .map_err(|_| -EINVAL)?
        .into_bytes_with_nul();
    // SAFETY: the template, which mkstemp() fills in.
    let fd = unsafe { mkstemp(path.as_mut_ptr().cast()) };
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the descriptor mkstemp() opened, the file's from here.
    let file = unsafe { File::from_raw_fd(fd) };
    // SAFETY: the open file.
    if unsafe { fchmod(fd, 0o600) } != 0 {
        let err = -errno();
        // SAFETY: the template's path, a C string.
        unsafe { unlink(path.as_ptr().cast()) };
        return Err(err);
    }
    // SAFETY: as above.
    if unsafe { unlink(path.as_ptr().cast()) } != 0 {
        return Err(-errno());
    }
    Ok(file)
}

fn errno() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EIO)
}

/// The gzip stream of a snapshot into its file, hashed as it goes. A
/// header of time 0 makes the same JSON the same object.
struct Writer {
    file: File,
    z: Box<ZStream>,
    header: Box<GzHeader>,
    md: Sha256Ctx,
    json_bytes: u64,
    object_bytes: u64,
    deflating: bool,
}

impl Writer {
    fn new(file: File) -> Result<Self, c_int> {
        let mut w = Writer {
            file,
            z: Box::new(ZStream::zeroed()),
            header: Box::new(GzHeader::zeroed()),
            md: Sha256Ctx::new(),
            json_bytes: 0,
            object_bytes: 0,
            deflating: false,
        };
        // SAFETY: the context, set up once.
        if unsafe { sha256_init(&mut w.md) } != 0 {
            return Err(-EIO);
        }
        // SAFETY: the stream, gzip framing, and the zlib it was built for.
        let zr = unsafe {
            deflateInit2_(
                &mut *w.z,
                -1,
                8,
                15 + 16,
                8,
                0,
                crate::sys::zlib::ZLIB_VERSION.as_ptr(),
                size_of::<ZStream>() as c_int,
            )
        };
        if zr != Z_OK {
            return Err(-EIO);
        }
        w.deflating = true;
        w.header.time = 0;
        w.header.os = 255;
        // SAFETY: the stream and the header, which outlives it.
        if unsafe { deflateSetHeader(&mut *w.z, &mut *w.header) } != Z_OK {
            return Err(-EIO);
        }
        Ok(w)
    }

    fn write_compressed(&mut self, data: &[u8]) -> Result<(), c_int> {
        let total = self
            .object_bytes
            .checked_add(data.len() as u64)
            .ok_or(-EOVERFLOW)?;
        if !data.is_empty() {
            self.file.write_all(data).map_err(|_| -EIO)?;
            // SAFETY: the context and the bytes.
            if unsafe { sha256_update(&mut self.md, data.as_ptr().cast(), data.len()) } != 0 {
                return Err(-EIO);
            }
        }
        self.object_bytes = total;
        Ok(())
    }

    /// One round of deflate() into a buffer, and what it made written.
    fn round(&mut self, flush: c_int) -> Result<c_int, c_int> {
        let mut out = vec![0u8; GZIP_BUFFER];
        self.z.next_out = out.as_mut_ptr();
        self.z.avail_out = GZIP_BUFFER as u32;
        // SAFETY: the stream, its input set by the caller and its output
        // here.
        let zr = unsafe { deflate(&mut *self.z, flush) };
        let produced = GZIP_BUFFER - self.z.avail_out as usize;
        if zr != Z_OK && !(flush == Z_FINISH && zr == Z_STREAM_END) {
            return Err(-EIO);
        }
        self.write_compressed(&out[..produced])?;
        Ok(zr)
    }

    fn json(&mut self, mut data: &[u8]) -> Result<(), c_int> {
        self.json_bytes = self
            .json_bytes
            .checked_add(data.len() as u64)
            .ok_or(-EOVERFLOW)?;
        while !data.is_empty() {
            let chunk = data.len().min(u32::MAX as usize);
            self.z.next_in = data.as_ptr().cast_mut();
            self.z.avail_in = chunk as u32;
            while self.z.avail_in != 0 {
                self.round(Z_NO_FLUSH)?;
            }
            data = &data[chunk..];
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Snapshot, c_int> {
        while self.round(Z_FINISH)? != Z_STREAM_END {}
        self.deflating = false;
        // SAFETY: the stream, ended once.
        if unsafe { deflateEnd(&mut *self.z) } != Z_OK {
            return Err(-EIO);
        }
        let mut sha256 = [0u8; 32];
        // SAFETY: the context and room for its digest.
        if unsafe { sha256_final(&mut self.md, sha256.as_mut_ptr()) } != 0 {
            return Err(-EIO);
        }
        self.file.flush().map_err(|_| -EIO)?;
        self.file.seek(SeekFrom::Start(0)).map_err(|_| -EIO)?;
        let mut b64 = [0u8; 45];
        // SAFETY: the digest and room for its 44 characters and a NUL.
        if unsafe { base64_encode(sha256.as_ptr(), 32, b64.as_mut_ptr().cast(), b64.len()) } != 0 {
            return Err(-EIO);
        }
        let file = self.file.try_clone().map_err(|_| -EIO)?;
        Ok(Snapshot {
            file,
            json_bytes: self.json_bytes,
            object_bytes: self.object_bytes,
            sha256_hex: String::from_utf8_lossy(&super::hex_lower(&sha256)).into_owned(),
            sha256_b64: String::from_utf8_lossy(&b64[..44]).into_owned(),
        })
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if self.deflating {
            // SAFETY: the stream, ended once.
            unsafe { deflateEnd(&mut *self.z) };
        }
        // SAFETY: the context, freed once.
        unsafe { sha256_free(&mut self.md) };
    }
}

/// The canonical value the signed decoder returns, gzipped: S3 stores
/// exactly that.
fn snapshot(decoder_path: Option<&CStr>, v: &MapView) -> Result<Snapshot, c_int> {
    let (mut out, mut len) = (core::ptr::null_mut(), 0usize);
    // SAFETY: a C string or none, the view and rooms for the output.
    let ret = unsafe {
        match decoder_path {
            Some(p) => upatch_decode_map_file_json_limit(
                p.as_ptr(),
                v,
                DECODER_JSON_MAX,
                &mut out,
                &mut len,
            ),
            None => upatch_decode_map_json_limit(v, DECODER_JSON_MAX, &mut out, &mut len),
        }
    };
    let decoded = Decoded { ptr: out, len };
    if ret != 0 {
        return Err(ret);
    }
    let mut w = Writer::new(temp_file()?)?;
    w.json(decoded.bytes())?;
    drop(decoded);
    w.finish()
}

fn valid_bucket(b: &[u8]) -> bool {
    (3..=BUCKET_MAX).contains(&b.len())
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter()
            .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
}

fn valid_region(r: &[u8]) -> bool {
    !r.is_empty()
        && r.len() < REGION_MAX
        && r.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'-')
}

/// Whether the key prefix names no `.` or `..` segment and holds no
/// control character, `?` or `#`.
fn valid_prefix(p: &[u8]) -> bool {
    p.iter().all(|&c| c >= 0x20 && c != b'?' && c != b'#')
        && p.split(|&c| c == b'/')
            .all(|seg| seg != b"." && seg != b"..")
}

/// An S3 destination, `s3://bucket[/prefix]`, and the AWS settings.
struct S3 {
    otel: Option<Box<Transport>>,
    opts: OtelOpts,
    bucket: Vec<u8>,
    prefix: Vec<u8>,
    region: Vec<u8>,
    endpoint: Option<Vec<u8>>,
    credentials: CString,
    session_token: Option<Vec<u8>>,
    ca_file: Option<CString>,
    insecure_tls: bool,
}

impl Drop for S3 {
    fn drop(&mut self) {
        self.otel = None;
        let mut c = core::mem::take(&mut self.credentials).into_bytes_with_nul();
        c.fill(0);
    }
}

impl S3 {
    fn parse(spec: &[u8], opts: OtelOpts) -> Result<Self, c_int> {
        let rest = spec.strip_prefix(b"s3://").ok_or(-EINVAL)?;
        let slash = rest.iter().position(|&c| c == b'/');
        let bucket = &rest[..slash.unwrap_or(rest.len())];
        if !valid_bucket(bucket) {
            return Err(-EINVAL);
        }
        let mut prefix = slash.map_or(&b""[..], |s| &rest[s + 1..]);
        while let Some(p) = prefix.strip_prefix(b"/") {
            prefix = p;
        }
        while let Some(p) = prefix.strip_suffix(b"/") {
            prefix = p;
        }
        if prefix.len() > PREFIX_MAX {
            return Err(-ENAMETOOLONG);
        }
        if !valid_prefix(prefix) {
            return Err(-EINVAL);
        }
        let region = env("AWS_REGION")
            .or_else(|| env("AWS_DEFAULT_REGION"))
            .unwrap_or_else(|| b"us-east-1".to_vec());
        if !valid_region(&region) {
            return Err(-EINVAL);
        }
        let endpoint = match env("AWS_ENDPOINT_URL_S3") {
            Some(e) if e.len() >= ENDPOINT_MAX => return Err(-ENAMETOOLONG),
            Some(mut e) => {
                while e.last() == Some(&b'/') {
                    e.pop();
                }
                if e.is_empty() {
                    return Err(-EINVAL);
                }
                Some(e)
            }
            None => None,
        };
        let (access, secret) = (env("AWS_ACCESS_KEY_ID"), env("AWS_SECRET_ACCESS_KEY"));
        let (Some(access), Some(secret)) = (access, secret) else {
            return Err(-EACCES);
        };
        if access.iter().any(|c| b"\r\n:".contains(c)) || secret.iter().any(|c| b"\r\n".contains(c))
        {
            return Err(-EACCES);
        }
        let credentials =
            CString::new([&access[..], b":", &secret].concat()).map_err(|_| -EINVAL)?;
        // A session token set empty is refused, not taken as unset.
        let session_token = std::env::var_os("AWS_SESSION_TOKEN").map(OsStringExt::into_vec);
        if session_token
            .as_ref()
            .is_some_and(|t| t.is_empty() || t.iter().any(|c| b"\r\n".contains(c)))
        {
            return Err(-EINVAL);
        }
        Ok(S3 {
            otel: None,
            opts,
            bucket: bucket.to_vec(),
            prefix: prefix.to_vec(),
            region,
            endpoint,
            credentials,
            session_token,
            ca_file: env("AWS_CA_BUNDLE").and_then(|c| CString::new(c).ok()),
            insecure_tls: false,
        })
    }

    /// Whether a custom endpoint may carry the snapshots and the
    /// credentials, as an OTLP endpoint may the data.
    fn validate_endpoint(&mut self) -> Result<(), c_int> {
        let Some(endpoint) = &self.endpoint else {
            if self.opts.allow_insecure {
                self.insecure_tls = true;
                eprint(b"WARNING: --otel-insecure disables TLS certificate and hostname verification for Amazon S3\n");
            }
            return Ok(());
        };
        let (scheme, host) = url_parts(endpoint)?;
        if endpoint.contains(&b'?') || endpoint.contains(&b'#') {
            return Err(-EINVAL);
        }
        if host.len() >= HOST_MAX {
            return Err(-ENAMETOOLONG);
        }
        match &scheme[..] {
            b"http" => {
                if !loopback_host(&host) && !self.opts.allow_insecure {
                    return Err(-EPERM);
                }
                if self.opts.allow_insecure {
                    eprint(
                        format!(
                            "WARNING: --otel-insecure sends S3 snapshots and credentials to http://{} without encryption\n",
                            shown(&host)
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
                            "WARNING: --otel-insecure disables TLS certificate and hostname verification for S3 endpoint {}\n",
                            shown(&host)
                        )
                        .as_bytes(),
                    );
                }
            }
            _ => return Err(-EPROTONOSUPPORT),
        }
        Ok(())
    }

    /// The object's key, `[prefix/]host/upatch/map/sha256.json.gz`, its
    /// s3:// URI and the URL it is PUT to.
    fn urls(&self, v: &MapView, s: &Snapshot) -> Result<(Vec<u8>, Vec<u8>), c_int> {
        let host: Vec<u8> = otlp::hostname()
            .into_iter()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.') {
                    c
                } else {
                    b'_'
                }
            })
            .collect();
        let sep: &[u8] = if self.prefix.is_empty() { b"" } else { b"/" };
        let key = [
            &self.prefix[..],
            sep,
            &host,
            b"/",
            crate::text::cstr(&v.upatch),
            b"/",
            crate::text::cstr(&v.name),
            b"/",
            s.sha256_hex.as_bytes(),
            b".json.gz",
        ]
        .concat();
        if key.len() > KEY_MAX {
            return Err(-ENAMETOOLONG);
        }
        let mut escaped = Vec::with_capacity(key.len());
        for &c in &key {
            if c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.' | b'~' | b'/') {
                escaped.push(c);
            } else {
                escaped.extend_from_slice(format!("%{c:02X}").as_bytes());
            }
        }
        let uri = [&b"s3://"[..], &self.bucket, b"/", &escaped].concat();
        let region = &self.region[..];
        let url = match &self.endpoint {
            Some(e) => [&e[..], b"/", &self.bucket, b"/", &escaped].concat(),
            None if self.bucket.contains(&b'.') => [
                &b"https://s3."[..],
                region,
                b".amazonaws.com/",
                &self.bucket,
                b"/",
                &escaped,
            ]
            .concat(),
            None => [
                &b"https://"[..],
                &self.bucket,
                b".s3.",
                region,
                b".amazonaws.com/",
                &escaped,
            ]
            .concat(),
        };
        if uri.len() >= URL_MAX || url.len() >= URL_MAX {
            return Err(-ENAMETOOLONG);
        }
        Ok((url, uri))
    }

    fn headers(&self, v: &MapView, s: &Snapshot) -> Result<Slist, c_int> {
        let mut list = Slist::default();
        let lines: [Vec<u8>; 10] = [
            b"Content-Type: application/json".to_vec(),
            b"Content-Encoding: gzip".to_vec(),
            b"Cache-Control: immutable".to_vec(),
            b"If-None-Match: *".to_vec(),
            b"Expect:".to_vec(),
            [&b"x-amz-content-sha256: "[..], s.sha256_hex.as_bytes()].concat(),
            [&b"x-amz-checksum-sha256: "[..], s.sha256_b64.as_bytes()].concat(),
            b"x-amz-meta-shirudo-schema: 1".to_vec(),
            [
                &b"x-amz-meta-shirudo-upatch: "[..],
                crate::text::cstr(&v.upatch),
            ]
            .concat(),
            [&b"x-amz-meta-shirudo-map: "[..], crate::text::cstr(&v.name)].concat(),
        ];
        for line in lines.iter().chain(
            self.session_token
                .as_ref()
                .map(|t| [&b"x-amz-security-token: "[..], t].concat())
                .iter(),
        ) {
            if line.len() >= 512 && !line.starts_with(b"x-amz-security-token") {
                return Err(-E2BIG);
            }
            match list.append(line) {
                0 => {}
                err => return Err(err),
            }
        }
        Ok(list)
    }

    /// PUTs the snapshot unless an object of its name is there, which
    /// the SHA-256 in the name makes the same: whether it was there.
    fn put(&self, v: &MapView, s: &mut Snapshot, url: &[u8]) -> Result<bool, c_int> {
        let max_attempts = self.opts.retries.checked_add(1).ok_or(-EINVAL)?;
        let headers = self.headers(v, s)?;
        let sigv4 =
            CString::new(format!("aws:amz:{}:s3", shown(&self.region))).map_err(|_| -EINVAL)?;
        let url = CString::new(url).map_err(|_| -EINVAL)?;
        let mut ret = Err(-EIO);
        for attempt in 0..max_attempts {
            let mut response = Response::new();
            // SAFETY: a new handle.
            let curl = unsafe { curl_easy_init() };
            if curl.is_null() {
                ret = Err(-ENOMEM);
                break;
            }
            if s.file.seek(SeekFrom::Start(0)).is_err() {
                // SAFETY: the handle, freed once.
                unsafe { curl_easy_cleanup(curl) };
                ret = Err(-EIO);
                break;
            }
            let (code, status) = match self.perform(curl, s, &url, &headers, &sigv4, &mut response)
            {
                Ok(r) => r,
                Err(err) => {
                    // SAFETY: the handle, freed once.
                    unsafe { curl_easy_cleanup(curl) };
                    ret = Err(err);
                    break;
                }
            };
            // SAFETY: the handle, freed once.
            unsafe { curl_easy_cleanup(curl) };
            if code == CURLE_OK && matches!(status, 200 | 201 | 204 | 412) {
                ret = Ok(status == 412);
                break;
            }
            let retry = if code != CURLE_OK {
                retryable_curl(code)
            } else {
                matches!(status, 408 | 409 | 500) || retryable_http(status)
            };
            if code != CURLE_OK {
                eprint(
                    format!(
                        "otel.s3: upload attempt {}/{max_attempts} failed: {}\n",
                        attempt + 1,
                        curl_error(code)
                    )
                    .as_bytes(),
                );
            } else {
                eprint(
                    format!(
                        "otel.s3: upload attempt {}/{max_attempts} received HTTP {status}\n",
                        attempt + 1
                    )
                    .as_bytes(),
                );
            }
            ret = Err(attempt_error(code));
            if !retry || attempt + 1 == max_attempts {
                break;
            }
            retry_wait(attempt, response.retry_after());
        }
        ret
    }

    fn perform(
        &self,
        curl: *mut Curl,
        s: &mut Snapshot,
        url: &CStr,
        headers: &Slist,
        sigv4: &CStr,
        response: &mut Response,
    ) -> Result<(CurlCode, c_long), c_int> {
        let ctx: *mut Response = response;
        let file: *mut File = &mut s.file;
        // SAFETY: the handle, and options whose values outlive the
        // transfer: the URL, the file, the headers, the strings, the
        // response.
        unsafe {
            set_ptr(curl, CURLOPT_URL, url.as_ptr());
            set_long(curl, CURLOPT_UPLOAD, 1);
            set_ptr(curl, CURLOPT_READDATA, file);
            set_callback(curl, CURLOPT_READFUNCTION, read_file);
            set_off(curl, CURLOPT_INFILESIZE_LARGE, s.object_bytes as i64);
            set_ptr(curl, CURLOPT_HTTPHEADER, headers.raw());
            set_ptr(curl, CURLOPT_AWS_SIGV4, sigv4.as_ptr());
            set_ptr(curl, CURLOPT_USERPWD, self.credentials.as_ptr());
            set_ptr(curl, CURLOPT_USERAGENT, c"shirudo-S3-Exporter-C/1".as_ptr());
            set_callback(curl, CURLOPT_WRITEFUNCTION, response_write);
            set_ptr(curl, CURLOPT_WRITEDATA, ctx);
            set_callback(curl, CURLOPT_HEADERFUNCTION, response_header);
            set_ptr(curl, CURLOPT_HEADERDATA, ctx);
            set_long(curl, CURLOPT_NOSIGNAL, 1);
            set_long(curl, CURLOPT_TIMEOUT_MS, DEFAULT_TIMEOUT_MS);
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
                return Err(-EINVAL);
            }
            if let Some(ca) = &self.ca_file {
                set_ptr(curl, CURLOPT_CAINFO, ca.as_ptr());
            }
            let code = curl_easy_perform(curl);
            let mut status: c_long = 0;
            if code == CURLE_OK {
                curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &mut status);
            }
            Ok((code, status))
        }
    }

    fn emit(&self, v: &MapView) -> c_int {
        let decoder_path = self.otel.as_ref().and_then(|t| t.decoder_path());
        let mut s = match snapshot(decoder_path, v) {
            Ok(s) => s,
            Err(err) => return err,
        };
        let (url, uri) = match self.urls(v, &s) {
            Ok(u) => u,
            Err(err) => return err,
        };
        let present = match self.put(v, &mut s, &url) {
            Ok(p) => p,
            Err(err) => return err,
        };
        eprint(
            format!(
                "otel.s3: {} {} ({} bytes)\n",
                if present { "found" } else { "uploaded" },
                shown(&uri),
                s.object_bytes
            )
            .as_bytes(),
        );
        let reference = match otlp::s3_reference(v, &s, &uri) {
            Ok(r) => r,
            Err(err) => return err,
        };
        match &self.otel {
            Some(t) => t.post(reference.bytes()),
            None => -EINVAL,
        }
    }
}

/// curl's read callback: the snapshot file, as fread() would read it.
unsafe extern "C" fn read_file(ptr: *mut c_char, size: usize, n: usize, ctx: *mut c_void) -> usize {
    // SAFETY: the file the transfer was given.
    let file = unsafe { &mut *ctx.cast::<File>() };
    let Some(len) = size.checked_mul(n) else {
        return 0;
    };
    // SAFETY: curl's room for len bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(ptr.cast::<u8>(), len) };
    let mut done = 0;
    while done < len {
        match file.read(&mut buf[done..]) {
            Ok(0) | Err(_) => break,
            Ok(k) => done += k,
        }
    }
    done
}

/// Sends a snapshot of the map to the S3 destination `spec` and a log
/// that points at it.
pub(super) fn send(
    spec: &CStr,
    v: &MapView,
    opts: Option<&OtelOpts>,
    decoder_path: Option<&CStr>,
) -> c_int {
    if spec.is_empty() {
        return -EINVAL;
    }
    if v.skipped {
        return -EOPNOTSUPP;
    }
    if v.truncated {
        return -E2BIG;
    }
    let opts = opts.copied().unwrap_or(OtelOpts::defaults());
    let mut s3 = match S3::parse(spec.to_bytes(), opts) {
        Ok(s) => s,
        Err(err) => return err,
    };
    if let Err(err) = s3.validate_endpoint() {
        return err;
    }
    let opts = s3.opts;
    match http::open_for_map(opts.endpoint(), v, Some(&opts), false, LOG, decoder_path) {
        Ok(mut t) => {
            t.s3_reference = true;
            s3.otel = Some(t);
        }
        Err(err) => return err,
    }
    s3.emit(v)
}
