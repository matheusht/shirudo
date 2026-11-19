// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Transfers: one curl request with the registry's auth challenge
//! answered once, downloads into memory or a file, and uploads.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::ptr;

use super::auth::{encode_basic, parse_challenge, token_from_body};
use super::refs::{upload_location, url};
use super::{
    AUTH_VALUE_SIZE, BASIC_ENCODED_SIZE, BASIC_HEADER_SIZE, BpmBuffer, Descriptor, HttpResponse,
    MANIFEST_MEDIA, MAX_HTTP_BODY, MAX_PACKAGE_BYTES, OciClient, PATH_MAX, copy_string, cstr,
    digest_matches, is_space, strscpy, strsprintf,
};
use crate::errno::{
    E2BIG, EACCES, EFBIG, EHOSTUNREACH, EINVAL, EKEYREJECTED, ENAMETOOLONG, ENOENT, ENOMEM,
};
use crate::ffi;
use crate::heap::{xfree, xreallocarray};
use crate::sys::curl::{
    CURL_ERROR_SIZE, CURLE_FILESIZE_EXCEEDED, CURLE_OK, CURLOPT_CONNECTTIMEOUT,
    CURLOPT_CUSTOMREQUEST, CURLOPT_FOLLOWLOCATION, CURLOPT_HTTPGET, CURLOPT_LOW_SPEED_LIMIT,
    CURLOPT_LOW_SPEED_TIME, CURLOPT_MAXFILESIZE_LARGE, CURLOPT_MAXREDIRS, CURLOPT_NOBODY,
    CURLOPT_NOSIGNAL, CURLOPT_PROTOCOLS_STR, CURLOPT_REDIR_PROTOCOLS_STR, CURLOPT_SSL_VERIFYHOST,
    CURLOPT_SSL_VERIFYPEER, CURLOPT_TIMEOUT, CURLOPT_UNRESTRICTED_AUTH, CURLOPT_URL, CurlCode,
    CurlOff,
};
use crate::sys::libc::{self, SEEK_SET, scrub};
use crate::util::crypto_openssl::sha256;
use crate::util::curl::{Easy, Slist, strerror};
use crate::util::hex::encode;
use crate::util::io::write_complete;
use crate::util::tls_openssl::tls_curl_policy;

/// A download bounded by the size its manifest declares.
pub(super) struct FileSink {
    fd: c_int,
    err: c_int,
    room: u64,
    overflow: bool,
}

/// The bytes a buffer holds, none when it has no allocation.
pub(super) fn buffer_bytes(b: &BpmBuffer) -> &[u8] {
    // SAFETY: a buffer holds len bytes at data, or data is NULL.
    unsafe { ffi::slice(b.data, if b.data.is_null() { 0 } else { b.len }) }
}

pub(crate) fn buffer_free(b: &mut BpmBuffer) {
    // SAFETY: data is NULL or the cap bytes the xmalloc family gave.
    unsafe { xfree(b.data.cast(), b.cap) };
    *b = BpmBuffer::new();
}

fn buffer_append(b: &mut BpmBuffer, data: &[u8]) -> c_int {
    let len = data.len();

    if len >= MAX_HTTP_BODY - b.len {
        return -E2BIG;
    }
    let want = b.len + len;
    if want + 1 > b.cap {
        let mut cap = if b.cap != 0 { b.cap } else { 4096 };

        while cap <= want {
            if cap > MAX_HTTP_BODY / 2 {
                cap = MAX_HTTP_BODY;
                break;
            }
            cap *= 2;
        }
        // SAFETY: data is NULL or the cap bytes the xmalloc family gave,
        // and a failed call leaves it alone.
        let grown = unsafe { xreallocarray(b.data.cast(), b.cap, cap, 1) };
        if grown.is_null() {
            return -ENOMEM;
        }
        b.data = grown.cast();
        b.cap = cap;
    }
    // SAFETY: the buffer holds cap > want bytes, of which data fills
    // len from b.len and the NUL the next.
    unsafe {
        ptr::copy_nonoverlapping(data.as_ptr(), b.data.add(b.len), len);
        b.len = want;
        b.data.add(want).write(0);
    }
    0
}

unsafe extern "C" fn write_memory(
    data: *mut c_char,
    size: usize,
    nmemb: usize,
    ud: *mut c_void,
) -> usize {
    let n = size.wrapping_mul(nmemb);
    // SAFETY: curl hands over n bytes at data, and the response the
    // request set as its write data.
    let (data, r) = unsafe {
        (
            ffi::slice(data.cast::<u8>(), n),
            &mut *ud.cast::<HttpResponse>(),
        )
    };

    if buffer_append(&mut r.body, data) != 0 {
        0
    } else {
        n
    }
}

unsafe extern "C" fn write_file(
    data: *mut c_char,
    size: usize,
    nmemb: usize,
    ud: *mut c_void,
) -> usize {
    let n = size.wrapping_mul(nmemb);
    // SAFETY: the sink the request set as its write data.
    let s = unsafe { &mut *ud.cast::<FileSink>() };

    if n as u64 > s.room {
        s.overflow = true;
        return 0;
    }
    s.room -= n as u64;
    // SAFETY: curl hands over n bytes at data.
    s.err = unsafe { write_complete(s.fd, data.cast(), n) };
    if s.err != 0 { 0 } else { n }
}

/// The descriptor is the caller's: a body is restarted in place.
fn sink_restart(s: &mut FileSink, fd: c_int, room: u64) -> c_int {
    // SAFETY: plain system calls on the caller's descriptor.
    if unsafe { libc::ftruncate(fd, 0) } != 0 || unsafe { libc::lseek(fd, 0, SEEK_SET) } < 0 {
        return -libc::errno();
    }
    *s = FileSink {
        fd,
        err: 0,
        room,
        overflow: false,
    };
    0
}

fn starts_with_ci(s: &[u8], prefix: &[u8]) -> bool {
    s.get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn skip_space(s: &[u8]) -> &[u8] {
    let n = s.iter().take_while(|&&c| is_space(c)).count();

    &s[n..]
}

/// What a response header tells the client: the auth challenge, the
/// content type and an upload's location.
pub(super) fn header_line(r: &mut HttpResponse, line: &[u8]) {
    if starts_with_ci(line, b"WWW-Authenticate:") {
        if strscpy(&mut r.www_auth, skip_space(&line[17..])).is_err() {
            r.www_auth[0] = 0;
        }
    } else if starts_with_ci(line, b"Content-Type:") {
        let v = skip_space(&line[13..]);
        let end = v
            .iter()
            .position(|c| b" ;\r\n".contains(c))
            .unwrap_or(v.len());

        copy_string(&mut r.content_type, &v[..end]);
    } else if starts_with_ci(line, b"Location:") {
        let v = skip_space(&line[9..]);
        let end = v
            .iter()
            .position(|c| b"\r\n".contains(c))
            .unwrap_or(v.len());

        copy_string(&mut r.location, &v[..end]);
    }
}

pub(super) unsafe extern "C" fn header(
    data: *mut c_char,
    size: usize,
    nmemb: usize,
    ud: *mut c_void,
) -> usize {
    let n = size.wrapping_mul(nmemb);

    if n >= 4096 {
        return n;
    }
    // SAFETY: curl hands over n bytes at data, and the response the
    // request set as its header data.
    let (data, r) = unsafe {
        (
            ffi::slice(data.cast::<u8>(), n),
            &mut *ud.cast::<HttpResponse>(),
        )
    };
    header_line(r, cstr(data));
    n
}

/// The deadline of a transfer: a minute, and the time `room` bytes, the
/// most it may carry, take at 128 KiB a second.
fn transfer_seconds(room: u64) -> c_long {
    const BASE_S: u64 = 60;
    const RATE_MIN: u64 = 128 * 1024;

    c_long::try_from(BASE_S + room / RATE_MIN).unwrap_or(c_long::MAX)
}

/// A registry that stops answering, or answers a few bytes at a time,
/// must not hold a timer's unit, and with it the config operation lock
/// every other command waits for, longer than the most a transfer may
/// carry takes at a floor rate: `room` bytes, in a minute and at 128 KiB
/// a second.
fn deadlines(easy: &mut Easy<'_>, room: u64) {
    easy.set_long(CURLOPT_CONNECTTIMEOUT, 30);
    easy.set_long(CURLOPT_LOW_SPEED_LIMIT, 1);
    easy.set_long(CURLOPT_LOW_SPEED_TIME, 60);
    easy.set_long(CURLOPT_TIMEOUT, transfer_seconds(room));
}

/// A `Name: value` header appended to `list` through a buffer of `CAP`
/// bytes, scrubbed after: -E2BIG when it does not fit, -ENOMEM.
fn append_header<const CAP: usize>(
    list: &mut Slist,
    name: &[u8],
    value: &[u8],
) -> Result<(), c_int> {
    let mut h = [0u8; CAP];
    let ret = match strsprintf(&mut h, &[name, value]) {
        Ok(_) => list.append(cstr(&h)),
        Err(_) => -E2BIG,
    };

    scrub(&mut h);
    if ret != 0 { Err(ret) } else { Ok(()) }
}

/// The header lines `req` sends, with `auth` as its Authorization.
fn request_headers(req: &Request, auth: Option<&[u8]>) -> Result<Slist, c_int> {
    let mut headers = Slist::default();

    if let Some(accept) = req.accept {
        append_header::<256>(&mut headers, b"Accept: ", accept.to_bytes())?;
    }
    if let Some(content_type) = req.content_type {
        append_header::<256>(&mut headers, b"Content-Type: ", content_type.to_bytes())?;
    }
    if let Some(auth) = auth {
        append_header::<8192>(&mut headers, b"Authorization: ", auth)?;
    }
    Ok(headers)
}

/// What one request sends.
pub(super) struct Request<'a> {
    pub method: &'a CStr,
    pub url: &'a CStr,
    pub accept: Option<&'a CStr>,
    pub content_type: Option<&'a CStr>,
    pub body: Option<&'a [u8]>,
}

fn curl_once(
    c: &mut OciClient,
    req: &Request,
    auth: Option<&[u8]>,
    r: &mut HttpResponse,
    mut file: Option<&mut FileSink>,
    follow: bool,
) -> c_int {
    let headers = match request_headers(req, auth) {
        Ok(headers) => headers,
        Err(err) => return err,
    };
    let mut errbuf = [0u8; CURL_ERROR_SIZE];
    let mut easy = match Easy::new() {
        Ok(easy) => easy,
        Err(err) => return err,
    };
    // The package's declared size for a download to disk, the in-memory
    // cap otherwise, and the request body for an upload.
    let room = file.as_ref().map_or(MAX_HTTP_BODY as u64, |f| f.room)
        + req.body.map_or(0, |b| b.len() as u64);
    let r_ptr = ptr::from_mut(r);

    easy.set_str(CURLOPT_URL, req.url);
    easy.set_str(CURLOPT_CUSTOMREQUEST, req.method);
    if req.method.to_bytes().eq_ignore_ascii_case(b"HEAD") {
        easy.set_long(CURLOPT_NOBODY, 1);
    }
    easy.set_headers(&headers);
    easy.set_error_buffer(&mut errbuf);
    easy.set_long(CURLOPT_NOSIGNAL, 1);
    deadlines(&mut easy, room);
    // OCI registries commonly redirect blob GETs to a signed CDN URL.
    // Follow only for blobs, never for manifest or upload calls.
    easy.set_long(CURLOPT_FOLLOWLOCATION, c_long::from(follow));
    if follow {
        follow_redirects(&mut easy, &c.base_url);
    }
    easy.set_long(CURLOPT_SSL_VERIFYPEER, 1);
    easy.set_long(CURLOPT_SSL_VERIFYHOST, 2);
    if tls_curl_policy(&mut easy, Some(as_cstr(&c.ca_file))).is_err() {
        crate::log::err(
            &[
                &b"bpm OCI request "[..],
                req.url.to_bytes(),
                b": cannot apply TLS policy",
            ]
            .concat(),
        );
        return -EHOSTUNREACH;
    }
    if let Some(body) = req.body {
        easy.set_post_fields(body);
    }
    match file.as_deref_mut() {
        Some(f) => {
            easy.set_off(CURLOPT_MAXFILESIZE_LARGE, f.room as CurlOff);
            // SAFETY: write_file() takes its data for the sink, which
            // outlives the handle and which nothing else touches while
            // the transfer runs.
            unsafe { easy.set_write(write_file, ptr::from_mut(f)) };
        }
        // SAFETY: write_memory() takes its data for the response, which
        // outlives the handle and which only the callbacks touch while
        // the transfer runs.
        None => unsafe { easy.set_write(write_memory, r_ptr) },
    }
    // SAFETY: header() takes its data for the response, as above.
    unsafe { easy.set_header(header, r_ptr) };
    let cc = easy.perform();
    let mut status = easy.response_code().unwrap_or(0);
    drop(easy);
    r.status = status;
    if cc != CURLE_OK {
        log_failure(req.url, &errbuf, cc);
        status = -1;
    }
    if let Some(f) = file
        && cc == CURLE_FILESIZE_EXCEEDED
    {
        f.overflow = true;
    }
    if status < 0 { -EHOSTUNREACH } else { 0 }
}

/// Up to five redirects, over no weaker a transport than the registry's
/// own, and the Authorization kept to the registry's host.
fn follow_redirects(easy: &mut Easy<'_>, base_url: &[u8]) {
    let protocols: &CStr = if base_url.starts_with(b"https://") {
        c"https"
    } else {
        c"http,https"
    };

    easy.set_long(CURLOPT_MAXREDIRS, 5);
    easy.set_str(CURLOPT_REDIR_PROTOCOLS_STR, protocols);
    // Keep Authorization restricted to the original registry host.
    easy.set_long(CURLOPT_UNRESTRICTED_AUTH, 0);
}

/// Why the request to `url` failed: the message libcurl left in
/// `errbuf`, or the text of `cc` when it left none.
fn log_failure(url: &CStr, errbuf: &[u8; CURL_ERROR_SIZE], cc: CurlCode) {
    let reason = if errbuf[0] != 0 {
        cstr(errbuf)
    } else {
        strerror(cc).to_bytes()
    };

    crate::log::err(&[&b"bpm OCI request "[..], url.to_bytes(), b": ", reason].concat());
}

/// A token for the registry: BPM_OCI_BEARER_TOKEN, or the answer of the
/// token server the challenge names, asked with Basic credentials when
/// the client has them.
fn get_bearer_token(c: &mut OciClient, challenge: &[u8]) -> c_int {
    let mut realm = [0u8; PATH_MAX];
    let mut service = [0u8; 256];
    let mut scope = [0u8; 512];

    if let Some(token) = libc::env(c"BPM_OCI_BEARER_TOKEN").filter(|t| !t.is_empty()) {
        if token.to_bytes().len() >= c.token.len() {
            return -E2BIG;
        }
        copy_string(&mut c.token, token.to_bytes());
        return 0;
    }
    if parse_challenge(challenge, &mut realm, &mut service, &mut scope) != 0 {
        return -EINVAL;
    }
    let mut basic = [0u8; BASIC_ENCODED_SIZE];
    let mut auth_header = [0u8; BASIC_HEADER_SIZE];
    let mut headers = Slist::default();
    let mut r = HttpResponse::new();

    let ret = token_exchange(
        c,
        &realm,
        &service,
        &scope,
        &mut basic,
        &mut auth_header,
        &mut headers,
        &mut r,
    );
    scrub(&mut basic);
    scrub(&mut auth_header);
    buffer_free(&mut r.body);
    ret
}

#[allow(clippy::too_many_arguments)]
fn token_exchange(
    c: &mut OciClient,
    realm: &[u8],
    service: &[u8],
    scope: &[u8],
    basic: &mut [u8],
    auth_header: &mut [u8],
    headers: &mut Slist,
    r: &mut HttpResponse,
) -> c_int {
    let mut url = [0u8; PATH_MAX * 2];
    let mut ret = -EINVAL;
    let mut easy = match Easy::new() {
        Ok(easy) => easy,
        Err(err) => return err,
    };

    let esc_service = easy.escape(as_cstr(service));
    let esc_scope = easy.escape(as_cstr(scope));
    let (Some(esc_service), Some(esc_scope)) = (esc_service, esc_scope) else {
        return ret;
    };
    if strsprintf(
        &mut url,
        &[
            cstr(realm),
            b"?service=",
            &esc_service,
            b"&scope=",
            &esc_scope,
        ],
    )
    .is_err()
    {
        return -ENAMETOOLONG;
    }
    if c.username[0] != 0 {
        ret = encode_basic(cstr(&c.username), cstr(&c.password), basic);
        if ret != 0 {
            return ret;
        }
        if strsprintf(auth_header, &[b"Authorization: Basic ", cstr(basic)]).is_err() {
            return -E2BIG;
        }
        ret = headers.append(cstr(auth_header));
        if ret != 0 {
            return ret;
        }
    }
    // The realm is the registry's to name and the credentials go there:
    // over no weaker a transport than the registry's own.
    let protocols: &CStr = if c.base_url.starts_with(b"https://") {
        c"https"
    } else {
        c"http,https"
    };
    easy.set_str(CURLOPT_URL, as_cstr(&url));
    easy.set_str(CURLOPT_PROTOCOLS_STR, protocols);
    easy.set_long(CURLOPT_HTTPGET, 1);
    easy.set_headers(headers);
    easy.set_long(CURLOPT_NOSIGNAL, 1);
    deadlines(&mut easy, MAX_HTTP_BODY as u64);
    // SAFETY: write_memory() takes its data for the response, which
    // outlives the handle and which only the callback touches while the
    // transfer runs.
    unsafe { easy.set_write(write_memory, ptr::from_mut(r)) };
    easy.set_long(CURLOPT_SSL_VERIFYPEER, 1);
    easy.set_long(CURLOPT_SSL_VERIFYHOST, 2);
    if tls_curl_policy(&mut easy, Some(as_cstr(&c.ca_file))).is_err() {
        return -EINVAL;
    }
    let cc = easy.perform();
    if let Some(status) = easy.response_code() {
        r.status = status;
    }
    if cc != CURLE_OK {
        return -EHOSTUNREACH;
    }
    if r.status >= 300 {
        return -EACCES;
    }
    // curl never calls the write callback for an empty body.
    if r.body.data.is_null() {
        return ret;
    }
    token_from_body(cstr(buffer_bytes(&r.body)), &mut c.token)
}

/// The value of the Authorization header that answers the challenge of
/// `r`: a Bearer token, Basic credentials, or -EACCES for anything else.
fn answer_challenge(c: &mut OciClient, www_auth: &[u8], auth: &mut [u8]) -> c_int {
    if starts_with_ci(www_auth, b"Bearer") {
        let ret = get_bearer_token(c, www_auth);

        if ret == 0 && strsprintf(auth, &[b"Bearer ", cstr(&c.token)]).is_err() {
            return -E2BIG;
        }
        ret
    } else if starts_with_ci(www_auth, b"Basic") && c.username[0] != 0 {
        basic_auth(c, auth)
    } else {
        -EACCES
    }
}

fn basic_auth(c: &OciClient, auth: &mut [u8]) -> c_int {
    let mut encoded = [0u8; BASIC_ENCODED_SIZE];
    let mut ret = encode_basic(cstr(&c.username), cstr(&c.password), &mut encoded);

    if ret == 0 && strsprintf(auth, &[b"Basic ", cstr(&encoded)]).is_err() {
        ret = -E2BIG;
    }
    scrub(&mut encoded);
    ret
}

fn status_errno(status: c_long) -> c_int {
    if status == 404 { -ENOENT } else { -EACCES }
}

pub(crate) fn get_memory(
    c: &mut OciClient,
    url: &CStr,
    accept: Option<&CStr>,
    out: &mut BpmBuffer,
    follow: bool,
) -> c_int {
    let mut r = HttpResponse::new();
    let ret = get_memory_into(c, url, accept, out, follow, &mut r);

    buffer_free(&mut r.body);
    ret
}

fn get_memory_into(
    c: &mut OciClient,
    url: &CStr,
    accept: Option<&CStr>,
    out: &mut BpmBuffer,
    follow: bool,
    r: &mut HttpResponse,
) -> c_int {
    let req = Request {
        method: c"GET",
        url,
        accept,
        content_type: None,
        body: None,
    };
    let mut auth = [0u8; AUTH_VALUE_SIZE];
    let mut ret = curl_once(c, &req, None, r, None, follow);

    if ret != 0 {
        return ret;
    }
    if r.status == 401 && r.www_auth[0] != 0 {
        let www_auth = r.www_auth;

        ret = answer_challenge(c, cstr(&www_auth), &mut auth);
        if ret == 0 {
            buffer_free(&mut r.body);
            *r = HttpResponse::new();
            ret = curl_once(c, &req, Some(cstr(&auth)), r, None, follow);
        }
        scrub(&mut auth);
        if ret != 0 {
            return ret;
        }
    }
    if !(200..300).contains(&r.status) {
        return status_errno(r.status);
    }
    *out = core::mem::replace(&mut r.body, BpmBuffer::new());
    0
}

pub(super) fn get_file(
    c: &mut OciClient,
    url: &CStr,
    accept: Option<&CStr>,
    fd: c_int,
    size: i64,
) -> c_int {
    let mut r = HttpResponse::new();
    let mut sink = FileSink {
        fd: 0,
        err: 0,
        room: 0,
        overflow: false,
    };
    let mut auth = [0u8; AUTH_VALUE_SIZE];

    if size < 0 || fd < 0 {
        return -EINVAL;
    }
    if size as u64 > MAX_PACKAGE_BYTES {
        return -EFBIG;
    }
    let mut ret = sink_restart(&mut sink, fd, size as u64);
    if ret != 0 {
        return ret;
    }
    let req = Request {
        method: c"GET",
        url,
        accept,
        content_type: None,
        body: None,
    };
    ret = curl_once(c, &req, None, &mut r, Some(&mut sink), true);
    let www_auth = r.www_auth;
    let challenge = cstr(&www_auth);
    if ret == 0 && r.status == 401 && !challenge.is_empty() && starts_with_ci(challenge, b"Bearer")
    {
        ret = sink_restart(&mut sink, fd, size as u64);
        if ret == 0 {
            ret = get_bearer_token(c, challenge);
        }
        if ret == 0 && strsprintf(&mut auth, &[b"Bearer ", cstr(&c.token)]).is_err() {
            ret = -E2BIG;
        }
        if ret == 0 {
            buffer_free(&mut r.body);
            r = HttpResponse::new();
            ret = curl_once(c, &req, Some(cstr(&auth)), &mut r, Some(&mut sink), true);
        }
    } else if ret == 0
        && r.status == 401
        && !challenge.is_empty()
        && starts_with_ci(challenge, b"Basic")
        && c.username[0] != 0
    {
        ret = sink_restart(&mut sink, fd, size as u64);
        if ret == 0 {
            ret = basic_auth(c, &mut auth);
        }
        if ret == 0 {
            buffer_free(&mut r.body);
            r = HttpResponse::new();
            ret = curl_once(c, &req, Some(cstr(&auth)), &mut r, Some(&mut sink), true);
        }
    }
    scrub(&mut auth);
    // A failed write ends the transfer too; it, not the transfer, is the cause.
    if sink.overflow {
        ret = -EFBIG;
    } else if sink.err != 0 {
        ret = sink.err;
    }
    if ret == 0 && !(200..300).contains(&r.status) {
        ret = status_errno(r.status);
    }
    buffer_free(&mut r.body);
    ret
}

/// A request for uploads: the response headers, Location among them, are
/// kept and a body goes along, and an auth challenge is answered once.
fn request(c: &mut OciClient, req: &Request, r: &mut HttpResponse) -> c_int {
    let mut auth = [0u8; AUTH_VALUE_SIZE];

    *r = HttpResponse::new();
    let mut ret = curl_once(c, req, None, r, None, false);
    if ret != 0 {
        return ret;
    }
    if r.status == 401 && r.www_auth[0] != 0 {
        let www_auth = r.www_auth;

        ret = answer_challenge(c, cstr(&www_auth), &mut auth);
        if ret == 0 {
            buffer_free(&mut r.body);
            *r = HttpResponse::new();
            ret = curl_once(c, req, Some(cstr(&auth)), r, None, false);
        }
        scrub(&mut auth);
        if ret != 0 {
            return ret;
        }
    }
    if !(200..300).contains(&r.status) {
        if r.status != 404 {
            let body = buffer_bytes(&r.body);

            if !body.is_empty() {
                let n = body.len().min(512);

                // As %.*s printed it: up to n bytes, ending at a NUL.
                crate::log::err(
                    &[
                        &b"bpm OCI request "[..],
                        req.url.to_bytes(),
                        format!(": HTTP {}: ", r.status).as_bytes(),
                        cstr(&body[..n]),
                    ]
                    .concat(),
                );
            } else {
                crate::log::err(
                    &[
                        &b"bpm OCI request "[..],
                        req.url.to_bytes(),
                        b": HTTP ",
                        format!("{}", r.status).as_bytes(),
                    ]
                    .concat(),
                );
            }
        }
        return status_errno(r.status);
    }
    0
}

/// The SHA-256 of `data` in lowercase hex, and a NUL, into `hex`.
pub(crate) fn sha256_hex(data: &[u8], hex: &mut [u8]) -> c_int {
    let (Some(out), Ok(digest)) = (hex.get_mut(..65), sha256(data)) else {
        return -EINVAL;
    };
    out[..64].copy_from_slice(&encode(&digest));
    out[64] = 0;
    0
}

/// The one payload and the one signature among a manifest's layers, each
/// matching its descriptor's digest and declared size.
pub(crate) fn get_signed(
    c: &mut OciClient,
    repository: &[u8],
    layers: &[Descriptor],
    payload_media: &[u8],
    sig_media: &[u8],
    payload: &mut BpmBuffer,
    sig: &mut BpmBuffer,
) -> c_int {
    let mut n_payload = 0;
    let mut n_sig = 0;
    let mut blob_url = [0u8; PATH_MAX];
    let mut hex = [0u8; 65];

    for layer in layers {
        let media = cstr(&layer.media);
        let (dst, seen) = if media == payload_media {
            (&mut *payload, &mut n_payload)
        } else if media == sig_media {
            (&mut *sig, &mut n_sig)
        } else {
            continue;
        };

        *seen += 1;
        if *seen > 1 {
            return -EINVAL;
        }
        let ret = url(c, repository, b"blobs", cstr(&layer.digest), &mut blob_url);
        if ret != 0 {
            return ret;
        }
        let blob_url = CStr::from_bytes_until_nul(&blob_url).map_err(|_| -EINVAL);
        let accept = CStr::from_bytes_until_nul(&layer.media).map_err(|_| -EINVAL);
        let (Ok(blob_url), Ok(accept)) = (blob_url, accept) else {
            return -EINVAL;
        };
        let ret = get_memory(c, blob_url, Some(accept), dst, true);
        if ret != 0 {
            return ret;
        }
        // SAFETY: the buffer the GET filled, len bytes at data.
        let got = unsafe { crate::ffi::slice(dst.data, dst.len) };
        if (layer.size >= 0 && dst.len as i64 != layer.size)
            || sha256_hex(got, &mut hex) != 0
            || !digest_matches(cstr(&layer.digest), cstr(&hex))
        {
            return -EKEYREJECTED;
        }
    }
    if !payload.data.is_null() && !sig.data.is_null() {
        0
    } else {
        -EINVAL
    }
}

fn descriptor(out: &mut Descriptor, media: &[u8], digest: &[u8], size: usize) {
    copy_string(&mut out.media, media);
    copy_string(&mut out.digest, digest);
    out.size = size as i64;
}

/// A blob uploaded unless the registry has it, and its descriptor.
pub(crate) fn push_blob(
    c: &mut OciClient,
    repository: &[u8],
    body: &[u8],
    media: &[u8],
    out: &mut Descriptor,
) -> c_int {
    let mut r = HttpResponse::new();
    let ret = push_blob_with(c, repository, body, media, out, &mut r);

    buffer_free(&mut r.body);
    ret
}

fn push_blob_with(
    c: &mut OciClient,
    repository: &[u8],
    body: &[u8],
    media: &[u8],
    out: &mut Descriptor,
    r: &mut HttpResponse,
) -> c_int {
    let mut hex = [0u8; 65];
    let mut digest = [0u8; 72];
    let mut blob_url = [0u8; PATH_MAX];
    let mut upload = [0u8; PATH_MAX];

    if sha256_hex(body, &mut hex) != 0 {
        return -EINVAL;
    }
    if strsprintf(&mut digest, &[b"sha256:", cstr(&hex)]).is_err() {
        return -ENAMETOOLONG;
    }
    let digest = cstr(&digest);
    let mut ret = url(c, repository, b"blobs", digest, &mut blob_url);
    if ret != 0 {
        return ret;
    }
    let head = Request {
        method: c"HEAD",
        url: as_cstr(&blob_url),
        accept: None,
        content_type: None,
        body: None,
    };
    ret = request(c, &head, r);
    buffer_free(&mut r.body);
    if ret == 0 {
        descriptor(out, media, digest, body.len());
        return 0;
    }
    if ret != -ENOENT {
        return ret;
    }
    ret = url(c, repository, b"blobs/uploads", b"", &mut blob_url);
    if ret != 0 {
        return ret;
    }
    let post = Request {
        method: c"POST",
        url: as_cstr(&blob_url),
        accept: None,
        content_type: None,
        body: None,
    };
    ret = request(c, &post, r);
    if ret != 0 {
        return ret;
    }
    if r.status != 202 || r.location[0] == 0 {
        return if r.status == 202 { -EINVAL } else { -EACCES };
    }
    let location = r.location;
    buffer_free(&mut r.body);
    *r = HttpResponse::new();
    ret = upload_location(c, cstr(&location), &mut upload);
    if ret != 0 {
        return ret;
    }
    let upload = cstr(&upload);
    let sep: &[u8] = if upload.contains(&b'?') { b"&" } else { b"?" };
    if strsprintf(&mut blob_url, &[upload, sep, b"digest=", digest]).is_err() {
        return -ENAMETOOLONG;
    }
    let put = Request {
        method: c"PUT",
        url: as_cstr(&blob_url),
        accept: None,
        content_type: Some(c"application/octet-stream"),
        body: Some(body),
    };
    ret = request(c, &put, r);
    if ret == 0 && r.status != 201 {
        ret = -EACCES;
    }
    if ret == 0 {
        descriptor(out, media, digest, body.len());
    }
    ret
}

/// A manifest put under `reference`, and its digest.
pub(crate) fn put_manifest(
    c: &mut OciClient,
    repository: &[u8],
    reference: &[u8],
    body: &[u8],
    digest: &mut [u8],
) -> c_int {
    let mut hex = [0u8; 65];
    let mut manifest_url = [0u8; PATH_MAX];
    let mut r = HttpResponse::new();

    if sha256_hex(body, &mut hex) != 0 || strsprintf(digest, &[b"sha256:", cstr(&hex)]).is_err() {
        return -ENAMETOOLONG;
    }
    let ret = url(c, repository, b"manifests", reference, &mut manifest_url);
    if ret != 0 {
        return ret;
    }
    let put = Request {
        method: c"PUT",
        url: as_cstr(&manifest_url),
        accept: Some(MANIFEST_MEDIA),
        content_type: Some(MANIFEST_MEDIA),
        body: Some(body),
    };
    let ret = request(c, &put, &mut r);
    buffer_free(&mut r.body);
    ret
}

/// A buffer strsprintf() terminated, as the C string it holds.
fn as_cstr(buf: &[u8]) -> &CStr {
    CStr::from_bytes_until_nul(buf).unwrap_or(c"")
}
