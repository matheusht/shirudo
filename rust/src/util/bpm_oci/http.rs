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
    MAX_HTTP_BODY, MAX_PACKAGE_BYTES, OciClient, PATH_MAX, c_ptr, copy_string, cstr,
    digest_matches, is_space, strscpy, strsprintf,
};
use crate::errno::{
    E2BIG, EACCES, EFBIG, EHOSTUNREACH, EINVAL, EKEYREJECTED, ENAMETOOLONG, ENOENT, ENOMEM,
};
use crate::ffi;
use crate::sys::crypto::{SHA256_LEN, sha256_buffer, tls_ca_cleanup, tls_curl_policy};
use crate::sys::curl::{self, Curl, CurlSlist};
use crate::sys::hex::hex_encode;
use crate::sys::io::write_complete;
use crate::sys::libc::{self, SEEK_SET, scrub};
use crate::sys::log::pr_err;
use crate::sys::malloc::{xfree, xreallocarray};

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

pub(super) fn buffer_free(b: &mut BpmBuffer) {
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

/// A registry that stops answering must not hold a timer's unit forever;
/// a slow transfer that still moves is left alone.
fn deadlines(handle: *mut Curl) {
    // SAFETY: a live handle and long options.
    unsafe {
        curl::set_long(handle, curl::CURLOPT_CONNECTTIMEOUT, 30);
        curl::set_long(handle, curl::CURLOPT_LOW_SPEED_LIMIT, 1);
        curl::set_long(handle, curl::CURLOPT_LOW_SPEED_TIME, 60);
    }
}

/// A `Name: value` header appended to `list` through a buffer of `CAP`
/// bytes, scrubbed after: -E2BIG when it does not fit, -ENOMEM.
fn append_header<const CAP: usize>(list: &mut *mut CurlSlist, name: &[u8], value: &[u8]) -> c_int {
    let mut h = [0u8; CAP];
    let fits = strsprintf(&mut h, &[name, value]).is_ok();
    let next = if fits {
        // SAFETY: a NUL-terminated line, which curl copies.
        unsafe { curl::curl_slist_append(*list, c_ptr(&h)) }
    } else {
        ptr::null_mut()
    };

    scrub(&mut h);
    if !fits {
        return -E2BIG;
    }
    if next.is_null() {
        return -ENOMEM;
    }
    *list = next;
    0
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
    file: Option<&mut FileSink>,
    follow: bool,
) -> c_int {
    let mut headers: *mut CurlSlist = ptr::null_mut();
    let ret = curl_once_headers(c, req, auth, r, file, follow, &mut headers);

    // SAFETY: a list curl built, or NULL.
    unsafe { curl::curl_slist_free_all(headers) };
    ret
}

fn curl_once_headers(
    c: &mut OciClient,
    req: &Request,
    auth: Option<&[u8]>,
    r: &mut HttpResponse,
    file: Option<&mut FileSink>,
    follow: bool,
    headers: &mut *mut CurlSlist,
) -> c_int {
    let mut errbuf = [0u8; curl::CURL_ERROR_SIZE];
    let mut status: c_long = 0;

    if let Some(accept) = req.accept {
        let ret = append_header::<256>(headers, b"Accept: ", accept.to_bytes());
        if ret != 0 {
            return ret;
        }
    }
    if let Some(content_type) = req.content_type {
        let ret = append_header::<256>(headers, b"Content-Type: ", content_type.to_bytes());
        if ret != 0 {
            return ret;
        }
    }
    if let Some(auth) = auth {
        let ret = append_header::<8192>(headers, b"Authorization: ", auth);
        if ret != 0 {
            return ret;
        }
    }
    // SAFETY: curl_easy_init() takes nothing.
    let handle = unsafe { curl::curl_easy_init() };
    if handle.is_null() {
        return -ENOMEM;
    }
    let file_ptr = file.map(|f| f as *mut FileSink);
    let r_ptr = ptr::from_mut(r);
    // SAFETY: a live handle; every pointer set, the URL, method, header
    // list, error buffer, body, response and sink, outlives the transfer,
    // and nothing touches them through another path until it ends.
    let cc = unsafe {
        curl::set_ptr(handle, curl::CURLOPT_URL, req.url.as_ptr());
        curl::set_ptr(handle, curl::CURLOPT_CUSTOMREQUEST, req.method.as_ptr());
        if req.method.to_bytes().eq_ignore_ascii_case(b"HEAD") {
            curl::set_long(handle, curl::CURLOPT_NOBODY, 1);
        }
        curl::set_ptr(handle, curl::CURLOPT_HTTPHEADER, *headers);
        curl::set_ptr(handle, curl::CURLOPT_ERRORBUFFER, errbuf.as_mut_ptr());
        curl::set_long(handle, curl::CURLOPT_NOSIGNAL, 1);
        deadlines(handle);
        // OCI registries commonly redirect blob GETs to a signed CDN URL.
        // Follow only for blobs, never for manifest or upload calls.
        curl::set_long(handle, curl::CURLOPT_FOLLOWLOCATION, c_long::from(follow));
        if follow {
            let protocols: &CStr = if c.base_url.starts_with(b"https://") {
                c"https"
            } else {
                c"http,https"
            };

            curl::set_long(handle, curl::CURLOPT_MAXREDIRS, 5);
            curl::set_ptr(
                handle,
                curl::CURLOPT_REDIR_PROTOCOLS_STR,
                protocols.as_ptr(),
            );
            // Keep Authorization restricted to the original registry host.
            curl::set_long(handle, curl::CURLOPT_UNRESTRICTED_AUTH, 0);
        }
        curl::set_long(handle, curl::CURLOPT_SSL_VERIFYPEER, 1);
        curl::set_long(handle, curl::CURLOPT_SSL_VERIFYHOST, 2);
        if tls_curl_policy(handle, &mut c.tls_ca) != 0 {
            pr_err(
                c"bpm OCI request %s: cannot apply TLS policy".as_ptr(),
                req.url.as_ptr(),
            );
            curl::curl_easy_cleanup(handle);
            return -EHOSTUNREACH;
        }
        if let Some(body) = req.body {
            curl::set_ptr(handle, curl::CURLOPT_POSTFIELDS, body.as_ptr());
            curl::set_off(
                handle,
                curl::CURLOPT_POSTFIELDSIZE_LARGE,
                body.len() as curl::CurlOff,
            );
        }
        match file_ptr {
            Some(f) => {
                curl::set_off(
                    handle,
                    curl::CURLOPT_MAXFILESIZE_LARGE,
                    (*f).room as curl::CurlOff,
                );
                curl::set_callback(handle, curl::CURLOPT_WRITEFUNCTION, write_file);
                curl::set_ptr(handle, curl::CURLOPT_WRITEDATA, f);
            }
            None => {
                curl::set_callback(handle, curl::CURLOPT_WRITEFUNCTION, write_memory);
                curl::set_ptr(handle, curl::CURLOPT_WRITEDATA, r_ptr);
            }
        }
        curl::set_callback(handle, curl::CURLOPT_HEADERFUNCTION, header);
        curl::set_ptr(handle, curl::CURLOPT_HEADERDATA, r_ptr);
        let cc = curl::curl_easy_perform(handle);
        curl::curl_easy_getinfo(handle, curl::CURLINFO_RESPONSE_CODE, &raw mut status);
        cc
    };
    r.status = status;
    if cc != curl::CURLE_OK {
        let reason = if errbuf[0] != 0 {
            c_ptr(&errbuf)
        } else {
            // SAFETY: any code has a static message.
            unsafe { curl::curl_easy_strerror(cc) }
        };

        // SAFETY: the C format with two C strings.
        unsafe { pr_err(c"bpm OCI request %s: %s".as_ptr(), req.url.as_ptr(), reason) };
        status = -1;
    }
    if let Some(f) = file_ptr {
        if cc == curl::CURLE_FILESIZE_EXCEEDED {
            // SAFETY: the caller's sink, which the transfer is done with.
            unsafe { (*f).overflow = true };
        }
    }
    // SAFETY: the handle, done with, and the client's TLS state.
    unsafe {
        curl::curl_easy_cleanup(handle);
        tls_ca_cleanup(&mut c.tls_ca);
    }
    if status < 0 { -EHOSTUNREACH } else { 0 }
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
    // SAFETY: curl_easy_init() takes nothing.
    let handle = unsafe { curl::curl_easy_init() };
    if handle.is_null() {
        return -ENOMEM;
    }
    let mut basic = [0u8; BASIC_ENCODED_SIZE];
    let mut auth_header = [0u8; BASIC_HEADER_SIZE];
    let mut headers: *mut CurlSlist = ptr::null_mut();
    let mut r = HttpResponse::new();
    let mut esc = [ptr::null_mut::<c_char>(); 2];

    let ret = token_exchange(
        c,
        handle,
        &realm,
        &service,
        &scope,
        &mut basic,
        &mut auth_header,
        &mut headers,
        &mut r,
        &mut esc,
    );
    scrub(&mut basic);
    scrub(&mut auth_header);
    // SAFETY: what curl allocated for the escapes and the list, NULL when
    // it did not, the handle and the client's TLS state.
    unsafe {
        curl::curl_free(esc[0].cast());
        curl::curl_free(esc[1].cast());
        curl::curl_slist_free_all(headers);
        curl::curl_easy_cleanup(handle);
        tls_ca_cleanup(&mut c.tls_ca);
    }
    buffer_free(&mut r.body);
    ret
}

#[allow(clippy::too_many_arguments)]
fn token_exchange(
    c: &mut OciClient,
    handle: *mut Curl,
    realm: &[u8],
    service: &[u8],
    scope: &[u8],
    basic: &mut [u8],
    auth_header: &mut [u8],
    headers: &mut *mut CurlSlist,
    r: &mut HttpResponse,
    esc: &mut [*mut c_char; 2],
) -> c_int {
    let mut url = [0u8; PATH_MAX * 2];
    let mut ret = -EINVAL;

    // SAFETY: a live handle and NUL-terminated strings, which curl copies.
    unsafe {
        esc[0] = curl::curl_easy_escape(handle, c_ptr(service), 0);
        esc[1] = curl::curl_easy_escape(handle, c_ptr(scope), 0);
    }
    if esc[0].is_null() || esc[1].is_null() {
        return ret;
    }
    // SAFETY: curl_easy_escape() returns C strings.
    let (esc_service, esc_scope) = unsafe { (CStr::from_ptr(esc[0]), CStr::from_ptr(esc[1])) };
    if strsprintf(
        &mut url,
        &[
            cstr(realm),
            b"?service=",
            esc_service.to_bytes(),
            b"&scope=",
            esc_scope.to_bytes(),
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
        // SAFETY: a NUL-terminated line, which curl copies.
        *headers = unsafe { curl::curl_slist_append(*headers, c_ptr(auth_header)) };
        if headers.is_null() {
            return -ENOMEM;
        }
    }
    // The realm is the registry's to name and the credentials go there:
    // over no weaker a transport than the registry's own.
    let protocols: &CStr = if c.base_url.starts_with(b"https://") {
        c"https"
    } else {
        c"http,https"
    };
    let r_ptr = ptr::from_mut(r);
    // SAFETY: a live handle; the URL, list and response outlive the
    // transfer and nothing else touches them until it ends.
    let cc = unsafe {
        curl::set_ptr(handle, curl::CURLOPT_URL, c_ptr(&url));
        curl::set_ptr(handle, curl::CURLOPT_PROTOCOLS_STR, protocols.as_ptr());
        curl::set_long(handle, curl::CURLOPT_HTTPGET, 1);
        curl::set_ptr(handle, curl::CURLOPT_HTTPHEADER, *headers);
        deadlines(handle);
        curl::set_callback(handle, curl::CURLOPT_WRITEFUNCTION, write_memory);
        curl::set_ptr(handle, curl::CURLOPT_WRITEDATA, r_ptr);
        curl::set_long(handle, curl::CURLOPT_SSL_VERIFYPEER, 1);
        curl::set_long(handle, curl::CURLOPT_SSL_VERIFYHOST, 2);
        if tls_curl_policy(handle, &mut c.tls_ca) != 0 {
            return -EINVAL;
        }
        let cc = curl::curl_easy_perform(handle);
        curl::curl_easy_getinfo(
            handle,
            curl::CURLINFO_RESPONSE_CODE,
            &raw mut (*r_ptr).status,
        );
        cc
    };
    if cc != curl::CURLE_OK {
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

pub(super) fn get_memory(
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

                // SAFETY: the C format, with a C string, a long, an int
                // and n bytes of the body for %.*s.
                unsafe {
                    pr_err(
                        c"bpm OCI request %s: HTTP %ld: %.*s".as_ptr(),
                        req.url.as_ptr(),
                        r.status,
                        n as c_int,
                        body.as_ptr(),
                    )
                };
            } else {
                // SAFETY: the C format, with a C string and a long.
                unsafe {
                    pr_err(
                        c"bpm OCI request %s: HTTP %ld".as_ptr(),
                        req.url.as_ptr(),
                        r.status,
                    )
                };
            }
        }
        return status_errno(r.status);
    }
    0
}

/// The SHA-256 of `len` bytes at `data` in lowercase hex.
pub(super) fn sha256_hex(data: *const u8, len: usize, hex: &mut [u8]) -> c_int {
    let mut digest = [0u8; SHA256_LEN];

    // SAFETY: the caller's len bytes at data, NULL only for none.
    if hex.len() < 65 || unsafe { sha256_buffer(data.cast(), len, digest.as_mut_ptr()) } != 0 {
        return -EINVAL;
    }
    // SAFETY: 32 bytes in, and 65 bytes of room for their hex and a NUL.
    unsafe { hex_encode(digest.as_ptr(), digest.len(), hex.as_mut_ptr().cast()) };
    0
}

/// The one payload and the one signature among a manifest's layers, each
/// matching its descriptor's digest and declared size.
pub(super) fn get_signed(
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
        if (layer.size >= 0 && dst.len as i64 != layer.size)
            || sha256_hex(dst.data, dst.len, &mut hex) != 0
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
pub(super) fn push_blob(
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

    if sha256_hex(body.as_ptr(), body.len(), &mut hex) != 0 {
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
pub(super) fn put_manifest(
    c: &mut OciClient,
    repository: &[u8],
    reference: &[u8],
    body: &[u8],
    digest: &mut [u8],
) -> c_int {
    let mut hex = [0u8; 65];
    let mut manifest_url = [0u8; PATH_MAX];
    let mut r = HttpResponse::new();

    if sha256_hex(body.as_ptr(), body.len(), &mut hex) != 0
        || strsprintf(digest, &[b"sha256:", cstr(&hex)]).is_err()
    {
        return -ENAMETOOLONG;
    }
    let ret = url(c, repository, b"manifests", reference, &mut manifest_url);
    if ret != 0 {
        return ret;
    }
    let media = c"application/vnd.oci.image.manifest.v1+json";
    let put = Request {
        method: c"PUT",
        url: as_cstr(&manifest_url),
        accept: Some(media),
        content_type: Some(media),
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
