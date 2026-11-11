// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The OCI distribution client behind `util/bpm_oci.h`: libcurl carries
//! HTTP and TLS, this module owns registry auth, blob and manifest
//! transfer, and reference parsing.

mod auth;
mod capi;
mod http;
mod manifest;
mod refs;

use core::ffi::{c_char, c_long};

use crate::errno::E2BIG;
use crate::sys::crypto::TlsCa;

const PATH_MAX: usize = 4096;
const MAX_NAME: usize = 128;
const MAX_ENDPOINT: usize = 512;
const MAX_MEDIA: usize = 192;
const MAX_DIGEST: usize = 128;
const MAX_HTTP_BODY: usize = 256 * 1024 * 1024;
const MAX_PACKAGE_BYTES: u64 = 256 * 1024 * 1024;
const USERNAME_SIZE: usize = 256;
const PASSWORD_SIZE: usize = 4096;
const TOKEN_SIZE: usize = 4096;
const BASIC_RAW_SIZE: usize = USERNAME_SIZE + PASSWORD_SIZE;
const BASIC_ENCODED_SIZE: usize = 4 * BASIC_RAW_SIZE.div_ceil(3) + 1;
const AUTH_VALUE_SIZE: usize = BASIC_ENCODED_SIZE + "Basic ".len() + 1;
const BASIC_HEADER_SIZE: usize = AUTH_VALUE_SIZE + "Authorization: ".len();

/// `struct bpm_buffer`: `len` bytes and a NUL in `cap`, which the xmalloc
/// family allocates and `bpm_buffer_free()` releases.
#[repr(C)]
pub struct BpmBuffer {
    data: *mut u8,
    len: usize,
    cap: usize,
}

/// `struct bpm_http_response`.
#[repr(C)]
pub struct HttpResponse {
    body: BpmBuffer,
    www_auth: [u8; 2048],
    content_type: [u8; MAX_MEDIA],
    location: [u8; PATH_MAX],
    status: c_long,
}

/// `struct bpm_oci_client`.
#[repr(C)]
pub struct OciClient {
    base_url: [u8; MAX_ENDPOINT],
    registry: [u8; MAX_ENDPOINT],
    username: [u8; USERNAME_SIZE],
    password: [u8; PASSWORD_SIZE],
    token: [u8; TOKEN_SIZE],
    ca_file: [u8; PATH_MAX],
    tls_ca: TlsCa,
}

/// `struct bpm_descriptor`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Descriptor {
    media: [u8; MAX_MEDIA],
    digest: [u8; MAX_DIGEST],
    title: [u8; PATH_MAX],
    size: i64,
}

const _: () = assert!(size_of::<BpmBuffer>() == 24);
const _: () = assert!(size_of::<HttpResponse>() == 6368);
const _: () = assert!(size_of::<OciClient>() == 13584);
const _: () = assert!(size_of::<Descriptor>() == 4424);

impl BpmBuffer {
    const fn new() -> Self {
        BpmBuffer {
            data: core::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }
}

impl HttpResponse {
    const fn new() -> Self {
        HttpResponse {
            body: BpmBuffer::new(),
            www_auth: [0; 2048],
            content_type: [0; MAX_MEDIA],
            location: [0; PATH_MAX],
            status: 0,
        }
    }
}

impl Descriptor {
    const fn new() -> Self {
        Descriptor {
            media: [0; MAX_MEDIA],
            digest: [0; MAX_DIGEST],
            title: [0; PATH_MAX],
            size: 0,
        }
    }
}

/// The C string a buffer holds: its bytes up to the first NUL.
fn cstr(buf: &[u8]) -> &[u8] {
    let n = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());

    &buf[..n]
}

/// The byte at `i` of a C string, and the NUL past its end.
fn at(s: &[u8], i: usize) -> u8 {
    s.get(i).copied().unwrap_or(0)
}

/// isspace() in the C locale, vertical tab included.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// strstr(): where `needle` first starts in `s`.
fn find(s: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    s.windows(needle.len()).position(|w| w == needle)
}

fn contains(s: &[u8], needle: &[u8]) -> bool {
    find(s, needle).is_some()
}

/// bpm_copy_string(): `src` cut to the room of `dst`, terminated.
fn copy_string(dst: &mut [u8], src: &[u8]) {
    let Some(room) = dst.len().checked_sub(1) else {
        return;
    };
    let n = src.len().min(room);

    dst[..n].copy_from_slice(&src[..n]);
    dst[n] = 0;
}

/// strscpy(): -E2BIG, with `src` cut and terminated, when it does not fit.
fn strscpy(dst: &mut [u8], src: &[u8]) -> Result<usize, i32> {
    if dst.is_empty() {
        return Err(-E2BIG);
    }
    if src.len() >= dst.len() {
        copy_string(dst, src);
        return Err(-E2BIG);
    }
    copy_string(dst, src);
    Ok(src.len())
}

/// strsprintf() of a format of `%s` conversions alone: the parts one
/// after another, or -E2BIG and an empty buffer when they do not fit.
fn strsprintf(dst: &mut [u8], parts: &[&[u8]]) -> Result<usize, i32> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let Some(room) = dst.len().checked_sub(1) else {
        return Err(-E2BIG);
    };
    let mut pos = 0;

    for part in parts {
        let n = part.len().min(room - pos);

        dst[pos..pos + n].copy_from_slice(&part[..n]);
        pos += n;
    }
    dst[pos] = 0;
    if total > room {
        dst[0] = 0;
        return Err(-E2BIG);
    }
    Ok(total)
}

/// A name or version: alphanumerics, `-`, `_`, `.` and with `plus` `+`,
/// not starting with a dot and shorter than `BPM_MAX_NAME`.
fn component_ok(s: &[u8], plus: bool) -> bool {
    if s.is_empty() || s.len() >= MAX_NAME || s[0] == b'.' {
        return false;
    }
    s.iter().all(|&c| {
        c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.') || (plus && c == b'+')
    })
}

fn name_ok(s: &[u8]) -> bool {
    component_ok(s, false)
}

fn version_ok(s: &[u8]) -> bool {
    component_ok(s, true)
}

fn package_name_ok(s: &[u8]) -> bool {
    if !s.first().is_some_and(u8::is_ascii_alphanumeric) {
        return false;
    }
    s.iter()
        .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        && s.len() < MAX_NAME
}

/// Where the text of `s` starts and ends with the blanks around it gone.
fn trim_range(s: &[u8]) -> (usize, usize) {
    let start = s.iter().position(|&c| !is_space(c)).unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|&c| !is_space(c))
        .map_or(start, |i| i + 1);

    (start, end)
}

/// Blanks trimmed off both ends of `s` into `out`; -E2BIG when `out` had
/// to cut it, as strscpy() does.
fn trim(s: &[u8], out: &mut [u8]) -> Result<(), i32> {
    let Some(room) = out.len().checked_sub(1) else {
        return Err(-E2BIG);
    };
    let (start, end) = trim_range(s);
    let mut text = &s[start..end];
    let mut ret = Ok(());

    if text.len() > room {
        text = &text[..room];
        ret = Err(-E2BIG);
    }
    out[..text.len()].copy_from_slice(text);
    out[text.len()] = 0;
    ret
}

/// `want` is `sha256:` and the hex of `hex` in either case.
fn digest_matches(want: &[u8], hex: &[u8]) -> bool {
    want.strip_prefix(b"sha256:")
        .is_some_and(|w| w.eq_ignore_ascii_case(hex))
}

/// A pointer for C to a NUL-terminated buffer.
fn c_ptr(buf: &[u8]) -> *const c_char {
    buf.as_ptr().cast()
}
