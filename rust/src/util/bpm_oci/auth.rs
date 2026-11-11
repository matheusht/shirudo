// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Registry credentials: Basic auth, the docker auth file, Bearer
//! challenges and the token a token server answers with.

use core::ffi::{CStr, c_int};

use super::{
    BASIC_RAW_SIZE, MAX_ENDPOINT, OciClient, PATH_MAX, at, cstr, find, is_space, strscpy,
    strsprintf,
};
use crate::errno::{E2BIG, EINVAL, ENAMETOOLONG, ENOENT, ENOSPC};
use crate::sys::{io, libc, malloc};

const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
        b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// The `user:password` that the base64 at the start of `s` encodes, up
/// to a NUL or a quote, blanks and padding skipped, into `user` and
/// `pass`.
pub(super) fn decode_basic(s: &[u8], user: &mut [u8], pass: &mut [u8]) -> c_int {
    let mut out = [0u8; BASIC_RAW_SIZE];
    let ret = decode_basic_into(s, &mut out, user, pass);

    libc::scrub(&mut out);
    ret
}

fn decode_basic_into(
    s: &[u8],
    out: &mut [u8; BASIC_RAW_SIZE],
    user: &mut [u8],
    pass: &mut [u8],
) -> c_int {
    let mut bits = -8;
    let mut n = 0;
    let mut val = 0u32;

    for &c in s {
        if c == 0 || c == b'"' || n >= out.len() {
            break;
        }
        if is_space(c) || c == b'=' {
            continue;
        }
        let Some(x) = base64_value(c) else {
            return -EINVAL;
        };
        // No more than 12 bits are ever pending.
        val = ((val << 6) | x) & 0xfff;
        bits += 6;
        if bits >= 0 {
            out[n] = (val >> bits) as u8;
            n += 1;
            bits -= 8;
        }
    }
    if n >= out.len() {
        return -E2BIG;
    }
    let decoded = &out[..n];
    if decoded.contains(&0) {
        return -EINVAL;
    }
    let Some(colon) = decoded.iter().position(|&c| c == b':') else {
        return -EINVAL;
    };
    if colon >= user.len() || n - colon > pass.len() {
        return -EINVAL;
    }
    user[..colon].copy_from_slice(&decoded[..colon]);
    user[colon] = 0;
    pass[..n - colon - 1].copy_from_slice(&decoded[colon + 1..]);
    pass[n - colon - 1] = 0;
    0
}

/// `user:pass` in base64 into `out`, terminated.
pub(super) fn encode_basic(user: &[u8], pass: &[u8], out: &mut [u8]) -> c_int {
    let mut raw = [0u8; BASIC_RAW_SIZE];
    let ret = encode_basic_from(user, pass, &mut raw, out);

    libc::scrub(&mut raw);
    ret
}

fn encode_basic_from(
    user: &[u8],
    pass: &[u8],
    raw: &mut [u8; BASIC_RAW_SIZE],
    out: &mut [u8],
) -> c_int {
    let Ok(len) = strsprintf(raw, &[user, b":", pass]) else {
        return -E2BIG;
    };
    let raw = &raw[..len];
    let mut o = 0;

    if 4 * len.div_ceil(3) + 1 > out.len() {
        return -ENOSPC;
    }
    for chunk in raw.chunks(3) {
        let v =
            (u32::from(chunk[0]) << 16) | (u32::from(at(chunk, 1)) << 8) | u32::from(at(chunk, 2));

        out[o] = BASE64[(v >> 18) as usize & 63];
        out[o + 1] = BASE64[(v >> 12) as usize & 63];
        out[o + 2] = if chunk.len() > 1 {
            BASE64[(v >> 6) as usize & 63]
        } else {
            b'='
        };
        out[o + 3] = if chunk.len() > 2 {
            BASE64[v as usize & 63]
        } else {
            b'='
        };
        o += 4;
    }
    out[o] = 0;
    0
}

/// The credentials for `registry`: BPM_OCI_USERNAME and BPM_OCI_PASSWORD,
/// or the `auth` of its entry in REGISTRY_AUTH_FILE or the docker
/// config, none when there is no file or no entry.
pub(super) fn load_registry_auth(registry: &[u8], c: &mut OciClient) -> c_int {
    let authfile = libc::env(c"REGISTRY_AUTH_FILE");
    let username = libc::env(c"BPM_OCI_USERNAME");
    let password = libc::env(c"BPM_OCI_PASSWORD");
    let docker = libc::env(c"DOCKER_CONFIG");
    let mut needle = [0u8; MAX_ENDPOINT + 8];
    let mut path = [0u8; PATH_MAX];

    if let (Some(username), Some(password)) = (username, password) {
        if strscpy(&mut c.username, username.to_bytes()).is_err()
            || strscpy(&mut c.password, password.to_bytes()).is_err()
        {
            return -E2BIG;
        }
        return 0;
    }
    let authfile = match (authfile, docker) {
        (Some(file), _) => file.to_bytes_with_nul(),
        (None, Some(docker)) => {
            if strsprintf(&mut path, &[docker.to_bytes(), b"/config.json"]).is_err() {
                return -ENAMETOOLONG;
            }
            &path[..]
        }
        (None, None) => {
            let home = libc::env(c"HOME").map_or(&b"/root"[..], CStr::to_bytes);

            if strsprintf(&mut path, &[home, b"/.docker/config.json"]).is_err() {
                return -ENAMETOOLONG;
            }
            &path[..]
        }
    };
    if strsprintf(&mut needle, &[b"\"", registry, b"\""]).is_err() {
        return -ENAMETOOLONG;
    }
    let mut body: *mut u8 = core::ptr::null_mut();
    let mut body_len = 0usize;
    // SAFETY: a C string path, and out-parameters read_file() fills.
    let ret = unsafe {
        io::read_file(
            authfile.as_ptr().cast(),
            4 * 1024 * 1024,
            (&raw mut body).cast(),
            &mut body_len,
        )
    };
    if ret != 0 {
        return if ret == -ENOENT { 0 } else { ret };
    }
    // SAFETY: read_file() gave body_len bytes and a NUL at body.
    let text = cstr(unsafe { core::slice::from_raw_parts(body, body_len + 1) });
    let ret = auth_entry(text, cstr(&needle), c);
    // SAFETY: the allocation read_file() made, released as it says.
    unsafe { malloc::xfree(body.cast(), body_len + 1) };
    ret
}

/// The auth file is local input; the registry key and its auth member
/// must sit in one JSON object before the credentials count.
fn auth_entry(text: &[u8], needle: &[u8], c: &mut OciClient) -> c_int {
    let Some(p) = find(text, needle) else {
        return 0;
    };
    let rest = &text[p..];
    let Some(end) = rest.iter().position(|&c| c == b'}') else {
        return -EINVAL;
    };
    let auth = match find(rest, b"\"auth\"") {
        Some(auth) if auth <= end => auth,
        _ => return 0,
    };
    let Some(colon) = rest[auth..].iter().position(|&c| c == b':') else {
        return -EINVAL;
    };
    let mut i = auth + colon + 1;
    while i < rest.len() && is_space(rest[i]) {
        i += 1;
    }
    if at(rest, i) != b'"' {
        return -EINVAL;
    }
    decode_basic(&rest[i + 1..], &mut c.username, &mut c.password)
}

/// The realm, service and scope of a `Bearer` challenge; -EINVAL without
/// a realm, -ENAMETOOLONG for one that does not fit.
pub(super) fn parse_challenge(
    header: &[u8],
    realm: &mut [u8],
    service: &mut [u8],
    scope: &mut [u8],
) -> c_int {
    let Some(prefix) = header.get(..6) else {
        return -EINVAL;
    };
    let mut p = 6;

    if !prefix.eq_ignore_ascii_case(b"Bearer") {
        return -EINVAL;
    }
    while p < header.len() {
        while matches!(at(header, p), b' ' | b',') {
            p += 1;
        }
        let rest = &header[p..];
        let field: Option<(usize, &mut [u8])> = if rest.starts_with(b"realm=\"") {
            Some((7, &mut *realm))
        } else if rest.starts_with(b"service=\"") {
            Some((9, &mut *service))
        } else if rest.starts_with(b"scope=\"") {
            Some((7, &mut *scope))
        } else {
            None
        };
        match field {
            Some((skip, dst)) => {
                let value = &rest[skip..];
                let Some(q) = value.iter().position(|&c| c == b'"') else {
                    return -EINVAL;
                };
                if q >= dst.len() {
                    return -ENAMETOOLONG;
                }
                dst[..q].copy_from_slice(&value[..q]);
                dst[q] = 0;
                p += skip + q + 1;
            }
            None => match rest.iter().position(|&c| c == b',') {
                Some(comma) => p += comma,
                None => break,
            },
        }
    }
    if at(realm, 0) != 0 { 0 } else { -EINVAL }
}

/// The token in a token server's JSON answer, `token` or `access_token`.
pub(super) fn token_from_body(body: &[u8], out: &mut [u8]) -> c_int {
    let Some(key) = find(body, b"\"token\"").or_else(|| find(body, b"\"access_token\"")) else {
        return -EINVAL;
    };
    let Some(colon) = body[key..].iter().position(|&c| c == b':') else {
        return -EINVAL;
    };
    let mut i = key + colon + 1;
    while i < body.len() && is_space(body[i]) {
        i += 1;
    }
    if at(body, i) != b'"' {
        return -EINVAL;
    }
    let token = &body[i + 1..];
    let Some(end) = token.iter().position(|&c| c == b'"') else {
        return -EINVAL;
    };
    if end >= out.len() {
        return -EINVAL;
    }
    // It goes into a header line as it is: no line break, no escape.
    if token[..end]
        .iter()
        .any(|&c| c < 0x21 || c == b'\\' || c == 0x7f)
    {
        return -EINVAL;
    }
    out[..end].copy_from_slice(&token[..end]);
    out[end] = 0;
    0
}
