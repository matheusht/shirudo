// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The TLS policy for every libcurl handle shirudo
//! opens: TLS 1.3 alone, hybrid ML-KEM key exchange unless the
//! configuration lets a host fall back to classical groups, and the CA
//! a client trusts added to what libcurl does. The policy does not
//! change how certificates are verified.

use core::ffi::{CStr, c_int, c_void};
use core::mem::ManuallyDrop;
use core::ptr;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use openssl::ssl::{SslContextBuilder, SslVersion};
use openssl::x509::X509;
use openssl_sys::{NID_undef, SSL, SSL_ctrl, SSL_get_servername, TLSEXT_NAMETYPE_host_name};

use crate::errno::EINVAL;
use crate::sys::curl::{
    CURL_SSLVERSION_TLSV1_3, CURLE_OK, CURLE_SSL_CACERT_BADFILE, CURLE_SSL_CIPHER,
    CURLE_SSL_CONNECT_ERROR, CURLOPT_FORBID_REUSE, CURLOPT_SSL_SESSIONID_CACHE, CURLOPT_SSLVERSION,
    CURLUPART_HOST, CURLUPART_SCHEME, Curl, CurlCode,
};
use crate::sys::libc::{O_CLOEXEC, O_RDONLY, open, strcasecmp};
use crate::sys::openssl::{
    SSL_CB_HANDSHAKE_DONE, SSL_CTRL_GET_NEGOTIATED_GROUP, SSL_CTX_set_info_callback,
    SSL_group_to_name,
};
use crate::text::{cstr, dns_name_valid};
use crate::util::config::{self, Scrubbed};
use crate::util::curl::{Easy, Url};
use crate::util::image_config;
use crate::util::io::check_trusted;

/// The groups of every host by default: hybrid ML-KEM alone.
const TLS_GROUPS: &str = "*X25519MLKEM768:SecP256r1MLKEM768";
/// The groups of a host tls.classical_hosts names: hybrid first, and
/// classical ones after.
const TLS_CLASSICAL_GROUPS: &str = "*X25519MLKEM768:SecP256r1MLKEM768:X25519:secp256r1";

/// Whether `host`, without its trailing dot, is a DNS name the list of
/// exact names apart by commas holds, case aside. An entry too long to
/// be a name, or not one, matches nothing.
fn host_listed(host: &[u8], list: &[u8]) -> bool {
    let host = host.strip_suffix(b".").unwrap_or(host);

    dns_name_valid(host)
        && list
            .split(|&c| c == b',')
            .any(|entry| dns_name_valid(entry) && entry.eq_ignore_ascii_case(host))
}

/// Whether the configuration lets the host `easy` is connecting to fall
/// back to classical key exchange: an https URL whose host is one of the
/// exact DNS names of tls.classical_hosts. libcurl asks again for each
/// redirect, so every registry host has to be named itself.
fn classical_host_allowed(easy: &Easy<'_>) -> bool {
    let mut cfg = Scrubbed::new();

    if image_config::get(&mut cfg) == 0 && config::load(&mut cfg) != 0 {
        return false;
    }
    let c = &*cfg;

    if !c.tls_classical_hosts_valid || c.tls_classical_hosts[0] == 0 {
        return false;
    }
    let Some(effective_url) = easy.effective_url() else {
        return false;
    };
    let Ok(url) = Url::parse(effective_url.to_bytes()) else {
        return false;
    };
    url.part(CURLUPART_SCHEME)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case(b"https"))
        && url
            .part(CURLUPART_HOST)
            .is_some_and(|host| host_listed(&host, cstr(&c.tls_classical_hosts)))
}

/// libssl's info callback on a connection to a host allowed classical
/// groups: a warning once its handshake is done, unless it settled on a
/// hybrid one.
///
/// # Safety
///
/// `ssl` is the connection libssl reports on.
unsafe extern "C" fn info_callback(ssl: *const SSL, kind: c_int, _ret: c_int) {
    if kind & SSL_CB_HANDSHAKE_DONE == 0 {
        return;
    }
    let ssl_mut = ssl.cast_mut();
    // SAFETY: the connection, asked for its group with the control the
    // C's macro sends, and the C strings of its group and host.
    let (group, host) = unsafe {
        let id = SSL_ctrl(ssl_mut, SSL_CTRL_GET_NEGOTIATED_GROUP, 0, ptr::null_mut()) as c_int;
        let group = if id == NID_undef {
            ptr::null()
        } else {
            SSL_group_to_name(ssl_mut, id)
        };

        if !group.is_null()
            && (strcasecmp(group, c"X25519MLKEM768".as_ptr()) == 0
                || strcasecmp(group, c"SecP256r1MLKEM768".as_ptr()) == 0)
        {
            return;
        }
        (group, SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name))
    };
    let host = if host.is_null() {
        c"unknown host"
    } else {
        // SAFETY: OpenSSL's server name of the connection, a C string.
        unsafe { CStr::from_ptr(host) }
    };
    let group = if group.is_null() {
        c"unknown group"
    } else {
        // SAFETY: OpenSSL's name of the group, a C string.
        unsafe { CStr::from_ptr(group) }
    };
    crate::log::warn(
        &[
            &b"TLS non-hybrid key exchange with "[..],
            host.to_bytes(),
            b": ",
            group.to_bytes(),
        ]
        .concat(),
    );
}

/// The CA file at `path` added to the trust store of `ctx`: CURLE_OK, or
/// CURLE_SSL_CACERT_BADFILE for a file that cannot be opened or read, is
/// not trusted or holds no PEM certificate. A certificate the store
/// already has, or cannot add, leaves the store as it was.
fn add_ca(ctx: &mut SslContextBuilder, path: &CStr) -> CurlCode {
    // SAFETY: a C string, and flags.
    let fd = unsafe { open(path.as_ptr(), O_RDONLY | O_CLOEXEC) };

    if fd < 0 {
        return CURLE_SSL_CACERT_BADFILE;
    }
    // SAFETY: the fd open() gave, owned from here.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    // SAFETY: the fd, and a C string.
    if unsafe { check_trusted(file.as_raw_fd(), path.as_ptr(), false) } != 0 {
        return CURLE_SSL_CACERT_BADFILE;
    }
    let mut text = Vec::new();
    if (&file).read_to_end(&mut text).is_err() {
        return CURLE_SSL_CACERT_BADFILE;
    }
    let Ok(cert) = X509::from_pem(&text) else {
        return CURLE_SSL_CACERT_BADFILE;
    };
    // The store takes its own reference, or keeps the one it has.
    drop(ctx.cert_store_mut().add_cert(cert));
    CURLE_OK
}

/// libcurl's `CURLOPT_SSL_CTX_FUNCTION`, before each connection: TLS 1.3,
/// the hybrid groups, or classical ones as well for an allowed host
/// whose handshake is then watched, and the client's CA.
///
/// # Safety
///
/// `curl` is the handle connecting, `sslctx` its `SSL_CTX`, and
/// `userptr` NULL or the CA path given to tls_curl_policy().
unsafe extern "C" fn sslctx_callback(
    curl: *mut Curl,
    sslctx: *mut c_void,
    userptr: *mut c_void,
) -> CurlCode {
    // SAFETY: the client's CA path, a C string, if it has one.
    let ca = (!userptr.is_null()).then(|| unsafe { CStr::from_ptr(userptr.cast()) });
    // SAFETY: the context libcurl hands over, which it keeps and frees, so
    // that it is never dropped here.
    let mut ctx = ManuallyDrop::new(unsafe { SslContextBuilder::from_ptr(sslctx.cast()) });
    let mut groups = TLS_GROUPS;
    // SAFETY: the handle libcurl is connecting, used only in this call.
    let easy = unsafe { Easy::from_callback(curl) };

    if let Some(mut easy) = easy.filter(|easy| classical_host_allowed(easy)) {
        // Keep this host's policy from leaking through libcurl's reuse
        // of connections and sessions.
        let kept = easy.set_long(CURLOPT_FORBID_REUSE, 1) == CURLE_OK
            && easy.set_long(CURLOPT_SSL_SESSIONID_CACHE, 0) == CURLE_OK;
        if !kept {
            return CURLE_SSL_CONNECT_ERROR;
        }
        groups = TLS_CLASSICAL_GROUPS;
        // SAFETY: the context, and a callback of libssl's type.
        unsafe { SSL_CTX_set_info_callback(ctx.as_ptr(), Some(info_callback)) };
    }
    // What either refuses, libcrypto's queue loses with it.
    let set = ctx.set_min_proto_version(Some(SslVersion::TLS1_3)).is_ok()
        && ctx.set_groups_list(groups).is_ok();
    if !set {
        return CURLE_SSL_CIPHER;
    }
    match ca {
        Some(path) if !path.is_empty() => add_ca(&mut ctx, path),
        _ => CURLE_OK,
    }
}

/// The policy on `easy`: TLS 1.3 at least, and the context callback,
/// with `ca`, the path of the CA file a client trusts, that settles the
/// rest each time libcurl connects. -EINVAL for a handle that refuses
/// an option.
pub(crate) fn tls_curl_policy<'a>(easy: &mut Easy<'a>, ca: Option<&'a CStr>) -> Result<(), c_int> {
    if easy.set_long(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSV1_3) != CURLE_OK {
        return Err(-EINVAL);
    }
    let ca = ca.map_or(ptr::null(), CStr::as_ptr);
    // SAFETY: sslctx_callback() takes its pointer for NULL or a C string,
    // and the path, which the handle borrows, outlives it.
    if unsafe { easy.set_ssl_ctx(sslctx_callback, ca.cast()) } != CURLE_OK {
        return Err(-EINVAL);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
