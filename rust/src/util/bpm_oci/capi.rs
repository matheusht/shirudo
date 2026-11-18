// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C interface of `util/bpm_oci.h`.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use super::{Descriptor, OciClient, auth, copy_string, http, manifest, refs};
use crate::errno::EINVAL;
use crate::ffi;
use crate::util::json::JsonEmit;

/// A C string the caller may pass as NULL.
///
/// # Safety
///
/// `s` is NULL or a C string valid for `'a`.
unsafe fn opt_bytes<'a>(s: *const c_char) -> Option<&'a [u8]> {
    // SAFETY: the caller passes NULL or a C string.
    (!s.is_null()).then(|| unsafe { ffi::c_str(s) })
}

/// # Safety
///
/// `dst` has room for `dst_sz` bytes and `src` is NULL or a C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_copy_string(dst: *mut c_char, dst_sz: usize, src: *const c_char) {
    // SAFETY: the caller passes NULL or a C string, and the room.
    let (src, dst) = unsafe {
        (
            opt_bytes(src).unwrap_or(b""),
            ffi::bytes_mut(dst.cast(), dst_sz),
        )
    };

    copy_string(dst, src);
}

/// # Safety
///
/// `endpoint` is NULL or a C string and `c` a client.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_oci_parse_endpoint(
    endpoint: *const c_char,
    c: *mut OciClient,
) -> c_int {
    // SAFETY: the caller passes NULL or a C string, and lends its client.
    unsafe {
        match opt_bytes(endpoint) {
            Some(endpoint) => refs::parse_endpoint(endpoint, &mut *c),
            None => -EINVAL,
        }
    }
}

/// # Safety
///
/// `raw` is NULL or a C string, `c` a client, and `repository` and `tag`
/// have room for their sizes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_oci_parse_pull_ref(
    raw: *const c_char,
    c: *mut OciClient,
    repository: *mut c_char,
    repository_sz: usize,
    tag: *mut c_char,
    tag_sz: usize,
) -> c_int {
    // SAFETY: the caller passes NULL or a C string, its client and the
    // room for the repository and the tag.
    unsafe {
        let Some(raw) = opt_bytes(raw) else {
            return -EINVAL;
        };
        refs::parse_pull_ref(
            raw,
            &mut *c,
            ffi::bytes_mut(repository.cast(), repository_sz),
            ffi::bytes_mut(tag.cast(), tag_sz),
        )
    }
}

/// # Safety
///
/// `raw` is NULL or a C string, `c` a client and `repository` has room
/// for `repository_sz`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_oci_parse_push_repo(
    raw: *const c_char,
    c: *mut OciClient,
    repository: *mut c_char,
    repository_sz: usize,
) -> c_int {
    // SAFETY: the caller passes NULL or a C string, its client and room.
    unsafe {
        let Some(raw) = opt_bytes(raw) else {
            return -EINVAL;
        };
        refs::parse_push_repo(
            raw,
            &mut *c,
            ffi::bytes_mut(repository.cast(), repository_sz),
        )
    }
}

/// # Safety
///
/// `raw` is NULL or a C string, `c` a client and `repository` has room
/// for `repository_sz`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_oci_parse_tree_repo(
    raw: *const c_char,
    c: *mut OciClient,
    repository: *mut c_char,
    repository_sz: usize,
) -> c_int {
    // SAFETY: the caller passes NULL or a C string, its client and room.
    unsafe {
        let Some(raw) = opt_bytes(raw) else {
            return -EINVAL;
        };
        refs::parse_tree_repo(
            raw,
            &mut *c,
            ffi::bytes_mut(repository.cast(), repository_sz),
        )
    }
}

/// # Safety
///
/// `c` is a client, `repo`, `kind` and `reference` are C strings and `out`
/// has room for `sz`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_oci_url(
    c: *const OciClient,
    repo: *const c_char,
    kind: *const c_char,
    reference: *const c_char,
    out: *mut c_char,
    sz: usize,
) -> c_int {
    // SAFETY: the caller passes its client, three C strings and room.
    unsafe {
        refs::url(
            &*c,
            ffi::c_str(repo),
            ffi::c_str(kind),
            ffi::c_str(reference),
            ffi::bytes_mut(out.cast(), sz),
        )
    }
}

/// # Safety
///
/// `c` is a client, `repository` and `media` are C strings, `body` holds
/// `body_len` bytes and `out` is a descriptor to fill.
pub unsafe extern "C" fn bpm_oci_push_blob(
    c: *mut OciClient,
    repository: *const c_char,
    body: *const c_void,
    body_len: usize,
    media: *const c_char,
    out: *mut Descriptor,
) -> c_int {
    // SAFETY: the caller passes its client, C strings, the body and its
    // descriptor.
    unsafe {
        http::push_blob(
            &mut *c,
            ffi::c_str(repository),
            ffi::slice(body.cast::<u8>(), body_len),
            ffi::c_str(media),
            &mut *out,
        )
    }
}

/// # Safety
///
/// `c` is a client, `repository` and `reference` are C strings, `body`
/// holds `body_len` bytes and `digest` has room for `digest_sz`.
pub unsafe extern "C" fn bpm_oci_put_manifest(
    c: *mut OciClient,
    repository: *const c_char,
    reference: *const c_char,
    body: *const u8,
    body_len: usize,
    digest: *mut c_char,
    digest_sz: usize,
) -> c_int {
    // SAFETY: the caller passes its client, C strings, the body and room.
    unsafe {
        http::put_manifest(
            &mut *c,
            ffi::c_str(repository),
            ffi::c_str(reference),
            ffi::slice(body, body_len),
            ffi::bytes_mut(digest.cast(), digest_sz),
        )
    }
}

/// # Safety
///
/// `body` holds `len` bytes, `layers` has room for `max_layers`
/// descriptors, `n_layers` is an int, and `package_name` is NULL or has
/// room for `package_name_sz`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_oci_parse_manifest(
    body: *const u8,
    len: usize,
    layers: *mut Descriptor,
    max_layers: c_int,
    n_layers: *mut c_int,
    package_name: *mut c_char,
    package_name_sz: usize,
) -> c_int {
    // SAFETY: the caller passes the body, room for the layers, its count
    // and room for the name, or NULL.
    unsafe {
        let name = (!package_name.is_null() && package_name_sz != 0)
            .then(|| ffi::bytes_mut(package_name.cast(), package_name_sz));

        manifest::parse_manifest(
            ffi::slice(body, len),
            layers,
            max_layers,
            &mut *n_layers,
            name,
        )
    }
}

/// # Safety
///
/// `e` is an emitter, `key` and `title` NULL or C strings and `d` a
/// descriptor.
pub unsafe extern "C" fn bpm_oci_emit_descriptor(
    e: *mut JsonEmit,
    key: *const c_char,
    d: *const Descriptor,
    title: *const c_char,
) {
    // SAFETY: the caller passes its emitter, C strings or NULL, and its
    // descriptor.
    unsafe { manifest::emit_descriptor(&mut *e, opt_bytes(key), &*d, opt_bytes(title)) };
}

/// The header callback, for the fuzz target that reaches it.
///
/// # Safety
///
/// `data` holds `size * nmemb` bytes and `ud` is a response.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_oci_header(
    data: *mut c_char,
    size: usize,
    nmemb: usize,
    ud: *mut c_void,
) -> usize {
    // SAFETY: the caller passes the bytes and a response, as curl does.
    unsafe { http::header(data, size, nmemb, ud) }
}

/// # Safety
///
/// `header` is NULL or a C string, and `realm`, `service` and `scope`
/// have room for their sizes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_oci_parse_challenge(
    header: *const c_char,
    realm: *mut c_char,
    rsz: usize,
    service: *mut c_char,
    ssz: usize,
    scope: *mut c_char,
    zsz: usize,
) -> c_int {
    // SAFETY: the caller passes NULL or a C string and three rooms.
    unsafe {
        let Some(header) = opt_bytes(header) else {
            return -EINVAL;
        };
        auth::parse_challenge(
            header,
            ffi::bytes_mut(realm.cast(), rsz),
            ffi::bytes_mut(service.cast(), ssz),
            ffi::bytes_mut(scope.cast(), zsz),
        )
    }
}

/// # Safety
///
/// `body` is a C string and `out` has room for `out_sz`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_oci_token_from_body(
    body: *const c_char,
    out: *mut c_char,
    out_sz: usize,
) -> c_int {
    // SAFETY: the caller passes a C string and room.
    unsafe { auth::token_from_body(ffi::c_str(body), ffi::bytes_mut(out.cast(), out_sz)) }
}

/// # Safety
///
/// `c` is a client, `location` NULL or a C string, and `out` has room
/// for `out_sz`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_oci_upload_location(
    c: *const OciClient,
    location: *const c_char,
    out: *mut c_char,
    out_sz: usize,
) -> c_int {
    // SAFETY: the caller passes its client, NULL or a C string, and room.
    unsafe {
        let Some(location) = opt_bytes(location) else {
            return -EINVAL;
        };
        refs::upload_location(&*c, location, ffi::bytes_mut(out.cast(), out_sz))
    }
}

/// "sha256:<hex>" of the `len` bytes at `data`, the form a registry names
/// a blob by, into `out`: 0, -ENAMETOOLONG for less room than that,
/// -EINVAL.
///
/// # Safety
///
/// `data` holds `len` bytes and `out` has room for `out_sz`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn bpm_sha256_digest(
    data: *const c_void,
    len: usize,
    out: *mut c_char,
    out_sz: usize,
) -> c_int {
    use crate::util::hex::{SHA256_DIGEST_STR_SIZE, sha256_digest_encode};

    if out_sz < SHA256_DIGEST_STR_SIZE {
        return -crate::errno::ENAMETOOLONG;
    }
    // SAFETY: the caller's bytes.
    let Ok(digest) = crate::util::crypto_openssl::sha256(unsafe { ffi::slice(data.cast(), len) })
    else {
        return -EINVAL;
    };
    let text = sha256_digest_encode(&digest);
    // SAFETY: room for the text and its terminator, checked above.
    unsafe { ptr::copy_nonoverlapping(text.as_ptr(), out.cast(), text.len()) };
    0
}
