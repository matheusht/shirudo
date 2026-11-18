// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C-shaped interface the crate still calls.

use core::ffi::{c_char, c_int, c_void};

use super::{Descriptor, OciClient, http, manifest};
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
