// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Signed payloads: a detached CMS signature checked against a
//! certificate, and the signed tree publication a registry holds.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use crate::errno::{E2BIG, EBADMSG, EINVAL, ENAMETOOLONG, ENOMEM};
use crate::ffi;
use crate::sys::bpm_tree::{TreePublication, tree_parse};
use crate::sys::crypto::{Cert, cert_free, cert_read_fd, cert_read_file, verify_detached};
use crate::sys::libc::PATH_MAX;
use crate::sys::malloc::{xcalloc, xfree};
use crate::text::{contains, cstr, strsprintf};
use crate::util::bpm_oci::{
    BpmBuffer, Descriptor, EMPTY_CONFIG_MEDIA, MANIFEST_MEDIA, MAX_ENTRIES, OciClient,
    TREE_ARTIFACT, TREE_MEDIA, TREE_SIG_MEDIA, buffer_free, descriptor, emit_descriptor,
    get_memory, get_signed, parse_manifest, sha256_hex, url,
};
use crate::util::json::emit_fixed;

unsafe extern "C" {
    fn keys_verify_signature(
        set: *const c_void,
        payload: *const u8,
        payload_len: usize,
        sig: *const u8,
        sig_len: usize,
        signer: *mut u8,
    ) -> c_int;
}

/// A signed payload: the bytes and the signature as the caller holds
/// them, NULL pointers included, which `verify_detached()` refuses.
pub(super) struct Signed {
    pub payload: *const u8,
    pub payload_len: usize,
    pub sig: *const u8,
    pub sig_len: usize,
}

/// 0 when `s` verifies against the certificate `read` fills, -EINVAL when
/// there is none.
fn verify_with(s: &Signed, read: impl FnOnce(&mut Cert) -> c_int) -> c_int {
    let mut cert = Cert::new();
    let mut ret = -EINVAL;

    if read(&mut cert) == 0 {
        // SAFETY: the payload and signature as the caller lends them,
        // and the cert just read.
        ret = unsafe { verify_detached(s.payload, s.payload_len, s.sig, s.sig_len, &cert) };
    }
    // SAFETY: a cert read or left empty, freed once.
    unsafe { cert_free(&mut cert) };
    ret
}

/// Against the certificate in the file at `cert_path`.
pub(super) fn verify_cms(s: &Signed, cert_path: *const c_char) -> c_int {
    // SAFETY: cert_read_file() takes the caller's path as it is.
    verify_with(s, |cert| unsafe { cert_read_file(cert_path, cert) })
}

/// Against the certificate the open `cert_fd` reads.
pub(super) fn verify_cms_fd(s: &Signed, cert_fd: c_int) -> c_int {
    // SAFETY: an fd and a cert to fill.
    verify_with(s, |cert| unsafe { cert_read_fd(cert_fd, cert) })
}

/// What a tree fetch holds until it ends.
struct Fetch {
    manifest: BpmBuffer,
    payload: BpmBuffer,
    sig: BpmBuffer,
    layers: *mut Descriptor,
}

impl Drop for Fetch {
    fn drop(&mut self) {
        // SAFETY: NULL, or the MAX_ENTRIES descriptors xcalloc() gave.
        unsafe { xfree(self.layers.cast(), MAX_ENTRIES * size_of::<Descriptor>()) };
        buffer_free(&mut self.manifest);
        buffer_free(&mut self.payload);
        buffer_free(&mut self.sig);
    }
}

/// The exact manifest written by the tree publisher.
pub(super) fn tree_manifest(
    payload: &Descriptor,
    sig: &Descriptor,
    out: &mut [u8],
) -> Result<usize, c_int> {
    let mut hex = [0u8; 65];
    if sha256_hex(b"{}".as_ptr(), 2, &mut hex) != 0 {
        return Err(-EINVAL);
    }
    let mut digest = [0u8; 72];
    digest[..7].copy_from_slice(b"sha256:");
    digest[7..].copy_from_slice(&hex);
    let config = descriptor(EMPTY_CONFIG_MEDIA, cstr(&digest), 2).ok_or(-E2BIG)?;

    emit_fixed(out, |e| {
        e.obj_open();
        e.kv_int(b"schemaVersion", 2);
        e.kv_string(b"mediaType", MANIFEST_MEDIA.to_bytes());
        e.kv_string(b"artifactType", TREE_ARTIFACT);
        emit_descriptor(e, Some(b"config"), &config, None);
        e.arr_open(b"layers");
        emit_descriptor(e, None, payload, None);
        emit_descriptor(e, None, sig, None);
        e.arr_close();
        e.obj_close();
    })
}

/// Only the manifest form written by Shirudo may name this signed tree.
fn canonical_manifest(manifest: &[u8], layers: &[Descriptor]) -> c_int {
    if layers.len() != 2
        || layers[0].media_bytes() != TREE_MEDIA
        || layers[1].media_bytes() != TREE_SIG_MEDIA
    {
        return -EBADMSG;
    }
    let mut expected = [0u8; 8192];
    match tree_manifest(&layers[0], &layers[1], &mut expected) {
        Ok(len) if manifest == &expected[..len] => 0,
        Ok(_) => -EBADMSG,
        Err(err) => err,
    }
}

/// Fetch the checked tree payload and leave its bytes with the caller.
pub(super) fn fetch_document(
    c: &mut OciClient,
    repository: &[u8],
    reference: &[u8],
    cert_path: *const c_char,
    trusted: *const c_void,
    payload: &mut BpmBuffer,
    manifest_digest: &mut [u8],
) -> c_int {
    let mut manifest_url = [0u8; PATH_MAX];
    let mut hex = [0u8; 65];
    let mut nl = 0;

    if reference.is_empty()
        || reference.iter().any(|&ch| matches!(ch, b'/' | b'?' | b'#'))
        || contains(reference, b"..")
    {
        return -EINVAL;
    }
    let ret = url(c, repository, b"manifests", reference, &mut manifest_url);
    if ret != 0 {
        return ret;
    }
    let Ok(manifest_url) = CStr::from_bytes_until_nul(&manifest_url) else {
        return -EINVAL;
    };
    let mut f = Fetch {
        manifest: BpmBuffer::new(),
        payload: BpmBuffer::new(),
        sig: BpmBuffer::new(),
        layers: ptr::null_mut(),
    };
    let ret = get_memory(
        c,
        manifest_url,
        Some(MANIFEST_MEDIA),
        &mut f.manifest,
        false,
    );
    if ret != 0 {
        return ret;
    }
    if manifest_digest.len() < 72 {
        return -ENAMETOOLONG;
    }
    if sha256_hex(f.manifest.data, f.manifest.len, &mut hex) != 0 {
        return -EINVAL;
    }
    if strsprintf(manifest_digest, &[b"sha256:", cstr(&hex)]).is_err() {
        return -ENAMETOOLONG;
    }
    // SAFETY: xcalloc gives room for MAX_ENTRIES descriptors, zeroed.
    f.layers = unsafe { xcalloc(MAX_ENTRIES, size_of::<Descriptor>()) }.cast();
    if f.layers.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the manifest's len bytes.
    let manifest = unsafe { ffi::slice(f.manifest.data, f.manifest.len) };
    let ret = parse_manifest(manifest, f.layers, MAX_ENTRIES as c_int, &mut nl, None);
    if ret != 0 {
        return ret;
    }
    let Ok(n) = usize::try_from(nl) else {
        return -EINVAL;
    };
    if n > MAX_ENTRIES {
        return -EINVAL;
    }
    // SAFETY: parse_manifest wrote n descriptors at layers.
    let layers = unsafe { ffi::slice(f.layers, n) };
    let ret = canonical_manifest(manifest, layers);
    if ret != 0 {
        return ret;
    }
    let ret = get_signed(
        c,
        repository,
        layers,
        TREE_MEDIA,
        TREE_SIG_MEDIA,
        &mut f.payload,
        &mut f.sig,
    );
    if ret != 0 {
        return ret;
    }
    let ret = if trusted.is_null() {
        let signed = Signed {
            payload: f.payload.data,
            payload_len: f.payload.len,
            sig: f.sig.data,
            sig_len: f.sig.len,
        };
        verify_cms(&signed, cert_path)
    } else {
        // SAFETY: trusted names the caller's set, and downloaded bytes
        // remain live through verification.
        unsafe {
            keys_verify_signature(
                trusted,
                f.payload.data,
                f.payload.len,
                f.sig.data,
                f.sig.len,
                ptr::null_mut(),
            )
        }
    };
    if ret != 0 {
        return ret;
    }
    *payload = core::mem::replace(&mut f.payload, BpmBuffer::new());
    0
}

/// Fetch the checked document and parse it as a tree publication.
pub(super) fn fetch_publication(
    c: &mut OciClient,
    repository: &[u8],
    reference: &[u8],
    cert_path: *const c_char,
    trusted: *const c_void,
    publication: *mut TreePublication,
    manifest_digest: &mut [u8],
) -> c_int {
    let mut payload = BpmBuffer::new();
    let ret = fetch_document(
        c,
        repository,
        reference,
        cert_path,
        trusted,
        &mut payload,
        manifest_digest,
    );
    if ret != 0 {
        return ret;
    }
    // SAFETY: the checked payload's len bytes and the caller's publication.
    let ret = unsafe { tree_parse(payload.data.cast(), payload.len, publication) };
    buffer_free(&mut payload);
    ret
}
