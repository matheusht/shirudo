// SPDX-License-Identifier: BSD-2-Clause
// Copyright (C) 2025 Google LLC.
// Copyright (c) 2026 Authors of shirudo

//! The CMS signer: a detached ML-DSA-87 signature over a loader's
//! instructions and data, the bytes the kernel reassembles and verifies
//! at BPF_PROG_LOAD. Only shirudo-build reaches it.
//!
//! Re-implemented from bpftool's signer (tools/bpf/bpftool/sign.c,
//! GPL-2.0-only OR BSD-2-Clause), under its BSD-2-Clause branch.

use core::ffi::{CStr, c_int};
use core::ptr;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use foreign_types::ForeignType;
use openssl::cms::CmsContentInfo;
use openssl::error::ErrorStack;
use openssl::hash::{MessageDigest, hash};
use openssl::pkey::{KeyType, PKey, Private};
use openssl::x509::X509;
use openssl_sys as ffi;

use super::{error, path, strerr};
use crate::errno::{E2BIG, EINVAL, EIO, ENOMEM, ENOSPC, EPERM};
use crate::sys::libc::{O_NONBLOCK, S_IFMT, S_IFREG};
use crate::sys::openssl::{CMS_NO_SIGNING_TIME, CMS_add1_signer, CMS_final, ERR_error_string_n};
use crate::util::crypto_openssl::{key_type_name, x509_from_der_bio};

fn say(text: String) {
    error(text.as_bytes());
}

/// Why signing failed: the errno, and the errors libcrypto gave.
type Failure = (c_int, ErrorStack);

/// A failure with what libcrypto still has queued.
fn failed(err: c_int) -> Failure {
    (err, ErrorStack::get())
}

/// OpenSSL's errors, each with where it rose, logged.
fn display_errors(errors: &ErrorStack) {
    for e in errors.errors() {
        let mut buf = [0u8; 256];
        // SAFETY: the error and the room for its string.
        unsafe { ERR_error_string_n(e.code(), buf.as_mut_ptr().cast(), buf.len()) };
        let text = String::from_utf8_lossy(crate::text::cstr(&buf));
        let (file, line) = (e.file(), e.line());
        match e.data() {
            Some(data) => say(format!("OpenSSL {text}: {file}:{line}: {data}")),
            None => say(format!("OpenSSL {text}: {file}:{line}")),
        }
    }
}

fn shown(p: &CStr) -> String {
    String::from_utf8_lossy(p.to_bytes()).into_owned()
}

/// The private key at `pkey`, opened, and checked on that descriptor to
/// be a regular file of mode 0600; why not, logged.
pub(crate) fn open_signing_key(pkey: &CStr) -> Result<OwnedFd, c_int> {
    // A FIFO in its place would block open() before the check refuses it.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK)
        .open(path(pkey.to_bytes()))
        .map_err(|e| {
            let err = -e.raw_os_error().unwrap_or(EIO);
            say(format!(
                "open private key {}: {}",
                shown(pkey),
                String::from_utf8_lossy(strerr(-err))
            ));
            err
        })?;
    let st = file.metadata().map_err(|e| {
        let err = -e.raw_os_error().unwrap_or(EIO);
        say(format!(
            "stat private key {}: {}",
            shown(pkey),
            String::from_utf8_lossy(strerr(-err))
        ));
        err
    })?;
    if st.mode() & u32::from(S_IFMT) != u32::from(S_IFREG) {
        say(format!("signing key {} is not a regular file", shown(pkey)));
        return Err(-EPERM);
    }
    if st.mode() & 0o7777 != 0o600 {
        say(format!(
            "signing key {0} has mode 0{1:o}, must be 0600 (run `chmod 0600 {0}`)",
            shown(pkey),
            st.mode() & 0o7777
        ));
        return Err(-EPERM);
    }
    Ok(file.into())
}

/// The private key at `pkey`.
fn private_key(pkey: &CStr) -> Result<PKey<Private>, Failure> {
    let fd = open_signing_key(pkey).map_err(|_| failed(-EINVAL))?;
    let mut text = Vec::new();

    // The allocator scrubs the key's text when it goes.
    File::from(fd)
        .read_to_end(&mut text)
        .map_err(|_| failed(-EINVAL))?;
    PKey::private_key_from_pem(&text).map_err(|e| (-EINVAL, e))
}

/// The certificate at `cert`, DER or PEM by its first two bytes.
fn certificate(cert: &CStr) -> Result<X509, Failure> {
    let text = std::fs::read(path(cert.to_bytes())).map_err(|e| {
        say(format!(
            "open certificate {}: {}",
            shown(cert),
            String::from_utf8_lossy(strerr(e.raw_os_error().unwrap_or(EIO)))
        ));
        failed(-EINVAL)
    })?;
    let parsed = match text[..] {
        // A SEQUENCE with a long-form length is raw DER.
        [0x30, 0x81..=0x84, ..] => x509_from_der_bio(&text),
        [_, _, ..] => X509::from_pem(&text),
        _ => return Err(failed(-EINVAL)),
    };
    parsed.map_err(|e| (-EINVAL, e))
}

/// A memory BIO reading bytes in place, freed when it goes.
struct Input(*mut ffi::BIO);

impl Drop for Input {
    fn drop(&mut self) {
        // SAFETY: the BIO, freed once.
        unsafe { ffi::BIO_free_all(self.0) };
    }
}

/// A detached CMS signature over `insns` and `data`, of at most `max`
/// bytes, with the ML-DSA-87 key at `pkey` and the certificate at
/// `cert`, and the SHA-256 of the two: -ENOSPC for a signature over
/// `max`, -EINVAL for a key or certificate that does not read, -EIO
/// when OpenSSL fails.
///
/// Never a signing time: the kernel refuses a signature whose signing
/// time falls outside the signer's validity period
/// (crypto/asymmetric_keys/pkcs7_verify.c), which would let a
/// certificate's dates decide what loads.
pub(crate) fn cms_sign(
    insns: &[u8],
    data: &[u8],
    max: usize,
    pkey: &CStr,
    cert: &CStr,
) -> Result<(Vec<u8>, [u8; 32]), c_int> {
    sign(insns, data, max, pkey, cert).map_err(|(err, errors)| {
        display_errors(&errors);
        err
    })
}

fn sign(
    insns: &[u8],
    data: &[u8],
    max: usize,
    pkey: &CStr,
    cert: &CStr,
) -> Result<(Vec<u8>, [u8; 32]), Failure> {
    // The signature and the payload digest span insns || data, the
    // concatenation the kernel folds and verifies at load.
    let content = [insns, data].concat();
    let len = c_int::try_from(content.len()).map_err(|_| failed(-E2BIG))?;
    // SAFETY: the content, which outlives the BIO.
    let input = Input(unsafe { ffi::BIO_new_mem_buf(content.as_ptr().cast(), len) });
    if input.0.is_null() {
        return Err(failed(-ENOMEM));
    }
    let key = private_key(pkey)?;
    if !key.is_a(KeyType::ML_DSA_87) {
        let name = key_type_name(&key);
        let name = name
            .as_deref()
            .map_or("unknown".into(), CStr::to_string_lossy);
        // The target's trust set refuses the smaller parameter sets, so
        // an artifact signed with one could never load.
        say(format!(
            "{}: {name} key; shirudo signs with ML-DSA-87 only (re-key with shirudo genkey)",
            shown(pkey)
        ));
        return Err(failed(-EINVAL));
    }
    let x509 = certificate(cert)?;

    let mut flags = ffi::CMS_NOCERTS
        | ffi::CMS_BINARY
        | ffi::CMS_NOSMIMECAP
        | CMS_NO_SIGNING_TIME
        | ffi::CMS_USE_KEYID
        | ffi::CMS_NOATTR;
    let mut digest = MessageDigest::sha256();
    if (0x3000_0000..0x4000_0000).contains(&openssl::version::number()) {
        // OpenSSL 3 cannot combine ML-DSA with CMS_NOATTR, so it signs
        // attributes, where the kernel takes ML-DSA only over SHA-512
        // (crypto/asymmetric_keys/public_key.c). bpftool and module
        // signing do the same; OpenSSL 4 signs the content directly.
        flags &= !ffi::CMS_NOATTR;
        digest = MessageDigest::sha512();
    }
    // SAFETY: no signer yet, so a partial structure.
    let cms = unsafe {
        ffi::CMS_sign(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ffi::CMS_NOCERTS
                | ffi::CMS_PARTIAL
                | ffi::CMS_BINARY
                | ffi::CMS_DETACHED
                | ffi::CMS_STREAM,
        )
    };
    if cms.is_null() {
        return Err(failed(-EINVAL));
    }
    // SAFETY: the structure CMS_sign() made, owned from here.
    let cms = unsafe { CmsContentInfo::from_ptr(cms) };
    // SAFETY: the structure, the certificate, the key and the digest.
    let signer = unsafe {
        CMS_add1_signer(
            cms.as_ptr(),
            x509.as_ptr(),
            key.as_ptr(),
            digest.as_ptr(),
            flags,
        )
    };
    if signer.is_null() {
        return Err(failed(-EINVAL));
    }
    // SAFETY: the structure and the content's BIO.
    let finished = unsafe {
        CMS_final(
            cms.as_ptr(),
            input.0,
            ptr::null_mut(),
            ffi::CMS_NOCERTS | ffi::CMS_BINARY,
        )
    };
    if finished != 1 {
        return Err(failed(-EIO));
    }
    let payload_sha256 = hash(MessageDigest::sha256(), &content)
        .map_err(|e| (-EIO, e))
        .and_then(|d| (*d).try_into().map_err(|_| failed(-EIO)))?;
    let signature = cms.to_der().map_err(|e| (-EIO, e))?;
    if signature.is_empty() {
        return Err(failed(-EIO));
    }
    if signature.len() > max {
        return Err(failed(-ENOSPC));
    }
    Ok((signature, payload_sha256))
}
