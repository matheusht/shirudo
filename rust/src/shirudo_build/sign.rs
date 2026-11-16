// SPDX-License-Identifier: BSD-2-Clause
// Copyright (C) 2025 Google LLC.
// Copyright (c) 2026 Authors of shirudo

//! The CMS signer: a detached ML-DSA-87 signature over a loader's
//! instructions and data, the bytes the kernel reassembles and verifies
//! at BPF_PROG_LOAD. Only shirudo-build reaches it.
//!
//! Re-implemented from bpftool's signer (tools/bpf/bpftool/sign.c,
//! GPL-2.0-only OR BSD-2-Clause), under its BSD-2-Clause branch.

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::ptr;
use std::fs::OpenOptions;
use std::os::fd::{IntoRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use super::{error, path, strerr};
use crate::errno::{E2BIG, EINVAL, EIO, ENOMEM, ENOSPC, EPERM};
use crate::sys::libc::{O_NONBLOCK, S_IFMT, S_IFREG};
use crate::sys::openssl::{
    BIO_CLOSE, BIO_CTRL_INFO, BIO_CTRL_RESET, BIO_ctrl, BIO_free, BIO_new, BIO_new_fd,
    BIO_new_file, BIO_new_mem_buf, BIO_read, BIO_s_mem, Bio, CMS_BINARY, CMS_ContentInfo_free,
    CMS_DETACHED, CMS_add1_signer, CMS_final, CMS_sign, CmsContentInfo, ERR_error_string_n,
    ERR_get_error_all, ERR_peek_error, EVP_Digest, EVP_PKEY_free, EVP_PKEY_get0_type_name,
    EVP_PKEY_is_a, EVP_sha256, EVP_sha512, EvpPkey, OpenSSL_version_num, PEM_read_bio_PrivateKey,
    PEM_read_bio_X509, X509, X509_free, d2i_X509_bio, i2d_CMS_bio_stream,
};

const CMS_NOCERTS: c_uint = 0x2;
const CMS_NOATTR: c_uint = 0x100;
const CMS_NOSMIMECAP: c_uint = 0x200;
const CMS_STREAM: c_uint = 0x1000;
const CMS_PARTIAL: c_uint = 0x4000;
const CMS_USE_KEYID: c_uint = 0x10000;
const CMS_NO_SIGNING_TIME: c_uint = 0x40_0000;
const ERR_TXT_STRING: c_int = 0x02;

fn say(text: String) {
    error(text.as_bytes());
}

/// OpenSSL's queued errors, each with where it rose, logged and taken.
fn display_errors() {
    loop {
        let (mut file, mut line, mut data, mut flags): (
            *const c_char,
            c_int,
            *const c_char,
            c_int,
        ) = (ptr::null(), 0, ptr::null(), 0);
        // SAFETY: rooms for where the error rose and its text.
        let e = unsafe {
            ERR_get_error_all(&mut file, &mut line, ptr::null_mut(), &mut data, &mut flags)
        };
        if e == 0 {
            return;
        }
        let mut buf = [0u8; 256];
        // SAFETY: the error and the room for its string.
        unsafe { ERR_error_string_n(e, buf.as_mut_ptr().cast(), buf.len()) };
        let text = String::from_utf8_lossy(crate::text::cstr(&buf)).into_owned();
        let file = if file.is_null() {
            String::new()
        } else {
            // SAFETY: OpenSSL's C string.
            unsafe { CStr::from_ptr(file) }
                .to_string_lossy()
                .into_owned()
        };
        if !data.is_null() && flags & ERR_TXT_STRING != 0 {
            // SAFETY: OpenSSL's C string.
            let data = unsafe { CStr::from_ptr(data) }.to_string_lossy();
            say(format!("OpenSSL {text}: {file}:{line}: {data}"));
        } else {
            say(format!("OpenSSL {text}: {file}:{line}"));
        }
    }
}

/// [`display_errors`] when `failed` and OpenSSL queued any.
fn display_errors_if(failed: bool) {
    // SAFETY: peeks at this thread's error queue.
    if failed && unsafe { ERR_peek_error() } != 0 {
        display_errors();
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

/// An OpenSSL object, freed when it goes.
struct Owned<T>(*mut T, unsafe extern "C" fn(*mut T));

impl<T> Drop for Owned<T> {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the object, freed once, here.
            unsafe { (self.1)(self.0) };
        }
    }
}

unsafe extern "C" fn bio_free(b: *mut Bio) {
    // SAFETY: the caller's BIO.
    unsafe { BIO_free(b) };
}

unsafe extern "C" fn cms_free(c: *mut CmsContentInfo) {
    // SAFETY: the caller's CMS structure.
    unsafe { CMS_ContentInfo_free(c) };
}

fn private_key(pkey: &CStr) -> Option<Owned<EvpPkey>> {
    let fd = open_signing_key(pkey).ok()?.into_raw_fd();
    // SAFETY: the descriptor, which the BIO closes from here.
    let b = Owned(unsafe { BIO_new_fd(fd, BIO_CLOSE) }, bio_free);
    if b.0.is_null() {
        // SAFETY: the descriptor the BIO did not take.
        unsafe { crate::sys::libc::close(fd) };
        display_errors_if(true);
        return None;
    }
    // SAFETY: the BIO, no password.
    let key = Owned(
        unsafe { PEM_read_bio_PrivateKey(b.0, ptr::null_mut(), None, ptr::null_mut()) },
        EVP_PKEY_free,
    );
    drop(b);
    display_errors_if(key.0.is_null());
    (!key.0.is_null()).then_some(key)
}

/// The certificate at `cert`, DER or PEM by its first two bytes.
fn certificate(cert: &CStr) -> Option<Owned<X509>> {
    // SAFETY: two C strings.
    let b = Owned(
        unsafe { BIO_new_file(cert.as_ptr(), c"rb".as_ptr()) },
        bio_free,
    );
    let x509 = (|| {
        if b.0.is_null() {
            return ptr::null_mut();
        }
        let mut head = [0u8; 2];
        // SAFETY: the BIO and room for two bytes.
        if unsafe { BIO_read(b.0, head.as_mut_ptr().cast(), 2) } != 2 {
            return ptr::null_mut();
        }
        // SAFETY: the BIO, rewound.
        if unsafe { BIO_ctrl(b.0, BIO_CTRL_RESET, 0, ptr::null_mut()) } != 0 {
            return ptr::null_mut();
        }
        // A SEQUENCE with a long-form length is raw DER.
        if head[0] == 0x30 && (0x81..=0x84).contains(&head[1]) {
            // SAFETY: the BIO.
            unsafe { d2i_X509_bio(b.0, ptr::null_mut()) }
        } else {
            // SAFETY: the BIO, no password.
            unsafe { PEM_read_bio_X509(b.0, ptr::null_mut(), None, ptr::null_mut()) }
        }
    })();
    drop(b);
    display_errors_if(x509.is_null());
    (!x509.is_null()).then_some(Owned(x509, X509_free))
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
    let result = sign(insns, data, max, pkey, cert);
    display_errors_if(result.is_err());
    result
}

fn sign(
    insns: &[u8],
    data: &[u8],
    max: usize,
    pkey: &CStr,
    cert: &CStr,
) -> Result<(Vec<u8>, [u8; 32]), c_int> {
    // The signature and the payload digest span insns || data, the
    // concatenation the kernel folds and verifies at load.
    let content = [insns, data].concat();
    let len = c_int::try_from(content.len()).map_err(|_| -E2BIG)?;
    // SAFETY: the content, which outlives the BIO.
    let input = Owned(
        unsafe { BIO_new_mem_buf(content.as_ptr().cast(), len) },
        bio_free,
    );
    if input.0.is_null() {
        return Err(-ENOMEM);
    }
    let key = private_key(pkey).ok_or(-EINVAL)?;
    // SAFETY: the key and a C string.
    if unsafe { EVP_PKEY_is_a(key.0, c"ML-DSA-87".as_ptr()) } != 1 {
        // SAFETY: the key; its type's name, a C string or null.
        let name = unsafe { EVP_PKEY_get0_type_name(key.0) };
        let name = if name.is_null() {
            "unknown".into()
        } else {
            // SAFETY: OpenSSL's C string.
            unsafe { CStr::from_ptr(name) }.to_string_lossy()
        };
        // The target's trust set refuses the smaller parameter sets, so
        // an artifact signed with one could never load.
        say(format!(
            "{}: {name} key; shirudo signs with ML-DSA-87 only (re-key with shirudo genkey)",
            shown(pkey)
        ));
        return Err(-EINVAL);
    }
    let x509 = certificate(cert).ok_or(-EINVAL)?;

    let mut flags = CMS_NOCERTS
        | CMS_BINARY
        | CMS_NOSMIMECAP
        | CMS_NO_SIGNING_TIME
        | CMS_USE_KEYID
        | CMS_NOATTR;
    // SAFETY: the version.
    let version = unsafe { OpenSSL_version_num() };
    // SAFETY: a static digest.
    let mut digest = unsafe { EVP_sha256() };
    if (0x3000_0000..0x4000_0000).contains(&version) {
        // OpenSSL 3 cannot combine ML-DSA with CMS_NOATTR, so it signs
        // attributes, where the kernel takes ML-DSA only over SHA-512
        // (crypto/asymmetric_keys/public_key.c). bpftool and module
        // signing do the same; OpenSSL 4 signs the content directly.
        flags &= !CMS_NOATTR;
        // SAFETY: a static digest.
        digest = unsafe { EVP_sha512() };
    }
    let cms = Owned(
        // SAFETY: no signer yet, so a partial structure.
        unsafe {
            CMS_sign(
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                CMS_NOCERTS | CMS_PARTIAL | CMS_BINARY | CMS_DETACHED | CMS_STREAM,
            )
        },
        cms_free,
    );
    if cms.0.is_null() {
        return Err(-EINVAL);
    }
    // SAFETY: the structure, the certificate, the key and the digest.
    if unsafe { CMS_add1_signer(cms.0, x509.0, key.0, digest, flags) }.is_null() {
        return Err(-EINVAL);
    }
    // SAFETY: the structure and the content's BIO.
    if unsafe { CMS_final(cms.0, input.0, ptr::null_mut(), CMS_NOCERTS | CMS_BINARY) } != 1 {
        return Err(-EIO);
    }
    let mut payload_sha256 = [0u8; 32];
    let mut n: c_uint = 32;
    // SAFETY: the content, the room for its digest and a static digest.
    let ret = unsafe {
        EVP_Digest(
            content.as_ptr().cast(),
            content.len(),
            payload_sha256.as_mut_ptr(),
            &mut n,
            EVP_sha256(),
            ptr::null_mut(),
        )
    };
    if ret != 1 {
        return Err(-EIO);
    }
    // SAFETY: a static method.
    let out = Owned(unsafe { BIO_new(BIO_s_mem()) }, bio_free);
    if out.0.is_null() {
        return Err(-ENOMEM);
    }
    // SAFETY: the memory BIO and the finished structure.
    if unsafe { i2d_CMS_bio_stream(out.0, cms.0, ptr::null_mut(), 0) } == 0 {
        return Err(-EIO);
    }
    // SAFETY: the memory BIO, how much it holds.
    let len = unsafe { BIO_ctrl(out.0, BIO_CTRL_INFO, 0, ptr::null_mut()) };
    if len <= 0 {
        return Err(-EIO);
    }
    let len = len as usize;
    if len > max {
        return Err(-ENOSPC);
    }
    let mut signature = vec![0u8; len];
    // SAFETY: the memory BIO and the room for what it holds.
    if unsafe { BIO_read(out.0, signature.as_mut_ptr().cast::<c_void>(), len as c_int) }
        != len as c_int
    {
        return Err(-EIO);
    }
    Ok((signature, payload_sha256))
}
