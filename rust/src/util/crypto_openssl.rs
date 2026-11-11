// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The crypto of `util/crypto.h` on libcrypto, linked into both profiles:
//! SHA-256, HMAC and AES, base64, the P-256 and RSA-OAEP operations of
//! the TPM's protocol, and the X.509 certificates and CMS signatures a
//! target trusts. Every key algorithm the kernel verifies comes from one
//! implementation.

use core::ffi::{CStr, c_char, c_int, c_long, c_uint, c_ulong, c_void};

use crate::errno::{EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOMEM, ENOPKG, EPROTONOSUPPORT};
use crate::sys::io::{check_trusted, read_fd};
use crate::sys::libc::{O_CLOEXEC, O_RDONLY, Tm, close, errno, open, strftime};
use crate::sys::log::pr_err;
use crate::sys::malloc::{xfree, xmalloc};
use crate::sys::openssl::*;
use crate::text::{cstr, strscpy};

pub(crate) const SHA256_LEN: usize = 32;

/// `KEYS_DER_MAX` of util/keys.h: the largest certificate read.
const KEYS_DER_MAX: usize = 1024 * 1024;

/// `struct cert`: an X.509 certificate, NULL before one is read.
#[repr(C)]
pub struct Cert {
    imp: *mut X509,
}

impl Cert {
    pub(crate) const fn new() -> Self {
        Cert {
            imp: core::ptr::null_mut(),
        }
    }

    /// The cert of an OpenSSL `X509`, which the caller keeps and frees.
    pub(crate) const fn of_x509(x509: *mut c_void) -> Self {
        Cert { imp: x509.cast() }
    }
}

/// `struct sha256_ctx`: a digest under way, which sha256_final() or
/// sha256_free() releases.
#[repr(C)]
pub struct Sha256Ctx {
    imp: *mut EvpMdCtx,
}

impl Sha256Ctx {
    pub(crate) const fn new() -> Self {
        Sha256Ctx {
            imp: core::ptr::null_mut(),
        }
    }
}

/// `struct cert_pubkey`.
#[repr(C)]
pub struct CertPubkey {
    rsa: bool,
    n: [u8; 512],
    n_len: usize,
    e: u32,
    x: [u8; 32],
    y: [u8; 32],
}

const _: () = assert!(size_of::<CertPubkey>() == 600);

/// OPENSSL_free().
///
/// # Safety
///
/// `p` is NULL or from OpenSSL's allocator.
unsafe fn openssl_free(p: *mut c_void) {
    // SAFETY: the caller passes such a pointer.
    unsafe { CRYPTO_free(p, c"".as_ptr(), 0) };
}

/// The certificate at `path`, PEM or DER, from a file only root may
/// write: 0, -EINVAL for one that does not parse, or -errno.
fn read_x509(path: *const c_char, out: &mut *mut X509) -> c_int {
    *out = core::ptr::null_mut();
    // SAFETY: the caller's C string and flags without a mode.
    let fd = unsafe { open(path, O_RDONLY | O_CLOEXEC) };
    if fd < 0 {
        return -errno();
    }
    // SAFETY: the fd, the caller's path, and not a secret.
    let ret = unsafe { check_trusted(fd, path, false) };
    if ret != 0 {
        // SAFETY: the fd open() gave, closed once.
        unsafe { close(fd) };
        return ret;
    }
    // SAFETY: the fd, which the BIO takes over.
    let bio = unsafe { BIO_new_fd(fd, BIO_CLOSE) };
    if bio.is_null() {
        // SAFETY: the fd open() gave, closed once.
        unsafe { close(fd) };
        return -ENOMEM;
    }
    // SAFETY: the BIO, freed once with its fd.
    let cert = unsafe {
        let mut cert = PEM_read_bio_X509(bio, core::ptr::null_mut(), None, core::ptr::null_mut());

        if cert.is_null() {
            ERR_clear_error();
            // File BIOs report a successful reset as 0, not 1.
            if BIO_ctrl(bio, BIO_CTRL_RESET, 0, core::ptr::null_mut()) >= 0 {
                cert = d2i_X509_bio(bio, core::ptr::null_mut());
            }
        }
        BIO_free(bio);
        cert
    };
    if cert.is_null() {
        // SAFETY: a call that takes no pointer.
        unsafe { ERR_clear_error() };
        return -EINVAL;
    }
    *out = cert;
    0
}

/// # Safety
///
/// `ctx` is NULL or points to a context.
pub(crate) unsafe fn sha256_init(ctx: *mut Sha256Ctx) -> c_int {
    // SAFETY: the caller passes NULL or a context.
    let Some(ctx) = (unsafe { ctx.as_mut() }) else {
        return -EINVAL;
    };

    ctx.imp = core::ptr::null_mut();
    // SAFETY: calls that take no pointer, and the new context.
    unsafe {
        let md = EVP_MD_CTX_new();

        if md.is_null() || EVP_DigestInit_ex(md, EVP_sha256(), core::ptr::null_mut()) != 1 {
            EVP_MD_CTX_free(md);
            return -EIO;
        }
        ctx.imp = md;
    }
    0
}

/// # Safety
///
/// `ctx` is NULL or points to a context, and `data` holds `len` bytes.
pub(crate) unsafe fn sha256_update(ctx: *mut Sha256Ctx, data: *const c_void, len: usize) -> c_int {
    // SAFETY: the caller passes NULL or a context.
    let Some(ctx) = (unsafe { ctx.as_mut() }) else {
        return -EINVAL;
    };

    if ctx.imp.is_null() || (len != 0 && data.is_null()) {
        return -EINVAL;
    }
    // SAFETY: the context's digest, and the caller's data.
    if unsafe { EVP_DigestUpdate(ctx.imp, data, len) } == 1 {
        0
    } else {
        -EIO
    }
}

/// # Safety
///
/// `ctx` is NULL or points to a context, and `out` is NULL or has room
/// for 32 bytes.
pub(crate) unsafe fn sha256_final(ctx: *mut Sha256Ctx, out: *mut u8) -> c_int {
    let mut len: c_uint = 0;
    // SAFETY: the caller passes NULL or a context.
    let Some(ctx) = (unsafe { ctx.as_mut() }) else {
        return -EINVAL;
    };

    if ctx.imp.is_null() || out.is_null() {
        return -EINVAL;
    }
    // SAFETY: the context's digest, freed once, and the caller's room.
    let ret = unsafe {
        let ok = EVP_DigestFinal_ex(ctx.imp, out, &mut len) == 1 && len == 32;

        EVP_MD_CTX_free(ctx.imp);
        if ok { 0 } else { -EIO }
    };
    ctx.imp = core::ptr::null_mut();
    ret
}

/// # Safety
///
/// `ctx` is NULL or points to a context.
pub(crate) unsafe fn sha256_free(ctx: *mut Sha256Ctx) {
    // SAFETY: the caller passes NULL or a context.
    if let Some(ctx) = unsafe { ctx.as_mut() } {
        // SAFETY: the context's digest or NULL, freed once.
        unsafe { EVP_MD_CTX_free(ctx.imp) };
        ctx.imp = core::ptr::null_mut();
    }
}

/// # Safety
///
/// `data` holds `len` bytes, and `out` is NULL or has room for 32.
pub(crate) unsafe fn sha256_buffer(data: *const c_void, len: usize, out: *mut u8) -> c_int {
    let mut ctx = Sha256Ctx::new();

    // SAFETY: the context here, and the caller's data and room.
    unsafe {
        let mut ret = sha256_init(&mut ctx);

        if ret == 0 {
            ret = sha256_update(&mut ctx, data, len);
        }
        if ret == 0 {
            ret = sha256_final(&mut ctx, out);
        } else {
            sha256_free(&mut ctx);
        }
        ret
    }
}

/// # Safety
///
/// `data` is NULL or holds `len` bytes, and `out` is NULL or has room
/// for `out_sz`.
unsafe fn base64_encode(data: *const u8, len: usize, out: *mut c_char, out_sz: usize) -> c_int {
    if data.is_null() || out.is_null() || len > c_int::MAX as usize {
        return -EINVAL;
    }
    let need = 4 * len.div_ceil(3) + 1;

    if out_sz < need {
        return -EINVAL;
    }
    // SAFETY: the caller's room for need bytes, and its data.
    unsafe {
        if EVP_EncodeBlock(out.cast(), data, len as c_int) < 0 {
            return -EIO;
        }
        *out.add(need - 1) = 0;
    }
    0
}

/// The P-256 public key at the point (x, y), or NULL for one not on the
/// curve.
fn p256_public_key(x: &[u8; 32], y: &[u8; 32]) -> *mut EvpPkey {
    let mut point = [0u8; 65];
    let mut pkey: *mut EvpPkey = core::ptr::null_mut();

    point[0] = 0x04;
    point[1..33].copy_from_slice(x);
    point[33..].copy_from_slice(y);
    // SAFETY: parameters naming the group and the point, both of which
    // outlive the calls, and the context made and freed here.
    unsafe {
        let mut params = [
            OSSL_PARAM_construct_utf8_string(c"group".as_ptr(), c"P-256".as_ptr().cast_mut(), 0),
            OSSL_PARAM_construct_octet_string(
                c"pub".as_ptr(),
                point.as_mut_ptr().cast(),
                point.len(),
            ),
            OSSL_PARAM_construct_end(),
        ];
        let kctx =
            EVP_PKEY_CTX_new_from_name(core::ptr::null_mut(), c"EC".as_ptr(), core::ptr::null());

        if kctx.is_null()
            || EVP_PKEY_fromdata_init(kctx) <= 0
            || EVP_PKEY_fromdata(kctx, &mut pkey, EVP_PKEY_PUBLIC_KEY, params.as_mut_ptr()) <= 0
        {
            EVP_PKEY_free(pkey);
            pkey = core::ptr::null_mut();
        }
        EVP_PKEY_CTX_free(kctx);
    }
    pkey
}

/// 0 when (r, s) is the ECDSA P-256 signature of the digest by the key
/// at (x, y), -EKEYREJECTED when not, -EINVAL for a key off the curve.
fn ecdsa_p256_verify(
    x: &[u8; 32],
    y: &[u8; 32],
    digest: &[u8; 32],
    r: &[u8; 32],
    s: &[u8; 32],
) -> c_int {
    let mut der: *mut u8 = core::ptr::null_mut();
    let mut ret = -EIO;
    let pkey = p256_public_key(x, y);

    // SAFETY: what OpenSSL gives here, each freed once below, the
    // numbers handed to the signature once it takes them.
    unsafe {
        let (mut br, mut bs, mut sig, mut vctx) = (
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );

        'out: {
            if pkey.is_null() {
                ret = -EINVAL;
                break 'out;
            }
            br = BN_bin2bn(r.as_ptr(), 32, core::ptr::null_mut());
            bs = BN_bin2bn(s.as_ptr(), 32, core::ptr::null_mut());
            sig = ECDSA_SIG_new();
            if br.is_null() || bs.is_null() || sig.is_null() || ECDSA_SIG_set0(sig, br, bs) == 0 {
                break 'out;
            }
            br = core::ptr::null_mut();
            bs = core::ptr::null_mut();
            let der_len = i2d_ECDSA_SIG(sig, &mut der);
            if der_len <= 0 {
                break 'out;
            }
            vctx = EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), pkey, core::ptr::null());
            if vctx.is_null()
                || EVP_PKEY_verify_init(vctx) <= 0
                || EVP_PKEY_CTX_set_signature_md(vctx, EVP_sha256()) <= 0
            {
                break 'out;
            }
            ret = if EVP_PKEY_verify(vctx, der, der_len as usize, digest.as_ptr(), 32) == 1 {
                0
            } else {
                -EKEYREJECTED
            };
        }
        openssl_free(der.cast());
        ECDSA_SIG_free(sig);
        BN_free(br);
        BN_free(bs);
        EVP_PKEY_CTX_free(vctx);
        EVP_PKEY_free(pkey);
        ERR_clear_error();
    }
    ret
}

/// The certificate in `der` into `cert`: 0 or -EINVAL.
///
/// # Safety
///
/// `der` holds `len` bytes, and `cert` points to a cert.
pub(crate) unsafe fn cert_read_der(der: *const u8, len: usize, cert: *mut Cert) -> c_int {
    let mut p = der;

    if der.is_null() || cert.is_null() || len > c_long::MAX as usize {
        return -EINVAL;
    }
    // SAFETY: the caller's DER bytes and cert.
    unsafe {
        (*cert).imp = d2i_X509(core::ptr::null_mut(), &mut p, len as c_long);
        if (*cert).imp.is_null() { -EINVAL } else { 0 }
    }
}

/// The certificate in memory, DER or PEM, as the C reader accepted.
///
/// # Safety
///
/// `buf` holds `len` bytes, and `cert` points to a cert.
pub(crate) unsafe fn cert_read_memory(buf: *const u8, len: usize, cert: *mut Cert) -> c_int {
    if buf.is_null() || cert.is_null() || len > c_int::MAX as usize {
        return -EINVAL;
    }
    // SAFETY: the caller supplies the bytes and cert.
    if unsafe { cert_read_der(buf, len, cert) } == 0 {
        return 0;
    }
    // SAFETY: failed DER parsing leaves OpenSSL errors before the PEM attempt.
    unsafe { ERR_clear_error() };
    // SAFETY: the caller supplies the bytes, whose length fits c_int.
    let bio = unsafe { BIO_new_mem_buf(buf.cast(), len as c_int) };
    if bio.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the BIO stays alive for this read, then is released once.
    unsafe {
        (*cert).imp = PEM_read_bio_X509(bio, core::ptr::null_mut(), None, core::ptr::null_mut());
        BIO_free(bio);
        if (*cert).imp.is_null() {
            ERR_clear_error();
            return -EINVAL;
        }
    }
    0
}

/// # Safety
///
/// `path` is NULL or a C string, and `cert` NULL or points to a cert.
pub(crate) unsafe fn cert_read_file(path: *const c_char, cert: *mut Cert) -> c_int {
    let mut x509 = core::ptr::null_mut();

    if path.is_null() || cert.is_null() {
        return -EINVAL;
    }
    let ret = read_x509(path, &mut x509);
    // SAFETY: the caller's cert.
    unsafe { (*cert).imp = x509 };
    ret
}

/// # Safety
///
/// `cert` is NULL or points to a cert.
pub(crate) unsafe fn cert_read_fd(fd: c_int, cert: *mut Cert) -> c_int {
    let mut der: *mut u8 = core::ptr::null_mut();
    let mut len = 0usize;

    if fd < 0 || cert.is_null() {
        return -EINVAL;
    }
    // SAFETY: the caller's fd, a label, a bound, and where read_fd()
    // leaves the bytes and their count.
    let ret = unsafe {
        read_fd(
            fd,
            c"certificate".as_ptr(),
            KEYS_DER_MAX,
            (&raw mut der).cast(),
            &mut len,
        )
    };
    if ret != 0 {
        return ret;
    }
    // SAFETY: the len bytes read_fd() gave, freed once with their NUL.
    unsafe {
        let ret = cert_read_der(der, len, cert);

        xfree(der.cast(), len + 1);
        ret
    }
}

/// # Safety
///
/// `cert` is NULL or points to a cert.
pub(crate) unsafe fn cert_free(cert: *mut Cert) {
    // SAFETY: the caller passes NULL or a cert.
    if let Some(cert) = unsafe { cert.as_mut() } {
        // SAFETY: its certificate or NULL, freed once.
        unsafe { X509_free(cert.imp) };
        cert.imp = core::ptr::null_mut();
    }
}

/// The certificate a cert holds, or none.
///
/// # Safety
///
/// `cert` is NULL or points to a cert.
unsafe fn x509_of(cert: *const Cert) -> Option<*mut X509> {
    // SAFETY: the caller passes NULL or a cert.
    unsafe { cert.as_ref() }
        .map(|c| c.imp)
        .filter(|x| !x.is_null())
}

/// SHA-256 over the DER SubjectPublicKeyInfo, the bytes Go's
/// x509.MarshalPKIXPublicKey writes; X509_pubkey_digest() hashes only the
/// key's bit string, which is easy to mistake for it. Re-encoding through
/// i2d_X509_PUBKEY keeps the value identical for every key algorithm the
/// X.509 parser accepts, including ML-DSA keys libcrypto cannot otherwise
/// marshal as a bare EVP_PKEY on older releases.
///
/// # Safety
///
/// `cert` is NULL or points to a cert, and `out` NULL or room for 32.
pub(crate) unsafe fn cert_pubkey_digest(cert: *const Cert, out: *mut u8) -> c_int {
    let mut len: c_uint = 0;

    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }).filter(|_| !out.is_null()) else {
        return -EINVAL;
    };
    // SAFETY: the certificate, its key, the room xmalloc() gives freed
    // once, and the caller's room for the digest.
    unsafe {
        let spki = X509_get_X509_PUBKEY(x509);
        if spki.is_null() {
            return -EINVAL;
        }
        let der_len = i2d_X509_PUBKEY(spki, core::ptr::null_mut());
        if der_len <= 0 {
            return -EINVAL;
        }
        let der: *mut u8 = xmalloc(der_len as usize).cast();
        if der.is_null() {
            return -ENOMEM;
        }
        let mut p = der;
        let ret = if i2d_X509_PUBKEY(spki, &mut p) == der_len
            && EVP_Digest(
                der.cast(),
                der_len as usize,
                out,
                &mut len,
                EVP_sha256(),
                core::ptr::null_mut(),
            ) != 0
            && len as usize == SHA256_LEN
        {
            0
        } else {
            -EINVAL
        };

        xfree(der.cast(), der_len as usize);
        ret
    }
}

/// The provider's name for the cert's public key, "ML-DSA-87".
///
/// # Safety
///
/// `cert` is NULL or points to a cert, and `out` NULL or room for
/// `out_sz`.
unsafe fn cert_key_algorithm(cert: *const Cert, out: *mut c_char, out_sz: usize) -> c_int {
    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }).filter(|_| !out.is_null() && out_sz != 0) else {
        return -EINVAL;
    };
    // SAFETY: the certificate and its key.
    let name = unsafe {
        let pubk = X509_get0_pubkey(x509);

        if pubk.is_null() {
            core::ptr::null()
        } else {
            EVP_PKEY_get0_type_name(pubk)
        }
    };
    if name.is_null() {
        return -ENOPKG;
    }
    // SAFETY: the caller's room, and OpenSSL's C string.
    let (out, name) = unsafe {
        (
            crate::ffi::bytes_mut(out.cast(), out_sz),
            CStr::from_ptr(name),
        )
    };
    if strscpy(out, name.to_bytes()).is_err() {
        return -ENAMETOOLONG;
    }
    0
}

/// The subject on one line, "O=Example, CN=fleet", control bytes
/// escaped.
///
/// # Safety
///
/// `cert` is NULL or points to a cert, and `out` NULL or room for
/// `out_sz`.
unsafe fn cert_subject(cert: *const Cert, out: *mut c_char, out_sz: usize) -> c_int {
    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }).filter(|_| !out.is_null() && out_sz != 0) else {
        return -EINVAL;
    };
    // SAFETY: a memory BIO freed once, the certificate's subject, and the
    // caller's room for out_sz bytes.
    unsafe {
        let bio = BIO_new(BIO_s_mem());
        if bio.is_null() {
            return -ENOMEM;
        }
        let ret = 'out: {
            if X509_NAME_print_ex(
                bio,
                X509_get_subject_name(x509),
                0,
                XN_FLAG_ONELINE & !XN_FLAG_SPC_EQ,
            ) < 0
            {
                break 'out -EINVAL;
            }
            let mut text: *mut c_char = core::ptr::null_mut();
            // BIO_get_mem_data().
            let len = BIO_ctrl(bio, BIO_CTRL_INFO, 0, (&raw mut text).cast());
            if len < 0 || len as usize >= out_sz {
                break 'out -ENAMETOOLONG;
            }
            if len != 0 {
                core::ptr::copy_nonoverlapping(text, out, len as usize);
            }
            *out.add(len as usize) = 0;
            0
        };

        BIO_free(bio);
        ret
    }
}

/// The start of the validity period as a UTC date, YYYY-MM-DD.
///
/// # Safety
///
/// `cert` is NULL or points to a cert, and `out` has room for 11 bytes.
unsafe fn cert_not_before(cert: *const Cert, out: *mut c_char) -> c_int {
    let mut tm = Tm::zeroed();

    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }) else {
        return -EINVAL;
    };
    // SAFETY: the certificate, a struct tm to fill, and the caller's
    // room for 11 bytes.
    unsafe {
        let t = X509_get0_notBefore(x509);

        if t.is_null() || ASN1_TIME_to_tm(t, &mut tm) == 0 {
            return -EINVAL;
        }
        if strftime(out, 11, c"%Y-%m-%d".as_ptr(), &tm) == 10 {
            0
        } else {
            -EINVAL
        }
    }
}

/// The CMS blob in `signature`, all of it and nothing more, or NULL.
fn read_cms(signature: *const u8, len: usize) -> *mut CmsContentInfo {
    let mut next = signature;

    if signature.is_null() || len == 0 || len > c_int::MAX as usize {
        return core::ptr::null_mut();
    }
    // SAFETY: the caller's len bytes of signature.
    unsafe {
        let mut cms = d2i_CMS_ContentInfo(core::ptr::null_mut(), &mut next, len as c_long);

        if !cms.is_null() && next != signature.add(len) {
            CMS_ContentInfo_free(cms);
            cms = core::ptr::null_mut();
        }
        cms
    }
}

/// Whether `signature` is a detached CMS signature of `payload` by the
/// cert. The algorithm comes from the SignerInfo, so an ML-DSA
/// signature, with signedAttrs and SHA-512 or bare on OpenSSL 4, and an
/// RSA one verify through one call; ML-DSA needs libcrypto >= 3.5.
///
/// # Safety
///
/// `payload` and `signature` hold their lengths, and `cert` is NULL or
/// points to a cert.
pub(crate) unsafe fn verify_detached(
    payload: *const u8,
    payload_len: usize,
    signature: *const u8,
    signature_len: usize,
    cert: *const Cert,
) -> c_int {
    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }) else {
        return -EINVAL;
    };
    if payload.is_null()
        || signature.is_null()
        || payload_len > c_int::MAX as usize
        || signature_len > c_int::MAX as usize
    {
        return -EINVAL;
    }
    let mut ret = -EINVAL;
    // SAFETY: what OpenSSL gives here, each freed once below, the cert's
    // certificate lent to the store and the stack, and the caller's
    // payload and signature.
    unsafe {
        let data = BIO_new_mem_buf(payload.cast(), payload_len as c_int);
        let out = BIO_new(BIO_s_null());
        let store = X509_STORE_new();
        let mut signers = core::ptr::null_mut();
        let mut cms = core::ptr::null_mut();

        'done: {
            if data.is_null()
                || out.is_null()
                || store.is_null()
                || X509_STORE_add_cert(store, x509) != 1
                || X509_STORE_set_flags(store, X509_V_FLAG_NO_CHECK_TIME) != 1
            {
                break 'done;
            }
            signers = OPENSSL_sk_new_null();
            if signers.is_null() || OPENSSL_sk_push(signers, x509.cast()) == 0 {
                break 'done;
            }
            cms = read_cms(signature, signature_len);
            if !cms.is_null()
                && CMS_verify(
                    cms,
                    signers,
                    store,
                    data,
                    out,
                    CMS_BINARY | CMS_DETACHED | CMS_NOINTERN,
                ) == 1
            {
                ret = 0;
            }
        }
        if ret != 0 {
            ERR_clear_error();
        }
        CMS_ContentInfo_free(cms);
        OPENSSL_sk_free(signers);
        X509_STORE_free(store);
        BIO_free(out);
        BIO_free(data);
    }
    ret
}

/// Whether a signer of the CMS blob names the cert, by key id or by
/// issuer and serial: 1 when one does, 0 when none, -EINVAL when the blob
/// does not parse. Says nothing about the signature's validity.
///
/// # Safety
///
/// `signature` holds `signature_len` bytes, and `cert` is NULL or points
/// to a cert.
unsafe fn cms_signed_by(signature: *const u8, signature_len: usize, cert: *const Cert) -> c_int {
    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }) else {
        return -EINVAL;
    };
    if signature.is_null() || signature_len > c_int::MAX as usize {
        return -EINVAL;
    }
    let mut ret = -EINVAL;
    let cms = read_cms(signature, signature_len);

    // SAFETY: the CMS, its signer infos, and the certificate.
    unsafe {
        if !cms.is_null() {
            let sis = CMS_get0_SignerInfos(cms);

            if !sis.is_null() {
                ret = 0;
                let mut i = 0;
                while i < OPENSSL_sk_num(sis) && ret == 0 {
                    if CMS_SignerInfo_cert_cmp(OPENSSL_sk_value(sis, i).cast(), x509) == 0 {
                        ret = 1;
                    }
                    i += 1;
                }
            }
        }
        if ret < 0 {
            ERR_clear_error();
        }
        CMS_ContentInfo_free(cms);
    }
    ret
}

/// # Safety
///
/// `key` holds `key_len` bytes, `data` `len`, and `out` has room for 32.
pub(crate) unsafe fn hmac_sha256(
    key: *const u8,
    key_len: usize,
    data: *const c_void,
    len: usize,
    out: *mut u8,
) -> c_int {
    let mut outl = 0usize;
    let mut ret = -EIO;

    // SAFETY: the MAC and its context, freed once, parameters naming the
    // digest, and the caller's key, data and room.
    unsafe {
        let mac = EVP_MAC_fetch(core::ptr::null_mut(), c"HMAC".as_ptr(), core::ptr::null());
        if mac.is_null() {
            return -EIO;
        }
        let params = [
            OSSL_PARAM_construct_utf8_string(c"digest".as_ptr(), c"SHA256".as_ptr().cast_mut(), 0),
            OSSL_PARAM_construct_end(),
        ];
        let ctx = EVP_MAC_CTX_new(mac);

        if !ctx.is_null()
            && EVP_MAC_init(ctx, key, key_len, params.as_ptr()) == 1
            && EVP_MAC_update(ctx, data.cast(), len) == 1
            && EVP_MAC_final(ctx, out, &mut outl, 32) == 1
            && outl == 32
        {
            ret = 0;
        }
        EVP_MAC_CTX_free(ctx);
        EVP_MAC_free(mac);
    }
    ret
}

/// AES-128 in CFB mode with a zero IV and no padding.
///
/// # Safety
///
/// `key` holds 16 bytes, `inp` `len`, and `out` has room for `len`.
pub(crate) unsafe fn aes128_cfb_encrypt(
    key: *const u8,
    inp: *const u8,
    len: usize,
    out: *mut u8,
) -> c_int {
    let (mut n, mut fin): (c_int, c_int) = (0, 0);
    let iv = [0u8; 16];
    let mut ret = -EIO;

    // SAFETY: the cipher context, freed once, and the caller's key, input
    // and room.
    unsafe {
        let ctx = EVP_CIPHER_CTX_new();

        if !ctx.is_null()
            && len <= c_int::MAX as usize
            && EVP_EncryptInit_ex(
                ctx,
                EVP_aes_128_cfb128(),
                core::ptr::null_mut(),
                key,
                iv.as_ptr(),
            ) == 1
            && EVP_CIPHER_CTX_set_padding(ctx, 0) == 1
            && EVP_EncryptUpdate(ctx, out, &mut n, inp, len as c_int) == 1
            && EVP_EncryptFinal_ex(ctx, out.add(n as usize), &mut fin) == 1
            && n as usize + fin as usize == len
        {
            ret = 0;
        }
        EVP_CIPHER_CTX_free(ctx);
    }
    ret
}

/// RSA-OAEP with SHA-256, MGF1-SHA-256 and the label, to the modulus `n`
/// with the public exponent `e`, 0 for 65537.
///
/// # Safety
///
/// `n`, `label` and `inp` hold their lengths, `out` has room for `cap`,
/// and `out_len` points to a size.
#[allow(clippy::too_many_arguments)]
unsafe fn rsa_oaep_encrypt(
    n: *const u8,
    n_len: usize,
    e: u32,
    label: *const c_void,
    label_len: usize,
    inp: *const u8,
    in_len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    if n_len > c_int::MAX as usize || label_len > c_int::MAX as usize {
        return -EINVAL;
    }
    let mut ret = -EIO;
    // SAFETY: what OpenSSL gives here, each freed once below, the label
    // handed to the context once it takes it, and the caller's buffers.
    unsafe {
        let bn = BN_bin2bn(n, n_len as c_int, core::ptr::null_mut());
        let be = BN_new();
        let bld = OSSL_PARAM_BLD_new();
        let (mut params, mut kctx, mut ectx) = (
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        );
        let mut pkey: *mut EvpPkey = core::ptr::null_mut();
        let mut lbl: *mut u8 = core::ptr::null_mut();

        'out: {
            if bn.is_null()
                || be.is_null()
                || bld.is_null()
                || BN_set_word(be, c_ulong::from(if e != 0 { e } else { 65537 })) == 0
                || OSSL_PARAM_BLD_push_BN(bld, c"n".as_ptr(), bn) == 0
                || OSSL_PARAM_BLD_push_BN(bld, c"e".as_ptr(), be) == 0
            {
                break 'out;
            }
            params = OSSL_PARAM_BLD_to_param(bld);
            kctx = EVP_PKEY_CTX_new_from_name(
                core::ptr::null_mut(),
                c"RSA".as_ptr(),
                core::ptr::null(),
            );
            if params.is_null()
                || kctx.is_null()
                || EVP_PKEY_fromdata_init(kctx) <= 0
                || EVP_PKEY_fromdata(kctx, &mut pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0
            {
                ret = -EINVAL;
                break 'out;
            }
            lbl = CRYPTO_malloc(if label_len != 0 { label_len } else { 1 }, c"".as_ptr(), 0).cast();
            if lbl.is_null() {
                break 'out;
            }
            if label_len != 0 {
                core::ptr::copy_nonoverlapping(label.cast::<u8>(), lbl, label_len);
            }
            ectx = EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), pkey, core::ptr::null());
            if ectx.is_null()
                || EVP_PKEY_encrypt_init(ectx) <= 0
                || EVP_PKEY_CTX_set_rsa_padding(ectx, RSA_PKCS1_OAEP_PADDING) <= 0
                || EVP_PKEY_CTX_set_rsa_oaep_md(ectx, EVP_sha256()) <= 0
                || EVP_PKEY_CTX_set_rsa_mgf1_md(ectx, EVP_sha256()) <= 0
                || EVP_PKEY_CTX_set0_rsa_oaep_label(ectx, lbl.cast(), label_len as c_int) <= 0
            {
                break 'out;
            }
            // The context owns the label now.
            lbl = core::ptr::null_mut();
            *out_len = cap;
            if EVP_PKEY_encrypt(ectx, out, out_len, inp, in_len) <= 0 {
                break 'out;
            }
            ret = 0;
        }
        openssl_free(lbl.cast());
        EVP_PKEY_CTX_free(ectx);
        EVP_PKEY_CTX_free(kctx);
        EVP_PKEY_free(pkey);
        OSSL_PARAM_free(params);
        OSSL_PARAM_BLD_free(bld);
        BN_free(bn);
        BN_free(be);
    }
    ret
}

/// One ephemeral P-256 ECDH against the point (x, y): the ephemeral
/// public point and the shared secret's x coordinate.
fn ecdh_p256_ephemeral(
    x: &[u8; 32],
    y: &[u8; 32],
    eph_x: &mut [u8; 32],
    eph_y: &mut [u8; 32],
    z: &mut [u8; 32],
) -> c_int {
    let mut zlen = 32usize;
    let mut ret = -EIO;
    let peer = p256_public_key(x, y);

    // SAFETY: what OpenSSL gives here, each freed once below, and the
    // caller's room.
    unsafe {
        let (mut bx, mut by) = (core::ptr::null_mut(), core::ptr::null_mut());
        let (mut eph, mut dctx) = (core::ptr::null_mut(), core::ptr::null_mut());

        'out: {
            if peer.is_null() {
                ret = -EINVAL;
                break 'out;
            }
            eph = EVP_PKEY_Q_keygen(
                core::ptr::null_mut(),
                core::ptr::null(),
                c"EC".as_ptr(),
                c"P-256".as_ptr(),
            );
            if eph.is_null()
                || EVP_PKEY_get_bn_param(eph, c"qx".as_ptr(), &mut bx) == 0
                || EVP_PKEY_get_bn_param(eph, c"qy".as_ptr(), &mut by) == 0
                || BN_bn2binpad(bx, eph_x.as_mut_ptr(), 32) != 32
                || BN_bn2binpad(by, eph_y.as_mut_ptr(), 32) != 32
            {
                break 'out;
            }
            dctx = EVP_PKEY_CTX_new_from_pkey(core::ptr::null_mut(), eph, core::ptr::null());
            if dctx.is_null()
                || EVP_PKEY_derive_init(dctx) <= 0
                || EVP_PKEY_derive_set_peer(dctx, peer) <= 0
                || EVP_PKEY_derive(dctx, z.as_mut_ptr(), &mut zlen) <= 0
                || zlen != 32
            {
                break 'out;
            }
            ret = 0;
        }
        BN_free(bx);
        BN_free(by);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(eph);
        EVP_PKEY_free(peer);
    }
    ret
}

/// # Safety
///
/// `inp` holds `in_len` bytes, `out` has room for `cap`, and `out_len`
/// points to a size.
unsafe fn base64_decode(
    inp: *const c_char,
    in_len: usize,
    out: *mut u8,
    cap: usize,
    out_len: *mut usize,
) -> c_int {
    let (mut n, mut fin): (c_int, c_int) = (0, 0);
    let mut ret = -EINVAL;

    // SAFETY: the decoding context, freed once, and the caller's input,
    // room and size.
    unsafe {
        let ctx = EVP_ENCODE_CTX_new();

        if !ctx.is_null() && in_len <= c_int::MAX as usize && cap >= 3 * in_len.div_ceil(4) {
            EVP_DecodeInit(ctx);
            if EVP_DecodeUpdate(ctx, out, &mut n, inp.cast(), in_len as c_int) >= 0
                && EVP_DecodeFinal(ctx, out.add(n as usize), &mut fin) >= 0
            {
                *out_len = n as usize + fin as usize;
                ret = 0;
            }
        }
        EVP_ENCODE_CTX_free(ctx);
    }
    ret
}

/// `BN_num_bytes()`.
fn bn_num_bytes(a: *const Bignum) -> c_int {
    // SAFETY: a number OpenSSL gave.
    (unsafe { BN_num_bits(a) } + 7) / 8
}

/// The cert's RSA modulus and exponent, or its P-256 point:
/// -EPROTONOSUPPORT for another key.
///
/// # Safety
///
/// `cert` is NULL or points to a cert, and `out` to room for a
/// cert_pubkey.
unsafe fn cert_pubkey(cert: *const Cert, out: *mut CertPubkey) -> c_int {
    let mut group = [0u8; 32];
    let mut ret = -EINVAL;

    // SAFETY: the caller's room, zeroed whole first, as the C's memset.
    let out = unsafe {
        out.write_bytes(0, 1);
        &mut *out
    };
    // SAFETY: the caller passes NULL or a cert.
    let pk = match unsafe { x509_of(cert) } {
        // SAFETY: the certificate.
        Some(x509) => unsafe { X509_get0_pubkey(x509) },
        None => core::ptr::null_mut(),
    };
    if pk.is_null() {
        return -EINVAL;
    }
    // SAFETY: the key, the numbers it gives, each freed once below, and
    // the room of out.
    unsafe {
        let (mut a, mut b) = (core::ptr::null_mut(), core::ptr::null_mut());
        let id = EVP_PKEY_get_base_id(pk);

        if id == EVP_PKEY_RSA {
            if EVP_PKEY_get_bn_param(pk, c"n".as_ptr(), &mut a) != 0
                && EVP_PKEY_get_bn_param(pk, c"e".as_ptr(), &mut b) != 0
                && bn_num_bytes(a) <= out.n.len() as c_int
                && bn_num_bytes(b) <= 4
            {
                out.rsa = true;
                out.n_len = BN_bn2bin(a, out.n.as_mut_ptr()) as usize;
                out.e = BN_get_word(b) as u32;
                ret = 0;
            }
        } else if id == EVP_PKEY_EC {
            let p256 = EVP_PKEY_get_utf8_string_param(
                pk,
                c"group".as_ptr(),
                group.as_mut_ptr().cast(),
                group.len(),
                core::ptr::null_mut(),
            ) != 0
                && matches!(cstr(&group), b"P-256" | b"prime256v1");

            if p256
                && EVP_PKEY_get_bn_param(pk, c"qx".as_ptr(), &mut a) != 0
                && EVP_PKEY_get_bn_param(pk, c"qy".as_ptr(), &mut b) != 0
                && BN_bn2binpad(a, out.x.as_mut_ptr(), 32) == 32
                && BN_bn2binpad(b, out.y.as_mut_ptr(), 32) == 32
            {
                ret = 0;
            }
        } else {
            ret = -EPROTONOSUPPORT;
        }
        BN_free(a);
        BN_free(b);
    }
    ret
}

/// Chains the cert to the PEM bundle of trusted issuers at the path, an
/// intermediate in it a trust anchor too: 0, -EKEYREJECTED with libcrypto's
/// static explanation, or -EINVAL when the bundle cannot be loaded.
///
/// # Safety
///
/// `cert` is NULL or points to a cert, `bundle_path` is NULL or a C
/// string, and `reason` points to where the reason goes.
unsafe fn cert_verify_chain(
    cert: *const Cert,
    bundle_path: *const c_char,
    reason: *mut *const c_char,
) -> c_int {
    let mut ret = -EIO;

    // SAFETY: the caller's place for the reason.
    unsafe { *reason = c"".as_ptr() };
    // SAFETY: the caller passes NULL or a cert.
    let Some(x509) = (unsafe { x509_of(cert) }).filter(|_| !bundle_path.is_null()) else {
        return -EINVAL;
    };
    // SAFETY: the store and its context, freed once, the caller's path
    // and certificate, and its place for the reason.
    unsafe {
        let store = X509_STORE_new();
        if store.is_null() {
            return -ENOMEM;
        }
        let mut ctx = core::ptr::null_mut();

        'out: {
            if X509_STORE_load_file(store, bundle_path) != 1 {
                ret = -EINVAL;
                break 'out;
            }
            if X509_STORE_set_flags(store, X509_V_FLAG_PARTIAL_CHAIN) != 1 {
                break 'out;
            }
            ctx = X509_STORE_CTX_new();
            if ctx.is_null() || X509_STORE_CTX_init(ctx, store, x509, core::ptr::null_mut()) != 1 {
                break 'out;
            }
            if X509_verify_cert(ctx) == 1 {
                ret = 0;
            } else {
                *reason =
                    X509_verify_cert_error_string(c_long::from(X509_STORE_CTX_get_error(ctx)));
                ret = -EKEYREJECTED;
            }
        }
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
    }
    ret
}

/// Logs libcrypto's last error under `where`.
///
/// # Safety
///
/// `where_` is a C string.
unsafe fn openssl_complain(where_: *const c_char) {
    let mut buf = [0u8; 256];

    // SAFETY: the room of buf, and a format of two C strings with the
    // caller's and OpenSSL's.
    unsafe {
        ERR_error_string_n(ERR_get_error(), buf.as_mut_ptr().cast(), buf.len());
        pr_err(c"openssl: %s: %s".as_ptr(), where_, buf.as_ptr());
    }
}

mod capi {
    use core::ffi::{c_char, c_int, c_void};

    use super::{Cert, CertPubkey, Sha256Ctx};

    /// # Safety
    ///
    /// `ctx` is NULL or points to a context.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sha256_init(ctx: *mut Sha256Ctx) -> c_int {
        // SAFETY: the caller's pointer.
        unsafe { super::sha256_init(ctx) }
    }

    /// # Safety
    ///
    /// `ctx` is NULL or points to a context, and `data` holds `len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sha256_update(
        ctx: *mut Sha256Ctx,
        data: *const c_void,
        len: usize,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::sha256_update(ctx, data, len) }
    }

    /// # Safety
    ///
    /// `ctx` is NULL or points to a context, and `out` NULL or room for 32.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sha256_final(ctx: *mut Sha256Ctx, out: *mut u8) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::sha256_final(ctx, out) }
    }

    /// # Safety
    ///
    /// `ctx` is NULL or points to a context.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sha256_free(ctx: *mut Sha256Ctx) {
        // SAFETY: the caller's pointer.
        unsafe { super::sha256_free(ctx) }
    }

    /// # Safety
    ///
    /// `data` holds `len` bytes, and `out` is NULL or room for 32.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sha256_buffer(data: *const c_void, len: usize, out: *mut u8) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::sha256_buffer(data, len, out) }
    }

    /// # Safety
    ///
    /// `data` is NULL or holds `len` bytes, and `out` NULL or room for
    /// `out_sz`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn base64_encode(
        data: *const u8,
        len: usize,
        out: *mut c_char,
        out_sz: usize,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::base64_encode(data, len, out, out_sz) }
    }

    /// # Safety
    ///
    /// Each pointer holds 32 bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn ecdsa_p256_verify(
        x: *const [u8; 32],
        y: *const [u8; 32],
        digest: *const [u8; 32],
        r: *const [u8; 32],
        s: *const [u8; 32],
    ) -> c_int {
        // SAFETY: the caller's 32 bytes at each.
        unsafe { super::ecdsa_p256_verify(&*x, &*y, &*digest, &*r, &*s) }
    }

    /// # Safety
    ///
    /// `path` is NULL or a C string, and `cert` NULL or points to a cert.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_read_file(path: *const c_char, cert: *mut Cert) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::cert_read_file(path, cert) }
    }

    /// # Safety
    ///
    /// `cert` is NULL or points to a cert.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_read_fd(fd: c_int, cert: *mut Cert) -> c_int {
        // SAFETY: the caller's pointer.
        unsafe { super::cert_read_fd(fd, cert) }
    }

    /// # Safety
    ///
    /// `cert` is NULL or points to a cert.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_free(cert: *mut Cert) {
        // SAFETY: the caller's pointer.
        unsafe { super::cert_free(cert) }
    }

    /// # Safety
    ///
    /// `cert` is NULL or points to a cert, and `out` NULL or room for 32.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_pubkey_digest(cert: *const Cert, out: *mut u8) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::cert_pubkey_digest(cert, out) }
    }

    /// # Safety
    ///
    /// `cert` is NULL or points to a cert, and `out` NULL or room for
    /// `out_sz`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_key_algorithm(
        cert: *const Cert,
        out: *mut c_char,
        out_sz: usize,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::cert_key_algorithm(cert, out, out_sz) }
    }

    /// # Safety
    ///
    /// `cert` is NULL or points to a cert, and `out` NULL or room for
    /// `out_sz`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_subject(
        cert: *const Cert,
        out: *mut c_char,
        out_sz: usize,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::cert_subject(cert, out, out_sz) }
    }

    /// # Safety
    ///
    /// `cert` is NULL or points to a cert, and `out` has room for 11.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_not_before(cert: *const Cert, out: *mut c_char) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::cert_not_before(cert, out) }
    }

    /// # Safety
    ///
    /// `payload` and `signature` hold their lengths, and `cert` is NULL or
    /// points to a cert.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn verify_detached(
        payload: *const u8,
        payload_len: usize,
        signature: *const u8,
        signature_len: usize,
        cert: *const Cert,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::verify_detached(payload, payload_len, signature, signature_len, cert) }
    }

    /// # Safety
    ///
    /// `signature` holds `signature_len` bytes, and `cert` is NULL or
    /// points to a cert.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cms_signed_by(
        signature: *const u8,
        signature_len: usize,
        cert: *const Cert,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::cms_signed_by(signature, signature_len, cert) }
    }

    /// # Safety
    ///
    /// `key` holds `key_len` bytes, `data` `len`, and `out` room for 32.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn hmac_sha256(
        key: *const u8,
        key_len: usize,
        data: *const c_void,
        len: usize,
        out: *mut u8,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::hmac_sha256(key, key_len, data, len, out) }
    }

    /// # Safety
    ///
    /// `key` holds 16 bytes, `inp` `len`, and `out` room for `len`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn aes128_cfb_encrypt(
        key: *const u8,
        inp: *const u8,
        len: usize,
        out: *mut u8,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::aes128_cfb_encrypt(key, inp, len, out) }
    }

    /// # Safety
    ///
    /// `n`, `label` and `inp` hold their lengths, `out` room for `cap`, and
    /// `out_len` points to a size.
    #[unsafe(no_mangle)]
    #[allow(clippy::too_many_arguments)]
    pub unsafe extern "C" fn rsa_oaep_encrypt(
        n: *const u8,
        n_len: usize,
        e: u32,
        label: *const c_void,
        label_len: usize,
        inp: *const u8,
        in_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe {
            super::rsa_oaep_encrypt(
                n, n_len, e, label, label_len, inp, in_len, out, cap, out_len,
            )
        }
    }

    /// # Safety
    ///
    /// Each pointer holds or has room for 32 bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn ecdh_p256_ephemeral(
        x: *const [u8; 32],
        y: *const [u8; 32],
        eph_x: *mut [u8; 32],
        eph_y: *mut [u8; 32],
        z: *mut [u8; 32],
    ) -> c_int {
        // SAFETY: the caller's 32 bytes at each.
        unsafe { super::ecdh_p256_ephemeral(&*x, &*y, &mut *eph_x, &mut *eph_y, &mut *z) }
    }

    /// # Safety
    ///
    /// `inp` holds `in_len` bytes, `out` room for `cap`, and `out_len`
    /// points to a size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn base64_decode(
        inp: *const c_char,
        in_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::base64_decode(inp, in_len, out, cap, out_len) }
    }

    /// # Safety
    ///
    /// `der` holds `len` bytes, and `cert` points to a cert.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_read_der(der: *const u8, len: usize, cert: *mut Cert) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::cert_read_der(der, len, cert) }
    }

    /// # Safety
    ///
    /// `buf` holds `len` bytes, and `cert` points to a cert.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_read_memory(
        buf: *const u8,
        len: usize,
        cert: *mut Cert,
    ) -> c_int {
        // SAFETY: the caller passes the bytes and cert.
        unsafe { super::cert_read_memory(buf, len, cert) }
    }

    /// # Safety
    ///
    /// `cert` is NULL or points to a cert, and `out` to room for a
    /// cert_pubkey.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_pubkey(cert: *const Cert, out: *mut CertPubkey) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::cert_pubkey(cert, out) }
    }

    /// # Safety
    ///
    /// `cert` is NULL or points to a cert, `bundle_path` NULL or a C
    /// string, and `reason` points to where the reason goes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cert_verify_chain(
        cert: *const Cert,
        bundle_path: *const c_char,
        reason: *mut *const c_char,
    ) -> c_int {
        // SAFETY: the caller's pointers.
        unsafe { super::cert_verify_chain(cert, bundle_path, reason) }
    }

    /// # Safety
    ///
    /// `where_` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn openssl_complain(where_: *const c_char) {
        // SAFETY: the caller's C string.
        unsafe { super::openssl_complain(where_) }
    }
}
