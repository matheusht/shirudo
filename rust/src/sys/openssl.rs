// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The libcrypto calls of the Rust code: the crypto behind
//! `util/crypto.h`, and what util/ makes past it.

use core::ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_void};

use super::libc::Tm;

/// A `BIO`.
pub enum Bio {}

/// An `X509` certificate.
pub enum X509 {}
/// An `X509_EXTENSION`.
pub enum X509Extension {}
/// An `ASN1_INTEGER`.
pub enum Asn1Integer {}

/// `X509V3_CTX`, `struct v3_ext_ctx` of OpenSSL 3's x509v3.h, which
/// callers keep on their stacks.
#[repr(C)]
pub struct X509v3Ctx {
    pub flags: c_int,
    pub issuer_cert: *mut X509,
    pub subject_cert: *mut X509,
    pub subject_req: *mut c_void,
    pub crl: *mut c_void,
    pub db_meth: *mut c_void,
    pub db: *mut c_void,
    pub issuer_pkey: *mut EvpPkey,
}

const _: () = assert!(size_of::<X509v3Ctx>() == 64);
const _: () = assert!(core::mem::offset_of!(X509v3Ctx, db) == 48);

impl X509v3Ctx {
    pub const fn zeroed() -> Self {
        X509v3Ctx {
            flags: 0,
            issuer_cert: core::ptr::null_mut(),
            subject_cert: core::ptr::null_mut(),
            subject_req: core::ptr::null_mut(),
            crl: core::ptr::null_mut(),
            db_meth: core::ptr::null_mut(),
            db: core::ptr::null_mut(),
            issuer_pkey: core::ptr::null_mut(),
        }
    }
}

/// The `pem_password_cb` of a PEM read.
pub type PemPasswordCb =
    unsafe extern "C" fn(buf: *mut c_char, size: c_int, rwflag: c_int, u: *mut c_void) -> c_int;

/// The `BIO_ctrl()` command `BIO_reset()` sends.
pub const BIO_CTRL_RESET: c_int = 1;

/// The option of `OPENSSL_init_crypto()` that leaves openssl.cnf unread.
pub const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x80;

/// An `OPENSSL_INIT_SETTINGS`.
pub enum InitSettings {}
/// An `EVP_PKEY`.
pub enum EvpPkey {}
/// An `EVP_PKEY_CTX`.
pub enum EvpPkeyCtx {}
/// An `EVP_MD`.
pub enum EvpMd {}
/// An `EVP_MD_CTX`.
pub enum EvpMdCtx {}
/// An `EVP_MAC`.
pub enum EvpMac {}
/// An `EVP_MAC_CTX`.
pub enum EvpMacCtx {}
/// An `EVP_CIPHER`.
pub enum EvpCipher {}
/// An `EVP_CIPHER_CTX`.
pub enum EvpCipherCtx {}
/// An `EVP_ENCODE_CTX`.
pub enum EvpEncodeCtx {}
/// A `BIGNUM`.
pub enum Bignum {}
/// An `ECDSA_SIG`.
pub enum EcdsaSig {}
/// A `CMS_ContentInfo`.
pub enum CmsContentInfo {}
/// A `CMS_SignerInfo`.
pub enum CmsSignerInfo {}
/// An `OPENSSL_STACK`, of whatever it holds.
pub enum Stack {}
/// An `X509_STORE`.
pub enum X509Store {}
/// An `X509_STORE_CTX`.
pub enum X509StoreCtx {}
/// An `X509_PUBKEY`.
pub enum X509Pubkey {}
/// An `X509_NAME`.
pub enum X509Name {}
/// An `ASN1_TIME`.
pub enum Asn1Time {}
/// A `BIO_METHOD`.
pub enum BioMethod {}
/// An `OSSL_PARAM_BLD`.
pub enum ParamBld {}

/// `OSSL_PARAM`.
#[repr(C)]
pub struct OsslParam {
    key: *const c_char,
    data_type: c_uint,
    data: *mut c_void,
    data_size: usize,
    return_size: usize,
}

const _: () = assert!(size_of::<OsslParam>() == 40);

pub const BIO_CLOSE: c_int = 1;
pub const BIO_NOCLOSE: c_int = 0;
pub const MBSTRING_UTF8: c_int = 0x1000;
pub const NID_SUBJECT_KEY_IDENTIFIER: c_int = 82;
pub const NID_KEY_USAGE: c_int = 83;
pub const NID_BASIC_CONSTRAINTS: c_int = 87;
pub const NID_AUTHORITY_KEY_IDENTIFIER: c_int = 90;
pub const OPENSSL_VERSION: c_int = 0;
pub const BIO_CTRL_INFO: c_int = 3;
/// `EVP_PKEY_PUBLIC_KEY`: the parameters and the public key.
pub const EVP_PKEY_PUBLIC_KEY: c_int = 0x86;
pub const EVP_PKEY_RSA: c_int = 6;
pub const EVP_PKEY_EC: c_int = 408;
pub const RSA_PKCS1_OAEP_PADDING: c_int = 4;
pub const CMS_DETACHED: c_uint = 0x40;
pub const CMS_BINARY: c_uint = 0x80;
pub const CMS_NOINTERN: c_uint = 0x10;
pub const X509_V_FLAG_PARTIAL_CHAIN: c_ulong = 0x8_0000;
pub const X509_V_FLAG_NO_CHECK_TIME: c_ulong = 0x20_0000;
pub const XN_FLAG_ONELINE: c_ulong = 0x82_031f;
pub const XN_FLAG_SPC_EQ: c_ulong = 0x80_0000;

unsafe extern "C" {
    pub fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> *mut Bio;
    pub fn BIO_ctrl(bio: *mut Bio, cmd: c_int, larg: c_long, parg: *mut c_void) -> c_long;
    pub fn BIO_free(bio: *mut Bio) -> c_int;
    pub fn d2i_X509_bio(bio: *mut Bio, x509: *mut *mut X509) -> *mut X509;
    pub fn PEM_read_bio_X509(
        bio: *mut Bio,
        x509: *mut *mut X509,
        cb: Option<PemPasswordCb>,
        u: *mut c_void,
    ) -> *mut X509;
    pub fn X509_free(x509: *mut X509);
    pub fn X509_digest(x: *const X509, md: *const EvpMd, out: *mut u8, len: *mut c_uint) -> c_int;
    pub fn X509_get_issuer_name(x: *const X509) -> *mut X509Name;
    pub fn X509_NAME_oneline(name: *const X509Name, buf: *mut c_char, size: c_int) -> *mut c_char;
    pub fn X509_NAME_cmp(a: *const X509Name, b: *const X509Name) -> c_int;
    pub fn i2d_PUBKEY(key: *const EvpPkey, out: *mut *mut u8) -> c_int;
    pub fn EVP_PKEY_get_bits(key: *const EvpPkey) -> c_int;
    pub fn PEM_read_bio_PrivateKey(
        bio: *mut Bio,
        key: *mut *mut EvpPkey,
        cb: Option<PemPasswordCb>,
        u: *mut c_void,
    ) -> *mut EvpPkey;
    pub fn OPENSSL_init_crypto(opts: u64, settings: *const InitSettings) -> c_int;
    pub fn BIO_new_fd(fd: c_int, close_flag: c_int) -> *mut Bio;
    pub fn BIO_new(method: *const BioMethod) -> *mut Bio;
    pub fn BIO_s_mem() -> *const BioMethod;
    pub fn BIO_s_null() -> *const BioMethod;
    pub fn ERR_clear_error();
    pub fn ERR_get_error() -> c_ulong;
    pub fn ERR_error_string_n(e: c_ulong, buf: *mut c_char, len: usize);
    pub fn CRYPTO_malloc(num: usize, file: *const c_char, line: c_int) -> *mut c_void;
    pub fn CRYPTO_free(ptr: *mut c_void, file: *const c_char, line: c_int);
    pub fn EVP_MD_CTX_new() -> *mut EvpMdCtx;
    pub fn EVP_MD_CTX_free(ctx: *mut EvpMdCtx);
    pub fn EVP_DigestInit_ex(ctx: *mut EvpMdCtx, ty: *const EvpMd, imp: *mut c_void) -> c_int;
    pub fn EVP_DigestUpdate(ctx: *mut EvpMdCtx, d: *const c_void, cnt: usize) -> c_int;
    pub fn EVP_DigestFinal_ex(ctx: *mut EvpMdCtx, md: *mut u8, s: *mut c_uint) -> c_int;
    pub fn EVP_Digest(
        data: *const c_void,
        count: usize,
        md: *mut u8,
        size: *mut c_uint,
        ty: *const EvpMd,
        imp: *mut c_void,
    ) -> c_int;
    pub fn EVP_sha256() -> *const EvpMd;
    pub fn EVP_EncodeBlock(t: *mut u8, f: *const u8, n: c_int) -> c_int;
    pub fn EVP_ENCODE_CTX_new() -> *mut EvpEncodeCtx;
    pub fn EVP_ENCODE_CTX_free(ctx: *mut EvpEncodeCtx);
    pub fn EVP_DecodeInit(ctx: *mut EvpEncodeCtx);
    pub fn EVP_DecodeUpdate(
        ctx: *mut EvpEncodeCtx,
        out: *mut u8,
        outl: *mut c_int,
        inp: *const u8,
        inl: c_int,
    ) -> c_int;
    pub fn EVP_DecodeFinal(ctx: *mut EvpEncodeCtx, out: *mut u8, outl: *mut c_int) -> c_int;
    pub fn OSSL_PARAM_construct_utf8_string(
        key: *const c_char,
        buf: *mut c_char,
        bsize: usize,
    ) -> OsslParam;
    pub fn OSSL_PARAM_construct_octet_string(
        key: *const c_char,
        buf: *mut c_void,
        bsize: usize,
    ) -> OsslParam;
    pub fn OSSL_PARAM_construct_end() -> OsslParam;
    pub fn OSSL_PARAM_BLD_new() -> *mut ParamBld;
    pub fn OSSL_PARAM_BLD_push_BN(
        bld: *mut ParamBld,
        key: *const c_char,
        bn: *const Bignum,
    ) -> c_int;
    pub fn OSSL_PARAM_BLD_to_param(bld: *mut ParamBld) -> *mut OsslParam;
    pub fn OSSL_PARAM_BLD_free(bld: *mut ParamBld);
    pub fn OSSL_PARAM_free(p: *mut OsslParam);
    pub fn EVP_PKEY_CTX_new_from_name(
        libctx: *mut c_void,
        name: *const c_char,
        propq: *const c_char,
    ) -> *mut EvpPkeyCtx;
    pub fn EVP_PKEY_CTX_new_from_pkey(
        libctx: *mut c_void,
        pkey: *mut EvpPkey,
        propq: *const c_char,
    ) -> *mut EvpPkeyCtx;
    pub fn EVP_PKEY_CTX_free(ctx: *mut EvpPkeyCtx);
    pub fn EVP_PKEY_fromdata_init(ctx: *mut EvpPkeyCtx) -> c_int;
    pub fn EVP_PKEY_fromdata(
        ctx: *mut EvpPkeyCtx,
        ppkey: *mut *mut EvpPkey,
        selection: c_int,
        params: *mut OsslParam,
    ) -> c_int;
    pub fn EVP_PKEY_free(key: *mut EvpPkey);
    pub fn EVP_PKEY_verify_init(ctx: *mut EvpPkeyCtx) -> c_int;
    pub fn EVP_PKEY_CTX_set_signature_md(ctx: *mut EvpPkeyCtx, md: *const EvpMd) -> c_int;
    pub fn EVP_PKEY_verify(
        ctx: *mut EvpPkeyCtx,
        sig: *const u8,
        siglen: usize,
        tbs: *const u8,
        tbslen: usize,
    ) -> c_int;
    pub fn EVP_PKEY_encrypt_init(ctx: *mut EvpPkeyCtx) -> c_int;
    pub fn EVP_PKEY_CTX_set_rsa_padding(ctx: *mut EvpPkeyCtx, pad_mode: c_int) -> c_int;
    pub fn EVP_PKEY_CTX_set_rsa_oaep_md(ctx: *mut EvpPkeyCtx, md: *const EvpMd) -> c_int;
    pub fn EVP_PKEY_CTX_set_rsa_mgf1_md(ctx: *mut EvpPkeyCtx, md: *const EvpMd) -> c_int;
    pub fn EVP_PKEY_CTX_set0_rsa_oaep_label(
        ctx: *mut EvpPkeyCtx,
        label: *mut c_void,
        llen: c_int,
    ) -> c_int;
    pub fn EVP_PKEY_encrypt(
        ctx: *mut EvpPkeyCtx,
        out: *mut u8,
        outlen: *mut usize,
        inp: *const u8,
        inlen: usize,
    ) -> c_int;
    pub fn EVP_PKEY_Q_keygen(
        libctx: *mut c_void,
        propq: *const c_char,
        ty: *const c_char,
        ...
    ) -> *mut EvpPkey;
    pub fn EVP_PKEY_get_bn_param(
        pkey: *const EvpPkey,
        key_name: *const c_char,
        bn: *mut *mut Bignum,
    ) -> c_int;
    pub fn EVP_PKEY_get_utf8_string_param(
        pkey: *const EvpPkey,
        key_name: *const c_char,
        out: *mut c_char,
        max: usize,
        out_sz: *mut usize,
    ) -> c_int;
    pub fn EVP_PKEY_get_base_id(pkey: *const EvpPkey) -> c_int;
    pub fn EVP_PKEY_get0_type_name(key: *const EvpPkey) -> *const c_char;
    pub fn EVP_PKEY_derive_init(ctx: *mut EvpPkeyCtx) -> c_int;
    pub fn EVP_PKEY_derive_set_peer(ctx: *mut EvpPkeyCtx, peer: *mut EvpPkey) -> c_int;
    pub fn EVP_PKEY_derive(ctx: *mut EvpPkeyCtx, key: *mut u8, keylen: *mut usize) -> c_int;
    pub fn BN_bin2bn(s: *const u8, len: c_int, ret: *mut Bignum) -> *mut Bignum;
    pub fn BN_new() -> *mut Bignum;
    pub fn BN_free(a: *mut Bignum);
    pub fn BN_set_word(a: *mut Bignum, w: c_ulong) -> c_int;
    pub fn BN_get_word(a: *const Bignum) -> c_ulong;
    pub fn BN_num_bits(a: *const Bignum) -> c_int;
    pub fn BN_bn2bin(a: *const Bignum, to: *mut u8) -> c_int;
    pub fn BN_bn2binpad(a: *const Bignum, to: *mut u8, tolen: c_int) -> c_int;
    pub fn ECDSA_SIG_new() -> *mut EcdsaSig;
    pub fn ECDSA_SIG_free(sig: *mut EcdsaSig);
    pub fn ECDSA_SIG_set0(sig: *mut EcdsaSig, r: *mut Bignum, s: *mut Bignum) -> c_int;
    pub fn i2d_ECDSA_SIG(sig: *const EcdsaSig, pp: *mut *mut u8) -> c_int;
    pub fn EVP_MAC_fetch(
        libctx: *mut c_void,
        algorithm: *const c_char,
        properties: *const c_char,
    ) -> *mut EvpMac;
    pub fn EVP_MAC_free(mac: *mut EvpMac);
    pub fn EVP_MAC_CTX_new(mac: *mut EvpMac) -> *mut EvpMacCtx;
    pub fn EVP_MAC_CTX_free(ctx: *mut EvpMacCtx);
    pub fn EVP_MAC_init(
        ctx: *mut EvpMacCtx,
        key: *const u8,
        keylen: usize,
        params: *const OsslParam,
    ) -> c_int;
    pub fn EVP_MAC_update(ctx: *mut EvpMacCtx, data: *const u8, datalen: usize) -> c_int;
    pub fn EVP_MAC_final(
        ctx: *mut EvpMacCtx,
        out: *mut u8,
        outl: *mut usize,
        outsize: usize,
    ) -> c_int;
    pub fn EVP_CIPHER_CTX_new() -> *mut EvpCipherCtx;
    pub fn EVP_CIPHER_CTX_free(ctx: *mut EvpCipherCtx);
    pub fn EVP_CIPHER_CTX_set_padding(ctx: *mut EvpCipherCtx, pad: c_int) -> c_int;
    pub fn EVP_aes_128_cfb128() -> *const EvpCipher;
    pub fn EVP_EncryptInit_ex(
        ctx: *mut EvpCipherCtx,
        ty: *const EvpCipher,
        imp: *mut c_void,
        key: *const u8,
        iv: *const u8,
    ) -> c_int;
    pub fn EVP_EncryptUpdate(
        ctx: *mut EvpCipherCtx,
        out: *mut u8,
        outl: *mut c_int,
        inp: *const u8,
        inl: c_int,
    ) -> c_int;
    pub fn EVP_EncryptFinal_ex(ctx: *mut EvpCipherCtx, out: *mut u8, outl: *mut c_int) -> c_int;
    pub fn d2i_X509(a: *mut *mut X509, inp: *mut *const u8, len: c_long) -> *mut X509;
    pub fn X509_get_X509_PUBKEY(x: *const X509) -> *mut X509Pubkey;
    pub fn i2d_X509_PUBKEY(a: *const X509Pubkey, out: *mut *mut u8) -> c_int;
    pub fn X509_get0_pubkey(x: *const X509) -> *mut EvpPkey;
    pub fn X509_get_subject_name(x: *const X509) -> *mut X509Name;
    pub fn X509_NAME_print_ex(
        out: *mut Bio,
        nm: *const X509Name,
        indent: c_int,
        flags: c_ulong,
    ) -> c_int;
    pub fn X509_get0_notBefore(x: *const X509) -> *const Asn1Time;
    pub fn ASN1_TIME_to_tm(s: *const Asn1Time, tm: *mut Tm) -> c_int;
    pub fn d2i_CMS_ContentInfo(
        a: *mut *mut CmsContentInfo,
        inp: *mut *const u8,
        len: c_long,
    ) -> *mut CmsContentInfo;
    pub fn CMS_ContentInfo_free(cms: *mut CmsContentInfo);
    pub fn CMS_verify(
        cms: *mut CmsContentInfo,
        certs: *mut Stack,
        store: *mut X509Store,
        dcont: *mut Bio,
        out: *mut Bio,
        flags: c_uint,
    ) -> c_int;
    pub fn CMS_get0_SignerInfos(cms: *mut CmsContentInfo) -> *mut Stack;
    pub fn CMS_SignerInfo_cert_cmp(si: *mut CmsSignerInfo, cert: *mut X509) -> c_int;
    pub fn OPENSSL_sk_new_null() -> *mut Stack;
    pub fn OPENSSL_sk_push(st: *mut Stack, data: *const c_void) -> c_int;
    pub fn OPENSSL_sk_free(st: *mut Stack);
    pub fn OPENSSL_sk_num(st: *const Stack) -> c_int;
    pub fn OPENSSL_sk_value(st: *const Stack, i: c_int) -> *mut c_void;
    pub fn X509_STORE_new() -> *mut X509Store;
    pub fn X509_STORE_free(xs: *mut X509Store);
    pub fn X509_STORE_add_cert(xs: *mut X509Store, x: *mut X509) -> c_int;
    pub fn X509_STORE_set_flags(xs: *mut X509Store, flags: c_ulong) -> c_int;
    pub fn X509_STORE_load_file(xs: *mut X509Store, file: *const c_char) -> c_int;
    pub fn X509_STORE_CTX_new() -> *mut X509StoreCtx;
    pub fn X509_STORE_CTX_free(ctx: *mut X509StoreCtx);
    pub fn X509_STORE_CTX_init(
        ctx: *mut X509StoreCtx,
        store: *mut X509Store,
        target: *mut X509,
        untrusted: *mut Stack,
    ) -> c_int;
    pub fn X509_STORE_CTX_get_error(ctx: *const X509StoreCtx) -> c_int;
    pub fn X509_verify_cert(ctx: *mut X509StoreCtx) -> c_int;
    pub fn X509_verify_cert_error_string(n: c_long) -> *const c_char;
    pub fn OPENSSL_version_major() -> c_uint;
    pub fn OPENSSL_version_minor() -> c_uint;
    pub fn OpenSSL_version(ty: c_int) -> *const c_char;
    pub fn X509_new() -> *mut X509;
    pub fn X509_set_version(x: *mut X509, version: c_long) -> c_int;
    pub fn X509_get_serialNumber(x: *mut X509) -> *mut Asn1Integer;
    pub fn ASN1_INTEGER_set(a: *mut Asn1Integer, v: c_long) -> c_int;
    pub fn X509_getm_notBefore(x: *const X509) -> *mut Asn1Time;
    pub fn X509_getm_notAfter(x: *const X509) -> *mut Asn1Time;
    pub fn X509_gmtime_adj(s: *mut Asn1Time, adj: c_long) -> *mut Asn1Time;
    pub fn ASN1_TIME_set_string_X509(s: *mut Asn1Time, text: *const c_char) -> c_int;
    pub fn X509_set_pubkey(x: *mut X509, pkey: *mut EvpPkey) -> c_int;
    pub fn X509_NAME_new() -> *mut X509Name;
    pub fn X509_NAME_free(name: *mut X509Name);
    pub fn X509_NAME_add_entry_by_txt(
        name: *mut X509Name,
        field: *const c_char,
        ty: c_int,
        bytes: *const u8,
        len: c_int,
        loc: c_int,
        set: c_int,
    ) -> c_int;
    pub fn X509_set_subject_name(x: *mut X509, name: *const X509Name) -> c_int;
    pub fn X509_set_issuer_name(x: *mut X509, name: *const X509Name) -> c_int;
    pub fn X509V3_set_ctx(
        ctx: *mut X509v3Ctx,
        issuer: *mut X509,
        subject: *mut X509,
        req: *mut c_void,
        crl: *mut c_void,
        flags: c_int,
    );
    pub fn X509V3_EXT_conf_nid(
        conf: *mut c_void,
        ctx: *mut X509v3Ctx,
        nid: c_int,
        value: *const c_char,
    ) -> *mut X509Extension;
    pub fn X509_add_ext(x: *mut X509, ex: *mut X509Extension, loc: c_int) -> c_int;
    pub fn X509_EXTENSION_free(ex: *mut X509Extension);
    pub fn X509_sign(x: *mut X509, pkey: *mut EvpPkey, md: *const EvpMd) -> c_int;
    pub fn PEM_write_bio_PrivateKey(
        bio: *mut Bio,
        pkey: *const EvpPkey,
        enc: *const EvpCipher,
        kstr: *const u8,
        klen: c_int,
        cb: Option<PemPasswordCb>,
        u: *mut c_void,
    ) -> c_int;
    pub fn i2d_X509_bio(bio: *mut Bio, x: *const X509) -> c_int;
}
