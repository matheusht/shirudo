// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The part of tpm2-tss the TPM client uses, through the Parsec
//! project's tss-esapi-sys: the ESYS calls, the TCTI loader and the
//! structures they take and give, under the names the client takes them
//! by, with the values it uses and constructors of the structures whose
//! parts are unions.

use tss_esapi_sys as t;

pub use t::{
    Esys_ActivateCredential, Esys_CreatePrimary, Esys_Finalize, Esys_FlushContext, Esys_Free,
    Esys_Initialize, Esys_NV_Certify, Esys_NV_DefineSpace, Esys_NV_Extend, Esys_NV_Read,
    Esys_NV_ReadPublic, Esys_NV_UndefineSpace, Esys_PCR_Extend, Esys_PCR_Read,
    Esys_PolicyCommandCode, Esys_PolicyGetDigest, Esys_PolicyNvWritten, Esys_PolicyOR,
    Esys_PolicyPCR, Esys_PolicySecret, Esys_PolicySigned, Esys_Quote, Esys_ReadClock, Esys_Sign,
    Esys_StartAuthSession, Esys_TR_Close, Esys_TR_FromTPMPublic, Esys_TR_GetName, Esys_TR_SetAuth,
    Esys_TRSess_GetNonceTPM, Esys_TRSess_SetAttributes, Tss2_TctiLdr_Finalize,
    Tss2_TctiLdr_Initialize,
};

pub type EsysContext = t::ESYS_CONTEXT;
pub type TctiContext = t::TSS2_TCTI_CONTEXT;
/// `ESYS_TR`: a handle of the ESYS layer.
pub type EsysTr = t::ESYS_TR;
/// `TSS2_RC`.
pub type Rc = t::TSS2_RC;

pub const ESYS_TR_NONE: EsysTr = 0xfff;
pub const ESYS_TR_PASSWORD: EsysTr = 0x0ff;
pub const ESYS_TR_PCR0: EsysTr = 0;
pub const ESYS_TR_RH_OWNER: EsysTr = 0x101;
pub const ESYS_TR_RH_ENDORSEMENT: EsysTr = 0x10b;

pub const RC_SUCCESS: Rc = 0;
pub const RC_FMT1: Rc = 0x080;
pub const RC_VALUE: Rc = 0x084;
pub const RC_HANDLE: Rc = 0x08b;
pub const RC_AUTH_FAIL: Rc = 0x08e;
pub const RC_POLICY_FAIL: Rc = 0x09d;
pub const RC_BAD_AUTH: Rc = 0x0a2;
pub const RC_NV_AUTHORIZATION: Rc = 0x149;
pub const RC_NV_UNINITIALIZED: Rc = 0x14a;

pub const ALG_RSA: u16 = 0x0001;
pub const ALG_AES: u16 = 0x0006;
pub const ALG_SHA256: u16 = 0x000b;
pub const ALG_NULL: u16 = 0x0010;
pub const ALG_RSASSA: u16 = 0x0014;
pub const ALG_ECDSA: u16 = 0x0018;
pub const ALG_ECC: u16 = 0x0023;
pub const ALG_CFB: u16 = 0x0043;
pub const ECC_NIST_P256: u16 = 0x0003;

/// `TPM2_SE`.
pub const SE_HMAC: u8 = 0;
pub const SE_POLICY: u8 = 1;
/// `TPMA_SESSION`.
pub const SESSION_CONTINUESESSION: u8 = 0x01;
pub const SESSION_AUDIT: u8 = 0x80;

pub const NV_WRITTEN: u32 = 0x2000_0000;
pub const ST_HASHCHECK: u16 = 0x8024;
pub const RH_NULL: u32 = 0x4000_0007;
pub const CC_NV_EXTEND: u32 = 0x0000_0136;
pub const NO: u8 = 0;
pub const YES: u8 = 1;

pub const OBJECT_FIXEDTPM: u32 = 0x0000_0002;
pub const OBJECT_FIXEDPARENT: u32 = 0x0000_0010;
pub const OBJECT_SENSITIVEDATAORIGIN: u32 = 0x0000_0020;
pub const OBJECT_USERWITHAUTH: u32 = 0x0000_0040;
pub const OBJECT_RESTRICTED: u32 = 0x0001_0000;
pub const OBJECT_SIGN_ENCRYPT: u32 = 0x0004_0000;

pub type Tpm2bDigest = t::TPM2B_DIGEST;
pub type Tpm2bData = t::TPM2B_DATA;
pub type SignatureRsa = t::TPMS_SIGNATURE_RSA;
pub type PcrSelectionList = t::TPML_PCR_SELECTION;
pub type DigestList = t::TPML_DIGEST;
pub type DigestValues = t::TPML_DIGEST_VALUES;
pub type TimeInfo = t::TPMS_TIME_INFO;
pub type Tpm2bNvPublic = t::TPM2B_NV_PUBLIC;
pub type Tpm2bName = t::TPM2B_NAME;
pub type Tpm2bMaxNvBuffer = t::TPM2B_MAX_NV_BUFFER;
pub type Tpm2bSensitiveCreate = t::TPM2B_SENSITIVE_CREATE;
pub type SymDef = t::TPMT_SYM_DEF_OBJECT;
pub type SymDefSession = t::TPMT_SYM_DEF;
pub type RsaScheme = t::TPMT_RSA_SCHEME;
pub type EccScheme = t::TPMT_ECC_SCHEME;
pub type SigScheme = t::TPMT_SIG_SCHEME;
pub type KdfScheme = t::TPMT_KDF_SCHEME;
pub type RsaParms = t::TPMS_RSA_PARMS;
pub type EccParms = t::TPMS_ECC_PARMS;
pub type Tpm2bPublicKeyRsa = t::TPM2B_PUBLIC_KEY_RSA;
pub type Tpm2bEccParameter = t::TPM2B_ECC_PARAMETER;
pub type EccPoint = t::TPMS_ECC_POINT;
pub type Public = t::TPMT_PUBLIC;
pub type Tpm2bPublic = t::TPM2B_PUBLIC;
pub type TkHashcheck = t::TPMT_TK_HASHCHECK;
pub type TkAuth = t::TPMT_TK_AUTH;
pub type Signature = t::TPMT_SIGNATURE;
pub type Tpm2bAttest = t::TPM2B_ATTEST;
pub type Tpm2bEncryptedSecret = t::TPM2B_ENCRYPTED_SECRET;
pub type Tpm2bIdObject = t::TPM2B_ID_OBJECT;

/// A structure of the bindings, all of whose bits zeroed are a value: its
/// empty one, as the C's `= {}` makes it, padding included.
pub trait Zeroed: Sized {
    fn zeroed() -> Self {
        // SAFETY: implemented only for the bindings' plain structures of
        // integers, arrays and unions of them.
        unsafe { core::mem::zeroed() }
    }
}

impl Zeroed for Tpm2bDigest {}
impl Zeroed for Tpm2bData {}
impl Zeroed for PcrSelectionList {}
impl Zeroed for Tpm2bSensitiveCreate {}
impl Zeroed for Tpm2bPublic {}
impl Zeroed for TkHashcheck {}
impl Zeroed for Tpm2bNvPublic {}
impl Zeroed for Tpm2bName {}
impl Zeroed for Tpm2bMaxNvBuffer {}
impl Zeroed for Tpm2bPublicKeyRsa {}
impl Zeroed for Tpm2bEccParameter {}
impl Zeroed for DigestList {}
impl Zeroed for DigestValues {}
impl Zeroed for Signature {}
impl Zeroed for Tpm2bIdObject {}
impl Zeroed for Tpm2bEncryptedSecret {}

/// A symmetric definition: `algorithm` with `key_bits` in `mode`, or
/// none with ALG_NULL.
pub fn sym_def(algorithm: u16, key_bits: u16, mode: u16) -> SymDef {
    // SAFETY: plain data, which zeroed bits make the empty definition.
    let mut s: SymDef = unsafe { core::mem::zeroed() };
    s.algorithm = algorithm;
    s.keyBits.sym = key_bits;
    s.mode.sym = mode;
    s
}

/// The symmetric definition of a session: none.
pub fn sym_def_null() -> SymDefSession {
    // SAFETY: plain data, which zeroed bits make the empty definition.
    let mut s: SymDefSession = unsafe { core::mem::zeroed() };
    s.algorithm = ALG_NULL;
    s
}

/// The RSA scheme `scheme` of `hash`, or none with ALG_NULL and 0.
pub fn rsa_scheme(scheme: u16, hash: u16) -> RsaScheme {
    // SAFETY: plain data, which zeroed bits make the empty scheme.
    let mut s: RsaScheme = unsafe { core::mem::zeroed() };
    s.scheme = scheme;
    s.details.anySig = t::TPMS_SCHEME_HASH { hashAlg: hash };
    s
}

/// The ECC scheme `scheme` of `hash`, or none with ALG_NULL and 0.
pub fn ecc_scheme(scheme: u16, hash: u16) -> EccScheme {
    // SAFETY: plain data, which zeroed bits make the empty scheme.
    let mut s: EccScheme = unsafe { core::mem::zeroed() };
    s.scheme = scheme;
    s.details.anySig = t::TPMS_SCHEME_HASH { hashAlg: hash };
    s
}

/// The signing scheme `scheme` of `hash`, or the key's own with ALG_NULL
/// and 0.
pub fn sig_scheme(scheme: u16, hash: u16) -> SigScheme {
    // SAFETY: plain data, which zeroed bits make the empty scheme.
    let mut s: SigScheme = unsafe { core::mem::zeroed() };
    s.scheme = scheme;
    s.details.any = t::TPMS_SCHEME_HASH { hashAlg: hash };
    s
}

/// No key derivation.
pub fn kdf_null() -> KdfScheme {
    // SAFETY: plain data, which zeroed bits make the empty scheme.
    let mut s: KdfScheme = unsafe { core::mem::zeroed() };
    s.scheme = ALG_NULL;
    s
}
