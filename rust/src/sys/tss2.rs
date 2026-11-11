// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The part of tpm2-tss the TPM client uses: the ESYS calls, the TCTI
//! loader, the structures they take and give in the layout of
//! tss2_tpm2_types.h, and its values. A union shirudo reads one way is a
//! Rust union of the variants it reads, of the C union's size.

use core::ffi::{c_char, c_void};

/// An `ESYS_CONTEXT`.
pub enum EsysContext {}
/// A `TSS2_TCTI_CONTEXT`.
pub enum TctiContext {}

/// `ESYS_TR`: a handle of the ESYS layer.
pub type EsysTr = u32;
/// `TSS2_RC`.
pub type Rc = u32;

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

/// A `TPM2B` of a digest's room: `TPM2B_DIGEST`, `TPM2B_AUTH`,
/// `TPM2B_NONCE`, `TPM2B_DATA` and `TPM2B_TIMEOUT`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tpm2bDigest {
    pub size: u16,
    pub buffer: [u8; 64],
}

impl Tpm2bDigest {
    pub const fn zeroed() -> Self {
        Tpm2bDigest {
            size: 0,
            buffer: [0; 64],
        }
    }
}

/// `TPMS_PCR_SELECTION`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PcrSelection {
    pub hash: u16,
    pub sizeof_select: u8,
    pub pcr_select: [u8; 4],
    /// The C's padding as a field, so that every byte handed to the
    /// library has a value, as the C's `= {}` gave it.
    pub _pad: u8,
}

/// `TPML_PCR_SELECTION`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PcrSelectionList {
    pub count: u32,
    pub pcr_selections: [PcrSelection; 16],
}

impl PcrSelectionList {
    pub const fn zeroed() -> Self {
        PcrSelectionList {
            count: 0,
            pcr_selections: [PcrSelection {
                hash: 0,
                sizeof_select: 0,
                pcr_select: [0; 4],
                _pad: 0,
            }; 16],
        }
    }
}

/// `TPML_DIGEST`.
#[repr(C)]
pub struct DigestList {
    pub count: u32,
    pub digests: [Tpm2bDigest; 8],
}

/// `TPMT_HA`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ha {
    pub hash_alg: u16,
    pub digest: [u8; 64],
}

/// `TPML_DIGEST_VALUES`.
#[repr(C)]
pub struct DigestValues {
    pub count: u32,
    pub digests: [Ha; 16],
}

/// `TPMS_CLOCK_INFO`.
#[repr(C)]
pub struct ClockInfo {
    pub clock: u64,
    pub reset_count: u32,
    pub restart_count: u32,
    pub safe: u8,
}

/// `TPMS_TIME_INFO`.
#[repr(C)]
pub struct TimeInfo {
    pub time: u64,
    pub clock_info: ClockInfo,
}

/// `TPMS_NV_PUBLIC`.
#[repr(C)]
pub struct NvPublic {
    pub nv_index: u32,
    pub name_alg: u16,
    /// The C's padding as a field, so that every byte handed to the
    /// library has a value, as the C's `= {}` gave it.
    pub _pad: u16,
    pub attributes: u32,
    pub auth_policy: Tpm2bDigest,
    pub data_size: u16,
}

/// `TPM2B_NV_PUBLIC`.
#[repr(C)]
pub struct Tpm2bNvPublic {
    pub size: u16,
    /// The C's padding as a field, so that every byte handed to the
    /// library has a value, as the C's `= {}` gave it.
    pub _pad: u16,
    pub nv_public: NvPublic,
}

/// `TPM2B_NAME`.
#[repr(C)]
pub struct Tpm2bName {
    pub size: u16,
    pub name: [u8; 68],
}

/// `TPM2B_MAX_NV_BUFFER`.
#[repr(C)]
pub struct Tpm2bMaxNvBuffer {
    pub size: u16,
    pub buffer: [u8; 2048],
}

/// `TPM2B_SENSITIVE_CREATE`, always given empty here.
#[repr(C)]
pub struct Tpm2bSensitiveCreate {
    size: u16,
    rest: [u8; 324],
}

impl Tpm2bSensitiveCreate {
    pub const fn zeroed() -> Self {
        Tpm2bSensitiveCreate {
            size: 0,
            rest: [0; 324],
        }
    }
}

/// `TPMT_SYM_DEF` and `TPMT_SYM_DEF_OBJECT`: an algorithm, and its key
/// size and mode, unions of one u16.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SymDef {
    pub algorithm: u16,
    pub key_bits: u16,
    pub mode: u16,
}

/// `TPMT_RSA_SCHEME`, `TPMT_ECC_SCHEME` and `TPMT_SIG_SCHEME`: a scheme
/// and its details, whose first u16 is the hash of every scheme here.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Scheme {
    pub scheme: u16,
    pub details: [u16; 2],
}

/// `TPMT_KDF_SCHEME`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct KdfScheme {
    pub scheme: u16,
    pub details: u16,
}

/// `TPMS_RSA_PARMS`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RsaParms {
    pub symmetric: SymDef,
    pub scheme: Scheme,
    pub key_bits: u16,
    /// The C's padding as a field, so that every byte handed to the
    /// library has a value, as the C's `= {}` gave it.
    pub _pad: u16,
    pub exponent: u32,
}

/// `TPMS_ECC_PARMS`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EccParms {
    pub symmetric: SymDef,
    pub scheme: Scheme,
    pub curve_id: u16,
    pub kdf: KdfScheme,
}

/// `TPMU_PUBLIC_PARMS`, of the RSA and ECC keys shirudo makes.
#[repr(C)]
#[derive(Clone, Copy)]
pub union PublicParms {
    pub rsa: RsaParms,
    pub ecc: EccParms,
}

/// `TPM2B_PUBLIC_KEY_RSA`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tpm2bPublicKeyRsa {
    pub size: u16,
    pub buffer: [u8; 512],
}

/// `TPM2B_ECC_PARAMETER`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Tpm2bEccParameter {
    pub size: u16,
    pub buffer: [u8; 128],
}

/// `TPMS_ECC_POINT`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EccPoint {
    pub x: Tpm2bEccParameter,
    pub y: Tpm2bEccParameter,
}

/// `TPMU_PUBLIC_ID`, of the RSA and ECC keys shirudo makes.
#[repr(C)]
#[derive(Clone, Copy)]
pub union PublicId {
    pub rsa: Tpm2bPublicKeyRsa,
    pub ecc: EccPoint,
}

/// `TPMT_PUBLIC`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Public {
    pub ty: u16,
    pub name_alg: u16,
    pub object_attributes: u32,
    pub auth_policy: Tpm2bDigest,
    /// The C's padding as a field, so that every byte handed to the
    /// library has a value, as the C's `= {}` gave it.
    pub _pad0: u16,
    pub parameters: PublicParms,
    pub unique: PublicId,
    /// The C's trailing padding, likewise.
    pub _pad1: u16,
}

/// `TPM2B_PUBLIC`.
#[repr(C)]
pub struct Tpm2bPublic {
    pub size: u16,
    /// The C's padding as a field, so that every byte handed to the
    /// library has a value, as the C's `= {}` gave it.
    pub _pad: u16,
    pub public_area: Public,
}

impl Tpm2bPublic {
    /// One of all zero bits, as `= {}` is in C.
    pub fn zeroed() -> Self {
        // SAFETY: integers, arrays and unions of them, of which all zero
        // bits are a value.
        unsafe { core::mem::zeroed() }
    }
}

/// `TPMT_TK_HASHCHECK`.
#[repr(C)]
pub struct TkHashcheck {
    pub tag: u16,
    /// The C's padding as a field, so that every byte handed to the
    /// library has a value, as the C's `= {}` gave it.
    pub _pad0: u16,
    pub hierarchy: u32,
    pub digest: Tpm2bDigest,
    /// The C's trailing padding, likewise.
    pub _pad1: u16,
}

/// `TPMS_SIGNATURE_RSA`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignatureRsa {
    pub hash: u16,
    pub sig: Tpm2bPublicKeyRsa,
}

/// `TPMS_SIGNATURE_ECC`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SignatureEcc {
    pub hash: u16,
    pub signature_r: Tpm2bEccParameter,
    pub signature_s: Tpm2bEccParameter,
}

/// `TPMU_SIGNATURE`, of the RSASSA and ECDSA signatures shirudo takes.
#[repr(C)]
#[derive(Clone, Copy)]
pub union SignatureUnion {
    pub rsassa: SignatureRsa,
    pub ecdsa: SignatureEcc,
}

/// `TPMT_SIGNATURE`.
#[repr(C)]
pub struct Signature {
    pub sig_alg: u16,
    pub signature: SignatureUnion,
}

/// `TPM2B_ATTEST`.
#[repr(C)]
pub struct Tpm2bAttest {
    pub size: u16,
    pub attestation_data: [u8; 2304],
}

/// `TPM2B_ENCRYPTED_SECRET`.
#[repr(C)]
pub struct Tpm2bEncryptedSecret {
    pub size: u16,
    pub secret: [u8; 512],
}

/// `TPM2B_ID_OBJECT`.
#[repr(C)]
pub struct Tpm2bIdObject {
    pub size: u16,
    pub credential: [u8; 132],
}

const _: () = assert!(size_of::<Tpm2bDigest>() == 66);
const _: () = assert!(size_of::<PcrSelection>() == 8);
const _: () = assert!(core::mem::offset_of!(PcrSelection, _pad) == 7);
const _: () = assert!(size_of::<PcrSelectionList>() == 132);
const _: () = assert!(size_of::<DigestList>() == 532);
const _: () = assert!(size_of::<Ha>() == 66);
const _: () = assert!(size_of::<DigestValues>() == 1060);
const _: () = assert!(size_of::<TimeInfo>() == 32);
const _: () = assert!(core::mem::offset_of!(TimeInfo, clock_info) == 8);
const _: () = assert!(core::mem::offset_of!(ClockInfo, reset_count) == 8);
const _: () = assert!(core::mem::offset_of!(ClockInfo, restart_count) == 12);
const _: () = assert!(size_of::<NvPublic>() == 80);
const _: () = assert!(core::mem::offset_of!(NvPublic, attributes) == 8);
const _: () = assert!(core::mem::offset_of!(NvPublic, auth_policy) == 12);
const _: () = assert!(core::mem::offset_of!(NvPublic, data_size) == 78);
const _: () = assert!(size_of::<Tpm2bNvPublic>() == 84);
const _: () = assert!(core::mem::offset_of!(Tpm2bNvPublic, nv_public) == 4);
const _: () = assert!(size_of::<Tpm2bName>() == 70);
const _: () = assert!(size_of::<Tpm2bMaxNvBuffer>() == 2050);
const _: () = assert!(size_of::<Tpm2bSensitiveCreate>() == 326);
const _: () = assert!(size_of::<SymDef>() == 6);
const _: () = assert!(size_of::<Scheme>() == 6);
const _: () = assert!(size_of::<KdfScheme>() == 4);
const _: () = assert!(size_of::<RsaParms>() == 20);
const _: () = assert!(core::mem::offset_of!(RsaParms, key_bits) == 12);
const _: () = assert!(core::mem::offset_of!(RsaParms, exponent) == 16);
const _: () = assert!(size_of::<EccParms>() == 18);
const _: () = assert!(core::mem::offset_of!(EccParms, curve_id) == 12);
const _: () = assert!(core::mem::offset_of!(EccParms, kdf) == 14);
const _: () = assert!(size_of::<PublicParms>() == 20);
const _: () = assert!(size_of::<PublicId>() == 514);
const _: () = assert!(size_of::<Public>() == 612);
const _: () = assert!(core::mem::offset_of!(Public, auth_policy) == 8);
const _: () = assert!(core::mem::offset_of!(Public, parameters) == 76);
const _: () = assert!(core::mem::offset_of!(Public, unique) == 96);
const _: () = assert!(size_of::<Tpm2bPublic>() == 616);
const _: () = assert!(core::mem::offset_of!(Tpm2bPublic, public_area) == 4);
const _: () = assert!(size_of::<TkHashcheck>() == 76);
const _: () = assert!(core::mem::offset_of!(TkHashcheck, digest) == 8);
const _: () = assert!(size_of::<SignatureEcc>() == 262);
const _: () = assert!(core::mem::offset_of!(SignatureEcc, signature_s) == 132);
const _: () = assert!(size_of::<Signature>() == 518);
const _: () = assert!(core::mem::offset_of!(Signature, signature) == 2);
const _: () = assert!(size_of::<Tpm2bAttest>() == 2306);
const _: () = assert!(size_of::<Tpm2bEncryptedSecret>() == 514);
const _: () = assert!(size_of::<Tpm2bIdObject>() == 134);

unsafe extern "C" {
    pub fn Tss2_TctiLdr_Initialize(conf: *const c_char, tcti: *mut *mut TctiContext) -> Rc;
    pub fn Tss2_TctiLdr_Finalize(tcti: *mut *mut TctiContext);
    pub fn Esys_Initialize(
        esys: *mut *mut EsysContext,
        tcti: *mut TctiContext,
        abi: *mut c_void,
    ) -> Rc;
    pub fn Esys_Finalize(esys: *mut *mut EsysContext);
    pub fn Esys_Free(ptr: *mut c_void);
    pub fn Esys_StartAuthSession(
        esys: *mut EsysContext,
        tpm_key: EsysTr,
        bind: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        nonce_caller: *const Tpm2bDigest,
        session_type: u8,
        symmetric: *const SymDef,
        auth_hash: u16,
        session_handle: *mut EsysTr,
    ) -> Rc;
    pub fn Esys_TRSess_SetAttributes(
        esys: *mut EsysContext,
        session: EsysTr,
        flags: u8,
        mask: u8,
    ) -> Rc;
    pub fn Esys_TRSess_GetNonceTPM(
        esys: *mut EsysContext,
        session: EsysTr,
        nonce: *mut *mut Tpm2bDigest,
    ) -> Rc;
    pub fn Esys_FlushContext(esys: *mut EsysContext, handle: EsysTr) -> Rc;
    pub fn Esys_TR_Close(esys: *mut EsysContext, handle: *mut EsysTr) -> Rc;
    pub fn Esys_TR_SetAuth(esys: *mut EsysContext, handle: EsysTr, auth: *const Tpm2bDigest) -> Rc;
    pub fn Esys_TR_GetName(esys: *mut EsysContext, handle: EsysTr, name: *mut *mut Tpm2bName)
    -> Rc;
    pub fn Esys_TR_FromTPMPublic(
        esys: *mut EsysContext,
        tpm_handle: u32,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        object: *mut EsysTr,
    ) -> Rc;
    pub fn Esys_PCR_Read(
        esys: *mut EsysContext,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        selection_in: *const PcrSelectionList,
        update_counter: *mut u32,
        selection_out: *mut *mut PcrSelectionList,
        values: *mut *mut DigestList,
    ) -> Rc;
    pub fn Esys_PCR_Extend(
        esys: *mut EsysContext,
        pcr_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        digests: *const DigestValues,
    ) -> Rc;
    pub fn Esys_ReadClock(
        esys: *mut EsysContext,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        current_time: *mut *mut TimeInfo,
    ) -> Rc;
    pub fn Esys_NV_ReadPublic(
        esys: *mut EsysContext,
        nv_index: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        nv_public: *mut *mut Tpm2bNvPublic,
        nv_name: *mut *mut Tpm2bName,
    ) -> Rc;
    pub fn Esys_NV_DefineSpace(
        esys: *mut EsysContext,
        auth_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        auth: *const Tpm2bDigest,
        public_info: *const Tpm2bNvPublic,
        nv_handle: *mut EsysTr,
    ) -> Rc;
    pub fn Esys_NV_UndefineSpace(
        esys: *mut EsysContext,
        auth_handle: EsysTr,
        nv_index: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
    ) -> Rc;
    pub fn Esys_NV_Read(
        esys: *mut EsysContext,
        auth_handle: EsysTr,
        nv_index: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        size: u16,
        offset: u16,
        data: *mut *mut Tpm2bMaxNvBuffer,
    ) -> Rc;
    pub fn Esys_NV_Extend(
        esys: *mut EsysContext,
        auth_handle: EsysTr,
        nv_index: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        data: *const Tpm2bMaxNvBuffer,
    ) -> Rc;
    pub fn Esys_NV_Certify(
        esys: *mut EsysContext,
        sign_handle: EsysTr,
        auth_handle: EsysTr,
        nv_index: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        qualifying_data: *const Tpm2bDigest,
        in_scheme: *const Scheme,
        size: u16,
        offset: u16,
        certify_info: *mut *mut Tpm2bAttest,
        signature: *mut *mut Signature,
    ) -> Rc;
    pub fn Esys_CreatePrimary(
        esys: *mut EsysContext,
        primary_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        in_sensitive: *const Tpm2bSensitiveCreate,
        in_public: *const Tpm2bPublic,
        outside_info: *const Tpm2bDigest,
        creation_pcr: *const PcrSelectionList,
        object_handle: *mut EsysTr,
        out_public: *mut *mut Tpm2bPublic,
        creation_data: *mut *mut c_void,
        creation_hash: *mut *mut c_void,
        creation_ticket: *mut *mut c_void,
    ) -> Rc;
    pub fn Esys_Sign(
        esys: *mut EsysContext,
        key_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        digest: *const Tpm2bDigest,
        in_scheme: *const Scheme,
        validation: *const TkHashcheck,
        signature: *mut *mut Signature,
    ) -> Rc;
    pub fn Esys_PolicySigned(
        esys: *mut EsysContext,
        auth_object: EsysTr,
        policy_session: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        nonce_tpm: *const Tpm2bDigest,
        cp_hash_a: *const Tpm2bDigest,
        policy_ref: *const Tpm2bDigest,
        expiration: i32,
        auth: *const Signature,
        timeout: *mut *mut c_void,
        policy_ticket: *mut *mut c_void,
    ) -> Rc;
    pub fn Esys_PolicyCommandCode(
        esys: *mut EsysContext,
        policy_session: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        code: u32,
    ) -> Rc;
    pub fn Esys_PolicyGetDigest(
        esys: *mut EsysContext,
        policy_session: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        policy_digest: *mut *mut Tpm2bDigest,
    ) -> Rc;
    pub fn Esys_PolicyNvWritten(
        esys: *mut EsysContext,
        policy_session: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        written_set: u8,
    ) -> Rc;
    pub fn Esys_PolicyPCR(
        esys: *mut EsysContext,
        policy_session: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        pcr_digest: *const Tpm2bDigest,
        pcrs: *const PcrSelectionList,
    ) -> Rc;
    pub fn Esys_PolicyOR(
        esys: *mut EsysContext,
        policy_session: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        p_hash_list: *const DigestList,
    ) -> Rc;
    pub fn Esys_PolicySecret(
        esys: *mut EsysContext,
        auth_handle: EsysTr,
        policy_session: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        nonce_tpm: *const Tpm2bDigest,
        cp_hash_a: *const Tpm2bDigest,
        policy_ref: *const Tpm2bDigest,
        expiration: i32,
        timeout: *mut *mut c_void,
        policy_ticket: *mut *mut c_void,
    ) -> Rc;
    pub fn Esys_ActivateCredential(
        esys: *mut EsysContext,
        activate_handle: EsysTr,
        key_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        credential_blob: *const Tpm2bIdObject,
        secret: *const Tpm2bEncryptedSecret,
        cert_info: *mut *mut Tpm2bDigest,
    ) -> Rc;
    pub fn Esys_Quote(
        esys: *mut EsysContext,
        sign_handle: EsysTr,
        shandle1: EsysTr,
        shandle2: EsysTr,
        shandle3: EsysTr,
        qualifying_data: *const Tpm2bDigest,
        in_scheme: *const Scheme,
        pcr_select: *const PcrSelectionList,
        quoted: *mut *mut Tpm2bAttest,
        signature: *mut *mut Signature,
    ) -> Rc;
}
