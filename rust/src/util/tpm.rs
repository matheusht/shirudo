// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The libtss2 client: the
//! measurement register and its NV writer key, PCRs, the endorsement and
//! attestation keys, quotes, certifications and credentials. Every
//! command goes through a salted HMAC session bound to the endorsement
//! key init froze.

use core::ffi::{CStr, c_char, c_int, c_uint};
use core::mem::MaybeUninit;
use core::ptr;

use crate::errno::{
    E2BIG, EACCES, EINVAL, EIO, EKEYREJECTED, ENODATA, ENODEV, ENOENT, ENOMEM, EPROTO,
    EPROTONOSUPPORT, text,
};
use crate::heap::{xcalloc, xfree};
use crate::sys::identity::Identity;
use crate::sys::libc::{errno, explicit_bzero, getenv, setenv, unsetenv};
use crate::sys::tss2::*;
use crate::text::strscpy;
use crate::util::config::{self, Scrubbed};
use crate::util::identity;
use crate::util::image_config;
use crate::util::tpm_wire::{
    EK_POLICY, TpmPublic, nv_extend_cphash, object_name, public_marshal, register_policy_final,
    writer_auth_hash, writer_public,
};

const EK_CERT_NV_RSA: u32 = 0x01C0_0002;
const EK_CERT_NV_ECC: u32 = 0x01C0_000A;
const NV_READ_CHUNK: usize = 512;

/// The sizes of digests, names and the TPM's other records.
const DIGEST_LEN: usize = 32;
const NAME_LEN: usize = 34;
const NV_RSA_BYTES: usize = 384;
const NV_RSA_PUBLIC_AREA_LEN: usize = 408;
pub(crate) const PUBLIC_MAX: usize = 512;
pub(crate) const ATTEST_MAX: usize = 1024;
pub(crate) const SIGNATURE_MAX: usize = 160;
const PCR_SELECT_LEN: u8 = 3;
/// The longest TCTI a config names.
const TCTI_MAX: usize = 256;

/// The measurement register's NV attributes, the NV writer's object
/// attributes and the TCG endorsement key's.
pub(crate) const REGISTER_ATTRS: u32 = 0x0e06_0048;
const WRITER_ATTRS: u32 = 0x0004_0072;
pub(crate) const EK_ATTRS: u32 = 0x0003_00b2;
/// TPM_NV_POLICY_REF, without the NUL sizeof() counts.
const NV_POLICY_REF: &[u8] = b"shirudo-nv-writer-v1";
/// CONF_PATH of util/paths.h, which a message names.
const CONF_PATH: &CStr = c"/etc/shirudo/shirudo.conf";

/// `struct tpm_key`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmKey {
    pub(crate) handle: u32,
    pub(crate) public: [u8; PUBLIC_MAX],
    pub(crate) public_len: usize,
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) name_len: usize,
}

impl TpmKey {
    pub(crate) const fn zeroed() -> Self {
        TpmKey {
            handle: 0,
            public: [0; PUBLIC_MAX],
            public_len: 0,
            name: [0; NAME_LEN],
            name_len: 0,
        }
    }
}

/// A TPM client, laid out for the tests that look inside.
#[repr(C)]
pub struct Tpm {
    pub(crate) session_key: TpmKey,
    pub(crate) tcti: *mut TctiContext,
    pub(crate) esys: *mut EsysContext,
    pub(crate) session: EsysTr,
    writer_seed: [u8; DIGEST_LEN],
    writer_public: [u8; NV_RSA_BYTES],
    writer_set: bool,
}

/// `struct tpm_nv_info`.
#[repr(C)]
pub struct TpmNvInfo {
    pub(crate) defined: bool,
    pub(crate) written: bool,
    attrs: u32,
    data_size: u16,
    pub(crate) policy: [u8; DIGEST_LEN],
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) name_len: usize,
}

/// `struct tpm_attestation`.
#[repr(C)]
pub struct TpmAttestation {
    pub(crate) attest: [u8; ATTEST_MAX],
    pub(crate) attest_len: usize,
    pub(crate) signature: [u8; SIGNATURE_MAX],
    pub(crate) signature_len: usize,
}

impl TpmAttestation {
    pub(crate) const fn zeroed() -> Self {
        TpmAttestation {
            attest: [0; ATTEST_MAX],
            attest_len: 0,
            signature: [0; SIGNATURE_MAX],
            signature_len: 0,
        }
    }
}

/// `struct tpm_writer_authorization`: what the NV writer signs to
/// authorize one NV_Extend.
#[repr(C)]
pub struct WriterAuthorization {
    nonce: Tpm2bDigest,
    cphash: Tpm2bDigest,
    pub(crate) digest: [u8; DIGEST_LEN],
}

const _: () = assert!(size_of::<TpmKey>() == 576);
const _: () = assert!(size_of::<Tpm>() == 1016);
const _: () = assert!(core::mem::offset_of!(Tpm, esys) == 584);
const _: () = assert!(core::mem::offset_of!(Tpm, session) == 592);
const _: () = assert!(core::mem::offset_of!(Tpm, writer_set) == 1012);
const _: () = assert!(size_of::<TpmNvInfo>() == 88);
const _: () = assert!(core::mem::offset_of!(TpmNvInfo, name_len) == 80);
const _: () = assert!(size_of::<TpmAttestation>() == 1200);
const _: () = assert!(size_of::<WriterAuthorization>() == 164);

/// A structure of tss2's of all zero bits, as `= {}` is in C.
fn zeroed<T>() -> T {
    // SAFETY: only for the structures of integers, arrays and unions of
    // them below, of which all zero bits are a value.
    unsafe { core::mem::zeroed() }
}

/// Starts a salted session bound to the session key: an audit HMAC
/// session for commands without an authorization handle, or a policy
/// session.
pub(crate) fn session_start(t: &Tpm, key: EsysTr, ty: u8, session: &mut EsysTr) -> c_int {
    let sym = sym_def_null();
    let mut attrs = SESSION_CONTINUESESSION;

    if ty == SE_HMAC {
        attrs |= SESSION_AUDIT;
    }
    // SAFETY: the context, handles, a template and room for the session.
    let mut ret = unsafe {
        Esys_StartAuthSession(
            t.esys,
            key,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ptr::null(),
            ty,
            &sym,
            ALG_SHA256,
            session,
        )
    };
    if ret == RC_SUCCESS {
        // SAFETY: the context and the session it started.
        ret = unsafe { Esys_TRSess_SetAttributes(t.esys, *session, attrs, 0xff) };
    }
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: start salted session: rc=0x{ret:08x}").as_bytes());
        if *session != ESYS_TR_NONE {
            // SAFETY: the context and its session.
            unsafe { Esys_FlushContext(t.esys, *session) };
            *session = ESYS_TR_NONE;
        }
        return -EIO;
    }
    0
}

/// The session key: the ECC endorsement key, which once enforcement is
/// active must be the one init froze in the identity.
fn session_setup(t: &mut Tpm, active: bool) -> c_int {
    let mut id = Identity::zeroed();

    if active {
        let ret = identity::read(&mut id);

        if ret != 0 {
            crate::log::err(format!("tpm: frozen identity unreadable: {}", text(ret)).as_bytes());
            return ret;
        }
        if id.ek_name[0] != 0 || u16::from(id.ek_name[1]) != ALG_SHA256 {
            crate::log::err(b"tpm: no frozen session key; trusted reboot required");
            return -EACCES;
        }
    }
    let mut key = TpmKey::zeroed();
    let ret = ek_create(t, false, &mut key);

    t.session_key = key;
    if ret != 0 {
        return ret;
    }
    if t.session_key.name_len != NAME_LEN || (active && t.session_key.name != id.ek_name) {
        crate::log::err(b"tpm: not the TPM init bound (session key name differs)");
        return -EACCES;
    }
    let mut session = t.session;
    let ret = session_start(t, t.session_key.handle, SE_HMAC, &mut session);

    t.session = session;
    ret
}

/// The TCTI into the `size` bytes at `buf`: SHIRUDO_TPM_TCTI or the
/// configuration's before an authenticated image is active, so tests can
/// pick a software TPM, and a device TCTI once one is. 0, -EACCES, or
/// -E2BIG.
///
/// # Safety
///
/// `buf` is room for `size` bytes.
unsafe fn tcti(buf: *mut u8, size: usize) -> c_int {
    let mut cfg = Scrubbed(MaybeUninit::zeroed());
    let mut tcti: *const c_char = if image_config::active() {
        ptr::null()
    } else {
        // SAFETY: a C string.
        unsafe { getenv(c"SHIRUDO_TPM_TCTI".as_ptr()) }
    };
    // SAFETY: tcti NULL or a C string the environment holds.
    let empty = |t: *const c_char| t.is_null() || unsafe { *t } == 0;

    if empty(tcti) {
        // SAFETY: room for a configuration, zeroed as the C's was.
        if unsafe { config::load(cfg.ptr()) } == 0 {
            // SAFETY: the configuration, filled.
            let c = unsafe { cfg.0.assume_init_ref() };

            if c.tpm_tcti[0] != 0 {
                tcti = c.tpm_tcti.as_ptr().cast();
            }
        }
    }
    if empty(tcti) {
        tcti = c"device:/dev/tpmrm0".as_ptr();
    }
    // SAFETY: a C string either way.
    let value = unsafe { CStr::from_ptr(tcti) }.to_bytes();

    if image_config::active() && !value.starts_with(b"device:") {
        return -EACCES;
    }
    // SAFETY: the caller's room.
    let out = unsafe { crate::ffi::bytes_mut(buf, size) };

    match strscpy(out, value) {
        Ok(_) => 0,
        Err(e) => e,
    }
}

/// Opens the TPM, its library logging off since that can expose session
/// keys even during bootstrap: 0 with `*out` set, or -errno.
///
/// # Safety
///
/// `out` is room for a pointer.
unsafe fn open_tpm(out: *mut *mut Tpm, quiet: bool) -> c_int {
    let mut tcti_buf = [0u8; TCTI_MAX];
    let active = identity::enforcement_active();

    if active < 0 {
        crate::log::err(
            format!("tpm: cannot determine enforcement state: {}", text(active)).as_bytes(),
        );
        return active;
    }
    // SAFETY: C strings.
    let set = unsafe {
        setenv(c"TSS2_LOG".as_ptr(), c"all+none".as_ptr(), 1) == 0
            && unsetenv(c"TSS2_LOGFILE".as_ptr()) == 0
    };
    if !set {
        let e = -errno();

        crate::log::err(format!("tpm: cannot disable library logging: {}", text(e)).as_bytes());
        return e;
    }
    // SAFETY: the room above.
    let e = unsafe { tcti(tcti_buf.as_mut_ptr(), tcti_buf.len()) };

    if e != 0 {
        if !quiet && e == -EACCES {
            crate::log::err(b"tpm: authenticated runtime requires a device TCTI");
        } else if !quiet {
            crate::log::err(
                format!(
                    "tpm: the TCTI is longer than {} bytes",
                    (TCTI_MAX - 1) as c_int
                )
                .as_bytes(),
            );
        }
        return e;
    }
    // SAFETY: a count and a size.
    let t = unsafe { xcalloc(1, size_of::<Tpm>()) }.cast::<Tpm>();

    if t.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the zeroed connection allocated above, all of whose bits
    // zeroed are one.
    let tr = unsafe { &mut *t };

    tr.session = ESYS_TR_NONE;
    tr.session_key.handle = ESYS_TR_NONE;
    // SAFETY: the TCTI, a C string, and room for its context.
    let ret = unsafe { Tss2_TctiLdr_Initialize(tcti_buf.as_ptr().cast(), &mut tr.tcti) };

    if ret != RC_SUCCESS {
        if !quiet {
            crate::log::err(
                &[
                    &b"tpm: TctiLdr_Initialize("[..],
                    crate::text::cstr(&tcti_buf),
                    b"): rc=0x",
                    format!("{ret:08x}").as_bytes(),
                ]
                .concat(),
            );
        }
        // SAFETY: the allocation above, freed once.
        unsafe { xfree(t.cast(), size_of::<Tpm>()) };
        return -EIO;
    }
    // SAFETY: room for the context, and the TCTI's.
    let ret = unsafe { Esys_Initialize(&mut tr.esys, tr.tcti, ptr::null_mut()) };

    if ret != RC_SUCCESS {
        if !quiet {
            crate::log::err(format!("tpm: Esys_Initialize: rc=0x{ret:08x}").as_bytes());
        }
        // SAFETY: the TCTI and the allocation, each released once.
        unsafe {
            Tss2_TctiLdr_Finalize(&mut tr.tcti);
            xfree(t.cast(), size_of::<Tpm>());
        }
        return -EIO;
    }
    let e = session_setup(tr, active != 0);

    if e != 0 {
        // SAFETY: the connection, closed once.
        unsafe { close(t) };
        return e;
    }
    // SAFETY: the caller's room.
    unsafe { *out = t };
    0
}

/// Closes what open_tpm() opened; NULL is nothing to close.
///
/// # Safety
///
/// `t` is NULL or a connection open_tpm() gave.
unsafe fn close(t: *mut Tpm) {
    // SAFETY: the caller's connection, if any.
    let Some(tr) = (unsafe { t.as_mut() }) else {
        return;
    };
    if !tr.esys.is_null() {
        if tr.session != ESYS_TR_NONE {
            // SAFETY: the context and its session.
            unsafe { Esys_FlushContext(tr.esys, tr.session) };
        }
        let esys = tr.esys;

        // SAFETY: the connection's context, not yet finalized.
        unsafe { key_flush(esys, &mut tr.session_key) };
        // SAFETY: the context, finalized once.
        unsafe { Esys_Finalize(&mut tr.esys) };
    }
    if !tr.tcti.is_null() {
        // SAFETY: the TCTI, finalized once.
        unsafe { Tss2_TctiLdr_Finalize(&mut tr.tcti) };
    }
    // SAFETY: the allocation open_tpm() made, freed once.
    unsafe { xfree(t.cast(), size_of::<Tpm>()) };
}

/// Whether `ret` is the TPM's `code`, of either format.
fn rc_is(ret: Rc, code: Rc) -> bool {
    if ret & 0xFFFF_0000 != 0 {
        return false; // not a TPM-layer code
    }
    if ret & RC_FMT1 != 0 {
        return (ret & 0x0BF) == (code & 0x0BF);
    }
    (ret & 0xFFF) == code
}

fn rc_is_auth_failure(ret: Rc) -> bool {
    rc_is(ret, RC_BAD_AUTH)
        || rc_is(ret, RC_AUTH_FAIL)
        || rc_is(ret, RC_NV_AUTHORIZATION)
        || rc_is(ret, RC_POLICY_FAIL)
}

/// The SHA-256 bank's PCRs of `mask`.
fn pcr_selection(mask: u32) -> PcrSelectionList {
    let mut sel = PcrSelectionList::zeroed();

    sel.count = 1;
    sel.pcrSelections[0].hash = ALG_SHA256;
    sel.pcrSelections[0].sizeofSelect = PCR_SELECT_LEN;
    sel.pcrSelections[0].pcrSelect[0] = mask as u8;
    sel.pcrSelections[0].pcrSelect[1] = (mask >> 8) as u8;
    sel.pcrSelections[0].pcrSelect[2] = (mask >> 16) as u8;
    sel
}

fn pcr_read(t: &Tpm, pcr: u32, out: &mut [u8; DIGEST_LEN]) -> c_int {
    let mut values: *mut DigestList = ptr::null_mut();
    let mut counter = 0u32;

    if pcr >= 24 {
        return -EINVAL;
    }
    let sel = pcr_selection(1 << pcr);
    // SAFETY: the context, handles, the selection and room for the
    // results.
    let ret = unsafe {
        Esys_PCR_Read(
            t.esys,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &sel,
            &mut counter,
            ptr::null_mut(),
            &mut values,
        )
    };
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: PCR_Read({pcr}): rc=0x{ret:08x}").as_bytes());
        return -EIO;
    }
    // SAFETY: the values ESYS gave on success.
    let v = unsafe { &*values };

    if v.count != 1 || v.digests[0].size != 32 {
        crate::log::err(format!("tpm: PCR {pcr} has no SHA-256 bank").as_bytes());
        // SAFETY: the values, freed once.
        unsafe { Esys_Free(values.cast()) };
        return -ENOENT;
    }
    out.copy_from_slice(&v.digests[0].buffer[..32]);
    // SAFETY: the values, freed once.
    unsafe { Esys_Free(values.cast()) };
    0
}

fn pcr_extend(t: &Tpm, pcr: u32, digest: &[u8; DIGEST_LEN]) -> c_int {
    let mut dv: DigestValues = zeroed();

    dv.count = 1;
    if pcr >= 24 {
        return -EINVAL;
    }
    dv.digests[0].hashAlg = ALG_SHA256;
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&digest[..32]);
    dv.digests[0].digest.sha256 = sha256;
    // SAFETY: the context, handles and the digests.
    let ret = unsafe {
        Esys_PCR_Extend(
            t.esys,
            ESYS_TR_PCR0 + pcr,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &dv,
        )
    };

    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: PCR_Extend({pcr}): rc=0x{ret:08x}").as_bytes());
        return -EIO;
    }
    0
}

/// The TPM's clock: its reset and restart counts.
fn read_clock(t: &Tpm) -> Result<(u32, u32), c_int> {
    let mut info: *mut TimeInfo = ptr::null_mut();
    // SAFETY: the context, handles and room for the time.
    let ret = unsafe { Esys_ReadClock(t.esys, t.session, ESYS_TR_NONE, ESYS_TR_NONE, &mut info) };

    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: ReadClock: rc=0x{ret:08x}").as_bytes());
        return Err(-EIO);
    }
    // SAFETY: the time ESYS gave on success, freed once.
    unsafe {
        let counts = ((*info).clockInfo.resetCount, (*info).clockInfo.restartCount);

        Esys_Free(info.cast());
        Ok(counts)
    }
}

/// The ESYS handle of the NV index: 0, -ENOENT, quiet, for one not
/// defined, or -EIO.
fn nv_handle(t: &Tpm, index: u32, out: &mut EsysTr) -> c_int {
    // SAFETY: the context, an index, handles and room for the handle.
    let ret =
        unsafe { Esys_TR_FromTPMPublic(t.esys, index, t.session, ESYS_TR_NONE, ESYS_TR_NONE, out) };

    if rc_is(ret, RC_HANDLE) {
        return -ENOENT; // quiet: undefined is normal
    }
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: TR_FromTPMPublic(0x{index:08x}): rc=0x{ret:08x}").as_bytes());
        return -EIO;
    }
    0
}

/// Closes an ESYS handle of an NV index.
fn tr_close(t: &Tpm, nv: &mut EsysTr) {
    // SAFETY: the context and its handle.
    unsafe { Esys_TR_Close(t.esys, nv) };
}

fn nv_info(t: &Tpm, index: u32, info: &mut TpmNvInfo) -> c_int {
    let mut public: *mut Tpm2bNvPublic = ptr::null_mut();
    let mut name: *mut Tpm2bName = ptr::null_mut();
    let mut nv = 0;

    // SAFETY: the caller's info, all of whose bits zeroed are one.
    unsafe { ptr::from_mut(info).write_bytes(0, 1) };
    let e = nv_handle(t, index, &mut nv);

    if e == -ENOENT {
        return 0;
    }
    if e != 0 {
        return e;
    }
    // SAFETY: the context, the index's handle, handles and room for its
    // public area and name.
    let ret = unsafe {
        Esys_NV_ReadPublic(
            t.esys,
            nv,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut public,
            &mut name,
        )
    };

    tr_close(t, &mut nv);
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: NV_ReadPublic(0x{index:08x}): rc=0x{ret:08x}").as_bytes());
        return -EIO;
    }
    // SAFETY: what ESYS gave on success, each freed once.
    unsafe {
        let p = &(*public).nvPublic;
        let n = &*name;

        info.defined = true;
        info.written = p.attributes & NV_WRITTEN != 0;
        info.attrs = p.attributes;
        info.data_size = p.dataSize;
        if p.authPolicy.size == 32 {
            info.policy.copy_from_slice(&p.authPolicy.buffer[..32]);
        }
        if usize::from(n.size) <= info.name.len() {
            let len = usize::from(n.size);

            info.name[..len].copy_from_slice(&n.name[..len]);
            info.name_len = len;
        }
        Esys_Free(public.cast());
        Esys_Free(name.cast());
    }
    0
}

/// The owner hierarchy's password for the next command.
fn owner_auth_set(t: &Tpm, auth: &[u8]) -> c_int {
    let mut owner = Tpm2bDigest::zeroed();

    let (Some(room), Ok(size)) = (
        owner.buffer.get_mut(..auth.len()),
        u16::try_from(auth.len()),
    ) else {
        return -EINVAL;
    };
    room.copy_from_slice(auth);
    owner.size = size;
    // SAFETY: the context, a handle and the password; then the copy
    // scrubbed.
    let ret = unsafe {
        let ret = Esys_TR_SetAuth(t.esys, ESYS_TR_RH_OWNER, &owner);

        explicit_bzero(owner.buffer.as_mut_ptr().cast(), owner.buffer.len());
        ret
    };
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: TR_SetAuth(owner): rc=0x{ret:08x}").as_bytes());
        return -EIO;
    }
    0
}

fn owner_auth_clear(t: &Tpm) {
    let empty = Tpm2bDigest::zeroed();

    // SAFETY: the context, a handle and an empty password.
    unsafe { Esys_TR_SetAuth(t.esys, ESYS_TR_RH_OWNER, &empty) };
}

fn owner_auth_error(op: &CStr, index: u32, ret: Rc) -> c_int {
    if rc_is_auth_failure(ret) {
        crate::log::err(
            &[
                &b"tpm: "[..],
                op.to_bytes(),
                b"(0x",
                format!("{index:08x}").as_bytes(),
                b"): owner-hierarchy authorization failed (rc=0x",
                format!("{ret:08x}").as_bytes(),
                b"). This TPM has owner auth set; supply it via tpm.owner_auth in ",
                CONF_PATH.to_bytes(),
                b" (or SHIRUDO_TPM_OWNER_AUTH), or clear the TPM owner auth.",
            ]
            .concat(),
        );
        return -EACCES;
    }
    crate::log::err(
        &[
            &b"tpm: "[..],
            op.to_bytes(),
            b"(0x",
            format!("{index:08x}").as_bytes(),
            b"): rc=0x",
            format!("{ret:08x}").as_bytes(),
        ]
        .concat(),
    );
    -EIO
}

pub(crate) fn nv_define(
    t: &Tpm,
    index: u32,
    policy: &[u8; DIGEST_LEN],
    owner_auth: &[u8],
) -> c_int {
    let mut public: Tpm2bNvPublic = zeroed();
    let nv_auth = Tpm2bDigest::zeroed();
    let mut nv = ESYS_TR_NONE;
    let e = owner_auth_set(t, owner_auth);

    if e != 0 {
        return e;
    }
    public.nvPublic.nvIndex = index;
    public.nvPublic.nameAlg = ALG_SHA256;
    public.nvPublic.attributes = REGISTER_ATTRS;
    public.nvPublic.authPolicy.size = 32;
    public.nvPublic.authPolicy.buffer[..32].copy_from_slice(policy);
    public.nvPublic.dataSize = DIGEST_LEN as u16;
    // SAFETY: the context, handles, the index's password and public
    // area, and room for its handle.
    let ret = unsafe {
        Esys_NV_DefineSpace(
            t.esys,
            ESYS_TR_RH_OWNER,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &nv_auth,
            &public,
            &mut nv,
        )
    };
    owner_auth_clear(t);
    if ret != RC_SUCCESS {
        return owner_auth_error(c"NV_DefineSpace", index, ret);
    }
    tr_close(t, &mut nv);
    0
}

pub(crate) fn nv_undefine(t: &Tpm, index: u32, owner_auth: &[u8]) -> c_int {
    let mut nv = 0;
    let e = nv_handle(t, index, &mut nv);

    if e != 0 {
        return e;
    }
    let e = owner_auth_set(t, owner_auth);

    if e != 0 {
        tr_close(t, &mut nv);
        return e;
    }
    // SAFETY: the context and handles.
    let ret = unsafe {
        Esys_NV_UndefineSpace(
            t.esys,
            ESYS_TR_RH_OWNER,
            nv,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
        )
    };

    owner_auth_clear(t);
    if ret != RC_SUCCESS {
        tr_close(t, &mut nv);
        return owner_auth_error(c"NV_UndefineSpace", index, ret);
    }
    0
}

pub(crate) fn nv_read(t: &Tpm, index: u32, out: &mut [u8; DIGEST_LEN]) -> c_int {
    let mut data: *mut Tpm2bMaxNvBuffer = ptr::null_mut();
    let mut nv = 0;
    let e = nv_handle(t, index, &mut nv);

    if e != 0 {
        return e;
    }
    // SAFETY: the context, handles and room for the data.
    let ret = unsafe {
        Esys_NV_Read(
            t.esys,
            nv,
            nv,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            DIGEST_LEN as u16,
            0,
            &mut data,
        )
    };
    tr_close(t, &mut nv);
    if rc_is(ret, RC_NV_UNINITIALIZED) {
        return -ENODATA; // quiet: nothing written this boot
    }
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: NV_Read(0x{index:08x}): rc=0x{ret:08x}").as_bytes());
        return -EIO;
    }
    // SAFETY: the data ESYS gave on success.
    let d = unsafe { &*data };

    if usize::from(d.size) != DIGEST_LEN {
        crate::log::err(
            format!(
                "tpm: NV_Read returned {} bytes, expected {}",
                c_uint::from(d.size),
                DIGEST_LEN as c_uint
            )
            .as_bytes(),
        );
        // SAFETY: the data, freed once.
        unsafe { Esys_Free(data.cast()) };
        return -EIO;
    }
    out.copy_from_slice(&d.buffer[..DIGEST_LEN]);
    // SAFETY: the data, freed once.
    unsafe { Esys_Free(data.cast()) };
    0
}

fn session_flush(t: &Tpm, session: EsysTr) {
    if session != ESYS_TR_NONE {
        // SAFETY: the context and its session.
        unsafe { Esys_FlushContext(t.esys, session) };
    }
}

/// The command hash of the NV_Extend of `event` to the index named
/// `name`, the TPM's nonce of the session, and their digest, which the
/// NV writer signs.
pub(crate) fn writer_prepare(
    t: &Tpm,
    session: EsysTr,
    name: &[u8; NAME_LEN],
    event: &[u8; DIGEST_LEN],
    authorization: &mut WriterAuthorization,
) -> c_int {
    let mut nonce: *mut Tpm2bDigest = ptr::null_mut();
    let mut cphash = [0u8; DIGEST_LEN];

    authorization.cphash.size = DIGEST_LEN as u16;
    // The C hashed into the caller's buffer in place: start from what
    // the caller left there.
    cphash.copy_from_slice(&authorization.cphash.buffer[..DIGEST_LEN]);
    let e = nv_extend_cphash(name, event, &mut cphash);

    authorization.cphash.buffer[..DIGEST_LEN].copy_from_slice(&cphash);
    if e != 0 {
        crate::log::err(format!("tpm: compute NV_Extend command hash: {}", text(e)).as_bytes());
        return e;
    }
    // SAFETY: the context, the session and room for its nonce.
    let ret = unsafe { Esys_TRSess_GetNonceTPM(t.esys, session, &mut nonce) };

    if ret != RC_SUCCESS || nonce.is_null() {
        crate::log::err(format!("tpm: NV writer PolicySigned: rc=0x{ret:08x}").as_bytes());
        // SAFETY: what ESYS gave, or NULL, freed once.
        unsafe { Esys_Free(nonce.cast()) };
        return -EACCES;
    }
    // SAFETY: the nonce ESYS gave on success, copied and freed once.
    unsafe {
        authorization.nonce = *nonce;
        Esys_Free(nonce.cast());
    }
    let n = &authorization.nonce;
    let e = match n.buffer.get(..usize::from(n.size)) {
        Some(nonce) => writer_auth_hash(nonce, &cphash, &mut authorization.digest),
        None => -EINVAL,
    };
    if e != 0 {
        crate::log::err(format!("tpm: compute NV writer authorization: {}", text(e)).as_bytes());
    }
    e
}

/// The NV writer: an RSA primary under the owner hierarchy whose unique
/// field the salt `seed` fills. The salt varies the key each boot, the
/// owner seed reproduces it after a reset, and the frozen modulus
/// `expected` refuses one made under another owner seed. 0 with the key
/// loaded in `*key`, or -errno with it flushed.
pub(crate) fn writer_primary(
    t: &Tpm,
    seed: &[u8; DIGEST_LEN],
    expected: Option<&[u8; NV_RSA_BYTES]>,
    public: &mut [u8; NV_RSA_BYTES],
    key: &mut EsysTr,
) -> c_int {
    let mut public_area = [0u8; NV_RSA_PUBLIC_AREA_LEN];
    let mut computed = [0u8; NAME_LEN];
    let creation_pcr = PcrSelectionList::zeroed();
    let sensitive = Tpm2bSensitiveCreate::zeroed();
    let mut out_pub: *mut Tpm2bPublic = ptr::null_mut();
    let mut cfg = Scrubbed(MaybeUninit::zeroed());
    let mut in_pub = Tpm2bPublic::zeroed();
    let mut name: *mut Tpm2bName = ptr::null_mut();
    let outside = Tpm2bData::zeroed();

    *key = ESYS_TR_NONE;
    let p = &mut in_pub.publicArea;

    p.type_ = ALG_RSA;
    p.nameAlg = ALG_SHA256;
    p.objectAttributes = WRITER_ATTRS;
    p.parameters.rsaDetail = RsaParms {
        symmetric: sym_def(ALG_NULL, 0, 0),
        scheme: rsa_scheme(ALG_RSASSA, ALG_SHA256),
        keyBits: 3072,
        exponent: 65537,
    };
    let mut rsa = Tpm2bPublicKeyRsa {
        size: DIGEST_LEN as u16,
        buffer: [0; 512],
    };
    rsa.buffer[..DIGEST_LEN].copy_from_slice(seed);
    p.unique.rsa = rsa;

    // SAFETY: room for a configuration, zeroed as the C's was.
    let mut e = unsafe { config::load(cfg.ptr()) };
    if e == 0 {
        // SAFETY: the configuration, filled.
        let c = unsafe { cfg.0.assume_init_ref() };

        e = match c.tpm_owner_auth.get(..c.tpm_owner_auth_len) {
            Some(auth) => owner_auth_set(t, auth),
            None => -EINVAL,
        };
    }
    // SAFETY: the configuration's bytes, scrubbed now as the C did.
    unsafe { explicit_bzero(cfg.ptr().cast(), size_of::<config::Config>()) };
    if e != 0 {
        return e;
    }
    // SAFETY: the context, handles, the templates, and room for the
    // handle and public area.
    let ret = unsafe {
        Esys_CreatePrimary(
            t.esys,
            ESYS_TR_RH_OWNER,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &sensitive,
            &in_pub,
            &outside,
            &creation_pcr,
            key,
            &mut out_pub,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    owner_auth_clear(t);
    let e = 'cleanup: {
        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: CreatePrimary(NV writer): rc=0x{ret:08x}").as_bytes());
            break 'cleanup if rc_is_auth_failure(ret) {
                -EACCES
            } else {
                -EIO
            };
        }
        let e = 'out: {
            if out_pub.is_null() {
                break 'out -EPROTO;
            }
            // SAFETY: the public area ESYS gave.
            let p = unsafe { &(*out_pub).publicArea };
            // SAFETY: the RSA variants, integers of which any bits are
            // values, as the C read them whatever the type.
            let (r, n) = unsafe { (&p.parameters.rsaDetail, &p.unique.rsa) };
            let bad = p.type_ != ALG_RSA
                || p.nameAlg != ALG_SHA256
                || p.objectAttributes != WRITER_ATTRS
                || p.authPolicy.size != 0
                || r.symmetric.algorithm != ALG_NULL
                || r.scheme.scheme != ALG_RSASSA
                // SAFETY: every scheme of a key holds its hash first.
                || unsafe { r.scheme.details.anySig.hashAlg } != ALG_SHA256
                || r.keyBits != 3072
                || r.exponent != 65537
                || usize::from(n.size) != NV_RSA_BYTES;

            if bad {
                break 'out -EPROTO;
            }
            public.copy_from_slice(&n.buffer[..NV_RSA_BYTES]);
            if expected.is_some_and(|x| *x != *public) {
                break 'out -EKEYREJECTED;
            }
            writer_public(public, &mut public_area);
            let e = object_name(&public_area, &mut computed);

            if e != 0 {
                break 'out e;
            }
            // SAFETY: the context, the key and room for its name.
            let ret = unsafe { Esys_TR_GetName(t.esys, *key, &mut name) };
            // SAFETY: the name ESYS gave, if any.
            let given = unsafe { name.as_ref() };
            let differs = ret != RC_SUCCESS
                || given.is_none_or(|n| {
                    usize::from(n.size) != NAME_LEN || n.name[..NAME_LEN] != computed
                });

            if differs { -EPROTO } else { 0 }
        };
        if e != 0 {
            crate::log::err(b"tpm: NV writer public key differs from the expected key");
        }
        e
    };
    // SAFETY: what ESYS gave, or NULL, each freed once.
    unsafe {
        Esys_Free(name.cast());
        Esys_Free(out_pub.cast());
    }
    if e != 0 {
        session_flush(t, *key);
        *key = ESYS_TR_NONE;
    }
    e
}

/// The NV writer's RSASSA signature over `hash`.
fn writer_sign(
    t: &Tpm,
    key: EsysTr,
    hash: &[u8; DIGEST_LEN],
    out: &mut [u8; NV_RSA_BYTES],
) -> c_int {
    let mut validation: TkHashcheck = zeroed();
    let scheme = sig_scheme(ALG_RSASSA, ALG_SHA256);
    let mut signature: *mut Signature = ptr::null_mut();
    let mut digest = Tpm2bDigest::zeroed();

    validation.tag = ST_HASHCHECK;
    validation.hierarchy = RH_NULL;
    digest.size = DIGEST_LEN as u16;
    digest.buffer[..DIGEST_LEN].copy_from_slice(hash);
    // SAFETY: the context, handles, the digest, scheme and ticket, and
    // room for the signature.
    let ret = unsafe {
        Esys_Sign(
            t.esys,
            key,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &digest,
            &scheme,
            &validation,
            &mut signature,
        )
    };
    let e = if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: Sign(NV writer): rc=0x{ret:08x}").as_bytes());
        -EACCES
    } else {
        // SAFETY: the signature ESYS gave, if any; its RSASSA variant read
        // only once its algorithm says so.
        unsafe {
            match signature.as_ref() {
                Some(s)
                    if s.sigAlg == ALG_RSASSA
                        && s.signature.rsassa.hash == ALG_SHA256
                        && usize::from(s.signature.rsassa.sig.size) == NV_RSA_BYTES =>
                {
                    out.copy_from_slice(&s.signature.rsassa.sig.buffer[..NV_RSA_BYTES]);
                    0
                }
                _ => -EPROTO,
            }
        }
    };
    // SAFETY: what ESYS gave, or NULL, freed once.
    unsafe { Esys_Free(signature.cast()) };
    e
}

/// TPM2_PolicySigned with the NV writer's signature over the
/// authorization: the TPM's code.
pub(crate) fn writer_authorize(
    t: &Tpm,
    key: EsysTr,
    session: EsysTr,
    authorization: &WriterAuthorization,
    signature: &[u8; NV_RSA_BYTES],
) -> Rc {
    let mut policy_ref = Tpm2bDigest::zeroed();
    let mut sig: Signature = zeroed();
    let mut timeout: *mut Tpm2bDigest = ptr::null_mut();
    let mut ticket: *mut TkAuth = ptr::null_mut();
    let mut rsassa = SignatureRsa {
        hash: ALG_SHA256,
        sig: Tpm2bPublicKeyRsa {
            size: NV_RSA_BYTES as u16,
            buffer: [0; 512],
        },
    };

    policy_ref.size = NV_POLICY_REF.len() as u16;
    sig.sigAlg = ALG_RSASSA;
    rsassa.sig.buffer[..NV_RSA_BYTES].copy_from_slice(signature);
    sig.signature.rsassa = rsassa;
    policy_ref.buffer[..NV_POLICY_REF.len()].copy_from_slice(NV_POLICY_REF);
    // SAFETY: the context, handles, the authorization's nonce and command
    // hash, the reference and signature, and room for the outputs, which
    // are freed once.
    unsafe {
        let ret = Esys_PolicySigned(
            t.esys,
            key,
            session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &authorization.nonce,
            &authorization.cphash,
            &policy_ref,
            0,
            &sig,
            &mut timeout,
            &mut ticket,
        );
        Esys_Free(timeout.cast());
        Esys_Free(ticket.cast());
        ret
    }
}

/// The policy session's PolicySigned by the NV writer over the exact
/// NV_Extend of `event` to `index`.
fn policy_writer_signed(t: &Tpm, session: EsysTr, index: u32, event: &[u8; DIGEST_LEN]) -> c_int {
    let mut authorization: WriterAuthorization = zeroed();
    let mut signature = [0u8; NV_RSA_BYTES];
    let mut public = [0u8; NV_RSA_BYTES];
    let mut key = ESYS_TR_NONE;
    let mut nv: TpmNvInfo = zeroed();

    if !t.writer_set {
        return -EKEYREJECTED;
    }
    let e = nv_info(t, index, &mut nv);

    if e != 0 {
        return e;
    }
    if !nv.defined || nv.name_len != NAME_LEN {
        crate::log::err(b"tpm: NV writer requires a defined register");
        return -ENODEV;
    }
    let e = writer_prepare(t, session, &nv.name, event, &mut authorization);

    if e != 0 {
        return e;
    }
    let seed = t.writer_seed;
    let expected = t.writer_public;
    let e = writer_primary(t, &seed, Some(&expected), &mut public, &mut key);

    if e != 0 {
        return e;
    }
    let mut e = writer_sign(t, key, &authorization.digest, &mut signature);

    if e == 0 {
        let ret = writer_authorize(t, key, session, &authorization, &signature);

        if ret != RC_SUCCESS {
            crate::log::err(format!("tpm: NV writer PolicySigned: rc=0x{ret:08x}").as_bytes());
            e = -EACCES;
        }
    }
    session_flush(t, key);
    // SAFETY: the signature's bytes.
    unsafe { explicit_bzero(signature.as_mut_ptr().cast(), signature.len()) };
    e
}

/// PolicyCommandCode(NV_Extend) closes the session, whose digest must be
/// the one computed in software: a drift is caught here.
pub(crate) fn policy_session_finish(
    t: &Tpm,
    session: EsysTr,
    expected: &[u8; DIGEST_LEN],
) -> c_int {
    let mut digest: *mut Tpm2bDigest = ptr::null_mut();
    // SAFETY: the context, handles and a command code.
    let ret = unsafe {
        Esys_PolicyCommandCode(
            t.esys,
            session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            CC_NV_EXTEND,
        )
    };

    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: register policy assertion: rc=0x{ret:08x}").as_bytes());
        return -EACCES;
    }
    // SAFETY: the context, handles and room for the digest.
    let ret = unsafe {
        Esys_PolicyGetDigest(
            t.esys,
            session,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut digest,
        )
    };
    // SAFETY: the digest ESYS gave, if any.
    let given = unsafe { digest.as_ref() };
    let differs = ret != RC_SUCCESS
        || given.is_none_or(|d| {
            usize::from(d.size) != DIGEST_LEN || d.buffer[..DIGEST_LEN] != *expected
        });
    let e = if differs {
        crate::log::err(
            format!(
                "tpm: register policy digest does not match the computed policy (rc=0x{ret:08x})"
            )
            .as_bytes(),
        );
        -EPROTO
    } else {
        0
    };
    // SAFETY: what ESYS gave, or NULL, freed once.
    unsafe { Esys_Free(digest.cast()) };
    e
}

/// The branches of a register write.
struct Branches<'a> {
    written: &'a [u8; DIGEST_LEN],
    init: &'a [u8; DIGEST_LEN],
}

/// Walks one branch of the register's write policy in a real session,
/// the first write of a boot the init branch, and authorizes the exact
/// NV_Extend with the TPM-held writer after PolicyOR. The session's
/// digest is checked against the software policy to catch a drift.
fn policy_session_register(
    t: &Tpm,
    init: bool,
    index: u32,
    event: &[u8; DIGEST_LEN],
    pcr_mask: u32,
    branches: &Branches<'_>,
    session: &mut EsysTr,
) -> c_int {
    let mut list: DigestList = zeroed();
    let mut expected = [0u8; DIGEST_LEN];

    list.count = 2;
    if !t.writer_set {
        crate::log::err(b"tpm: register policy requires the NV writer public key");
        return -EACCES;
    }
    let e = session_start(t, t.session_key.handle, SE_POLICY, session);

    if e != 0 {
        return e;
    }
    // SAFETY: the context, the session and handles.
    let mut ret = unsafe {
        Esys_PolicyNvWritten(
            t.esys,
            *session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            if init { NO } else { YES },
        )
    };
    if ret == RC_SUCCESS && init {
        let live = Tpm2bDigest::zeroed();
        let sel = pcr_selection(pcr_mask);

        // SAFETY: the context, the session, handles, an empty digest and
        // the selection.
        ret = unsafe {
            Esys_PolicyPCR(
                t.esys,
                *session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &live,
                &sel,
            )
        };
    }
    if ret == RC_SUCCESS {
        list.digests[0].size = 32;
        list.digests[0].buffer[..32].copy_from_slice(branches.written);
        list.digests[1].size = 32;
        list.digests[1].buffer[..32].copy_from_slice(branches.init);
        // SAFETY: the context, the session, handles and the branches.
        ret = unsafe {
            Esys_PolicyOR(
                t.esys,
                *session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &list,
            )
        };
    }
    if ret == RC_SUCCESS {
        let e = policy_writer_signed(t, *session, index, event);

        if e != 0 {
            session_flush(t, *session);
            *session = ESYS_TR_NONE;
            return e;
        }
    }
    if ret != RC_SUCCESS {
        if rc_is(ret, RC_VALUE) && init {
            crate::log::err(b"tpm: the anchoring PCR moved; the register can only be initialised in the boot window");
        } else {
            crate::log::err(format!("tpm: register policy assertion: rc=0x{ret:08x}").as_bytes());
        }
        session_flush(t, *session);
        *session = ESYS_TR_NONE;
        return -EACCES;
    }
    let mut e = register_policy_final(
        branches.written,
        branches.init,
        &t.writer_public,
        &mut expected,
    );

    if e != 0 {
        crate::log::err(format!("tpm: compute signed register policy: {}", text(e)).as_bytes());
    } else {
        e = policy_session_finish(t, *session, &expected);
    }
    if e != 0 {
        session_flush(t, *session);
        *session = ESYS_TR_NONE;
    }
    e
}

fn nv_extend_session(t: &Tpm, index: u32, session: EsysTr, event: &[u8; DIGEST_LEN]) -> c_int {
    let mut data: Tpm2bMaxNvBuffer = zeroed();
    let mut nv = 0;

    data.size = DIGEST_LEN as u16;
    let e = nv_handle(t, index, &mut nv);

    if e != 0 {
        return e;
    }
    data.buffer[..DIGEST_LEN].copy_from_slice(event);
    // SAFETY: the context, handles and the data.
    let ret = unsafe { Esys_NV_Extend(t.esys, nv, nv, session, ESYS_TR_NONE, ESYS_TR_NONE, &data) };

    tr_close(t, &mut nv);
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: NV_Extend(0x{index:08x}): rc=0x{ret:08x}").as_bytes());
        return if rc_is_auth_failure(ret) {
            -EACCES
        } else {
            -EIO
        };
    }
    0
}

/// One extend of the register, through the policy branch `init` names.
fn nv_extend_through(
    t: &Tpm,
    init: bool,
    index: u32,
    pcr_mask: u32,
    branches: &Branches<'_>,
    event: &[u8; DIGEST_LEN],
) -> c_int {
    let mut session = ESYS_TR_NONE;
    let e = policy_session_register(t, init, index, event, pcr_mask, branches, &mut session);

    if e != 0 {
        return e;
    }
    let e = nv_extend_session(t, index, session, event);

    session_flush(t, session);
    e
}

/// `put_be16()`.
fn put_be16(out: &mut [u8], v: u16) {
    out[..2].copy_from_slice(&v.to_be_bytes());
}

/// `tpm_put2b()`: a TPM2B of `data` at the start of `out`, its length.
fn put2b(out: &mut [u8], data: &[u8]) -> usize {
    put_be16(out, data.len() as u16);
    out[2..2 + data.len()].copy_from_slice(data);
    data.len() + 2
}

/// The marshalled TPMT_PUBLIC of a key shirudo makes, from the area ESYS
/// gave.
fn public_from_tss(p: &Public, out: &mut [u8], len: &mut usize) -> c_int {
    let mut public = TpmPublic::zeroed();

    if p.nameAlg != ALG_SHA256 || p.authPolicy.size > 32 {
        return -EINVAL;
    }
    public.ty = p.type_;
    public.attrs = p.objectAttributes;
    public.policy_len = usize::from(p.authPolicy.size);
    public.policy[..public.policy_len].copy_from_slice(&p.authPolicy.buffer[..public.policy_len]);
    if p.type_ == ALG_ECC {
        // SAFETY: an ECC key's variants, read once its type says ECC.
        let (ecc, point) = unsafe { (&p.parameters.eccDetail, &p.unique.ecc) };

        public.sym_alg = ecc.symmetric.algorithm;
        if public.sym_alg != ALG_NULL {
            // SAFETY: a symmetric definition's bits and mode, as the C read
            // them whatever the algorithm.
            (public.sym_bits, public.sym_mode) =
                unsafe { (ecc.symmetric.keyBits.sym, ecc.symmetric.mode.sym) };
        }
        public.scheme = ecc.scheme.scheme;
        if public.scheme != ALG_NULL {
            // SAFETY: every scheme of a key holds its hash first.
            public.scheme_hash = unsafe { ecc.scheme.details.anySig.hashAlg };
        }
        public.curve = ecc.curveID;
        if ecc.kdf.scheme != ALG_NULL || point.x.size != 32 || point.y.size != 32 {
            return -EINVAL;
        }
        public.x.copy_from_slice(&point.x.buffer[..32]);
        public.y.copy_from_slice(&point.y.buffer[..32]);
    } else if p.type_ == ALG_RSA {
        // SAFETY: an RSA key's variants, read once its type says RSA.
        let (rsa, n) = unsafe { (&p.parameters.rsaDetail, &p.unique.rsa) };

        public.sym_alg = rsa.symmetric.algorithm;
        if public.sym_alg != ALG_NULL {
            // SAFETY: a symmetric definition's bits and mode, as the C read
            // them whatever the algorithm.
            (public.sym_bits, public.sym_mode) =
                unsafe { (rsa.symmetric.keyBits.sym, rsa.symmetric.mode.sym) };
        }
        public.scheme = rsa.scheme.scheme;
        if public.scheme != ALG_NULL {
            // SAFETY: every scheme of a key holds its hash first.
            public.scheme_hash = unsafe { rsa.scheme.details.anySig.hashAlg };
        }
        public.rsa_bits = rsa.keyBits;
        public.rsa_exponent = rsa.exponent;
        if usize::from(n.size) > public.n.len() {
            return -EINVAL;
        }
        public.n_len = usize::from(n.size);
        public.n[..public.n_len].copy_from_slice(&n.buffer[..public.n_len]);
    } else {
        return -EPROTONOSUPPORT;
    }
    public_marshal(&public, out, len)
}

/// An ECDSA signature as TPMT_SIGNATURE.
fn marshal_signature(sig: &Signature, out: &mut [u8], len: &mut usize) -> c_int {
    // SAFETY: the ECDSA variant, whose fields any bits are values of;
    // used only once the algorithm says ECDSA.
    let e = unsafe { &sig.signature.ecdsa };

    if sig.sigAlg != ALG_ECDSA
        || e.signatureR.size > 64
        || e.signatureS.size > 64
        || out.len() < 8 + 128
    {
        return -EINVAL;
    }
    let mut off = 0;

    put_be16(&mut out[off..], sig.sigAlg);
    off += 2;
    put_be16(&mut out[off..], e.hash);
    off += 2;
    off += put2b(
        &mut out[off..],
        &e.signatureR.buffer[..usize::from(e.signatureR.size)],
    );
    off += put2b(
        &mut out[off..],
        &e.signatureS.buffer[..usize::from(e.signatureS.size)],
    );
    *len = off;
    0
}

/// A primary under the endorsement hierarchy, with its marshalled public
/// area and its name, the latter checked against the area so that what
/// the evidence carries is what the TPM named.
fn endorsement_primary(t: &Tpm, in_pub: &Tpm2bPublic, what: &CStr, key: &mut TpmKey) -> c_int {
    let sensitive = Tpm2bSensitiveCreate::zeroed();
    let creation_pcr = PcrSelectionList::zeroed();
    let mut out_pub: *mut Tpm2bPublic = ptr::null_mut();
    let mut name: *mut Tpm2bName = ptr::null_mut();
    let outside = Tpm2bData::zeroed();
    let mut computed = [0u8; NAME_LEN];
    let mut handle: EsysTr = 0;

    // SAFETY: the caller's key, all of whose bits zeroed are one,
    // padding included as memset() left it.
    unsafe { ptr::from_mut(key).write_bytes(0, 1) };
    let auth = if t.session == ESYS_TR_NONE {
        ESYS_TR_PASSWORD
    } else {
        t.session
    };
    // SAFETY: the context, handles, the templates and room for the
    // handle and public area.
    let ret = unsafe {
        Esys_CreatePrimary(
            t.esys,
            ESYS_TR_RH_ENDORSEMENT,
            auth,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &sensitive,
            in_pub,
            &outside,
            &creation_pcr,
            &mut handle,
            &mut out_pub,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if ret != RC_SUCCESS {
        if rc_is_auth_failure(ret) {
            crate::log::err(
                &[
                    &b"tpm: CreatePrimary("[..],
                    what.to_bytes(),
                    b"): the endorsement hierarchy has an auth value (rc=0x",
                    format!("{ret:08x}").as_bytes(),
                    b")",
                ]
                .concat(),
            );
        } else {
            crate::log::err(
                &[
                    &b"tpm: CreatePrimary("[..],
                    what.to_bytes(),
                    b"): rc=0x",
                    format!("{ret:08x}").as_bytes(),
                ]
                .concat(),
            );
        }
        return -EIO;
    }
    key.handle = handle;
    // SAFETY: the public area ESYS gave on success, freed once.
    let mut e = unsafe {
        let e = public_from_tss(&(*out_pub).publicArea, &mut key.public, &mut key.public_len);

        Esys_Free(out_pub.cast());
        e
    };
    if e == 0 {
        e = match key.public.get(..key.public_len) {
            Some(public) => object_name(public, &mut computed),
            None => -EINVAL,
        };
    }
    if e == 0 {
        // SAFETY: the context, the key and room for its name.
        let ret = unsafe { Esys_TR_GetName(t.esys, handle, &mut name) };
        // SAFETY: the name ESYS gave on success.
        let given = unsafe { name.as_ref() };

        match given {
            Some(n)
                if ret == RC_SUCCESS
                    && usize::from(n.size) == NAME_LEN
                    && n.name[..NAME_LEN] == computed =>
            {
                key.name.copy_from_slice(&n.name[..NAME_LEN]);
                key.name_len = NAME_LEN;
            }
            _ => {
                crate::log::err(
                    &[
                        &b"tpm: "[..],
                        what.to_bytes(),
                        b" name does not match its marshalled public area",
                    ]
                    .concat(),
                );
                e = -EPROTO;
            }
        }
        // SAFETY: what ESYS gave, or NULL, freed once.
        unsafe { Esys_Free(name.cast()) };
    }
    if e != 0 {
        // SAFETY: the open connection's context.
        unsafe { key_flush(t.esys, key) };
    }
    e
}

fn ak_create(t: &Tpm, ak: &mut TpmKey) -> c_int {
    let mut in_pub = Tpm2bPublic::zeroed();
    let p = &mut in_pub.publicArea;

    p.type_ = ALG_ECC;
    p.nameAlg = ALG_SHA256;
    p.objectAttributes = OBJECT_FIXEDTPM
        | OBJECT_FIXEDPARENT
        | OBJECT_SENSITIVEDATAORIGIN
        | OBJECT_USERWITHAUTH
        | OBJECT_RESTRICTED
        | OBJECT_SIGN_ENCRYPT;
    p.parameters.eccDetail = EccParms {
        symmetric: sym_def(ALG_NULL, 0, 0),
        scheme: ecc_scheme(ALG_ECDSA, ALG_SHA256),
        curveID: ECC_NIST_P256,
        kdf: kdf_null(),
    };
    endorsement_primary(t, &in_pub, c"attestation key", ak)
}

fn ek_create(t: &Tpm, rsa: bool, ek: &mut TpmKey) -> c_int {
    let mut in_pub = Tpm2bPublic::zeroed();
    let p = &mut in_pub.publicArea;
    let symmetric = sym_def(ALG_AES, 128, ALG_CFB);

    p.type_ = if rsa { ALG_RSA } else { ALG_ECC };
    p.nameAlg = ALG_SHA256;
    p.objectAttributes = EK_ATTRS;
    p.authPolicy.size = 32;
    p.authPolicy.buffer[..32].copy_from_slice(&EK_POLICY);
    if rsa {
        p.parameters.rsaDetail = RsaParms {
            symmetric,
            scheme: rsa_scheme(ALG_NULL, 0),
            keyBits: 2048,
            exponent: 0,
        };
        p.unique.rsa = Tpm2bPublicKeyRsa {
            size: 256,
            buffer: [0; 512],
        };
    } else {
        p.parameters.eccDetail = EccParms {
            symmetric,
            scheme: ecc_scheme(ALG_NULL, 0),
            curveID: ECC_NIST_P256,
            kdf: kdf_null(),
        };
        let empty = Tpm2bEccParameter {
            size: 32,
            buffer: [0; 128],
        };
        p.unique.ecc = EccPoint { x: empty, y: empty };
    }
    endorsement_primary(t, &in_pub, c"endorsement key", ek)
}

/// Flushes the key's handle, if any, and forgets the key.
///
/// # Safety
///
/// `esys` is the context of the open connection the key's handle
/// belongs to, or anything when the key has none.
unsafe fn key_flush(esys: *mut EsysContext, key: &mut TpmKey) {
    if key.handle != ESYS_TR_NONE && key.handle != 0 {
        // SAFETY: the caller's context, and the key's handle in it.
        unsafe { Esys_FlushContext(esys, key.handle) };
    }
    // SAFETY: the key's bytes.
    unsafe { explicit_bzero(ptr::from_mut(key).cast(), size_of::<TpmKey>()) };
    key.handle = ESYS_TR_NONE;
}

fn attestation_copy(attest: &Tpm2bAttest, sig: &Signature, out: &mut TpmAttestation) -> c_int {
    let size = usize::from(attest.size);

    if size > out.attest.len() {
        return -E2BIG;
    }
    out.attest[..size].copy_from_slice(&attest.attestationData[..size]);
    out.attest_len = size;
    marshal_signature(sig, &mut out.signature, &mut out.signature_len)
}

/// The caller's nonce as qualifying data: -EINVAL for one too long.
///
/// # Safety
///
/// `nonce` holds `nonce_len` bytes.
unsafe fn qualifying(nonce: *const u8, nonce_len: usize) -> Result<Tpm2bData, c_int> {
    let mut qual = Tpm2bData::zeroed();

    if nonce_len > qual.buffer.len() {
        return Err(-EINVAL);
    }
    // SAFETY: the caller's nonce_len bytes.
    unsafe { ptr::copy_nonoverlapping(nonce, qual.buffer.as_mut_ptr(), nonce_len) };
    qual.size = nonce_len as u16;
    Ok(qual)
}

/// Copies an attestation and its signature ESYS gave, and frees them.
///
/// # Safety
///
/// `attest` and `sig` are ESYS's outputs of a successful command.
unsafe fn attestation_take(
    attest: *mut Tpm2bAttest,
    sig: *mut Signature,
    out: &mut TpmAttestation,
) -> c_int {
    // SAFETY: the outputs, copied and then each freed once.
    unsafe {
        let e = attestation_copy(&*attest, &*sig, out);

        Esys_Free(attest.cast());
        Esys_Free(sig.cast());
        e
    }
}

/// # Safety
///
/// `nonce` holds `nonce_len` bytes.
unsafe fn quote(
    t: &Tpm,
    ak: &TpmKey,
    nonce: *const u8,
    nonce_len: usize,
    pcr_mask: u32,
    out: &mut TpmAttestation,
) -> c_int {
    let scheme = sig_scheme(ALG_NULL, 0);
    let mut sig: *mut Signature = ptr::null_mut();
    let mut quoted: *mut Tpm2bAttest = ptr::null_mut();
    // SAFETY: the caller's nonce.
    let qual = match unsafe { qualifying(nonce, nonce_len) } {
        Ok(q) => q,
        Err(e) => return e,
    };
    let sel = pcr_selection(pcr_mask);
    // SAFETY: the context, handles, the nonce, scheme and selection, and
    // room for the quote and signature.
    let ret = unsafe {
        Esys_Quote(
            t.esys,
            ak.handle,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &qual,
            &scheme,
            &sel,
            &mut quoted,
            &mut sig,
        )
    };
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: Quote: rc=0x{ret:08x}").as_bytes());
        return -EIO;
    }
    // SAFETY: the outputs of the successful command.
    unsafe { attestation_take(quoted, sig, out) }
}

/// # Safety
///
/// `nonce` holds `nonce_len` bytes.
unsafe fn nv_certify(
    t: &Tpm,
    ak: &TpmKey,
    index: u32,
    nonce: *const u8,
    nonce_len: usize,
    out: &mut TpmAttestation,
) -> c_int {
    let scheme = sig_scheme(ALG_NULL, 0);
    let mut sig: *mut Signature = ptr::null_mut();
    let mut info: *mut Tpm2bAttest = ptr::null_mut();
    let mut nv = 0;
    // SAFETY: the caller's nonce.
    let qual = match unsafe { qualifying(nonce, nonce_len) } {
        Ok(q) => q,
        Err(e) => return e,
    };
    let e = nv_handle(t, index, &mut nv);

    if e != 0 {
        return e;
    }
    // SAFETY: the context, handles, the nonce and scheme, and room for
    // the certification and signature.
    let ret = unsafe {
        Esys_NV_Certify(
            t.esys,
            ak.handle,
            nv,
            nv,
            t.session,
            ESYS_TR_PASSWORD,
            ESYS_TR_NONE,
            &qual,
            &scheme,
            DIGEST_LEN as u16,
            0,
            &mut info,
            &mut sig,
        )
    };
    tr_close(t, &mut nv);
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: NV_Certify(0x{index:08x}): rc=0x{ret:08x}").as_bytes());
        return if rc_is(ret, RC_NV_UNINITIALIZED) {
            -ENODATA
        } else {
            -EIO
        };
    }
    // SAFETY: the outputs of the successful command.
    unsafe { attestation_take(info, sig, out) }
}

/// A credential and its protector, as an operator made them for `ak`
/// under `ek`.
struct Credential<'a> {
    blob: &'a [u8],
    secret: &'a [u8],
}

/// TPM2_ActivateCredential through the endorsement key's policy: the
/// credential into `out`, or -EKEYREJECTED for one the TPM refuses.
fn activate_credential(
    t: &Tpm,
    ak: &TpmKey,
    ek: &TpmKey,
    cred: &Credential<'_>,
    out: &mut [u8],
    out_len: &mut usize,
) -> c_int {
    let mut sec: Tpm2bEncryptedSecret = zeroed();
    let mut cert_info: *mut Tpm2bDigest = ptr::null_mut();
    let mut session = ESYS_TR_NONE;
    let mut id: Tpm2bIdObject = zeroed();

    if cred.blob.len() > id.credential.len() || cred.secret.len() > sec.secret.len() {
        return -EINVAL;
    }
    id.size = cred.blob.len() as u16;
    id.credential[..cred.blob.len()].copy_from_slice(cred.blob);
    sec.size = cred.secret.len() as u16;
    sec.secret[..cred.secret.len()].copy_from_slice(cred.secret);
    let e = session_start(t, t.session_key.handle, SE_POLICY, &mut session);

    if e != 0 {
        return e;
    }
    // The endorsement key's policy: the hierarchy's own authorisation.
    // SAFETY: the context and handles, the rest NULL.
    let ret = unsafe {
        Esys_PolicySecret(
            t.esys,
            ESYS_TR_RH_ENDORSEMENT,
            session,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            ptr::null(),
            ptr::null(),
            ptr::null(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        )
    };
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: PolicySecret(endorsement): rc=0x{ret:08x}").as_bytes());
        session_flush(t, session);
        return -EACCES;
    }
    // SAFETY: the context, handles, the credential and secret, and room
    // for what it protects.
    let ret = unsafe {
        Esys_ActivateCredential(
            t.esys,
            ak.handle,
            ek.handle,
            t.session,
            session,
            ESYS_TR_NONE,
            &id,
            &sec,
            &mut cert_info,
        )
    };
    session_flush(t, session);
    if ret != RC_SUCCESS {
        crate::log::err(format!("tpm: ActivateCredential: rc=0x{ret:08x}").as_bytes());
        return if ret & 0xFFFF_0000 == 0 {
            -EKEYREJECTED
        } else {
            -EIO
        };
    }
    // SAFETY: the credential ESYS gave on success, freed once.
    unsafe {
        let c = &*cert_info;
        let size = usize::from(c.size);

        if size > out.len() {
            Esys_Free(cert_info.cast());
            return -E2BIG;
        }
        out[..size].copy_from_slice(&c.buffer[..size]);
        *out_len = size;
        Esys_Free(cert_info.cast());
    }
    0
}

/// The whole of an NV index, in chunks the TPM takes, into `out`.
fn nv_read_all(t: &Tpm, index: u32, out: &mut [u8], len: &mut usize) -> c_int {
    let mut public: *mut Tpm2bNvPublic = ptr::null_mut();
    let mut nv = 0;
    let e = nv_handle(t, index, &mut nv);

    if e != 0 {
        return e;
    }
    // SAFETY: the context, handles and room for the public area.
    let ret = unsafe {
        Esys_NV_ReadPublic(
            t.esys,
            nv,
            t.session,
            ESYS_TR_NONE,
            ESYS_TR_NONE,
            &mut public,
            ptr::null_mut(),
        )
    };

    if ret != RC_SUCCESS {
        tr_close(t, &mut nv);
        return -EIO;
    }
    // SAFETY: the public area ESYS gave on success, freed once.
    let total = unsafe {
        let total = usize::from((*public).nvPublic.dataSize);

        Esys_Free(public.cast());
        total
    };
    if total > out.len() {
        tr_close(t, &mut nv);
        return -E2BIG;
    }
    let mut off = 0;

    while off < total {
        let mut data: *mut Tpm2bMaxNvBuffer = ptr::null_mut();
        let want = (total - off).min(NV_READ_CHUNK);
        // SAFETY: the context, handles and room for the data.
        let ret = unsafe {
            Esys_NV_Read(
                t.esys,
                nv,
                nv,
                t.session,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                want as u16,
                off as u16,
                &mut data,
            )
        };
        if ret != RC_SUCCESS {
            tr_close(t, &mut nv);
            return -EIO;
        }
        // SAFETY: the data ESYS gave on success, freed once.
        let got = unsafe {
            let d = &*data;
            let size = usize::from(d.size);

            if size == 0 || size > want {
                Esys_Free(data.cast());
                None
            } else {
                out[off..off + size].copy_from_slice(&d.buffer[..size]);
                Esys_Free(data.cast());
                Some(size)
            }
        };
        let Some(size) = got else {
            tr_close(t, &mut nv);
            return -EIO;
        };
        off += size;
    }
    tr_close(t, &mut nv);
    *len = total;
    0
}

/// The endorsement key's certificate from its TCG NV index, the ECC one
/// first, `*rsa` telling which; -ENOENT for none.
fn ek_certificate(t: &Tpm, out: &mut [u8], len: &mut usize, rsa: &mut bool) -> c_int {
    *rsa = false;
    let mut e = nv_read_all(t, EK_CERT_NV_ECC, out, len);

    if e == -ENOENT {
        e = nv_read_all(t, EK_CERT_NV_RSA, out, len);
        *rsa = e == 0;
    }
    e
}

/// For Rust callers.
pub(crate) use capi::{
    tpm_activate_credential, tpm_ak_create, tpm_boot_identity, tpm_close, tpm_ek_certificate,
    tpm_ek_create, tpm_ek_name, tpm_key_flush, tpm_nv_certify, tpm_nv_define, tpm_nv_extend,
    tpm_nv_extend_first, tpm_nv_info, tpm_nv_read, tpm_nv_set_writer, tpm_nv_undefine, tpm_open,
    tpm_open_quiet, tpm_pcr_extend, tpm_pcr_read, tpm_quote, tpm_reset_count, tpm_tcti,
    tpm_writer_create,
};

mod capi {
    use core::ffi::{c_char, c_int, c_void};

    use super::{
        Branches, Credential, DIGEST_LEN, NAME_LEN, NV_RSA_BYTES, Tpm, TpmAttestation, TpmKey,
        TpmNvInfo,
    };
    use crate::errno::{EACCES, EINVAL};
    use crate::ffi;
    use crate::sys::tss2::ESYS_TR_NONE;

    /// A fixed-size array at `p`.
    ///
    /// # Safety
    ///
    /// `p` points to `N` readable bytes.
    unsafe fn arr<'a, const N: usize>(p: *const u8) -> &'a [u8; N] {
        // SAFETY: the caller's N bytes.
        unsafe { &*p.cast::<[u8; N]>() }
    }

    /// Room for a fixed-size array at `p`.
    ///
    /// # Safety
    ///
    /// `p` points to `N` writable bytes.
    unsafe fn arr_mut<'a, const N: usize>(p: *mut u8) -> &'a mut [u8; N] {
        // SAFETY: the caller's N bytes.
        unsafe { &mut *p.cast::<[u8; N]>() }
    }

    /// # Safety
    ///
    /// `buf` is room for `size` bytes.
    pub unsafe extern "C" fn tpm_tcti(buf: *mut c_char, size: usize) -> c_int {
        // SAFETY: the caller passes room.
        unsafe { super::tcti(buf.cast(), size) }
    }

    /// # Safety
    ///
    /// `out` is room for a pointer.
    pub unsafe extern "C" fn tpm_open(out: *mut *mut Tpm) -> c_int {
        // SAFETY: the caller passes room.
        unsafe { super::open_tpm(out, false) }
    }

    /// # Safety
    ///
    /// `out` is room for a pointer.
    pub unsafe extern "C" fn tpm_open_quiet(out: *mut *mut Tpm) -> c_int {
        // SAFETY: the caller passes room.
        unsafe { super::open_tpm(out, true) }
    }

    /// # Safety
    ///
    /// `t` is NULL or a connection tpm_open() gave.
    pub unsafe extern "C" fn tpm_close(t: *mut Tpm) {
        // SAFETY: the caller passes a connection.
        unsafe { super::close(t) }
    }

    /// # Safety
    ///
    /// `t` is a connection, and `out` room for a name.
    pub unsafe extern "C" fn tpm_ek_name(t: *mut Tpm, out: *mut u8) {
        // SAFETY: the caller passes a connection and room.
        unsafe { *arr_mut::<NAME_LEN>(out) = (*t).session_key.name };
    }

    /// # Safety
    ///
    /// `t` is NULL or a connection, and `seed` and `public` NULL or a
    /// seed and a modulus.
    pub unsafe extern "C" fn tpm_nv_set_writer(
        t: *mut Tpm,
        seed: *const u8,
        public: *const u8,
    ) -> c_int {
        // SAFETY: the modulus's first byte, once its pointer is not NULL.
        let top = unsafe { public.as_ref() }.copied().unwrap_or(0);

        if t.is_null() || seed.is_null() || public.is_null() || top & 0x80 == 0 {
            crate::log::err(b"tpm: NV writer identity is required");
            return -EACCES;
        }
        // SAFETY: the caller's connection, seed and modulus.
        unsafe {
            let t = &mut *t;

            t.writer_seed = *arr::<DIGEST_LEN>(seed);
            t.writer_public = *arr::<NV_RSA_BYTES>(public);
            t.writer_set = true;
        }
        0
    }

    /// # Safety
    ///
    /// `t` is a connection, and `out` room for a digest.
    pub unsafe extern "C" fn tpm_pcr_read(t: *mut Tpm, pcr: u32, out: *mut u8) -> c_int {
        // SAFETY: the caller passes a connection and room.
        unsafe { super::pcr_read(&*t, pcr, arr_mut(out)) }
    }

    /// # Safety
    ///
    /// `t` is a connection, and `digest` a digest.
    pub unsafe extern "C" fn tpm_pcr_extend(t: *mut Tpm, pcr: u32, digest: *const u8) -> c_int {
        // SAFETY: the caller passes a connection and a digest.
        unsafe { super::pcr_extend(&*t, pcr, arr(digest)) }
    }

    /// # Safety
    ///
    /// `t` is a connection, and `out` room for a count.
    pub unsafe extern "C" fn tpm_reset_count(t: *mut Tpm, out: *mut u32) -> c_int {
        // SAFETY: the caller passes a connection and room.
        match super::read_clock(unsafe { &*t }) {
            Ok((reset, _)) => {
                // SAFETY: as above.
                unsafe { *out = reset };
                0
            }
            Err(e) => e,
        }
    }

    /// # Safety
    ///
    /// `t`, `reset` and `restart` are NULL or a connection and room for
    /// two counts.
    pub unsafe extern "C" fn tpm_boot_identity(
        t: *mut Tpm,
        reset: *mut u32,
        restart: *mut u32,
    ) -> c_int {
        if t.is_null() || reset.is_null() || restart.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller passes a connection and room.
        match super::read_clock(unsafe { &*t }) {
            Ok((r, s)) => {
                // SAFETY: as above.
                unsafe {
                    *reset = r;
                    *restart = s;
                }
                0
            }
            Err(e) => e,
        }
    }

    /// # Safety
    ///
    /// `t` is a connection, and `info` room for the info.
    pub unsafe extern "C" fn tpm_nv_info(t: *mut Tpm, index: u32, info: *mut TpmNvInfo) -> c_int {
        // SAFETY: the caller passes a connection and room.
        unsafe { super::nv_info(&*t, index, &mut *info) }
    }

    /// # Safety
    ///
    /// `t` is a connection, `policy` a digest, and `owner_auth` holds
    /// `owner_auth_len` bytes.
    pub unsafe extern "C" fn tpm_nv_define(
        t: *mut Tpm,
        index: u32,
        policy: *const u8,
        owner_auth: *const c_void,
        owner_auth_len: usize,
    ) -> c_int {
        // SAFETY: the caller passes a connection, a digest and the
        // password.
        unsafe {
            super::nv_define(
                &*t,
                index,
                arr(policy),
                ffi::slice(owner_auth.cast(), owner_auth_len),
            )
        }
    }

    /// # Safety
    ///
    /// `t` is a connection, and `owner_auth` holds `owner_auth_len`
    /// bytes.
    pub unsafe extern "C" fn tpm_nv_undefine(
        t: *mut Tpm,
        index: u32,
        owner_auth: *const c_void,
        owner_auth_len: usize,
    ) -> c_int {
        // SAFETY: the caller passes a connection and the password.
        unsafe { super::nv_undefine(&*t, index, ffi::slice(owner_auth.cast(), owner_auth_len)) }
    }

    /// # Safety
    ///
    /// `t` is a connection, and `out` room for a digest.
    pub unsafe extern "C" fn tpm_nv_read(t: *mut Tpm, index: u32, out: *mut u8) -> c_int {
        // SAFETY: the caller passes a connection and room.
        unsafe { super::nv_read(&*t, index, arr_mut(out)) }
    }

    /// # Safety
    ///
    /// `t` is a connection, and the rest are digests.
    pub unsafe extern "C" fn tpm_nv_extend_first(
        t: *mut Tpm,
        index: u32,
        pcr_mask: u32,
        branch_written: *const u8,
        branch_init: *const u8,
        event: *const u8,
    ) -> c_int {
        // SAFETY: the caller passes a connection and digests.
        unsafe {
            let branches = Branches {
                written: arr(branch_written),
                init: arr(branch_init),
            };

            super::nv_extend_through(&*t, true, index, pcr_mask, &branches, arr(event))
        }
    }

    /// # Safety
    ///
    /// `t` is a connection, and the rest are digests.
    pub unsafe extern "C" fn tpm_nv_extend(
        t: *mut Tpm,
        index: u32,
        branch_written: *const u8,
        branch_init: *const u8,
        event: *const u8,
    ) -> c_int {
        // SAFETY: the caller passes a connection and digests.
        unsafe {
            let branches = Branches {
                written: arr(branch_written),
                init: arr(branch_init),
            };

            super::nv_extend_through(&*t, false, index, 0, &branches, arr(event))
        }
    }

    /// # Safety
    ///
    /// `t` is a connection, and `ak` room for a key.
    pub unsafe extern "C" fn tpm_ak_create(t: *mut Tpm, ak: *mut TpmKey) -> c_int {
        // SAFETY: the caller passes a connection and room.
        unsafe { super::ak_create(&*t, &mut *ak) }
    }

    /// # Safety
    ///
    /// `t` is a connection, and `ek` room for a key.
    pub unsafe extern "C" fn tpm_ek_create(t: *mut Tpm, rsa: bool, ek: *mut TpmKey) -> c_int {
        // SAFETY: the caller passes a connection and room.
        unsafe { super::ek_create(&*t, rsa, &mut *ek) }
    }

    /// # Safety
    ///
    /// `t` is a connection, `ak` and `ek` keys, `blob` and `secret` hold
    /// their lengths' bytes, and `out` is room for `cap`.
    pub unsafe extern "C" fn tpm_activate_credential(
        t: *mut Tpm,
        ak: *const TpmKey,
        ek: *const TpmKey,
        blob: *const u8,
        blob_len: usize,
        secret: *const u8,
        secret_len: usize,
        out: *mut u8,
        cap: usize,
        out_len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes a connection, keys, the bytes and
        // room.
        unsafe {
            let cred = Credential {
                blob: ffi::slice(blob, blob_len),
                secret: ffi::slice(secret, secret_len),
            };

            super::activate_credential(
                &*t,
                &*ak,
                &*ek,
                &cred,
                ffi::bytes_mut(out, cap),
                &mut *out_len,
            )
        }
    }

    /// # Safety
    ///
    /// `key` is a key, and `t` a connection when the key holds a handle:
    /// as the C did, an empty key is flushed without one, so a caller's
    /// cleanup may pass a connection it already closed.
    pub unsafe extern "C" fn tpm_key_flush(t: *mut Tpm, key: *mut TpmKey) {
        // SAFETY: the caller passes a key.
        let key = unsafe { &mut *key };
        let esys = if key.handle != ESYS_TR_NONE && key.handle != 0 {
            // SAFETY: a key with a handle comes with its connection.
            unsafe { (*t).esys }
        } else {
            core::ptr::null_mut()
        };
        // SAFETY: the connection of a key with a handle, else NULL for a
        // key with none.
        unsafe { super::key_flush(esys, key) };
    }

    /// # Safety
    ///
    /// `t` is a connection, `ak` a key, `nonce` holds `nonce_len` bytes,
    /// and `out` is room for an attestation.
    pub unsafe extern "C" fn tpm_quote(
        t: *mut Tpm,
        ak: *const TpmKey,
        nonce: *const u8,
        nonce_len: usize,
        pcr_mask: u32,
        out: *mut TpmAttestation,
    ) -> c_int {
        // SAFETY: the caller passes a connection, a key, the nonce and
        // room.
        unsafe { super::quote(&*t, &*ak, nonce, nonce_len, pcr_mask, &mut *out) }
    }

    /// # Safety
    ///
    /// `t` is a connection, `ak` a key, `nonce` holds `nonce_len` bytes,
    /// and `out` is room for an attestation.
    pub unsafe extern "C" fn tpm_nv_certify(
        t: *mut Tpm,
        ak: *const TpmKey,
        index: u32,
        nonce: *const u8,
        nonce_len: usize,
        out: *mut TpmAttestation,
    ) -> c_int {
        // SAFETY: the caller passes a connection, a key, the nonce and
        // room.
        unsafe { super::nv_certify(&*t, &*ak, index, nonce, nonce_len, &mut *out) }
    }

    /// # Safety
    ///
    /// `t` is a connection, `out` room for `cap` bytes, and `len` and
    /// `rsa` room for a length and a flag.
    pub unsafe extern "C" fn tpm_ek_certificate(
        t: *mut Tpm,
        out: *mut u8,
        cap: usize,
        len: *mut usize,
        rsa: *mut bool,
    ) -> c_int {
        // SAFETY: the caller passes a connection and room.
        unsafe { super::ek_certificate(&*t, ffi::bytes_mut(out, cap), &mut *len, &mut *rsa) }
    }

    /// # Safety
    ///
    /// `t` is a connection, `seed` a seed, and `public` room for a
    /// modulus.
    pub unsafe extern "C" fn tpm_writer_create(
        t: *mut Tpm,
        seed: *const u8,
        public: *mut u8,
    ) -> c_int {
        let mut key = ESYS_TR_NONE;

        // SAFETY: the caller passes a connection, a seed and room.
        unsafe {
            let t = &*t;
            let e = super::writer_primary(t, arr(seed), None, arr_mut(public), &mut key);

            super::session_flush(t, key);
            e
        }
    }
}
