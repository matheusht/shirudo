// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-tpm-session: the TPM client's sessions against an attacker on
//! the TPM's transport. Authenticated reads, writes, a quote and a
//! certification succeed; then, by the case named, a suppressed
//! NV_Extend or PCR_Extend answered with a forged or replayed success, a
//! corrupted readback, or a wrong, missing or unreadable session-key
//! pin, must be refused and leave the TPM as it was.
//!
//!   test-tpm-session nv-extend|nv-replay|unsalted-control|pcr-extend|nv-read|pcr-read|clock|policy-digest|identity
//!
//! make links it with --wrap=prctl, which tpm_client answers, and
//! --wrap=syscall, through which the identity map init would have pinned
//! is faked at bpf(2).

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_int, c_long};
use core::sync::atomic::Ordering;

use tss_esapi_sys as tss;

use super::tpm_client::ENFORCING;
use super::{err, helper_main, out};
use crate::errno::{EACCES, EIO, EKEYREJECTED, ENOENT};
use crate::sys::identity::Identity;
use crate::sys::tss2::{ESYS_TR_NONE, Esys_Free, RC_SUCCESS, Rc, Tpm2bDigest, Tpm2bName, Zeroed};
use crate::util::chain::{PCR_MASK, memneq_explicit};
use crate::util::crypto_openssl::{hmac_sha256, sha256};
use crate::util::identity::IDENTITY_PIN;
use crate::util::tpm::{
    Tpm, TpmAttestation, TpmKey, TpmNvInfo, tpm_activate_credential, tpm_ak_create,
    tpm_boot_identity, tpm_close, tpm_ek_create, tpm_ek_name, tpm_key_flush, tpm_nv_certify,
    tpm_nv_define, tpm_nv_extend, tpm_nv_extend_first, tpm_nv_info, tpm_nv_read, tpm_nv_set_writer,
    tpm_nv_undefine, tpm_open, tpm_pcr_extend, tpm_pcr_read, tpm_quote, tpm_writer_create,
};
use crate::util::tpm_wire::{NV_RSA_BYTES, tpm_register_policy};

helper_main!(shirudo_helper_test_tpm_session, run);

const TEST_INDEX: u32 = 0x0181_8E02;

/// TPM2_CC of the commands a case intercepts, TPM2_ST_SESSIONS and
/// TPM2_ALG_SHA256.
const CC_NV_EXTEND: u32 = 0x136;
const CC_NV_READ: u32 = 0x14e;
const CC_PCR_READ: u32 = 0x17e;
const CC_READ_CLOCK: u32 = 0x181;
const CC_PCR_EXTEND: u32 = 0x182;
const CC_POLICY_GET_DIGEST: u32 = 0x189;
const ST_SESSIONS: u16 = 0x8002;
const ALG_SHA256: u8 = 0x0b;

/// TSS2_TCTI_RC_GENERAL_FAILURE, _INSUFFICIENT_BUFFER and _BAD_VALUE.
const TCTI_GENERAL_FAILURE: Rc = 0xa_0001;
const TCTI_INSUFFICIENT_BUFFER: Rc = 0xa_0006;
const TCTI_BAD_VALUE: Rc = 0xa_000b;

/// bpf(2)'s commands and the offsets in its attribute and in struct
/// bpf_map_info that the fake reads and writes.
const BPF_MAP_LOOKUP_ELEM: c_long = 1;
const BPF_OBJ_GET: c_long = 7;
const BPF_OBJ_GET_INFO_BY_FD: c_long = 15;

/// What this single-threaded helper keeps for its fakes, which the
/// wraps and the TCTI's callbacks reach on the main thread alone.
struct Global<T>(UnsafeCell<T>);

// SAFETY: one thread touches it, the helper's own.
unsafe impl<T> Sync for Global<T> {}

impl<T> Global<T> {
    /// # Safety
    ///
    /// No other reference to it is live.
    #[allow(clippy::mut_from_ref)]
    unsafe fn get(&self) -> &mut T {
        // SAFETY: the caller's.
        unsafe { &mut *self.0.get() }
    }
}

/// The identity map's fake: its value, the error a lookup gets, or the
/// fd it is open as.
struct FakeIdentity {
    identity: Identity,
    error: c_int,
    fd: c_int,
}

static FAKE: Global<FakeIdentity> = Global(UnsafeCell::new(FakeIdentity {
    identity: Identity::zeroed(),
    error: 0,
    fd: -1,
}));

unsafe extern "C" {
    fn __real_syscall(number: c_long, ...) -> c_long;
}

fn set_errno(e: c_int) {
    // SAFETY: this thread's errno.
    unsafe { *libc::__errno_location() = e };
}

/// The identity map init would have pinned, the test's or its error,
/// faked at the bpf() syscall.
///
/// # Safety
///
/// As syscall(2) with these arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_syscall(
    number: c_long,
    a0: c_long,
    a1: c_long,
    a2: c_long,
    a3: c_long,
    a4: c_long,
    a5: c_long,
) -> c_long {
    if number == libc::SYS_bpf {
        let attr = a1 as *mut u8;
        // SAFETY: the fake, on this thread, and the caller's attribute of
        // the command, read and written at its fields' offsets.
        unsafe {
            let fake = FAKE.get();
            let at = |off: usize| attr.add(off);
            match a0 {
                BPF_OBJ_GET
                    if CStr::from_ptr(at(0).cast::<u64>().read_unaligned() as *const _)
                        == IDENTITY_PIN =>
                {
                    if fake.error != 0 {
                        set_errno(-fake.error);
                        return -1;
                    }
                    fake.fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                    return fake.fd.into();
                }
                BPF_OBJ_GET_INFO_BY_FD
                    if fake.fd >= 0 && at(0).cast::<u32>().read_unaligned() as c_int == fake.fd =>
                {
                    let len = at(4).cast::<u32>().read_unaligned() as usize;
                    let info = at(8).cast::<u64>().read_unaligned() as *mut u8;
                    info.write_bytes(0, len);
                    info.add(8)
                        .cast::<u32>()
                        .write_unaligned(size_of::<u32>() as u32);
                    info.add(12)
                        .cast::<u32>()
                        .write_unaligned(size_of::<Identity>() as u32);
                    info.add(16).cast::<u32>().write_unaligned(1);
                    return 0;
                }
                BPF_MAP_LOOKUP_ELEM
                    if fake.fd >= 0 && at(0).cast::<u32>().read_unaligned() as c_int == fake.fd =>
                {
                    let value = at(16).cast::<u64>().read_unaligned() as *mut Identity;
                    value.write_unaligned(core::ptr::read(&fake.identity));
                    return 0;
                }
                _ => {}
            }
        }
    }
    // SAFETY: the caller's call, made.
    unsafe { __real_syscall(number, a0, a1, a2, a3, a4, a5) }
}

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Capture,
    Replay,
    Forge,
    Corrupt,
    CorruptHmac,
}

/// The TCTI's own transmit and receive, which the proxy stands before,
/// and what it captured.
struct Proxy {
    transmit: tss::TSS2_TCTI_TRANSMIT_FCN,
    receive: tss::TSS2_TCTI_RECEIVE_FCN,
    context: *mut tss::TSS2_TCTI_CONTEXT,
    response: [u8; 4096],
    response_len: usize,
    mode: Mode,
    command: u32,
    selected: bool,
    hit: bool,
}

const PROXY_NONE: Proxy = Proxy {
    transmit: None,
    receive: None,
    context: core::ptr::null_mut(),
    response: [0; 4096],
    response_len: 0,
    mode: Mode::Capture,
    command: 0,
    selected: false,
    hit: false,
};

static PROXY: Global<Proxy> = Global(UnsafeCell::new(PROXY_NONE));

fn proxy() -> &'static mut Proxy {
    // SAFETY: the proxy, on this thread, one reference at a time.
    unsafe { PROXY.get() }
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

/// NV_Extend's reply forged as a success: it has no parameters, and an
/// unsalted policy session may omit the response HMAC, which older
/// libtpms versions still emit and which is then computed with the
/// empty key.
fn forge_success(command: &[u8]) -> Rc {
    let p = proxy();
    if command.len() < 62
        || be16(command, 26) != 32
        || p.response_len < 51
        || be16(&p.response, 14) != 32
    {
        return TCTI_BAD_VALUE;
    }
    let hmac_len = usize::from(be16(&p.response, 49));
    if (hmac_len != 0 && hmac_len != 32) || p.response_len != 51 + hmac_len {
        return TCTI_BAD_VALUE;
    }
    if hmac_len == 0 {
        return RC_SUCCESS;
    }
    let mut header = [0u8; 8];
    header[..4].copy_from_slice(&p.response[6..10]);
    header[4..].copy_from_slice(&command[6..10]);
    let Ok(rp_hash) = sha256(&header) else {
        return TCTI_GENERAL_FAILURE;
    };
    let mut input = [0u8; 97];
    input[..32].copy_from_slice(&rp_hash);
    input[32..64].copy_from_slice(&p.response[16..48]);
    input[64..96].copy_from_slice(&command[28..60]);
    input[96] = p.response[48];
    let empty = 0u8;
    // SAFETY: an empty key, the input and the HMAC's room in the reply.
    if unsafe {
        hmac_sha256(
            &empty,
            0,
            input.as_ptr().cast(),
            input.len(),
            p.response.as_mut_ptr().add(51),
        )
    } != 0
    {
        return TCTI_GENERAL_FAILURE;
    }
    RC_SUCCESS
}

macro_rules! check {
    ($e:expr) => {
        if !$e {
            err(&format!("line {}: {}\n", line!(), stringify!($e)));
            return Err(());
        }
    };
}

fn forge_reply_cases() -> Result<(), ()> {
    let ret = (|| {
        let mut command = [0u8; 97];
        command[26..28].copy_from_slice(&32u16.to_be_bytes());
        let p = proxy();
        p.response[14..16].copy_from_slice(&32u16.to_be_bytes());
        p.response_len = 51;
        check!(forge_success(&command) == RC_SUCCESS);
        proxy().response_len = 83;
        check!(forge_success(&command) == TCTI_BAD_VALUE);
        proxy().response[49..51].copy_from_slice(&32u16.to_be_bytes());
        check!(forge_success(&command) == RC_SUCCESS);
        proxy().response_len -= 1;
        check!(forge_success(&command) == TCTI_BAD_VALUE);
        proxy().response[49..51].copy_from_slice(&31u16.to_be_bytes());
        check!(forge_success(&command) == TCTI_BAD_VALUE);
        Ok(())
    })();
    *proxy() = PROXY_NONE;
    ret
}

/// # Safety
///
/// `context` is the TCTI the proxy stands before, `command` `size`
/// bytes.
unsafe extern "C" fn transmit(
    context: *mut tss::TSS2_TCTI_CONTEXT,
    size: u64,
    command: *const u8,
) -> Rc {
    if size < 10 {
        return TCTI_BAD_VALUE;
    }
    // SAFETY: the caller's command.
    let cmd = unsafe { core::slice::from_raw_parts(command, size as usize) };
    let p = proxy();
    p.selected = u32::from_be_bytes([cmd[6], cmd[7], cmd[8], cmd[9]]) == p.command;
    if p.selected && p.mode == Mode::Forge {
        return forge_success(cmd);
    }
    if p.selected && p.mode == Mode::Replay {
        return RC_SUCCESS;
    }
    match p.transmit {
        // SAFETY: the TCTI's own transmit, with the caller's arguments.
        Some(f) => unsafe { f(context, size, command) },
        None => TCTI_GENERAL_FAILURE,
    }
}

/// # Safety
///
/// `context` is the TCTI the proxy stands before, `size` room for the
/// reply's size and `response` NULL or `*size` bytes of room.
unsafe extern "C" fn receive(
    context: *mut tss::TSS2_TCTI_CONTEXT,
    size: *mut u64,
    response: *mut u8,
    timeout: i32,
) -> Rc {
    let p = proxy();
    // SAFETY: the caller's size, the reply's room and the TCTI's own
    // receive.
    unsafe {
        if p.selected && matches!(p.mode, Mode::Replay | Mode::Forge) {
            if p.response_len == 0 {
                return TCTI_BAD_VALUE;
            }
            if !response.is_null() {
                if (*size as usize) < p.response_len {
                    return TCTI_INSUFFICIENT_BUFFER;
                }
                core::ptr::copy_nonoverlapping(p.response.as_ptr(), response, p.response_len);
                p.hit = true;
            }
            *size = p.response_len as u64;
            return RC_SUCCESS;
        }
        let Some(f) = p.receive else {
            return TCTI_GENERAL_FAILURE;
        };
        let ret = f(context, size, response, timeout);
        if ret != RC_SUCCESS || response.is_null() || !p.selected {
            return ret;
        }
        if *size < 17 || *size as usize > p.response.len() {
            return TCTI_BAD_VALUE;
        }
        p.hit = true;
        let reply = core::slice::from_raw_parts_mut(response, *size as usize);
        match p.mode {
            Mode::Capture => {
                p.response[..reply.len()].copy_from_slice(reply);
                p.response_len = reply.len();
            }
            Mode::CorruptHmac => {
                if be16(reply, 0) == ST_SESSIONS {
                    reply[reply.len() - 1] ^= 1;
                }
            }
            _ => reply[16] ^= 1,
        }
    }
    RC_SUCCESS
}

/// The proxy put before the TCTI of `t` for `command`.
fn intercept(t: &Tpm, command: u32, mode: Mode) {
    // SAFETY: the connection's TCTI, whose common part is its first,
    // which the proxy alone changes while it stands before it.
    let c = unsafe { &mut *t.tcti.cast::<tss::TSS2_TCTI_CONTEXT_COMMON_V1>() };
    let p = proxy();
    p.context = t.tcti.cast();
    p.transmit = c.transmit;
    p.receive = c.receive;
    p.command = command;
    p.mode = mode;
    p.selected = false;
    p.hit = false;
    c.transmit = Some(transmit);
    c.receive = Some(receive);
}

fn restore() {
    let p = proxy();
    if p.context.is_null() {
        return;
    }
    // SAFETY: the TCTI intercept() stood before, still open.
    let c = unsafe { &mut *p.context.cast::<tss::TSS2_TCTI_CONTEXT_COMMON_V1>() };
    c.transmit = p.transmit;
    c.receive = p.receive;
    p.context = core::ptr::null_mut();
}

fn hit() -> bool {
    proxy().hit
}

/// A credential made for `ak` under an EK of the kind asked for comes
/// back through ActivateCredential, and a blob altered by a bit does not.
fn activate(t: *mut Tpm, ak: &TpmKey, rsa: bool) -> Result<(), ()> {
    let mut credential = Tpm2bDigest::zeroed();
    credential.size = 32;
    credential.buffer[0] = 7;
    let mut secret: *mut tss::TPM2B_ENCRYPTED_SECRET = core::ptr::null_mut();
    let mut blob: *mut tss::TPM2B_ID_OBJECT = core::ptr::null_mut();
    let mut ek = TpmKey::zeroed();
    let mut recovered = [0u8; 32];
    // SAFETY: the connection, its keys, and what ESYS gives, freed once.
    let ret = unsafe {
        (|| {
            check!(tpm_ek_create(t, rsa, &mut ek) == 0);
            let mut name = Tpm2bName::zeroed();
            name.size = ak.name_len as u16;
            name.name[..ak.name_len].copy_from_slice(&ak.name[..ak.name_len]);
            let tr = &*t;
            check!(
                tss::Esys_MakeCredential(
                    tr.esys,
                    ek.handle,
                    tr.session,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    &credential,
                    &name,
                    &mut blob,
                    &mut secret
                ) == RC_SUCCESS
            );
            let (b, s) = (&mut *blob, &*secret);
            let mut length = 0usize;
            let activate =
                |b: &tss::TPM2B_ID_OBJECT, recovered: &mut [u8; 32], length: &mut usize| {
                    tpm_activate_credential(
                        t,
                        ak,
                        &ek,
                        b.credential.as_ptr(),
                        b.size.into(),
                        s.secret.as_ptr(),
                        s.size.into(),
                        recovered.as_mut_ptr(),
                        recovered.len(),
                        length,
                    )
                };
            check!(activate(b, &mut recovered, &mut length) == 0);
            check!(
                length == usize::from(credential.size)
                    && !memneq_explicit(&recovered[..length], &credential.buffer[..length])
            );
            b.credential[usize::from(b.size) - 1] ^= 1;
            check!(activate(b, &mut recovered, &mut length) == -EKEYREJECTED);
            Ok(())
        })()
    };
    recovered.fill(0);
    // SAFETY: what ESYS gave, scrubbed and freed once, and the EK flushed.
    unsafe {
        if let Some(s) = secret.as_mut() {
            core::ptr::write_bytes(s, 0, 1);
        }
        Esys_Free(secret.cast());
        Esys_Free(blob.cast());
        tpm_key_flush(t, &mut ek);
    }
    ret
}

/// TSS2_LOG asks for traces into stdout; the client must silence its log
/// and forget where it went before it talks to the TPM.
fn open_silenced(t: &mut *mut Tpm) -> Result<(), ()> {
    // SAFETY: the environment, which only this thread touches.
    unsafe {
        std::env::set_var("TSS2_LOG", "all+TRACE");
        std::env::set_var("TSS2_LOGFILE", "stdout");
    }
    // SAFETY: room for the connection.
    check!(unsafe { tpm_open(t) } == 0);
    check!(std::env::var_os("TSS2_LOG").is_some_and(|v| v == "all+none"));
    check!(std::env::var_os("TSS2_LOGFILE").is_none());
    Ok(())
}

/// What the setup leaves the case: the register's policy branches, the
/// event it extends with, and the register's value after.
struct Keys {
    branch_written: [u8; 32],
    branch_init: [u8; 32],
    event: [u8; 32],
    before: [u8; 32],
}

fn setup(t: &mut *mut Tpm, ak: &mut TpmKey, keys: &mut Keys, defined: &mut bool) -> Result<(), ()> {
    let mut values = [0u8; 64];
    let mut public = [0u8; NV_RSA_BYTES];
    let mut policy = [0u8; 32];
    let mut seed = [0u8; 32];
    seed[0] = 1;
    let (mut reset, mut restart) = (0u32, 0u32);
    let mut attestation = TpmAttestation::zeroed();
    // SAFETY: a structure of numbers, for which zeros are a value.
    let mut info: TpmNvInfo = unsafe { core::mem::zeroed() };

    open_silenced(t)?;
    // SAFETY: the fake, on this thread, and the connection.
    unsafe {
        let fake = FAKE.get();
        tpm_ek_name(*t, fake.identity.ek_name.as_mut_ptr());
        check!(fake.identity.ek_name[1] == ALG_SHA256);
        tpm_close(*t);
    }
    *t = core::ptr::null_mut();
    ENFORCING.store(1, Ordering::Relaxed);
    open_silenced(t)?;
    let t = *t;
    // SAFETY: the connection, its keys and rooms, all of this helper.
    unsafe {
        check!(tpm_boot_identity(t, &mut reset, &mut restart) == 0);
        check!(tpm_pcr_read(t, 9, values.as_mut_ptr()) == 0);
        check!(tpm_pcr_read(t, 11, values.as_mut_ptr().add(32)) == 0);
        check!(tpm_ak_create(t, ak) == 0);
        check!(tpm_quote(t, ak, keys.event.as_ptr(), 32, 1 << 9, &mut attestation) == 0);
        activate(t, ak, false)?;
        activate(t, ak, true)?;
        tpm_key_flush(t, ak);
        check!(tpm_writer_create(t, seed.as_ptr(), public.as_mut_ptr()) == 0);
        check!(tpm_nv_set_writer(t, seed.as_ptr(), public.as_ptr()) == 0);
        check!(
            tpm_register_policy(
                PCR_MASK,
                values.as_ptr(),
                2,
                public.as_ptr(),
                keys.branch_written.as_mut_ptr(),
                keys.branch_init.as_mut_ptr(),
                policy.as_mut_ptr()
            ) == 0
        );
        check!(tpm_nv_info(t, TEST_INDEX, &mut info) == 0 && !info.defined);
        check!(tpm_nv_define(t, TEST_INDEX, policy.as_ptr(), core::ptr::null(), 0) == 0);
        *defined = true;
        check!(
            tpm_nv_extend_first(
                t,
                TEST_INDEX,
                PCR_MASK,
                keys.branch_written.as_ptr(),
                keys.branch_init.as_ptr(),
                keys.event.as_ptr()
            ) == 0
        );
        check!(tpm_nv_read(t, TEST_INDEX, keys.before.as_mut_ptr()) == 0);
        check!(tpm_ak_create(t, ak) == 0);
        check!(tpm_nv_certify(t, ak, TEST_INDEX, keys.event.as_ptr(), 32, &mut attestation) == 0);
        tpm_key_flush(t, ak);
    }
    out("authenticated TPM reads, writes, quote and certification succeeded\n");
    Ok(())
}

/// The case `how` on the connection at `*t`, which it may reopen.
fn case(how: &[u8], t: &mut *mut Tpm, keys: &Keys) -> Result<(), ()> {
    let (mut before, mut after) = (keys.before, [0u8; 32]);
    let (bw, bi, ev) = (
        keys.branch_written.as_ptr(),
        keys.branch_init.as_ptr(),
        keys.event.as_ptr(),
    );
    // SAFETY: the connection, open, and rooms of this helper; reopened
    // where a case closes it.
    unsafe {
        let tr = &mut **t;
        match how {
            b"nv-extend" | b"nv-replay" | b"unsalted-control" => {
                let unsalted = how == b"unsalted-control";
                let salting_key = tr.session_key.handle;
                if unsalted {
                    tr.session_key.handle = ESYS_TR_NONE;
                }
                intercept(tr, CC_NV_EXTEND, Mode::Capture);
                check!(tpm_nv_extend(*t, TEST_INDEX, bw, bi, ev) == 0);
                check!(hit());
                restore();
                check!(tpm_nv_read(*t, TEST_INDEX, before.as_mut_ptr()) == 0);
                intercept(
                    tr,
                    CC_NV_EXTEND,
                    if how == b"nv-replay" {
                        Mode::Replay
                    } else {
                        Mode::Forge
                    },
                );
                if unsalted {
                    check!(tpm_nv_extend(*t, TEST_INDEX, bw, bi, ev) == 0);
                } else {
                    check!(tpm_nv_extend(*t, TEST_INDEX, bw, bi, ev) < 0);
                }
                check!(hit());
                restore();
                tr.session_key.handle = salting_key;
                reopen(t)?;
                check!(tpm_nv_read(*t, TEST_INDEX, after.as_mut_ptr()) == 0 && before == after);
                out(if unsalted {
                    "negative control: unsalted session accepted suppressed NV_Extend\n"
                } else {
                    "suppressed NV_Extend with forged or replayed success rejected; register unchanged\n"
                });
            }
            b"pcr-extend" => {
                intercept(tr, CC_PCR_EXTEND, Mode::Capture);
                check!(tpm_pcr_extend(*t, 23, ev) == 0 && hit());
                restore();
                check!(tpm_pcr_read(*t, 23, before.as_mut_ptr()) == 0);
                intercept(tr, CC_PCR_EXTEND, Mode::Replay);
                check!(tpm_pcr_extend(*t, 23, ev) < 0 && hit());
                restore();
                reopen(t)?;
                check!(tpm_pcr_read(*t, 23, after.as_mut_ptr()) == 0 && before == after);
                out("suppressed PCR_Extend with replayed success rejected; PCR unchanged\n");
            }
            b"nv-read" | b"pcr-read" | b"clock" | b"policy-digest" => {
                let (mut reset, mut restart) = (0u32, 0u32);
                match how {
                    b"policy-digest" => {
                        intercept(tr, CC_POLICY_GET_DIGEST, Mode::CorruptHmac);
                        check!(tpm_nv_extend(*t, TEST_INDEX, bw, bi, ev) < 0 && hit());
                    }
                    b"nv-read" => {
                        intercept(tr, CC_NV_READ, Mode::Corrupt);
                        check!(tpm_nv_read(*t, TEST_INDEX, after.as_mut_ptr()) < 0 && hit());
                    }
                    b"pcr-read" => {
                        intercept(tr, CC_PCR_READ, Mode::Corrupt);
                        check!(tpm_pcr_read(*t, 9, after.as_mut_ptr()) < 0 && hit());
                    }
                    _ => {
                        intercept(tr, CC_READ_CLOCK, Mode::Corrupt);
                        check!(tpm_boot_identity(*t, &mut reset, &mut restart) < 0 && hit());
                    }
                }
                restore();
                reopen(t)?;
                check!(tpm_nv_read(*t, TEST_INDEX, after.as_mut_ptr()) == 0 && before == after);
                out("forged readback rejected; live register unchanged\n");
            }
            _ => {
                check!(how == b"identity");
                tpm_close(*t);
                *t = core::ptr::null_mut();
                let fake = FAKE.get();
                let mut other: *mut Tpm = core::ptr::null_mut();
                fake.identity.ek_name[2] ^= 1;
                check!(tpm_open(&mut other) == -EACCES && other.is_null());
                fake.identity.ek_name[2] ^= 1;
                fake.identity.ek_name[1] = 0;
                check!(tpm_open(&mut other) == -EACCES && other.is_null());
                fake.identity.ek_name[1] = ALG_SHA256;
                fake.error = -ENOENT;
                check!(tpm_open(&mut other) == -ENOENT && other.is_null());
                fake.error = 0;
                ENFORCING.store(-EIO, Ordering::Relaxed);
                check!(tpm_open(&mut other) == -EIO && other.is_null());
                ENFORCING.store(1, Ordering::Relaxed);
                out("wrong, missing and unreadable session-key pins refused without fallback\n");
            }
        }
    }
    Ok(())
}

/// The connection closed and opened again.
fn reopen(t: &mut *mut Tpm) -> Result<(), ()> {
    // SAFETY: the connection, closed once, and room for the next.
    unsafe {
        tpm_close(*t);
        *t = core::ptr::null_mut();
        check!(tpm_open(t) == 0);
    }
    Ok(())
}

fn run(args: &[&CStr]) -> c_int {
    let mut t: *mut Tpm = core::ptr::null_mut();
    let mut ak = TpmKey::zeroed();
    let mut keys = Keys {
        branch_written: [0; 32],
        branch_init: [0; 32],
        event: [0; 32],
        before: [0; 32],
    };
    keys.event[0] = 2;
    let mut defined = false;
    let result = (|| {
        check!(args.len() == 2);
        forge_reply_cases()?;
        setup(&mut t, &mut ak, &mut keys, &mut defined)?;
        case(args[1].to_bytes(), &mut t, &keys)
    })();
    let mut ret = c_int::from(result.is_err());
    restore();
    // SAFETY: the connection or NULL, its AK, flushed and closed once; a
    // connection of its own to remove the scratch index.
    unsafe {
        tpm_key_flush(t, &mut ak);
        tpm_close(t);
        ENFORCING.store(1, Ordering::Relaxed);
        let fake = FAKE.get();
        fake.error = 0;
        fake.identity.ek_name[1] = ALG_SHA256;
        if defined {
            let mut t: *mut Tpm = core::ptr::null_mut();
            if tpm_open(&mut t) != 0 || tpm_nv_undefine(t, TEST_INDEX, core::ptr::null(), 0) != 0 {
                ret = 1;
            }
            tpm_close(t);
        }
    }
    ret
}
