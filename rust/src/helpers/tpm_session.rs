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
use crate::util::tpm::{Branches, Key, Tpm};
use crate::util::tpm_wire::{RegisterPolicy, register_policy};

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

fn set_errno(e: c_int) {
    // SAFETY: this thread's errno.
    unsafe { *libc::__errno_location() = e };
}

/// The identity map init would have pinned, the test's or its error,
/// faked at the bpf() syscall.
/// The syscall hook of test-tpm-session.
fn fake_bpf(number: c_long, args: [c_long; 6]) -> Option<c_long> {
    let [a0, a1, ..] = args;
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
                        return Some(-1);
                    }
                    fake.fd = libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC);
                    return Some(fake.fd.into());
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
                    return Some(0);
                }
                BPF_MAP_LOOKUP_ELEM
                    if fake.fd >= 0 && at(0).cast::<u32>().read_unaligned() as c_int == fake.fd =>
                {
                    let value = at(16).cast::<u64>().read_unaligned() as *mut Identity;
                    value.write_unaligned(core::ptr::read(&fake.identity));
                    return Some(0);
                }
                _ => {}
            }
        }
    }
    None
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

/// What `$e` gave, or the line it failed at printed and Err(()).
macro_rules! take {
    ($e:expr) => {
        match $e {
            Ok(value) => value,
            Err(_) => {
                err(&format!("line {}: {}\n", line!(), stringify!($e)));
                return Err(());
            }
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
    let tcti = t.tcti_context();
    // SAFETY: the connection's TCTI, whose common part is its first,
    // which the proxy alone changes while it stands before it.
    let c = unsafe { &mut *tcti.cast::<tss::TSS2_TCTI_CONTEXT_COMMON_V1>() };
    let p = proxy();
    p.context = tcti.cast();
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
fn activate(t: &Tpm, ak: &Key<'_>, rsa: bool) -> Result<(), ()> {
    let mut credential = Tpm2bDigest::zeroed();
    credential.size = 32;
    credential.buffer[0] = 7;
    let mut secret: *mut tss::TPM2B_ENCRYPTED_SECRET = core::ptr::null_mut();
    let mut blob: *mut tss::TPM2B_ID_OBJECT = core::ptr::null_mut();
    let ret = (|| {
        let ek = take!(t.ek_create(rsa));
        let mut name = Tpm2bName::zeroed();
        let ak_name = &ak.public().name;
        name.size = ak_name.len() as u16;
        name.name[..ak_name.len()].copy_from_slice(ak_name);
        // SAFETY: the connection's context and session, its EK, the
        // credential and name, and room for what ESYS gives.
        let made = unsafe {
            tss::Esys_MakeCredential(
                t.esys_context(),
                ek.raw(),
                t.hmac_session(),
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &credential,
                &name,
                &mut blob,
                &mut secret,
            )
        };
        check!(made == RC_SUCCESS);
        // SAFETY: what ESYS gave on success.
        let (b, s) = unsafe { (&mut *blob, &*secret) };
        let activate = |b: &tss::TPM2B_ID_OBJECT| {
            let blob = &b.credential[..usize::from(b.size)];
            t.activate_credential(ak, &ek, blob, &s.secret[..usize::from(s.size)])
        };
        let recovered = take!(activate(b));
        check!(
            recovered.len() == usize::from(credential.size)
                && !memneq_explicit(&recovered, &credential.buffer[..recovered.len()])
        );
        b.credential[usize::from(b.size) - 1] ^= 1;
        check!(activate(b).err() == Some(-EKEYREJECTED));
        Ok(())
    })();
    // SAFETY: what ESYS gave, scrubbed and freed once.
    unsafe {
        if let Some(s) = secret.as_mut() {
            core::ptr::write_bytes(s, 0, 1);
        }
        Esys_Free(secret.cast());
        Esys_Free(blob.cast());
    }
    ret
}

/// TSS2_LOG asks for traces into stdout; the client must silence its log
/// and forget where it went before it talks to the TPM.
fn open_silenced() -> Result<Tpm, ()> {
    // SAFETY: the environment, which only this thread touches.
    unsafe {
        std::env::set_var("TSS2_LOG", "all+TRACE");
        std::env::set_var("TSS2_LOGFILE", "stdout");
    }
    let t = take!(Tpm::open());
    check!(std::env::var_os("TSS2_LOG").is_some_and(|v| v == "all+none"));
    check!(std::env::var_os("TSS2_LOGFILE").is_none());
    Ok(t)
}

/// What the setup leaves the case: the register's policy branches, the
/// event it extends with, and the register's value after.
struct Keys {
    branch_written: [u8; 32],
    branch_init: [u8; 32],
    event: [u8; 32],
    before: [u8; 32],
}

impl Keys {
    fn branches(&self) -> Branches<'_> {
        Branches {
            written: &self.branch_written,
            init: &self.branch_init,
        }
    }
}

fn setup(t: &mut Option<Tpm>, keys: &mut Keys, defined: &mut bool) -> Result<(), ()> {
    let mut values = [0u8; 64];
    let mut policy = [0u8; 32];
    let mut seed = [0u8; 32];
    seed[0] = 1;

    let first = open_silenced()?;
    // SAFETY: the fake, on this thread.
    let fake = unsafe { FAKE.get() };
    fake.identity.ek_name = *first.ek_name();
    check!(fake.identity.ek_name[1] == ALG_SHA256);
    drop(first);
    ENFORCING.store(1, Ordering::Relaxed);
    let t = t.insert(open_silenced()?);
    take!(t.boot_identity());
    values[..32].copy_from_slice(&take!(t.pcr_read(9)));
    values[32..].copy_from_slice(&take!(t.pcr_read(11)));
    let ak = take!(t.ak_create());
    take!(t.quote(&ak, &keys.event, 1 << 9));
    activate(t, &ak, false)?;
    activate(t, &ak, true)?;
    drop(ak);
    let public = take!(t.writer_create(&seed));
    take!(t.set_writer(&seed, &public));
    let digests = RegisterPolicy {
        branch_written: &mut keys.branch_written,
        branch_init: &mut keys.branch_init,
        policy: &mut policy,
    };
    check!(register_policy(PCR_MASK, &values, &public, digests) == 0);
    check!(t.nv_info(TEST_INDEX).is_ok_and(|info| !info.defined));
    take!(t.nv_define(TEST_INDEX, &policy, &[]));
    *defined = true;
    take!(t.nv_extend_first(TEST_INDEX, PCR_MASK, &keys.branches(), &keys.event));
    keys.before = take!(t.nv_read(TEST_INDEX));
    let ak = take!(t.ak_create());
    take!(t.nv_certify(&ak, TEST_INDEX, &keys.event));
    drop(ak);
    out("authenticated TPM reads, writes, quote and certification succeeded\n");
    Ok(())
}

/// The case `how` on the connection `t`, which it may reopen.
fn case(how: &[u8], t: &mut Option<Tpm>, keys: &Keys) -> Result<(), ()> {
    let (mut before, branches, ev) = (keys.before, keys.branches(), &keys.event);
    let Some(tr) = t.as_mut() else {
        return Err(());
    };
    match how {
        b"nv-extend" | b"nv-replay" | b"unsalted-control" => {
            let unsalted = how == b"unsalted-control";
            let salting_key = if unsalted {
                tr.replace_salt_key(ESYS_TR_NONE)
            } else {
                ESYS_TR_NONE
            };
            intercept(tr, CC_NV_EXTEND, Mode::Capture);
            check!(tr.nv_extend(TEST_INDEX, &branches, ev).is_ok());
            check!(hit());
            restore();
            before = take!(tr.nv_read(TEST_INDEX));
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
                check!(tr.nv_extend(TEST_INDEX, &branches, ev).is_ok());
            } else {
                check!(tr.nv_extend(TEST_INDEX, &branches, ev).is_err());
            }
            check!(hit());
            restore();
            if unsalted {
                tr.replace_salt_key(salting_key);
            }
            let tr = reopen(t)?;
            check!(tr.nv_read(TEST_INDEX) == Ok(before));
            out(if unsalted {
                "negative control: unsalted session accepted suppressed NV_Extend\n"
            } else {
                "suppressed NV_Extend with forged or replayed success rejected; register unchanged\n"
            });
        }
        b"pcr-extend" => {
            intercept(tr, CC_PCR_EXTEND, Mode::Capture);
            check!(tr.pcr_extend(23, ev).is_ok() && hit());
            restore();
            before = take!(tr.pcr_read(23));
            intercept(tr, CC_PCR_EXTEND, Mode::Replay);
            check!(tr.pcr_extend(23, ev).is_err() && hit());
            restore();
            let tr = reopen(t)?;
            check!(tr.pcr_read(23) == Ok(before));
            out("suppressed PCR_Extend with replayed success rejected; PCR unchanged\n");
        }
        b"nv-read" | b"pcr-read" | b"clock" | b"policy-digest" => {
            match how {
                b"policy-digest" => {
                    intercept(tr, CC_POLICY_GET_DIGEST, Mode::CorruptHmac);
                    check!(tr.nv_extend(TEST_INDEX, &branches, ev).is_err() && hit());
                }
                b"nv-read" => {
                    intercept(tr, CC_NV_READ, Mode::Corrupt);
                    check!(tr.nv_read(TEST_INDEX).is_err() && hit());
                }
                b"pcr-read" => {
                    intercept(tr, CC_PCR_READ, Mode::Corrupt);
                    check!(tr.pcr_read(9).is_err() && hit());
                }
                _ => {
                    intercept(tr, CC_READ_CLOCK, Mode::Corrupt);
                    check!(tr.boot_identity().is_err() && hit());
                }
            }
            restore();
            let tr = reopen(t)?;
            check!(tr.nv_read(TEST_INDEX) == Ok(before));
            out("forged readback rejected; live register unchanged\n");
        }
        _ => {
            check!(how == b"identity");
            *t = None;
            // SAFETY: the fake, on this thread.
            let fake = unsafe { FAKE.get() };
            fake.identity.ek_name[2] ^= 1;
            check!(Tpm::open().err() == Some(-EACCES));
            fake.identity.ek_name[2] ^= 1;
            fake.identity.ek_name[1] = 0;
            check!(Tpm::open().err() == Some(-EACCES));
            fake.identity.ek_name[1] = ALG_SHA256;
            fake.error = -ENOENT;
            check!(Tpm::open().err() == Some(-ENOENT));
            fake.error = 0;
            ENFORCING.store(-EIO, Ordering::Relaxed);
            check!(Tpm::open().err() == Some(-EIO));
            ENFORCING.store(1, Ordering::Relaxed);
            out("wrong, missing and unreadable session-key pins refused without fallback\n");
        }
    }
    Ok(())
}

/// The connection closed and opened again.
fn reopen(t: &mut Option<Tpm>) -> Result<&Tpm, ()> {
    *t = None;
    Ok(t.insert(take!(Tpm::open())))
}

fn run(args: &[&CStr]) -> c_int {
    let mut t: Option<Tpm> = None;
    let mut keys = Keys {
        branch_written: [0; 32],
        branch_init: [0; 32],
        event: [0; 32],
        before: [0; 32],
    };
    keys.event[0] = 2;
    let mut defined = false;
    super::set_syscall_hook(fake_bpf);
    let result = (|| {
        check!(args.len() == 2);
        forge_reply_cases()?;
        setup(&mut t, &mut keys, &mut defined)?;
        case(args[1].to_bytes(), &mut t, &keys)
    })();
    let mut ret = c_int::from(result.is_err());
    restore();
    drop(t);
    ENFORCING.store(1, Ordering::Relaxed);
    // SAFETY: the fake, on this thread.
    let fake = unsafe { FAKE.get() };
    fake.error = 0;
    fake.identity.ek_name[1] = ALG_SHA256;
    if defined
        && Tpm::open()
            .and_then(|t| t.nv_undefine(TEST_INDEX, &[]))
            .is_err()
    {
        ret = 1;
    }
    ret
}
