// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-nv-cphash: the NV writer's PolicySigned authorization of one
//! NV_Extend, on a scratch index: the authorized event extends, another
//! event under the same authorization fails the policy, a replayed or
//! corrupted signature is refused, and the value moves only as
//! SHA256(before || event).

use core::ffi::{CStr, c_int};

use super::{err, helper_main, out, perror};
use crate::sys::tss2::{
    ALG_RSASSA, ALG_SHA256, CC_NV_EXTEND, ESYS_TR_NONE, ESYS_TR_PASSWORD, Esys_FlushContext,
    Esys_Free, Esys_NV_Extend, Esys_NV_Read, Esys_Sign, Esys_TR_Close, Esys_TR_FromTPMPublic,
    Esys_TR_GetName, Esys_TRSess_SetAttributes, EsysContext, EsysTr, RC_POLICY_FAIL, RC_SUCCESS,
    RH_NULL, Rc, SE_POLICY, SESSION_CONTINUESESSION, ST_HASHCHECK, Signature, TkHashcheck,
    Tpm2bDigest, Tpm2bMaxNvBuffer, Tpm2bName, Zeroed, sig_scheme,
};
use crate::util::crypto_openssl::sha256;
use crate::util::tpm::{
    Tpm, WriterAuthorization, nv_define, nv_undefine, policy_session_finish, session_start,
    tpm_close, tpm_open, tpm_writer_create, writer_authorize, writer_prepare, writer_primary,
};
use crate::util::tpm_wire::{NAME_LEN, NV_RSA_BYTES, policy_command_code, policy_signed};

helper_main!(shirudo_helper_test_nv_cphash, run);

const TEST_NV_INDEX: u32 = 0x0181_8E01;
/// TPM2_RC_SIGNATURE | TPM2_RC_P | TPM2_RC_5: PolicySigned's signature,
/// its fifth parameter, bad.
const RC_BAD_SIGNATURE: Rc = 0x09b | 0x040 | 0x500;
/// TPM2_RC_POLICY_FAIL | TPM2_RC_S | TPM2_RC_1: the first session's
/// policy not met.
const RC_SESSION_POLICY_FAIL: Rc = RC_POLICY_FAIL | 0x800 | 0x100;

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    Valid,
    Replay,
    Corrupt,
}

type Step = Result<(), ()>;

fn tpm_ok(ret: Rc, operation: &str) -> Step {
    if ret == RC_SUCCESS {
        return Ok(());
    }
    err(&format!("{operation}: rc=0x{ret:08x}\n"));
    Err(())
}

fn flush(esys: *mut EsysContext, session: &mut EsysTr) -> Step {
    let handle = core::mem::replace(session, ESYS_TR_NONE);
    if handle == ESYS_TR_NONE {
        return Ok(());
    }
    // SAFETY: the context and a session of it.
    tpm_ok(unsafe { Esys_FlushContext(esys, handle) }, "FlushContext")
}

fn read_value(esys: *mut EsysContext, nv: EsysTr) -> Result<[u8; 32], ()> {
    let mut data: *mut Tpm2bMaxNvBuffer = core::ptr::null_mut();
    // SAFETY: the context, the index and room for its data, freed once.
    unsafe {
        let ret = tpm_ok(
            Esys_NV_Read(
                esys,
                nv,
                nv,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                32,
                0,
                &mut data,
            ),
            "NV_Read",
        );
        let value = match data.as_ref() {
            Some(d) if ret.is_ok() && d.size == 32 => {
                Ok(d.buffer[..32].try_into().unwrap_or([0; 32]))
            }
            _ if ret.is_ok() => {
                err("NV_Read: expected a 32-byte value\n");
                Err(())
            }
            _ => Err(()),
        };
        Esys_Free(data.cast());
        value
    }
}

fn sign_digest(
    esys: *mut EsysContext,
    writer: EsysTr,
    digest: &[u8; 32],
) -> Result<[u8; NV_RSA_BYTES], ()> {
    let mut validation = TkHashcheck::zeroed();
    validation.tag = ST_HASHCHECK;
    validation.hierarchy = RH_NULL;
    let scheme = sig_scheme(ALG_RSASSA, ALG_SHA256);
    let mut input = Tpm2bDigest::zeroed();
    input.size = 32;
    input.buffer[..32].copy_from_slice(digest);
    let mut signed: *mut Signature = core::ptr::null_mut();
    // SAFETY: the context, the writer, the digest, scheme and ticket, and
    // room for the signature, whose RSASSA variant is read once its
    // algorithm says so, and which is freed once.
    unsafe {
        let ret = tpm_ok(
            Esys_Sign(
                esys,
                writer,
                ESYS_TR_PASSWORD,
                ESYS_TR_NONE,
                ESYS_TR_NONE,
                &input,
                &scheme,
                &validation,
                &mut signed,
            ),
            "Sign",
        );
        let signature = match signed.as_ref() {
            Some(s)
                if ret.is_ok()
                    && s.sigAlg == ALG_RSASSA
                    && s.signature.rsassa.hash == ALG_SHA256
                    && usize::from(s.signature.rsassa.sig.size) == NV_RSA_BYTES =>
            {
                let mut out = [0u8; NV_RSA_BYTES];
                out.copy_from_slice(&s.signature.rsassa.sig.buffer[..NV_RSA_BYTES]);
                Ok(out)
            }
            _ if ret.is_ok() => {
                err("Sign returned an unexpected signature\n");
                Err(())
            }
            _ => Err(()),
        };
        Esys_Free(signed.cast());
        signature
    }
}

/// A policy session authorizing the NV_Extend of `event` to `nv` with
/// the writer's signature, or with `saved` replayed, or corrupted;
/// `saved` keeps a valid one.
#[allow(clippy::too_many_arguments)]
fn authorize(
    t: &Tpm,
    writer: EsysTr,
    nv: EsysTr,
    event: &[u8; 32],
    policy: &[u8; 32],
    session: &mut EsysTr,
    saved: &mut [u8; NV_RSA_BYTES],
    fault: Fault,
) -> Step {
    let mut name: *mut Tpm2bName = core::ptr::null_mut();
    let ret = (|| {
        if session_start(t, t.session_key.handle, SE_POLICY, session) != 0 {
            return Err(());
        }
        // SAFETY: the context, the session, and room for the index's name.
        unsafe {
            tpm_ok(
                Esys_TRSess_SetAttributes(
                    t.esys,
                    *session,
                    SESSION_CONTINUESESSION,
                    SESSION_CONTINUESESSION,
                ),
                "TRSess_SetAttributes",
            )?;
            tpm_ok(Esys_TR_GetName(t.esys, nv, &mut name), "TR_GetName")?;
        }
        // SAFETY: the name ESYS gave, if any.
        let index_name: [u8; NAME_LEN] = match unsafe { name.as_ref() } {
            Some(n) if usize::from(n.size) == NAME_LEN => {
                n.name[..NAME_LEN].try_into().map_err(|_| ())?
            }
            _ => {
                err("NV index has an invalid Name\n");
                return Err(());
            }
        };
        // SAFETY: an authorization of zeros, which the prepare fills.
        let mut authorization: WriterAuthorization = unsafe { core::mem::zeroed() };
        if writer_prepare(t, *session, &index_name, event, &mut authorization) != 0 {
            return Err(());
        }
        let signature = match fault {
            Fault::Replay => *saved,
            _ => {
                let mut s = sign_digest(t.esys, writer, &authorization.digest)?;
                if fault == Fault::Corrupt {
                    s[0] ^= 1;
                }
                s
            }
        };
        let trc = writer_authorize(t, writer, *session, &authorization, &signature);
        if fault != Fault::Valid {
            if trc != RC_BAD_SIGNATURE {
                err(&format!(
                    "PolicySigned: expected bad signature, got 0x{trc:08x}\n"
                ));
                return Err(());
            }
            return Ok(());
        }
        tpm_ok(trc, "PolicySigned")?;
        if policy_session_finish(t, *session, policy) != 0 {
            return Err(());
        }
        *saved = signature;
        Ok(())
    })();
    // SAFETY: the name ESYS gave, or NULL, freed once.
    unsafe { Esys_Free(name.cast()) };
    ret
}

fn buffer(first: u8) -> Tpm2bMaxNvBuffer {
    let mut b = Tpm2bMaxNvBuffer::zeroed();
    b.size = 32;
    b.buffer[0] = first;
    b
}

fn event_of(b: &Tpm2bMaxNvBuffer) -> [u8; 32] {
    b.buffer[..32].try_into().unwrap_or([0; 32])
}

struct State {
    session: EsysTr,
    writer: EsysTr,
    nv: EsysTr,
    defined: bool,
}

fn scenario(t: &Tpm, st: &mut State) -> Step {
    let esys = t.esys;
    let (event_a, event_b, seed) = (buffer(1), buffer(2), buffer(0));
    let mut writer_seed = [0u8; 32];
    let got = loop {
        // SAFETY: room for the seed.
        let got = unsafe { libc::getrandom(writer_seed.as_mut_ptr().cast(), writer_seed.len(), 0) };
        if got >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            break got;
        }
    };
    if got != writer_seed.len() as isize {
        perror("getrandom");
        return Err(());
    }
    let mut writer_public = [0u8; NV_RSA_BYTES];
    // SAFETY: the connection, the seed and room for the public key.
    let e = unsafe {
        tpm_writer_create(
            (t as *const Tpm).cast_mut(),
            writer_seed.as_ptr(),
            writer_public.as_mut_ptr(),
        )
    };
    if e != 0 {
        err(&format!("create TPM NV writer: {}\n", super::strerror(-e)));
        return Err(());
    }
    let mut policy = [0u8; 32];
    let mut signed = [0u8; 32];
    if policy_signed(&[0; 32], &writer_public, &mut signed) != 0
        || policy_command_code(&signed, CC_NV_EXTEND, &mut policy) != 0
    {
        err("cannot construct the scratch NV writer policy\n");
        return Err(());
    }
    let mut public = [0u8; NV_RSA_BYTES];
    if writer_primary(
        t,
        &writer_seed,
        Some(&writer_public),
        &mut public,
        &mut st.writer,
    ) != 0
        || nv_define(t, TEST_NV_INDEX, &policy, &[]) != 0
    {
        return Err(());
    }
    st.defined = true;
    let mut signature = [0u8; NV_RSA_BYTES];
    let from_public = |nv: &mut EsysTr| {
        // SAFETY: the context and room for the index's handle.
        tpm_ok(
            unsafe {
                Esys_TR_FromTPMPublic(
                    esys,
                    TEST_NV_INDEX,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    ESYS_TR_NONE,
                    nv,
                )
            },
            "TR_FromTPMPublic",
        )
    };
    // SAFETY: the context, the index, the session and the event.
    let extend = |nv, session, event: &Tpm2bMaxNvBuffer| unsafe {
        Esys_NV_Extend(esys, nv, nv, session, ESYS_TR_NONE, ESYS_TR_NONE, event)
    };
    from_public(&mut st.nv)?;
    authorize(
        t,
        st.writer,
        st.nv,
        &event_of(&seed),
        &policy,
        &mut st.session,
        &mut signature,
        Fault::Valid,
    )?;
    tpm_ok(extend(st.nv, st.session, &seed), "NV_Extend(seed)")?;
    flush(esys, &mut st.session)?;
    // SAFETY: the context and the index's handle, closed.
    tpm_ok(unsafe { Esys_TR_Close(esys, &mut st.nv) }, "TR_Close(NV)")?;
    from_public(&mut st.nv)?;
    let before = read_value(esys, st.nv)?;
    authorize(
        t,
        st.writer,
        st.nv,
        &event_of(&event_a),
        &policy,
        &mut st.session,
        &mut signature,
        Fault::Valid,
    )?;
    let trc = extend(st.nv, st.session, &event_b);
    if trc != RC_SESSION_POLICY_FAIL {
        err(&format!(
            "NV_Extend(B): expected session-1 policy failure, got 0x{trc:08x}\n"
        ));
        return Err(());
    }
    flush(esys, &mut st.session)?;
    if read_value(esys, st.nv)? != before {
        err("rejected NV_Extend changed the scratch value\n");
        return Err(());
    }
    for fault in [Fault::Replay, Fault::Corrupt] {
        authorize(
            t,
            st.writer,
            st.nv,
            &event_of(&event_a),
            &policy,
            &mut st.session,
            &mut signature,
            fault,
        )?;
        flush(esys, &mut st.session)?;
    }
    if read_value(esys, st.nv)? != before {
        err("replayed or corrupt signature changed the scratch value\n");
        return Err(());
    }
    authorize(
        t,
        st.writer,
        st.nv,
        &event_of(&event_a),
        &policy,
        &mut st.session,
        &mut signature,
        Fault::Valid,
    )?;
    tpm_ok(extend(st.nv, st.session, &event_a), "NV_Extend(A)")?;
    flush(esys, &mut st.session)?;
    let after = read_value(esys, st.nv)?;
    let folded = [before, event_of(&event_a)].concat();
    if sha256(&folded).ok() != Some(after) {
        err("authorized NV_Extend did not produce SHA256(before || A)\n");
        return Err(());
    }
    Ok(())
}

fn run(_: &[&CStr]) -> c_int {
    let mut t: *mut Tpm = core::ptr::null_mut();
    // SAFETY: room for the connection, closed once at the end.
    if unsafe { tpm_open(&mut t) } != 0 {
        // SAFETY: as below.
        unsafe { tpm_close(t) };
        return 1;
    }
    // SAFETY: the connection just opened.
    let tr = unsafe { &*t };
    let mut st = State {
        session: ESYS_TR_NONE,
        writer: ESYS_TR_NONE,
        nv: ESYS_TR_NONE,
        defined: false,
    };
    let mut ok = scenario(tr, &mut st).is_ok();
    ok &= flush(tr.esys, &mut st.session).is_ok();
    if st.defined && nv_undefine(tr, TEST_NV_INDEX, &[]) != 0 {
        ok = false;
    }
    ok &= flush(tr.esys, &mut st.writer).is_ok();
    // SAFETY: the connection, closed once.
    unsafe { tpm_close(t) };
    if ok {
        out("PolicySigned: replay and corruption rejected; value unchanged\n");
        out("cpHash: authorized A; rejected B unchanged; extended A; scratch index removed\n");
    }
    c_int::from(!ok)
}
