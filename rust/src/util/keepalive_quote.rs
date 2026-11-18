// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The shirudo.quote of a keepalive: the
//! attestation key's quote of the SHA-256 of the body, as the attest, sig
//! and ak fields in base64.

use core::ffi::c_int;
use core::ptr;

use crate::errno::E2BIG;
use crate::util::crypto_openssl::{base64, sha256};
use crate::util::tpm::{
    Tpm, TpmAttestation, TpmKey, tpm_ak_create, tpm_close, tpm_key_flush, tpm_open, tpm_quote,
};

/// attest=<TPMS_ATTEST>;sig=<TPMT_SIGNATURE>;ak=<TPMT_PUBLIC> in padded
/// base64.
pub(crate) fn format(att: &TpmAttestation, ak: &TpmKey) -> Result<Vec<u8>, c_int> {
    let part = |b: &[u8], len: usize| base64(b.get(..len).ok_or(-E2BIG)?);
    Ok([
        &b"attest="[..],
        &part(&att.attest, att.attest_len)?,
        b";sig=",
        &part(&att.signature, att.signature_len)?,
        b";ak=",
        &part(&ak.public, ak.public_len)?,
    ]
    .concat())
}

/// The quote of the SHA-256 of `body` by an attestation key made for it
/// and flushed after, over no PCR, which tells a keepalive quote from one
/// of attest.
pub(crate) fn quote(body: &[u8]) -> Result<Vec<u8>, c_int> {
    let digest = sha256(body)?;
    let mut tpm: *mut Tpm = ptr::null_mut();
    let mut ak = TpmKey::zeroed();
    let mut att = TpmAttestation::zeroed();

    // SAFETY: room for the connection.
    let ret = unsafe { tpm_open(&mut tpm) };
    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the connection tpm_open() gave, and room for the key.
    let mut ret = unsafe { tpm_ak_create(tpm, &mut ak) };
    if ret == 0 {
        // SAFETY: the connection, the key made on it, the digest, and
        // room for the quote.
        ret = unsafe { tpm_quote(tpm, &ak, digest.as_ptr(), digest.len(), 0, &mut att) };
    }
    let quoted = if ret == 0 {
        format(&att, &ak)
    } else {
        Err(ret)
    };
    // SAFETY: the key, made on the connection or empty, flushed once.
    unsafe { tpm_key_flush(tpm, &mut ak) };
    // SAFETY: the connection tpm_open() gave, closed once.
    unsafe { tpm_close(tpm) };
    quoted
}

#[cfg(test)]
mod tests;
