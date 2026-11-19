// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The shirudo.quote of a keepalive: the
//! attestation key's quote of the SHA-256 of the body, as the attest, sig
//! and ak fields in base64.

use core::ffi::c_int;

use crate::util::crypto_openssl::{base64, sha256};
use crate::util::tpm::{Attestation, KeyPublic, Tpm};

/// attest=<TPMS_ATTEST>;sig=<TPMT_SIGNATURE>;ak=<TPMT_PUBLIC> in padded
/// base64.
pub(crate) fn format(att: &Attestation, ak: &KeyPublic) -> Result<Vec<u8>, c_int> {
    Ok([
        &b"attest="[..],
        &base64(&att.attest)?,
        b";sig=",
        &base64(&att.signature)?,
        b";ak=",
        &base64(&ak.area)?,
    ]
    .concat())
}

/// The quote of the SHA-256 of `body` by an attestation key made for it
/// and flushed after, over no PCR, which tells a keepalive quote from one
/// of attest.
pub(crate) fn quote(body: &[u8]) -> Result<Vec<u8>, c_int> {
    let digest = sha256(body)?;
    let tpm = Tpm::open()?;
    let ak = tpm.ak_create()?;
    let att = tpm.quote(&ak, &digest, 0)?;

    format(&att, ak.public())
}

#[cfg(test)]
mod tests;
