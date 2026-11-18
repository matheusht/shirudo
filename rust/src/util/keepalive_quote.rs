// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The shirudo.quote of a keepalive, behind `util/keepalive_quote.h`: the
//! attestation key's quote of the SHA-256 of the body, as the attest, sig
//! and ak fields in base64.

use core::ffi::c_int;

use crate::errno::E2BIG;
use crate::util::crypto_openssl::{base64_encode, sha256};
use crate::util::tpm::{
    ATTEST_MAX, PUBLIC_MAX, SIGNATURE_MAX, Tpm, TpmAttestation, TpmKey, tpm_ak_create, tpm_close,
    tpm_key_flush, tpm_open, tpm_quote,
};

/// BASE64_SIZE(): the room base64_encode() needs for `n` bytes, its
/// terminator included.
const fn base64_size(n: usize) -> usize {
    4 * n.div_ceil(3) + 1
}

/// `data` in padded base64, at most `max` bytes of it.
fn base64(data: &[u8], max: usize) -> Result<Vec<u8>, c_int> {
    let mut out = vec![0u8; base64_size(max)];
    // SAFETY: the bytes and the room, of their lengths.
    let ret = unsafe {
        base64_encode(
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr().cast(),
            out.len(),
        )
    };
    if ret != 0 {
        return Err(ret);
    }
    let len = out.iter().position(|&c| c == 0).unwrap_or(out.len());
    out.truncate(len);
    Ok(out)
}

/// attest=<TPMS_ATTEST>;sig=<TPMT_SIGNATURE>;ak=<TPMT_PUBLIC> in padded
/// base64.
pub(crate) fn format(att: &TpmAttestation, ak: &TpmKey) -> Result<Vec<u8>, c_int> {
    let part = |b: &[u8], len: usize, max: usize| base64(b.get(..len).ok_or(-E2BIG)?, max);
    Ok([
        &b"attest="[..],
        &part(&att.attest, att.attest_len, ATTEST_MAX)?,
        b";sig=",
        &part(&att.signature, att.signature_len, SIGNATURE_MAX)?,
        b";ak=",
        &part(&ak.public, ak.public_len, PUBLIC_MAX)?,
    ]
    .concat())
}

/// The quote of the SHA-256 of `body` by an attestation key made for it
/// and flushed after, over no PCR, which tells a keepalive quote from one
/// of attest.
pub(crate) fn quote(body: &[u8]) -> Result<Vec<u8>, c_int> {
    let digest = sha256(body)?;
    let mut tpm: *mut Tpm = core::ptr::null_mut();
    // SAFETY: room for the connection.
    let ret = unsafe { tpm_open(&mut tpm) };
    if ret != 0 {
        return Err(ret);
    }
    let mut ak = TpmKey::zeroed();
    let mut att = TpmAttestation::zeroed();
    // SAFETY: the connection, the key, the digest and room for the quote.
    let ret = unsafe {
        match tpm_ak_create(tpm, &mut ak) {
            0 => tpm_quote(tpm, &ak, digest.as_ptr(), digest.len(), 0, &mut att),
            err => err,
        }
    };
    let quoted = if ret == 0 {
        format(&att, &ak)
    } else {
        Err(ret)
    };
    // SAFETY: the key and the connection, each let go of once.
    unsafe {
        tpm_key_flush(tpm, &mut ak);
        tpm_close(tpm);
    }
    quoted
}

/// `text` and its terminator into the `cap` bytes at `out`, or -E2BIG
/// with `out` empty.
///
/// # Safety
///
/// `out` is room for `cap` bytes.
unsafe fn put(text: &[u8], out: *mut u8, cap: usize) -> c_int {
    // SAFETY: the caller's room.
    let out = unsafe { crate::ffi::bytes_mut(out, cap) };
    if text.len() < out.len() {
        out[..text.len()].copy_from_slice(text);
        out[text.len()] = 0;
        return 0;
    }
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    -E2BIG
}

#[cfg(test)]
mod tests;

mod capi {
    use core::ffi::{c_char, c_int};

    /// # Safety
    ///
    /// `body` holds `len` bytes, and `quote` is room for `cap` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keepalive_quote(
        body: *const c_char,
        len: usize,
        quote: *mut c_char,
        cap: usize,
    ) -> c_int {
        // SAFETY: the caller's body and room.
        unsafe {
            match super::quote(crate::ffi::slice(body.cast(), len)) {
                Ok(text) => super::put(&text, quote.cast(), cap),
                Err(err) => err,
            }
        }
    }
}
