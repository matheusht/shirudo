// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! TPM 2.0 wire-format helpers that need no TPM, behind
//! `util/tpm_wire.h`: policy digests, NV and object names, the key
//! derivations and credential protection, and the attestation
//! structures a verifier parses from evidence.

mod capi;
mod kdf;
mod parse;
mod policy;

use core::ffi::c_int;

use crate::errno::EINVAL;

pub(crate) const DIGEST_LEN: usize = 32;
/// nameAlg and a SHA-256.
const NAME_LEN: usize = 2 + DIGEST_LEN;
pub(crate) const NV_RSA_BYTES: usize = 384;
const NV_RSA_PUBLIC_AREA_LEN: usize = 24 + NV_RSA_BYTES;
const CREDENTIAL_LEN: usize = 32;
const ID_OBJECT_LEN: usize = 2 + 32 + 2 + CREDENTIAL_LEN;

const ALG_RSA: u16 = 0x0001;
const ALG_AES: u16 = 0x0006;
const ALG_SHA256: u16 = 0x000B;
const ALG_ECC: u16 = 0x0023;
const ALG_ECDSA: u16 = 0x0018;
const ALG_RSASSA: u16 = 0x0014;
const ALG_NULL: u16 = 0x0010;
const ALG_CFB: u16 = 0x0043;
const ECC_NIST_P256: u16 = 0x0003;
const ST_ATTEST_NV: u16 = 0x8014;
const ST_ATTEST_QUOTE: u16 = 0x8018;
const GENERATED: u32 = 0xFF54_4347;
const PCR_SELECT_LEN: usize = 3;
const PCR_SELECTION_LEN: usize = 7 + PCR_SELECT_LEN;
const NV_POLICY_REF: &[u8] = b"shirudo-nv-writer-v1";
const WRITER_ATTRS: u32 = 0x0004_0072;
const CC_NV_EXTEND: u32 = 0x0000_0136;

/// `struct tpm_public`: a TPMT_PUBLIC of the shapes shirudo makes or
/// checks.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TpmPublic {
    ty: u16,
    attrs: u32,
    policy_len: usize,
    policy: [u8; DIGEST_LEN],
    sym_alg: u16,
    sym_bits: u16,
    sym_mode: u16,
    scheme: u16,
    scheme_hash: u16,
    curve: u16,
    x: [u8; 32],
    y: [u8; 32],
    rsa_bits: u16,
    rsa_exponent: u32,
    n_len: usize,
    n: [u8; 256],
}

/// `struct tpm_ecc_public`.
#[repr(C)]
pub struct TpmEccPublic {
    attrs: u32,
    scheme: u16,
    hash: u16,
    curve: u16,
    x: [u8; 32],
    y: [u8; 32],
}

/// `struct tpm_attest`: a TPMS_ATTEST, its pointers into the buffer it
/// was parsed from.
#[repr(C)]
pub struct TpmAttest {
    ty: u16,
    signer: [u8; NAME_LEN],
    signer_len: usize,
    extra: *const u8,
    extra_len: usize,
    clock: u64,
    reset_count: u32,
    restart_count: u32,
    safe: bool,
    firmware_version: u64,
    pcr_mask: u32,
    pcr_digest: [u8; DIGEST_LEN],
    index_name: [u8; NAME_LEN],
    index_name_len: usize,
    offset: u16,
    nv_data: *const u8,
    nv_len: usize,
}

const _: () = assert!(size_of::<TpmPublic>() == 400);
const _: () = assert!(size_of::<TpmEccPublic>() == 76);
const _: () = assert!(size_of::<TpmAttest>() == 200);

impl TpmPublic {
    const fn zeroed() -> Self {
        TpmPublic {
            ty: 0,
            attrs: 0,
            policy_len: 0,
            policy: [0; DIGEST_LEN],
            sym_alg: 0,
            sym_bits: 0,
            sym_mode: 0,
            scheme: 0,
            scheme_hash: 0,
            curve: 0,
            x: [0; 32],
            y: [0; 32],
            rsa_bits: 0,
            rsa_exponent: 0,
            n_len: 0,
            n: [0; 256],
        }
    }
}

/// Big-endian fields off the front of a buffer: a read takes them, or
/// fails with -EINVAL when the buffer holds too few.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    fn left(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], c_int> {
        if self.left() < n {
            return Err(-EINVAL);
        }
        let s = &self.buf[self.pos..self.pos + n];

        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, c_int> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, c_int> {
        let b = self.take(2)?;

        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32, c_int> {
        let b = self.take(4)?;

        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64, c_int> {
        let hi = self.u32()?;
        let lo = self.u32()?;

        Ok((u64::from(hi) << 32) | u64::from(lo))
    }

    /// A TPM2B of at most `max` bytes.
    fn sized(&mut self, max: usize) -> Result<&'a [u8], c_int> {
        let n = usize::from(self.u16()?);

        if n > self.left() || n > max {
            return Err(-EINVAL);
        }
        self.take(n)
    }

    /// A TPM2B of exactly `out.len()` bytes into `out`.
    fn sized_into(&mut self, out: &mut [u8]) -> Result<(), c_int> {
        let d = self.sized(out.len())?;

        if d.len() != out.len() {
            return Err(-EINVAL);
        }
        out.copy_from_slice(d);
        Ok(())
    }
}

/// The 0 or negative errno a C function returns for `r`.
fn errno(r: Result<(), c_int>) -> c_int {
    r.err().unwrap_or(0)
}

/// A TPM2B: the size, then the bytes, at the front of `out`; how many
/// bytes that took.
fn put_sized(out: &mut [u8], data: &[u8]) -> usize {
    out[..2].copy_from_slice(&(data.len() as u16).to_be_bytes());
    out[2..2 + data.len()].copy_from_slice(data);
    2 + data.len()
}
