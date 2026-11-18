// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The TPM structures a verifier reads from evidence: a TPMT_PUBLIC, an
//! ECDSA signature and a TPMS_ATTEST. A parse fills its output field by
//! field as it reads, so that a refusal leaves what it had read, as the
//! C did; the caller zeroes the output first.

use core::ffi::c_int;

use super::{
    ALG_AES, ALG_CFB, ALG_ECC, ALG_ECDSA, ALG_NULL, ALG_RSA, ALG_SHA256, DIGEST_LEN, ECC_NIST_P256,
    GENERATED, NAME_LEN, PCR_SELECT_LEN, Reader, ST_ATTEST_NV, ST_ATTEST_QUOTE, TpmAttest,
    TpmEccPublic, TpmPublic, errno,
};
use crate::errno::{E2BIG, EINVAL, EPROTONOSUPPORT};

/// A TPMT_PUBLIC of a SHA-256-named P-256 or RSA-2048 key, its symmetric
/// protector absent or AES-128-CFB, its scheme absent or ECDSA with
/// SHA-256.
pub(crate) fn public_parse(buf: &[u8], out: &mut TpmPublic) -> c_int {
    errno(public_fields(&mut Reader::new(buf), out))
}

fn public_fields(r: &mut Reader<'_>, out: &mut TpmPublic) -> Result<(), c_int> {
    out.ty = r.u16()?;
    if r.u16()? != ALG_SHA256 {
        return Err(-EINVAL);
    }
    out.attrs = r.u32()?;
    let policy = r.sized(DIGEST_LEN)?;
    out.policy_len = policy.len();
    if !policy.is_empty() && policy.len() != DIGEST_LEN {
        return Err(-EINVAL);
    }
    out.policy[..policy.len()].copy_from_slice(policy);
    out.sym_alg = r.u16()?;
    if out.sym_alg != ALG_NULL {
        out.sym_bits = r.u16()?;
        out.sym_mode = r.u16()?;
    }
    out.scheme = r.u16()?;
    if out.scheme != ALG_NULL {
        out.scheme_hash = r.u16()?;
    }
    match out.ty {
        ALG_ECC => {
            out.curve = r.u16()?;
            if r.u16()? != ALG_NULL {
                return Err(-EINVAL);
            }
            r.sized_into(&mut out.x)?;
            r.sized_into(&mut out.y)?;
        }
        ALG_RSA => {
            out.rsa_bits = r.u16()?;
            out.rsa_exponent = r.u32()?;
            let n = r.sized(out.n.len())?;
            out.n_len = n.len();
            out.n[..n.len()].copy_from_slice(n);
        }
        _ => return Err(-EPROTONOSUPPORT),
    }
    if r.left() != 0 {
        return Err(-EINVAL);
    }
    let sym_ok = out.sym_alg == ALG_NULL
        || (out.sym_alg == ALG_AES && out.sym_bits == 128 && out.sym_mode == ALG_CFB);
    let scheme_ok =
        out.scheme == ALG_NULL || (out.scheme == ALG_ECDSA && out.scheme_hash == ALG_SHA256);
    let key_ok = match out.ty {
        ALG_ECC => out.curve == ECC_NIST_P256,
        _ => {
            out.rsa_bits == 2048
                && out.n_len == 256
                && (out.rsa_exponent == 0 || out.rsa_exponent == 65537)
        }
    };
    if !(sym_ok && scheme_ok && key_ok) {
        return Err(-EPROTONOSUPPORT);
    }
    Ok(())
}

/// `public` as a TPMT_PUBLIC into `out`, and how many bytes it took.
pub(crate) fn public_marshal(public: &TpmPublic, out: &mut [u8], len: &mut usize) -> c_int {
    if public.policy_len != 0 && public.policy_len != DIGEST_LEN {
        return -EINVAL;
    }
    let mut need = 2 + 2 + 4 + 2 + public.policy_len + 2 + 2;
    if public.sym_alg != ALG_NULL {
        need += 4;
    }
    if public.scheme != ALG_NULL {
        need += 2;
    }
    if public.ty == ALG_ECC {
        need += 2 + 2 + 2 + 32 + 2 + 32;
    } else if public.ty == ALG_RSA && public.n_len <= public.n.len() {
        need += 2 + 4 + 2 + public.n_len;
    } else {
        return -EINVAL;
    }
    if out.len() < need {
        return -E2BIG;
    }
    let mut off = 0;
    let mut put = |bytes: &[u8]| {
        out[off..off + bytes.len()].copy_from_slice(bytes);
        off += bytes.len();
    };
    put(&public.ty.to_be_bytes());
    put(&ALG_SHA256.to_be_bytes());
    put(&public.attrs.to_be_bytes());
    put(&(public.policy_len as u16).to_be_bytes());
    put(&public.policy[..public.policy_len]);
    put(&public.sym_alg.to_be_bytes());
    if public.sym_alg != ALG_NULL {
        put(&public.sym_bits.to_be_bytes());
        put(&public.sym_mode.to_be_bytes());
    }
    put(&public.scheme.to_be_bytes());
    if public.scheme != ALG_NULL {
        put(&public.scheme_hash.to_be_bytes());
    }
    if public.ty == ALG_ECC {
        put(&public.curve.to_be_bytes());
        put(&ALG_NULL.to_be_bytes());
        put(&32u16.to_be_bytes());
        put(&public.x);
        put(&32u16.to_be_bytes());
        put(&public.y);
    } else {
        put(&public.rsa_bits.to_be_bytes());
        put(&public.rsa_exponent.to_be_bytes());
        put(&(public.n_len as u16).to_be_bytes());
        put(&public.n[..public.n_len]);
    }
    *len = off;
    0
}

/// An ECDSA P-256 signing key with SHA-256 and no symmetric protector.
pub(super) fn ecc_public_parse(buf: &[u8], out: &mut TpmEccPublic) -> c_int {
    let mut public = TpmPublic::zeroed();
    let ret = public_parse(buf, &mut public);

    if ret != 0 {
        return ret;
    }
    if public.ty != ALG_ECC || public.sym_alg != ALG_NULL || public.scheme != ALG_ECDSA {
        return -EPROTONOSUPPORT;
    }
    out.attrs = public.attrs;
    out.scheme = public.scheme;
    out.hash = public.scheme_hash;
    out.curve = public.curve;
    out.x = public.x;
    out.y = public.y;
    0
}

/// A TPMT_SIGNATURE of ECDSA with SHA-256: its r into `r_out`, then its
/// s into `s_out`.
pub(super) fn ecdsa_signature_parse(
    buf: &[u8],
    r_out: &mut [u8; 32],
    s_out: &mut [u8; 32],
) -> c_int {
    errno(signature_fields(&mut Reader::new(buf), r_out, s_out))
}

fn signature_fields(
    r: &mut Reader<'_>,
    r_out: &mut [u8; 32],
    s_out: &mut [u8; 32],
) -> Result<(), c_int> {
    if r.u16()? != ALG_ECDSA || r.u16()? != ALG_SHA256 {
        return Err(-EINVAL);
    }
    r.sized_into(r_out)?;
    r.sized_into(s_out)?;
    if r.left() != 0 {
        return Err(-EINVAL);
    }
    Ok(())
}

/// A name of at most NAME_LEN bytes into `name`, and its length.
fn name_into(r: &mut Reader<'_>, name: &mut [u8; NAME_LEN], len: &mut usize) -> Result<(), c_int> {
    let d = r.sized(NAME_LEN)?;

    name[..d.len()].copy_from_slice(d);
    *len = d.len();
    Ok(())
}

/// A TPMS_ATTEST of TPM2_Quote, over one SHA-256 bank, or of
/// TPM2_NV_Certify. Its extra data and NV contents point into `buf`.
pub(crate) fn attest_parse(buf: &[u8], out: &mut TpmAttest) -> c_int {
    errno(attest_fields(&mut Reader::new(buf), out))
}

fn attest_fields(r: &mut Reader<'_>, out: &mut TpmAttest) -> Result<(), c_int> {
    if r.u32()? != GENERATED {
        return Err(-EINVAL);
    }
    out.ty = r.u16()?;
    name_into(r, &mut out.signer, &mut out.signer_len)?;
    let extra = r.sized(64)?;
    out.extra = extra.as_ptr();
    out.extra_len = extra.len();
    out.clock = r.u64()?;
    out.reset_count = r.u32()?;
    out.restart_count = r.u32()?;
    let safe = r.u8()?;
    out.firmware_version = r.u64()?;
    out.safe = safe != 0;

    match out.ty {
        ST_ATTEST_QUOTE => {
            if r.u32()? != 1 || r.u16()? != ALG_SHA256 {
                return Err(-EINVAL);
            }
            let n = usize::from(r.u8()?);
            if n != PCR_SELECT_LEN || r.left() < n {
                return Err(-EINVAL);
            }
            let select = r.take(n)?;
            out.pcr_mask =
                u32::from(select[0]) | (u32::from(select[1]) << 8) | (u32::from(select[2]) << 16);
            r.sized_into(&mut out.pcr_digest)?;
            if r.left() != 0 {
                return Err(-EINVAL);
            }
            Ok(())
        }
        ST_ATTEST_NV => {
            name_into(r, &mut out.index_name, &mut out.index_name_len)?;
            out.offset = r.u16()?;
            let data = r.sized(2048)?;
            out.nv_data = data.as_ptr();
            out.nv_len = data.len();
            if r.left() != 0 {
                return Err(-EINVAL);
            }
            Ok(())
        }
        _ => Err(-EPROTONOSUPPORT),
    }
}
