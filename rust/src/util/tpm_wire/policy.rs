// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Policy digests, the names of NV indexes and objects, and the
//! measurement register's writer key as the TPM sees it.

use core::ffi::c_int;

use super::{
    ALG_NULL, ALG_RSA, ALG_RSASSA, ALG_SHA256, CC_NV_EXTEND, DIGEST_LEN, NAME_LEN, NV_POLICY_REF,
    NV_RSA_BYTES, NV_RSA_PUBLIC_AREA_LEN, PCR_SELECT_LEN, PCR_SELECTION_LEN, Reader, WRITER_ATTRS,
    put_sized,
};
use crate::errno::{EINVAL, EIO};
use crate::util::crypto_openssl::{
    Sha256Ctx, sha256_buffer, sha256_final, sha256_free, sha256_init, sha256_update,
};

const CC_POLICY_OR: u32 = 0x0000_0171;
const CC_POLICY_COMMAND_CODE: u32 = 0x0000_016C;
const CC_POLICY_SIGNED: u32 = 0x0000_0160;
const CC_POLICY_PCR: u32 = 0x0000_017F;
const CC_POLICY_NV_WRITTEN: u32 = 0x0000_018F;

type Digest = [u8; DIGEST_LEN];

/// SHA-256 of `data` into `out`, as `sha256_buffer()` gives it.
fn sha256(data: &[u8], out: &mut [u8]) -> c_int {
    debug_assert!(out.len() >= DIGEST_LEN);
    // SAFETY: data.len() bytes, and room for a digest at out.
    unsafe { sha256_buffer(data.as_ptr().cast(), data.len(), out.as_mut_ptr()) }
}

/// A policy command's update of `prev`: SHA-256(prev || cc || a || b),
/// or zeros and -EIO when the digest fails.
fn policy_hash(prev: &Digest, cc: u32, a: &[u8], b: &[u8], out: &mut Digest) -> c_int {
    let mut ctx = Sha256Ctx::new();
    let cc = cc.to_be_bytes();

    // SAFETY: a context sha256_init() sets up, which sha256_final()
    // releases, or sha256_free() when an update or the final fails, and
    // the byte counts of the slices passed.
    unsafe {
        if sha256_init(&mut ctx) != 0 {
            *out = [0; DIGEST_LEN];
            return -EIO;
        }
        if sha256_update(&mut ctx, prev.as_ptr().cast(), prev.len()) != 0
            || sha256_update(&mut ctx, cc.as_ptr().cast(), cc.len()) != 0
            || (!a.is_empty() && sha256_update(&mut ctx, a.as_ptr().cast(), a.len()) != 0)
            || (!b.is_empty() && sha256_update(&mut ctx, b.as_ptr().cast(), b.len()) != 0)
            || sha256_final(&mut ctx, out.as_mut_ptr()) != 0
        {
            *out = [0; DIGEST_LEN];
            sha256_free(&mut ctx);
            return -EIO;
        }
    }
    0
}

pub(super) fn policy_nv_written(prev: &Digest, written: bool, out: &mut Digest) -> c_int {
    policy_hash(prev, CC_POLICY_NV_WRITTEN, &[u8::from(written)], &[], out)
}

/// A TPML_PCR_SELECTION of one SHA-256 bank and the PCRs of `mask`.
fn pcr_selection(mask: u32) -> [u8; PCR_SELECTION_LEN] {
    let mut out = [0u8; PCR_SELECTION_LEN];

    out[..4].copy_from_slice(&1u32.to_be_bytes());
    out[4..6].copy_from_slice(&ALG_SHA256.to_be_bytes());
    out[6] = PCR_SELECT_LEN as u8;
    out[7..].copy_from_slice(&mask.to_le_bytes()[..PCR_SELECT_LEN]);
    out
}

pub(super) fn policy_pcr(prev: &Digest, mask: u32, pcr_digest: &Digest, out: &mut Digest) -> c_int {
    policy_hash(prev, CC_POLICY_PCR, &pcr_selection(mask), pcr_digest, out)
}

pub(super) fn policy_or(a: &Digest, b: &Digest, out: &mut Digest) -> c_int {
    policy_hash(&[0; DIGEST_LEN], CC_POLICY_OR, a, b, out)
}

/// The writer's fixed TPMT_PUBLIC, without the outer TPM2B_PUBLIC size:
/// a 24-byte prefix and the modulus.
pub(super) fn writer_public(modulus: &[u8; NV_RSA_BYTES], out: &mut [u8; NV_RSA_PUBLIC_AREA_LEN]) {
    out[0..2].copy_from_slice(&ALG_RSA.to_be_bytes());
    out[2..4].copy_from_slice(&ALG_SHA256.to_be_bytes());
    out[4..8].copy_from_slice(&WRITER_ATTRS.to_be_bytes());
    // An empty authPolicy: its size alone.
    out[8..10].copy_from_slice(&0u16.to_be_bytes());
    out[10..12].copy_from_slice(&ALG_NULL.to_be_bytes());
    out[12..14].copy_from_slice(&ALG_RSASSA.to_be_bytes());
    out[14..16].copy_from_slice(&ALG_SHA256.to_be_bytes());
    out[16..18].copy_from_slice(&3072u16.to_be_bytes());
    out[18..22].copy_from_slice(&65537u32.to_be_bytes());
    put_sized(&mut out[22..], modulus);
}

pub(super) fn nv_extend_cphash(name: &[u8; NAME_LEN], event: &Digest, out: &mut Digest) -> c_int {
    let mut command = [0u8; 4 + 2 * NAME_LEN + 2 + DIGEST_LEN];

    command[..4].copy_from_slice(&CC_NV_EXTEND.to_be_bytes());
    command[4..4 + NAME_LEN].copy_from_slice(name);
    command[4 + NAME_LEN..4 + 2 * NAME_LEN].copy_from_slice(name);
    put_sized(&mut command[4 + 2 * NAME_LEN..], event);
    sha256(&command, out)
}

pub(super) fn writer_auth_hash(nonce: &[u8], cphash: &Digest, out: &mut Digest) -> c_int {
    let mut bytes = [0u8; 64 + 4 + DIGEST_LEN + NV_POLICY_REF.len()];
    let n = nonce.len();

    if n == 0 || n > 64 {
        return -EINVAL;
    }
    bytes[..n].copy_from_slice(nonce);
    bytes[n..n + 4].copy_from_slice(&0u32.to_be_bytes());
    bytes[n + 4..n + 4 + DIGEST_LEN].copy_from_slice(cphash);
    bytes[n + 4 + DIGEST_LEN..n + 4 + DIGEST_LEN + NV_POLICY_REF.len()]
        .copy_from_slice(NV_POLICY_REF);
    sha256(&bytes[..n + 4 + DIGEST_LEN + NV_POLICY_REF.len()], out)
}

pub(super) fn policy_signed(
    prev: &Digest,
    modulus: &[u8; NV_RSA_BYTES],
    out: &mut Digest,
) -> c_int {
    let mut public = [0u8; NV_RSA_PUBLIC_AREA_LEN];
    let mut name = [0u8; NAME_LEN];
    let mut bytes = [0u8; DIGEST_LEN + NV_POLICY_REF.len()];

    writer_public(modulus, &mut public);
    let ret = object_name(&public, &mut name);
    if ret != 0 {
        return ret;
    }
    let ret = policy_hash(prev, CC_POLICY_SIGNED, &name, &[], out);
    if ret != 0 {
        return ret;
    }
    bytes[..DIGEST_LEN].copy_from_slice(out);
    bytes[DIGEST_LEN..].copy_from_slice(NV_POLICY_REF);
    sha256(&bytes, out)
}

pub(super) fn policy_command_code(prev: &Digest, command_code: u32, out: &mut Digest) -> c_int {
    policy_hash(
        prev,
        CC_POLICY_COMMAND_CODE,
        &command_code.to_be_bytes(),
        &[],
        out,
    )
}

/// The register's write policy from its two branches: PolicyOR of them,
/// PolicySigned by the writer, PolicyCommandCode(NV_Extend).
pub(super) fn register_policy_final(
    branch_written: &Digest,
    branch_init: &Digest,
    modulus: &[u8; NV_RSA_BYTES],
    policy: &mut Digest,
) -> c_int {
    let mut ret = policy_or(branch_written, branch_init, policy);

    if ret == 0 {
        let prev = *policy;

        ret = policy_signed(&prev, modulus, policy);
    }
    if ret == 0 {
        let prev = *policy;

        ret = policy_command_code(&prev, CC_NV_EXTEND, policy);
    }
    ret
}

/// The digests of `register_policy()`, which writes them in this order.
pub(super) struct RegisterPolicy<'a> {
    pub branch_written: &'a mut Digest,
    pub branch_init: &'a mut Digest,
    pub policy: &'a mut Digest,
}

/// The register's write policy from the `pcr_values` the binding PCRs of
/// `mask` held, which `pcr_values_len` bytes of SHA-256 cover.
pub(super) fn register_policy(
    mask: u32,
    pcr_values: *const u8,
    pcr_values_len: usize,
    modulus: &[u8; NV_RSA_BYTES],
    out: RegisterPolicy<'_>,
) -> c_int {
    let zero = [0u8; DIGEST_LEN];
    let mut pcr_digest = [0u8; DIGEST_LEN];
    let mut unwritten = [0u8; DIGEST_LEN];

    let mut ret = policy_nv_written(&zero, true, out.branch_written);
    if ret == 0 {
        ret = policy_nv_written(&zero, false, &mut unwritten);
    }
    if ret == 0 {
        // SAFETY: the caller's pcr_values_len bytes, as sha256_buffer()
        // reads them, and room for the digest.
        ret = unsafe { sha256_buffer(pcr_values.cast(), pcr_values_len, pcr_digest.as_mut_ptr()) };
    }
    if ret == 0 {
        ret = policy_pcr(&unwritten, mask, &pcr_digest, out.branch_init);
    }
    if ret != 0 {
        return ret;
    }
    register_policy_final(out.branch_written, out.branch_init, modulus, out.policy)
}

/// The name of an NV index: nameAlg || SHA-256(TPMS_NV_PUBLIC).
pub(super) fn nv_name(
    index: u32,
    attrs: u32,
    policy: &Digest,
    data_size: u16,
    name: &mut [u8; NAME_LEN],
) -> c_int {
    let mut public = [0u8; 4 + 2 + 4 + 2 + DIGEST_LEN + 2];

    public[0..4].copy_from_slice(&index.to_be_bytes());
    public[4..6].copy_from_slice(&ALG_SHA256.to_be_bytes());
    public[6..10].copy_from_slice(&attrs.to_be_bytes());
    public[10..12].copy_from_slice(&(DIGEST_LEN as u16).to_be_bytes());
    public[12..44].copy_from_slice(policy);
    public[44..46].copy_from_slice(&data_size.to_be_bytes());
    name[..2].copy_from_slice(&ALG_SHA256.to_be_bytes());
    sha256(&public, &mut name[2..])
}

/// The name of an object: nameAlg || SHA-256(TPMT_PUBLIC), for a public
/// area named with SHA-256.
pub(super) fn object_name(public: &[u8], name: &mut [u8; NAME_LEN]) -> c_int {
    let mut r = Reader::new(public);

    // The type, then the nameAlg.
    if !matches!((r.u16(), r.u16()), (Ok(_), Ok(ALG_SHA256))) {
        return -EINVAL;
    }
    name[..2].copy_from_slice(&ALG_SHA256.to_be_bytes());
    sha256(public, &mut name[2..])
}

/// The qualified name of a primary: nameAlg || SHA-256(hierarchy ||
/// name).
pub(super) fn qualified_name(
    hierarchy: u32,
    name: &[u8; NAME_LEN],
    out: &mut [u8; NAME_LEN],
) -> c_int {
    let mut buf = [0u8; 4 + NAME_LEN];

    buf[..4].copy_from_slice(&hierarchy.to_be_bytes());
    buf[4..].copy_from_slice(name);
    out[..2].copy_from_slice(&ALG_SHA256.to_be_bytes());
    sha256(&buf, &mut out[2..])
}
