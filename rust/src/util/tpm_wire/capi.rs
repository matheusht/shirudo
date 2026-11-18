// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C-shaped interface the crate still calls. A function copies its digests,
//! names and keys before it writes an output, so that an output may be
//! one of them, as the policy digests' `prev` and `out` are; it zeroes
//! a structure it parses into, padding included, as the C's memset()
//! did.

use core::ffi::{c_char, c_int};

use super::kdf::{self};
use super::policy::{self, RegisterPolicy};
use super::{
    CREDENTIAL_LEN, DIGEST_LEN, ID_OBJECT_LEN, NAME_LEN, NV_RSA_BYTES, TpmAttest, TpmEccPublic,
    TpmPublic, parse,
};
use crate::ffi;

/// The TCG default endorsement key policy,
/// PolicySecret(TPM_RH_ENDORSEMENT).
pub const EK_POLICY: [u8; DIGEST_LEN] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];

/// A copy of the `N` bytes at `p`.
///
/// # Safety
///
/// `p` points to `N` readable bytes.
unsafe fn copy<const N: usize>(p: *const u8) -> [u8; N] {
    // SAFETY: the caller's N bytes, which have no alignment to keep.
    unsafe { p.cast::<[u8; N]>().read() }
}

/// The room for `N` bytes at `p`.
///
/// # Safety
///
/// `p` points to `N` writable bytes that nothing else accesses for `'a`.
unsafe fn room<'a, const N: usize>(p: *mut u8) -> &'a mut [u8; N] {
    // SAFETY: the caller's N bytes, which have no alignment to keep.
    unsafe { &mut *p.cast::<[u8; N]>() }
}

/// # Safety
///
/// `pcr_values` holds `n_values` digests, `writer_public` a modulus, and
/// `branch_written`, `branch_init` and `policy` are three distinct rooms
/// for a digest.
pub unsafe extern "C" fn tpm_register_policy(
    pcr_mask: u32,
    pcr_values: *const u8,
    n_values: usize,
    writer_public: *const u8,
    branch_written: *mut u8,
    branch_init: *mut u8,
    policy: *mut u8,
) -> c_int {
    // SAFETY: the caller passes the values, a modulus and three rooms.
    unsafe {
        let modulus = copy::<NV_RSA_BYTES>(writer_public);
        let out = RegisterPolicy {
            branch_written: room(branch_written),
            branch_init: room(branch_init),
            policy: room(policy),
        };

        policy::register_policy(
            pcr_mask,
            pcr_values,
            n_values.wrapping_mul(DIGEST_LEN),
            &modulus,
            out,
        )
    }
}

/// # Safety
///
/// `policy` holds a digest and `name` has room for a name.
pub unsafe extern "C" fn tpm_nv_name(
    index: u32,
    attrs: u32,
    policy: *const u8,
    data_size: u16,
    name: *mut u8,
) -> c_int {
    // SAFETY: the caller passes a digest and the room.
    unsafe {
        let policy = copy::<DIGEST_LEN>(policy);

        policy::nv_name(index, attrs, &policy, data_size, room(name))
    }
}

/// # Safety
///
/// `public` holds `len` bytes, which `name` does not overlap, and `name`
/// has room for a name.
pub unsafe extern "C" fn tpm_object_name(public: *const u8, len: usize, name: *mut u8) -> c_int {
    // SAFETY: the caller passes the public area and the room.
    unsafe { policy::object_name(ffi::slice(public, len), room(name)) }
}

/// # Safety
///
/// `buf` holds `len` bytes and `out` is a public area to fill.
pub unsafe extern "C" fn tpm_public_parse(
    buf: *const u8,
    len: usize,
    out: *mut TpmPublic,
) -> c_int {
    // SAFETY: the caller passes the bytes and the structure, all of
    // whose bits zeroed are a valid one.
    unsafe {
        out.write_bytes(0, 1);
        parse::public_parse(ffi::slice(buf, len), &mut *out)
    }
}

/// # Safety
///
/// `buf` holds `len` bytes and `out` is a key to fill.
pub unsafe extern "C" fn tpm_ecc_public_parse(
    buf: *const u8,
    len: usize,
    out: *mut TpmEccPublic,
) -> c_int {
    // SAFETY: the caller passes the bytes and the structure, all of
    // whose bits zeroed are a valid one.
    unsafe {
        out.write_bytes(0, 1);
        parse::ecc_public_parse(ffi::slice(buf, len), &mut *out)
    }
}

/// # Safety
///
/// `z` holds 32 bytes, `label` is a C string, `party_u` and `party_v`
/// hold `u_len` and `v_len` bytes, and `out` has room for a digest.
pub unsafe extern "C" fn tpm_kdfe(
    z: *const u8,
    label: *const c_char,
    party_u: *const u8,
    u_len: usize,
    party_v: *const u8,
    v_len: usize,
    out: *mut u8,
) -> c_int {
    // SAFETY: the caller passes the secret, a C string, the two parties
    // and the room.
    unsafe {
        let z = copy::<DIGEST_LEN>(z);
        let (label, u) = (ffi::c_str(label), ffi::slice(party_u, u_len));
        let v = ffi::slice(party_v, v_len);

        kdf::kdfe(&z, label, u, v, room(out))
    }
}

/// # Safety
///
/// `seed` holds 32 bytes, `name` a name, `credential` a credential, and
/// `out` has room for `TPM_ID_OBJECT_LEN` bytes.
pub unsafe extern "C" fn tpm_credential_protect(
    seed: *const u8,
    name: *const u8,
    credential: *const u8,
    out: *mut u8,
) -> c_int {
    // SAFETY: the caller passes the seed, a name, a credential and the
    // room.
    unsafe {
        let seed = copy::<DIGEST_LEN>(seed);
        let name = copy::<NAME_LEN>(name);
        let credential = copy::<CREDENTIAL_LEN>(credential);

        kdf::credential_protect(&seed, &name, &credential, room::<ID_OBJECT_LEN>(out))
    }
}

/// # Safety
///
/// `buf` holds `len` bytes, which outlive the pointers into them that
/// `out` takes, and `out` is an attestation to fill.
pub unsafe extern "C" fn tpm_attest_parse(
    buf: *const u8,
    len: usize,
    out: *mut TpmAttest,
) -> c_int {
    // SAFETY: the caller passes the bytes and the structure, all of
    // whose bits zeroed are a valid one.
    unsafe {
        out.write_bytes(0, 1);
        parse::attest_parse(ffi::slice(buf, len), &mut *out)
    }
}

/// # Safety
///
/// `a` is an attestation, `ak_name` holds a name and `is` is room for
/// whether it signed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_attest_signer(
    a: *const TpmAttest,
    ak_name: *const u8,
    is: *mut bool,
) -> c_int {
    // SAFETY: the caller passes the attestation, the name and the room.
    unsafe {
        match super::attest_signer(&*a, &copy::<NAME_LEN>(ak_name)) {
            Ok(signed) => {
                is.write(signed);
                0
            }
            Err(err) => err,
        }
    }
}

/// # Safety
///
/// `attest` holds `len` bytes, `sig` `sig_len`, and `x` and `y` 32 each.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_attest_verify(
    attest: *const u8,
    len: usize,
    sig: *const u8,
    sig_len: usize,
    x: *const u8,
    y: *const u8,
) -> c_int {
    // SAFETY: the caller passes the bytes and the point.
    unsafe {
        super::attest_verify(
            ffi::slice(attest, len),
            ffi::slice(sig, sig_len),
            &copy::<32>(x),
            &copy::<32>(y),
        )
    }
}
