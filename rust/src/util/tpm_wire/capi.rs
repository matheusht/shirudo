// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The C interface of `util/tpm_wire.h`. A function copies its digests,
//! names and keys before it writes an output, so that an output may be
//! one of them, as the policy digests' `prev` and `out` are; it zeroes
//! a structure it parses into, padding included, as the C's memset()
//! did.

use core::ffi::{c_char, c_int};

use super::kdf::{self, HmacKey};
use super::policy::{self, RegisterPolicy};
use super::{
    CREDENTIAL_LEN, DIGEST_LEN, ID_OBJECT_LEN, NAME_LEN, NV_RSA_BYTES, NV_RSA_PUBLIC_AREA_LEN,
    TpmAttest, TpmEccPublic, TpmPublic, parse,
};
use crate::ffi;

/// The TCG default endorsement key policy,
/// PolicySecret(TPM_RH_ENDORSEMENT).
#[allow(non_upper_case_globals)]
#[unsafe(no_mangle)]
pub static shirudo_tpm_ek_policy: [u8; DIGEST_LEN] = [
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
/// `modulus` holds `TPM_NV_RSA_BYTES` bytes and `out` has room for
/// `TPM_NV_RSA_PUBLIC_AREA_LEN`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_writer_public(modulus: *const u8, out: *mut u8) {
    // SAFETY: the caller passes the modulus and the room.
    unsafe {
        let modulus = copy::<NV_RSA_BYTES>(modulus);

        policy::writer_public(&modulus, room::<NV_RSA_PUBLIC_AREA_LEN>(out));
    }
}

/// # Safety
///
/// `name` holds a name, `event` a digest and `out` has room for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_nv_extend_cphash(
    name: *const u8,
    event: *const u8,
    out: *mut u8,
) -> c_int {
    // SAFETY: the caller passes a name, a digest and the room.
    unsafe {
        let (name, event) = (copy::<NAME_LEN>(name), copy::<DIGEST_LEN>(event));

        policy::nv_extend_cphash(&name, &event, room(out))
    }
}

/// # Safety
///
/// `nonce` holds `nonce_len` bytes, which `out` does not overlap,
/// `cphash` a digest, and `out` has room for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_writer_auth_hash(
    nonce: *const u8,
    nonce_len: usize,
    cphash: *const u8,
    out: *mut u8,
) -> c_int {
    // SAFETY: the caller passes the nonce, a digest and the room.
    unsafe {
        let cphash = copy::<DIGEST_LEN>(cphash);

        policy::writer_auth_hash(ffi::slice(nonce, nonce_len), &cphash, room(out))
    }
}

/// # Safety
///
/// `prev` holds a digest, `writer_public` a modulus, and `out` has room
/// for a digest.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_policy_signed(
    prev: *const u8,
    writer_public: *const u8,
    out: *mut u8,
) -> c_int {
    // SAFETY: the caller passes a digest, a modulus and the room.
    unsafe {
        let (prev, modulus) = (
            copy::<DIGEST_LEN>(prev),
            copy::<NV_RSA_BYTES>(writer_public),
        );

        policy::policy_signed(&prev, &modulus, room(out))
    }
}

/// # Safety
///
/// `prev` holds a digest and `out` has room for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_policy_command_code(
    prev: *const u8,
    command_code: u32,
    out: *mut u8,
) -> c_int {
    // SAFETY: the caller passes a digest and the room.
    unsafe {
        let prev = copy::<DIGEST_LEN>(prev);

        policy::policy_command_code(&prev, command_code, room(out))
    }
}

/// # Safety
///
/// `branch_written` and `branch_init` hold digests, `writer_public` a
/// modulus, and `policy` has room for a digest.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_register_policy_final(
    branch_written: *const u8,
    branch_init: *const u8,
    writer_public: *const u8,
    policy: *mut u8,
) -> c_int {
    // SAFETY: the caller passes two digests, a modulus and the room.
    unsafe {
        let written = copy::<DIGEST_LEN>(branch_written);
        let init = copy::<DIGEST_LEN>(branch_init);
        let modulus = copy::<NV_RSA_BYTES>(writer_public);

        policy::register_policy_final(&written, &init, &modulus, room(policy))
    }
}

/// # Safety
///
/// `prev` holds a digest and `out` has room for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_policy_nv_written(
    prev: *const u8,
    written: bool,
    out: *mut u8,
) -> c_int {
    // SAFETY: the caller passes a digest and the room.
    unsafe {
        let prev = copy::<DIGEST_LEN>(prev);

        policy::policy_nv_written(&prev, written, room(out))
    }
}

/// # Safety
///
/// `prev` and `pcr_digest` hold digests and `out` has room for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_policy_pcr(
    prev: *const u8,
    pcr_mask: u32,
    pcr_digest: *const u8,
    out: *mut u8,
) -> c_int {
    // SAFETY: the caller passes two digests and the room.
    unsafe {
        let (prev, digest) = (copy::<DIGEST_LEN>(prev), copy::<DIGEST_LEN>(pcr_digest));

        policy::policy_pcr(&prev, pcr_mask, &digest, room(out))
    }
}

/// # Safety
///
/// `a` and `b` hold digests and `out` has room for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_policy_or(a: *const u8, b: *const u8, out: *mut u8) -> c_int {
    // SAFETY: the caller passes two digests and the room.
    unsafe {
        let (a, b) = (copy::<DIGEST_LEN>(a), copy::<DIGEST_LEN>(b));

        policy::policy_or(&a, &b, room(out))
    }
}

/// # Safety
///
/// `pcr_values` holds `n_values` digests, `writer_public` a modulus, and
/// `branch_written`, `branch_init` and `policy` are three distinct rooms
/// for a digest.
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_object_name(public: *const u8, len: usize, name: *mut u8) -> c_int {
    // SAFETY: the caller passes the public area and the room.
    unsafe { policy::object_name(ffi::slice(public, len), room(name)) }
}

/// # Safety
///
/// `name` holds a name and `out` has room for one.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_qualified_name(
    hierarchy: u32,
    name: *const u8,
    out: *mut u8,
) -> c_int {
    // SAFETY: the caller passes a name and the room.
    unsafe {
        let name = copy::<NAME_LEN>(name);

        policy::qualified_name(hierarchy, &name, room(out))
    }
}

/// # Safety
///
/// `buf` holds `len` bytes and `out` is a public area to fill.
#[unsafe(no_mangle)]
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
/// `public` is a public area, `out` has room for `cap` bytes and `len`
/// is a size.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_public_marshal(
    public: *const TpmPublic,
    out: *mut u8,
    cap: usize,
    len: *mut usize,
) -> c_int {
    // SAFETY: the caller passes its public area, the room and the size.
    unsafe { parse::public_marshal(&*public, ffi::bytes_mut(out, cap), &mut *len) }
}

/// # Safety
///
/// `buf` holds `len` bytes and `out` is a key to fill.
#[unsafe(no_mangle)]
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
/// `key` holds `key_len` bytes as `hmac_sha256()` takes them, `label` is
/// a C string, `ctx_u` and `ctx_v` hold `u_len` and `v_len` bytes, and
/// `out` has room for `out_len` that overlap none of them.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_kdfa(
    key: *const u8,
    key_len: usize,
    label: *const c_char,
    ctx_u: *const u8,
    u_len: usize,
    ctx_v: *const u8,
    v_len: usize,
    out: *mut u8,
    out_len: usize,
) -> c_int {
    let key = HmacKey {
        ptr: key,
        len: key_len,
    };

    // SAFETY: the caller passes a C string, the two contexts and the
    // room, apart.
    unsafe {
        kdf::kdfa(
            &key,
            ffi::c_str(label),
            ffi::slice(ctx_u, u_len),
            ffi::slice(ctx_v, v_len),
            ffi::bytes_mut(out, out_len),
        )
    }
}

/// # Safety
///
/// `z` holds 32 bytes, `label` is a C string, `party_u` and `party_v`
/// hold `u_len` and `v_len` bytes, and `out` has room for a digest.
#[unsafe(no_mangle)]
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
#[unsafe(no_mangle)]
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
/// `buf` holds `len` bytes, and `r_out` and `s_out` are two distinct
/// rooms for 32 bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn tpm_ecdsa_signature_parse(
    buf: *const u8,
    len: usize,
    r_out: *mut u8,
    s_out: *mut u8,
) -> c_int {
    // SAFETY: the caller passes the bytes and two rooms.
    unsafe { parse::ecdsa_signature_parse(ffi::slice(buf, len), room(r_out), room(s_out)) }
}

/// # Safety
///
/// `buf` holds `len` bytes, which outlive the pointers into them that
/// `out` takes, and `out` is an attestation to fill.
#[unsafe(no_mangle)]
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
