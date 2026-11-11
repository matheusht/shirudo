// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The key derivations of TPM 2.0 Part 1 with SHA-256, KDFa and KDFe,
//! and the credential protection of Part 1, 24.4, built on them. A label
//! comes without its terminating NUL, which a derivation adds.

use core::ffi::c_int;

use super::{CREDENTIAL_LEN, DIGEST_LEN, ID_OBJECT_LEN, NAME_LEN};
use crate::errno::{EINVAL, EIO};
use crate::sys::libc::scrub;
use crate::util::crypto_openssl::{aes128_cfb_encrypt, hmac_sha256, sha256_buffer};

/// The most bytes one KDFa derivation gives.
const KDFA_MAX: usize = 4096;

/// The HMAC key of a KDFa, as the caller holds it: NULL is not an empty
/// key to OpenSSL.
pub(super) struct HmacKey {
    pub ptr: *const u8,
    pub len: usize,
}

/// KDFa: SP800-108 in counter mode with HMAC-SHA-256, `out.len()` bytes
/// of it.
pub(super) fn kdfa(key: &HmacKey, label: &[u8], u: &[u8], v: &[u8], out: &mut [u8]) -> c_int {
    let mut buf = [0u8; 4 + 64 + 1 + 2 * NAME_LEN + 4];
    let mut block = [0u8; DIGEST_LEN];
    let mut done = 0;
    let mut ret = 0;

    if label.len() > 64 || u.len() > NAME_LEN || v.len() > NAME_LEN || out.len() > KDFA_MAX {
        return -EINVAL;
    }
    let bits = (out.len() * 8) as u32;
    let mut i = 1u32;
    while done < out.len() {
        let mut off = 0;

        for part in [&i.to_be_bytes()[..], label, &[0], u, v, &bits.to_be_bytes()] {
            buf[off..off + part.len()].copy_from_slice(part);
            off += part.len();
        }
        // SAFETY: the caller's key of key.len bytes as hmac_sha256() takes
        // it, off bytes of buf, and room for a block.
        if unsafe {
            hmac_sha256(
                key.ptr,
                key.len,
                buf.as_ptr().cast(),
                off,
                block.as_mut_ptr(),
            )
        } != 0
        {
            ret = -EIO;
            break;
        }
        let n = (out.len() - done).min(DIGEST_LEN);

        out[done..done + n].copy_from_slice(&block[..n]);
        done += n;
        i += 1;
    }
    scrub(&mut block);
    ret
}

/// KDFe: SP800-56A one-step with SHA-256, one block.
pub(super) fn kdfe(
    z: &[u8; DIGEST_LEN],
    label: &[u8],
    u: &[u8],
    v: &[u8],
    out: &mut [u8; DIGEST_LEN],
) -> c_int {
    let mut buf = [0u8; 4 + 32 + 64 + 1 + 2 * 64];
    let mut off = 0;

    if label.len() > 64 || u.len() > 64 || v.len() > 64 {
        return -EINVAL;
    }
    for part in [&1u32.to_be_bytes()[..], z, label, &[0], u, v] {
        buf[off..off + part.len()].copy_from_slice(part);
        off += part.len();
    }
    // SAFETY: off bytes of buf, and room for the digest.
    let ret = unsafe { sha256_buffer(buf.as_ptr().cast(), off, out.as_mut_ptr()) };
    scrub(&mut buf);
    ret
}

/// From a seed shared with the endorsement key, the TPM2B_ID_OBJECT
/// contents TPM2_ActivateCredential takes for the object named `name`:
/// the integrity HMAC, then the credential encrypted, under keys both
/// derived from the seed and the name.
pub(super) fn credential_protect(
    seed: &[u8; DIGEST_LEN],
    name: &[u8; NAME_LEN],
    credential: &[u8; CREDENTIAL_LEN],
    out: &mut [u8; ID_OBJECT_LEN],
) -> c_int {
    let mut plain = [0u8; 2 + CREDENTIAL_LEN];
    let mut sym_key = [0u8; 16];
    let mut hmac_key = [0u8; DIGEST_LEN];
    let ret = protect(
        seed,
        name,
        credential,
        &mut plain,
        &mut sym_key,
        &mut hmac_key,
        out,
    );

    scrub(&mut plain);
    scrub(&mut sym_key);
    scrub(&mut hmac_key);
    ret
}

fn protect(
    seed: &[u8; DIGEST_LEN],
    name: &[u8; NAME_LEN],
    credential: &[u8; CREDENTIAL_LEN],
    plain: &mut [u8; 2 + CREDENTIAL_LEN],
    sym_key: &mut [u8; 16],
    hmac_key: &mut [u8; DIGEST_LEN],
    out: &mut [u8; ID_OBJECT_LEN],
) -> c_int {
    let seed_key = HmacKey {
        ptr: seed.as_ptr(),
        len: seed.len(),
    };
    let mut enc = [0u8; 2 + CREDENTIAL_LEN];
    let mut mac_in = [0u8; 2 + CREDENTIAL_LEN + NAME_LEN];
    let mut mac = [0u8; DIGEST_LEN];

    if kdfa(&seed_key, b"STORAGE", name, &[], sym_key) != 0 {
        return -EIO;
    }
    plain[..2].copy_from_slice(&(CREDENTIAL_LEN as u16).to_be_bytes());
    plain[2..].copy_from_slice(credential);
    // SAFETY: a 16-byte key, the plain bytes, and room for as many.
    if unsafe {
        aes128_cfb_encrypt(
            sym_key.as_ptr(),
            plain.as_ptr(),
            plain.len(),
            enc.as_mut_ptr(),
        )
    } != 0
        || kdfa(&seed_key, b"INTEGRITY", &[], &[], hmac_key) != 0
    {
        return -EIO;
    }
    mac_in[..enc.len()].copy_from_slice(&enc);
    mac_in[enc.len()..].copy_from_slice(name);
    // SAFETY: a 32-byte key, the bytes of mac_in, and room for the HMAC.
    if unsafe {
        hmac_sha256(
            hmac_key.as_ptr(),
            hmac_key.len(),
            mac_in.as_ptr().cast(),
            mac_in.len(),
            mac.as_mut_ptr(),
        )
    } != 0
    {
        return -EIO;
    }
    out[..2].copy_from_slice(&(DIGEST_LEN as u16).to_be_bytes());
    out[2..34].copy_from_slice(&mac);
    out[34..].copy_from_slice(&enc);
    0
}
