// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The NV writer key: the TPM key that alone
//! may extend the measurement register, created from a fresh seed at
//! init, and read back from the identity map after.

use core::ffi::c_int;

use crate::errno::{EINTR, EIO, EKEYREJECTED};
use crate::sys::identity::Identity;
use crate::sys::libc::{errno, getrandom, scrub, strerror};
use crate::util::identity;
use crate::util::tpm::{tpm_close, tpm_open, tpm_writer_create};
use crate::util::tpm_wire::{DIGEST_LEN, NV_RSA_BYTES};

/// A fresh seed into `seed`, and the writer key the TPM creates from it,
/// its modulus into `public`; on failure both are zeroed.
fn create(seed: &mut [u8; DIGEST_LEN], public: &mut [u8; NV_RSA_BYTES]) -> c_int {
    let mut off = 0;

    while off < seed.len() {
        // SAFETY: the room left in seed.
        let got = unsafe { getrandom(seed[off..].as_mut_ptr().cast(), seed.len() - off, 0) };

        if got < 0 && errno() == EINTR {
            continue;
        }
        if got <= 0 {
            return failed(if got < 0 { -errno() } else { -EIO }, seed, public);
        }
        off += got as usize;
    }

    let mut t = core::ptr::null_mut();
    // SAFETY: where tpm_open() leaves the connection.
    let mut err = unsafe { tpm_open(&mut t) };

    if err == 0 {
        // SAFETY: the connection, the seed, and the room for a modulus.
        err = unsafe { tpm_writer_create(t, seed.as_ptr(), public.as_mut_ptr()) };
    }
    // SAFETY: what tpm_open() left, open or NULL.
    unsafe { tpm_close(t) };
    if err == 0 {
        return 0;
    }
    failed(err, seed, public)
}

fn failed(err: c_int, seed: &mut [u8; DIGEST_LEN], public: &mut [u8; NV_RSA_BYTES]) -> c_int {
    // SAFETY: a format of one C string, and strerror()'s.
    unsafe {
        crate::log::log_c!(
            crate::log::err,
            c"nv writer: TPM key creation failed: %s".as_ptr(),
            strerror(-err),
        )
    };
    scrub(seed);
    public.fill(0);
    err
}

/// The writer's seed and modulus as init froze them in the identity map;
/// -EKEYREJECTED when the modulus there is not one, its top bit clear.
pub(crate) fn read(seed: &mut [u8; DIGEST_LEN], public: &mut [u8; NV_RSA_BYTES]) -> c_int {
    let mut id = Identity::zeroed();
    let mut err = identity::read(&mut id);

    if err == 0 && id.nv_writer_public[0] & 0x80 == 0 {
        err = -EKEYREJECTED;
    }
    if err != 0 {
        // SAFETY: a format of one C string, and strerror()'s.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"nv writer: public key lookup failed: %s".as_ptr(),
                strerror(-err),
            )
        };
        return err;
    }
    seed.copy_from_slice(&id.nv_writer_seed);
    public.copy_from_slice(&id.nv_writer_public);
    0
}

pub(crate) use capi::nv_writer_create;

mod capi {
    use core::ffi::c_int;

    use crate::util::tpm_wire::{DIGEST_LEN, NV_RSA_BYTES};

    /// # Safety
    ///
    /// `seed` has room for 32 bytes and `public` for 384, apart.
    pub unsafe extern "C" fn nv_writer_create(seed: *mut u8, public: *mut u8) -> c_int {
        // SAFETY: the caller passes the room for both; nothing reads
        // either before writing it.
        unsafe {
            super::create(
                &mut *seed.cast::<[u8; DIGEST_LEN]>(),
                &mut *public.cast::<[u8; NV_RSA_BYTES]>(),
            )
        }
    }
}
