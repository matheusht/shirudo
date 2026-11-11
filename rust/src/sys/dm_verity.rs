// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The dm-verity mappings of `util/dm_verity.h` that stay in C. They
//! take a `struct config_image_open`, which rust/src/util/config_image.rs
//! defines, by pointer.

use core::ffi::{c_char, c_int, c_void};

use crate::sys::libc::PATH_MAX;

/// `struct dm_verity`: a mapping of an image, its device and the loop
/// devices of its parts, -1 for one not open.
#[repr(C)]
pub struct DmVerity {
    /// The `struct config_image` the mapping is of.
    pub image: [u64; 11],
    pub name: [u8; 128],
    pub path: [u8; PATH_MAX],
    pub device: u64,
    pub data_device: u64,
    pub hash_device: u64,
    pub data_loop_fd: c_int,
    pub hash_loop_fd: c_int,
}

const _: () = assert!(size_of::<DmVerity>() == 4344);

unsafe extern "C" {
    /// A mapping named `name` of the `struct config_image_open` at
    /// `image`, into `out`.
    pub fn dm_verity_create(image: *const c_void, name: *const c_char, out: *mut DmVerity)
    -> c_int;
    /// Whether the mapping reads back as the image's root hash says.
    pub fn dm_verity_verify(device: *const DmVerity, image: *const c_void) -> c_int;
    /// The mapping removed, at its last close when `deferred`.
    pub fn dm_verity_remove(device: *mut DmVerity, deferred: bool) -> c_int;
    /// The loop devices' fds closed.
    pub fn dm_verity_close(device: *mut DmVerity);
}
