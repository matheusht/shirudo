// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The `struct bpf_*_info` the kernel fills for a BPF object, kept as
//! bytes at the alignment of the uapi and read at its offsets, so that
//! no layout is bound for the few fields shirudo reads.

use core::ffi::c_int;

use crate::sys::bpf::bpf_obj_get_info_by_fd;

/// The sizes of `struct bpf_link_info`, `struct bpf_prog_info` and
/// `struct bpf_map_info`.
pub(crate) const LINK_INFO_SIZE: usize = 64;
pub(crate) const PROG_INFO_SIZE: usize = 232;
pub(crate) const MAP_INFO_SIZE: usize = 104;
/// Where `struct bpf_map_info` keeps its value size and entry count.
pub(crate) const MAP_VALUE_SIZE: usize = 12;
pub(crate) const MAP_MAX_ENTRIES: usize = 16;

/// An info structure of `N` bytes.
#[repr(C, align(8))]
pub(crate) struct Info<const N: usize>([u8; N]);

impl<const N: usize> Info<N> {
    pub(crate) fn new() -> Self {
        Info([0; N])
    }

    /// The structure's bytes.
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.0
    }

    /// The field of 32 bits at `off`.
    pub(crate) fn u32_at(&self, off: usize) -> u32 {
        u32::from_ne_bytes(self.0[off..off + 4].try_into().unwrap_or_default())
    }

    /// Sets the bytes at `off`, as a caller asks for more than the
    /// fixed part: a buffer and its size.
    pub(crate) fn set(&mut self, off: usize, v: &[u8]) {
        self.0[off..off + v.len()].copy_from_slice(v);
    }

    /// Filled from the BPF object `fd`, or libbpf's -errno.
    pub(crate) fn read(&mut self, fd: c_int) -> Result<(), c_int> {
        let mut len = N as u32;
        // SAFETY: a descriptor and room for the N bytes of info.
        match unsafe { bpf_obj_get_info_by_fd(fd, self.0.as_mut_ptr().cast(), &mut len) } {
            0 => Ok(()),
            r => Err(r),
        }
    }
}
