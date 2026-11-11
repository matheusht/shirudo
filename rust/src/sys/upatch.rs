// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The `.upatch` reader of `util/upatch.h`.

use core::ffi::{c_char, c_int, c_void};

use crate::sys::libc::Dirent;

pub const NAME_MAX: usize = 256;
pub const PAYLOAD_HASH_LEN: usize = 32;

/// `struct upatch_host_header`: the container's header as the reader
/// holds it, in host order.
#[repr(C)]
pub struct UpatchHostHeader {
    magic: u64,
    version: u32,
    flags: u32,
    name: [u8; NAME_MAX],
    pub payload_sha256: [u8; PAYLOAD_HASH_LEN],
    loader_insns_off: u32,
    loader_insns_len: u32,
    signature_off: u32,
    signature_len: u32,
    metadata_off: u32,
    metadata_len: u32,
    data_off: u32,
    data_len: u32,
    log_buf_sz: u32,
    nr_maps: u32,
    nr_progs: u32,
    rodata_data_off: u32,
    ty: u32,
    reserved1: u32,
}

/// `struct upatch`: a container upatch_open() opened, which
/// upatch_close() releases.
#[repr(C)]
pub struct Upatch {
    pub hdr: UpatchHostHeader,
    map: *const u8,
    map_size: usize,
    owned: bool,
    rodata_offset_in_header: bool,
    decoder_blob: *const c_void,
    decoder_blob_len: u32,
    nr_decoders: u32,
    signed_name: *const c_char,
    signed_attach: *const u8,
    signed_attach_len: u32,
    signed_unload_payload: *const u8,
    signed_policy_labels: *const c_void,
    signed_policy_labels_len: u32,
    signed_policy_map_idx: u32,
    signed_socket_policy_map_idx: u32,
}

const _: () = assert!(size_of::<UpatchHostHeader>() == 360);
const _: () = assert!(core::mem::offset_of!(UpatchHostHeader, payload_sha256) == 272);
const _: () = assert!(size_of::<Upatch>() == 456);
const _: () = assert!(core::mem::offset_of!(Upatch, decoder_blob) == 384);
const _: () = assert!(core::mem::offset_of!(Upatch, signed_unload_payload) == 424);

unsafe extern "C" {
    /// Whether `name` and `payload_hex` make a member of a measured set:
    /// a name upatch_name_valid() takes and the 64 hex digits of its
    /// payload's SHA-256.
    pub fn upatch_member_valid(name: *const c_char, payload_hex: *const c_char) -> bool;
    /// An upatch name: [A-Za-z0-9._-]+ not starting with '.', short
    /// enough for its pin directory.
    pub fn upatch_name_valid(name: *const c_char) -> bool;
    /// The container at `path` opened into `out`: 0 or -errno.
    pub fn upatch_open(path: *const c_char, out: *mut Upatch) -> c_int;
    /// What upatch_open() took for `u` released.
    pub fn upatch_close(u: *mut Upatch);
    /// The header's name, NUL-terminated, into `out`, room for
    /// NAME_MAX + 1 bytes.
    pub fn upatch_header_name(u: *const Upatch, out: *mut c_char);
    /// scandir()'s filter of the archives: a name that ends in ".upatch".
    pub fn upatch_select(e: *const Dirent) -> c_int;
}
