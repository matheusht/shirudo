// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The parts of `shirudo-build` in tools/shirudo-build/ that are still
//! C: the packager, and the image, upatch, bpm and keys commands.

use core::ffi::{c_char, c_int, c_void};

unsafe extern "C" {
    /// `shirudo-build image ...`, from its command word on.
    pub fn build_image(argc: c_int, argv: *mut *mut c_char) -> c_int;
    /// `shirudo-build upatch ...`, from its command word on.
    pub fn build_upatch_cli(argc: c_int, argv: *mut *mut c_char) -> c_int;
    /// `shirudo-build bpm ...`, from its command word on.
    pub fn build_bpm(argc: c_int, argv: *mut *mut c_char) -> c_int;
    /// `shirudo-build keys vouch ...`, from `vouch` on.
    pub fn build_keys_vouch(argc: c_int, argv: *mut *mut c_char) -> c_int;
    /// Packages and signs the object at `bpf_o` as upatch `name` at
    /// `out_upatch`, with `nr_policies` policy labels at `policies`;
    /// `src_path`, NULL for none, anchors relative decoder paths. 0 or
    /// -errno, logged.
    pub fn build_package_load(
        bpf_o: *const c_char,
        src_path: *const c_char,
        out_upatch: *const c_char,
        name: *const c_char,
        policies: *const c_void,
        nr_policies: u32,
        pkey_path: *const c_char,
        cert_path: *const c_char,
    ) -> c_int;
    /// Signs the directive that unloads upatch `name`, whose payload has
    /// the digest at `payload_sha256`, at `out_upatch`: 0 or -errno.
    pub fn build_package_unload(
        name: *const c_char,
        payload_sha256: *const u8,
        out_upatch: *const c_char,
        pkey_path: *const c_char,
        cert_path: *const c_char,
    ) -> c_int;
    /// The upatch name a source or object path gives, into `cap` bytes
    /// at `out`: 0, or -ENAMETOOLONG.
    pub fn build_upatch_name(source: *const c_char, out: *mut c_char, cap: usize) -> c_int;
}
