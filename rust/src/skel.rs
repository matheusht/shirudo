// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The light skeletons of bpf2 and the seal, which init loads: the Rust
//! tools/bpf-lskel writes of each (bpf/*.skel.rs) when it generates the
//! loader util/loader.c embeds. Their map types are read from the
//! objects' BTF, so a layout the BPF C changes fails this build instead
//! of a boot; the seal names bpf2's types where they are laid out alike,
//! and takes bpf2's maps as `seal::Shared`, of those types.

/// bpf2: the guards, their maps and the identity the seal shares.
#[allow(dead_code)] // the skeleton has what bpf2 has; init uses some
pub(crate) mod bpf2 {
    include!("../../bpf/bpf2.skel.rs");
}

/// The seal: its hooks, its own maps, and bpf2's it takes.
#[allow(dead_code)]
pub(crate) mod seal {
    include!("../../bpf/seal.skel.rs");
}
