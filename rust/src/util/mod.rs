// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The ports of `util/`, one module for each C file they replace.

pub(crate) mod attest;
pub(crate) mod bpm_oci;
pub(crate) mod bpm_package;
pub(crate) mod bpm_source_config;
pub(crate) mod bpm_state;
pub(crate) mod bpm_tree;
pub(crate) mod bpm_tree_state;
pub(crate) mod chain;
pub(crate) mod conditions;
pub(crate) mod config;
mod config_attest;
mod config_image;
pub(crate) mod config_measure;
mod config_update;
pub(crate) mod crypto_openssl;
mod dm_verity;
mod elf_target;
pub(crate) mod eventlog;
pub(crate) mod format;
mod harden;
pub(crate) mod help;
pub(crate) mod image_bootstrap;
mod image_cache;
pub(crate) mod image_config;
pub(crate) mod initrd;
pub(crate) mod io;
pub(crate) mod json;
mod kernel_abi;
mod kernel_build_id;
mod kernel_release;
pub(crate) mod keyring;
pub(crate) mod keys;
pub(crate) mod measured;
pub(crate) mod nv_writer;
pub(crate) mod preflight;
mod report;
mod serializer;
mod similar;
pub(crate) mod sysinfo;
mod timefmt;
mod tls_openssl;
pub(crate) mod tpm;
pub(crate) mod tpm_wire;
pub(crate) mod upatch;
pub(crate) mod upatch_rodata;
pub(crate) mod upatch_table;
