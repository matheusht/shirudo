// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The ports of `util/`, one module for each C file they replace.

mod attest;
mod bpm_oci;
mod bpm_package;
mod bpm_source_config;
mod bpm_state;
mod bpm_tree;
mod bpm_tree_state;
mod chain;
mod conditions;
pub(crate) mod config;
mod config_attest;
mod config_image;
mod config_measure;
mod config_update;
pub(crate) mod crypto_openssl;
mod dm_verity;
mod elf_target;
mod eventlog;
mod format;
mod harden;
pub(crate) mod help;
mod image_bootstrap;
mod image_cache;
pub(crate) mod image_config;
mod initrd;
pub(crate) mod io;
mod json;
mod kernel_abi;
mod kernel_build_id;
mod kernel_release;
mod keyring;
mod keys;
mod measured;
mod nv_writer;
mod preflight;
mod report;
mod serializer;
mod similar;
mod sysinfo;
mod timefmt;
mod tls_openssl;
mod tpm;
mod tpm_wire;
mod upatch;
mod upatch_rodata;
mod upatch_table;
