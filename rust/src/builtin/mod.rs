// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The commands, one module for each. The table in `commands`
//! dispatches to them with the command line from the command's name on.

mod attest;
mod bpm;
mod build;
mod commands;
mod config;
mod genkey;
mod image;
mod init;
pub(crate) mod keys;
mod status;
mod upatch;
mod version;

/// The commands and the parts of them the test helpers run.
#[cfg(feature = "test-helpers")]
pub(crate) use {
    attest::cmd_attest, bpm::cmd_bpm, bpm::source_key_open, config::cmd_config, keys::cmd_keys,
    status::cmd_status,
};
