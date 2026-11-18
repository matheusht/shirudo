// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-image-cli: a command of shirudo with the config image a test
//! names in place of the node's, as the image tests run bpm, keys and
//! config against an image without booting one.
//!
//!   test-image-cli <image root> bpm|keys|config <args>...
//!   test-image-cli <image root> source <name>
//!   test-image-cli <image root> tree

use core::ffi::{CStr, c_char, c_int};
use std::io::{BufRead, Read};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use super::out;
use crate::builtin::{cmd_bpm, cmd_config, cmd_keys, source_key_open};
use crate::errno::EIO;
use crate::util::config::{Config, config_load_path};
use crate::util::image_config;

/// The image's config set from a bootstrap of no file but the TPM's
/// owner auth and TCTI, or why not.
fn use_image(root: &CStr) -> bool {
    let Ok(dir) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(std::ffi::OsStr::from_bytes(root.to_bytes()))
    else {
        return false;
    };
    // SAFETY: a config of numbers and arrays, for which zeros are a value.
    let mut bootstrap: Box<Config> = Box::new(unsafe { core::mem::zeroed() });
    // SAFETY: the config to fill and a C string.
    if unsafe { config_load_path(&mut *bootstrap, c"/dev/null".as_ptr()) } != 0 {
        return false;
    }
    bootstrap.tpm_owner_auth[..15].copy_from_slice(b"bootstrap-owner");
    bootstrap.tpm_owner_auth_len = 15;
    let _ = crate::text::strscpy(&mut bootstrap.tpm_tcti, b"bootstrap-tcti");
    image_config::set(&bootstrap, dir.as_raw_fd()) == 0
}

/// The first line of the key file of source `name`, as bpm opens it.
fn source(name: &CStr) -> c_int {
    let fd = source_key_open(name.to_bytes());
    if fd < 0 {
        return fd;
    }
    // SAFETY: the descriptor source_key_open() gave, owned here.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut line = Vec::new();
    match std::io::BufReader::new(file.take(63)).read_until(b'\n', &mut line) {
        Ok(n) if n > 0 => {
            out(&String::from_utf8_lossy(&line));
            0
        }
        _ => -EIO,
    }
}

/// # Safety
///
/// The arguments the C runtime passes main().
#[unsafe(no_mangle)]
pub unsafe extern "C" fn shirudo_helper_test_image_cli(
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // SAFETY: main()'s arguments.
    let args = unsafe { super::args(argc, argv) };
    if args.len() < 3 {
        return 2;
    }
    if !use_image(args[1]) {
        return 1;
    }
    // SAFETY: the arguments from the command's name on, handed on.
    let command = |run: unsafe extern "C" fn(c_int, *const *const c_char) -> c_int| unsafe {
        run(argc - 2, argv.add(2))
    };
    let ret = match (args[2].to_bytes(), args.len()) {
        (b"bpm", _) => command(cmd_bpm),
        (b"keys", _) => command(cmd_keys),
        (b"config", _) => command(cmd_config),
        (b"source", 4) => source(args[3]),
        (b"tree", _) => {
            out(&format!(
                "{}\n",
                crate::util::initrd::cert_path().to_string_lossy()
            ));
            0
        }
        _ => 2,
    };
    image_config::clear();
    c_int::from(ret != 0)
}
