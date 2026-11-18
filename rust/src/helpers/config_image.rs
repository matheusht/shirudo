// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-config-image: a config image's superblock read, or the image
//! opened against an expected root hash.
//!
//!   test-config-image decode <hash file>
//!   test-config-image root <prefix> <root hex>

use core::ffi::{CStr, c_int};
use std::os::fd::AsRawFd;

use super::{err, helper_main, out, strerror};
use crate::errno::EINVAL;
use crate::util::config_image::{ConfigImageOpen, read_header};

helper_main!(shirudo_helper_test_config_image, run);

fn open_root(prefix: &CStr, root_hex: &CStr) -> c_int {
    let mut root = [0u8; 32];
    if crate::util::hex::decode(root_hex.to_bytes(), &mut root).is_err() {
        return -EINVAL;
    }
    match ConfigImageOpen::open(prefix, Some(&root)) {
        Ok(mut op) => {
            op.close();
            0
        }
        Err(err) => err,
    }
}

fn decode(path: &CStr) -> c_int {
    use std::os::unix::ffi::OsStrExt;
    let file = match std::fs::File::open(std::ffi::OsStr::from_bytes(path.to_bytes())) {
        Ok(f) => f,
        Err(e) => return -e.raw_os_error().unwrap_or(crate::errno::EIO),
    };
    match read_header(file.as_raw_fd()) {
        Ok(image) => {
            out(&format!("{} {}\n", image.data_blocks, image.hash_blocks));
            0
        }
        Err(e) => e,
    }
}

fn run(args: &[&CStr]) -> c_int {
    let ret = match args {
        [_, cmd, prefix, root] if cmd.to_bytes() == b"root" => open_root(prefix, root),
        [_, cmd, path] if cmd.to_bytes() == b"decode" => decode(path),
        _ => -EINVAL,
    };
    if ret != 0 {
        let text = strerror(-ret);
        err(&format!("config image: {} ({ret})\n", text));
    }
    c_int::from(ret != 0)
}
