// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-tpm-preopened: an NV_Extend of the register written raw by a
//! child to the TPM device its parent opened, which the LSM must refuse
//! and which must leave the register as it was.

use core::ffi::{CStr, c_int};
use std::os::fd::AsRawFd;

use super::{err, helper_main, out, perror};
use crate::sys::tss2::CC_NV_EXTEND;
use crate::util::eventlog::NV_INDEX;
use crate::util::tpm::{Tpm, nv_read, tpm_close, tpm_open};

helper_main!(shirudo_helper_test_tpm_preopened, run);

/// The register's value, read through a TPM connection of its own.
fn read_register() -> Option<[u8; 32]> {
    let mut t: *mut Tpm = core::ptr::null_mut();
    let mut value = [0u8; 32];
    // SAFETY: room for the connection, read through and closed once.
    unsafe {
        if tpm_open(&mut t) != 0 {
            return None;
        }
        let ret = nv_read(&*t, NV_INDEX, &mut value);
        tpm_close(t);
        (ret == 0).then_some(value)
    }
}

/// An unsigned NV_Extend of the register written to `fd`: refused with
/// EACCES, as the test wants.
fn write_extend(fd: c_int) -> c_int {
    let mut command = [0u8; 18];
    command[..2].copy_from_slice(&[0x80, 0x01]);
    command[2..6].copy_from_slice(&18u32.to_be_bytes());
    command[6..10].copy_from_slice(&CC_NV_EXTEND.to_be_bytes());
    command[10..14].copy_from_slice(&NV_INDEX.to_be_bytes());
    command[14..18].copy_from_slice(&NV_INDEX.to_be_bytes());
    // SAFETY: the command's bytes to the device.
    let written = unsafe { libc::write(fd, command.as_ptr().cast(), command.len()) };
    let errno = if written < 0 {
        std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
    } else {
        0
    };
    if written == -1 && errno == libc::EACCES {
        return 0;
    }
    err(&format!(
        "inherited NV_Extend: wrote {written}/{}, errno={errno}\n",
        command.len()
    ));
    1
}

fn run(_: &[&CStr]) -> c_int {
    let Some(before) = read_register() else {
        return 1;
    };
    let device = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tpmrm0")
    {
        Ok(d) => d,
        Err(_) => {
            perror("/dev/tpmrm0");
            return 1;
        }
    };
    // SAFETY: a fork of this process, one thread; the child writes and
    // exits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        perror("fork");
        return 1;
    }
    if pid == 0 {
        let ret = write_extend(device.as_raw_fd());
        // SAFETY: the child gone with its answer.
        unsafe { libc::_exit(ret) };
    }
    drop(device);
    let mut status = 0;
    // SAFETY: the child and room for its status.
    let waited = unsafe { libc::waitpid(pid, &mut status, 0) };
    if waited != pid || !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        err("inherited NV_Extend was not refused by the LSM\n");
        return 1;
    }
    if read_register() != Some(before) {
        err("inherited NV_Extend changed the register\n");
        return 1;
    }
    out("inherited-TPM: unsigned NV_Extend rejected by LSM; value unchanged\n");
    0
}
