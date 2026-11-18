// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-signed-load: the signed loader of a .upatch loaded against a
//! keyring of the caller's choosing: the certificate named is added to
//! the session keyring, whose serial goes as the load's keyring_id. The
//! loader's data map is left out, so that BPF_MAP_CREATE policy cannot
//! mask the load gate. Prints "loaded" or "errno=<n>".
//!
//! t6104 shows with it that a loader whose signature the kernel verifies
//! is still denied with EACCES by shirudo's lsm/bpf_prog_load admission
//! when the verifying keyring is not the sealed one.
//!
//!   test-signed-load <upatch> <cert.der>

use core::ffi::{CStr, c_int, c_long};
use std::ffi::OsStr;
use std::io::Read;
use std::os::unix::ffi::OsStrExt;

use super::{err, helper_main, out, strerror};
use crate::util::bpf_sys::{Attr, BPF_PROG_LOAD};

helper_main!(shirudo_helper_test_signed_load, run);

const BPF_PROG_TYPE_SYSCALL: u32 = 31;
const BPF_F_SLEEPABLE: u32 = 1 << 4;
const KEY_SPEC_SESSION_KEYRING: c_long = -3;
const KEYCTL_GET_KEYRING_ID: c_long = 0;
/// The offsets of loader_insns_off, _len, signature_off and _len in
/// struct upatch_header, little-endian.
const LOADER_INSNS_OFF: usize = 304;
const SIGNATURE_OFF: usize = 312;

fn le32(b: &[u8], off: usize) -> Option<usize> {
    Some(u32::from_le_bytes(b.get(off..off + 4)?.try_into().ok()?) as usize)
}

fn errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn run(args: &[&CStr]) -> c_int {
    let [_, upatch, cert_path, ..] = args else {
        let me = args
            .first()
            .map_or("test-signed-load".into(), |a| a.to_string_lossy());
        err(&format!("usage: {me} <upatch> <cert.der>\n"));
        return 2;
    };
    let file = match std::fs::read(OsStr::from_bytes(upatch.to_bytes())) {
        Ok(f) => f,
        Err(e) => {
            err(&format!(
                "open {}: {}\n",
                upatch.to_string_lossy(),
                strerror(e.raw_os_error().unwrap_or(0))
            ));
            return 2;
        }
    };
    let field = |off| le32(&file, off).unwrap_or(0);
    let (insns_off, insns_len) = (field(LOADER_INSNS_OFF), field(LOADER_INSNS_OFF + 4));
    let (sig_off, sig_len) = (field(SIGNATURE_OFF), field(SIGNATURE_OFF + 4));
    if file.len() < insns_off.saturating_add(insns_len)
        || file.len() < sig_off.saturating_add(sig_len)
    {
        err("upatch: offsets past the file\n");
        return 2;
    }
    // An ML-DSA-87 certificate is about 7.5 KiB.
    let mut cert = vec![0u8; 16384];
    let n = match std::fs::File::open(OsStr::from_bytes(cert_path.to_bytes())) {
        Ok(mut f) => f.read(&mut cert).unwrap_or(0),
        Err(e) => {
            err(&format!(
                "open {}: {}\n",
                cert_path.to_string_lossy(),
                strerror(e.raw_os_error().unwrap_or(0))
            ));
            return 2;
        }
    };
    if n == 0 {
        err("read cert: short\n");
        return 2;
    }
    // SAFETY: C strings, the certificate's bytes and a keyring.
    if unsafe {
        libc::syscall(
            libc::SYS_add_key,
            c"asymmetric".as_ptr(),
            c"".as_ptr(),
            cert.as_ptr(),
            n,
            KEY_SPEC_SESSION_KEYRING,
        )
    } < 0
    {
        err(&format!("add_key cert: {}\n", strerror(errno())));
        return 2;
    }
    // keyring_id is the containing keyring's serial, not the key's.
    // SAFETY: a query of numbers.
    let serial = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            KEYCTL_GET_KEYRING_ID,
            KEY_SPEC_SESSION_KEYRING,
            1 as c_long,
        )
    };
    if serial < 0 {
        err(&format!("get session keyring: {}\n", strerror(errno())));
        return 2;
    }
    let ret = Attr::new()
        .u32(0, BPF_PROG_TYPE_SYSCALL)
        .u32(4, (insns_len / 8) as u32)
        .ptr(8, file[insns_off..].as_ptr())
        .ptr(16, c"Dual BSD/GPL".as_ptr())
        .u32(44, BPF_F_SLEEPABLE)
        .put(48, b"sigtest")
        .ptr(152, file[sig_off..].as_ptr())
        .u32(160, sig_len as u32)
        .u32(164, serial as u32)
        .fd(BPF_PROG_LOAD);
    match ret {
        Ok(_prog) => out("loaded\n"),
        Err(e) => out(&format!("errno={e}\n")),
    }
    0
}
