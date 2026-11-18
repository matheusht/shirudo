// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-config-attest: the config evidence `shirudo attest` gives for a
//! journal rendered, or a document of it parsed and replayed against a
//! quote's PCRs and boot.
//!
//!   test-config-attest render <journal dir> <nonce hex>
//!   test-config-attest parse <evidence>
//!   test-config-attest replay <evidence> <root hex|-> <pcr|-> <reset> <restart> <pcr value hex>

use core::ffi::{CStr, c_char, c_int, c_void};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use super::{err, helper_main, out};
use crate::errno::{EINVAL, EIO, EPERM};
use crate::heap::xfree;
use crate::util::attest::{NONCE_MAX, evidence_config};
use crate::util::chain::PCR_MASK;
use crate::util::config_attest::{Evidence, Quote, clear, parse, verify};
use crate::util::config_measure::nvpcr;
use crate::util::config_update::{
    ConfigUpdate, ConfigUpdateOps, ConfigUpdateTarget, config_update_close, config_update_open,
};
use crate::util::json::MAX_BYTES;
use crate::util::tpm::{Tpm, tpm_boot_identity, tpm_close, tpm_open, tpm_pcr_read};

helper_main!(shirudo_helper_test_config_attest, run);

/// `read` of a TPM connection opened for it and closed after.
fn with_tpm(read: impl FnOnce(*mut Tpm) -> c_int) -> c_int {
    let mut tpm: *mut Tpm = core::ptr::null_mut();
    // SAFETY: room for the connection, closed once, after.
    unsafe {
        let mut ret = tpm_open(&mut tpm);
        if ret == 0 {
            ret = read(tpm);
        }
        tpm_close(tpm);
        ret
    }
}

unsafe extern "C" fn boot_identity(_: *mut c_void, reset: *mut u32, restart: *mut u32) -> c_int {
    // SAFETY: a connection and the journal's rooms.
    with_tpm(|tpm| unsafe { tpm_boot_identity(tpm, reset, restart) })
}

unsafe extern "C" fn pcr_read(_: *mut c_void, pcr: u32, out: *mut u8) -> c_int {
    // SAFETY: a connection and the journal's 32 bytes of room.
    with_tpm(|tpm| unsafe { tpm_pcr_read(tpm, pcr, out) })
}

unsafe extern "C" fn no_extend(_: *mut c_void, _: u32, _: *const u8) -> c_int {
    -EPERM
}

unsafe extern "C" fn no_activate(_: *mut c_void, _: *const ConfigUpdateTarget) -> c_int {
    -EPERM
}

unsafe extern "C" fn no_seal(_: *mut c_void, _: c_int) -> c_int {
    0
}

/// A journal read, as attest reads it, that changes nothing.
static OPS: ConfigUpdateOps = ConfigUpdateOps {
    boot_identity: Some(boot_identity),
    pcr_read: Some(pcr_read),
    pcr_extend: Some(no_extend),
    prepare: Some(no_activate),
    activate: Some(no_activate),
    seal: Some(no_seal),
    checkpoint: None,
    lock_wait_ms: 0,
};

fn render(directory: &CStr, nonce_hex: &CStr) -> c_int {
    let hex = nonce_hex.to_bytes();
    let mut nonce = [0u8; NONCE_MAX];
    let n = hex.len() / 2;
    if hex.len() % 2 != 0
        || n > NONCE_MAX
        || crate::util::hex::decode(hex, &mut nonce[..n]).is_err()
    {
        return -EINVAL;
    }
    let mut update = ConfigUpdate::closed();
    let (mut doc, mut len, mut cap): (*mut c_char, usize, usize) = (core::ptr::null_mut(), 0, 0);
    // SAFETY: a C string, the ops, the journal to fill, the nonce, and
    // rooms for the document, which is freed and the journal closed after.
    unsafe {
        let mut ret =
            config_update_open(directory.as_ptr(), &OPS, core::ptr::null_mut(), &mut update);
        if ret == 0 {
            ret = evidence_config(
                nonce.as_ptr(),
                n,
                PCR_MASK,
                core::ptr::null(),
                &mut update,
                &mut doc,
                &mut len,
                &mut cap,
            );
        }
        if ret == 0 {
            ret = crate::util::io::write_complete(libc::STDOUT_FILENO, doc.cast(), len);
        }
        xfree(doc.cast(), cap);
        config_update_close(&mut update);
        ret
    }
}

/// The evidence document at `path`: a regular file of 1 to MAX_BYTES
/// bytes, not followed through a link.
fn read_document(path: &CStr) -> Result<Vec<u8>, c_int> {
    use std::io::Read;
    let errno = |e: std::io::Error| -e.raw_os_error().unwrap_or(EIO);
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(OsStr::from_bytes(path.to_bytes()))
        .map_err(errno)?;
    let size = file.metadata().map_err(|_| -EINVAL)?.len();
    if size == 0 || size > MAX_BYTES as u64 {
        return Err(-EINVAL);
    }
    let mut doc = vec![0u8; size as usize];
    file.read_exact(&mut doc).map_err(|_| -EIO)?;
    Ok(doc)
}

/// As strtoul() of base 10, which the C helper called: the leading
/// digits, 0 for none.
fn number(text: &CStr) -> u64 {
    let digits: Vec<u8> = text
        .to_bytes()
        .iter()
        .copied()
        .take_while(u8::is_ascii_digit)
        .collect();
    std::str::from_utf8(&digits)
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(0)
}

/// The evidence replayed: args are the evidence, root, pcr, reset,
/// restart and PCR value; the reason printed.
fn replay(config: &Evidence, args: &[&CStr]) -> c_int {
    let [root_hex, pcr_arg, reset, restart, value] = args else {
        return -EINVAL;
    };
    let mut pcrs = [[0u8; 32]; 24];
    let mut root = [0u8; 32];
    let mut certified = [0u8; 32];
    let is_nvpcr = nvpcr(config.pcr);
    let no_root = root_hex.to_bytes() == b"-";
    if (!is_nvpcr && config.pcr >= 24)
        || (!no_root && crate::util::hex::decode(root_hex.to_bytes(), &mut root).is_err())
        || crate::util::hex::decode(
            value.to_bytes(),
            if is_nvpcr {
                &mut certified
            } else {
                &mut pcrs[config.pcr as usize]
            },
        )
        .is_err()
    {
        return -EINVAL;
    }
    // As atoi(): a number, which a PCR index fits.
    let pcr: c_int = if pcr_arg.to_bytes() == b"-" {
        -1
    } else {
        number(pcr_arg) as c_int
    };
    let mask_pcr = if pcr < 0 { config.pcr } else { pcr as u32 };
    let quote = Quote {
        mask: if is_nvpcr {
            0
        } else {
            1u32.checked_shl(mask_pcr).unwrap_or(0)
        },
        reset: number(reset) as u32,
        pcrs: &pcrs,
        nvpcr: is_nvpcr.then_some(&certified),
    };
    let _ = restart; // Kept in the helper CLI for existing replay commands.
    let (ret, reason) = verify(config, &quote, (!no_root).then_some(&root), pcr);
    out(&format!("reason={}\n", reason.to_string_lossy()));
    ret
}

fn run(args: &[&CStr]) -> c_int {
    if let [_, how, directory, nonce] = args
        && how.to_bytes() == b"render"
    {
        let ret = render(directory, nonce);
        if ret != 0 {
            err(&format!("render failed: {ret}\n"));
        }
        return c_int::from(ret != 0);
    }
    if args.len() != 3 && args.len() != 8 {
        return 2;
    }
    // SAFETY: evidence of nothing, for which zeros are the value, cleared
    // whatever the parse left in it.
    let mut config: Evidence = unsafe { core::mem::zeroed() };
    let ret = match read_document(args[2]) {
        // SAFETY: the document and the evidence to fill.
        Ok(doc) => match unsafe { parse(&doc, &mut config) } {
            0 if args.len() == 8 && args[1].to_bytes() == b"replay" => replay(&config, &args[3..]),
            0 if args[1].to_bytes() != b"parse" => -EINVAL,
            ret => ret,
        },
        Err(e) => e,
    };
    out(&format!("rc={ret}\n"));
    // SAFETY: the evidence the parse filled.
    unsafe { clear(&mut config) };
    c_int::from(ret != 0)
}
