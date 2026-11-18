// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-image-keys: an image's trust set validated, and with
//! certificates for the BPF keyring, a live config update made through
//! the journal with the TPM and the keyring stood in for.
//!
//!   test-image-keys <primary cert> <image root>
//!   test-image-keys <primary cert> <image root> <journal dir> <held cert>...
//!
//! SHIRUDO_TEST_IMAGE_INTERRUPT fails the live update's first activation.

use core::ffi::{CStr, c_int, c_void};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;

use super::{helper_main, out};
use crate::errno::EIO;
use crate::util::chain::fold;
use crate::util::config_update::{
    ConfigUpdate, ConfigUpdateOps, ConfigUpdateTarget, config_update_begin, config_update_boot,
    config_update_close, config_update_complete_boot, config_update_open,
};
use crate::util::image_keys::{check_set_with, validate_set};
use crate::util::keys::{TrustedSet, read_der_bytes};

helper_main!(shirudo_helper_test_image_keys, run);

struct Context<'a> {
    set: &'a TrustedSet,
    /// The certificates the BPF keyring holds, as the command line names.
    held: &'a [&'a CStr],
    pcr: [u8; 32],
    extends: u32,
    activations: u32,
    live: bool,
    interrupt: bool,
}

/// # Safety
///
/// `opaque` is the update's Context.
unsafe fn ctx<'a>(opaque: *mut c_void) -> &'a mut Context<'a> {
    // SAFETY: the caller's.
    unsafe { &mut *opaque.cast::<Context<'a>>() }
}

/// Whether the keyring holds `der`: 1, 0, or -errno for a held
/// certificate that does not read.
fn holds(held: &[&CStr], der: &[u8]) -> c_int {
    for path in held {
        match read_der_bytes(path) {
            Ok(candidate) if candidate == der => return 1,
            Ok(_) => {}
            Err(e) => return e,
        }
    }
    0
}

unsafe extern "C" fn boot_identity(_: *mut c_void, reset: *mut u32, restart: *mut u32) -> c_int {
    // SAFETY: the journal's rooms.
    unsafe { (*reset, *restart) = (1, 1) };
    0
}

unsafe extern "C" fn pcr_read(opaque: *mut c_void, _: u32, out: *mut u8) -> c_int {
    // SAFETY: the context and the journal's 32 bytes of room.
    unsafe { core::ptr::copy_nonoverlapping(ctx(opaque).pcr.as_ptr(), out, 32) };
    0
}

unsafe extern "C" fn pcr_extend(opaque: *mut c_void, _: u32, event: *const u8) -> c_int {
    // SAFETY: the context, and the journal's event of 32 bytes.
    unsafe {
        let c = ctx(opaque);
        c.extends += 1;
        fold(c.pcr.as_mut_ptr(), event)
    }
}

unsafe extern "C" fn prepare(opaque: *mut c_void, _: *const ConfigUpdateTarget) -> c_int {
    // SAFETY: the context.
    let c = unsafe { ctx(opaque) };
    if c.live {
        check_set_with(c.set, |der| holds(c.held, der))
    } else {
        0
    }
}

unsafe extern "C" fn activate(opaque: *mut c_void, _: *const ConfigUpdateTarget) -> c_int {
    // SAFETY: the context.
    let c = unsafe { ctx(opaque) };
    c.activations += 1;
    if c.live && c.interrupt {
        c.interrupt = false;
        return -EIO;
    }
    0
}

unsafe extern "C" fn seal(_: *mut c_void, _: c_int) -> c_int {
    0
}

static OPS: ConfigUpdateOps = ConfigUpdateOps {
    boot_identity: Some(boot_identity),
    pcr_read: Some(pcr_read),
    pcr_extend: Some(pcr_extend),
    prepare: Some(prepare),
    activate: Some(activate),
    seal: Some(seal),
    checkpoint: None,
    lock_wait_ms: 0,
};

fn target(prefix: &[u8], fill: u8) -> Box<ConfigUpdateTarget> {
    let mut t = Box::new(ConfigUpdateTarget::zeroed());
    t.prefix[..prefix.len()].copy_from_slice(prefix);
    t.root_hash = [fill; 32];
    t
}

/// A boot to /verified/boot, then a live update to /verified/live,
/// in the journal at `directory`.
fn live_update(directory: &CStr, set: &TrustedSet, held: &[&CStr]) -> c_int {
    let mut c = Context {
        set,
        held,
        pcr: [0; 32],
        extends: 0,
        activations: 0,
        live: false,
        interrupt: false,
    };
    // The context, which the callbacks reach through the journal: from
    // here only through this pointer.
    let cp = &raw mut c;
    // SAFETY: an update the open fills.
    let mut update: ConfigUpdate = unsafe { core::mem::zeroed() };
    // SAFETY: a C string, the ops, the context, which outlives the
    // update, and the update to fill; the update closed after.
    unsafe {
        let mut ret = config_update_open(directory.as_ptr(), &OPS, cp.cast(), &mut update);
        if ret != 0 {
            return ret;
        }
        ret = config_update_boot(&mut update, &*target(b"/verified/boot", 1), 15);
        if ret == 0 {
            ret = config_update_complete_boot(&mut update);
        }
        (*cp).live = true;
        (*cp).interrupt = std::env::var_os("SHIRUDO_TEST_IMAGE_INTERRUPT").is_some();
        (*cp).extends = 0;
        (*cp).activations = 0;
        if ret == 0 {
            ret = config_update_begin(&mut update, &*target(b"/verified/live", 2), 15);
        }
        out(&format!(
            "extends={} activations={}\n",
            (*cp).extends,
            (*cp).activations
        ));
        config_update_close(&mut update);
        ret
    }
}

fn run(args: &[&CStr]) -> c_int {
    if args.len() != 3 && args.len() < 5 {
        return 2;
    }
    let Ok(root) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(std::ffi::OsStr::from_bytes(args[2].to_bytes()))
    else {
        return 2;
    };
    // SAFETY: a set of no member, for which zeros are the value.
    let mut set: Box<TrustedSet> = Box::new(unsafe { core::mem::zeroed() });
    let mut ret = validate_set(args[1], root.as_raw_fd(), &mut set);
    if ret == 0 && args.len() >= 5 {
        ret = live_update(args[3], &set, &args[4..]);
    }
    drop(root);
    out(&format!("rc={ret} signers={}\n", set.len()));
    c_int::from(ret != 0)
}
