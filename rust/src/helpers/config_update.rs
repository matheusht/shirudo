// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-config-update: the config update journal driven step by step
//! against a simulated TPM, which a file in the journal's directory keeps
//! across runs, or the TPM itself with SHIRUDO_TEST_CONFIG_TPM; the
//! journal's state, staged update and events printed after each step.
//!
//!   test-config-update <dir> describe|boot|update|stage|cancel-stage|staged|complete|check|inspect|reset|restart|drift|lock [<id A-Z> [<pcr>]]
//!
//! The environment makes a step fail or crash where the protocol must
//! survive it: SHIRUDO_TEST_CONFIG_{READ_FAIL,EXTEND,PREPARE_FAIL,
//! ACTIVATE_FAIL,SEAL_FAIL,STAGE_CRASH,CRASH,FAIL,BOOT_PENDING,
//! LOCK_WAIT_MS}.

use core::ffi::{CStr, c_int, c_void};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use super::{helper_main, out};
use crate::errno::{EINVAL, EIO, EKEYREJECTED, EPERM, ETIMEDOUT, EUCLEAN};
use crate::util::chain::fold;
use crate::util::config_measure::{EVENT_BOOT, event};
use crate::util::config_update::{
    ConfigUpdate, ConfigUpdateOps, ConfigUpdateRecord, ConfigUpdateTarget, config_update_begin,
    config_update_boot, config_update_check, config_update_clear_staged, config_update_close,
    config_update_complete_boot, config_update_events, config_update_open, config_update_read,
    config_update_stage, config_update_stage_read, config_update_staged,
};
use crate::util::hex::encode;
use crate::util::tpm::{Tpm, tpm_boot_identity, tpm_close, tpm_open, tpm_pcr_extend, tpm_pcr_read};
use libc::ECANCELED;

helper_main!(shirudo_helper_test_config_update, run);

/// The simulated TPM's state, kept whole in `<dir>/simulator`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Simulated {
    value: [u8; 32],
    active: [u8; 32],
    reset_count: u32,
    restart_count: u32,
    extends: u32,
    prepares: u32,
    activations: u32,
    partial: u32,
}

impl Simulated {
    fn as_bytes(&self) -> &[u8] {
        // SAFETY: a plain structure of arrays and u32s without padding,
        // whose bytes are all values.
        unsafe { core::slice::from_raw_parts((self as *const Self).cast(), size_of::<Self>()) }
    }

    fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: as as_bytes(); any bytes are a value.
        unsafe { core::slice::from_raw_parts_mut((self as *mut Self).cast(), size_of::<Self>()) }
    }
}

const _: () = assert!(size_of::<Simulated>() == 88);

struct Context<'a> {
    update: *mut ConfigUpdate,
    sim: Simulated,
    tpm: *mut Tpm,
    directory: &'a CStr,
    staging: bool,
}

fn env(name: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(name)
}

/// As strtoul() of base 10, which the C helper called: the leading
/// digits, 0 for none.
fn number(text: &[u8]) -> u64 {
    let n = text.iter().take_while(|c| c.is_ascii_digit()).count();
    std::str::from_utf8(&text[..n])
        .ok()
        .and_then(|d| d.parse().ok())
        .unwrap_or(0)
}

fn errno(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

impl Context<'_> {
    fn path(&self, name: &str) -> PathBuf {
        std::path::Path::new(OsStr::from_bytes(self.directory.to_bytes())).join(name)
    }

    /// The state written to a new file, synced, moved over the old and
    /// the directory synced.
    fn save(&self) -> c_int {
        let (path, temporary) = (self.path("simulator"), self.path("simulator.tmp"));
        let write = || -> std::io::Result<()> {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(&temporary)?;
            f.write_all(self.sim.as_bytes())?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&temporary, &path)?;
            std::fs::File::open(OsStr::from_bytes(self.directory.to_bytes()))?.sync_all()
        };
        write().map_or_else(|e| errno(&e), |()| 0)
    }

    /// The state from the file, or a fresh TPM's when there is none.
    fn load(&mut self) -> c_int {
        let mut f = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(self.path("simulator"))
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                self.sim.reset_count = 1;
                return 0;
            }
            Err(e) => return errno(&e),
        };
        match f.read(self.sim.as_bytes_mut()) {
            Ok(n) if n == size_of::<Simulated>() => 0,
            _ => -EIO,
        }
    }

    fn pcr_read(&self, pcr: u32, out: &mut [u8; 32]) -> c_int {
        if env("SHIRUDO_TEST_CONFIG_READ_FAIL").is_some() {
            return -EIO;
        }
        if !self.tpm.is_null() {
            // SAFETY: the connection and 32 bytes of room.
            return unsafe { tpm_pcr_read(self.tpm, pcr, out.as_mut_ptr()) };
        }
        *out = self.sim.value;
        0
    }
}

/// # Safety
///
/// `opaque` is the journal's Context.
unsafe fn ctx<'a>(opaque: *mut c_void) -> &'a mut Context<'a> {
    // SAFETY: the caller's.
    unsafe { &mut *opaque.cast::<Context<'a>>() }
}

unsafe extern "C" fn boot_identity(
    opaque: *mut c_void,
    reset: *mut u32,
    restart: *mut u32,
) -> c_int {
    // SAFETY: the context and the journal's rooms.
    unsafe {
        let c = ctx(opaque);
        if !c.tpm.is_null() {
            return tpm_boot_identity(c.tpm, reset, restart);
        }
        (*reset, *restart) = (c.sim.reset_count, c.sim.restart_count);
    }
    0
}

unsafe extern "C" fn pcr_read(opaque: *mut c_void, pcr: u32, out: *mut u8) -> c_int {
    // SAFETY: the context and the journal's 32 bytes of room.
    unsafe { ctx(opaque).pcr_read(pcr, &mut *out.cast::<[u8; 32]>()) }
}

unsafe extern "C" fn pcr_extend(opaque: *mut c_void, pcr: u32, event: *const u8) -> c_int {
    let mode = env("SHIRUDO_TEST_CONFIG_EXTEND");
    let mode = mode.as_deref().map(OsStr::as_bytes);
    // SAFETY: the context.
    let c = unsafe { ctx(opaque) };
    c.sim.extends += 1;
    let mut ret = c.save();
    if ret != 0 {
        return ret;
    }
    if mode == Some(b"before") {
        return -EIO;
    }
    let mut wrong = [0u8; 32];
    wrong[0] = 1;
    let event = if mode == Some(b"drift") {
        wrong.as_ptr()
    } else {
        event
    };
    // SAFETY: the connection or the simulated value, and the event's 32
    // bytes.
    ret = unsafe {
        if c.tpm.is_null() {
            fold(&mut c.sim.value, &*event.cast::<[u8; 32]>())
        } else {
            tpm_pcr_extend(c.tpm, pcr, event)
        }
    };
    if ret == 0 {
        ret = c.save();
    }
    if ret == 0 && mode == Some(b"ambiguous") {
        return -ETIMEDOUT;
    }
    ret
}

fn prefix(t: &ConfigUpdateTarget) -> &[u8] {
    crate::text::cstr(&t.prefix)
}

unsafe extern "C" fn prepare(opaque: *mut c_void, target: *const ConfigUpdateTarget) -> c_int {
    // SAFETY: the context and the journal's target.
    let (c, target) = unsafe { (ctx(opaque), &*target) };
    c.sim.prepares += 1;
    let ret = c.save();
    if ret != 0 {
        return ret;
    }
    if env("SHIRUDO_TEST_CONFIG_PREPARE_FAIL").is_some() {
        return -EKEYREJECTED;
    }
    let p = prefix(target);
    match p.strip_prefix(b"/verified/config-") {
        Some(&[id]) if target.root_hash.iter().all(|&b| b == id) => 0,
        _ => -EKEYREJECTED,
    }
}

unsafe extern "C" fn activate(opaque: *mut c_void, target: *const ConfigUpdateTarget) -> c_int {
    // SAFETY: the context and the journal's target.
    let (c, target) = unsafe { (ctx(opaque), &*target) };
    let mut record = ConfigUpdateRecord::zeroed();
    let mut live = [0u8; 32];
    // SAFETY: the journal open, and room for its record.
    let mut ret = unsafe { config_update_read(c.update, &mut record) };
    if ret == 0 {
        ret = c.pcr_read(record.pcr, &mut live);
    }
    if ret != 0 {
        return ret;
    }
    if !record.pending || target.root_hash != record.target.root_hash {
        return -EUCLEAN;
    }
    c.sim.activations += 1;
    c.sim.partial = prefix(target).last().copied().map_or(0, u32::from);
    let ret = c.save();
    if ret != 0 {
        return ret;
    }
    if env("SHIRUDO_TEST_CONFIG_ACTIVATE_FAIL").is_some() {
        return -EIO;
    }
    c.sim.active = target.root_hash;
    c.sim.partial = 0;
    c.save()
}

unsafe extern "C" fn seal(opaque: *mut c_void, _: c_int) -> c_int {
    // SAFETY: the context.
    if unsafe { ctx(opaque) }.staging && env("SHIRUDO_TEST_CONFIG_STAGE_CRASH").is_some() {
        // SAFETY: the process gone mid-protocol, as a crash leaves it.
        unsafe { libc::_exit(99) };
    }
    if env("SHIRUDO_TEST_CONFIG_SEAL_FAIL").is_some() {
        -EPERM
    } else {
        0
    }
}

unsafe extern "C" fn checkpoint(_: *mut c_void, checkpoint: c_int) -> c_int {
    let at = |name| env(name).is_some_and(|v| number(v.as_bytes()) == checkpoint as u64);
    if at("SHIRUDO_TEST_CONFIG_CRASH") {
        // SAFETY: the process gone at the checkpoint, as a crash leaves it.
        unsafe { libc::_exit(99) };
    }
    if at("SHIRUDO_TEST_CONFIG_FAIL") {
        -ECANCELED
    } else {
        0
    }
}

static OPS: ConfigUpdateOps = ConfigUpdateOps {
    boot_identity: Some(boot_identity),
    pcr_read: Some(pcr_read),
    pcr_extend: Some(pcr_extend),
    prepare: Some(prepare),
    activate: Some(activate),
    seal: Some(seal),
    checkpoint: Some(checkpoint),
    lock_wait_ms: 0,
};

fn target(id: u8) -> ConfigUpdateTarget {
    let mut t = ConfigUpdateTarget::zeroed();
    let p = format!("/verified/config-{}", id as char);
    t.prefix[..p.len()].copy_from_slice(p.as_bytes());
    t.root_hash = [id; 32];
    t
}

fn hex(b: &[u8]) -> String {
    String::from_utf8_lossy(&encode(b)).into_owned()
}

unsafe extern "C" fn show_event(record: *const ConfigUpdateRecord, opaque: *mut c_void) -> c_int {
    // SAFETY: the walk's record and the count inspect() hands it.
    let (r, count) = unsafe { (&*record, &mut *opaque.cast::<u32>()) };
    out(&format!(
        "event={}:{}:{}:{}:{}\n",
        r.sequence,
        r.reset_count,
        r.pcr,
        r.kind,
        hex(&r.target.root_hash)
    ));
    *count += 1;
    0
}

fn inspect(c: &Context<'_>) {
    out(&format!(
        "extends={}\nprepares={}\nactivations={}\npartial={}\n",
        c.sim.extends, c.sim.prepares, c.sim.activations, c.sim.partial
    ));
    let mut value = [0u8; 32];
    if c.pcr_read(15, &mut value) == 0 {
        out(&format!("pcr_value={}\n", hex(&value)));
    }
    let mut record = ConfigUpdateRecord::zeroed();
    // SAFETY: the journal open, and room for its record.
    let ret = unsafe { config_update_read(c.update, &mut record) };
    out(&format!("state_rc={ret}\n"));
    if ret == 0 {
        out(&format!(
            "sequence={}\npending={}\nkind={}\npcr={}\nreset={}\nprefix={}\nrestart={}\ninitial_pcr={}\nroot_hash={}\n",
            record.sequence,
            u32::from(record.pending),
            record.kind,
            record.pcr,
            record.reset_count,
            String::from_utf8_lossy(prefix(&record.target)),
            record.restart_count,
            hex(&record.initial_pcr),
            hex(&record.target.root_hash)
        ));
    }
    // SAFETY: as above.
    let ret = unsafe { config_update_stage_read(c.update, &mut record) };
    out(&format!("stage_rc={ret}\n"));
    if ret == 0 {
        out(&format!(
            "stage_prefix={}\nstage_sequence={}\n",
            String::from_utf8_lossy(prefix(&record.target)),
            record.sequence
        ));
    }
    let mut count = 0u32;
    // SAFETY: the journal, the callback and its count.
    let ret = unsafe { config_update_events(c.update, Some(show_event), (&raw mut count).cast()) };
    out(&format!("events_rc={ret}\nevents={count}\n"));
}

fn describe(t: &ConfigUpdateTarget) -> c_int {
    out(&format!("root_hash={}\n", hex(&t.root_hash)));
    match event(EVENT_BOOT, &t.root_hash) {
        Ok(e) => {
            out(&format!("boot_event={}\n", hex(&e)));
            0
        }
        Err(_) => 1,
    }
}

/// The step `how`, on the journal open in `c`.
fn step(c: &mut Context<'_>, how: &[u8], dir: &CStr, mut t: ConfigUpdateTarget, pcr: u32) -> c_int {
    let update = c.update;
    // SAFETY: the journal open, its target and rooms.
    unsafe {
        match how {
            b"boot" => {
                let ret = config_update_boot(update, &t, pcr);
                if ret == 0 && env("SHIRUDO_TEST_CONFIG_BOOT_PENDING").is_none() {
                    return config_update_complete_boot(update);
                }
                ret
            }
            b"update" => config_update_begin(update, &t, pcr),
            b"stage" => {
                c.staging = true;
                config_update_stage(update, &t)
            }
            b"cancel-stage" => config_update_clear_staged(update),
            b"staged" => {
                let mut previous = ConfigUpdateRecord::zeroed();
                let mut ret = config_update_read(update, &mut previous);
                if ret == 0 {
                    ret = config_update_staged(update, &previous, c.sim.reset_count, &mut t);
                }
                out(&format!("eligible={ret}\n"));
                if ret == 1 {
                    out(&format!(
                        "candidate={}\n",
                        String::from_utf8_lossy(prefix(&t))
                    ));
                    return 0;
                }
                ret
            }
            b"complete" => config_update_complete_boot(update),
            b"check" => config_update_check(update, core::ptr::null_mut()),
            b"inspect" => 0,
            b"reset" | b"restart" | b"resume" | b"drift" => {
                match how {
                    b"reset" => c.sim.reset_count += 1,
                    b"restart" | b"resume" => c.sim.restart_count += 1,
                    _ => {}
                }
                if how != b"resume" {
                    c.sim.value = [if how == b"drift" { 0x55 } else { 0 }; 32];
                }
                c.save()
            }
            b"lock" => {
                let mut second = ConfigUpdate::closed();
                let ret = config_update_open(
                    dir.as_ptr(),
                    &OPS,
                    (c as *mut Context<'_>).cast(),
                    &mut second,
                );
                config_update_close(&mut second);
                ret
            }
            _ => -EINVAL,
        }
    }
}

fn run(args: &[&CStr]) -> c_int {
    if !(3..=5).contains(&args.len()) {
        return 2;
    }
    let id = match args.get(3).map(|a| a.to_bytes()) {
        None => b'A',
        Some(&[id @ b'A'..=b'Z']) => id,
        Some(_) => return 2,
    };
    let pcr = args.get(4).map_or(15, |p| number(p.to_bytes()) as u32);
    let t = target(id);
    let how = args[2].to_bytes();
    if how == b"describe" {
        return describe(&t);
    }

    let mut update = ConfigUpdate::closed();
    let mut c = Context {
        update: &raw mut update,
        sim: Simulated::default(),
        tpm: core::ptr::null_mut(),
        directory: args[1],
        staging: false,
    };
    let ret = 'out: {
        let ret = c.load();
        if ret != 0 {
            break 'out ret;
        }
        if env("SHIRUDO_TEST_CONFIG_TPM").is_some() {
            // SAFETY: room for the connection, closed at the end.
            let ret = unsafe { tpm_open(&mut c.tpm) };
            if ret != 0 {
                break 'out ret;
            }
        }
        // The ops with the lock wait the environment asks for; the
        // journal keeps a pointer to them while open, so they live here.
        let ops = ConfigUpdateOps {
            lock_wait_ms: env("SHIRUDO_TEST_CONFIG_LOCK_WAIT_MS")
                .map_or(0, |v| number(v.as_bytes()) as u32),
            ..OPS
        };
        let cp: *mut Context<'_> = &raw mut c;
        // SAFETY: a C string, the ops and the context, which outlive the
        // journal, and the journal to fill, closed after.
        unsafe {
            let ret = config_update_open(args[1].as_ptr(), &ops, cp.cast(), (*cp).update);
            if ret != 0 {
                break 'out ret;
            }
            let ret = step(&mut *cp, how, args[1], t, pcr);
            inspect(&*cp);
            config_update_close((*cp).update);
            ret
        }
    };
    if !c.tpm.is_null() {
        // SAFETY: the connection tpm_open() gave, closed once.
        unsafe { tpm_close(c.tpm) };
    }
    out(&format!("rc={ret}\n"));
    c_int::from(ret != 0)
}
