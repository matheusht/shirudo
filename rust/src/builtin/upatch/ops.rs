// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch load` and `unload`, and the installs, removals and
//! purges of bpm and keys, which take the same path: the operations that
//! move the measurement register.
//!
//! An operation stages the operator's file, so that what is measured,
//! loaded and archived all come from one read. It checks the target
//! against the caller's expectations and the anchor init froze, and
//! takes the register lock. Under the lock it undoes whatever an
//! earlier, stopped operation left that this boot's records do not
//! cover. The signed loader then loads or verifies.
//! A load archives before it extends the register, and is undone when
//! either fails, so that nothing runs unmeasured. An unload extends
//! before it detaches, so that the register never misses a detach.

use core::ffi::{CStr, c_char, c_int, c_void};
use std::ffi::CString;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;

use super::list::{BPFFS_UPATCHES_DIR, UPATCHES_DIR};
use super::{hex, log_audit, log_err, log_info, log_warn, strerr};
use crate::errno::{
    EACCES, EBADMSG, EINVAL, ENAMETOOLONG, ENODEV, ENOENT, ENOSPC, EOPNOTSUPP, EPERM, ESTALE,
};
use crate::heap::xfree;
use crate::sys::libc::{close, errno, getxattr};
use crate::sys::upatch::UPATCH_INSTALL_TARGET_MISSING;
use crate::sys::version::shirudo_version_id;
use crate::text::cstr;
use crate::util::bpf_sys::bpf_obj_get;
use crate::util::chain::{chain_extend, chain_read, chain_upatch_event, memneq_explicit};
use crate::util::config::{self, Scrubbed};
use crate::util::crypto_openssl::{Cert, cms_signed_by};
use crate::util::eventlog::{
    eventlog_append, eventlog_lock, eventlog_path, eventlog_record_open, eventlog_unlock,
    eventlog_would_exceed,
};
use crate::util::help::{Help, HelpSection};
use crate::util::hex::hex_decode;
use crate::util::io::read_file;
use crate::util::json::JsonEmit;
use crate::util::kernel_abi::kernel_abi_check;
use crate::util::measured::{
    MeasuredSet, measured_set_boot, measured_set_free, measured_unmeasured_archives,
    measured_unmeasured_pins,
};
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::report::{OpReport, report_emit, report_free};
use crate::util::seal::{seal_mkdir_p, seal_open_read, seal_write_file};
use crate::util::upatch::{
    self, NAME_MAX, Opened, Upatch, name_valid, pin_name, upatch_open_memory, upatch_signature,
};
use crate::util::upatch_resolve::XATTR_PAYLOAD;
use crate::util::upatch_verify::archive_verify;

/// LSM_LINK_PIN and XATTR_PAYLOAD of util/paths.h, and the most a
/// .upatch file holds.
const UPATCHES_DIR_C: &CStr = c"/var/lib/shirudo/upatches";
pub(super) const LSM_LINK_PIN: &CStr = c"/run/shirudo/bpffs/lsm_link";
const UPATCH_FILE_MAX: usize = 16 * 1024 * 1024;
const DIGEST_LEN: usize = 32;
const KERNEL_ABI_DETAIL_MAX: usize = 256;

/// What a load or an unload is asked to do.
#[derive(Default)]
struct OpArgs<'a> {
    file: Option<&'a CStr>,
    expect_chain: Option<&'a CStr>,
    expect_version_id: Option<&'a CStr>,
    report: Option<&'a CStr>,
    no_precheck: bool,
    no_version_check: bool,
    /// An install of the very payload loaded is done.
    loaded_is_done: bool,
}

const OP_EXPECT_CHAIN: c_int = 0;
const OP_EXPECT_VERSION_ID: c_int = 1;
const OP_NO_PRECHECK: c_int = 2;
const OP_NO_VERSION_CHECK: c_int = 3;
const OP_REPORT: c_int = 4;

static OP_OPTS: [OptSpec; 5] = [
    OptSpec::new(
        c"--expect-chain",
        0,
        0,
        Some(c"<hex>"),
        c"refuse unless the register holds this value before",
    ),
    OptSpec::new(
        c"--expect-version-id",
        0,
        0,
        Some(c"<hex>"),
        c"refuse unless this binary's SHIRUDO_VERSION_ID is this",
    ),
    OptSpec::new(
        c"--no-precheck",
        0,
        0,
        None,
        c"skip the pre-flight checks, --expect-chain included",
    ),
    OptSpec::new(
        c"--no-version-check",
        0,
        0,
        None,
        c"skip the --expect-version-id comparison",
    ),
    OptSpec::new(
        c"--report",
        0,
        0,
        Some(c"<path>"),
        c"write the JSON report there, - for standard output",
    ),
];

static OP_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &OP_OPTS)];

static LOAD_HELP: Help = Help::new(
    c"shirudo upatch load [--expect-chain=<hex>] [--expect-version-id=<hex>]\n                       \
      [--no-precheck] [--no-version-check] [--report=<path>]\n                       \
      <file.upatch>",
    Some(
        c"Load a signed LOAD .upatch into the target kernel: verify the\n\
          signature, run the loader, pin the resulting link, and extend this\n\
          boot's TPM measurement register. Target-only.",
    ),
    &OP_SECTIONS,
    Some(
        c"Examples:\n  shirudo upatch load cve-2026-31431.upatch\n  \
          shirudo upatch load --expect-chain=$(...) foo.upatch\n  \
          shirudo upatch load --report=- foo.upatch | jq",
    ),
);

static UNLOAD_HELP: Help = Help::new(
    c"shirudo upatch unload [--expect-chain=<hex>] [--expect-version-id=<hex>]\n                       \
      [--no-precheck] [--no-version-check] [--report=<path>]\n                       \
      <unload-directive.upatch>",
    Some(
        c"Apply a signed UNLOAD directive: detach the named upatch,\n\
          remove its pin, and extend the TPM measurement register (unloads\n\
          move the register forward, never roll it back). Target-only.",
    ),
    &OP_SECTIONS,
    Some(
        c"Examples:\n  shirudo upatch unload cve-2026-31431.unload.upatch\n  \
          shirudo upatch unload --report=- foo.unload.upatch | jq",
    ),
);

/// The options and the file of a load or an unload, or how the command
/// exits without running: 0 after help.
fn parse<'a>(args: &'a [*const c_char], unload: bool) -> Result<OpArgs<'a>, c_int> {
    let (command, help) = if unload {
        (c"upatch unload", &UNLOAD_HELP)
    } else {
        (c"upatch load", &LOAD_HELP)
    };
    let mut p = OptParser::new(command, &OP_OPTS, Some(help), args, 1);
    let mut o = OpArgs::default();

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            OP_EXPECT_CHAIN => {
                if value.and_then(decode_chain).is_none() {
                    p.usage(
                        format!(
                            "--expect-chain must be {} hexadecimal characters",
                            2 * DIGEST_LEN
                        )
                        .as_bytes(),
                    );
                    return Err(EXIT_USAGE);
                }
                o.expect_chain = value;
            }
            OP_EXPECT_VERSION_ID => o.expect_version_id = value,
            OP_NO_PRECHECK => o.no_precheck = true,
            OP_NO_VERSION_CHECK => o.no_version_check = true,
            OP_REPORT => o.report = value,
            OPT_ARG => {
                if o.file.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return Err(EXIT_USAGE);
                }
                o.file = value;
            }
            OPT_DONE => return Err(0),
            _ => return Err(EXIT_USAGE),
        }
    }
    if o.file.is_none() {
        p.usage(b"takes the .upatch file");
        return Err(EXIT_USAGE);
    }
    Ok(o)
}

/// The register value a caller expects, as hex_decode() reads it.
fn decode_chain(hex: &CStr) -> Option<[u8; DIGEST_LEN]> {
    let mut want = [0u8; DIGEST_LEN];
    // SAFETY: a C string and room for the digest.
    (unsafe { hex_decode(hex.as_ptr(), want.as_mut_ptr(), DIGEST_LEN) } == 0).then_some(want)
}

/// Records a failure in the report.
pub(super) fn fail(
    rep: &mut OpReport,
    phase: &'static CStr,
    category: &'static CStr,
    err: c_int,
    message: &[u8],
) {
    rep.ok = false;
    rep.phase = phase.as_ptr();
    rep.category = category.as_ptr();
    rep.err = err.abs();
    let n = message.len().min(rep.message.len() - 1);
    for (d, &s) in rep.message.iter_mut().zip(&message[..n]) {
        *d = s as c_char;
    }
    rep.message[n] = 0;
}

fn category_is(rep: &OpReport, category: &[u8]) -> bool {
    // SAFETY: a static C string, when set.
    !rep.category.is_null() && unsafe { crate::ffi::c_str(rep.category) } == category
}

/// The version gate, which runs first: a caller built from other sources
/// than this target makes every later comparison meaningless.
fn version_gate(a: &OpArgs, rep: &mut OpReport, op: &[u8]) -> Result<(), ()> {
    let Some(want) = a.expect_version_id.filter(|_| !a.no_version_check) else {
        return Ok(());
    };
    // SAFETY: the build's version ID, a C string.
    let have = unsafe { CStr::from_ptr(&raw const shirudo_version_id) };
    if want == have {
        return Ok(());
    }
    log_err(
        &[
            b"upatch ",
            op,
            b": version mismatch, the operator expects ",
            want.to_bytes(),
            b" and the target is ",
            have.to_bytes(),
            b"; deploy a matching shirudo or pass --no-version-check",
        ]
        .concat(),
    );
    fail(
        rep,
        c"pre_flight",
        c"version_mismatch",
        EPERM,
        b"SHIRUDO_VERSION_ID mismatch (operator vs target)",
    );
    Err(())
}

/// The file at `path`, at most UPATCH_FILE_MAX bytes of it, or -errno.
fn read(path: &CStr) -> Result<Vec<u8>, c_int> {
    let (mut buf, mut len): (*mut u8, usize) = (core::ptr::null_mut(), 0);
    // SAFETY: a C string and room for the buffer and its length.
    let ret = unsafe {
        read_file(
            path.as_ptr(),
            UPATCH_FILE_MAX,
            (&raw mut buf).cast(),
            &mut len,
        )
    };
    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the len bytes read.
    let data = unsafe { crate::ffi::slice(buf, len) }.to_vec();
    // SAFETY: the buffer and its NUL, freed once.
    unsafe { xfree(buf.cast(), len + 1) };
    Ok(data)
}

/// Writes `data` to `path` through the seal: 0 or -errno.
fn write(path: &CStr, data: &[u8], mode: u32) -> c_int {
    // SAFETY: a C string and the bytes.
    unsafe { seal_write_file(path.as_ptr(), data.as_ptr().cast(), data.len(), mode) }
}

fn mkdir(path: &CStr) -> c_int {
    // SAFETY: a C string.
    unsafe { seal_mkdir_p(path.as_ptr(), 0o700) }
}

fn archive_path(name: &[u8]) -> CString {
    CString::new([UPATCHES_DIR.as_bytes(), b"/", name, b".upatch"].concat()).unwrap_or_default()
}

/// Archives the bytes a load read for boot restore: 0 or -errno.
fn persist(data: &[u8], name: &[u8]) -> c_int {
    let ret = mkdir(UPATCHES_DIR_C);
    if ret != 0 {
        log_err(&[b"mkdir ", UPATCHES_DIR.as_bytes(), b": ", strerr(-ret)].concat());
        return ret;
    }
    write(&archive_path(name), data, 0o644)
}

fn os(b: &[u8]) -> &OsStr {
    OsStr::from_bytes(b)
}

fn io_err(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(crate::errno::EIO)
}

/// The pin directory of upatch `name`.
fn pin_dir(name: &[u8]) -> Vec<u8> {
    [BPFFS_UPATCHES_DIR.as_bytes(), b"/", &pin_name(name)].concat()
}

/// Whether the upatch has its pin directory, loaded or part way there.
fn is_pinned(name: &[u8]) -> bool {
    fs::metadata(os(&pin_dir(name))).is_ok()
}

/// Removes the entries of `dir`, none a directory, and then `dir`.
fn wipe(dir: &[u8]) -> c_int {
    let entries = match fs::read_dir(os(dir)) {
        Ok(d) => d,
        Err(e) => return io_err(&e),
    };
    for e in entries.map_while(Result::ok) {
        if let Err(e) = fs::remove_file(e.path()) {
            if e.raw_os_error() != Some(ENOENT) {
                return io_err(&e);
            }
        }
    }
    match fs::remove_dir(os(dir)) {
        Err(e) if e.raw_os_error() != Some(ENOENT) => io_err(&e),
        _ => 0,
    }
}

/// Removes the pins of upatch `name`. Unlinking the link pin drops its
/// last reference, which detaches.
pub(super) fn remove_pins(name: &[u8]) -> c_int {
    let dir = pin_dir(name);
    if let Err(e) = fs::metadata(os(&dir)) {
        return io_err(&e);
    }
    for sub in [&b"/maps"[..], b"/serializers"] {
        let sub = [&dir[..], sub].concat();
        if fs::metadata(os(&sub)).is_ok() {
            let ret = wipe(&sub);
            if ret != 0 {
                return ret;
            }
        }
    }
    wipe(&dir)
}

/// The payload digest recorded on the pins of upatch `name`, the value
/// bpf2's xattr guard keeps unforgeable, or -errno.
fn pin_payload(name: &[u8]) -> Result<[u8; DIGEST_LEN], c_int> {
    let dir = CString::new(pin_dir(name)).map_err(|_| -EINVAL)?;
    let mut out = [0u8; DIGEST_LEN];
    // SAFETY: two C strings and room for the digest.
    let n = unsafe {
        getxattr(
            dir.as_ptr(),
            XATTR_PAYLOAD.as_ptr(),
            out.as_mut_ptr().cast(),
            DIGEST_LEN,
        )
    };
    match n {
        n if n < 0 => Err(-errno()),
        32 => Ok(out),
        _ => Err(-EINVAL),
    }
}

/// Takes a load the register did not record back out: pins, then
/// archive.
fn undo_load(name: &[u8]) -> c_int {
    let ret = remove_pins(name);
    if ret != 0 {
        return ret;
    }
    match fs::remove_file(os(archive_path(name).to_bytes())) {
        Err(e) if e.raw_os_error() != Some(ENOENT) => io_err(&e),
        _ => 0,
    }
}

fn unload_unmeasured(name: &[u8]) {
    match undo_load(name) {
        0 => log_err(
            &[
                b"upatch load: ",
                name,
                b" was not measured; the load was undone",
            ]
            .concat(),
        ),
        err => log_err(
            &[
                b"upatch load: ",
                name,
                b" is loaded but not measured and could not be undone: ",
                strerr(-err),
                b"; operator must reconcile",
            ]
            .concat(),
        ),
    }
}

/// An undo pass callback: the rest are still undone when one fails, and
/// `ctx` keeps the first error.
unsafe extern "C" fn undo_pin(name: *const c_char, ctx: *mut c_void) -> c_int {
    // SAFETY: the walk's C string and the pass's first error.
    let (name, failed) = unsafe { (crate::ffi::c_str(name), &mut *ctx.cast::<c_int>()) };
    match undo_load(name) {
        0 => log_audit(
            &[
                b"upatch: ",
                name,
                b" was pinned without a record of this boot; the load was undone",
            ]
            .concat(),
        ),
        err => {
            log_err(
                &[
                    b"upatch: ",
                    name,
                    b" is pinned without a record of this boot and could not be undone: ",
                    strerr(-err),
                    b"; operator must reconcile",
                ]
                .concat(),
            );
            if *failed == 0 {
                *failed = err;
            }
        }
    }
    0
}

/// As [`undo_pin`], for an archive no record covers.
unsafe extern "C" fn undo_archive(
    name: *const c_char,
    path: *const c_char,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: the walk's C strings and the pass's first error.
    let (name, path, failed) = unsafe {
        (
            crate::ffi::c_str(name),
            crate::ffi::c_str(path),
            &mut *ctx.cast::<c_int>(),
        )
    };
    match fs::remove_file(os(path)) {
        Err(e) if e.raw_os_error() != Some(ENOENT) => {
            let err = io_err(&e);
            log_err(
                &[
                    b"upatch: ",
                    name,
                    b" is archived without a record of its load and could not be removed: ",
                    strerr(-err),
                    b"; operator must reconcile",
                ]
                .concat(),
            );
            if *failed == 0 {
                *failed = err;
            }
        }
        _ => log_audit(
            &[
                b"upatch: ",
                name,
                b" was archived without a record of its load; the archive was removed",
            ]
            .concat(),
        ),
    }
    0
}

/// Undoes what earlier operations left that this boot's records do not
/// cover: a load a signal stopped between its pins and its extend, an
/// unload stopped between its append and its detach, an archive brought
/// back after its unload. It runs under the register lock a load holds
/// from before its pins to its append, so that it never takes a load in
/// flight for a stopped one. An operation whose pass fails refuses: a
/// load beside such pins could share their directory under one name.
fn undo_unmeasured(rep: &mut OpReport, op: &[u8]) -> Result<(), ()> {
    let mut set: *mut MeasuredSet = core::ptr::null_mut();
    // SAFETY: room for the set.
    let ret = unsafe { measured_set_boot(&mut set) };
    // The records count only as the register vouches for them: the
    // eventlog and the boot ID are paths root can bind over in a
    // namespace of its own.
    if ret == -EBADMSG {
        log_err(
            &[
                b"upatch ",
                op,
                b": this boot's eventlog records do not fold to the measurement register; refused, nothing changed",
            ]
            .concat(),
        );
        fail(
            rep,
            c"tpm_extend",
            c"tampered",
            ret,
            b"this boot's records do not fold to the register",
        );
        return Err(());
    }
    if ret != 0 {
        log_err(
            &[
                b"upatch ",
                op,
                b": cannot read this boot's records: ",
                strerr(-ret),
                b"; refused, nothing changed",
            ]
            .concat(),
        );
        fail(
            rep,
            c"tpm_extend",
            c"tpm_error",
            ret,
            b"cannot read this boot's records",
        );
        return Err(());
    }
    let mut failed: c_int = 0;
    let ctx = (&raw mut failed).cast::<c_void>();
    // SAFETY: the set, the callbacks and their context.
    let mut ret = unsafe { measured_unmeasured_pins(set, Some(undo_pin), ctx) };
    if ret >= 0 {
        // SAFETY: as above.
        ret = unsafe { measured_unmeasured_archives(set, Some(undo_archive), ctx) };
    }
    // SAFETY: the set, freed once.
    unsafe { measured_set_free(set) };
    if ret >= 0 && failed == 0 {
        return Ok(());
    }
    let ret = if ret < 0 { ret } else { failed };
    log_err(
        &[
            b"upatch ",
            op,
            b": cannot undo what this boot's records do not cover: ",
            strerr(-ret),
            b"; refused",
        ]
        .concat(),
    );
    fail(
        rep,
        c"tpm_extend",
        c"tpm_error",
        ret,
        b"cannot undo what this boot's records do not cover",
    );
    Err(())
}

/// The tamper gate before any BPF_PROG_LOAD: a kernel whose ABI shirudo
/// does not know, a detached LSM, a missing anchor, or a concurrent
/// operator who advanced the register surface here, before any kernel
/// state changes.
fn preflight(expect_chain: Option<&CStr>, rep: &mut OpReport) -> Result<(), ()> {
    let mut detail = [0u8; KERNEL_ABI_DETAIL_MAX];
    // SAFETY: room for the detail.
    if unsafe { kernel_abi_check(detail.as_mut_ptr().cast(), detail.len()) } != 0 {
        let detail = cstr(&detail);
        log_err(
            &[
                b"upatch: pre-flight refused (category: kernel_abi_unsupported, message: ",
                detail,
                b")",
            ]
            .concat(),
        );
        fail(
            rep,
            c"pre_flight",
            c"kernel_abi_unsupported",
            EOPNOTSUPP,
            detail,
        );
        return Err(());
    }
    if super::loader::trust_anchor(Some(&mut *rep)).is_err() {
        return Err(());
    }
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(LSM_LINK_PIN.as_ptr()) };
    if fd < 0 {
        let err = errno();
        let category = super::pin_category(err);
        let detached: &[u8] = if err == ENOENT {
            b", message: lsm_detached"
        } else {
            b""
        };
        log_err(
            &[
                b"upatch: pre-flight refused (category: ",
                category.to_bytes(),
                detached,
                b"): open ",
                LSM_LINK_PIN.to_bytes(),
                b": ",
                strerr(err),
            ]
            .concat(),
        );
        fail(
            rep,
            c"pre_flight",
            category,
            err,
            b"cannot open the LSM link pin",
        );
        return Err(());
    }
    // SAFETY: the pin opened above.
    unsafe { close(fd) };

    let Some(expect) = expect_chain else {
        return Ok(());
    };
    let Some(want) = decode_chain(expect) else {
        log_err(b"upatch load: --expect-chain must be 64 hex chars");
        return Err(());
    };
    let mut have = [0u8; DIGEST_LEN];
    // SAFETY: room for the register.
    match unsafe { chain_read(have.as_mut_ptr()) } {
        0 => {}
        r if r == -ENODEV => {
            log_err(b"upatch load: pre-flight refused (category: tampered, message: chain_drift): register unreadable, cannot confirm --expect-chain");
            return Err(());
        }
        r => {
            log_err(&[b"upatch load: chain read failed: ", strerr(-r)].concat());
            return Err(());
        }
    }
    if memneq_explicit(&want, &have) {
        log_err(
            &[
                b"upatch load: pre-flight refused (category: tampered, message: chain_drift): live register ",
                &hex(&have)[..],
                b" is not the expected one; run status and pass the refreshed value",
            ]
            .concat(),
        );
        return Err(());
    }
    Ok(())
}

/// The prechecks, or the warning that they were skipped.
fn precheck(a: &OpArgs, rep: &mut OpReport, op: &[u8]) -> Result<(), ()> {
    if a.no_precheck {
        log_warn(
            &[
                b"upatch ",
                op,
                b": --no-precheck, pre-flight state check skipped",
            ]
            .concat(),
        );
        return Ok(());
    }
    preflight(a.expect_chain, rep).inspect_err(|()| {
        if rep.category.is_null() {
            fail(
                rep,
                c"pre_flight",
                c"tampered",
                EPERM,
                b"pre-flight check failed",
            );
        }
    })
}

/// Refuses an operation whose event the log could not take: the
/// register and the log advance together.
fn eventlog_room(rep: &mut OpReport, op: &[u8]) -> Result<(), ()> {
    let mut cfg = Scrubbed(core::mem::MaybeUninit::zeroed());
    // SAFETY: room for the configuration, which defaults when unreadable.
    unsafe { config::load(cfg.ptr()) };
    // SAFETY: as above.
    let max = unsafe { cfg.0.assume_init_ref() }.eventlog_max_bytes;
    if eventlog_would_exceed(max) == 0 {
        return Ok(());
    }
    // SAFETY: the log's path, a static C string.
    let path = unsafe { crate::ffi::c_str(eventlog_path()) };
    log_err(
        &[
            b"upatch ",
            op,
            b": eventlog ",
            path,
            b" would exceed eventlog.max_bytes ",
            max.to_string().as_bytes(),
            b"; refused, nothing loaded or extended",
        ]
        .concat(),
    );
    fail(
        rep,
        c"pre_flight",
        c"eventlog_full",
        ENOSPC,
        b"eventlog would exceed eventlog.max_bytes",
    );
    Err(())
}

/// The register lock, released when dropped.
struct Lock(c_int);

impl Lock {
    fn take(rep: &mut OpReport, op: &[u8], nothing: &[u8]) -> Result<Lock, ()> {
        match eventlog_lock() {
            fd if fd >= 0 => Ok(Lock(fd)),
            err => {
                log_err(
                    &[
                        b"upatch ",
                        op,
                        b": cannot take the register lock: ",
                        strerr(-err),
                        b" (category: tpm_error); ",
                        nothing,
                    ]
                    .concat(),
                );
                fail(
                    rep,
                    c"tpm_extend",
                    c"tpm_error",
                    err,
                    b"cannot take the register lock",
                );
                Err(())
            }
        }
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        eventlog_unlock(self.0);
    }
}

/// The eventlog entry `ty` that mirrors the extend `event`, or -errno.
fn event_record(
    ty: &CStr,
    name: &[u8],
    payload: &[u8; DIGEST_LEN],
    event: &[u8; DIGEST_LEN],
    reason: Option<&[u8]>,
) -> Result<Vec<u8>, c_int> {
    let mut buf = vec![0u8; 4096];
    let mut e = JsonEmit::fixed(&mut buf);
    // SAFETY: the emitter, a C string and the event's digest.
    unsafe { eventlog_record_open(&mut e, ty.as_ptr(), event.as_ptr()) };
    e.obj_open_key(b"upatch");
    e.kv_string(b"name", name);
    e.kv_string(b"payload_sha256", &hex(payload));
    e.obj_close();
    if let Some(r) = reason {
        e.kv_string(b"reason", r);
    }
    e.obj_close();
    if e.err() != 0 {
        log_err(
            &[
                b"eventlog: ",
                ty.to_bytes(),
                b" entry encode failed: ",
                strerr(-e.err()),
            ]
            .concat(),
        );
        return Err(e.err());
    }
    let len = e.written();
    buf.truncate(len + 1);
    Ok(buf)
}

/// One operator operation, measured: its own register event, where boot
/// restore coalesces into one, and the eventlog entry after it. A
/// missing TPM or register is an error, never an unmeasured success.
/// The register value after it goes into `out_chain`; the error, and
/// whether the register moved before it, come back.
#[allow(clippy::too_many_arguments)]
fn measure(
    tag: &CStr,
    ty: &CStr,
    op: &[u8],
    name: &[u8],
    payload: &[u8; DIGEST_LEN],
    reason: Option<&[u8]>,
    out_chain: Option<&mut [c_char; 65]>,
) -> (c_int, bool) {
    let c_name = CString::new(name).unwrap_or_default();
    let (mut event, mut chain) = ([0u8; DIGEST_LEN], [0u8; DIGEST_LEN]);
    // SAFETY: two C strings, the payload and room for the event.
    let ret = unsafe {
        chain_upatch_event(
            tag.as_ptr(),
            c_name.as_ptr(),
            payload.as_ptr(),
            event.as_mut_ptr(),
        )
    };
    if ret != 0 {
        log_err(
            &[
                b"upatch ",
                op,
                b": cannot hash the event (category: tpm_error)",
            ]
            .concat(),
        );
        return (ret, false);
    }
    // SAFETY: the event and room for the register.
    let ret = unsafe { chain_extend(event.as_ptr(), chain.as_mut_ptr()) };
    if ret != 0 {
        let why: &[u8] = match ret {
            r if r == -ENODEV => b": TPM register unavailable (category: tpm_error): not measured; shirudo needs the register init bound this boot",
            r if r == -EACCES => b": register is not the one init bound (category: tampered): not measured; the operator must reconcile",
            // A lost answer or a failed read back: the register may have moved.
            _ => b": register extend failed (category: tpm_error): the TPM may have taken the event without its record; the operator must reconcile",
        };
        log_err(&[b"upatch ", op, why].concat());
        return (ret, false);
    }
    let appended = event_record(ty, name, payload, &event, reason).and_then(|line| {
        // SAFETY: the record, NUL-terminated.
        match unsafe { eventlog_append(line.as_ptr().cast()) } {
            0 => Ok(()),
            err => Err(err),
        }
    });
    if let Err(err) = appended {
        log_err(
            &[b"upatch ", op, b": eventlog append failed after the extend: register and log disagree; the operator must reconcile"]
                .concat(),
        );
        return (err, true);
    }
    let chain_hex = hex(&chain);
    if let Some(out) = out_chain {
        for (d, &s) in out.iter_mut().zip(chain_hex.iter().chain(&[0])) {
            *d = s as c_char;
        }
    }
    log_audit(
        &[
            b"upatch ",
            op,
            b": ",
            name,
            b" measured, register ",
            &chain_hex,
        ]
        .concat(),
    );
    (0, true)
}

/// A register other than the one init set up is a verdict, not a TPM
/// fault.
fn chain_category(err: c_int, measured: bool) -> &'static CStr {
    if !measured && err == -EACCES {
        c"tampered"
    } else {
        c"tpm_error"
    }
}

/// The operator's file, read once into memory and parsed there: the name
/// and payload measured, the program loaded and the copy archived all
/// come from that one read. A copy on disk, under a name another command
/// can take, or a file read again, could set them apart.
struct Artifact {
    u: Box<Upatch>,
    // The bytes the container points into, which outlive it.
    data: Vec<u8>,
}

impl Artifact {
    fn read(src: &CStr) -> Result<Self, c_int> {
        let data = read(src)?;
        // SAFETY: an all-zero container is a closed one.
        let mut u: Box<Upatch> = Box::new(unsafe { core::mem::zeroed() });
        // SAFETY: the bytes, which the artifact keeps while the container
        // is open, and the container to fill.
        match unsafe { upatch_open_memory(data.as_ptr().cast(), data.len(), &mut *u) } {
            0 => Ok(Artifact { u, data }),
            err => Err(err),
        }
    }
}

impl core::ops::Deref for Artifact {
    type Target = Upatch;

    fn deref(&self) -> &Upatch {
        &self.u
    }
}

impl Drop for Artifact {
    fn drop(&mut self) {
        // SAFETY: the container read() opened, closed once, before the
        // bytes it points into go.
        unsafe { upatch::upatch_close(&mut *self.u) };
    }
}

/// Reads `file` once, or reports why not.
fn read_artifact(file: &CStr, rep: &mut OpReport, op: &[u8]) -> Result<Artifact, ()> {
    Artifact::read(file).map_err(|err| {
        log_err(
            &[
                b"upatch ",
                op,
                b": read ",
                file.to_bytes(),
                b": ",
                strerr(-err),
            ]
            .concat(),
        );
        fail(
            rep,
            c"parse",
            c"parser_rejected",
            err,
            b"cannot read .upatch",
        );
    })
}

fn header_name(u: &Upatch) -> Vec<u8> {
    let mut name = [0u8; NAME_MAX + 1];
    upatch::header_name(u, &mut name);
    cstr(&name).to_vec()
}

fn set_payload_hex(rep: &mut OpReport, payload: &[u8]) {
    for (d, &s) in rep
        .payload_hex
        .iter_mut()
        .zip(hex(payload).iter().chain(&[0]))
    {
        *d = s as c_char;
    }
}

/// Emits the report a caller asked for, and frees it.
pub(super) fn finish(rep: &mut OpReport, report: Option<&CStr>) {
    if let Some(path) = report {
        // SAFETY: a C string, and the report, whose strings outlive it.
        unsafe { report_emit(path.as_ptr(), rep) };
    }
    // SAFETY: the report, its log freed once.
    unsafe { report_free(rep) };
}

/// A load, after its arguments: 0, 1, or UPATCH_INSTALL_TARGET_MISSING
/// for a kprobe target whose module is not loaded.
fn load(a: &OpArgs) -> c_int {
    let file = a.file.unwrap_or(c"");
    let mut rep = OpReport::new(c"upatch_load");
    rep.path = file.as_ptr();
    let mut name = CString::default();
    let mut ret = load_steps(a, file, &mut rep, &mut name);
    if ret == 1 && category_is(&rep, b"attach_target_missing") {
        ret = UPATCH_INSTALL_TARGET_MISSING;
    }
    finish(&mut rep, a.report);
    ret
}

fn load_steps(a: &OpArgs, file: &CStr, rep: &mut OpReport, name_out: &mut CString) -> c_int {
    if version_gate(a, rep, b"load").is_err() {
        return 1;
    }
    let Ok(u) = read_artifact(file, rep, b"load") else {
        return 1;
    };
    let name = header_name(&u);
    let payload = u.hdr.payload_sha256;
    set_payload_hex(rep, &payload);
    *name_out = CString::new(name.clone()).unwrap_or_default();
    rep.name = name_out.as_ptr();

    if precheck(a, rep, b"load").is_err() || eventlog_room(rep, b"load").is_err() {
        return 1;
    }
    if !name_valid(Some(&name)) {
        log_err(
            &[
                b"upatch load: refusing unsafe upatch name '",
                &name[..],
                b"'",
            ]
            .concat(),
        );
        fail(rep, c"parse", c"parser_rejected", 0, b"unsafe upatch name");
        return 1;
    }
    let Ok(_lock) = Lock::take(rep, b"load", b"nothing loaded") else {
        return 1;
    };
    if undo_unmeasured(rep, b"load").is_err() {
        return 1;
    }
    // Past the undo pass a payload on the pins is a load this boot's
    // records hold, and only an unload removes it. A load over a live
    // upatch would rebind its serializer pins to maps nothing reads, and
    // an undo of it would take the live one's pins and archive with it.
    // An install of the very payload loaded is done: bpm retries one that
    // a stop cut off between this load and its own record.
    if let Ok(live) = pin_payload(&name) {
        if a.loaded_is_done && live == payload {
            log_info(
                &[
                    b"upatch load: ",
                    &name[..],
                    b" is already loaded with this payload",
                ]
                .concat(),
            );
            rep.ok = true;
            rep.category = c"already_loaded".as_ptr();
            return 0;
        }
        log_err(
            &[
                b"upatch load: ",
                &name[..],
                b" is already loaded; unload it with its signed directive first",
            ]
            .concat(),
        );
        fail(
            rep,
            c"pin",
            c"already_loaded",
            crate::errno::EEXIST,
            b"upatch already loaded",
        );
        return 1;
    }
    if super::loader::apply(&u, file, false, Some(&mut *rep)).is_err() {
        return 1;
    }

    // Archived before it is measured: the archive is the intent boot
    // restore replays, and an event for an upatch that will not survive
    // a reboot would drift from it. A load whose archive or extend fails
    // is undone, pins and archive, so that no upatch runs unmeasured; a
    // caller who stops this process first gets the same from the next
    // upatch command, and from the next init.
    let err = persist(&u.data, &name);
    if err != 0 {
        log_err(
            &[
                b"upatch load: loaded but not archived under ",
                UPATCHES_DIR.as_bytes(),
                b": ",
                strerr(-err),
                b"; not measured",
            ]
            .concat(),
        );
        unload_unmeasured(&name);
        fail(
            rep,
            c"persist",
            c"unknown",
            err,
            b"persist failed; the load was undone",
        );
        return 1;
    }
    let (err, measured) = measure(
        c"shirudo-upatch",
        c"upatch_load",
        b"load",
        &name,
        &payload,
        None,
        Some(&mut rep.chain_after),
    );
    if err != 0 {
        if !measured {
            unload_unmeasured(&name);
        }
        let msg: &[u8] = if measured {
            b"eventlog append failed after the extend"
        } else {
            b"chain extend failed; the load was undone"
        };
        fail(rep, c"tpm_extend", chain_category(err, measured), err, msg);
        return 1;
    }
    rep.ok = true;
    rep.phase = c"done".as_ptr();
    rep.tpm_present = rep.chain_after[0] != 0;
    0
}

/// `upatch load`, from `load` on.
pub(super) fn run_load(args: &[*const c_char]) -> c_int {
    match parse(args, false) {
        Ok(a) => load(&a),
        Err(code) => code,
    }
}

/// `upatch unload`, from `unload` on.
pub(super) fn run_unload(args: &[*const c_char]) -> c_int {
    let a = match parse(args, true) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let file = a.file.unwrap_or(c"");
    let mut rep = OpReport::new(c"upatch_unload");
    rep.path = file.as_ptr();
    let mut name = CString::default();
    let ret = unload_steps(&a, file, &mut rep, &mut name);
    if ret != 0 {
        let or = |s: *const c_char, d: &'static [u8]| {
            if s.is_null() {
                d
            } else {
                // SAFETY: the report's static C strings, when set.
                unsafe { crate::ffi::c_str(s) }
            }
        };
        let message = cstr(bytes_of(&rep.message));
        log_err(
            &[
                &b"upatch unload failed: name="[..],
                if name.is_empty() {
                    b"(unknown)"
                } else {
                    name.to_bytes()
                },
                b" phase=",
                or(rep.phase, b"(unknown)"),
                b" category=",
                or(rep.category, b"(unknown)"),
                b" err=",
                rep.err.to_string().as_bytes(),
                b" (",
                if rep.err != 0 {
                    strerr(rep.err)
                } else {
                    b"none"
                },
                b") message=",
                if message.is_empty() {
                    b"(none)"
                } else {
                    message
                },
            ]
            .concat(),
        );
    }
    finish(&mut rep, a.report);
    ret
}

fn bytes_of(a: &[c_char]) -> &[u8] {
    // SAFETY: c_char and u8 have one size and alignment.
    unsafe { core::slice::from_raw_parts(a.as_ptr().cast(), a.len()) }
}

fn unload_steps(a: &OpArgs, file: &CStr, rep: &mut OpReport, name_out: &mut CString) -> c_int {
    if version_gate(a, rep, b"unload").is_err() {
        return 1;
    }
    // Read once, as a load is: the target and the payload the kernel's
    // signature check covers must be the bytes acted on after it, and a
    // file of root's is root's to rewrite between the two.
    let Ok(u) = read_artifact(file, rep, b"unload") else {
        return 1;
    };
    if !upatch::is_unload(&u) {
        log_err(
            &[
                b"upatch unload: ",
                file.to_bytes(),
                b" is a LOAD upatch; use `shirudo upatch load`",
            ]
            .concat(),
        );
        fail(rep, c"parse", c"parser_rejected", 0, b"is a LOAD upatch");
        return 1;
    }
    // The target's name and the payload it is expected to carry are the
    // directive's signed sections; the header's name must be the same,
    // since status and the package tooling read it.
    let payload = match upatch::signed_unload_payload(&u).filter(|_| upatch::name_signed(&u)) {
        Some(p) => <[u8; DIGEST_LEN]>::try_from(p).unwrap_or_default(),
        None => {
            log_err(
                &[
                    b"upatch unload: the target of ",
                    file.to_bytes(),
                    b" is not signature-covered or differs from the header; rebuild the directive",
                ]
                .concat(),
            );
            fail(
                rep,
                c"parse",
                c"parser_rejected",
                0,
                b"directive target not signed",
            );
            return 1;
        }
    };
    let name = header_name(&u);
    *name_out = CString::new(name.clone()).unwrap_or_default();
    rep.name = name_out.as_ptr();
    set_payload_hex(rep, &payload);

    if !name_valid(Some(&name)) {
        log_err(
            &[
                b"upatch unload: refusing unsafe upatch name '",
                &name[..],
                b"'",
            ]
            .concat(),
        );
        fail(rep, c"parse", c"parser_rejected", 0, b"unsafe upatch name");
        return 1;
    }
    let archived = archive_path(&name);
    if precheck(a, rep, b"unload").is_err() || eventlog_room(rep, b"unload").is_err() {
        return 1;
    }
    let Ok(_lock) = Lock::take(rep, b"unload", b"nothing detached") else {
        return 1;
    };
    if undo_unmeasured(rep, b"unload").is_err() {
        return 1;
    }
    // A bad signature fails here, before anything is removed.
    if super::loader::apply(&u, file, true, Some(&mut *rep)).is_err() {
        log_err(b"upatch unload: signature verification failed; refusing");
        return 1;
    }

    // The live value is the xattr bpf2 guards; the expected one is
    // signed, so a directive detaches the upatch its signer made it for
    // and nothing else. A pin whose value cannot be read is refused; no
    // pin at all is the already-unloaded case below.
    match pin_payload(&name) {
        Ok(live) if memneq_explicit(&live, &payload) => {
            log_err(
                &[
                    b"upatch unload: payload_mismatch, the upatch loaded under '",
                    &name[..],
                    b"' is not what the directive expects; refused",
                ]
                .concat(),
            );
            fail(
                rep,
                c"pin",
                c"payload_mismatch",
                EPERM,
                b"loaded payload does not match directive",
            );
            return 1;
        }
        Ok(_) => log_info(
            &[
                b"upatch unload: ",
                &name[..],
                b" carries the directive's payload",
            ]
            .concat(),
        ),
        Err(err) if err != -ENOENT => {
            log_err(
                &[
                    b"upatch unload: cannot read the payload recorded for '",
                    &name[..],
                    b"': ",
                    strerr(-err),
                    b"; refusing",
                ]
                .concat(),
            );
            fail(
                rep,
                c"pin",
                c"payload_mismatch",
                err,
                b"payload xattr unreadable",
            );
            return 1;
        }
        Err(_) => {}
    }

    let unarchive = || {
        if let Err(e) = fs::remove_file(os(archived.to_bytes())) {
            if e.raw_os_error() != Some(ENOENT) {
                log_warn(
                    &[
                        b"upatch unload: could not remove ",
                        archived.to_bytes(),
                        b": ",
                        strerr(-io_err(&e)),
                    ]
                    .concat(),
                );
            }
        }
    };
    // An archive with no pins is one init could not restore, or one an
    // interrupted unload left: the directive removes it only when it is
    // the payload the directive names, as it would its pins.
    if !is_pinned(&name) {
        // SAFETY: an all-zero container is a closed one.
        let mut held: Upatch = unsafe { core::mem::zeroed() };
        match archive_verify(&name, &payload, &mut held) {
            0 => {
                // SAFETY: the container archive_verify() opened.
                unsafe { upatch::upatch_close(&mut held) };
                unarchive();
            }
            err if err != -ESTALE || fs::metadata(os(archived.to_bytes())).is_ok() => {
                log_err(
                    &[
                        b"upatch unload: payload_mismatch, ",
                        archived.to_bytes(),
                        b" is not the upatch the directive expects; it stays",
                    ]
                    .concat(),
                );
                fail(
                    rep,
                    c"pin",
                    c"payload_mismatch",
                    if err == -ESTALE { EPERM } else { -err },
                    b"archived payload does not match directive",
                );
                return 1;
            }
            _ => {}
        }
        log_info(&[b"upatch unload: ", &name[..], b" already unloaded (no pin)"].concat());
        log_audit(&[b"upatch unload: name=", &name[..], b" already_unloaded"].concat());
        rep.ok = true;
        rep.phase = c"done".as_ptr();
        rep.category = c"already_unloaded".as_ptr();
        fail_message(rep, b"already unloaded");
        return 0;
    }

    // Measured before it happens: a detach the register does not know is
    // what a caller who stops this process at the right moment would get.
    // The other way round, a detach that fails after the event leaves a
    // shield the register says is gone, which the next status reports and
    // the operator can repeat.
    let (err, _) = measure(
        c"shirudo-unload",
        c"upatch_unload",
        b"unload",
        &name,
        &payload,
        None,
        Some(&mut rep.chain_after),
    );
    if err != 0 {
        fail(
            rep,
            c"tpm_extend",
            chain_category(err, false),
            err,
            b"chain extend failed; nothing detached",
        );
        return 1;
    }
    let err = remove_pins(&name);
    if err != 0 {
        log_err(
            &[
                b"upatch unload: measured, but failed to remove the pin for ",
                &name[..],
                b": ",
                strerr(-err),
                b"; repeat the unload",
            ]
            .concat(),
        );
        fail(
            rep,
            c"pin",
            c"detach_failed",
            err,
            b"pin removal failed after the event was measured",
        );
        return 1;
    }
    log_info(&[b"upatch unload: ", &name[..], b" detached and unpinned"].concat());
    unarchive();
    rep.ok = true;
    rep.phase = c"done".as_ptr();
    rep.tpm_present = rep.chain_after[0] != 0;
    0
}

/// The report's message alone.
fn fail_message(rep: &mut OpReport, message: &[u8]) {
    let n = message.len().min(rep.message.len() - 1);
    for (d, &s) in rep.message.iter_mut().zip(&message[..n]) {
        *d = s as c_char;
    }
    rep.message[n] = 0;
}

/// An install from a package: a load without the prechecks, done when
/// the payload is already the one loaded.
pub(crate) fn install(path: &CStr) -> c_int {
    load(&OpArgs {
        file: Some(path),
        no_precheck: true,
        loaded_is_done: true,
        ..OpArgs::default()
    })
}

/// A removal from a package: the unload directive at `path`.
pub(crate) fn remove(path: &CStr) -> c_int {
    run_unload(&[c"unload".as_ptr(), c"--no-precheck".as_ptr(), path.as_ptr()])
}

/// Detaches, unpins and unarchives upatch `name` without a directive,
/// because the key that signed it was revoked. It holds the register
/// lock from the archive read to its unlink, as a load and an unload do,
/// and checks the signer on what that read finds: an upgrade may have
/// replaced the upatch since the caller's scan with one another key
/// signed. 1 when the unload was measured, 0 when only the archive went,
/// -ESTALE when the archive is no longer `signer`'s and stays, -errno
/// otherwise.
pub(crate) fn purge(name: &CStr, signer: *const Cert, reason: &CStr) -> c_int {
    if !name_valid(Some(name.to_bytes())) {
        return -EINVAL;
    }
    let lock = eventlog_lock();
    if lock < 0 {
        log_err(
            &[
                b"upatch purge: cannot take the register lock: ",
                strerr(-lock),
                b" (category: tpm_error); nothing measured or detached",
            ]
            .concat(),
        );
        return lock;
    }
    let _lock = Lock(lock);
    purge_locked(name.to_bytes(), signer, reason.to_bytes())
}

fn purge_locked(name: &[u8], signer: *const Cert, reason: &[u8]) -> c_int {
    let archived = archive_path(name);
    if archived.as_bytes().len() >= 4096 {
        return -ENAMETOOLONG;
    }
    // SAFETY: a C string.
    let fd = unsafe { seal_open_read(archived.as_ptr()) };
    if fd < 0 {
        return fd;
    }
    let u = Opened::open_fd(fd);
    // SAFETY: the descriptor, closed once.
    unsafe { close(fd) };
    let u = match u {
        Ok(u) => u,
        Err(err) => return err,
    };
    // SAFETY: the container's signature, of its header's length, and the
    // caller's certificate.
    let ret = unsafe {
        cms_signed_by(
            upatch_signature(&*u).cast(),
            u.hdr.signature_len as usize,
            signer,
        )
    };
    let payload = u.hdr.payload_sha256;
    drop(u);
    if ret != 1 {
        return if ret < 0 { ret } else { -ESTALE };
    }

    // As for unload: the event first, then the detach it describes.
    let loaded = is_pinned(name);
    if loaded {
        let (ret, _) = measure(
            c"shirudo-unload",
            c"upatch_unload",
            b"purge",
            name,
            &payload,
            Some(reason),
            None,
        );
        if ret != 0 {
            return ret;
        }
        let ret = remove_pins(name);
        if ret != 0 {
            log_err(
                &[
                    b"upatch purge: measured, but failed to remove the pin for ",
                    name,
                    b": ",
                    strerr(-ret),
                ]
                .concat(),
            );
            return ret;
        }
    }
    if let Err(e) = fs::remove_file(os(archived.to_bytes())) {
        if e.raw_os_error() != Some(ENOENT) {
            let err = io_err(&e);
            log_err(
                &[
                    b"upatch purge: could not remove ",
                    archived.to_bytes(),
                    b": ",
                    strerr(-err),
                ]
                .concat(),
            );
            return err;
        }
    }
    let how: &[u8] = if loaded { b"detached" } else { b"archive_only" };
    log_audit(&[b"upatch purge: name=", name, b" reason=", reason, b" ", how].concat());
    c_int::from(loaded)
}
