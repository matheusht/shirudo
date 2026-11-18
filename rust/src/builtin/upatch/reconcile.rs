// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch reconcile`: each loaded XDP upatch attached to the
//! devices its signed classes select that came after its load, and the
//! pins of links whose devices went away removed. One pass, which udev
//! and a timer run.
//!
//! Every upatch is checked before any is attached: a changed archive
//! stops the pass, so nothing keeps acting on a host in that state.

use core::ffi::{CStr, c_char, c_int};
use std::ffi::{CString, OsStr};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;

use super::loader::{AttachError, trust_anchor, xdp_attach_one};
use super::ops::{LSM_LINK_PIN, fail, finish};
use super::{log_audit, log_err, log_info, log_warn, pin_category, strerr};
use crate::errno::{EACCES, ENAMETOOLONG, ENODATA, ENOENT, EOVERFLOW, EPERM, ESTALE};
use crate::util::bpf_info::{Info, LINK_INFO_SIZE};
use crate::util::chain::memneq_explicit;
use crate::util::eventlog::{eventlog_lock, eventlog_pending_path, eventlog_unlock};
use crate::util::help::{Help, HelpSection};
use crate::util::measured::{MeasuredSet, measured_set_boot, measured_set_free};
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser, OptSpec};
use crate::util::report::OpReport;
use crate::util::upatch::{NAME_MAX, ProgSpec, Upatch, upatch_close};
use crate::util::upatch_pins::{LINK_PIN_PREFIX, PAYLOAD_HASH_LEN, Pins, each_pinned, pin_payload};
use crate::util::upatch_resolve::{each_link_info, pin_path};
use crate::util::upatch_verify::{
    Specs, archive_specs, archive_verify, pin_measured, xdp_each_uncovered,
};
use crate::util::xdp::{self, XdpDevice};

/// bpf_link_info's type, and its xdp.ifindex at the start of the union.
const LINK_TYPE: usize = 0;
const LINK_XDP_IFINDEX: usize = 16;
const BPF_LINK_TYPE_XDP: u32 = 6;

const RECONCILE_REPORT: c_int = 0;

static RECONCILE_OPTS: [OptSpec; 1] = [OptSpec::new(
    c"--report",
    0,
    0,
    Some(c"<path>"),
    c"write the operation report as JSON, - for standard output",
)];

static RECONCILE_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &RECONCILE_OPTS)];

static RECONCILE_HELP: Help = Help::new(
    c"shirudo upatch reconcile [--report=<path>]",
    Some(
        c"Attach each loaded XDP upatch to the devices its signed classes select\n\
          and that it is not attached to yet, and remove the pins of devices that\n\
          are gone. One pass; udev and a timer run it.",
    ),
    &RECONCILE_SECTIONS,
    None,
);

fn num(n: u32) -> String {
    n.to_string()
}

/// A loaded XDP upatch: the payload its pins record, and its archive
/// opened and checked against that payload, with its attach specs.
struct Work {
    name: Vec<u8>,
    payload: [u8; PAYLOAD_HASH_LEN],
    u: Box<Upatch>,
    specs: Option<Specs>,
}

impl Work {
    fn new(name: &[u8]) -> Self {
        Work {
            name: name.to_vec(),
            payload: [0; PAYLOAD_HASH_LEN],
            // SAFETY: an all-zero container is a closed one.
            u: Box::new(unsafe { core::mem::zeroed() }),
            specs: None,
        }
    }

    /// The pins' payload and the archive that is it: -ENODATA without a
    /// payload, or archive_specs()'s -errno.
    fn read(&mut self) -> c_int {
        let Ok(payload) = pin_payload(&self.name) else {
            return -ENODATA;
        };
        self.payload = payload;
        match archive_specs(&self.name, &self.payload, &mut self.u) {
            Ok(specs) => {
                self.specs = Some(specs);
                0
            }
            Err(err) => err,
        }
    }

    fn specs(&self) -> &[ProgSpec] {
        self.specs.as_ref().map_or(&[], Specs::as_slice)
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        // The specs go before the container they were read from.
        if self.specs.take().is_some() {
            // SAFETY: the container archive_specs() opened, closed once.
            unsafe { upatch_close(&mut *self.u) };
        }
    }
}

/// The register lock, released when dropped.
struct Locked(c_int);

impl Locked {
    fn take(rep: &mut OpReport) -> Result<Self, ()> {
        match eventlog_lock() {
            fd if fd >= 0 => Ok(Locked(fd)),
            err => {
                fail(
                    rep,
                    c"pre_flight",
                    c"tpm_error",
                    err,
                    b"cannot take the register lock",
                );
                Err(())
            }
        }
    }
}

impl Drop for Locked {
    fn drop(&mut self) {
        eventlog_unlock(self.0);
    }
}

/// The payload this boot's records hold upatch `name` with, when they
/// hold it with the payload pinned now.
fn pin_is_measured(name: &[u8]) -> Result<Option<[u8; PAYLOAD_HASH_LEN]>, c_int> {
    let mut set: *mut MeasuredSet = core::ptr::null_mut();
    // SAFETY: room for the set.
    let ret = unsafe { measured_set_boot(&mut set) };
    if ret != 0 {
        return Err(ret);
    }
    let held = pin_measured(set, name);
    // SAFETY: the set, freed once.
    unsafe { measured_set_free(set) };
    Ok(held)
}

fn fail_verify(name: &[u8], err: c_int, rep: &mut OpReport) {
    if err == -ESTALE || err == -ENODATA {
        log_err(
            &[
                &b"upatch reconcile: the archive of "[..],
                name,
                b" is not what was loaded (tampered)",
            ]
            .concat(),
        );
        fail(
            rep,
            c"pre_flight",
            c"tampered",
            0,
            b"archive differs from the loaded payload",
        );
    } else {
        log_err(
            &[
                &b"upatch reconcile: cannot check "[..],
                name,
                b": ",
                strerr(-err),
            ]
            .concat(),
        );
        fail(rep, c"pre_flight", c"unknown", err, b"archive check failed");
    }
}

fn records_failed(err: c_int, rep: &mut OpReport) {
    log_err(
        &[
            &b"upatch reconcile: cannot read this boot's records: "[..],
            strerr(-err),
        ]
        .concat(),
    );
    fail(
        rep,
        c"pre_flight",
        c"tpm_error",
        err,
        b"cannot read this boot's records",
    );
}

/// The upatch `w` names, read: Ok(false) to pass it over. A load in
/// progress has pins before it has an archive, and one that died leaves
/// pins without a record, which status reports as such. Only the
/// register lock tells those from an upatch the records hold whose
/// archive has changed, which is the one this refuses.
fn open(w: &mut Work, rep: &mut OpReport) -> Result<bool, ()> {
    if w.read() == 0 {
        return Ok(true);
    }
    let lock = Locked::take(rep)?;
    match pin_is_measured(&w.name) {
        Err(err) => {
            records_failed(err, rep);
            return Err(());
        }
        Ok(None) => return Ok(false),
        Ok(Some(_)) => {}
    }
    let ret = w.read();
    drop(lock);
    if ret != 0 {
        fail_verify(&w.name, ret, rep);
        return Err(());
    }
    Ok(true)
}

/// Every upatch with an XDP program pin, read.
fn collect(rep: &mut OpReport) -> Result<Vec<Work>, ()> {
    let mut work = Vec::new();
    let ret = each_pinned(&mut |name| {
        if Pins::read(name).map_or(true, |p| p.nr_xdp_progs == 0) {
            return 0;
        }
        if name.len() > NAME_MAX {
            fail(
                rep,
                c"pre_flight",
                c"unknown",
                ENAMETOOLONG,
                b"upatch name too long",
            );
            return 1;
        }
        let mut w = Work::new(name);
        match open(&mut w, rep) {
            Ok(true) => work.push(w),
            Ok(false) => {}
            Err(()) => return 1,
        }
        0
    });
    if ret < 0 {
        fail(
            rep,
            c"pre_flight",
            c"unknown",
            -ret,
            b"cannot read the pin directory",
        );
    }
    if ret != 0 { Err(()) } else { Ok(work) }
}

/// The link numbers of an upatch: the next free one, and whether a link
/// lost its device.
#[derive(Default)]
struct Scan {
    next: u32,
    dead: bool,
}

/// Walks the links of `name`; with `collect`, removes the pins of links
/// whose device went away. The kernel clears a link's ifindex for good
/// when its device goes.
fn scan_links(name: &[u8], collect: bool, scan: &mut Scan) -> c_int {
    each_link_info(name, &mut |index, pin, info: &Info<LINK_INFO_SIZE>| {
        if info.u32_at(LINK_TYPE) == BPF_LINK_TYPE_XDP && info.u32_at(LINK_XDP_IFINDEX) == 0 {
            scan.dead = true;
            if collect {
                if let Err(e) = std::fs::remove_file(OsStr::from_bytes(pin.to_bytes())) {
                    return -e.raw_os_error().unwrap_or(ENOENT);
                }
                log_info(
                    &[
                        &b"XDP: removed "[..],
                        pin.to_bytes(),
                        b", its device is gone",
                    ]
                    .concat(),
                );
                return 0;
            }
        }
        if index == u32::MAX {
            return -EOVERFLOW;
        }
        if index >= scan.next {
            scan.next = index + 1;
        }
        0
    })
}

/// Program `prog` of upatch `name` attached to `dev` at link number
/// `next`. What fails for this device alone is left for the next pass.
fn attach(
    prog: c_int,
    name: &[u8],
    spec: &ProgSpec,
    dev: &XdpDevice,
    next: &mut u32,
    rep: &mut OpReport,
) -> Result<(), ()> {
    let pin = (*next != u32::MAX)
        .then(|| pin_path(name, &[]).ok())
        .flatten()
        .and_then(|dir| {
            CString::new([dir.as_bytes(), b"/", LINK_PIN_PREFIX, num(*next).as_bytes()].concat())
                .ok()
        });
    let Some(pin) = pin else {
        fail(
            rep,
            c"link_create",
            c"unknown",
            ENAMETOOLONG,
            b"no pin name left for the link",
        );
        return Err(());
    };
    match xdp_attach_one(prog, spec, dev, &pin) {
        Ok(()) => {
            *next += 1;
            log_audit(
                &[
                    &b"XDP: upatch="[..],
                    name,
                    b" attached device=",
                    dev.name(),
                    b" ifindex=",
                    num(dev.ifindex).as_bytes(),
                    b" class=",
                    num(dev.class()).as_bytes(),
                ]
                .concat(),
            );
        }
        Err(AttachError::Errno(e)) if e == EACCES || e == EPERM => {
            fail(
                rep,
                c"link_create",
                c"lsm_denied",
                e,
                b"the guards refused the XDP link",
            );
            return Err(());
        }
        Err(AttachError::Xdp(xdp::ERR_LINK_SCOPE)) => {
            fail(
                rep,
                c"link_create",
                c"attach_scope_mismatch",
                xdp::attach_errno(xdp::ERR_LINK_SCOPE),
                xdp::attach_strerror(xdp::ERR_LINK_SCOPE).to_bytes(),
            );
            return Err(());
        }
        Err(AttachError::Xdp(xdp::ERR_NO_NATIVE | xdp::ERR_OCCUPIED)) => {}
        Err(e) if xdp::attach_skippable(e.code(), dev) => {}
        Err(e) => log_warn(
            &[
                &b"XDP: upatch "[..],
                name,
                b": attach ",
                dev.name(),
                b" (ifindex ",
                num(dev.ifindex).as_bytes(),
                b"): ",
                xdp::attach_strerror(e.code()).to_bytes(),
            ]
            .concat(),
        ),
    }
    Ok(())
}

/// The devices the XDP programs of `w` select and that run nothing, each
/// counted in `needed`. With `next` each is attached at the next link
/// number; without, a program pin that cannot be opened only says the
/// pins need a look under the register lock.
fn walk(
    w: &Work,
    devices: &[XdpDevice],
    mut next: Option<&mut u32>,
    needed: &mut bool,
    rep: &mut OpReport,
) -> Result<(), ()> {
    let collecting = next.is_none();
    let ret = xdp_each_uncovered(
        &w.name,
        w.specs(),
        devices,
        &mut |fd, spec, dev, attached| {
            if attached != 0 {
                return 0;
            }
            *needed = true;
            match next.as_deref_mut() {
                None => 0,
                Some(next) => {
                    c_int::from(attach(fd.as_raw_fd(), &w.name, spec, dev, next, rep).is_err())
                }
            }
        },
    );
    if ret == 0 {
        return Ok(());
    }
    if ret > 0 {
        return Err(());
    }
    if collecting {
        *needed = true;
        return Ok(());
    }
    log_err(
        &[
            &b"upatch reconcile: an XDP program of "[..],
            &w.name,
            b": ",
            strerr(-ret),
        ]
        .concat(),
    );
    fail(
        rep,
        c"pre_flight",
        pin_category(-ret),
        ret,
        b"cannot open an XDP program pin",
    );
    Err(())
}

/// Under the register lock, with the records still holding the payload
/// `w` was read with and its archive still that payload: the pins of
/// gone devices removed and the uncovered devices attached.
fn apply(w: &Work, devices: &[XdpDevice], rep: &mut OpReport) -> Result<(), ()> {
    let _lock = Locked::take(rep)?;
    let payload = match pin_is_measured(&w.name) {
        Err(err) => {
            records_failed(err, rep);
            return Err(());
        }
        Ok(None) => return Ok(()),
        Ok(Some(p)) => p,
    };
    if memneq_explicit(&payload, &w.payload) {
        return Ok(());
    }
    // SAFETY: an all-zero container is a closed one.
    let mut again: Upatch = unsafe { core::mem::zeroed() };
    match archive_verify(&w.name, &payload, &mut again) {
        0 => {
            // SAFETY: the container opened above.
            unsafe { upatch_close(&mut again) };
        }
        err => {
            fail_verify(&w.name, err, rep);
            return Err(());
        }
    }
    let mut scan = Scan::default();
    let ret = scan_links(&w.name, true, &mut scan);
    if ret != 0 {
        let category = if ret == -EACCES || ret == -EPERM {
            c"lsm_denied"
        } else {
            c"unknown"
        };
        fail(rep, c"link_create", category, ret, b"cannot read the links");
        return Err(());
    }
    let mut needed = false;
    walk(w, devices, Some(&mut scan.next), &mut needed, rep)
}

fn exists(path: &CStr) -> bool {
    std::fs::metadata(OsStr::from_bytes(path.to_bytes())).is_ok()
}

fn preflight(rep: &mut OpReport) -> Result<(), ()> {
    if xdp::netns_initial() != 0 {
        fail(
            rep,
            c"pre_flight",
            c"not_initialized",
            0,
            b"not in the initial network namespace",
        );
        return Err(());
    }
    // SAFETY: the eventlog's C string, which lives as long as the process.
    let pending = unsafe { CStr::from_ptr(eventlog_pending_path()) };
    if !exists(LSM_LINK_PIN) || exists(pending) {
        fail(
            rep,
            c"pre_flight",
            c"not_initialized",
            0,
            b"init has not finished on the root file system",
        );
        return Err(());
    }
    trust_anchor(Some(rep)).map(|_| ())
}

/// One upatch reconciled. Without the register lock a missing pin may
/// be an unload or an upgrade, so a failure to read the pins only sends
/// the upatch on to apply(), which can tell.
fn reconcile(w: &Work, devices: &[XdpDevice], rep: &mut OpReport) -> Result<(), ()> {
    let mut scan = Scan::default();
    let mut needed = false;

    if scan_links(&w.name, false, &mut scan) != 0 {
        needed = true;
    } else {
        walk(w, devices, None, &mut needed, rep)?;
    }
    if !needed && !scan.dead {
        return Ok(());
    }
    apply(w, devices, rep)
}

fn pass(rep: &mut OpReport) -> Result<(), ()> {
    preflight(rep)?;
    let work = collect(rep)?;
    let devices = if work.is_empty() {
        Vec::new()
    } else {
        match xdp::devices_read() {
            Ok(d) => d,
            Err(err) => {
                fail(
                    rep,
                    c"pre_flight",
                    c"unknown",
                    err,
                    b"cannot read the interfaces",
                );
                return Err(());
            }
        }
    };
    xdp::warn_unclassified(&devices);
    for w in &work {
        reconcile(w, &devices, rep)?;
    }
    Ok(())
}

/// `shirudo upatch reconcile`.
pub(super) fn run(args: &[*const c_char]) -> c_int {
    let mut p = OptParser::new(
        c"upatch reconcile",
        &RECONCILE_OPTS,
        Some(&RECONCILE_HELP),
        args,
        1,
    );
    let mut report = None;

    loop {
        match p.next() {
            OPT_END => break,
            RECONCILE_REPORT => report = p.value(),
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let mut rep = OpReport::new(c"upatch_reconcile");
    let ret = if pass(&mut rep).is_ok() {
        rep.ok = true;
        0
    } else {
        1
    };
    finish(&mut rep, report);
    ret
}
