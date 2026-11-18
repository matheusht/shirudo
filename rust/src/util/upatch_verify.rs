// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Whether the archive of a loaded upatch is still what was loaded, and
//! the checks status makes of the upatches this boot measured: an XDP
//! archive changed since its load, a link lost, a device an XDP upatch
//! selects that does not run it.

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::os::unix::ffi::OsStrExt;

use crate::errno::{
    E2BIG, EIO, EMFILE, ENAMETOOLONG, ENFILE, ENODEV, ENOENT, ENOMEM, ESTALE, EXDEV,
};
use crate::util::chain::{memneq_explicit, sha256_2};
use crate::util::measured::{MeasuredSet, measured_holds};
use crate::util::upatch::{
    ATTACH_XDP, NAME_MAX, ProgSpec, ROLE_ATTACH, Upatch, header_name, name_signed,
    signed_attach_len, specs_free, specs_parse, upatch_close, upatch_data, upatch_loader,
    upatch_open, upatch_open_fd,
};
use crate::util::upatch_pins::{
    PAYLOAD_HASH_LEN, Pins, each_pinned, pin_payload, xdp_prog_open, xdp_prog_pin,
};
use crate::util::upatch_resolve::each_link_info;
use crate::util::xdp::{self, Reconcile, XdpDevice};

/// The archives of the loaded upatches.
const UPATCHES_DIR: &[u8] = b"/var/lib/shirudo/upatches";
const PATH_MAX: usize = 4096;
/// Where `struct bpf_link_info` keeps its type.
const LINK_TYPE: usize = 0;
const BPF_LINK_TYPE_XDP: u32 = 6;

fn stale_unless_resources(err: c_int) -> c_int {
    if [-ENOMEM, -EMFILE, -ENFILE].contains(&err) {
        err
    } else {
        -ESTALE
    }
}

/// The archive of upatch `name`.
fn archive_path(name: &[u8]) -> Result<CString, c_int> {
    let path = [UPATCHES_DIR, b"/", name, b".upatch"].concat();
    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(path).map_err(|_| -ENAMETOOLONG)
}

/// SHA-256 of the loader's instructions, then the data: what a header's
/// payload_sha256 claims and the pin directory, the register and an
/// unload directive record.
pub(crate) fn payload_digest(u: &Upatch) -> Result<[u8; PAYLOAD_HASH_LEN], c_int> {
    let mut out = [0u8; PAYLOAD_HASH_LEN];
    // SAFETY: the open container's loader and data, of the lengths its
    // header gives, and room for the digest.
    let ret = unsafe {
        sha256_2(
            upatch_loader(u).cast(),
            u.hdr.loader_insns_len as usize,
            upatch_data(u).cast(),
            u.hdr.data_len as usize,
            out.as_mut_ptr(),
        )
    };
    if ret != 0 { Err(ret) } else { Ok(out) }
}

/// The artifact open at `fd` into `out`, when its bytes are what
/// `payload` names: -ESTALE when they are not, or another -errno when the
/// check itself could not run. The bytes are hashed, not the header's
/// claim about them; `out` is closed again on a failure.
pub(crate) fn verify_fd(
    fd: BorrowedFd<'_>,
    payload: &[u8; PAYLOAD_HASH_LEN],
    out: &mut Upatch,
) -> c_int {
    // SAFETY: the caller's descriptor and container.
    let ret = unsafe { upatch_open_fd(fd.as_raw_fd(), out) };
    if ret != 0 {
        return stale_unless_resources(ret);
    }
    let ret = match payload_digest(out) {
        Ok(digest)
            if memneq_explicit(&digest, payload)
                || memneq_explicit(&out.hdr.payload_sha256, payload) =>
        {
            -ESTALE
        }
        Ok(_) => 0,
        Err(err) => err,
    };
    if ret != 0 {
        // SAFETY: the container opened above.
        unsafe { upatch_close(out) };
    }
    ret
}

/// The archive of upatch `name` into `out` when it is the payload
/// `payload` names, signed with that name.
pub(crate) fn archive_verify(
    name: &[u8],
    payload: &[u8; PAYLOAD_HASH_LEN],
    out: &mut Upatch,
) -> c_int {
    let path = match archive_path(name) {
        Ok(p) => p,
        Err(err) => return err,
    };
    let fd = match crate::util::seal::open_owned(path.as_bytes()) {
        Ok(fd) => fd,
        Err(err) => return stale_unless_resources(err),
    };
    let ret = verify_fd(std::os::fd::AsFd::as_fd(&fd), payload, out);
    drop(fd);
    if ret != 0 {
        return ret;
    }
    let mut header = [0u8; NAME_MAX + 1];
    header_name(out, &mut header);
    if crate::text::cstr(&header) != name || !name_signed(out) {
        // SAFETY: the container opened above.
        unsafe { upatch_close(out) };
        return -ESTALE;
    }
    0
}

/// The attach specs a container's signed metadata gives, freed when they
/// go.
pub(crate) struct Specs {
    ptr: *mut ProgSpec,
    n: u32,
}

impl Specs {
    pub(crate) fn as_slice(&self) -> &[ProgSpec] {
        // SAFETY: the n specs specs_parse() gave.
        unsafe { crate::ffi::slice(self.ptr, self.n as usize) }
    }
}

impl Drop for Specs {
    fn drop(&mut self) {
        // SAFETY: the specs specs_parse() gave, freed once.
        unsafe { specs_free(self.ptr, self.n) };
    }
}

/// The specs of an open container: -ESTALE for metadata that does not
/// parse, -ENOMEM; `u` stays open.
pub(crate) fn verified_specs(u: &Upatch) -> Result<Specs, c_int> {
    if u.signed_attach.is_null() {
        return Err(-ESTALE);
    }
    let mut ptr: *mut ProgSpec = core::ptr::null_mut();
    // SAFETY: the signed metadata of the open container, and room for the
    // specs.
    let ret = unsafe {
        specs_parse(
            u.signed_attach.cast(),
            signed_attach_len(u),
            u.hdr.nr_maps,
            u.hdr.nr_progs,
            &mut ptr,
        )
    };
    match ret {
        0 => Ok(Specs {
            ptr,
            n: u.hdr.nr_progs,
        }),
        err if err == -ENOMEM => Err(err),
        _ => Err(-ESTALE),
    }
}

/// As [`archive_verify`], with the signed attach metadata of every
/// program.
pub(crate) fn archive_specs(
    name: &[u8],
    payload: &[u8; PAYLOAD_HASH_LEN],
    u: &mut Upatch,
) -> Result<Specs, c_int> {
    match archive_verify(name, payload, u) {
        0 => {}
        err => return Err(err),
    }
    verified_specs(u).inspect_err(|_| {
        // SAFETY: the container opened above.
        unsafe { upatch_close(u) };
    })
}

/// XDP links come and go with devices, so their number says nothing.
/// What cannot change is a program pin for each XDP program and a link
/// for each other attach program. Link numbers are shared and shift with
/// the devices, so the kernel says which links are which.
fn xdp_upatch_complete(name: &[u8], specs: &[ProgSpec], nr_attach: u32) -> c_int {
    let mut nr_xdp = 0u32;

    for (i, _) in specs
        .iter()
        .enumerate()
        .filter(|(_, s)| s.kind == ATTACH_XDP)
    {
        nr_xdp += 1;
        let Ok(pin) = xdp_prog_pin(name, i as u32) else {
            return -ENAMETOOLONG;
        };
        match std::fs::metadata(std::ffi::OsStr::from_bytes(pin.as_bytes())) {
            Ok(_) => {}
            Err(e) if e.raw_os_error() == Some(ENOENT) => return 0,
            Err(e) => return -e.raw_os_error().unwrap_or(EIO),
        }
    }
    if nr_attach == nr_xdp {
        return 1;
    }
    let mut found = 0u32;
    let ret = each_link_info(name, &mut |_, _, info| {
        if info.u32_at(LINK_TYPE) != BPF_LINK_TYPE_XDP {
            found += 1;
        }
        0
    });
    if ret != 0 {
        return ret;
    }
    c_int::from(found == nr_attach - nr_xdp)
}

/// 1 when every link `specs` imply is pinned for `name`, 0 when one is
/// missing, or -errno.
fn links_complete_specs(name: &[u8], specs: &[ProgSpec]) -> c_int {
    let nr_attach = specs.iter().filter(|s| s.role == ROLE_ATTACH).count() as u32;

    if specs.iter().any(|s| s.kind == ATTACH_XDP) {
        return xdp_upatch_complete(name, specs, nr_attach);
    }
    match Pins::read(name) {
        Ok(pins) => c_int::from(pins.complete(nr_attach)),
        Err(err) => err,
    }
}

/// 1 when every link the signed metadata of the archive at `path` implies
/// is pinned for `name`, 0 when one is missing, -ESTALE when the archive
/// is gone or unusable, or another -errno when that cannot be told.
pub(crate) fn links_complete(name: &[u8], path: &CStr) -> c_int {
    // SAFETY: an all-zero container is a closed one.
    let mut u: Upatch = unsafe { core::mem::zeroed() };
    // SAFETY: a C string and the container to fill.
    let ret = unsafe { upatch_open(path.as_ptr(), &mut u) };
    if ret != 0 {
        return stale_unless_resources(ret);
    }
    let ret = match verified_specs(&u) {
        Ok(specs) => links_complete_specs(name, specs.as_slice()),
        Err(err) => stale_unless_resources(err),
    };
    // SAFETY: the container opened above.
    unsafe { upatch_close(&mut u) };
    ret
}

/// Calls `cb` for each device an XDP program of `name` selects and that
/// does not run it, with what the device runs instead as devices were
/// read, 0 for nothing. A non-zero return of `cb` ends the walk with that
/// value, and a program pin that cannot be opened ends it with its
/// -errno.
pub(crate) fn xdp_each_uncovered(
    name: &[u8],
    specs: &[ProgSpec],
    devices: &[XdpDevice],
    cb: &mut dyn FnMut(BorrowedFd<'_>, &ProgSpec, &XdpDevice, u32) -> c_int,
) -> c_int {
    for (i, spec) in specs
        .iter()
        .enumerate()
        .filter(|(_, s)| s.kind == ATTACH_XDP)
    {
        let (fd, prog_id) = match xdp_prog_open(name, i as u32) {
            Ok(p) => p,
            Err(err) => return err,
        };
        for (j, dev) in devices.iter().enumerate() {
            let attached = dev.attached();
            if !xdp::selected(devices, j, spec.device_classes)
                || xdp::reconcile_action(true, attached, prog_id) == Reconcile::Covered
            {
                continue;
            }
            let ret = cb(std::os::fd::AsFd::as_fd(&fd), spec, dev, attached);
            if ret != 0 {
                return ret;
            }
        }
    }
    0
}

/// The payload the pin directory of `name` records, when the set holds
/// `name` with it.
pub(crate) fn pin_measured(s: *const MeasuredSet, name: &[u8]) -> Option<[u8; PAYLOAD_HASH_LEN]> {
    let payload = pin_payload(name).ok()?;
    let hex = CString::new(crate::util::hex::encode(&payload)).ok()?;
    let name_c = CString::new(name).ok()?;
    // SAFETY: the caller's set and two C strings.
    unsafe { measured_holds(s, name_c.as_ptr(), hex.as_ptr()) }.then_some(payload)
}

/// A name, a device and why it does not run the upatch.
pub(crate) type Uncovered<'a> = &'a mut dyn FnMut(&[u8], &[u8], &[u8]) -> c_int;
/// An upatch's name.
pub(crate) type Named<'a> = &'a mut dyn FnMut(&[u8]) -> c_int;

/// The checks status makes of the upatches the set holds, in one walk
/// that reads and hashes each XDP archive once. Each callback that is
/// there runs for a hit, and a non-zero return ends the walk; the counts
/// hold what was found even then.
/// changed: an XDP upatch whose archive is not what was loaded.
/// lost: an upatch missing a link, or whose archive is gone or unusable.
/// uncovered: a device an XDP upatch selects that does not run it, and
/// why.
#[derive(Default)]
pub(crate) struct Checks<'a> {
    pub(crate) changed: Option<Named<'a>>,
    pub(crate) lost: Option<Named<'a>>,
    pub(crate) uncovered: Option<Uncovered<'a>>,
    pub(crate) nr_changed: c_int,
    pub(crate) nr_lost: c_int,
    pub(crate) nr_uncovered: c_int,
    /// The first changed or lost check that could not run.
    pub(crate) check_err: c_int,
    /// The first coverage check that could not run.
    pub(crate) coverage_err: c_int,
}

fn note_err(slot: &mut c_int, err: c_int) {
    if err < 0 && *slot == 0 {
        *slot = err;
    }
}

/// One walk of the checks, with the devices read once, when one needs
/// them.
struct Walk<'c, 'a> {
    s: *const MeasuredSet,
    c: &'c mut Checks<'a>,
    devices: Vec<XdpDevice>,
    devices_tried: bool,
    devices_ok: bool,
}

impl Walk<'_, '_> {
    fn changed(&mut self, name: &[u8]) -> c_int {
        self.c.nr_changed += 1;
        self.c.changed.as_mut().map_or(0, |cb| cb(name))
    }

    /// `complete` is 1, 0 or -errno, as [`links_complete`] returns.
    fn links(&mut self, name: &[u8], complete: c_int) -> c_int {
        if complete == 1 {
            return 0;
        }
        if complete < 0 && complete != -ESTALE {
            note_err(&mut self.c.check_err, complete);
            return 0;
        }
        self.c.nr_lost += 1;
        self.c.lost.as_mut().map_or(0, |cb| cb(name))
    }

    /// Read from the archive as it is, for an upatch the hash does not
    /// vouch for.
    fn links_unverified(&mut self, name: &[u8]) -> c_int {
        match archive_path(name) {
            Ok(path) => {
                let complete = links_complete(name, &path);
                self.links(name, complete)
            }
            Err(err) => {
                note_err(&mut self.c.check_err, err);
                0
            }
        }
    }

    /// Whether `name` selects it is not known, so unless a device runs
    /// name's program it may run without it.
    fn unclassified(&mut self, name: &[u8], specs: &[ProgSpec]) -> c_int {
        let runs_ours = |attached: u32| {
            attached != 0
                && specs
                    .iter()
                    .enumerate()
                    .filter(|(_, s)| s.kind == ATTACH_XDP)
                    .any(|(i, _)| xdp_prog_open(name, i as u32).is_ok_and(|(_, id)| id == attached))
        };
        for dev in &self.devices {
            if dev.unclassified_err == 0 || runs_ours(dev.xdp_drv_id) {
                continue;
            }
            let why = format!(
                "not classified: {}",
                xdp::attach_strerror(dev.unclassified_err).to_string_lossy()
            );
            if why.len() >= 128 {
                return -E2BIG;
            }
            self.c.nr_uncovered += 1;
            let ret = self
                .c
                .uncovered
                .as_mut()
                .map_or(0, |cb| cb(name, dev.name(), why.as_bytes()));
            if ret != 0 {
                return ret;
            }
        }
        0
    }

    fn coverage(&mut self, name: &[u8], specs: &[ProgSpec]) -> c_int {
        if self.c.uncovered.is_none() {
            return 0;
        }
        // Under the lock, as the pins are: a load that attaches between
        // the two reads would otherwise show its device as not attached.
        if !self.devices_tried {
            self.devices_tried = true;
            match xdp::devices_read() {
                Ok(devs) => {
                    self.devices = devs;
                    self.devices_ok = true;
                }
                Err(err) => note_err(&mut self.c.coverage_err, err),
            }
        }
        if !self.devices_ok {
            return 0;
        }
        let devices = core::mem::take(&mut self.devices);
        let c = &mut *self.c;
        let mut ret = xdp_each_uncovered(name, specs, &devices, &mut |_, _, dev, attached| {
            let mut err = 0;
            let mut features = 0;
            if attached == 0 {
                err = xdp::device_verify(dev);
                // The read finds nothing, not an error, for a device gone
                // since.
                if err == -ENODEV || err == -EXDEV {
                    return 0;
                }
                match xdp::device_features(dev.ifindex) {
                    Ok(f) => {
                        features = f;
                        err = 0;
                    }
                    Err(e) => err = e,
                }
            }
            c.nr_uncovered += 1;
            let why = xdp::uncovered_reason(attached, err, features);
            c.uncovered
                .as_mut()
                .map_or(0, |cb| cb(name, dev.name(), why.to_bytes()))
        });
        self.devices = devices;
        if ret == 0 {
            ret = self.unclassified(name, specs);
        }
        if ret < 0 {
            note_err(&mut self.c.coverage_err, ret);
            return 0;
        }
        ret
    }

    /// One verified read of an XDP upatch's archive serves the three
    /// checks: its hash, the links its metadata implies and the devices
    /// it selects.
    fn check_one(&mut self, name: &[u8]) -> c_int {
        let Some(payload) = pin_measured(self.s, name) else {
            return 0;
        };
        if Pins::read(name).map_or(true, |p| p.nr_xdp_progs == 0) {
            return self.links_unverified(name);
        }
        // SAFETY: an all-zero container is a closed one.
        let mut u: Upatch = unsafe { core::mem::zeroed() };
        let ret = archive_verify(name, &payload, &mut u);
        if ret == -ESTALE {
            let ret = self.changed(name);
            return if ret != 0 {
                ret
            } else {
                self.links_unverified(name)
            };
        }
        if ret != 0 {
            note_err(&mut self.c.check_err, ret);
            note_err(&mut self.c.coverage_err, ret);
            return self.links_unverified(name);
        }
        // The bytes are what was loaded; metadata it cannot parse is a
        // lost link.
        let ret = match verified_specs(&u) {
            Err(err) if err != -ESTALE => {
                note_err(&mut self.c.check_err, err);
                note_err(&mut self.c.coverage_err, err);
                0
            }
            Err(err) => self.links(name, err),
            Ok(specs) => {
                let complete = links_complete_specs(name, specs.as_slice());
                match self.links(name, complete) {
                    0 => self.coverage(name, specs.as_slice()),
                    ret => ret,
                }
            }
        };
        // SAFETY: the container opened above.
        unsafe { upatch_close(&mut u) };
        ret
    }
}

/// The checks of the upatches the set `s` holds, into `c`.
pub(crate) fn checks_run(s: *const MeasuredSet, c: &mut Checks<'_>) {
    let mut devices_tried = false;

    // Elsewhere the devices are another namespace's, whether or not an
    // XDP upatch is found to check them against.
    if c.uncovered.is_some() {
        let ret = xdp::netns_initial();
        note_err(&mut c.coverage_err, ret);
        devices_tried = ret != 0;
    }
    let mut w = Walk {
        s,
        c,
        devices: Vec::new(),
        devices_tried,
        devices_ok: false,
    };
    let ret = each_pinned(&mut |name| w.check_one(name));
    // Nothing walked is nothing checked, coverage included.
    if ret < 0 {
        note_err(&mut w.c.check_err, ret);
        note_err(&mut w.c.coverage_err, ret);
    }
}

#[cfg(test)]
mod tests;
