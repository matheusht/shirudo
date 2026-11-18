// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the pin directory of a loaded upatch holds: which links, which
//! XDP program pins, the payload hash a load set on it; and the upatches
//! that have one.

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;

use crate::errno::{EINVAL, EIO, ENAMETOOLONG, ENOENT, ESTALE};
use crate::sys::libc::{errno, getxattr};
use crate::util::bpf_info::{Info, PROG_INFO_SIZE};
use crate::util::bpf_sys::bpf_obj_get;
use crate::util::upatch::{NAME_MAX, pin_name};
use crate::util::upatch_resolve::{BPFFS_UPATCHES_DIR, XATTR_PAYLOAD, pin_path};

/// `UPATCH_PAYLOAD_HASH_LEN`.
pub(crate) const PAYLOAD_HASH_LEN: usize = 32;
const BPF_PROG_TYPE_XDP: u32 = 6;
/// Where `struct bpf_prog_info` keeps its type and id.
const PROG_TYPE: usize = 0;
const PROG_ID: usize = 4;

/// `LINK_PIN_PREFIX` and `XDP_PROG_PIN_PREFIX` of util/paths.h.
pub(crate) const LINK_PIN_PREFIX: &[u8] = b"link_";
pub(crate) const XDP_PROG_PIN_PREFIX: &[u8] = b"xdp_prog_";

/// `struct upatch_pins`: the pins of an upatch's directory, as far as
/// whether it is loaded, and whole, goes: `link` of a single attach
/// program, the numbered links, lowest and highest, and the XDP program
/// pins, lowest first.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Pins {
    pub(crate) has_link: bool,
    pub(crate) nr_links: u32,
    pub(crate) first_link: u32,
    pub(crate) last_link: u32,
    pub(crate) nr_xdp_progs: u32,
    pub(crate) first_xdp_prog: u32,
}

/// The index of a `<prefix><n>` pin: n in decimal, without a leading
/// zero, within u32.
fn pin_index(entry: &[u8], prefix: &[u8]) -> Option<u32> {
    let digits = entry.strip_prefix(prefix)?;

    if digits.is_empty()
        || (digits[0] == b'0' && digits.len() > 1)
        || !digits.iter().all(u8::is_ascii_digit)
    {
        return None;
    }
    core::str::from_utf8(digits).ok()?.parse().ok()
}

impl Pins {
    /// One entry of the directory taken into account.
    pub(crate) fn note(&mut self, entry: &[u8]) {
        if entry == b"link" {
            self.has_link = true;
        } else if let Some(index) = pin_index(entry, LINK_PIN_PREFIX) {
            if self.nr_links == 0 || index < self.first_link {
                self.first_link = index;
            }
            if self.nr_links == 0 || index > self.last_link {
                self.last_link = index;
            }
            self.nr_links += 1;
        } else if let Some(index) = pin_index(entry, XDP_PROG_PIN_PREFIX) {
            if self.nr_xdp_progs == 0 || index < self.first_xdp_prog {
                self.first_xdp_prog = index;
            }
            self.nr_xdp_progs += 1;
        }
    }

    /// Only link_0 stands for the numbered links: a non-XDP upatch that
    /// has lost it must still read as not loaded, where restore calls
    /// that tampering. XDP link pins come and go with devices, so its
    /// program pin says it is loaded.
    pub(crate) fn loaded(&self) -> bool {
        self.has_link || (self.nr_links != 0 && self.first_link == 0) || self.nr_xdp_progs != 0
    }

    /// Whether the pins are the links of an upatch of `nr_attach`
    /// non-XDP programs: link alone for one, link_0 to link_<n-1> for
    /// more.
    pub(crate) fn complete(&self, nr_attach: u32) -> bool {
        match nr_attach {
            0 => true,
            1 => self.has_link,
            n => self.nr_links == n && self.first_link == 0 && self.last_link == n - 1,
        }
    }

    /// The pins of the directory of upatch `name`: -ENOENT without one.
    pub(crate) fn read(name: &[u8]) -> Result<Self, c_int> {
        let dir = [BPFFS_UPATCHES_DIR.as_bytes(), b"/", &pin_name(name)].concat();
        let errno = |e: std::io::Error| -e.raw_os_error().unwrap_or(EIO);
        let mut pins = Pins::default();

        for e in std::fs::read_dir(std::ffi::OsStr::from_bytes(&dir)).map_err(errno)? {
            pins.note(e.map_err(errno)?.file_name().as_bytes());
        }
        Ok(pins)
    }
}

/// Whether upatch `name` is loaded, by its pins alone, so a caller
/// without the task mark adds no denied BPF_OBJ_GET to the tamper
/// counters.
pub(crate) fn loaded_pins(name: &[u8]) -> bool {
    Pins::read(name).is_ok_and(|p| p.loaded())
}

/// The pin that keeps XDP program `index` of upatch `name` loaded.
pub(crate) fn xdp_prog_pin(name: &[u8], index: u32) -> Result<CString, c_int> {
    let entry = [XDP_PROG_PIN_PREFIX, index.to_string().as_bytes()].concat();

    pin_path(name, &[&entry]).map_err(|_| -ENAMETOOLONG)
}

/// XDP program `index` pinned for upatch `name`, and its id; -ESTALE when
/// the pin holds a program that is not XDP.
pub(crate) fn xdp_prog_open(name: &[u8], index: u32) -> Result<(OwnedFd, u32), c_int> {
    let pin = xdp_prog_pin(name, index)?;
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(pin.as_ptr()) };
    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the descriptor bpf_obj_get() opened, owned from here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let mut info = Info::<PROG_INFO_SIZE>::new();
    info.read(std::os::fd::AsRawFd::as_raw_fd(&fd))?;
    if info.u32_at(PROG_TYPE) != BPF_PROG_TYPE_XDP {
        return Err(-ESTALE);
    }
    Ok((fd, info.u32_at(PROG_ID)))
}

/// The payload hash a load set on the pin directory of upatch `name`:
/// -ENAMETOOLONG, -EINVAL when it is not a hash, or the -errno of the
/// read.
pub(crate) fn pin_payload(name: &[u8]) -> Result<[u8; PAYLOAD_HASH_LEN], c_int> {
    let dir = pin_path(name, &[]).map_err(|_| -ENAMETOOLONG)?;
    let mut out = [0u8; PAYLOAD_HASH_LEN];
    // SAFETY: two C strings and room for the hash.
    let n = unsafe {
        getxattr(
            dir.as_ptr(),
            XATTR_PAYLOAD.as_ptr(),
            out.as_mut_ptr().cast(),
            out.len(),
        )
    };
    if n < 0 {
        return Err(-errno());
    }
    if n as usize != PAYLOAD_HASH_LEN {
        return Err(-EINVAL);
    }
    Ok(out)
}

/// Calls `cb` with each `link_<n>` pin of upatch `name`, in directory
/// order, and stops at the first nonzero return, which it returns.
pub(crate) fn each_link(name: &[u8], cb: &mut dyn FnMut(u32, &CStr) -> c_int) -> c_int {
    let Ok(dir) = pin_path(name, &[]) else {
        return -ENAMETOOLONG;
    };
    let errno_of = |e: std::io::Error| -e.raw_os_error().unwrap_or(EIO);
    let entries = match std::fs::read_dir(std::ffi::OsStr::from_bytes(dir.as_bytes())) {
        Ok(e) => e,
        Err(e) => return errno_of(e),
    };
    for e in entries {
        let e = match e {
            Ok(e) => e,
            Err(e) => return errno_of(e),
        };
        let file = e.file_name();
        let Some(index) = pin_index(file.as_bytes(), LINK_PIN_PREFIX) else {
            continue;
        };
        let pin = [dir.as_bytes(), b"/", file.as_bytes()].concat();
        let Ok(pin) = CString::new(pin) else {
            return -ENAMETOOLONG;
        };
        let ret = cb(index, &pin);
        if ret != 0 {
            return ret;
        }
    }
    0
}

/// Calls `cb` with the name of each upatch that has a pin directory and
/// stops at the first nonzero return, which it returns. No directory at
/// all is 0, any other failure to read it -errno.
pub(crate) fn each_pinned(cb: &mut dyn FnMut(&[u8]) -> c_int) -> c_int {
    let errno_of = |e: std::io::Error| -e.raw_os_error().unwrap_or(EIO);
    let entries = match std::fs::read_dir(BPFFS_UPATCHES_DIR) {
        Ok(e) => e,
        Err(e) if e.raw_os_error() == Some(ENOENT) => return 0,
        Err(e) => return errno_of(e),
    };
    for e in entries {
        let e = match e {
            Ok(e) => e,
            Err(e) => return errno_of(e),
        };
        let mut name = [0u8; NAME_MAX + 1];
        if crate::util::measured::name_from_bpffs(&mut name, e.file_name().as_bytes()) != 0 {
            continue;
        }
        let ret = cb(crate::text::cstr(&name));
        if ret != 0 {
            return ret;
        }
    }
    0
}

mod capi {
    use core::ffi::{CStr, c_char, c_int};

    use super::Pins;
    use crate::errno::ENAMETOOLONG;
    use crate::text::strsprintf;

    /// # Safety
    ///
    /// `pins` is a record and `entry` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_pins_note(pins: *mut Pins, entry: *const c_char) {
        // SAFETY: the caller's record and C string.
        unsafe { (*pins).note(CStr::from_ptr(entry).to_bytes()) }
    }

    /// # Safety
    ///
    /// `pins` is a record.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_pins_loaded(pins: *const Pins) -> bool {
        // SAFETY: the caller's record.
        unsafe { (*pins).loaded() }
    }

    /// # Safety
    ///
    /// `pins` is a record.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_pins_complete(pins: *const Pins, nr_attach: u32) -> bool {
        // SAFETY: the caller's record.
        unsafe { (*pins).complete(nr_attach) }
    }

    /// 0, or a negative errno; -ENOENT when the upatch has no pin
    /// directory. `out` is cleared first.
    ///
    /// # Safety
    ///
    /// `name` is a C string and `out` room for a record.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_pins_read(name: *const c_char, out: *mut Pins) -> c_int {
        // SAFETY: the caller's C string and room.
        unsafe {
            *out = Pins::default();
            match Pins::read(CStr::from_ptr(name).to_bytes()) {
                Ok(pins) => {
                    *out = pins;
                    0
                }
                Err(err) => err,
            }
        }
    }

    /// # Safety
    ///
    /// `name` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_loaded_pins(name: *const c_char) -> bool {
        // SAFETY: the caller's C string.
        super::loaded_pins(unsafe { CStr::from_ptr(name) }.to_bytes())
    }

    /// The pin that keeps XDP program `index` of `name` loaded into `out`:
    /// 0, or -ENAMETOOLONG with `out` empty.
    ///
    /// # Safety
    ///
    /// `out` has room for `cap` bytes and `name` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_xdp_prog_pin(
        out: *mut c_char,
        cap: usize,
        name: *const c_char,
        index: u32,
    ) -> c_int {
        // SAFETY: the caller's room and C string.
        let (room, name) =
            unsafe { (crate::ffi::bytes_mut(out.cast(), cap), CStr::from_ptr(name)) };
        let pin = super::xdp_prog_pin(name.to_bytes(), index);
        match pin {
            Ok(p) if p.as_bytes().len() < room.len() => {
                room[..=p.as_bytes().len()].copy_from_slice(p.as_bytes_with_nul());
                0
            }
            _ => {
                if let Some(first) = room.first_mut() {
                    *first = 0;
                }
                -ENAMETOOLONG
            }
        }
    }

    /// The fd of XDP program `index` pinned for `name`, its id in `*id`,
    /// or -errno; -ESTALE when the pin holds a program that is not XDP.
    ///
    /// # Safety
    ///
    /// `name` is a C string and `id` room for a number.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_xdp_prog_open(
        name: *const c_char,
        index: u32,
        id: *mut u32,
    ) -> c_int {
        // SAFETY: the caller's C string.
        match super::xdp_prog_open(unsafe { CStr::from_ptr(name) }.to_bytes(), index) {
            Ok((fd, prog_id)) => {
                // SAFETY: the caller's room.
                unsafe { *id = prog_id };
                std::os::fd::IntoRawFd::into_raw_fd(fd)
            }
            Err(err) => err,
        }
    }

    /// # Safety
    ///
    /// `name` is a C string and `out` room for the hash.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_pin_payload(
        name: *const c_char,
        out: *mut [u8; super::PAYLOAD_HASH_LEN],
    ) -> c_int {
        // SAFETY: the caller's C string.
        match super::pin_payload(unsafe { CStr::from_ptr(name) }.to_bytes()) {
            Ok(hash) => {
                // SAFETY: the caller's room.
                unsafe { *out = hash };
                0
            }
            Err(err) => err,
        }
    }

    /// # Safety
    ///
    /// `cb` takes the name and `ctx`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_each_pinned(
        cb: unsafe extern "C" fn(*const c_char, *mut core::ffi::c_void) -> c_int,
        ctx: *mut core::ffi::c_void,
    ) -> c_int {
        super::each_pinned(&mut |name| {
            let Ok(name) = std::ffi::CString::new(name) else {
                return 0;
            };
            // SAFETY: the caller's callback and context, with a C string.
            unsafe { cb(name.as_ptr(), ctx) }
        })
    }

    /// # Safety
    ///
    /// `name` is a C string and `cb` takes the index, the pin and `ctx`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_each_link(
        name: *const c_char,
        cb: unsafe extern "C" fn(u32, *const c_char, *mut core::ffi::c_void) -> c_int,
        ctx: *mut core::ffi::c_void,
    ) -> c_int {
        // SAFETY: the caller's C string.
        super::each_link(
            unsafe { CStr::from_ptr(name) }.to_bytes(),
            &mut |index, pin| {
                // SAFETY: the caller's callback and context, with a C string.
                unsafe { cb(index, pin.as_ptr(), ctx) }
            },
        )
    }

    /// The numbered link `index` in the pin directory `dir`: 0 or
    /// -ENAMETOOLONG.
    ///
    /// # Safety
    ///
    /// `out` has room for `cap` bytes and `dir` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_link_pin(
        out: *mut c_char,
        cap: usize,
        dir: *const c_char,
        index: u32,
    ) -> c_int {
        // SAFETY: the caller's room and C string.
        let (out, dir) = unsafe {
            (
                core::slice::from_raw_parts_mut(out.cast::<u8>(), cap),
                CStr::from_ptr(dir).to_bytes(),
            )
        };
        let index = index.to_string();
        match strsprintf(out, &[dir, b"/", super::LINK_PIN_PREFIX, index.as_bytes()]) {
            Ok(_) => 0,
            Err(_) => -ENAMETOOLONG,
        }
    }
}
