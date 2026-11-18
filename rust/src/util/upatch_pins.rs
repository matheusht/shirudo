// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the pin directory of a loaded upatch holds: main's
//! util/upatch_pins.c, whose XDP program pins, payload hash and walks
//! over pins come with the port of the upatch runtime.

use core::ffi::c_int;
use std::os::unix::ffi::OsStrExt;

use crate::errno::EIO;
use crate::util::upatch::pin_name;
use crate::util::upatch_resolve::BPFFS_UPATCHES_DIR;

/// `LINK_PIN_PREFIX` and `XDP_PROG_PIN_PREFIX` of util/paths.h.
pub(crate) const LINK_PIN_PREFIX: &[u8] = b"link_";
pub(crate) const XDP_PROG_PIN_PREFIX: &[u8] = b"xdp_prog_";

/// `struct upatch_pins`: the pins of an upatch's directory, as far as
/// whether it is loaded, and whole, goes.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Pins {
    has_link: bool,
    nr_links: u32,
    first_link: u32,
    last_link: u32,
    nr_xdp_progs: u32,
    first_xdp_prog: u32,
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
