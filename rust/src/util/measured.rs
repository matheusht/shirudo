// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The measured set behind `util/measured.h`: the upatches the eventlog
//! records as loaded, each with the payload of its load, and the pins
//! and archives that set does not account for.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;

use crate::errno::{E2BIG, EEXIST, EINVAL, ENAMETOOLONG, ENOENT, ENOMEM, ENOSPC};
use crate::sys::hex::hex_encode;
use crate::sys::libc::{Dirent, PATH_MAX, alphasort, errno, getxattr, scandir, strcmp, strnlen};
use crate::sys::malloc::{libc_free, xcalloc, xfree, xmalloc};
use crate::sys::seal::seal_owns;
use crate::text::{at, strscpy, strsprintf};
use crate::util::chain::MeasuredUpatch;
use crate::util::eventlog::{
    UPATCH_INIT, UPATCH_UNLOAD, eventlog_boot_upatches, eventlog_upatches,
};
use crate::util::upatch::{
    NAME_MAX, PAYLOAD_HASH_LEN, Upatch, upatch_close, upatch_header_name, upatch_member_valid,
    upatch_open, upatch_select,
};

/// `MEASURED_MAX`: the most upatches a set holds.
const MEASURED_MAX: usize = 4096;
/// `BPFFS_UPATCHES_DIR` of util/paths.h: the pins of the upatches loaded.
const BPFFS_UPATCHES_DIR: &CStr = c"/run/shirudo/bpffs/upatches";
/// `UPATCHES_DIR` of util/paths.h: the archives of the upatches loaded.
const UPATCHES_DIR: &CStr = c"/var/lib/shirudo/upatches";
/// `XATTR_PAYLOAD` of util/paths.h: the payload digest a pin records.
const XATTR_PAYLOAD: &CStr = c"security.bpf.shirudo.payload";

/// `struct measured_entry`: a member of a set.
#[repr(C)]
struct Entry {
    name: [u8; NAME_MAX + 1],
    payload_hex: [u8; 2 * PAYLOAD_HASH_LEN + 1],
}

/// `struct measured_set`: the members, room for MEASURED_MAX of them.
#[repr(C)]
pub struct MeasuredSet {
    entries: *mut Entry,
    n: usize,
}

/// What util/measured.h's pin walk calls with each upatch it finds.
type PinFn = unsafe extern "C" fn(name: *const c_char, ctx: *mut c_void) -> c_int;
/// What util/measured.h's archive walk calls with each upatch it finds.
type ArchiveFn =
    unsafe extern "C" fn(name: *const c_char, path: *const c_char, ctx: *mut c_void) -> c_int;

/// What util/measured.h's member walk calls with each measured upatch.
type EachFn = unsafe extern "C" fn(
    name: *const c_char,
    payload_hex: *const c_char,
    ctx: *mut c_void,
) -> c_int;

/// strscpy() of the C string at `src` into `dst`, reading no more of it
/// than the C's strnlen() bounded by the room did.
///
/// # Safety
///
/// `src` is a C string, or holds at least `dst.len()` bytes.
unsafe fn strscpy_c(dst: &mut [u8], src: *const c_char) -> Result<usize, c_int> {
    // SAFETY: the caller's string, measured within the room.
    let src = unsafe { core::slice::from_raw_parts(src.cast::<u8>(), strnlen(src, dst.len())) };

    strscpy(dst, src)
}

/// What the eventlog's walk calls with each init, load and unload it
/// measures: the set at `ctx` started over, the name's payload set or
/// the name added with it, or the name gone, the last member in its
/// place.
///
/// # Safety
///
/// `ctx` is a set, and for a load or an unload `name` and `payload_hex`
/// are C strings.
unsafe extern "C" fn measured_event(
    event: c_int,
    name: *const c_char,
    payload_hex: *const c_char,
    ctx: *mut c_void,
) -> c_int {
    // SAFETY: the walk hands back the set the fold gave it.
    let s = unsafe { &mut *ctx.cast::<MeasuredSet>() };
    let mut i = 0;

    if event == UPATCH_INIT {
        s.n = 0;
        return 0;
    }
    while i < s.n {
        // SAFETY: a member of the set and the walk's name.
        if unsafe { strcmp((&raw const (*s.entries.add(i)).name).cast(), name) } == 0 {
            break;
        }
        i += 1;
    }
    if event == UPATCH_UNLOAD {
        if i < s.n {
            s.n -= 1;
            // SAFETY: two members of the set, which may be one.
            unsafe { ptr::copy(s.entries.add(s.n), s.entries.add(i), 1) };
        }
        return 0;
    }
    if i == s.n {
        if s.n == MEASURED_MAX {
            return -ENOSPC;
        }
        s.n += 1;
    }
    // SAFETY: a member of the set, inside its room, and the walk's
    // strings.
    unsafe {
        let e = &mut *s.entries.add(i);

        if strscpy_c(&mut e.name, name).is_err()
            || strscpy_c(&mut e.payload_hex, payload_hex).is_err()
        {
            return -EINVAL;
        }
    }
    0
}

/// The set the eventlog's records make into `*out`: every boot's with
/// `all`, an empty one for no log, else this boot's.
///
/// # Safety
///
/// `out` is room for a pointer.
unsafe fn fold(out: *mut *mut MeasuredSet, all: bool) -> c_int {
    // SAFETY: the caller's room.
    unsafe { *out = ptr::null_mut() };
    // SAFETY: an allocation of a set, freed by its size.
    let s = unsafe { xmalloc(size_of::<MeasuredSet>()) }.cast::<MeasuredSet>();

    if s.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the set allocated, its fields written before any is read.
    let entries = unsafe {
        (&raw mut (*s).n).write(0);
        let entries = xcalloc(MEASURED_MAX, size_of::<Entry>()).cast::<Entry>();

        (&raw mut (*s).entries).write(entries);
        entries
    };
    if entries.is_null() {
        // SAFETY: the set, by its size.
        unsafe { xfree(s.cast(), size_of::<MeasuredSet>()) };
        return -ENOMEM;
    }
    // SAFETY: the walk calls back with the set, which outlives it.
    let mut ret = unsafe {
        if all {
            eventlog_upatches(Some(measured_event), s.cast())
        } else {
            eventlog_boot_upatches(Some(measured_event), s.cast())
        }
    };
    if ret == -ENOENT && all {
        ret = 0;
    }
    if ret != 0 {
        // SAFETY: the set and its members, freed once.
        unsafe { set_free(s) };
        return ret;
    }
    // SAFETY: the caller's room.
    unsafe { *out = s };
    0
}

/// # Safety
///
/// `s` is NULL or a set fold() made.
unsafe fn set_free(s: *mut MeasuredSet) {
    if s.is_null() {
        return;
    }
    // SAFETY: the set's members and the set, by their sizes.
    unsafe {
        xfree((*s).entries.cast(), MEASURED_MAX * size_of::<Entry>());
        xfree(s.cast(), size_of::<MeasuredSet>());
    }
}

/// Whether the set holds `name` with the payload `payload_hex`.
///
/// # Safety
///
/// `s` is a set, and `name` and `payload_hex` C strings.
unsafe fn holds(s: *const MeasuredSet, name: *const c_char, payload_hex: *const c_char) -> bool {
    // SAFETY: the caller's set.
    let s = unsafe { &*s };

    for i in 0..s.n {
        // SAFETY: a member of the set and the caller's strings.
        let found = unsafe {
            let e = s.entries.add(i);

            strcmp((&raw const (*e).name).cast(), name) == 0
                && strcmp((&raw const (*e).payload_hex).cast(), payload_hex) == 0
        };

        if found {
            return true;
        }
    }
    false
}

/// Walk each member in order, stopping at the first nonzero callback result.
///
/// # Safety
///
/// `s` is a valid set and `cb` accepts its member strings and `ctx`.
unsafe fn each(s: *const MeasuredSet, cb: EachFn, ctx: *mut c_void) -> c_int {
    // SAFETY: the caller's set.
    let s = unsafe { &*s };

    for i in 0..s.n {
        // SAFETY: the entry is within the set and its strings are NUL terminated.
        let ret = unsafe {
            let e = &*s.entries.add(i);
            cb(e.name.as_ptr().cast(), e.payload_hex.as_ptr().cast(), ctx)
        };
        if ret != 0 {
            return ret;
        }
    }
    0
}

/// The name and payload digest an init record lists for the upatch `u`.
///
/// # Safety
///
/// `e` is room for a member and `u` an open upatch.
unsafe fn upatch_of(e: *mut MeasuredUpatch, u: *const Upatch) {
    // SAFETY: the caller's room and upatch.
    unsafe {
        upatch_header_name(u, (&raw mut (*e).name).cast());
        hex_encode(
            (&raw const (*u).hdr.payload_sha256).cast(),
            PAYLOAD_HASH_LEN,
            (&raw mut (*e).payload_hex).cast(),
        );
    }
}

/// `name` with `payload_hex` added to the `*n` members of `set`, room for
/// `max`: 0, -EINVAL for a member upatch_member_valid() refuses, -EEXIST
/// for a name held, or -E2BIG when the set is full or a string too long.
///
/// # Safety
///
/// `set` has room for `max` members of which `*n` are held, and `name`
/// and `payload_hex` are C strings.
unsafe fn set_add(
    set: *mut MeasuredUpatch,
    n: *mut usize,
    max: usize,
    name: *const c_char,
    payload_hex: *const c_char,
) -> c_int {
    // SAFETY: the caller's strings.
    if !unsafe { upatch_member_valid(name, payload_hex) } {
        return -EINVAL;
    }
    // SAFETY: the caller's count.
    let count = unsafe { *n };
    for i in 0..count {
        // SAFETY: a member held and the caller's name.
        if unsafe { strcmp((&raw const (*set.add(i)).name).cast(), name) } == 0 {
            return -EEXIST;
        }
    }
    if count >= max {
        return -E2BIG;
    }
    // SAFETY: the room for the next member, and the caller's strings.
    unsafe {
        let e = &mut *set.add(count);

        if strscpy_c(&mut e.name, name).is_err()
            || strscpy_c(&mut e.payload_hex, payload_hex).is_err()
        {
            return -E2BIG;
        }
        *n = count + 1;
    }
    0
}

/// upatch_name_from_bpffs() of util/paths.h: the upatch name the pin
/// name `name` spells, each `~d` a dot again, into `out` with its NUL;
/// -EINVAL for another `~`, -ENAMETOOLONG for a name `out` cannot hold.
fn name_from_bpffs(out: &mut [u8], name: &[u8]) -> c_int {
    let (mut i, mut j) = (0, 0);

    if out.is_empty() {
        return -EINVAL;
    }
    while i < name.len() {
        let mut c = name[i];

        if c == b'~' {
            if at(name, i + 1) != b'd' {
                return -EINVAL;
            }
            i += 1;
            c = b'.';
        }
        if j + 1 >= out.len() {
            return -ENAMETOOLONG;
        }
        out[j] = c;
        j += 1;
        i += 1;
    }
    out[j] = 0;
    0
}

/// The `n` entries scandir() gave, and the list.
///
/// # Safety
///
/// `names` is the list of `n` entries scandir() allocated.
unsafe fn free_names(names: *mut *mut Dirent, n: c_int) {
    // SAFETY: the caller's list, each entry and the list freed once.
    unsafe {
        for i in 0..n.max(0) as usize {
            libc_free((*names.add(i)).cast());
        }
        libc_free(names.cast());
    }
}

/// The name of a directory entry, up to its NUL.
///
/// # Safety
///
/// `e` is an entry scandir() gave.
unsafe fn entry_name<'a>(e: *const Dirent) -> &'a [u8] {
    // SAFETY: the entry's name, a C string.
    unsafe { CStr::from_ptr((&raw const (*e).d_name).cast()) }.to_bytes()
}

/// The upatches pinned in the private bpffs that the set does not hold
/// with the payload their pin records, each to `cb`: how many, or the
/// first non-zero `cb` returned, or -errno.
///
/// # Safety
///
/// `s` is a set, and `cb` takes `ctx`.
unsafe fn unmeasured_pins(s: *const MeasuredSet, cb: Option<PinFn>, ctx: *mut c_void) -> c_int {
    let mut pins: *mut *mut Dirent = ptr::null_mut();
    let (mut ret, mut unmeasured) = (0, 0);

    // SAFETY: a C string, where the list goes, and a comparison.
    let n = unsafe {
        scandir(
            BPFFS_UPATCHES_DIR.as_ptr(),
            &mut pins,
            None,
            Some(alphasort),
        )
    };
    if n < 0 {
        return if errno() == ENOENT { 0 } else { -errno() };
    }
    for i in 0..n as usize {
        let mut payload_hex = [0u8; 2 * PAYLOAD_HASH_LEN + 1];
        let mut payload = [0u8; PAYLOAD_HASH_LEN];
        let mut name = [0u8; NAME_MAX + 1];
        let mut dir = [0u8; PATH_MAX];
        // SAFETY: an entry of the list.
        let pin = unsafe { entry_name(*pins.add(i)) };

        if pin == b"."
            || pin == b".."
            || name_from_bpffs(&mut name, pin) != 0
            || strsprintf(&mut dir, &[BPFFS_UPATCHES_DIR.to_bytes(), b"/", pin]).is_err()
        {
            continue;
        }
        // SAFETY: the pin's path, the attribute's name, and room for it.
        let got = unsafe {
            getxattr(
                dir.as_ptr().cast(),
                XATTR_PAYLOAD.as_ptr(),
                payload.as_mut_ptr().cast(),
                payload.len(),
            )
        };
        if got == payload.len() as isize {
            // SAFETY: the digest and room for its hex.
            unsafe {
                hex_encode(
                    payload.as_ptr(),
                    payload.len(),
                    payload_hex.as_mut_ptr().cast(),
                )
            };
        }
        // SAFETY: the caller's set, and two C strings.
        if unsafe { holds(s, name.as_ptr().cast(), payload_hex.as_ptr().cast()) } {
            continue;
        }
        unmeasured += 1;
        if let Some(cb) = cb {
            // SAFETY: the caller's function and context, with a name.
            ret = unsafe { cb(name.as_ptr().cast(), ctx) };
            if ret != 0 {
                break;
            }
        }
    }
    // SAFETY: the list scandir() gave.
    unsafe { free_names(pins, n) };
    if ret != 0 { ret } else { unmeasured }
}

/// The upatches archived with the seal label that the set does not hold
/// with the payload of their archive, each to `cb`: how many, or the
/// first non-zero `cb` returned, or -errno.
///
/// # Safety
///
/// `s` is a set, and `cb` takes `ctx`.
unsafe fn unmeasured_archives(
    s: *const MeasuredSet,
    cb: Option<ArchiveFn>,
    ctx: *mut c_void,
) -> c_int {
    let mut names: *mut *mut Dirent = ptr::null_mut();
    let (mut ret, mut unmeasured) = (0, 0);

    // SAFETY: a C string, where the list goes, a filter and a comparison.
    let n = unsafe {
        scandir(
            UPATCHES_DIR.as_ptr(),
            &mut names,
            Some(upatch_select),
            Some(alphasort),
        )
    };
    if n < 0 {
        return if errno() == ENOENT { 0 } else { -errno() };
    }
    for i in 0..n as usize {
        // SAFETY: all of whose bits zeroed are a member, which
        // upatch_of() fills.
        let mut m: MeasuredUpatch = unsafe { core::mem::zeroed() };
        let mut path = [0u8; PATH_MAX];
        let mut u = MaybeUninit::<Upatch>::uninit();
        // SAFETY: an entry of the list.
        let archive = unsafe { entry_name(*names.add(i)) };

        if strsprintf(&mut path, &[UPATCHES_DIR.to_bytes(), b"/", archive]).is_err() {
            continue;
        }
        // SAFETY: the archive's path, and room for the upatch; the C
        // opened only what the seal label marks.
        let opened = unsafe {
            seal_owns(path.as_ptr().cast())
                && upatch_open(path.as_ptr().cast(), u.as_mut_ptr()) == 0
        };
        if !opened {
            continue;
        }
        // SAFETY: the member's room and the upatch opened, closed once.
        unsafe {
            upatch_of(&mut m, u.as_ptr());
            upatch_close(u.as_mut_ptr());
        }
        // SAFETY: the caller's set, and the member's two C strings.
        if unsafe { holds(s, m.name.as_ptr().cast(), m.payload_hex.as_ptr().cast()) } {
            continue;
        }
        unmeasured += 1;
        if let Some(cb) = cb {
            // SAFETY: the caller's function and context, with a name and
            // a path.
            ret = unsafe { cb(m.name.as_ptr().cast(), path.as_ptr().cast(), ctx) };
            if ret != 0 {
                break;
            }
        }
    }
    // SAFETY: the list scandir() gave.
    unsafe { free_names(names, n) };
    if ret != 0 { ret } else { unmeasured }
}

mod capi {
    use core::ffi::{c_char, c_int, c_void};

    use super::{ArchiveFn, EachFn, MeasuredSet, PinFn};
    use crate::util::chain::MeasuredUpatch;
    use crate::util::upatch::Upatch;

    /// # Safety
    ///
    /// `out` is room for a pointer.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn measured_set_boot(out: *mut *mut MeasuredSet) -> c_int {
        // SAFETY: the caller passes the room.
        unsafe { super::fold(out, false) }
    }

    /// # Safety
    ///
    /// `out` is room for a pointer.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn measured_set_log(out: *mut *mut MeasuredSet) -> c_int {
        // SAFETY: the caller passes the room.
        unsafe { super::fold(out, true) }
    }

    /// # Safety
    ///
    /// `s` is a set, and `name` and `payload_hex` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn measured_holds(
        s: *const MeasuredSet,
        name: *const c_char,
        payload_hex: *const c_char,
    ) -> bool {
        // SAFETY: the caller passes a set and two C strings.
        unsafe { super::holds(s, name, payload_hex) }
    }

    /// # Safety
    ///
    /// `s` is NULL or a set, freed once.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn measured_set_free(s: *mut MeasuredSet) {
        // SAFETY: the caller passes NULL or a set.
        unsafe { super::set_free(s) }
    }

    /// # Safety
    ///
    /// `s` is a set and `cb` accepts its member strings and `ctx`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn measured_each(
        s: *const MeasuredSet,
        cb: EachFn,
        ctx: *mut c_void,
    ) -> c_int {
        // SAFETY: the caller passes the set and callback.
        unsafe { super::each(s, cb, ctx) }
    }

    /// # Safety
    ///
    /// `e` is room for a member and `u` an open upatch.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn measured_upatch_of(e: *mut MeasuredUpatch, u: *const Upatch) {
        // SAFETY: the caller passes the room and the upatch.
        unsafe { super::upatch_of(e, u) }
    }

    /// # Safety
    ///
    /// `set` has room for `max` members of which `*n` are held, and
    /// `name` and `payload_hex` are C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn measured_set_add(
        set: *mut MeasuredUpatch,
        n: *mut usize,
        max: usize,
        name: *const c_char,
        payload_hex: *const c_char,
    ) -> c_int {
        // SAFETY: the caller passes the set, its count and two C strings.
        unsafe { super::set_add(set, n, max, name, payload_hex) }
    }

    /// # Safety
    ///
    /// `s` is a set, and `cb` NULL or a function that takes `ctx`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn measured_unmeasured_pins(
        s: *const MeasuredSet,
        cb: Option<PinFn>,
        ctx: *mut c_void,
    ) -> c_int {
        // SAFETY: the caller passes a set and its function.
        unsafe { super::unmeasured_pins(s, cb, ctx) }
    }

    /// # Safety
    ///
    /// `s` is a set, and `cb` NULL or a function that takes `ctx`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn measured_unmeasured_archives(
        s: *const MeasuredSet,
        cb: Option<ArchiveFn>,
        ctx: *mut c_void,
    ) -> c_int {
        // SAFETY: the caller passes a set and its function.
        unsafe { super::unmeasured_archives(s, cb, ctx) }
    }
}
