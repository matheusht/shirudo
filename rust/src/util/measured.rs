// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The measured set: the upatches the eventlog
//! records as loaded, each with the payload of its load, and the pins
//! and archives that set does not account for.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;

use crate::errno::{E2BIG, EEXIST, EINVAL, ENAMETOOLONG, ENOENT, ENOMEM, ENOSPC};
use crate::heap::{xcalloc, xfree, xmalloc};
use crate::sys::libc::{PATH_MAX, getxattr, strcmp, strnlen};
use crate::text::{at, strscpy, strsprintf};
use crate::util::chain::MeasuredUpatch;
use crate::util::eventlog::{UPATCH_INIT, UPATCH_UNLOAD, eventlog_upatches};
use crate::util::hex::hex_encode;
use crate::util::seal::seal_owns;
use crate::util::upatch::{
    NAME_MAX, PAYLOAD_HASH_LEN, Upatch, upatch_close, upatch_header_name, upatch_member_valid,
    upatch_open,
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

/// What the pin walk calls with each upatch it finds.
type PinFn = unsafe extern "C" fn(name: *const c_char, ctx: *mut c_void) -> c_int;
/// What the archive walk calls with each upatch it finds.
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
            verified::upatches(measured_event, s.cast())
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
pub(crate) fn name_from_bpffs(out: &mut [u8], name: &[u8]) -> c_int {
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

/// The upatches pinned in the private bpffs that the set does not hold
/// with the payload their pin records, each to `cb`: how many, or the
/// first non-zero `cb` returned, or -errno.
///
/// # Safety
///
/// `s` is a set, and `cb` takes `ctx`.
unsafe fn unmeasured_pins(s: *const MeasuredSet, cb: Option<PinFn>, ctx: *mut c_void) -> c_int {
    let (mut ret, mut unmeasured) = (0, 0);

    let pins = match crate::util::io::dir_names(BPFFS_UPATCHES_DIR.to_bytes(), |_| true) {
        Ok(pins) => pins,
        Err(err) if err == -ENOENT => return 0,
        Err(err) => return err,
    };
    for pin in &pins {
        let mut payload_hex = [0u8; 2 * PAYLOAD_HASH_LEN + 1];
        let mut payload = [0u8; PAYLOAD_HASH_LEN];
        let mut name = [0u8; NAME_MAX + 1];
        let mut dir = [0u8; PATH_MAX];

        if name_from_bpffs(&mut name, pin) != 0
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
    let (mut ret, mut unmeasured) = (0, 0);

    let names = match crate::util::io::dir_names(UPATCHES_DIR.to_bytes(), |n| {
        crate::text::name_has_suffix(n, b".upatch")
    }) {
        Ok(names) => names,
        Err(err) if err == -ENOENT => return 0,
        Err(err) => return err,
    };
    for archive in &names {
        // SAFETY: all of whose bits zeroed are a member, which
        // upatch_of() fills.
        let mut m: MeasuredUpatch = unsafe { core::mem::zeroed() };
        let mut path = [0u8; PATH_MAX];
        let mut u = MaybeUninit::<Upatch>::uninit();

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
    if ret != 0 { ret } else { unmeasured }
}

/// The members of set `s` whose pin directory is gone, each handed to
/// `cb` until it returns nonzero: how many, that return, or -errno. A
/// load the records hold keeps its pin directory until its unload.
///
/// # Safety
///
/// `s` is a set.
pub(crate) unsafe fn unpinned(s: *const MeasuredSet, cb: &mut dyn FnMut(&[u8]) -> c_int) -> c_int {
    use std::os::unix::ffi::OsStrExt;

    // SAFETY: the caller's set.
    let s = unsafe { &*s };
    let mut n = 0;
    for i in 0..s.n {
        // SAFETY: a member of the set.
        let name = crate::text::cstr(unsafe { &(*s.entries.add(i)).name });
        let Ok(dir) = crate::util::upatch_resolve::pin_path(name, &[]) else {
            return -ENAMETOOLONG;
        };
        match std::fs::symlink_metadata(std::ffi::OsStr::from_bytes(dir.as_bytes())) {
            Ok(_) => continue,
            Err(e) if e.raw_os_error() == Some(ENOENT) => {}
            Err(e) => return -e.raw_os_error().unwrap_or(EINVAL),
        }
        n += 1;
        let ret = cb(name);
        if ret != 0 {
            return ret;
        }
    }
    n
}

pub(crate) use capi::{
    measured_holds, measured_set_add, measured_set_boot, measured_set_free, measured_set_log,
    measured_unmeasured_archives, measured_unmeasured_pins, measured_upatch_of,
};

#[cfg(test)]
mod tests;

mod capi {
    use core::ffi::{c_char, c_int, c_void};

    use super::{ArchiveFn, EachFn, MeasuredSet, PinFn};
    use crate::util::chain::MeasuredUpatch;
    use crate::util::upatch::Upatch;

    /// # Safety
    ///
    /// `out` is room for a pointer.
    pub unsafe extern "C" fn measured_set_boot(out: *mut *mut MeasuredSet) -> c_int {
        // SAFETY: the caller passes the room.
        unsafe { super::fold(out, false) }
    }

    /// # Safety
    ///
    /// `out` is room for a pointer.
    pub unsafe extern "C" fn measured_set_log(out: *mut *mut MeasuredSet) -> c_int {
        // SAFETY: the caller passes the room.
        unsafe { super::fold(out, true) }
    }

    /// # Safety
    ///
    /// `s` is a set, and `name` and `payload_hex` C strings.
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
    pub unsafe extern "C" fn measured_upatch_of(e: *mut MeasuredUpatch, u: *const Upatch) {
        // SAFETY: the caller passes the room and the upatch.
        unsafe { super::upatch_of(e, u) }
    }

    /// # Safety
    ///
    /// `set` has room for `max` members of which `*n` are held, and
    /// `name` and `payload_hex` are C strings.
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
    pub unsafe extern "C" fn measured_unmeasured_archives(
        s: *const MeasuredSet,
        cb: Option<ArchiveFn>,
        ctx: *mut c_void,
    ) -> c_int {
        // SAFETY: the caller passes a set and its function.
        unsafe { super::unmeasured_archives(s, cb, ctx) }
    }
}

/// This boot's records as the TPM vouches for them.
mod verified {
    use core::ffi::{c_int, c_void};
    use std::ffi::CString;

    use super::{MEASURED_MAX, set_add};
    use crate::errno::{EBADMSG, EINVAL, ENOENT, ENOMEM};
    use crate::text::cstr;
    use crate::util::chain::{
        self, ChainLive, MeasuredUpatch, chain_fold, chain_init_event, chain_key_event,
        chain_tree_event, chain_upatch_event, memneq_explicit,
    };
    use crate::util::eventlog::{self, upatches_record};
    use crate::util::hex;
    use crate::util::json::{JsonField, parse_schema};
    use crate::util::upatch::{NAME_MAX, PAYLOAD_HASH_LEN, member_valid};

    const TPM_NAME_LEN: usize = 34;
    type Callback = unsafe extern "C" fn(
        c_int,
        *const core::ffi::c_char,
        *const core::ffi::c_char,
        *mut c_void,
    ) -> c_int;

    /// What a record says of the register it was bound to.
    struct Binding {
        ty: [u8; 8],
        name_hex: [u8; 2 * TPM_NAME_LEN + 1],
        reset: i64,
    }

    /// Whether `line` is an init record of the register the TPM reports
    /// now: its index's name and the TPM's reset count.
    fn init_of_live(line: &[u8], live: &ChainLive) -> bool {
        let mut b = Binding {
            ty: [0; 8],
            name_hex: [0; 2 * TPM_NAME_LEN + 1],
            reset: -1,
        };
        let f = [
            JsonField::string(c"type", |b: &mut Binding| &mut b.ty),
            JsonField::string(c"nv_name", |b| &mut b.name_hex),
            JsonField::int(c"tpm_reset_count", |b| &mut b.reset),
        ];
        if parse_schema(line, &f, &mut b).is_err()
            || cstr(&b.ty) != b"init"
            || !f[1].seen()
            || !f[2].seen()
            || b.reset != i64::from(live.reset_count)
        {
            return false;
        }
        let text = cstr(&b.name_hex);
        let mut name = [0u8; TPM_NAME_LEN];
        text.len() == 2 * TPM_NAME_LEN && hex::decode(text, &mut name).is_ok() && name == live.name
    }

    /// The fields of a record that give its event.
    struct Record {
        ty: [u8; 32],
        digest_hex: [u8; 65],
        cert_hex: [u8; 65],
        tree_root_hex: [u8; 65],
        key_hex: [u8; 65],
        operation: [u8; 72],
        name: [u8; NAME_MAX + 1],
        payload_hex: [u8; 2 * PAYLOAD_HASH_LEN + 1],
        seq: i64,
        set: Vec<MeasuredUpatch>,
        n: usize,
        init: bool,
        upatch: bool,
        key: bool,
        tree: bool,
    }

    fn set_entry(r: &mut Record) -> Result<(), c_int> {
        // SAFETY: the record's set of MEASURED_MAX members, its count and
        // two C strings.
        let ret = unsafe {
            set_add(
                r.set.as_mut_ptr(),
                &mut r.n,
                MEASURED_MAX,
                r.name.as_ptr().cast(),
                r.payload_hex.as_ptr().cast(),
            )
        };
        r.name[0] = 0;
        r.payload_hex[0] = 0;
        match ret {
            0 => Ok(()),
            err => Err(err),
        }
    }

    fn parse(line: &[u8], r: &mut Record) -> c_int {
        let entry = [
            JsonField::string(c"name", |r: &mut Record| &mut r.name),
            JsonField::string(c"payload_sha256", |r| &mut r.payload_hex),
        ];
        let upatch = [
            JsonField::string(c"name", |r: &mut Record| &mut r.name),
            JsonField::string(c"payload_sha256", |r| &mut r.payload_hex),
        ];
        let key = [JsonField::string(c"cert_sha256", |r: &mut Record| {
            &mut r.key_hex
        })];
        let tree = [
            JsonField::int(c"seq", |r: &mut Record| &mut r.seq),
            JsonField::string(c"operation_digest", |r| &mut r.operation),
        ];
        let f = [
            JsonField::string(c"type", |r: &mut Record| &mut r.ty),
            JsonField::string(c"digest", |r| &mut r.digest_hex),
            JsonField::string(c"cert_sha256", |r| &mut r.cert_hex),
            JsonField::string(c"tree_root", |r| &mut r.tree_root_hex),
            JsonField::array(c"set", &entry, &set_entry),
            JsonField::object(c"upatch", &upatch),
            JsonField::object(c"key", &key),
            JsonField::object(c"tree", &tree),
        ];
        if parse_schema(line, &f, r).is_err() || !f[0].seen() || !f[1].seen() {
            return -EINVAL;
        }
        r.init = f[2].seen() && f[3].seen() && f[4].seen();
        r.upatch = f[5].seen();
        r.key = key[0].seen();
        r.tree = tree[0].seen() && tree[1].seen() && r.seq > 0;
        0
    }

    fn decode32(text: &[u8]) -> Result<[u8; 32], c_int> {
        let mut out = [0u8; 32];
        hex::decode(cstr(text), &mut out).map_err(|_| -EINVAL)?;
        Ok(out)
    }

    /// The event the fields of `r` give, as the extend that wrote it made
    /// it; a type no writer uses is refused.
    fn event_of(r: &mut Record) -> Result<[u8; 32], c_int> {
        let mut event = [0u8; 32];
        let ty = cstr(&r.ty);
        // SAFETY: digests and C strings of the record, and room for the
        // event.
        let ret = unsafe {
            match ty {
                b"init" => {
                    if !r.init {
                        return Err(-EINVAL);
                    }
                    let (cert, root) = (decode32(&r.cert_hex)?, decode32(&r.tree_root_hex)?);
                    let mut set_digest = [0u8; 32];
                    chain_init_event(
                        cert.as_ptr(),
                        r.set.as_mut_ptr(),
                        r.n,
                        root.as_ptr(),
                        set_digest.as_mut_ptr(),
                        event.as_mut_ptr(),
                    )
                }
                b"upatch_load" | b"upatch_unload" => {
                    if !r.upatch
                        || !member_valid(r.name.as_ptr().cast(), r.payload_hex.as_ptr().cast())
                    {
                        return Err(-EINVAL);
                    }
                    let payload = decode32(&r.payload_hex)?;
                    let tag = if ty == b"upatch_load" {
                        c"shirudo-upatch"
                    } else {
                        c"shirudo-unload"
                    };
                    chain_upatch_event(
                        tag.as_ptr(),
                        r.name.as_ptr().cast(),
                        payload.as_ptr(),
                        event.as_mut_ptr(),
                    )
                }
                b"key_revoke" => {
                    if !r.key {
                        return Err(-EINVAL);
                    }
                    let cert = decode32(&r.key_hex)?;
                    chain_key_event(
                        c"shirudo-key-revoke".as_ptr(),
                        cert.as_ptr(),
                        event.as_mut_ptr(),
                    )
                }
                b"tree_op" => {
                    let operation = crate::util::bpm_tree::digest_bytes(&r.operation);
                    let (true, Some(operation)) = (r.tree, operation) else {
                        return Err(-EINVAL);
                    };
                    chain_tree_event(r.seq, operation.as_ptr(), event.as_mut_ptr())
                }
                _ => return Err(-EINVAL),
            }
        };
        if ret != 0 { Err(ret) } else { Ok(event) }
    }

    /// The event the fields of a record give and the digest the record
    /// claims for it: a record counts for what it says only where the two
    /// agree.
    fn record_event(line: &[u8]) -> Result<([u8; 32], [u8; 32]), c_int> {
        let mut set = Vec::new();
        set.try_reserve_exact(MEASURED_MAX).map_err(|_| -ENOMEM)?;
        // SAFETY: an all-zero member is an empty one.
        set.resize_with(MEASURED_MAX, || unsafe { core::mem::zeroed() });
        let mut r = Box::new(Record {
            ty: [0; 32],
            digest_hex: [0; 65],
            cert_hex: [0; 65],
            tree_root_hex: [0; 65],
            key_hex: [0; 65],
            operation: [0; 72],
            name: [0; NAME_MAX + 1],
            payload_hex: [0; 2 * PAYLOAD_HASH_LEN + 1],
            seq: 0,
            set,
            n: 0,
            init: false,
            upatch: false,
            key: false,
            tree: false,
        });
        match parse(line, &mut r) {
            0 => {}
            err => return Err(err),
        }
        let digest = decode32(&r.digest_hex)?;
        Ok((event_of(&mut r)?, digest))
    }

    /// eventlog_boot_upatches() for the records the TPM vouches for: the
    /// boot starts at the last init record that names the live index and
    /// the TPM's reset count, every record's digest is derived from its
    /// fields, and the records fold to the value the TPM reports. `cb`
    /// sees the events as the walk goes; only a return of 0 makes them
    /// this boot's. -ENOENT without such an init record, -EBADMSG when a
    /// record or the fold does not match, -ENODEV without a register this
    /// reset.
    pub(super) fn upatches(cb: Callback, ctx: *mut c_void) -> c_int {
        let live = match chain::live() {
            Ok(l) => l,
            Err(err) => return err,
        };
        let log = match eventlog::read_records() {
            Ok(l) => l,
            Err(err) => return err,
        };
        let lines: Vec<&[u8]> = log
            .split_inclusive(|&c| c == b'\n')
            .filter_map(|l| l.strip_suffix(b"\n"))
            .collect();
        let Some(anchor) = lines.iter().rposition(|l| init_of_live(l, &live)) else {
            return -ENOENT;
        };
        let mut register = [0u8; 32];
        for (k, line) in lines[anchor..].iter().enumerate() {
            let (event, digest) = match record_event(line) {
                Ok(e) => e,
                Err(err) => return err,
            };
            if memneq_explicit(&event, &digest) {
                return -EBADMSG;
            }
            // SAFETY: the register and the event, digests both.
            let ret = unsafe { chain_fold(register.as_mut_ptr(), event.as_ptr()) };
            if ret != 0 {
                return ret;
            }
            let Ok(line) = CString::new(*line) else {
                return -EINVAL;
            };
            // SAFETY: the caller's callback and context.
            let ret = unsafe { upatches_record(&line, k == 0, Some(cb), ctx) };
            if ret != 0 {
                return ret;
            }
        }
        if memneq_explicit(&register, &live.value) {
            return -EBADMSG;
        }
        0
    }
}
