// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! What the records of a boot say: the register they replay to, the
//! binding of its init record, a tree operation measured, and the
//! upatches loaded and unloaded.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use super::{sha256_calc, walk_boot, walk_log};
use crate::errno::{EINVAL, ENOENT};
use crate::sys::hex::hex_decode;
use crate::sys::libc::abort;
use crate::text::cstr;
use crate::util::json::{JsonArray, JsonField, parse_schema};
use crate::util::upatch::{NAME_MAX, PAYLOAD_HASH_LEN, upatch_member_valid};

const NAME_LEN: usize = 34;
const NV_RSA_BYTES: usize = 384;

/// `enum eventlog_upatch_event`.
pub(crate) const UPATCH_INIT: c_int = 0;
pub(super) const UPATCH_LOAD: c_int = 1;
pub(crate) const UPATCH_UNLOAD: c_int = 2;

/// What `eventlog_boot_lines()` calls with each line.
pub(super) type LineFn =
    unsafe extern "C" fn(line: *const c_char, len: usize, ctx: *mut c_void) -> c_int;
/// What the upatch walks call with each event.
pub(super) type UpatchFn = unsafe extern "C" fn(
    event: c_int,
    name: *const c_char,
    payload_hex: *const c_char,
    ctx: *mut c_void,
) -> c_int;

/// `struct eventlog_init`: this boot's last init record.
#[repr(C)]
pub struct EventlogInit {
    pub(crate) writer_public: [u8; NV_RSA_BYTES],
    pcr: u32,
    pub(crate) initrd: bool,
    pub(crate) pcr_before: [u8; 32],
    pub(crate) phase_before: [u8; 32],
    pub(crate) name: [u8; NAME_LEN],
    name_len: usize,
    pub(crate) anchor_digest: [u8; 32],
    pub(crate) have_reset_count: bool,
    pub(crate) reset_count: u32,
    records: u32,
    pub(crate) records_epoch: u32,
}

const _: () = assert!(size_of::<EventlogInit>() == 544);

/// `hex` decoded into `out`, as hex_decode() takes it: 0 or -EINVAL.
fn decode(hex: &[u8], out: &mut [u8]) -> c_int {
    // SAFETY: hex ends in a NUL the parser wrote, and out has room for
    // out.len() bytes.
    unsafe { hex_decode(hex.as_ptr().cast(), out.as_mut_ptr(), out.len()) }
}

/// The register this boot's records replay to: each digest folded in
/// order, from zero at an init record.
pub(super) fn replay(out: &mut [u8; 32]) -> c_int {
    let mut chain = [0u8; 32];
    let ret = walk_boot(&mut |line, is_init| replay_line(line, is_init, &mut chain));

    if ret == 0 {
        *out = chain;
    }
    ret
}

fn replay_line(line: &CStr, is_init: bool, chain: &mut [u8; 32]) -> c_int {
    let mut digest_hex = [0u8; 2 * 32 + 1];
    let mut digest = [0u8; 32];
    let mut cat = [0u8; 64];
    let mut f = [JsonField::string(
        c"digest",
        digest_hex.as_mut_ptr(),
        digest_hex.len(),
    )];

    // SAFETY: the schema names a local of this call.
    if unsafe { parse_schema(line.to_bytes(), f.as_mut_ptr(), f.len()) } != 0
        || !f[0].seen()
        || decode(&digest_hex, &mut digest) != 0
    {
        return -EINVAL;
    }
    if is_init {
        *chain = [0; 32];
    }
    cat[..32].copy_from_slice(chain);
    cat[32..].copy_from_slice(&digest);
    sha256_calc(&cat, chain)
}

/// This boot's last init record into `out`, which the caller zeroed.
pub(super) fn boot_init(out: &mut EventlogInit) -> c_int {
    walk_boot(&mut |line, is_init| init_line(line, is_init, out))
}

fn init_line(line: &CStr, is_init: bool, out: &mut EventlogInit) -> c_int {
    let mut writer_public = [0u8; 2 * NV_RSA_BYTES + 1];
    let mut pcr_before = [0u8; 2 * 32 + 1];
    let mut name = [0u8; 2 * NAME_LEN + 1];
    let mut phase_before = [0u8; 2 * 32 + 1];
    let mut anchor = [0u8; 2 * 32 + 1];
    let mut bound_in = [0u8; 8];
    let (mut pcr, mut reset_count) = (-1i64, -1i64);

    if !is_init {
        return 0;
    }
    let mut f = [
        JsonField::string(c"pcr_before", pcr_before.as_mut_ptr(), pcr_before.len()),
        JsonField::string(c"nv_name", name.as_mut_ptr(), name.len()),
        JsonField::string(c"anchor_digest", anchor.as_mut_ptr(), anchor.len()),
        JsonField::int(c"pcr", &mut pcr),
        JsonField::int(c"tpm_reset_count", &mut reset_count),
        JsonField::string(
            c"phase_before",
            phase_before.as_mut_ptr(),
            phase_before.len(),
        ),
        JsonField::string(c"bound_in", bound_in.as_mut_ptr(), bound_in.len()),
        JsonField::string(
            c"nv_writer_public",
            writer_public.as_mut_ptr(),
            writer_public.len(),
        ),
    ];
    // SAFETY: the schema names locals of this call.
    let ret = unsafe { parse_schema(line.to_bytes(), f.as_mut_ptr(), f.len()) };

    if ret != 0
        || !f[0].seen()
        || !f[1].seen()
        || !f[2].seen()
        || !f[3].seen()
        || !f[5].seen()
        || !(0..24).contains(&pcr)
        || (f[4].seen() && !(0..=i64::from(u32::MAX)).contains(&reset_count))
        || cstr(&name).len() != 2 * NAME_LEN
        || decode(&pcr_before, &mut out.pcr_before) != 0
        || decode(&phase_before, &mut out.phase_before) != 0
        || decode(&name, &mut out.name) != 0
        || decode(&anchor, &mut out.anchor_digest) != 0
        || !f[7].seen()
        || decode(&writer_public, &mut out.writer_public) != 0
    {
        return -EINVAL;
    }
    out.initrd = f[6].seen() && cstr(&bound_in) == b"initrd";
    // Records are of one TPM reset unless both carry a count and the
    // counts differ; a record without one cannot vouch for a reset in
    // between.
    let have_reset_count = f[4].seen();
    out.records = out.records.wrapping_add(1);
    if out.records == 1
        || (have_reset_count && out.have_reset_count && reset_count as u32 != out.reset_count)
    {
        out.records_epoch = 1;
    } else {
        out.records_epoch = out.records_epoch.wrapping_add(1);
    }
    out.have_reset_count = have_reset_count;
    out.reset_count = reset_count as u32;
    out.name_len = NAME_LEN;
    out.pcr = pcr as u32;
    0
}

/// Each of this boot's lines to `cb`, as a C string and its length; a
/// NULL `cb` faults when called, as the C's call through it did.
pub(super) fn boot_lines(cb: Option<LineFn>, ctx: *mut c_void) -> c_int {
    walk_boot(&mut |line, _| {
        let Some(cb) = cb else {
            // SAFETY: a call that takes nothing.
            unsafe { abort() }
        };
        // SAFETY: the caller's function and context, with a line that
        // lives for the call.
        unsafe { cb(line.as_ptr(), line.to_bytes().len(), ctx) }
    })
}

/// Whether this boot measured the tree operation of sequence `seq` and
/// digest `digest`: 1, 0, or a negative errno.
pub(super) fn tree_op_measured(seq: i64, digest: &[u8]) -> c_int {
    let mut found = false;
    let ret = walk_boot(&mut |line, _| {
        let mut ty = [0u8; 32];
        let mut line_digest = [0u8; 128];
        let mut line_seq = 0i64;
        let mut tree = [
            JsonField::int(c"seq", &mut line_seq),
            JsonField::string(
                c"operation_digest",
                line_digest.as_mut_ptr(),
                line_digest.len(),
            ),
        ];
        let mut f = [
            JsonField::string(c"type", ty.as_mut_ptr(), ty.len()),
            JsonField::object(c"tree", tree.as_mut_ptr(), tree.len()),
        ];

        // SAFETY: the schema names locals of this call.
        if unsafe { parse_schema(line.to_bytes(), f.as_mut_ptr(), f.len()) } != 0 {
            return -EINVAL;
        }
        if f[0].seen()
            && cstr(&ty) == b"tree_op"
            && tree[0].seen()
            && tree[1].seen()
            && line_seq == seq
            && cstr(&line_digest) == digest
        {
            found = true;
        }
        0
    });

    if ret == -ENOENT {
        return 0;
    }
    if ret != 0 {
        return ret;
    }
    c_int::from(found)
}

/// The upatch walk's state. The parser writes the entry fields, and the
/// array callback reads them and the rest, through raw pointers alone.
struct UpatchSink {
    cb: Option<UpatchFn>,
    ctx: *mut c_void,
    name: [u8; NAME_MAX + 1],
    payload_hex: [u8; 2 * PAYLOAD_HASH_LEN + 1],
    ret: c_int,
}

/// The sink's callback on `event`, which faults when it is NULL, as the
/// C's call through it did.
///
/// # Safety
///
/// `u` is the walk's sink, and `name` and `payload` are NULL or C
/// strings.
unsafe fn notify(
    u: *mut UpatchSink,
    event: c_int,
    name: *const c_char,
    payload: *const c_char,
) -> c_int {
    // SAFETY: the caller's sink and strings.
    unsafe {
        match (*u).cb {
            Some(cb) => cb(event, name, payload, (*u).ctx),
            None => abort(),
        }
    }
}

/// An entry of an init record's set: a load boot restore made.
unsafe extern "C" fn on_set_entry(ud: *mut c_void) -> c_int {
    let u = ud.cast::<UpatchSink>();

    // SAFETY: the sink upatches() made the array's context, which the
    // parser is not writing now; name and payload_hex are terminated
    // within their room.
    unsafe {
        let name = (&raw const (*u).name).cast::<c_char>();
        let payload = (&raw const (*u).payload_hex).cast::<c_char>();

        if !upatch_member_valid(name, payload) {
            return -EINVAL;
        }
        (*u).ret = notify(u, UPATCH_LOAD, name, payload);
        (*u).name[0] = 0;
        (*u).payload_hex[0] = 0;
        (*u).ret
    }
}

/// The upatch events of this boot's records, or with `all` of every
/// record: an init and the set its record lists, then each load and
/// unload.
pub(super) fn upatches(all: bool, cb: Option<UpatchFn>, ctx: *mut c_void) -> c_int {
    let mut sink = UpatchSink {
        cb,
        ctx,
        name: [0; NAME_MAX + 1],
        payload_hex: [0; 2 * PAYLOAD_HASH_LEN + 1],
        ret: 0,
    };
    let u = &raw mut sink;

    walk_log(all, &mut |line, is_init| {
        // SAFETY: the sink lives for the walk and is reached through u
        // alone.
        unsafe { upatches_line(u, line.to_bytes(), is_init) }
    })
}

/// Parse one record for a C caller that already read and checked the log.
pub(super) fn upatches_record(
    line: &[u8],
    is_init: bool,
    cb: Option<UpatchFn>,
    ctx: *mut c_void,
) -> c_int {
    let mut sink = UpatchSink {
        cb,
        ctx,
        name: [0; NAME_MAX + 1],
        payload_hex: [0; 2 * PAYLOAD_HASH_LEN + 1],
        ret: 0,
    };
    // SAFETY: the sink belongs to this call alone.
    unsafe { upatches_line(&raw mut sink, line, is_init) }
}

/// # Safety
///
/// `u` is the walk's sink, which only this pointer reaches meanwhile.
unsafe fn upatches_line(u: *mut UpatchSink, line: &[u8], is_init: bool) -> c_int {
    let mut ty = [0u8; 32];

    // SAFETY: the caller's sink; the schema names it and a local of this
    // call, and the callback reaches the sink through u's copy.
    unsafe {
        let name = (&raw mut (*u).name).cast::<u8>();
        let payload = (&raw mut (*u).payload_hex).cast::<u8>();

        *name = 0;
        *payload = 0;
        if is_init {
            let ret = notify(u, UPATCH_INIT, ptr::null(), ptr::null());
            if ret != 0 {
                return ret;
            }
        }
        let mut entry = [
            JsonField::string(c"name", name, NAME_MAX + 1),
            JsonField::string(c"payload_sha256", payload, 2 * PAYLOAD_HASH_LEN + 1),
        ];
        let mut set = JsonArray::new(on_set_entry, u.cast());
        // Only an init record's set lists what boot restore loaded.
        let set_field = JsonField::array(c"set", &raw mut set, entry.as_mut_ptr(), entry.len());
        let mut f = [
            JsonField::string(c"type", ty.as_mut_ptr(), ty.len()),
            if is_init {
                set_field
            } else {
                set_field.keyless()
            },
            JsonField::object(c"upatch", entry.as_mut_ptr(), entry.len()),
        ];

        if parse_schema(line, f.as_mut_ptr(), f.len()) != 0 {
            return if (*u).ret != 0 { (*u).ret } else { -EINVAL };
        }
        if is_init {
            return 0;
        }
        let t = cstr(&ty);
        if t != b"upatch_load" && t != b"upatch_unload" {
            return 0;
        }
        if !f[2].seen() || !upatch_member_valid(name.cast(), payload.cast()) {
            return -EINVAL;
        }
        let event = if t[7] == b'l' {
            UPATCH_LOAD
        } else {
            UPATCH_UNLOAD
        };
        notify(u, event, name.cast(), payload.cast())
    }
}
