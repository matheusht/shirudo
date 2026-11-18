// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The measurement register behind `util/chain.h`: an NV extend index
//! bound to this boot and anchored in a PCR, after systemd's NvPCR, and
//! the digests every measuring path shares.

use core::ffi::{c_int, c_void};
use core::mem::MaybeUninit;
use core::ptr;

use crate::errno::{E2BIG, EACCES, EEXIST, EIO, EKEYREJECTED, ENODEV, ENOENT, ENOMEM, EPROTO};
use crate::heap::{xfree, xmalloc};
use crate::sys::libc::{qsort, strcmp, strerror, strlen, strnlen};
use crate::sys::tss2::NV_WRITTEN;
use crate::text::{cstr, strsprintf};
use crate::util::config::{self, Scrubbed};
use crate::util::crypto_openssl::{
    Sha256Ctx, sha256_buffer, sha256_final, sha256_free, sha256_init, sha256_update,
};
use crate::util::eventlog::{EventlogInit, NV_INDEX, eventlog_boot_init, eventlog_path};
use crate::util::hex::hex_encode;
use crate::util::initrd::in_initrd;
use crate::util::nv_writer;
use crate::util::tpm::{
    REGISTER_ATTRS, Tpm, TpmNvInfo, tpm_close, tpm_nv_define, tpm_nv_extend, tpm_nv_extend_first,
    tpm_nv_info, tpm_nv_read, tpm_nv_set_writer, tpm_nv_undefine, tpm_open, tpm_open_quiet,
    tpm_pcr_extend, tpm_pcr_read, tpm_reset_count,
};
use crate::util::tpm_wire::{DIGEST_LEN, NAME_LEN, NV_RSA_BYTES, tpm_nv_name, tpm_register_policy};
use crate::util::upatch::{NAME_MAX, PAYLOAD_HASH_LEN};

/// `CHAIN_NAME`, the register's name in its anchor.
const CHAIN_NAME: &[u8] = b"shirudo";
/// `CHAIN_PCR`: PCR 9, which holds the initrd and nothing measured after
/// it, and takes the anchor.
pub(crate) const PCR: u32 = 9;
/// `CHAIN_PHASE_PCR`: PCR 11, which systemd extends with the boot phase.
pub(crate) const PHASE_PCR: u32 = 11;
/// `CHAIN_PCR_MASK`: the PCRs the init branch binds to.
pub(crate) const PCR_MASK: u32 = (1 << PCR) | (1 << PHASE_PCR);
/// `CHAIN_ANCHOR_MAX`.
pub(crate) const ANCHOR_MAX: usize = 128;

/// `struct measured_upatch`: a member of the set an init event lists.
#[repr(C)]
pub struct MeasuredUpatch {
    pub(crate) name: [u8; NAME_MAX + 1],
    pub(crate) payload_hex: [u8; 2 * PAYLOAD_HASH_LEN + 1],
}

/// `struct chain_init_info`: the binding chain_init() made or found.
#[repr(C)]
pub struct ChainInitInfo {
    pub(crate) writer_public: [u8; NV_RSA_BYTES],
    pub(crate) reused: bool,
    pub(crate) initrd: bool,
    pub(crate) reset_count: u32,
    pub(crate) value: [u8; DIGEST_LEN],
    pub(crate) pcr_before: [u8; DIGEST_LEN],
    pub(crate) phase_before: [u8; DIGEST_LEN],
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) name_len: usize,
    pub(crate) anchor: [u8; ANCHOR_MAX],
    pub(crate) anchor_digest: [u8; DIGEST_LEN],
}

/// `struct chain_status`: the register as a status report sees it.
#[repr(C)]
pub struct ChainStatus {
    pub(crate) tpm: bool,
    pub(crate) defined: bool,
    pub(crate) written: bool,
    pub(crate) logged: bool,
    pub(crate) anchored: bool,
    pub(crate) rebound: bool,
    pub(crate) value: [u8; DIGEST_LEN],
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) name_len: usize,
    pub(crate) init: EventlogInit,
}

const _: () = assert!(size_of::<ChainLive>() == 72);
const _: () = assert!(size_of::<MeasuredUpatch>() == 322);
const _: () = assert!(size_of::<ChainInitInfo>() == 696);
const _: () = assert!(core::mem::offset_of!(ChainInitInfo, reset_count) == 388);
const _: () = assert!(core::mem::offset_of!(ChainInitInfo, name_len) == 528);
const _: () = assert!(core::mem::offset_of!(ChainInitInfo, anchor_digest) == 664);
const _: () = assert!(size_of::<ChainStatus>() == 624);
const _: () = assert!(core::mem::offset_of!(ChainStatus, name_len) == 72);
const _: () = assert!(core::mem::offset_of!(ChainStatus, init) == 80);

/// memneq_explicit() of include/shirudo/string.h: whether the two
/// differ, in a time that depends on their length alone.
/// The history root of a tree after one more operation, whatever its
/// outcome on this node: SHA-256 of "shirudo-tree-history" with its NUL,
/// the root before it and the operation's digest. The publisher computes
/// a segment's base with it, without the TPM.
pub(crate) fn history_step(
    prev: &[u8; 32],
    operation_digest: &[u8; 32],
) -> Result<[u8; 32], c_int> {
    const TAG: &[u8] = b"shirudo-tree-history\0";
    let mut buf = [0u8; TAG.len() + 64];

    buf[..TAG.len()].copy_from_slice(TAG);
    buf[TAG.len()..TAG.len() + 32].copy_from_slice(prev);
    buf[TAG.len() + 32..].copy_from_slice(operation_digest);
    crate::util::crypto_openssl::sha256(&buf)
}

pub(crate) fn memneq_explicit(a: &[u8], b: &[u8]) -> bool {
    let mut neq = 0u8;

    for (x, y) in a.iter().zip(b) {
        neq |= x ^ y;
        neq = core::hint::black_box(neq);
    }
    neq != 0
}

/// SHA-256 of the `a_len` bytes at `a` and then, if any, the `b_len` at
/// `b`, into `out`, or zeros and the error: sha256_2().
///
/// # Safety
///
/// `a` and `b` hold their lengths' bytes and `out` has room for a
/// digest.
pub(crate) unsafe fn sha256_2(
    a: *const c_void,
    a_len: usize,
    b: *const c_void,
    b_len: usize,
    out: *mut u8,
) -> c_int {
    let mut ctx = Sha256Ctx::new();
    // SAFETY: the context here.
    let mut ret = unsafe { sha256_init(&mut ctx) };

    if ret == 0 {
        // SAFETY: the context begun, the caller's bytes and room.
        unsafe {
            ret = sha256_update(&mut ctx, a, a_len);
            if ret == 0 && b_len != 0 {
                ret = sha256_update(&mut ctx, b, b_len);
            }
            if ret == 0 {
                ret = sha256_final(&mut ctx, out);
            }
            sha256_free(&mut ctx);
        }
    }
    if ret != 0 {
        // SAFETY: the caller's room for a digest.
        unsafe { out.write_bytes(0, DIGEST_LEN) };
    }
    ret
}

/// The order qsort() gives the set: strcmp() of the names.
///
/// # Safety
///
/// `a` and `b` are members of a set, whose names end in a NUL.
unsafe extern "C" fn member_cmp(a: *const c_void, b: *const c_void) -> c_int {
    // SAFETY: qsort() hands two members of the caller's set.
    unsafe {
        strcmp(
            (&raw const (*a.cast::<MeasuredUpatch>()).name).cast(),
            (&raw const (*b.cast::<MeasuredUpatch>()).name).cast(),
        )
    }
}

/// A member's payload digest in hex and its name, each up to the NUL
/// strlen() finds, as the C's "%s" took them.
///
/// # Safety
///
/// `m` is a member whose strings end in a NUL, in their fields or past.
unsafe fn member_strings<'a>(m: *const MeasuredUpatch) -> (&'a [u8], &'a [u8]) {
    // SAFETY: the caller's member, and the C strings at its fields.
    unsafe {
        let hex = (&raw const (*m).payload_hex).cast::<u8>();
        let name = (&raw const (*m).name).cast::<u8>();

        (
            core::slice::from_raw_parts(hex, strlen(hex.cast())),
            core::slice::from_raw_parts(name, strlen(name.cast())),
        )
    }
}

/// The init event: the set sorted by name, its listing of one
/// "<payload hex> <name>\n" line a member, whose digest goes into
/// `set_digest`, and the digest of the tag, `cert_sha`, the listing's
/// and `tree_root` into `event`. Both are zeros when it fails.
///
/// # Safety
///
/// `set` holds `n` members, `cert_sha` and `tree_root` digests, and
/// `set_digest` and `event` have room for one.
unsafe fn init_event(
    cert_sha: *const u8,
    set: *mut MeasuredUpatch,
    n: usize,
    tree_root: *const u8,
    set_digest: *mut u8,
    event: *mut u8,
) -> c_int {
    const TAG: &[u8] = b"shirudo-init\0";
    let mut tag = [0u8; TAG.len() + 3 * DIGEST_LEN];
    let mut listing_len = 0usize;
    let mut off = 0;

    if n > 1 {
        // SAFETY: the caller's n members, sorted in place.
        unsafe { qsort(set.cast(), n, size_of::<MeasuredUpatch>(), Some(member_cmp)) };
    }
    for i in 0..n {
        // SAFETY: a member of the caller's set.
        let (hex, name) = unsafe { member_strings(set.add(i)) };

        listing_len += hex.len() + 1 + name.len() + 1;
    }
    // SAFETY: the caller's room for the two digests.
    unsafe {
        set_digest.write_bytes(0, DIGEST_LEN);
        event.write_bytes(0, DIGEST_LEN);
    }
    // SAFETY: an allocation, freed below by its size.
    let listing = unsafe { xmalloc(listing_len + 1) }.cast::<u8>();

    if listing.is_null() {
        return -ENOMEM;
    }
    for i in 0..n {
        // SAFETY: a member of the caller's set, and the room the
        // allocation has left.
        let (hex, name, room) = unsafe {
            let (hex, name) = member_strings(set.add(i));

            (
                hex,
                name,
                core::slice::from_raw_parts_mut(listing.add(off), listing_len + 1 - off),
            )
        };

        match strsprintf(room, &[hex, b" ", name, b"\n"]) {
            Ok(w) => off += w,
            Err(e) => {
                // SAFETY: the allocation, by its size.
                unsafe { xfree(listing.cast(), listing_len + 1) };
                return e;
            }
        }
    }
    // SAFETY: the listing, freed once by its size, and the caller's room.
    let ret = unsafe {
        let ret = sha256_buffer(listing.cast(), listing_len, set_digest);

        xfree(listing.cast(), listing_len + 1);
        ret
    };
    if ret != 0 {
        return ret;
    }
    tag[..TAG.len()].copy_from_slice(TAG);
    // SAFETY: the caller's digests, its room for one, and the tag here.
    unsafe {
        let fields = tag[TAG.len()..].as_mut_ptr();

        ptr::copy_nonoverlapping(cert_sha, fields, DIGEST_LEN);
        ptr::copy_nonoverlapping(set_digest, fields.add(DIGEST_LEN), DIGEST_LEN);
        ptr::copy_nonoverlapping(tree_root, fields.add(2 * DIGEST_LEN), DIGEST_LEN);
        sha256_buffer(tag.as_ptr().cast(), tag.len(), event)
    }
}

/// The event of a upatch loaded or unloaded: the digest of `tag` and its
/// NUL, the payload digest and the name cut at NAME_MAX bytes.
///
/// # Safety
///
/// `tag` and `name` are C strings, `payload` a digest and `event` room
/// for one.
unsafe fn upatch_event(
    tag: *const u8,
    name: *const u8,
    payload: *const u8,
    event: *mut u8,
) -> c_int {
    let mut buf = [0u8; b"shirudo-unload\0".len() + DIGEST_LEN + NAME_MAX];
    // SAFETY: the caller's C strings.
    let (taglen, namelen) = unsafe { (strlen(tag.cast()) + 1, strnlen(name.cast(), NAME_MAX)) };
    let mut off = 0;

    // SAFETY: the caller's tag and its NUL, digest and name, each of the
    // length measured; a tag longer than the room overran the C's.
    unsafe {
        buf[off..off + taglen].copy_from_slice(core::slice::from_raw_parts(tag, taglen));
        off += taglen;
        buf[off..off + DIGEST_LEN]
            .copy_from_slice(core::slice::from_raw_parts(payload, DIGEST_LEN));
        off += DIGEST_LEN;
        buf[off..off + namelen].copy_from_slice(core::slice::from_raw_parts(name, namelen));
        off += namelen;
        sha256_buffer(buf.as_ptr().cast(), off, event)
    }
}

/// The event of a tree operation: the digest of the tag and its NUL,
/// `seq` as a u64 most significant byte first, and the operation's
/// digest.
///
/// # Safety
///
/// `operation` is a digest and `event` room for one.
unsafe fn tree_event(seq: i64, operation: *const u8, event: *mut u8) -> c_int {
    const TAG: &[u8] = b"shirudo-tree\0";
    let mut buf = [0u8; TAG.len() + 8 + DIGEST_LEN];

    buf[..TAG.len()].copy_from_slice(TAG);
    buf[TAG.len()..TAG.len() + 8].copy_from_slice(&(seq as u64).to_be_bytes());
    // SAFETY: the caller's digest and room.
    unsafe {
        ptr::copy_nonoverlapping(operation, buf[TAG.len() + 8..].as_mut_ptr(), DIGEST_LEN);
        sha256_buffer(buf.as_ptr().cast(), buf.len(), event)
    }
}

/// The register at `chain` extended by `event`, as the TPM extends it,
/// or zeros and the error.
///
/// # Safety
///
/// `chain` and `event` are digests, which may be the same.
unsafe fn fold(chain: *mut u8, event: *const u8) -> c_int {
    let mut cat = [0u8; 2 * DIGEST_LEN];

    // SAFETY: the caller's two digests, copied before the result
    // overwrites the register.
    unsafe {
        ptr::copy_nonoverlapping(chain, cat.as_mut_ptr(), DIGEST_LEN);
        ptr::copy_nonoverlapping(event, cat[DIGEST_LEN..].as_mut_ptr(), DIGEST_LEN);
        sha256_buffer(cat.as_ptr().cast(), cat.len(), chain)
    }
}

/// `v` as "%x" prints it.
fn lower_hex(v: u32, buf: &mut [u8; 8]) -> &[u8] {
    let skip = (v.leading_zeros() / 4).min(7) as usize;

    for (i, d) in buf.iter_mut().enumerate() {
        *d = b"0123456789abcdef"[((v >> (28 - 4 * i)) & 0xf) as usize];
    }
    &buf[skip..]
}

/// The PCR record anchoring the register named `name` into `out`:
/// "nvpcr-init:shirudo:0x<index>:<name in hex>", or -E2BIG and, for room
/// of a byte or more, an empty string.
///
/// # Safety
///
/// `name` is a name and `out` has room for `cap` bytes.
unsafe fn anchor(name: *const u8, out: *mut u8, cap: usize) -> c_int {
    let mut hex = [0u8; 2 * NAME_LEN + 1];
    let mut index = [0u8; 8];

    // SAFETY: the caller's name, and room for its hex and NUL.
    unsafe { hex_encode(name, NAME_LEN, hex.as_mut_ptr().cast()) };
    if cap == 0 {
        return -E2BIG;
    }
    // SAFETY: the caller's room.
    let out = unsafe { core::slice::from_raw_parts_mut(out, cap) };
    let parts: [&[u8]; 6] = [
        b"nvpcr-init:",
        CHAIN_NAME,
        b":0x",
        lower_hex(NV_INDEX, &mut index),
        b":",
        &hex[..2 * NAME_LEN],
    ];

    match strsprintf(out, &parts) {
        Ok(_) => 0,
        Err(_) => -E2BIG,
    }
}

/// The binding PCR values in PCR order, as PolicyPCR hashes them.
fn bind_values(
    pcr_before: &[u8; DIGEST_LEN],
    phase_before: &[u8; DIGEST_LEN],
    out: &mut [u8; 2 * DIGEST_LEN],
) {
    out[..DIGEST_LEN].copy_from_slice(pcr_before);
    out[DIGEST_LEN..].copy_from_slice(phase_before);
}

/// The register's policy for the PCR values it binds to and the writer,
/// its two branches, and the names its index has before and after the
/// first write, TPMA_NV_WRITTEN being part of the public area.
struct Expectation {
    branch_written: [u8; DIGEST_LEN],
    branch_init: [u8; DIGEST_LEN],
    policy: [u8; DIGEST_LEN],
    unwritten: [u8; NAME_LEN],
    written: [u8; NAME_LEN],
}

impl Expectation {
    const fn new() -> Self {
        Expectation {
            branch_written: [0; DIGEST_LEN],
            branch_init: [0; DIGEST_LEN],
            policy: [0; DIGEST_LEN],
            unwritten: [0; NAME_LEN],
            written: [0; NAME_LEN],
        }
    }
}

/// The expectation for the PCR values and the writer into `e`.
fn register_expectation(
    pcr_before: &[u8; DIGEST_LEN],
    phase_before: &[u8; DIGEST_LEN],
    writer_public: &[u8; NV_RSA_BYTES],
    e: &mut Expectation,
) -> c_int {
    let mut values = [0u8; 2 * DIGEST_LEN];

    bind_values(pcr_before, phase_before, &mut values);
    // SAFETY: two values, a modulus and three rooms for a digest.
    let ret = unsafe {
        tpm_register_policy(
            PCR_MASK,
            values.as_ptr(),
            2,
            writer_public.as_ptr(),
            e.branch_written.as_mut_ptr(),
            e.branch_init.as_mut_ptr(),
            e.policy.as_mut_ptr(),
        )
    };
    if ret != 0 {
        // SAFETY: the C's format and its argument.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"tpm: compute signed register policy: %s".as_ptr(),
                strerror(-ret),
            )
        };
        return ret;
    }
    // SAFETY: the policy and rooms for the names.
    unsafe {
        let mut ret = tpm_nv_name(
            NV_INDEX,
            REGISTER_ATTRS,
            e.policy.as_ptr(),
            DIGEST_LEN as u16,
            e.unwritten.as_mut_ptr(),
        );

        if ret == 0 {
            ret = tpm_nv_name(
                NV_INDEX,
                REGISTER_ATTRS | NV_WRITTEN,
                e.policy.as_ptr(),
                DIGEST_LEN as u16,
                e.written.as_mut_ptr(),
            );
        }
        ret
    }
}

fn name_equals(info: &TpmNvInfo, name: &[u8; NAME_LEN]) -> bool {
    info.name_len == NAME_LEN && !memneq_explicit(&info.name, name)
}

/// The index defined afresh with `policy`, undefined first when
/// `defined`, under the owner auth of the configuration.
fn register_define(tpm: *mut Tpm, defined: bool, policy: &[u8; DIGEST_LEN]) -> c_int {
    let mut cfg = Scrubbed(MaybeUninit::zeroed());

    // SAFETY: the configuration to fill; the C went on with whatever its
    // result.
    unsafe { config::load(cfg.ptr()) };
    // SAFETY: the configuration, zero or filled.
    let c = unsafe { &*cfg.ptr() };
    let auth = c.tpm_owner_auth.as_ptr().cast::<c_void>();

    if defined {
        // SAFETY: the connection and the owner auth.
        let ret = unsafe { tpm_nv_undefine(tpm, NV_INDEX, auth, c.tpm_owner_auth_len) };

        if ret != 0 {
            return ret;
        }
    }
    // SAFETY: the connection, the policy and the owner auth.
    unsafe { tpm_nv_define(tpm, NV_INDEX, policy.as_ptr(), auth, c.tpm_owner_auth_len) }
}

/// The NV writer init froze, its modulus into `public`, set on the
/// connection.
fn register_writer(tpm: *mut Tpm, public: &mut [u8; NV_RSA_BYTES]) -> c_int {
    let mut seed = [0u8; DIGEST_LEN];
    let ret = nv_writer::read(&mut seed, public);

    if ret != 0 {
        return ret;
    }
    // SAFETY: the connection, the seed and the modulus.
    unsafe { tpm_nv_set_writer(tpm, seed.as_ptr(), public.as_ptr()) }
}

/// A structure of integers, bools and arrays of them, all of whose bits
/// zeroed are a value.
fn zeroed<T>() -> T {
    // SAFETY: only for EventlogInit and TpmNvInfo here, which are such.
    unsafe { core::mem::zeroed() }
}

/// Bind the register to this boot and write `event` as its first event,
/// or find the binding a run before made: chain_init().
pub(crate) fn init(event: &[u8; DIGEST_LEN], info: &mut ChainInitInfo) -> c_int {
    let mut tpm: *mut Tpm = ptr::null_mut();

    // SAFETY: the caller's structure, all of whose bits zeroed are one.
    unsafe { ptr::from_mut(info).write_bytes(0, 1) };
    // SAFETY: where tpm_open() leaves the connection.
    if unsafe { tpm_open(&mut tpm) } != 0 {
        return -ENODEV;
    }
    let ret = bind(tpm, event, info);

    // SAFETY: the connection, closed once.
    unsafe { tpm_close(tpm) };
    ret
}

/// chain_init() on the connection `tpm`.
fn bind(tpm: *mut Tpm, event: &[u8; DIGEST_LEN], info: &mut ChainInitInfo) -> c_int {
    let mut e = Expectation::new();
    let mut rec: EventlogInit = zeroed();
    let mut nv: TpmNvInfo = zeroed();

    // SAFETY: the connection and room for the count and the index.
    let ret = unsafe { tpm_reset_count(tpm, &mut info.reset_count) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: as above.
    let ret = unsafe { tpm_nv_info(tpm, NV_INDEX, &mut nv) };
    if ret != 0 {
        return ret;
    }

    // A record of this boot for the TPM's reset count means init bound
    // the register already: written and of the recorded name, a re-run
    // keeps it; anything else is refused, as binding again would restart
    // the history the record vouches for. A log that cannot be read may
    // hold such a record.
    // SAFETY: the record to fill.
    let ret = unsafe { eventlog_boot_init(&mut rec) };
    if ret != 0 && ret != -ENOENT {
        // SAFETY: the C's format and its arguments.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"tpm: eventlog %s unreadable: %s; not binding register 0x%08x".as_ptr(),
                eventlog_path(),
                strerror(-ret),
                NV_INDEX,
            )
        };
        return ret;
    }
    let recorded = ret == 0 && (!rec.have_reset_count || rec.reset_count == info.reset_count);
    if recorded {
        return rebind(tpm, &rec, &nv, &mut e, info);
    }
    if nv.defined && nv.written {
        // SAFETY: the C's format and its argument.
        unsafe {
            crate::log::log_c!(
                crate::log::warn,
                c"tpm: register 0x%08x written this boot without a record; rebinding it".as_ptr(),
                NV_INDEX,
            )
        };
    }

    // SAFETY: the connection and room for the PCR values.
    let mut ret = unsafe { tpm_pcr_read(tpm, PCR, info.pcr_before.as_mut_ptr()) };
    if ret == 0 {
        // SAFETY: as above.
        ret = unsafe { tpm_pcr_read(tpm, PHASE_PCR, info.phase_before.as_mut_ptr()) };
    }
    if ret != 0 {
        return ret;
    }
    info.initrd = in_initrd();
    let ret = register_writer(tpm, &mut info.writer_public);
    if ret != 0 {
        return ret;
    }
    let mut ret = register_expectation(
        &info.pcr_before,
        &info.phase_before,
        &info.writer_public,
        &mut e,
    );
    if ret == 0 {
        // SAFETY: the written name and the anchor's room.
        ret = unsafe { anchor(e.written.as_ptr(), info.anchor.as_mut_ptr(), ANCHOR_MAX) };
    }
    if ret != 0 {
        return ret;
    }

    if !nv.defined || nv.written || !name_equals(&nv, &e.unwritten) {
        let ret = register_define(tpm, nv.defined, &e.policy);
        if ret != 0 {
            return ret;
        }
        // SAFETY: the connection and the index's info.
        let ret = unsafe { tpm_nv_info(tpm, NV_INDEX, &mut nv) };
        if ret != 0 {
            return ret;
        }
        if !nv.defined || !name_equals(&nv, &e.unwritten) {
            // SAFETY: the C's format and its argument.
            unsafe {
                crate::log::log_c!(
                    crate::log::err,
                    c"tpm: register 0x%08x name does not match the computed public area".as_ptr(),
                    NV_INDEX,
                )
            };
            return -EPROTO;
        }
    }

    // SAFETY: the connection, the branches and the event.
    let ret = unsafe {
        tpm_nv_extend_first(
            tpm,
            NV_INDEX,
            PCR_MASK,
            e.branch_written.as_ptr(),
            e.branch_init.as_ptr(),
            event.as_ptr(),
        )
    };
    if ret != 0 {
        return ret;
    }
    info.name = e.written;
    info.name_len = NAME_LEN;
    let len = cstr(&info.anchor).len();
    // SAFETY: the anchor's bytes and room for its digest.
    let ret = unsafe {
        sha256_buffer(
            info.anchor.as_ptr().cast(),
            len,
            info.anchor_digest.as_mut_ptr(),
        )
    };
    if ret != 0 {
        return ret;
    }
    // SAFETY: the connection and the anchor's digest.
    let ret = unsafe { tpm_pcr_extend(tpm, PCR, info.anchor_digest.as_ptr()) };
    if ret != 0 {
        // SAFETY: the C's format and its argument.
        unsafe {
            crate::log::log_c!(crate::log::err,
                c"tpm: register written but PCR %u not anchored; the init branch stays open until reboot"
                    .as_ptr(),
                PCR,
            )
        };
        return ret;
    }
    // SAFETY: the connection and room for the value.
    unsafe { tpm_nv_read(tpm, NV_INDEX, info.value.as_mut_ptr()) }
}

/// The binding the record `rec` of this boot names: the register as it
/// is when written under the recorded name, else -EEXIST.
fn rebind(
    tpm: *mut Tpm,
    rec: &EventlogInit,
    nv: &TpmNvInfo,
    e: &mut Expectation,
    info: &mut ChainInitInfo,
) -> c_int {
    let ret = register_writer(tpm, &mut info.writer_public);
    if ret != 0 {
        return ret;
    }
    let ret = register_expectation(&rec.pcr_before, &rec.phase_before, &info.writer_public, e);
    if ret != 0 {
        return ret;
    }
    if !name_equals(nv, &e.written) {
        // SAFETY: the C's format.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"tpm: recorded register has an obsolete policy; trusted reboot required".as_ptr(),
            )
        };
        return -EEXIST;
    }
    if memneq_explicit(&info.writer_public, &rec.writer_public) {
        // SAFETY: the C's format.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"tpm: recorded NV writer differs from the guarded key".as_ptr()
            )
        };
        return -EKEYREJECTED;
    }
    if nv.defined && nv.written && name_equals(nv, &rec.name) {
        // SAFETY: the connection and room for the value.
        let ret = unsafe { tpm_nv_read(tpm, NV_INDEX, info.value.as_mut_ptr()) };
        if ret != 0 {
            return ret;
        }
        info.name[..nv.name_len].copy_from_slice(&nv.name[..nv.name_len]);
        info.name_len = nv.name_len;
        info.pcr_before = rec.pcr_before;
        info.phase_before = rec.phase_before;
        info.anchor_digest = rec.anchor_digest;
        // SAFETY: the name and the anchor's room.
        let ret = unsafe { anchor(info.name.as_ptr(), info.anchor.as_mut_ptr(), ANCHOR_MAX) };
        if ret != 0 {
            return ret;
        }
        info.initrd = rec.initrd;
        info.reused = true;
        return 0;
    }
    let state = if !nv.defined {
        c"gone"
    } else if !nv.written {
        c"unwritten"
    } else {
        c"not the recorded index"
    };
    // SAFETY: the C's format and its arguments.
    unsafe {
        crate::log::log_c!(crate::log::err,
            c"tpm: register 0x%08x bound this boot is %s; not binding another before the next TPM reset"
                .as_ptr(),
            NV_INDEX,
            state.as_ptr(),
        )
    };
    -EEXIST
}

/// Extend this boot's register by `event` through the written branch,
/// its value then into `out_chain` unless NULL: chain_extend().
///
/// # Safety
///
/// `out_chain` is NULL or room for a digest.
unsafe fn extend(event: &[u8; DIGEST_LEN], out_chain: *mut u8) -> c_int {
    let mut e = Expectation::new();
    let mut values = [0u8; 2 * DIGEST_LEN];
    let mut rec: EventlogInit = zeroed();
    let mut tpm: *mut Tpm = ptr::null_mut();

    // SAFETY: the record to fill.
    if unsafe { eventlog_boot_init(&mut rec) } != 0 {
        return -ENODEV;
    }
    bind_values(&rec.pcr_before, &rec.phase_before, &mut values);
    // SAFETY: two values, a modulus and three rooms for a digest.
    let ret = unsafe {
        tpm_register_policy(
            PCR_MASK,
            values.as_ptr(),
            2,
            rec.writer_public.as_ptr(),
            e.branch_written.as_mut_ptr(),
            e.branch_init.as_mut_ptr(),
            e.policy.as_mut_ptr(),
        )
    };
    if ret != 0 {
        // SAFETY: the C's format and its argument.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"tpm: compute signed register policy: %s".as_ptr(),
                strerror(-ret),
            )
        };
        return ret;
    }

    // SAFETY: where tpm_open() leaves the connection.
    if unsafe { tpm_open(&mut tpm) } != 0 {
        return -ENODEV;
    }
    // SAFETY: the connection, and the caller's NULL or room.
    let ret = unsafe { extend_on(tpm, &rec, &e, event, out_chain) };

    // SAFETY: the connection, closed once.
    unsafe { tpm_close(tpm) };
    ret
}

/// chain_extend() on the connection `tpm`, with the record `rec` and the
/// branches and policy `e` of its binding.
///
/// # Safety
///
/// `out_chain` is NULL or room for a digest.
unsafe fn extend_on(
    tpm: *mut Tpm,
    rec: &EventlogInit,
    e: &Expectation,
    event: &[u8; DIGEST_LEN],
    out_chain: *mut u8,
) -> c_int {
    let mut writer_public = [0u8; NV_RSA_BYTES];
    let mut nv: TpmNvInfo = zeroed();
    let mut reset = 0u32;

    // SAFETY: the connection and the index's info.
    let ret = unsafe { tpm_nv_info(tpm, NV_INDEX, &mut nv) };
    if ret != 0 {
        return ret;
    }
    if !nv.defined || !nv.written {
        return -ENODEV;
    }
    if !name_equals(&nv, &rec.name) {
        // SAFETY: the C's format and its argument.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"tpm: register 0x%08x is not the index init recorded (recreated?)".as_ptr(),
                NV_INDEX,
            )
        };
        return -EACCES;
    }
    if memneq_explicit(&nv.policy, &e.policy) {
        // SAFETY: the C's format.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"tpm: register write policy is obsolete or substituted".as_ptr()
            )
        };
        return -EACCES;
    }
    // SAFETY: the connection and room for the count.
    let ret = unsafe { tpm_reset_count(tpm, &mut reset) };
    if ret != 0 {
        return ret;
    }
    if !rec.have_reset_count || reset != rec.reset_count {
        // SAFETY: the C's format.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"tpm: register reset differs from the init record".as_ptr()
            )
        };
        return -EACCES;
    }
    let ret = register_writer(tpm, &mut writer_public);
    if ret != 0 {
        return ret;
    }
    if memneq_explicit(&writer_public, &rec.writer_public) {
        // SAFETY: the C's format.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"tpm: recorded NV writer differs from the guarded key".as_ptr()
            )
        };
        return -EKEYREJECTED;
    }
    // SAFETY: the connection, the branches and the event.
    let ret = unsafe {
        tpm_nv_extend(
            tpm,
            NV_INDEX,
            e.branch_written.as_ptr(),
            e.branch_init.as_ptr(),
            event.as_ptr(),
        )
    };
    if ret != 0 {
        return -EIO;
    }
    if out_chain.is_null() {
        return 0;
    }
    // SAFETY: the connection and the caller's room.
    if unsafe { tpm_nv_read(tpm, NV_INDEX, out_chain) } != 0 {
        -EIO
    } else {
        0
    }
}

/// The register's value this boot into `out`: chain_read().
///
/// # Safety
///
/// `out` has room for a digest.
unsafe fn read(out: *mut u8) -> c_int {
    let mut tpm: *mut Tpm = ptr::null_mut();

    // SAFETY: where tpm_open() leaves the connection.
    if unsafe { tpm_open(&mut tpm) } != 0 {
        return -ENODEV;
    }
    // SAFETY: the connection, the caller's room, and the connection
    // closed once.
    let ret = unsafe {
        let ret = tpm_nv_read(tpm, NV_INDEX, out);

        tpm_close(tpm);
        ret
    };
    if ret != 0 { -ENODEV } else { 0 }
}

/// The register as the TPM reports it, over the session init pinned.
#[repr(C)]
pub(crate) struct ChainLive {
    pub(crate) name: [u8; NAME_LEN],
    pub(crate) reset_count: u32,
    pub(crate) value: [u8; DIGEST_LEN],
}

/// The live register's name, value and TPM reset count: -ENODEV when no
/// TPM answers or the index is not written this reset, -EIO when a read
/// fails.
pub(crate) fn live() -> Result<ChainLive, c_int> {
    let mut tpm: *mut Tpm = ptr::null_mut();
    let mut out = ChainLive {
        name: [0; NAME_LEN],
        reset_count: 0,
        value: [0; DIGEST_LEN],
    };
    let mut nv: TpmNvInfo = zeroed();

    // SAFETY: where tpm_open() leaves the connection.
    if unsafe { tpm_open(&mut tpm) } != 0 {
        return Err(-ENODEV);
    }
    // SAFETY: the connection, rooms for what it reads, and the
    // connection closed once.
    let ret = unsafe {
        let mut ret = if tpm_reset_count(tpm, &mut out.reset_count) != 0
            || tpm_nv_info(tpm, NV_INDEX, &mut nv) != 0
        {
            -EIO
        } else {
            0
        };
        if ret == 0 && (!nv.defined || !nv.written || nv.name_len != NAME_LEN) {
            ret = -ENODEV;
        }
        if ret == 0 {
            out.name.copy_from_slice(&nv.name[..NAME_LEN]);
            if tpm_nv_read(tpm, NV_INDEX, out.value.as_mut_ptr()) != 0 {
                ret = -EIO;
            }
        }
        tpm_close(tpm);
        ret
    };
    if ret != 0 { Err(ret) } else { Ok(out) }
}

/// Whether a TPM answers with the register written: chain_bound().
pub(crate) fn bound() -> bool {
    let mut tpm: *mut Tpm = ptr::null_mut();
    let mut nv: TpmNvInfo = zeroed();

    // SAFETY: where tpm_open_quiet() leaves the connection.
    if unsafe { tpm_open_quiet(&mut tpm) } != 0 {
        return false;
    }
    // SAFETY: the connection, the index's info, and the connection
    // closed once.
    unsafe {
        let bound = tpm_nv_info(tpm, NV_INDEX, &mut nv) == 0 && nv.defined && nv.written;

        tpm_close(tpm);
        bound
    }
}

/// The register as the TPM and this boot's records show it: chain_status().
pub(crate) fn status(st: &mut ChainStatus) -> c_int {
    let mut tpm: *mut Tpm = ptr::null_mut();

    // SAFETY: the caller's structure, all of whose bits zeroed are one.
    unsafe { ptr::from_mut(st).write_bytes(0, 1) };
    // SAFETY: the record to fill.
    st.logged = unsafe { eventlog_boot_init(&mut st.init) } == 0;
    st.rebound = st.logged && st.init.records_epoch > 1;
    // SAFETY: where tpm_open_quiet() leaves the connection.
    if unsafe { tpm_open_quiet(&mut tpm) } != 0 {
        return -ENODEV;
    }
    st.tpm = true;
    let ret = status_on(tpm, st);

    // SAFETY: the connection, closed once.
    unsafe { tpm_close(tpm) };
    ret
}

/// chain_status() on the connection `tpm`.
fn status_on(tpm: *mut Tpm, st: &mut ChainStatus) -> c_int {
    let mut e = Expectation::new();
    let mut values = [0u8; 2 * DIGEST_LEN];
    let mut nv: TpmNvInfo = zeroed();
    let mut reset_count = 0u32;

    // SAFETY: the connection and room for the count.
    let ret = unsafe { tpm_reset_count(tpm, &mut reset_count) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: the connection and the index's info.
    let mut ret = unsafe { tpm_nv_info(tpm, NV_INDEX, &mut nv) };
    if ret != 0 {
        return ret;
    }
    st.defined = nv.defined;
    st.written = nv.written;
    st.name[..nv.name_len].copy_from_slice(&nv.name[..nv.name_len]);
    st.name_len = nv.name_len;
    if nv.defined && nv.written {
        // SAFETY: the connection and room for the value.
        ret = unsafe { tpm_nv_read(tpm, NV_INDEX, st.value.as_mut_ptr()) };
    }
    st.anchored = nv.defined
        && nv.written
        && st.logged
        && name_equals(&nv, &st.init.name)
        && (!st.init.have_reset_count || st.init.reset_count == reset_count);
    if st.anchored {
        bind_values(&st.init.pcr_before, &st.init.phase_before, &mut values);
        // SAFETY: two values, a modulus and three rooms for a digest.
        ret = unsafe {
            tpm_register_policy(
                PCR_MASK,
                values.as_ptr(),
                2,
                st.init.writer_public.as_ptr(),
                e.branch_written.as_mut_ptr(),
                e.branch_init.as_mut_ptr(),
                e.policy.as_mut_ptr(),
            )
        };
        if ret != 0 {
            // SAFETY: the C's format and its argument.
            unsafe {
                crate::log::log_c!(
                    crate::log::err,
                    c"tpm: compute signed register policy: %s".as_ptr(),
                    strerror(-ret),
                )
            };
            st.anchored = false;
            return ret;
        }
        // SAFETY: the policy and room for the name.
        st.anchored = unsafe {
            tpm_nv_name(
                NV_INDEX,
                REGISTER_ATTRS | NV_WRITTEN,
                e.policy.as_ptr(),
                DIGEST_LEN as u16,
                e.written.as_mut_ptr(),
            )
        } == 0
            && name_equals(&nv, &e.written);
    }
    ret
}

pub(crate) use capi::{
    chain_anchor, chain_bound, chain_extend, chain_fold, chain_key_event, chain_read,
    chain_tree_event, chain_upatch_event,
};

pub(crate) use capi::chain_init_event;

mod capi {
    use core::ffi::{c_char, c_int, c_void};

    use super::{ChainInitInfo, ChainLive, ChainStatus, DIGEST_LEN, MeasuredUpatch};

    /// # Safety
    ///
    /// `a` and `b` hold their lengths' bytes and `out` has room for a
    /// digest.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn sha256_2(
        a: *const c_void,
        a_len: usize,
        b: *const c_void,
        b_len: usize,
        out: *mut u8,
    ) -> c_int {
        // SAFETY: the caller passes the bytes and the room.
        unsafe { super::sha256_2(a, a_len, b, b_len, out) }
    }

    /// # Safety
    ///
    /// `set` holds `n` members, `cert_sha` and `tree_root` digests, and
    /// `set_digest` and `event` have room for one.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_init_event(
        cert_sha: *const u8,
        set: *mut MeasuredUpatch,
        n: usize,
        tree_root: *const u8,
        set_digest: *mut u8,
        event: *mut u8,
    ) -> c_int {
        // SAFETY: the caller passes the set, the digests and the rooms.
        unsafe { super::init_event(cert_sha, set, n, tree_root, set_digest, event) }
    }

    /// # Safety
    ///
    /// `tag` is a C string, `cert_sha` a digest and `event` room for one.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_key_event(
        tag: *const c_char,
        cert_sha: *const u8,
        event: *mut u8,
    ) -> c_int {
        // SAFETY: the caller passes a C string, a digest and the room.
        unsafe {
            super::sha256_2(
                tag.cast(),
                crate::sys::libc::strlen(tag) + 1,
                cert_sha.cast(),
                DIGEST_LEN,
                event,
            )
        }
    }

    /// # Safety
    ///
    /// `tag` and `name` are C strings, `payload` a digest and `event`
    /// room for one.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_upatch_event(
        tag: *const c_char,
        name: *const c_char,
        payload: *const u8,
        event: *mut u8,
    ) -> c_int {
        // SAFETY: the caller passes two C strings, a digest and the room.
        unsafe { super::upatch_event(tag.cast(), name.cast(), payload, event) }
    }

    /// # Safety
    ///
    /// `operation_digest` is a digest and `event` room for one.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_tree_event(
        seq: i64,
        operation_digest: *const u8,
        event: *mut u8,
    ) -> c_int {
        // SAFETY: the caller passes a digest and the room.
        unsafe { super::tree_event(seq, operation_digest, event) }
    }

    /// # Safety
    ///
    /// `prev` and `operation_digest` hold 32 bytes, and `out` has room for
    /// 32, which may be `prev`'s.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_history_step(
        prev: *const [u8; 32],
        operation_digest: *const [u8; 32],
        out: *mut [u8; 32],
    ) -> c_int {
        // SAFETY: the caller's 32 bytes at each, read before out is
        // written.
        let (ret, root) = match unsafe { super::history_step(&*prev, &*operation_digest) } {
            Ok(root) => (0, root),
            Err(err) => (err, [0; 32]),
        };
        // SAFETY: the caller's room.
        unsafe { *out = root };
        ret
    }

    /// # Safety
    ///
    /// `chain` and `event` are digests, which may be the same.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_fold(chain: *mut u8, event: *const u8) -> c_int {
        // SAFETY: the caller passes two digests.
        unsafe { super::fold(chain, event) }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn chain_upatch_tag(ty: u32, load: bool) -> *const c_char {
        match (ty, load) {
            (1, true) => c"shirudo-upatch".as_ptr(),
            (1, false) => c"shirudo-unload".as_ptr(),
            (2, true) => c"shirudo-java".as_ptr(),
            (2, false) => c"shirudo-java-unload".as_ptr(),
            _ => core::ptr::null(),
        }
    }

    /// # Safety
    ///
    /// `out` is room for the live register.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_live(out: *mut ChainLive) -> c_int {
        // SAFETY: the caller provides room for the result.
        unsafe {
            match super::live() {
                Ok(value) => {
                    out.write(value);
                    0
                }
                Err(err) => {
                    out.write_bytes(0, 1);
                    err
                }
            }
        }
    }

    /// # Safety
    ///
    /// `name` is a name and `out` has room for `cap` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_anchor(name: *const u8, out: *mut c_char, cap: usize) -> c_int {
        // SAFETY: the caller passes a name and the room.
        unsafe { super::anchor(name, out.cast(), cap) }
    }

    /// # Safety
    ///
    /// `event` is a digest and `info` a structure to fill.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_init(event: *const u8, info: *mut ChainInitInfo) -> c_int {
        // SAFETY: the caller passes a digest and the structure.
        unsafe { super::init(&*event.cast(), &mut *info) }
    }

    /// # Safety
    ///
    /// `event` is a digest and `out_chain` NULL or room for one.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_extend(event: *const u8, out_chain: *mut u8) -> c_int {
        // SAFETY: the caller passes a digest and NULL or the room.
        unsafe { super::extend(&*event.cast(), out_chain) }
    }

    /// # Safety
    ///
    /// `out` has room for a digest.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_read(out: *mut u8) -> c_int {
        // SAFETY: the caller passes the room.
        unsafe { super::read(out) }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn chain_bound() -> bool {
        super::bound()
    }

    /// # Safety
    ///
    /// `st` is a structure to fill.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn chain_status(st: *mut ChainStatus) -> c_int {
        // SAFETY: the caller passes the structure.
        unsafe { super::status(&mut *st) }
    }
}
