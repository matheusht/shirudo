// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The keepalive body, the status record a node's TPM quotes,
//! and its packed fields: the outcome mask of the
//! operations of the window and the conditions word.

use core::ffi::{CStr, c_char, c_int};

use crate::errno::{E2BIG, EINVAL};
use crate::text::cstr;
use crate::util::bpm_tree::TreeState;
use crate::util::conditions::{CONDITIONS_MAX, Condition};
use crate::util::crypto_openssl::base64_encode;
use crate::util::integrity::INTEGRITY_MAX;
use crate::util::json::JsonEmit;
use crate::util::tamper::TAMPER_MAX;

const SCHEMA: &[u8] = b"shirudo.keepalive/1";
const HASH_HEX_LEN: usize = 64;

/// `KEEPALIVE_MASK_OPS`: the operations a mask holds, two bits each.
pub(crate) const MASK_OPS: usize = 512;
const MASK_BYTES: usize = MASK_OPS / 4;
/// `KEEPALIVE_MASK_B64_MAX`: BASE64_SIZE() of the mask's bytes.
pub(crate) const MASK_B64_MAX: usize = 4 * MASK_BYTES.div_ceil(3) + 1;
/// `KEEPALIVE_BODY_MAX`: the largest body and its terminator.
pub(crate) const BODY_MAX: usize = 4096;

pub(crate) const REGISTER_REBOUND: u32 = 1 << 0;
pub(crate) const BOUND_LATE: u32 = 1 << 1;
pub(crate) const TREE_LOG_MISMATCH: u32 = 1 << 2;
pub(crate) const TAMPER_UNAVAILABLE: u32 = 1 << 3;
pub(crate) const TREE_OP_PENDING: u32 = 1 << 4;
pub(crate) const SNAPSHOT_UNSETTLED: u32 = 1 << 5;
pub(crate) const INTEGRITY_UNAVAILABLE: u32 = 1 << 6;

/// How many times a snapshot reads the tree before it gives up on a
/// state that keeps moving.
const SNAPSHOT_TRIES: usize = 3;

const CODE_BITS: usize = 2;
const CODE_MAX: u8 = 3;
const CODES_PER_BYTE: usize = 4;

/// The backend reads a pair by its place here: append, never reorder.
const COND_ORDER: [&[u8]; CONDITIONS_MAX] = [
    b"LsmAttached",
    b"KeyringSealed",
    b"ChainIntact",
    b"UpatchesMeasured",
    b"TpmMeasured",
    b"ConfigActive",
    b"XdpCovered",
];

const _: () = assert!(CODE_BITS * COND_ORDER.len() <= 16);

/// What a body reports of the tree a node follows.
pub(crate) struct Tree<'a> {
    pub(crate) tree_id: Option<&'a [u8]>,
    pub(crate) generation: u64,
    pub(crate) base_seq: u64,
    pub(crate) last_seq: u64,
    /// A hash, or none.
    pub(crate) base_root: Option<&'a [u8]>,
    /// A hash.
    pub(crate) projection_root: Option<&'a [u8]>,
    /// From mask(): none is null, "" a window of no operation.
    pub(crate) mask: Option<&'a [u8]>,
}

/// What a body says. A string that may be null is so when it is none or,
/// but for the mask, empty; a hash is 64 lowercase hex digits.
pub(crate) struct Input<'a> {
    pub(crate) boot_id: Option<&'a [u8]>,
    /// A hash.
    pub(crate) version_id: Option<&'a [u8]>,
    /// A hash, or none.
    pub(crate) config_root: Option<&'a [u8]>,
    pub(crate) kernel_release: Option<&'a [u8]>,
    pub(crate) image_id: Option<&'a [u8]>,
    pub(crate) image_version: Option<&'a [u8]>,
    /// A hash, or none.
    pub(crate) image_root: Option<&'a [u8]>,
    pub(crate) verdict: Option<&'a [u8]>,
    /// From cond().
    pub(crate) cond: u16,
    pub(crate) flags: u32,
    pub(crate) tamper: Option<&'a [u64; TAMPER_MAX]>,
    pub(crate) integrity: Option<&'a [u64; INTEGRITY_MAX]>,
    /// None: the node follows no tree, and the tree keys are null.
    pub(crate) tree: Option<Tree<'a>>,
    /// A hash.
    pub(crate) set_sha256: Option<&'a [u8]>,
    pub(crate) count: u64,
    pub(crate) not_ok: u64,
}

/// The codes, two bits each, packed four to a byte with the first in the
/// highest bits, as the backend reads them, in base64 into `b64` with its
/// terminator: -EINVAL for a code past two bits or more than MASK_OPS
/// codes, -E2BIG for a buffer too small.
pub(crate) fn mask(codes: &[u8], b64: &mut [u8]) -> c_int {
    if codes.len() > MASK_OPS {
        return -EINVAL;
    }
    let mut raw = [0u8; MASK_BYTES];
    for (i, &code) in codes.iter().enumerate() {
        if code > CODE_MAX {
            return -EINVAL;
        }
        let slot = CODES_PER_BYTE - 1 - i % CODES_PER_BYTE;
        raw[i / CODES_PER_BYTE] |= code << (CODE_BITS * slot);
    }
    let len = codes.len().div_ceil(CODES_PER_BYTE);
    if b64.len() < 4 * len.div_ceil(3) + 1 {
        return -E2BIG;
    }
    // SAFETY: the packed bytes and the caller's room, of their lengths.
    unsafe { base64_encode(raw.as_ptr(), len, b64.as_mut_ptr().cast(), b64.len()) }
}

fn code_of(status: &[u8]) -> u16 {
    match status {
        b"OK" => 1,
        b"WARN" => 2,
        b"ALERT" => 3,
        _ => 0,
    }
}

/// The conditions word: each condition's code by its type name, so that
/// a condition conditions() adds moves none, and 0 for one not given.
pub(crate) fn cond(conds: &[Condition]) -> u16 {
    let named = |name: &[u8]| {
        conds.iter().find_map(|c| {
            // SAFETY: the condition's static C strings.
            let (kind, status) = unsafe { (c_str(c.kind), c_str(c.status)) };
            (kind == name).then(|| code_of(status))
        })
    };
    COND_ORDER.iter().enumerate().fold(0, |word, (i, name)| {
        word | named(name).unwrap_or(0) << (CODE_BITS * i)
    })
}

/// A C string's bytes, none for NULL.
///
/// # Safety
///
/// `s` is NULL or a C string.
unsafe fn c_str<'a>(s: *const c_char) -> &'a [u8] {
    if s.is_null() {
        b""
    } else {
        // SAFETY: the caller's C string.
        unsafe { CStr::from_ptr(s) }.to_bytes()
    }
}

fn is_hash(s: Option<&[u8]>) -> bool {
    s.is_some_and(|s| {
        s.len() == HASH_HEX_LEN && s.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    })
}

fn is_absent(s: Option<&[u8]>) -> bool {
    s.is_none_or(<[u8]>::is_empty)
}

fn is_hash_or_absent(s: Option<&[u8]>) -> bool {
    is_absent(s) || is_hash(s)
}

fn is_valid(i: &Input<'_>) -> bool {
    let tree_ok = i.tree.as_ref().is_none_or(|t| {
        t.tree_id.is_some() && is_hash_or_absent(t.base_root) && is_hash(t.projection_root)
    });
    i.boot_id.is_some()
        && is_hash(i.version_id)
        && is_hash_or_absent(i.config_root)
        && i.kernel_release.is_some()
        && is_hash_or_absent(i.image_root)
        && i.verdict.is_some()
        && tree_ok
        && is_hash(i.set_sha256)
}

fn kv_string_or_null(e: &mut JsonEmit, key: &[u8], val: Option<&[u8]>) {
    match val {
        Some(v) if !v.is_empty() => e.kv_string(key, v),
        _ => e.kv_null(key),
    }
}

fn kv_counters(e: &mut JsonEmit, key: &[u8], counts: Option<&[u64]>) {
    let Some(counts) = counts else {
        e.kv_null(key);
        return;
    };
    e.arr_open(key);
    for &n in counts {
        e.u64_value(n);
    }
    e.arr_close();
}

fn kv_tree(e: &mut JsonEmit, tree: Option<&Tree<'_>>) {
    let Some(t) = tree else {
        for key in [
            &b"tree_id"[..],
            b"generation",
            b"base_seq",
            b"last_seq",
            b"base_root",
            b"projection_root",
            b"mask",
        ] {
            e.kv_null(key);
        }
        return;
    };
    e.kv_string(b"tree_id", t.tree_id.unwrap_or_default());
    e.kv_u64(b"generation", t.generation);
    e.kv_u64(b"base_seq", t.base_seq);
    e.kv_u64(b"last_seq", t.last_seq);
    kv_string_or_null(e, b"base_root", t.base_root);
    e.kv_string(b"projection_root", t.projection_root.unwrap_or_default());
    match t.mask {
        Some(m) => e.kv_string(b"mask", m),
        None => e.kv_null(b"mask"),
    }
}

/// The body as one compact JSON object into `e`: -EINVAL for a string
/// that is none where the body needs one or a hash that is not one, else
/// the emitter's error, -ENOSPC when its room does not hold the body or
/// -EILSEQ for a string that is not UTF-8.
pub(crate) fn emit(i: &Input<'_>, e: &mut JsonEmit) -> c_int {
    if !is_valid(i) {
        return -EINVAL;
    }
    fn s(v: Option<&[u8]>) -> &[u8] {
        v.unwrap_or_default()
    }
    e.obj_open();
    e.kv_string(b"schema", SCHEMA);
    e.kv_string(b"boot_id", s(i.boot_id));
    e.kv_string(b"version_id", s(i.version_id));
    kv_string_or_null(e, b"config_root", i.config_root);
    e.kv_string(b"kernel_release", s(i.kernel_release));
    kv_string_or_null(e, b"image_id", i.image_id);
    kv_string_or_null(e, b"image_version", i.image_version);
    kv_string_or_null(e, b"image_root", i.image_root);
    e.kv_string(b"verdict", s(i.verdict));
    e.kv_u64(b"cond", i.cond.into());
    e.kv_u64(b"flags", i.flags.into());
    kv_counters(e, b"tamper", i.tamper.map(|c| &c[..]));
    kv_counters(e, b"integrity", i.integrity.map(|c| &c[..]));
    kv_tree(e, i.tree.as_ref());
    e.kv_string(b"set_sha256", s(i.set_sha256));
    e.kv_u64(b"count", i.count);
    e.kv_u64(b"not_ok", i.not_ok);
    e.obj_close();
    e.err()
}

/// The body, at most BODY_MAX bytes with its terminator, as emit() makes
/// it.
pub(crate) fn body(i: &Input<'_>) -> Result<Vec<u8>, c_int> {
    let mut buf = [0u8; BODY_MAX];
    let mut e = JsonEmit::fixed(&mut buf);
    match emit(i, &mut e) {
        0 => Ok(e.output().to_vec()),
        err => Err(err),
    }
}

/// The reads of a snapshot: the tree state, whether an operation is
/// pending, and what follows the state, None where it could not be read:
/// the outcomes up to its last_seq and the loaded set, which fails the
/// snapshot with a nonzero return.
pub(crate) trait SnapshotOps {
    fn read_state(&mut self) -> Result<TreeState, c_int>;
    fn pending(&mut self) -> bool;
    fn collect(&mut self, state: Option<&TreeState>) -> c_int;
}

fn state_same(a: &Result<TreeState, c_int>, b: &Result<TreeState, c_int>) -> bool {
    let (Ok(a), Ok(b)) = (a, b) else {
        return a.as_ref().err() == b.as_ref().err();
    };
    a.schema == b.schema
        && a.generation == b.generation
        && a.last_seq == b.last_seq
        && a.head_seq == b.head_seq
        && a.segment_base_seq == b.segment_base_seq
        && cstr(&a.tree_id) == cstr(&b.tree_id)
        && cstr(&a.projection_root) == cstr(&b.projection_root)
        && cstr(&a.projection_root_tpm) == cstr(&b.projection_root_tpm)
        && cstr(&a.manifest_digest) == cstr(&b.manifest_digest)
}

/// One point of the tree and the loaded set: the first state read of the
/// last try, and TREE_OP_PENDING when that try saw an operation pending
/// and SNAPSHOT_UNSETTLED when the tries ran out.
pub(crate) struct Snapshot {
    pub(crate) state: Result<TreeState, c_int>,
    pub(crate) flags: u32,
}

/// Reads the tree keys and the loaded set of one point without the tree
/// lock, which a sync holds for minutes: the state, whether an operation
/// is pending, what collect() reads, pending again and the state again,
/// over again while the second state differs from the first, at most
/// SNAPSHOT_TRIES times. The snapshot, or what collect() returned.
pub(crate) fn snapshot(ops: &mut dyn SnapshotOps) -> Result<Snapshot, c_int> {
    let mut tries = 0;

    loop {
        let state = ops.read_state();
        let mut pending = ops.pending();
        let ret = ops.collect(state.as_ref().ok());
        if ret != 0 {
            return Err(ret);
        }
        pending = ops.pending() || pending;
        let again = ops.read_state();
        let settled = state_same(&state, &again);
        tries += 1;
        if settled || tries == SNAPSHOT_TRIES {
            let mut flags = 0;
            if pending {
                flags |= TREE_OP_PENDING;
            }
            if !settled {
                flags |= SNAPSHOT_UNSETTLED;
            }
            return Ok(Snapshot { state, flags });
        }
    }
}

#[cfg(test)]
mod tests;
