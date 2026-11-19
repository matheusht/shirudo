// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The measured set: the upatches the eventlog
//! records as loaded, each with the payload of its load, and the pins
//! and archives that set does not account for.

use core::ffi::{CStr, c_int};

use crate::errno::{E2BIG, EEXIST, EINVAL, ENAMETOOLONG, ENOENT, ENOSPC};
use crate::sys::libc::{PATH_MAX, getxattr};
use crate::text::{at, cstr, strscpy, strsprintf};
use crate::util::chain::MeasuredUpatch;
use crate::util::eventlog::{self, UPATCH_INIT, UPATCH_UNLOAD};
use crate::util::hex::{self, hex_encode};
use crate::util::seal;
use crate::util::upatch::{NAME_MAX, Opened, PAYLOAD_HASH_LEN, Upatch, header_name, member_valid};

/// `MEASURED_MAX`: the most upatches a set holds.
const MEASURED_MAX: usize = 4096;
/// `BPFFS_UPATCHES_DIR` of util/paths.h: the pins of the upatches loaded.
const BPFFS_UPATCHES_DIR: &CStr = c"/run/shirudo/bpffs/upatches";
/// `UPATCHES_DIR` of util/paths.h: the archives of the upatches loaded.
const UPATCHES_DIR: &CStr = c"/var/lib/shirudo/upatches";
/// `XATTR_PAYLOAD` of util/paths.h: the payload digest a pin records.
const XATTR_PAYLOAD: &CStr = c"security.bpf.shirudo.payload";

/// A member of a set: an upatch the records hold loaded, and its
/// payload's digest in hex.
struct Entry {
    name: Vec<u8>,
    payload_hex: Vec<u8>,
}

/// The members, at most MEASURED_MAX of them.
#[derive(Default)]
pub(crate) struct MeasuredSet {
    entries: Vec<Entry>,
}

impl MeasuredSet {
    /// This boot's set, from records the register vouches for.
    pub(crate) fn boot() -> Result<Self, c_int> {
        Self::fold(false)
    }

    /// The set every boot's records make, an empty one for no log.
    pub(crate) fn log() -> Result<Self, c_int> {
        Self::fold(true)
    }

    fn fold(all: bool) -> Result<Self, c_int> {
        let mut s = Self::default();
        let mut on_event =
            |event, name: &[u8], payload_hex: &[u8]| s.event(event, name, payload_hex);
        let ret = if all {
            match eventlog::upatches(true, &mut on_event) {
                r if r == -ENOENT => 0,
                r => r,
            }
        } else {
            verified::upatches(&mut on_event)
        };
        if ret != 0 { Err(ret) } else { Ok(s) }
    }

    /// One event of the walk: the set started over at an init, the
    /// name's payload set or the name added with it at a load, or the
    /// name gone at an unload, the last member in its place.
    fn event(&mut self, event: c_int, name: &[u8], payload_hex: &[u8]) -> c_int {
        if event == UPATCH_INIT {
            self.entries.clear();
            return 0;
        }
        let at = self.entries.iter().position(|e| e.name == name);
        if event == UPATCH_UNLOAD {
            if let Some(i) = at {
                self.entries.swap_remove(i);
            }
            return 0;
        }
        if at.is_none() && self.entries.len() == MEASURED_MAX {
            return -ENOSPC;
        }
        if name.len() > NAME_MAX || payload_hex.len() > 2 * PAYLOAD_HASH_LEN {
            return -EINVAL;
        }
        let payload_hex = payload_hex.to_vec();
        match at {
            Some(i) => self.entries[i].payload_hex = payload_hex,
            None => self.entries.push(Entry {
                name: name.to_vec(),
                payload_hex,
            }),
        }
        0
    }

    /// Whether the set holds `name` with the payload `payload_hex`.
    pub(crate) fn holds(&self, name: &[u8], payload_hex: &[u8]) -> bool {
        self.entries
            .iter()
            .any(|e| e.name == name && e.payload_hex == payload_hex)
    }
}

/// A member of no name and no payload digest.
const NO_MEMBER: MeasuredUpatch = MeasuredUpatch {
    name: [0; NAME_MAX + 1],
    payload_hex: [0; 2 * PAYLOAD_HASH_LEN + 1],
};

/// The member an init record lists for the upatch `u`: its header's name
/// and its payload digest in hex.
pub(crate) fn upatch_of(u: &Upatch) -> MeasuredUpatch {
    let mut member = NO_MEMBER;
    let payload_hex = hex::encode(&u.hdr.payload_sha256);

    header_name(u, &mut member.name);
    member.payload_hex[..payload_hex.len()].copy_from_slice(&payload_hex);
    member
}

/// `name` with `payload_hex` added to `set`, which holds at most `max`:
/// -EINVAL for a member member_valid() refuses, -EEXIST for a name held,
/// or -E2BIG when the set is full or a string too long.
pub(crate) fn set_add(
    set: &mut Vec<MeasuredUpatch>,
    max: usize,
    name: &[u8],
    payload_hex: &[u8],
) -> Result<(), c_int> {
    if !member_valid(name, payload_hex) {
        return Err(-EINVAL);
    }
    if set.iter().any(|held| cstr(&held.name) == name) {
        return Err(-EEXIST);
    }
    if set.len() >= max {
        return Err(-E2BIG);
    }
    let mut member = NO_MEMBER;
    if strscpy(&mut member.name, name).is_err()
        || strscpy(&mut member.payload_hex, payload_hex).is_err()
    {
        return Err(-E2BIG);
    }
    set.push(member);
    Ok(())
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

impl MeasuredSet {
    /// The upatches pinned in the private bpffs that the set does not hold
    /// with the payload their pin records, each to `cb`: how many, or the
    /// first non-zero `cb` returned, or -errno.
    pub(crate) fn unmeasured_pins(&self, mut cb: impl FnMut(&[u8]) -> c_int) -> c_int {
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
            if self.holds(cstr(&name), cstr(&payload_hex)) {
                continue;
            }
            unmeasured += 1;
            ret = cb(cstr(&name));
            if ret != 0 {
                break;
            }
        }
        if ret != 0 { ret } else { unmeasured }
    }
}

impl MeasuredSet {
    /// The upatches archived with the seal label that the set does not hold
    /// with the payload of their archive, each to `cb` with its archive's
    /// path: how many, or the first non-zero `cb` returned, or -errno.
    pub(crate) fn unmeasured_archives(&self, mut cb: impl FnMut(&[u8], &[u8]) -> c_int) -> c_int {
        let (mut ret, mut unmeasured) = (0, 0);

        let names = match crate::util::io::dir_names(UPATCHES_DIR.to_bytes(), |n| {
            crate::text::name_has_suffix(n, b".upatch")
        }) {
            Ok(names) => names,
            Err(err) if err == -ENOENT => return 0,
            Err(err) => return err,
        };
        for archive in &names {
            let mut path = [0u8; PATH_MAX];

            if strsprintf(&mut path, &[UPATCHES_DIR.to_bytes(), b"/", archive]).is_err() {
                continue;
            }
            let Ok(path_c) = CStr::from_bytes_until_nul(&path) else {
                continue;
            };
            if !seal::owns(path_c.to_bytes()) {
                continue;
            }
            let m = match Opened::open(path_c) {
                Ok(u) => upatch_of(&u),
                Err(_) => continue,
            };
            if self.holds(cstr(&m.name), cstr(&m.payload_hex)) {
                continue;
            }
            unmeasured += 1;
            ret = cb(cstr(&m.name), cstr(&path));
            if ret != 0 {
                break;
            }
        }
        if ret != 0 { ret } else { unmeasured }
    }
}

impl MeasuredSet {
    /// The members whose pin directory is gone, each handed to `cb` until it
    /// returns nonzero: how many, that return, or -errno. A load the records
    /// hold keeps its pin directory until its unload.
    pub(crate) fn unpinned(&self, mut cb: impl FnMut(&[u8]) -> c_int) -> c_int {
        use std::os::unix::ffi::OsStrExt;

        let mut n = 0;
        for e in &self.entries {
            let name = &e.name[..];
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
}

#[cfg(test)]
mod tests;

/// This boot's records as the TPM vouches for them.
mod verified {
    use core::ffi::c_int;
    use std::ffi::CString;

    use super::{MEASURED_MAX, set_add};
    use crate::errno::{EBADMSG, EINVAL, ENOENT, ENOMEM};
    use crate::text::cstr;
    use crate::util::chain::{
        self, ChainLive, MeasuredUpatch, chain_fold, chain_init_event, chain_key_event,
        chain_tree_event, chain_upatch_event, memneq_explicit,
    };
    use crate::util::eventlog::{self, UpatchFn, upatches_record};
    use crate::util::hex;
    use crate::util::json::{JsonField, parse_schema};
    use crate::util::upatch::{NAME_MAX, PAYLOAD_HASH_LEN, member_valid};

    const TPM_NAME_LEN: usize = 34;

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
        init: bool,
        upatch: bool,
        key: bool,
        tree: bool,
    }

    fn set_entry(r: &mut Record) -> Result<(), c_int> {
        let added = set_add(
            &mut r.set,
            MEASURED_MAX,
            cstr(&r.name),
            cstr(&r.payload_hex),
        );
        r.name[0] = 0;
        r.payload_hex[0] = 0;
        added
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
                        r.set.len(),
                        root.as_ptr(),
                        set_digest.as_mut_ptr(),
                        event.as_mut_ptr(),
                    )
                }
                b"upatch_load" | b"upatch_unload" => {
                    if !r.upatch || !member_valid(cstr(&r.name), cstr(&r.payload_hex)) {
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
    pub(super) fn upatches(cb: UpatchFn<'_>) -> c_int {
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
            let ret = upatches_record(&line, k == 0, &mut *cb);
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
