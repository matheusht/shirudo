// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The packages bpm installed, as /var/lib/shirudo/bpm/state.json records
//! them.

use core::ffi::{CStr, c_int};

use crate::errno::{E2BIG, EINVAL, ENOENT};
use crate::sys::libc::PATH_MAX;
use crate::text::{cstr, strsprintf};
use crate::util::bpm_oci::{MAX_NAME, name_ok, version_ok};
use crate::util::json::{JsonEmit, JsonField, parse_schema};
use crate::util::seal;

/// `BPM_MAX_STATE`: the most packages the state records.
const MAX_STATE: c_int = 256;
const STATE_FILE_MAX: usize = 8 * 1024 * 1024;
const STATE_EMIT_MAX: usize = 1024 * 1024;

/// BPM_STATE_PATH, BPM_VAR_DIR and BPM_PACKAGES_DIR of util/paths.h.
const STATE_PATH: &CStr = c"/var/lib/shirudo/bpm/state.json";
const VAR_DIR: &CStr = c"/var/lib/shirudo/bpm";
const PACKAGES_DIR: &[u8] = b"/var/lib/shirudo/bpm/packages";

/// `struct bpm_state_entry`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpmStateEntry {
    pub(crate) name: [u8; MAX_NAME],
    pub(crate) version: [u8; MAX_NAME],
    pub(crate) source: [u8; MAX_NAME],
    pub(crate) path: [u8; PATH_MAX],
}

const _: () = assert!(size_of::<BpmStateEntry>() == 3 * 128 + 4096);

impl BpmStateEntry {
    pub(crate) const fn new() -> Self {
        BpmStateEntry {
            name: [0; MAX_NAME],
            version: [0; MAX_NAME],
            source: [0; MAX_NAME],
            path: [0; PATH_MAX],
        }
    }
}

/// Where the entries go, and the scratch entry the schema fills for each
/// before `take_entry()` takes it.
struct StateSink<'s> {
    items: &'s mut [BpmStateEntry],
    n: usize,
    scratch: BpmStateEntry,
}

impl StateSink<'_> {
    fn take_entry(&mut self) -> Result<(), c_int> {
        let mut expected = [0u8; PATH_MAX];
        let Some(item) = self.items.get_mut(self.n) else {
            return Err(-E2BIG);
        };
        let e = &self.scratch;
        let (name, version, source) = (cstr(&e.name), cstr(&e.version), cstr(&e.source));

        if name.is_empty()
            || version.is_empty()
            || !name_ok(name)
            || !version_ok(version)
            || !name_ok(source)
        {
            return Err(-EINVAL);
        }
        if strsprintf(&mut expected, &[PACKAGES_DIR, b"/", name, b"/", version]).is_err()
            || cstr(&expected) != cstr(&e.path)
        {
            return Err(-EINVAL);
        }
        *item = self.scratch;
        self.n += 1;
        // A field the next entry leaves out is not this entry's.
        self.scratch = BpmStateEntry::new();
        Ok(())
    }
}

/// The entries of a state document into `st`, as many as it holds, and
/// their count into `n`: 0, -EINVAL or -E2BIG.
fn parse(body: &[u8], st: &mut [BpmStateEntry], n: &mut c_int) -> c_int {
    let mut sink = StateSink {
        items: st,
        n: 0,
        scratch: BpmStateEntry::new(),
    };
    let sub = [
        JsonField::string(c"name", |s: &mut StateSink| &mut s.scratch.name),
        JsonField::string(c"version", |s| &mut s.scratch.version),
        JsonField::string(c"source", |s| &mut s.scratch.source),
        JsonField::string(c"path", |s| &mut s.scratch.path),
    ];
    let root = [JsonField::array(c"packages", &sub, &StateSink::take_entry)];

    if let Err(err) = parse_schema(body, &root, &mut sink) {
        return err;
    }
    if !root[0].seen() {
        return -EINVAL;
    }
    *n = sink.n as c_int;
    0
}

/// The entries as the document parse() reads, into `buf`, and its length
/// into `len`: 0 or -E2BIG.
fn emit(st: &[BpmStateEntry], buf: &mut [u8], len: &mut usize) -> c_int {
    let mut e = JsonEmit::fixed(buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.arr_open(b"packages");
    for entry in st {
        e.obj_open();
        e.kv_string(b"name", cstr(&entry.name));
        e.kv_string(b"version", cstr(&entry.version));
        e.kv_string(b"source", cstr(&entry.source));
        e.kv_string(b"path", cstr(&entry.path));
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    if e.err() != 0 {
        return -E2BIG;
    }
    *len = e.written();
    0
}

/// The recorded entries, as many as `st` holds; none when there is no
/// state yet.
fn read(st: &mut [BpmStateEntry], n: &mut c_int) -> c_int {
    let body = match crate::util::io::read(STATE_PATH, STATE_FILE_MAX) {
        Ok(body) => body,
        Err(err) if err == -ENOENT => {
            *n = 0;
            return 0;
        }
        Err(err) => return err,
    };
    parse(&body, st, n)
}

/// The packages the state records.
pub(crate) fn read_all() -> Result<Vec<BpmStateEntry>, c_int> {
    let mut st = vec![BpmStateEntry::new(); MAX_STATE as usize];
    let mut n = 0;

    match read(&mut st, &mut n) {
        0 => {
            st.truncate(usize::try_from(n).unwrap_or(0));
            Ok(st)
        }
        err => Err(err),
    }
}

pub(crate) fn write(st: &[BpmStateEntry]) -> c_int {
    let mut len = 0usize;
    let mut buf = vec![0u8; STATE_EMIT_MAX];
    let mut ret = emit(st, &mut buf, &mut len);

    if ret == 0 {
        ret = seal::mkdir_p(VAR_DIR.to_bytes(), 0o700)
            .and_then(|()| seal::write_file(STATE_PATH.to_bytes(), &buf[..len], 0o600))
            .err()
            .unwrap_or(0);
    }
    ret
}

#[cfg(test)]
mod tests;
