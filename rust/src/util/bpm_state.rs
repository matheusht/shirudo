// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The packages bpm installed, as /var/lib/shirudo/bpm/state.json records
//! them, behind `util/bpm_state.h`.

use core::ffi::{CStr, c_char, c_int, c_void};

use crate::errno::{E2BIG, EINVAL, ENOENT, ENOMEM};
use crate::heap::{xfree, xmalloc};
use crate::sys::libc::PATH_MAX;
use crate::text::{cstr, strsprintf};
use crate::util::bpm_oci::{MAX_NAME, name_ok, version_ok};
use crate::util::io::read_file;
use crate::util::json::{JsonArray, JsonEmit, JsonField, parse_schema};
use crate::util::seal::{seal_mkdir_p, seal_write_file};

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
/// before `on_state_entry()` takes it.
struct StateSink {
    items: *mut BpmStateEntry,
    n: c_int,
    scratch: BpmStateEntry,
}

unsafe extern "C" fn on_state_entry(ud: *mut c_void) -> c_int {
    let s = ud.cast::<StateSink>();
    let mut expected = [0u8; PATH_MAX];

    // SAFETY: the sink bpm_state_parse() made the array's context, read
    // and written through this pointer alone, as the parser writes the
    // scratch entry through its own and is not running now.
    unsafe {
        if (*s).n >= MAX_STATE {
            return -E2BIG;
        }
        let e = &(*s).scratch;
        let (name, version, source) = (cstr(&e.name), cstr(&e.version), cstr(&e.source));

        if name.is_empty()
            || version.is_empty()
            || !name_ok(name)
            || !version_ok(version)
            || !name_ok(source)
        {
            return -EINVAL;
        }
        if strsprintf(&mut expected, &[PACKAGES_DIR, b"/", name, b"/", version]).is_err()
            || cstr(&expected) != cstr(&e.path)
        {
            return -EINVAL;
        }
        (*s).items.add((*s).n as usize).write((*s).scratch);
        (*s).n += 1;
        // A field the next entry leaves out is not this entry's.
        (*s).scratch = BpmStateEntry::new();
    }
    0
}

/// The entries of a state document into `st`, which holds
/// `BPM_MAX_STATE`, and their count into `n`: 0, -EINVAL or -E2BIG.
///
/// # Safety
///
/// `st` has room for `BPM_MAX_STATE` entries.
unsafe fn parse(body: &[u8], st: *mut BpmStateEntry, n: &mut c_int) -> c_int {
    let mut sink = StateSink {
        items: st,
        n: 0,
        scratch: BpmStateEntry::new(),
    };
    let mut arr = JsonArray::new(on_state_entry, (&raw mut sink).cast());
    let mut sub = [
        JsonField::string(c"name", (&raw mut sink.scratch.name).cast(), MAX_NAME),
        JsonField::string(c"version", (&raw mut sink.scratch.version).cast(), MAX_NAME),
        JsonField::string(c"source", (&raw mut sink.scratch.source).cast(), MAX_NAME),
        JsonField::string(c"path", (&raw mut sink.scratch.path).cast(), PATH_MAX),
    ];
    let mut root = [JsonField::array(
        c"packages",
        &raw mut arr,
        sub.as_mut_ptr(),
        sub.len(),
    )];
    // SAFETY: every pointer of the schema names a local of this frame,
    // which outlives the parse and is touched meanwhile only through
    // those pointers and the sink's.
    let ret = unsafe { parse_schema(body, root.as_mut_ptr(), root.len()) };

    if ret != 0 {
        return ret;
    }
    if !root[0].seen() {
        return -EINVAL;
    }
    *n = sink.n;
    0
}

/// The entries as the document parse() reads, into `buf`, and its length
/// into `len`: 0 or -E2BIG.
fn emit(st: &[BpmStateEntry], buf: *mut c_char, cap: usize, len: &mut usize) -> c_int {
    let mut e = JsonEmit::fixed(buf, cap);

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

/// The recorded entries; none when there is no state yet.
///
/// # Safety
///
/// `st` has room for `BPM_MAX_STATE` entries.
unsafe fn read(st: *mut BpmStateEntry, n: &mut c_int) -> c_int {
    let mut body: *mut c_char = core::ptr::null_mut();
    let mut len = 0usize;
    // SAFETY: a C string, a bound, and where read_file() leaves the body
    // and its length.
    let ret = unsafe {
        read_file(
            STATE_PATH.as_ptr(),
            STATE_FILE_MAX,
            (&raw mut body).cast(),
            &mut len,
        )
    };

    if ret == -ENOENT {
        *n = 0;
        return 0;
    }
    if ret != 0 {
        return ret;
    }
    // SAFETY: the len bytes read_file() gave, and the caller's room.
    let ret = unsafe { parse(core::slice::from_raw_parts(body.cast::<u8>(), len), st, n) };
    // SAFETY: what read_file() allocated, len bytes and a NUL.
    unsafe { xfree(body.cast(), len + 1) };
    ret
}

/// The packages the state records.
pub(crate) fn read_all() -> Result<Vec<BpmStateEntry>, c_int> {
    let mut st = vec![BpmStateEntry::new(); MAX_STATE as usize];
    let mut n = 0;

    // SAFETY: room for MAX_STATE entries.
    match unsafe { read(st.as_mut_ptr(), &mut n) } {
        0 => {
            st.truncate(usize::try_from(n).unwrap_or(0));
            Ok(st)
        }
        err => Err(err),
    }
}

pub(crate) fn write(st: &[BpmStateEntry]) -> c_int {
    let mut len = 0usize;
    // SAFETY: a size alone.
    let buf: *mut c_char = unsafe { xmalloc(STATE_EMIT_MAX) }.cast();

    if buf.is_null() {
        return -ENOMEM;
    }
    let mut ret = emit(st, buf, STATE_EMIT_MAX, &mut len);

    if ret == 0 {
        // SAFETY: a C string and a mode.
        ret = unsafe { seal_mkdir_p(VAR_DIR.as_ptr(), 0o700) };
    }
    if ret == 0 {
        // SAFETY: a C string, the len bytes emitted, and a mode.
        ret = unsafe { seal_write_file(STATE_PATH.as_ptr(), buf.cast(), len, 0o600) };
    }
    // SAFETY: what xmalloc() gave, and its size.
    unsafe { xfree(buf.cast(), STATE_EMIT_MAX) };
    ret
}

mod capi {
    use core::ffi::{c_char, c_int};

    use super::BpmStateEntry;
    use crate::ffi;

    /// # Safety
    ///
    /// `body` holds `len` bytes, `st` has room for `BPM_MAX_STATE`
    /// entries, and `n` points to an int.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bpm_state_parse(
        body: *const c_char,
        len: usize,
        st: *mut BpmStateEntry,
        n: *mut c_int,
    ) -> c_int {
        // SAFETY: the caller passes the body, the room and the count.
        unsafe { super::parse(ffi::slice(body.cast(), len), st, &mut *n) }
    }

    /// # Safety
    ///
    /// `st` holds `n` entries, `buf` has room for `cap` bytes, and `len`
    /// points to a size.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bpm_state_emit(
        st: *const BpmStateEntry,
        n: c_int,
        buf: *mut c_char,
        cap: usize,
        len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes the entries, the room and the length.
        unsafe { super::emit(ffi::slice(st, n.max(0) as usize), buf, cap, &mut *len) }
    }
}
