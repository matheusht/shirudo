// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The upatch tree's state on a target: whether
//! an operation's selector matches the node, the cursor and the pending
//! record a sync keeps, and the tree eventlog whose projection chain it
//! replays.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::ffi::CString;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::fs::FileExt;

use crate::errno::{
    E2BIG, EBADMSG, EINTR, EINVAL, EIO, ENAMETOOLONG, ENOENT, ENOMEM, ENOSPC, text,
};
use crate::ffi;
use crate::heap::{libc_free, xfree, xmalloc};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    File, O_RDONLY, PATH_MAX, R_OK, Utsname, access, close, errno, fclose, fdopen, fopen, uname,
};
use crate::text::{cstr, find, strscpy, strsprintf};
use crate::util::bpm_tree::{
    MAX_KCONFIG, MAX_LABELS, MAX_VALUES, STRING_MAX, TreeKv, TreeOperation, TreePending,
    TreeSelector, TreeSelectorKv, TreeState, count, pairs,
};
use crate::util::crypto_openssl::sha256_into;
use crate::util::hex::{self, hex_decode, hex_encode, sha256_digest_decode};
use crate::util::image_config;
use crate::util::io::lock_exclusive;
use crate::util::io::{read, read_text_line};
use crate::util::json::{JsonEmit, JsonField, MAX_BYTES, parse_schema};
use crate::util::kernel_build_id::read_build_id;
use crate::util::kernel_release::prefix_matches;
use crate::util::seal::{
    seal_append_line, seal_mkdir_p, seal_open, seal_open_read, seal_write_file,
};
use crate::util::upatch::upatch_name_valid;

/// The open-addressed index of a selector's kconfig keys.
const HASH_SIZE: usize = 128;
/// The largest kernel config read: a distribution's is some 300 KiB.
const KCONFIG_MAX: usize = 4 << 20;
/// `KERNEL_BUILD_ID_STRING_MAX`: 2 * 64 hex digits and a NUL.
const BUILD_ID_STRING_MAX: usize = 2 * 64 + 1;
/// A line of a kernel config longer than this, with its newline, is
/// skipped whole.
const LINE_MAX: usize = 1024;

/// BPM_TREE_* of util/paths.h, and the node's labels.
const TREE_ETC_PATH: &CStr = c"/etc/shirudo/bpm/upatch-tree.conf";
const TREE_VAR_DIR: &CStr = c"/var/lib/shirudo/bpm/upatch-tree";
const STATE: &[u8] = b"state.json";
const EVENTLOG: &[u8] = b"tree-eventlog";
const OUTCOMES: &[u8] = b"outcomes";
const PENDING: &[u8] = b"pending.json";

#[cfg(test)]
std::thread_local! {
    /// The directory a test keeps the tree's files in, in place of
    /// TREE_VAR_DIR, for the test's own thread.
    static TEST_DIR: core::cell::RefCell<Option<CString>> = const { core::cell::RefCell::new(None) };
}

/// The tree's directory, or the file `name` in it.
fn tree_path(name: &[u8]) -> CString {
    #[cfg(test)]
    let dir = TEST_DIR.with_borrow(Clone::clone);
    #[cfg(not(test))]
    let dir: Option<CString> = None;
    let mut path = dir.as_deref().unwrap_or(TREE_VAR_DIR).to_bytes().to_vec();

    if !name.is_empty() {
        path.push(b'/');
        path.extend_from_slice(name);
    }
    CString::new(path).unwrap_or_default()
}
const NODE_LABELS_PATH: &CStr = c"/etc/shirudo/node.labels";

/// isspace() in the C locale, which shirudo runs in.
fn is_space(c: u8) -> bool {
    matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')
}

/// `s` without the isspace() bytes it starts with.
fn trim_start(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if !is_space(*first) {
            break;
        }
        s = rest;
    }
    s
}

/// `s` without the isspace() bytes it ends with.
fn trim_end(mut s: &[u8]) -> &[u8] {
    while let [rest @ .., last] = s {
        if !is_space(*last) {
            break;
        }
        s = rest;
    }
    s
}

/// Whether one of the values of `v` is `want`.
fn values_match(v: &TreeSelectorKv, want: &[u8]) -> bool {
    v.values[..count(v.n_values, MAX_VALUES)]
        .iter()
        .any(|value| cstr(value) == want)
}

/// A pair added after the `n` at `dst`, of at most `max`: 0, -E2BIG for
/// no room, or -ENOSPC for a key or value too long.
fn kv_add(dst: &mut [TreeKv], n: &mut c_int, max: c_int, key: &[u8], value: &[u8]) -> c_int {
    if *n >= max {
        return -E2BIG;
    }
    let kv = &mut dst[*n as usize];

    if strscpy(&mut kv.key, key).is_err() || strscpy(&mut kv.value, value).is_err() {
        return -ENOSPC;
    }
    *n += 1;
    0
}

/// The value of the first of the pairs with `key`.
fn kv_value<'a>(v: &'a [TreeKv], key: &[u8]) -> Option<&'a [u8]> {
    v.iter()
        .find(|kv| cstr(&kv.key) == key)
        .map(|kv| cstr(&kv.value))
}

/// Whether a tree is configured, in the config image when one is active.
fn configured() -> bool {
    if !image_config::active() {
        // SAFETY: a C string and a mode.
        return unsafe { access(TREE_ETC_PATH.as_ptr(), R_OK) } == 0;
    }
    let fd = image_config::open(image_config::TREE_CONF, O_RDONLY);

    if fd < 0 {
        return false;
    }
    // SAFETY: the fd the image gave, closed once.
    unsafe { close(fd) };
    true
}

/// The `key = value` lines of `f`, which it closes, into the `max` pairs
/// at `out`, `*n` of them; a blank line, a comment and a line without a
/// `=` say nothing. 0, or -errno.
///
/// # Safety
///
/// `f` is an open stream, and `out` room for `max` pairs.
unsafe fn read_config_stream(f: *mut File, out: *mut TreeKv, n: &mut c_int, max: c_int) -> c_int {
    // SAFETY: the caller's room for max pairs.
    let out = unsafe { core::slice::from_raw_parts_mut(out, usize::try_from(max).unwrap_or(0)) };
    let mut capacity = 0usize;
    let mut line: *mut c_char = ptr::null_mut();
    let mut ret = 0;

    *n = 0;
    loop {
        // SAFETY: the caller's stream, and getline()'s buffer and size.
        let got = unsafe { read_text_line(f, &mut line, &mut capacity, 511) };

        if got == 0 {
            break;
        }
        if got < 0 {
            ret = got;
            break;
        }
        // SAFETY: the line read_text_line() gave, a C string.
        let text = trim_start(unsafe { ffi::c_str(line) });

        if text.is_empty() || text[0] == b'#' {
            continue;
        }
        let text = trim_end(text);
        let Some(eq) = text.iter().position(|&c| c == b'=') else {
            continue;
        };
        // The key keeps what is before the '='; the value loses the
        // spaces it starts with.
        ret = kv_add(out, n, max, &text[..eq], trim_start(&text[eq + 1..]));
        if ret != 0 {
            break;
        }
    }
    // SAFETY: getline()'s buffer and the caller's stream, each released
    // once.
    unsafe {
        libc_free(line.cast());
        fclose(f);
    }
    ret
}

/// read_config_stream() on `fd`, which it closes.
///
/// # Safety
///
/// `fd` is open, and `out` room for `max` pairs.
unsafe fn read_config_fd(fd: c_int, out: *mut TreeKv, n: &mut c_int, max: c_int) -> c_int {
    // SAFETY: the caller's fd, and a mode.
    let f = unsafe { fdopen(fd, c"r".as_ptr()) };

    if f.is_null() {
        let ret = -errno();

        // SAFETY: the caller's fd, which no stream took, closed once.
        unsafe { close(fd) };
        return ret;
    }
    // SAFETY: the stream, and the caller's room.
    unsafe { read_config_stream(f, out, n, max) }
}

/// read_config_stream() on the file at `path`.
///
/// # Safety
///
/// `path` is a C string, and `out` room for `max` pairs.
unsafe fn read_config_file(
    path: *const c_char,
    out: *mut TreeKv,
    n: &mut c_int,
    max: c_int,
) -> c_int {
    *n = 0;
    // SAFETY: the caller's C string, and a mode.
    let f = unsafe { fopen(path, c"re".as_ptr()) };

    if f.is_null() {
        return -errno();
    }
    // SAFETY: the stream, and the caller's room.
    unsafe { read_config_stream(f, out, n, max) }
}

/// FNV-1a of a selector key.
fn selector_hash(key: &[u8]) -> u32 {
    key.iter().fold(2_166_136_261u32, |hash, &c| {
        (hash ^ u32::from(c)).wrapping_mul(16_777_619)
    })
}

/// The slots of an index of the kconfig keys, each the first pair of its
/// key, or -1.
fn hash_build(kconfig: &[TreeSelectorKv], slots: &mut [i32; HASH_SIZE]) {
    *slots = [-1; HASH_SIZE];
    for (i, kv) in kconfig.iter().enumerate() {
        let key = cstr(&kv.key);
        let mut slot = selector_hash(key) as usize & (HASH_SIZE - 1);

        while slots[slot] >= 0 && cstr(&kconfig[slots[slot] as usize].key) != key {
            slot = (slot + 1) & (HASH_SIZE - 1);
        }
        if slots[slot] < 0 {
            slots[slot] = i as i32;
        }
    }
}

/// The pair of the index holding `key`.
fn hash_find(kconfig: &[TreeSelectorKv], slots: &[i32; HASH_SIZE], key: &[u8]) -> Option<usize> {
    let mut slot = selector_hash(key) as usize & (HASH_SIZE - 1);

    for _ in 0..HASH_SIZE {
        let i = usize::try_from(slots[slot]).ok()?;

        if cstr(&kconfig[i].key) == key {
            return Some(i);
        }
        slot = (slot + 1) & (HASH_SIZE - 1);
    }
    None
}

/// Where the selector's kconfig values go as a config is read.
struct KconfigValues<'a> {
    kconfig: &'a [TreeSelectorKv],
    slots: &'a [i32; HASH_SIZE],
    values: &'a mut [[u8; STRING_MAX]],
    found: &'a mut [bool],
}

/// One line of a kernel config: the value of a key the selector names
/// kept, `# CONFIG_X is not set` reading as `n`. 0, or -ENOSPC for a
/// value too long for any selector to name.
fn config_line(line: &[u8], kv: &mut KconfigValues<'_>) -> c_int {
    let start = trim_start(cstr(line));

    if start.is_empty() {
        return 0;
    }
    let (key, value): (&[u8], &[u8]) = if start.starts_with(b"# CONFIG_") {
        let start = &start[2..];
        let Some(at) = find(start, b" is not set") else {
            return 0;
        };

        (&start[..at], b"n")
    } else {
        if start[0] == b'#' {
            return 0;
        }
        let Some(eq) = start.iter().position(|&c| c == b'=') else {
            return 0;
        };
        let mut value = trim_end(trim_start(&start[eq + 1..]));

        if value.len() > 1 && value[0] == b'"' && value[value.len() - 1] == b'"' {
            value = &value[1..value.len() - 1];
        }
        (trim_end(&start[..eq]), value)
    };
    let Some(index) = hash_find(kv.kconfig, kv.slots, key) else {
        return 0;
    };
    if strscpy(&mut kv.values[index], value).is_err() {
        return -ENOSPC;
    }
    kv.found[index] = true;
    0
}

/// The one gzip member of `input`, with nothing behind it, into an
/// allocation of `*cap` bytes holding `*out_len` and a NUL. Not through
/// a gzip file's reads: zlib 1.3.2 reads on past the end of a member
/// into a next one, finds that cut short, and has gzclose() fail the
/// whole file.
///
/// # Safety
///
/// `input` holds `len` bytes.
unsafe fn gunzip(
    input: *mut u8,
    len: usize,
    out: &mut *mut u8,
    out_len: &mut usize,
    cap: &mut usize,
) -> c_int {
    // SAFETY: the caller's len bytes.
    let input = unsafe { ffi::slice(input, len) };
    let text = match crate::util::gzip::gunzip_one(input, KCONFIG_MAX) {
        Ok(t) => t,
        Err(err) => return -err,
    };
    // SAFETY: a size, the text and its NUL.
    let buf = unsafe { xmalloc(text.len() + 1) }.cast::<u8>();
    if buf.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the text.len() + 1 bytes xmalloc() gave, zeroed.
    unsafe { core::ptr::copy_nonoverlapping(text.as_ptr(), buf, text.len()) };
    *out = buf;
    *out_len = text.len();
    *cap = text.len() + 1;
    0
}

/// The lines of a kernel config into the selector's values. A line of
/// LINE_MAX bytes or more with its newline is skipped whole, as a part
/// from the middle of a long string value would read as an option of its
/// own: its option reads as not set.
fn config_text(text: &[u8], kv: &mut KconfigValues<'_>) -> c_int {
    let mut off = 0usize;

    while off < text.len() {
        let rest = &text[off..];
        let n = rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());

        if n < LINE_MAX - 1 {
            let ret = config_line(&rest[..n], kv);

            if ret != 0 {
                return ret;
            }
        }
        off += n + 1;
    }
    0
}

/// The kernel config at `path`, gzip'd or not, into the selector's
/// values: 0 or -errno.
///
/// # Safety
///
/// `path` is a C string.
unsafe fn read_selector_config_file(
    path: *const c_char,
    kv: &mut KconfigValues<'_>,
    gz: bool,
) -> c_int {
    // SAFETY: the caller's C string.
    let mut raw = match read(unsafe { CStr::from_ptr(path) }, KCONFIG_MAX) {
        Ok(raw) => raw,
        Err(err) => return err,
    };
    if !gz {
        return config_text(&raw, kv);
    }
    let mut text: *mut u8 = ptr::null_mut();
    let mut text_len = 0usize;
    let mut cap = 0usize;
    // SAFETY: the file's bytes, and rooms for what they inflate to.
    let ret = unsafe {
        gunzip(
            raw.as_mut_ptr(),
            raw.len(),
            &mut text,
            &mut text_len,
            &mut cap,
        )
    };
    if ret != 0 {
        return ret;
    }
    // SAFETY: the text_len bytes of the text.
    let ret = config_text(unsafe { ffi::slice(text, text_len) }, kv);

    // SAFETY: the text's allocation, of cap bytes, freed once.
    unsafe { xfree(text.cast(), cap) };
    ret
}

/// Whether the selector's kconfig pairs match the running kernel's
/// config: /proc/config.gz, or /boot/config-<release> when that cannot
/// be read or names none of them. 1, 0, or -errno.
///
/// # Safety
///
/// `release` is the node's release, a C string.
unsafe fn kconfig_matches(kconfig: &[TreeSelectorKv], release: &[u8]) -> c_int {
    let mut slots = [-1i32; HASH_SIZE];
    let mut values = [[0u8; STRING_MAX]; MAX_KCONFIG];
    let mut found = [false; MAX_KCONFIG];

    hash_build(kconfig, &mut slots);
    let mut kv = KconfigValues {
        kconfig,
        slots: &slots,
        values: &mut values,
        found: &mut found,
    };
    // SAFETY: a C string.
    let config_rc =
        unsafe { read_selector_config_file(c"/proc/config.gz".as_ptr(), &mut kv, true) };
    let config_any = kv.found[..kconfig.len()].iter().any(|&f| f);

    if config_rc != 0 || !config_any {
        let mut path = [0u8; PATH_MAX];

        kv.found.fill(false);
        if strsprintf(&mut path, &[b"/boot/config-", release]).is_err() {
            return -ENAMETOOLONG;
        }
        // SAFETY: the path, terminated by strsprintf().
        let ret = unsafe { read_selector_config_file(path.as_ptr().cast(), &mut kv, false) };

        // No config to show, or a value longer than any selector names,
        // matches nothing; a config that cannot be read is no answer,
        // and the sync must not move past the operation on it.
        if ret == -ENOENT || ret == -ENOSPC {
            return if config_rc != 0 && config_rc != -ENOENT && config_rc != -ENOSPC {
                config_rc
            } else {
                0
            };
        }
        if ret != 0 {
            return ret;
        }
    }
    // The config is read into the first pair of a key, so a key named
    // twice is matched there: left unfound, the operation was skipped
    // and the tree moved past it for good.
    for pair in kconfig {
        match hash_find(kconfig, &slots, cstr(&pair.key)) {
            Some(k) if kv.found[k] && values_match(pair, cstr(&kv.values[k])) => {}
            _ => return 0,
        }
    }
    1
}

/// Whether the selector's label pairs match the node's labels, from the
/// config image when one is active. 1, 0, or -errno.
fn labels_match(labels_wanted: &[TreeSelectorKv]) -> c_int {
    let mut labels: [TreeKv; MAX_LABELS] = [const {
        TreeKv {
            key: [0; STRING_MAX],
            value: [0; STRING_MAX],
        }
    }; MAX_LABELS];
    let mut nl: c_int = 0;
    let ret = if image_config::active() {
        let fd = image_config::open(image_config::NODE_LABELS, O_RDONLY);

        if fd == -ENOENT {
            return 0;
        }
        if fd < 0 {
            return fd;
        }
        // SAFETY: the fd the image gave, and room for the labels.
        unsafe { read_config_fd(fd, labels.as_mut_ptr(), &mut nl, MAX_LABELS as c_int) }
    } else {
        // SAFETY: a C string, and room for the labels.
        unsafe {
            read_config_file(
                NODE_LABELS_PATH.as_ptr(),
                labels.as_mut_ptr(),
                &mut nl,
                MAX_LABELS as c_int,
            )
        }
    };
    if ret == -ENOENT {
        return 0;
    }
    if ret != 0 {
        return ret;
    }
    let have = &labels[..count(nl, MAX_LABELS)];

    for wanted in labels_wanted {
        match kv_value(have, cstr(&wanted.key)) {
            Some(v) if values_match(wanted, v) => {}
            _ => return 0,
        }
    }
    1
}

/// Whether the selector matches the running node: 1, 0, or -errno when
/// its labels or kernel config cannot be read. An empty selector is the
/// tree's explicit wildcard, and matches before the node is asked, so an
/// unconstrained operation applies even without uname(2).
///
/// # Safety
///
/// `s` is NULL or a selector whose pairs are as its counts say.
unsafe fn selector_matches(s: *const TreeSelector) -> c_int {
    // SAFETY: the caller's selector, if any.
    let Some(s) = (unsafe { s.as_ref() }) else {
        return 0;
    };
    if s.n_kernel_release_prefix == 0
        && s.n_kernel_build_id == 0
        && s.n_architecture == 0
        && s.n_kconfig == 0
        && s.n_labels == 0
    {
        return 1;
    }
    let mut u = Utsname::zeroed();

    // SAFETY: room for the node's names.
    if unsafe { uname(&mut u) } != 0 {
        return 0;
    }
    let release = cstr(crate::sys::libc::bytes(&u.release));

    if s.n_kernel_release_prefix != 0
        && !s.kernel_release_prefix[..count(s.n_kernel_release_prefix, MAX_VALUES)]
            .iter()
            .any(|prefix| prefix_matches(release, cstr(prefix)))
    {
        return 0;
    }
    if s.n_kernel_build_id != 0 {
        let mut build_id = [0u8; BUILD_ID_STRING_MAX];

        // A selector naming a build ID is fail-closed on a kernel that
        // publishes none.
        // SAFETY: room for the hex digits of a build ID.
        if unsafe { read_build_id(build_id.as_mut_ptr().cast()) } != 0 {
            return 0;
        }
        if !s.kernel_build_id[..count(s.n_kernel_build_id, MAX_VALUES)]
            .iter()
            .any(|id| cstr(id) == cstr(&build_id))
        {
            return 0;
        }
    }
    if s.n_architecture != 0
        && !s.architecture[..count(s.n_architecture, MAX_VALUES)]
            .iter()
            .any(|arch| cstr(arch) == cstr(crate::sys::libc::bytes(&u.machine)))
    {
        return 0;
    }
    if s.n_kconfig != 0 {
        // SAFETY: the selector's kconfig pairs.
        let kconfig = unsafe { pairs(s.kconfig, s.n_kconfig, MAX_KCONFIG) };
        // SAFETY: the node's release, a C string.
        let ret = unsafe { kconfig_matches(kconfig, release) };

        if ret != 1 {
            return ret;
        }
    }
    if s.n_labels != 0 {
        // SAFETY: the selector's label pairs.
        let ret = labels_match(unsafe { pairs(s.labels, s.n_labels, MAX_LABELS) });

        if ret != 1 {
            return ret;
        }
    }
    1
}

/// json_parse(): the `len` bytes at `data` against the schema.
///
/// # Safety
///
/// `data` holds `len` bytes, and the fields are a valid schema.
unsafe fn json_parse(data: *const u8, len: usize, fields: &mut [JsonField]) -> c_int {
    if len > MAX_BYTES {
        return -E2BIG;
    }
    // SAFETY: the caller's bytes and schema.
    unsafe { parse_schema(ffi::slice(data, len), fields.as_mut_ptr(), fields.len()) }
}

/// Whether `hex` is exactly 64 hex digits: a SHA-256 digest.
fn hex32_valid(hex: &[u8; 65]) -> bool {
    let mut raw = [0u8; 32];

    // SAFETY: a C string, and room for 32 bytes.
    unsafe { hex_decode(hex.as_ptr().cast(), raw.as_mut_ptr(), raw.len()) == 0 }
}

/// Whether the 32 bytes differ, in a time that does not depend on where:
/// memneq_explicit().
fn differ(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut neq = 0u8;

    for i in 0..32 {
        neq |= a[i] ^ b[i];
        neq = core::hint::black_box(neq);
    }
    neq != 0
}

/// The pending record in the `len` bytes at `body`: 0, or -EINVAL for one
/// that lacks its schema, sequence number, upatch name or digest.
///
/// # Safety
///
/// `body` holds `len` bytes, and `out` is room for a record.
unsafe fn pending_parse(body: *const c_char, len: usize, out: *mut TreePending) -> c_int {
    // SAFETY: the caller's room, all of whose bits zeroed are a record.
    let out = unsafe {
        out.write_bytes(0, 1);
        &mut *out
    };
    let mut schema = 0i64;
    let mut fields = [
        JsonField::int(c"schema", &mut schema),
        JsonField::int(c"seq", &mut out.seq),
        JsonField::string(c"id", out.id.as_mut_ptr(), out.id.len()),
        JsonField::string(
            c"operation_digest",
            out.operation_digest.as_mut_ptr(),
            out.operation_digest.len(),
        ),
    ];
    // SAFETY: the caller's bytes, and a schema of the record's fields.
    let mut ret = unsafe { json_parse(body.cast(), len, &mut fields) };

    if ret == 0 {
        let mut digest = [0u8; 32];
        // SAFETY: the record's C strings, and room for a digest.
        let bad = unsafe {
            schema != 1
                || out.seq <= 0
                || !upatch_name_valid(out.id.as_ptr().cast())
                || sha256_digest_decode(out.operation_digest.as_ptr().cast(), digest.as_mut_ptr())
                    != 0
        };
        if bad {
            ret = -EINVAL;
        }
    }
    ret
}

/// The pending record, -ENOENT for none.
///
/// # Safety
///
/// `out` is room for a record.
unsafe fn pending_read(out: *mut TreePending) -> c_int {
    let body = match read(&tree_path(PENDING), 64 * 1024) {
        Ok(body) => body,
        Err(err) => return err,
    };
    // SAFETY: the record's bytes, and the caller's room.
    unsafe { pending_parse(body.as_ptr().cast(), body.len(), out) }
}

/// The operation a sync starts recorded as pending: 0 or -errno.
fn pending_write(op: &TreeOperation) -> c_int {
    let mut buf = [0u8; 1024];
    let mut e = JsonEmit::fixed(&mut buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_int(b"seq", op.seq);
    e.kv_string(b"id", cstr(&op.id));
    e.kv_string(b"operation_digest", cstr(&op.operation_digest));
    e.obj_close();
    if e.err() != 0 {
        return e.err();
    }
    // SAFETY: a C string, and a mode.
    let ret = unsafe { seal_mkdir_p(tree_path(b"").as_ptr(), 0o700) };

    if ret != 0 {
        return ret;
    }
    // SAFETY: a C string, the bytes emitted, and a mode.
    unsafe {
        seal_write_file(
            tree_path(PENDING).as_ptr(),
            e.output().as_ptr().cast(),
            e.output().len(),
            0o600,
        )
    }
}

/// The tree state at `path` into `out`, which keeps what was read of it
/// on an error: 0, or -errno.
///
/// # Safety
///
/// `path` is a C string, and `out` room for a state.
unsafe fn state_read(path: *const c_char, out: *mut TreeState) -> c_int {
    // SAFETY: the caller's room, all of whose bits zeroed are a state.
    let out = unsafe {
        out.write_bytes(0, 1);
        &mut *out
    };
    let mut schema = 0i64;
    // SAFETY: the caller's C string.
    let body = match read(unsafe { CStr::from_ptr(path) }, MAX_BYTES) {
        Ok(body) => body,
        Err(err) => return err,
    };
    let mut f = [
        JsonField::int(c"schema", &mut schema),
        JsonField::string(c"tree_id", out.tree_id.as_mut_ptr(), out.tree_id.len()),
        JsonField::int(c"generation", &mut out.generation),
        JsonField::int(c"last_seq", &mut out.last_seq),
        JsonField::string(
            c"projection_root",
            out.projection_root.as_mut_ptr(),
            out.projection_root.len(),
        ),
        JsonField::string(
            c"projection_root_tpm",
            out.projection_root_tpm.as_mut_ptr(),
            out.projection_root_tpm.len(),
        ),
        JsonField::string(
            c"manifest_digest",
            out.manifest_digest.as_mut_ptr(),
            out.manifest_digest.len(),
        ),
        JsonField::int(c"head_seq", &mut out.head_seq),
        JsonField::int(c"segment_base_seq", &mut out.segment_base_seq),
    ];
    // SAFETY: the file's bytes, and a schema of the state's fields.
    let mut ret = unsafe { json_parse(body.as_ptr(), body.len(), &mut f) };
    // tree_id, last_seq, both projection roots, head and segment base.
    let required = [1, 3, 4, 5, 7, 8];

    if ret == 0 && (schema != 1 || !required.iter().all(|&i| f[i].seen())) {
        ret = -EINVAL;
    }
    if ret == 0 && (!hex32_valid(&out.projection_root) || !hex32_valid(&out.projection_root_tpm)) {
        ret = -EINVAL;
    }
    if ret == 0 && out.manifest_digest[0] != 0 {
        let mut digest = [0u8; 32];

        // SAFETY: a C string, and room for a digest.
        if unsafe { sha256_digest_decode(out.manifest_digest.as_ptr().cast(), digest.as_mut_ptr()) }
            != 0
        {
            ret = -EINVAL;
        }
    }
    out.schema = schema as c_int;
    ret
}

/// The tree state written whole in place of what was there: 0 or -errno.
fn state_write(s: &TreeState) -> c_int {
    let mut buf = [0u8; 4096];
    let mut e = JsonEmit::fixed(&mut buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_string(b"tree_id", cstr(&s.tree_id));
    e.kv_int(b"generation", s.generation);
    e.kv_int(b"last_seq", s.last_seq);
    e.kv_string(b"projection_root", cstr(&s.projection_root));
    e.kv_string(b"projection_root_tpm", cstr(&s.projection_root_tpm));
    e.kv_string(b"manifest_digest", cstr(&s.manifest_digest));
    e.kv_int(b"head_seq", s.head_seq);
    e.kv_int(b"segment_base_seq", s.segment_base_seq);
    e.obj_close();
    if e.err() != 0 {
        return e.err();
    }
    let dir = tree_path(b"");
    // SAFETY: a C string, and a mode.
    let ret = unsafe { seal_mkdir_p(dir.as_ptr(), 0o700) };

    if ret != 0 {
        crate::log::err(
            &[
                &b"tree state mkdir "[..],
                dir.to_bytes(),
                b": ",
                text(ret).as_bytes(),
            ]
            .concat(),
        );
        return ret;
    }
    // SAFETY: a C string, the bytes emitted, and a mode.
    unsafe {
        seal_write_file(
            tree_path(STATE).as_ptr(),
            e.output().as_ptr().cast(),
            e.output().len(),
            0o600,
        )
    }
}

/// An operation applied, appended to the tree eventlog with the
/// projection root it leads to: 0 or -errno.
///
/// # Safety
///
/// `operation_digest` is NULL or a C string, and `projection_root` 32
/// bytes.
unsafe fn event_append(
    seq: i64,
    operation_digest: *const c_char,
    projection_root: *const u8,
) -> c_int {
    let mut digest = [0u8; 32];
    let mut root = [0 as c_char; 65];
    let mut buf = [0u8; 1024];

    // SAFETY: the caller's string, and room for a digest.
    if unsafe { sha256_digest_decode(operation_digest, digest.as_mut_ptr()) } != 0 {
        return -EINVAL;
    }
    // SAFETY: the caller's 32 bytes, and room for their hex digits.
    unsafe { hex_encode(projection_root, 32, root.as_mut_ptr()) };
    let mut e = JsonEmit::fixed(&mut buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_int(b"seq", seq);
    // SAFETY: the caller's C string, a digest just decoded.
    e.kv_string(b"digest", unsafe { ffi::c_str(operation_digest) });
    // SAFETY: the hex digits hex_encode() terminated.
    e.kv_string(b"projection_root", unsafe { ffi::c_str(root.as_ptr()) });
    e.obj_close();
    if e.err() != 0 {
        return e.err();
    }
    // SAFETY: a C string, and a mode.
    let ret = unsafe { seal_mkdir_p(tree_path(b"").as_ptr(), 0o700) };

    if ret != 0 {
        return ret;
    }
    // SAFETY: a C string, and the bytes emitted.
    unsafe {
        seal_append_line(
            tree_path(EVENTLOG).as_ptr(),
            e.output().as_ptr().cast(),
            e.output().len(),
        )
    }
}

/// What the eventlog's records, whole lines in order, chain to: each
/// SHA-256 of the chain so far and the record's operation digest, which
/// must be the projection root it recorded. Its root into `out`: 0, or
/// -errno with `out` unchanged.
///
/// # Safety
///
/// `path` is a C string, and `out` room for 32 bytes.
unsafe fn event_replay(path: *const c_char, out: *mut u8) -> c_int {
    // SAFETY: the caller's C string.
    let body = match read(unsafe { CStr::from_ptr(path) }, MAX_BYTES) {
        Ok(body) => body,
        Err(err) => return err,
    };
    let mut ret = 0;
    let text = &body[..];
    let mut chain = [0u8; 32];
    let mut previous_seq = 0i64;

    // A NUL would end the walk early and replay a shorter chain.
    if text.contains(&0) {
        return -EINVAL;
    }
    // Whole lines only: a record cut short at the end is not one yet.
    let whole = text.iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1);

    for line in text[..whole]
        .split(|&c| c == b'\n')
        .filter(|l| !l.is_empty())
    {
        let mut digest = [0u8; 128];
        let mut projection = [0u8; 65];
        let mut seq = 0i64;
        let mut f = [
            JsonField::int(c"seq", &mut seq),
            JsonField::string(c"digest", digest.as_mut_ptr(), digest.len()),
            JsonField::string(
                c"projection_root",
                projection.as_mut_ptr(),
                projection.len(),
            ),
        ];
        let mut d = [0u8; 32];
        let mut recorded = [0u8; 32];
        // SAFETY: the line's bytes, and a schema of the record's fields.
        let parsed = unsafe { json_parse(line.as_ptr(), line.len(), &mut f) };

        let bad = parsed != 0
            || !f[0].seen()
            || !f[1].seen()
            || !f[2].seen()
            || seq <= previous_seq
            || cstr(&projection).len() != 64;

        // SAFETY: the record's projection root, a C string, and room for
        // 32 bytes.
        if bad || unsafe { hex_decode(projection.as_ptr().cast(), recorded.as_mut_ptr(), 32) } != 0
        {
            ret = -EINVAL;
            break;
        }
        previous_seq = seq;
        // SAFETY: the record's digest, a C string, and room for 32 bytes.
        if unsafe { sha256_digest_decode(digest.as_ptr().cast(), d.as_mut_ptr()) } != 0 {
            ret = -EINVAL;
            break;
        }
        let mut next = [0u8; 64];

        next[..32].copy_from_slice(&chain);
        next[32..].copy_from_slice(&d);
        ret = sha256_into(&next, &mut chain);
        if ret != 0 {
            break;
        }
        if differ(&chain, &recorded) {
            ret = -EINVAL;
            break;
        }
    }
    if ret == 0 {
        // SAFETY: the caller's room for 32 bytes.
        unsafe { ptr::copy_nonoverlapping(chain.as_ptr(), out, 32) };
    }
    ret
}

/// What a sync did of an operation on this node.
pub(crate) const OUTCOME_APPLIED: i64 = 1;
pub(crate) const OUTCOME_UNMATCHED: i64 = 2;
pub(crate) const OUTCOME_MODULE_ABSENT: i64 = 3;

/// A line of the outcome record, the longest seq's 218 bytes with its
/// newline.
const OUTCOME_LINE_MAX: usize = 256;

/// One line of the record: an operation's seq and outcome, and the
/// projection and history roots after it. Seq 0, where every tree
/// starts, has zero roots.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct OutcomeLine {
    seq: i64,
    outcome: i64,
    projection_root: [u8; 32],
    history_root: [u8; 32],
}

fn outcome_valid(outcome: i64) -> bool {
    matches!(
        outcome,
        OUTCOME_APPLIED | OUTCOME_UNMATCHED | OUTCOME_MODULE_ABSENT
    )
}

fn outcome_emit(line: &OutcomeLine, buf: &mut [u8; OUTCOME_LINE_MAX]) -> Result<usize, c_int> {
    let mut e = JsonEmit::fixed(buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_int(b"seq", line.seq);
    e.kv_int(b"outcome", line.outcome);
    e.kv_string(b"projection_root", &hex::encode(&line.projection_root));
    e.kv_string(b"history_root", &hex::encode(&line.history_root));
    e.obj_close();
    match e.err() {
        0 => Ok(e.written()),
        err => Err(err),
    }
}

fn outcome_parse(text: &[u8]) -> Result<OutcomeLine, c_int> {
    let (mut projection, mut history) = ([0u8; 65], [0u8; 65]);
    let mut line = OutcomeLine::default();
    let mut schema = 0i64;
    let mut f = [
        JsonField::int(c"schema", &mut schema),
        JsonField::int(c"seq", &mut line.seq),
        JsonField::int(c"outcome", &mut line.outcome),
        JsonField::string(
            c"projection_root",
            projection.as_mut_ptr(),
            projection.len(),
        ),
        JsonField::string(c"history_root", history.as_mut_ptr(), history.len()),
    ];
    // SAFETY: the line's bytes, and a schema of its fields.
    let parsed = unsafe { json_parse(text.as_ptr(), text.len(), &mut f) };

    if parsed != 0
        || schema != 1
        || line.seq <= 0
        || !outcome_valid(line.outcome)
        || hex::decode(cstr(&projection), &mut line.projection_root).is_err()
        || hex::decode(cstr(&history), &mut line.history_root).is_err()
    {
        return Err(-EBADMSG);
    }
    Ok(line)
}

/// The record read from its start: the line last read, at seq 0 before
/// any, and where the next begins.
struct Outcomes {
    file: std::fs::File,
    end: u64,
    line: OutcomeLine,
}

impl Outcomes {
    /// The record open at `fd`, which it closes.
    fn new(fd: c_int) -> Self {
        Outcomes {
            // SAFETY: an fd the caller opened, which nothing else owns.
            file: unsafe { std::fs::File::from_raw_fd(fd) },
            end: 0,
            line: OutcomeLine::default(),
        }
    }

    /// The next line, which must be whole and of the next seq: every
    /// seq has its line. A last line without its newline is an append
    /// that did not finish, and counts as no line.
    fn next(&mut self) -> Result<(), c_int> {
        let mut buf = [0u8; OUTCOME_LINE_MAX];
        let mut have = 0;

        while have < buf.len() {
            match self.file.read_at(&mut buf[have..], self.end + have as u64) {
                Ok(0) => break,
                Ok(n) => have += n,
                Err(e) if e.raw_os_error() == Some(EINTR) => {}
                Err(e) => return Err(-e.raw_os_error().unwrap_or(EIO)),
            }
        }
        let newline = buf[..have]
            .iter()
            .position(|&c| c == b'\n')
            .ok_or(-EBADMSG)?;
        let next = outcome_parse(&buf[..newline])?;
        if next.seq != self.line.seq + 1 {
            return Err(-EBADMSG);
        }
        self.line = next;
        self.end += newline as u64 + 1;
        Ok(())
    }

    fn seek(&mut self, seq: i64) -> Result<(), c_int> {
        while self.line.seq < seq {
            self.next()?;
        }
        Ok(())
    }

    /// The lines past the one last read dropped, as a sync that stopped
    /// left them.
    fn cut(&self) -> Result<(), c_int> {
        let errno = |e: std::io::Error| -e.raw_os_error().unwrap_or(EIO);

        if self.file.metadata().map_err(errno)?.len() == self.end {
            return Ok(());
        }
        self.file.set_len(self.end).map_err(errno)?;
        self.file.sync_all().map_err(errno)
    }

    /// The record closed: 0 or -errno.
    fn close(self) -> c_int {
        // SAFETY: the fd the record owned, closed once.
        if unsafe { crate::sys::libc::close(self.file.into_raw_fd()) } != 0 {
            -crate::sys::libc::errno()
        } else {
            0
        }
    }
}

/// An operation's outcome appended with the roots after it, under the
/// bpm lock: 0 or -errno.
pub(crate) fn outcome_append(
    seq: i64,
    outcome: i64,
    projection_root: &[u8; 32],
    history_root: &[u8; 32],
) -> c_int {
    let line = OutcomeLine {
        seq,
        outcome,
        projection_root: *projection_root,
        history_root: *history_root,
    };
    let mut buf = [0u8; OUTCOME_LINE_MAX];

    if seq <= 0 || !outcome_valid(outcome) {
        return -EINVAL;
    }
    let len = match outcome_emit(&line, &mut buf) {
        Ok(len) => len,
        Err(err) => return err,
    };
    // SAFETY: a C string, and a mode.
    let ret = unsafe { seal_mkdir_p(tree_path(b"").as_ptr(), 0o700) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: a C string, and the bytes emitted.
    unsafe { seal_append_line(tree_path(OUTCOMES).as_ptr(), buf.as_ptr().cast(), len) }
}

/// What the record holds of the operations of seq `from` + 1 through
/// `to`: their outcomes onto `codes` and the roots at `from` into
/// `roots`, each as soon as it is read. -ENOENT without a record unless
/// it asks for no line, -EBADMSG for one that ends early or is out of
/// order.
fn outcomes_read(
    from: i64,
    to: i64,
    codes: &mut Vec<u8>,
    roots: &mut Option<([u8; 32], [u8; 32])>,
) -> c_int {
    if from < 0 || to < from {
        return -EINVAL;
    }
    // SAFETY: a C string.
    let fd = unsafe { seal_open_read(tree_path(OUTCOMES).as_ptr()) };
    if fd == -ENOENT && to == 0 {
        *roots = Some(([0; 32], [0; 32]));
        return 0;
    }
    if fd < 0 {
        return fd;
    }
    let mut o = Outcomes::new(fd);
    let read = (|| {
        o.seek(from)?;
        *roots = Some((o.line.projection_root, o.line.history_root));
        while o.line.seq < to {
            o.next()?;
            codes.push(o.line.outcome as u8);
        }
        Ok(())
    })();
    let _ = o.close();
    read.err().unwrap_or(0)
}

/// The projection and history roots the record holds at `seq`.
pub(crate) fn outcome_roots(seq: i64) -> Result<([u8; 32], [u8; 32]), c_int> {
    let (mut codes, mut roots) = (Vec::new(), None);

    match outcomes_read(seq, seq, &mut codes, &mut roots) {
        0 => roots.ok_or(-EINVAL),
        err => Err(err),
    }
}

/// The history root at `last_seq`, the lines past it dropped, which a
/// sync that stopped left: under the bpm lock and the record's own.
pub(crate) fn outcomes_resume(last_seq: i64) -> Result<[u8; 32], c_int> {
    if last_seq < 0 {
        return Err(-EINVAL);
    }
    // SAFETY: a C string, flags and a mode.
    let fd = unsafe { seal_open(tree_path(OUTCOMES).as_ptr(), crate::sys::libc::O_RDWR, 0) };
    if fd == -ENOENT && last_seq == 0 {
        return Ok([0; 32]);
    }
    if fd < 0 {
        return Err(fd);
    }
    let mut o = Outcomes::new(fd);
    let resumed = match lock_exclusive(fd) {
        0 => o.seek(last_seq).and_then(|()| o.cut()),
        err => Err(err),
    }
    .map(|()| o.line.history_root);
    match (resumed, o.close()) {
        (Ok(root), 0) => Ok(root),
        (Ok(_), err) => Err(err),
        (Err(err), _) => Err(err),
    }
}

/// The eventlog replayed, and whether it matches the projection root of
/// `s`, which tree_state_read() returned `state_rc` for: a state that
/// could not be read matches no replay.
pub(crate) fn eventlog_matches(s: &TreeState, state_rc: c_int) -> Result<([u8; 32], bool), c_int> {
    eventlog_matches_at(&tree_path(EVENTLOG), s, state_rc)
}

/// [`eventlog_matches`] of the eventlog at `path`.
fn eventlog_matches_at(
    path: &CStr,
    s: &TreeState,
    state_rc: c_int,
) -> Result<([u8; 32], bool), c_int> {
    let mut replay = [0u8; 32];
    let mut live = [0u8; 32];

    // SAFETY: a C string, and room for 32 bytes.
    let ret = unsafe { event_replay(path.as_ptr(), replay.as_mut_ptr()) };
    if ret != 0 {
        return Err(ret);
    }
    let matches = state_rc == 0
        && hex::decode(cstr(&s.projection_root), &mut live).is_ok()
        && !differ(&live, &replay);
    Ok((replay, matches))
}

/// The tree's part of `shirudo status --json`: whether one is configured
/// and an operation pending, its state, and whether the eventlog replays
/// to the projection root the state recorded.
fn emit_status(e: &mut JsonEmit) {
    let mut s = TreeState::zeroed();
    let configured = configured();

    e.obj_open_key(b"upatch_tree");
    e.kv_bool(b"configured", configured);
    // SAFETY: a C string and a mode.
    e.kv_bool(
        b"pending",
        unsafe { access(tree_path(PENDING).as_ptr(), R_OK) } == 0,
    );
    // SAFETY: a C string, and room for a state.
    let state_rc = unsafe { state_read(tree_path(STATE).as_ptr(), &mut s) };
    if state_rc == 0 {
        e.kv_string(b"tree_id", cstr(&s.tree_id));
        e.kv_int(b"generation", s.generation);
        e.kv_int(b"last_seq", s.last_seq);
        e.kv_string(b"projection_root", cstr(&s.projection_root));
        e.kv_string(b"manifest_digest", cstr(&s.manifest_digest));
    } else {
        e.kv_null(b"state");
    }
    match eventlog_matches(&s, state_rc) {
        Ok((replay, matches)) => {
            e.kv_string(b"eventlog_projection_root", &hex::encode(&replay));
            e.kv_bool(b"eventlog_matches_state", matches);
        }
        Err(_) => {
            e.kv_null(b"eventlog_projection_root");
            e.kv_null(b"eventlog_matches_state");
        }
    }
    e.obj_close();
}

/// For the unit test and fuzz targets: the selector's kconfig values from
/// the config at `path`, as the selector match reads them.
///
/// # Safety
///
/// `path` is a C string, `s` a selector, and `values` and `found` room
/// for an entry for each of its kconfig pairs.
#[cfg(any(test, shirudo_fuzz))]
unsafe fn kconfig_read(
    path: *const c_char,
    s: *const TreeSelector,
    values: *mut [u8; STRING_MAX],
    found: *mut bool,
    gz: bool,
) -> c_int {
    // SAFETY: the caller's selector and its pairs.
    let kconfig = unsafe { pairs((*s).kconfig, (*s).n_kconfig, MAX_KCONFIG) };
    let mut slots = [-1i32; HASH_SIZE];

    hash_build(kconfig, &mut slots);
    // SAFETY: the caller's room for an entry for each pair.
    let mut kv = unsafe {
        KconfigValues {
            kconfig,
            slots: &slots,
            values: core::slice::from_raw_parts_mut(values, kconfig.len()),
            found: core::slice::from_raw_parts_mut(found, kconfig.len()),
        }
    };
    // SAFETY: the caller's C string.
    unsafe { read_selector_config_file(path, &mut kv, gz) }
}

pub(crate) use capi::{
    tree_configured, tree_emit_status, tree_event_append, tree_event_replay, tree_outcomes_read,
    tree_pending_read, tree_pending_write, tree_selector_matches, tree_state_read,
    tree_state_write,
};

/// Whether an operation is pending: pending.json exists.
pub(crate) fn tree_pending_exists() -> bool {
    use std::os::unix::ffi::OsStrExt;

    std::fs::metadata(std::ffi::OsStr::from_bytes(tree_path(PENDING).to_bytes())).is_ok()
}

/// The status file in which the tree says why it left upatch `name`
/// not loaded.
pub(crate) fn tree_status_path(name: &[u8]) -> CString {
    tree_path(&[&b"status/"[..], name].concat())
}

#[cfg(test)]
mod tests;

#[cfg(shirudo_fuzz)]
mod fuzz;

mod capi {
    use core::ffi::{c_char, c_int};

    use super::{TreeOperation, TreePending, TreeSelector, TreeState};
    use crate::util::json::JsonEmit;

    /// # Safety
    ///
    /// `codes` has room for `to` - `from` outcomes, and the roots for 32
    /// bytes each.
    pub unsafe extern "C" fn tree_outcomes_read(
        from: i64,
        to: i64,
        codes: *mut u8,
        projection_root: *mut [u8; 32],
        history_root: *mut [u8; 32],
    ) -> c_int {
        let (mut read, mut roots) = (Vec::new(), None);
        let ret = super::outcomes_read(from, to, &mut read, &mut roots);
        // SAFETY: the caller's rooms, which take what was read.
        unsafe {
            if let Some((projection, history)) = roots {
                *projection_root = projection;
                *history_root = history;
            }
            core::ptr::copy_nonoverlapping(read.as_ptr(), codes, read.len());
        }
        ret
    }

    pub extern "C" fn tree_configured() -> bool {
        super::configured()
    }

    /// # Safety
    ///
    /// `selector` is NULL or a selector whose pairs are as its counts
    /// say.
    pub unsafe extern "C" fn tree_selector_matches(selector: *const TreeSelector) -> c_int {
        // SAFETY: the caller passes a selector.
        unsafe { super::selector_matches(selector) }
    }

    /// # Safety
    ///
    /// `out` is room for a record.
    pub unsafe extern "C" fn tree_pending_read(out: *mut TreePending) -> c_int {
        // SAFETY: the caller passes room for a record.
        unsafe { super::pending_read(out) }
    }

    /// # Safety
    ///
    /// `op` is an operation.
    pub unsafe extern "C" fn tree_pending_write(op: *const TreeOperation) -> c_int {
        // SAFETY: the caller passes an operation.
        super::pending_write(unsafe { &*op })
    }

    /// # Safety
    ///
    /// `out` is room for a state.
    pub unsafe extern "C" fn tree_state_read(out: *mut TreeState) -> c_int {
        // SAFETY: a C string, and the caller's room.
        unsafe { super::state_read(super::tree_path(super::STATE).as_ptr(), out) }
    }

    /// # Safety
    ///
    /// `state` is a state.
    pub unsafe extern "C" fn tree_state_write(state: *const TreeState) -> c_int {
        // SAFETY: the caller passes a state.
        super::state_write(unsafe { &*state })
    }

    /// # Safety
    ///
    /// `operation_digest` is NULL or a C string, and `projection_root` 32
    /// bytes.
    pub unsafe extern "C" fn tree_event_append(
        seq: i64,
        operation_digest: *const c_char,
        projection_root: *const u8,
    ) -> c_int {
        // SAFETY: the caller passes a string and 32 bytes.
        unsafe { super::event_append(seq, operation_digest, projection_root) }
    }

    /// # Safety
    ///
    /// `out` is room for 32 bytes.
    pub unsafe extern "C" fn tree_event_replay(out: *mut u8) -> c_int {
        // SAFETY: a C string, and the caller's room.
        unsafe { super::event_replay(super::tree_path(super::EVENTLOG).as_ptr(), out) }
    }

    /// # Safety
    ///
    /// `e` is an emitter.
    pub unsafe extern "C" fn tree_emit_status(e: *mut JsonEmit) {
        // SAFETY: the caller passes an emitter.
        super::emit_status(unsafe { &mut *e })
    }
}
