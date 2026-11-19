// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The upatch tree's state on a target: whether
//! an operation's selector matches the node, the cursor and the pending
//! record a sync keeps, and the tree eventlog whose projection chain it
//! replays.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::io::{BufRead, BufReader};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileExt;

use crate::errno::{E2BIG, EBADMSG, EINTR, EINVAL, EIO, ENAMETOOLONG, ENOENT, ENOSPC, text};
use crate::sys::libc::{O_RDONLY, PATH_MAX, R_OK, Utsname, Zeroed, access, bytes, uname};
use crate::text::{cstr, find};
use crate::util::bpm_tree::{
    MAX_KCONFIG, MAX_LABELS, STRING_MAX, TreeOperation, TreePending, TreeSelector, TreeSelectorKv,
    TreeState, digest_bytes,
};
use crate::util::crypto_openssl::sha256_into;
use crate::util::hex;
use crate::util::image_config;
use crate::util::io::{lock_exclusive, read};
use crate::util::json::{JsonEmit, JsonField, MAX_BYTES, parse_schema};
use crate::util::kernel_build_id::read_build_id;
use crate::util::kernel_release::prefix_matches;
use crate::util::seal;
use crate::util::{gzip, upatch};

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
    v.values.iter().any(|value| value == want)
}

/// The errno of an I/O error.
fn io_errno(e: std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

/// Whether access(2) lets this process read `path`.
fn readable(path: &CStr) -> bool {
    // SAFETY: a C string and a mode.
    unsafe { access(path.as_ptr(), R_OK) == 0 }
}

/// uname(2) of the node, None where it fails.
fn node_names() -> Option<Utsname> {
    let mut u = Utsname::zeroed();

    // SAFETY: room for the node's names.
    (unsafe { uname(&mut u) } == 0).then_some(u)
}

/// Whether a tree is configured, in the config image when one is active.
pub(crate) fn configured() -> bool {
    if !image_config::active() {
        return readable(TREE_ETC_PATH);
    }
    image_config::open_fd(image_config::TREE_CONF, O_RDONLY).is_ok()
}

/// A `key = value` line of a node's labels.
struct Label {
    key: Vec<u8>,
    value: Vec<u8>,
}

/// The most bytes a line of a labels file holds, without its newline.
const LABEL_LINE_MAX: usize = 511;

/// The line read, without its newline: -EINVAL for one that holds a NUL,
/// -E2BIG for one longer than LABEL_LINE_MAX.
fn text_line(line: &[u8]) -> Result<&[u8], c_int> {
    let row = line.strip_suffix(b"\n").unwrap_or(line);

    if line.contains(&0) {
        return Err(-EINVAL);
    }
    if row.len() > LABEL_LINE_MAX {
        return Err(-E2BIG);
    }
    Ok(row)
}

/// A label added after `labels`, of at most `max`: -E2BIG for no room,
/// or -ENOSPC for a key or value too long.
fn label_add(labels: &mut Vec<Label>, max: usize, key: &[u8], value: &[u8]) -> Result<(), c_int> {
    if labels.len() >= max {
        return Err(-E2BIG);
    }
    if key.len() >= STRING_MAX || value.len() >= STRING_MAX {
        return Err(-ENOSPC);
    }
    labels.push(Label {
        key: key.to_vec(),
        value: value.to_vec(),
    });
    Ok(())
}

/// The value of the first of the labels with `key`.
fn label_value<'a>(labels: &'a [Label], key: &[u8]) -> Option<&'a [u8]> {
    labels.iter().find(|l| l.key == key).map(|l| &l.value[..])
}

/// The `key = value` lines of `config`, at most `max`; a blank line, a
/// comment and a line without a `=` say nothing.
fn read_config(mut config: impl BufRead, max: usize) -> Result<Vec<Label>, c_int> {
    let mut labels = Vec::new();
    let mut line = Vec::new();

    loop {
        line.clear();
        if config.read_until(b'\n', &mut line).map_err(io_errno)? == 0 {
            return Ok(labels);
        }
        let text = trim_start(text_line(&line)?);

        if text.is_empty() || text[0] == b'#' {
            continue;
        }
        let text = trim_end(text);
        let Some(eq) = text.iter().position(|&c| c == b'=') else {
            continue;
        };
        // The key keeps what is before the '='; the value loses the
        // spaces it starts with.
        label_add(&mut labels, max, &text[..eq], trim_start(&text[eq + 1..]))?;
    }
}

/// read_config() of the file at `path`.
fn read_config_file(path: &CStr, max: usize) -> Result<Vec<Label>, c_int> {
    let file = std::fs::File::open(OsStr::from_bytes(path.to_bytes())).map_err(io_errno)?;

    read_config(BufReader::new(file), max)
}

/// The node's labels, from the config image when one is active.
fn node_labels() -> Result<Vec<Label>, c_int> {
    if !image_config::active() {
        return read_config_file(NODE_LABELS_PATH, MAX_LABELS);
    }
    let fd = image_config::open_fd(image_config::NODE_LABELS, O_RDONLY)?;

    read_config(BufReader::new(std::fs::File::from(fd)), MAX_LABELS)
}

/// FNV-1a of a selector key.
fn selector_hash(key: &[u8]) -> u32 {
    key.iter().fold(2_166_136_261u32, |hash, &c| {
        (hash ^ u32::from(c)).wrapping_mul(16_777_619)
    })
}

/// The slot of the index where the probe for `key` starts.
fn first_slot(key: &[u8]) -> usize {
    selector_hash(key) as usize & (HASH_SIZE - 1)
}

/// The selector's kconfig keys, under an open-addressed index whose slots
/// each hold the first pair of a key, and the values a config gives them
/// as it is read.
struct KconfigValues<'a> {
    kconfig: &'a [TreeSelectorKv],
    slots: [Option<usize>; HASH_SIZE],
    values: Vec<Option<Vec<u8>>>,
}

impl<'a> KconfigValues<'a> {
    /// The index of `kconfig`, of at most MAX_KCONFIG pairs, which leaves
    /// a free slot to end each probe.
    fn new(kconfig: &'a [TreeSelectorKv]) -> Self {
        let mut slots: [Option<usize>; HASH_SIZE] = [None; HASH_SIZE];

        for (i, kv) in kconfig.iter().enumerate() {
            let mut slot = first_slot(&kv.key);

            while let Some(j) = slots[slot] {
                if kconfig[j].key == kv.key {
                    break;
                }
                slot = (slot + 1) & (HASH_SIZE - 1);
            }
            if slots[slot].is_none() {
                slots[slot] = Some(i);
            }
        }
        KconfigValues {
            kconfig,
            slots,
            values: vec![None; kconfig.len()],
        }
    }

    /// The pair of the index holding `key`.
    fn find(&self, key: &[u8]) -> Option<usize> {
        let mut slot = first_slot(key);

        for _ in 0..HASH_SIZE {
            let i = self.slots[slot]?;

            if self.kconfig[i].key == key {
                return Some(i);
            }
            slot = (slot + 1) & (HASH_SIZE - 1);
        }
        None
    }

    /// The value the config read gave the pair at `i`.
    fn value(&self, i: usize) -> Option<&[u8]> {
        self.values.get(i)?.as_deref()
    }
}

/// One line of a kernel config: the value of a key the selector names
/// kept, `# CONFIG_X is not set` reading as `n`. -ENOSPC for a value too
/// long for any selector to name.
fn config_line(line: &[u8], kv: &mut KconfigValues<'_>) -> Result<(), c_int> {
    let start = trim_start(cstr(line));

    if start.is_empty() {
        return Ok(());
    }
    let (key, value): (&[u8], &[u8]) = if start.starts_with(b"# CONFIG_") {
        let start = &start[2..];
        let Some(at) = find(start, b" is not set") else {
            return Ok(());
        };

        (&start[..at], b"n")
    } else {
        if start[0] == b'#' {
            return Ok(());
        }
        let Some(eq) = start.iter().position(|&c| c == b'=') else {
            return Ok(());
        };
        let mut value = trim_end(trim_start(&start[eq + 1..]));

        if value.len() > 1 && value[0] == b'"' && value[value.len() - 1] == b'"' {
            value = &value[1..value.len() - 1];
        }
        (trim_end(&start[..eq]), value)
    };
    let Some(index) = kv.find(key) else {
        return Ok(());
    };
    if value.len() >= STRING_MAX {
        return Err(-ENOSPC);
    }
    kv.values[index] = Some(value.to_vec());
    Ok(())
}

/// The lines of a kernel config into the selector's values. A line of
/// LINE_MAX bytes or more with its newline is skipped whole, as a part
/// from the middle of a long string value would read as an option of its
/// own: its option reads as not set.
fn config_text(text: &[u8], kv: &mut KconfigValues<'_>) -> Result<(), c_int> {
    let mut off = 0usize;

    while off < text.len() {
        let rest = &text[off..];
        let n = rest.iter().position(|&c| c == b'\n').unwrap_or(rest.len());

        if n < LINE_MAX - 1 {
            config_line(&rest[..n], kv)?;
        }
        off += n + 1;
    }
    Ok(())
}

/// The kernel config at `path`, gzip'd or not, into the selector's
/// values.
fn read_selector_config_file(
    path: &CStr,
    kv: &mut KconfigValues<'_>,
    gz: bool,
) -> Result<(), c_int> {
    let raw = read(path, KCONFIG_MAX)?;

    if !gz {
        return config_text(&raw, kv);
    }
    // The one gzip member of the file, with nothing behind it; not
    // through a gzip file's reads: zlib 1.3.2 reads on past the end of a
    // member into a next one, finds that cut short, and has gzclose()
    // fail the whole file.
    let text = gzip::gunzip_one(&raw, KCONFIG_MAX).map_err(|err| -err)?;
    config_text(&text, kv)
}

/// Whether the selector's kconfig pairs, at most MAX_KCONFIG, match the
/// running kernel's config: /proc/config.gz, or /boot/config-<release>
/// when that cannot be read or names none of them.
fn kconfig_matches(kconfig: &[TreeSelectorKv], release: &[u8]) -> Result<bool, c_int> {
    let mut kv = KconfigValues::new(kconfig);
    let config_rc = read_selector_config_file(c"/proc/config.gz", &mut kv, true);

    if config_rc.is_err() || kv.values.iter().all(Option::is_none) {
        let path = [&b"/boot/config-"[..], release].concat();

        kv.values.fill(None);
        if path.len() >= PATH_MAX {
            return Err(-ENAMETOOLONG);
        }
        let path = CString::new(path).map_err(|_| -EINVAL)?;
        match read_selector_config_file(&path, &mut kv, false) {
            // No config to show, or a value longer than any selector
            // names, matches nothing; a config that cannot be read is no
            // answer, and the sync must not move past the operation on
            // it.
            Err(err) if err == -ENOENT || err == -ENOSPC => {
                return match config_rc {
                    Err(rc) if rc != -ENOENT && rc != -ENOSPC => Err(rc),
                    _ => Ok(false),
                };
            }
            Err(err) => return Err(err),
            Ok(()) => {}
        }
    }
    // The config is read into the first pair of a key, so a key named
    // twice is matched there: left unfound, the operation was skipped
    // and the tree moved past it for good.
    Ok(kconfig.iter().all(|pair| {
        kv.find(&pair.key)
            .and_then(|k| kv.value(k))
            .is_some_and(|v| values_match(pair, v))
    }))
}

/// Whether the selector's label pairs match the node's labels, from the
/// config image when one is active.
fn labels_match(labels_wanted: &[TreeSelectorKv]) -> Result<bool, c_int> {
    let labels = match node_labels() {
        Err(err) if err == -ENOENT => return Ok(false),
        labels => labels?,
    };

    Ok(labels_wanted
        .iter()
        .all(|wanted| label_value(&labels, &wanted.key).is_some_and(|v| values_match(wanted, v))))
}

/// The first `max` of `v`.
fn at_most<T>(v: &[T], max: usize) -> &[T] {
    &v[..v.len().min(max)]
}

/// Whether the selector matches the running node, or -errno when its
/// labels or kernel config cannot be read. An empty selector is the
/// tree's explicit wildcard, and matches before the node is asked, so an
/// unconstrained operation applies even without uname(2).
pub(crate) fn selector_matches(s: &TreeSelector) -> Result<bool, c_int> {
    if s.is_empty() {
        return Ok(true);
    }
    let Some(u) = node_names() else {
        return Ok(false);
    };
    let release = cstr(bytes(&u.release));

    if !s.kernel_release_prefix.is_empty()
        && !s
            .kernel_release_prefix
            .iter()
            .any(|prefix| prefix_matches(release, prefix))
    {
        return Ok(false);
    }
    if !s.kernel_build_id.is_empty() {
        let mut build_id = [0u8; BUILD_ID_STRING_MAX];

        // A selector naming a build ID is fail-closed on a kernel that
        // publishes none.
        // SAFETY: room for the hex digits of a build ID.
        if unsafe { read_build_id(build_id.as_mut_ptr().cast()) } != 0 {
            return Ok(false);
        }
        if !s.kernel_build_id.iter().any(|id| id == cstr(&build_id)) {
            return Ok(false);
        }
    }
    if !s.architecture.is_empty()
        && !s
            .architecture
            .iter()
            .any(|arch| arch == cstr(bytes(&u.machine)))
    {
        return Ok(false);
    }
    if !s.kconfig.is_empty() && !kconfig_matches(at_most(&s.kconfig, MAX_KCONFIG), release)? {
        return Ok(false);
    }
    if !s.labels.is_empty() && !labels_match(at_most(&s.labels, MAX_LABELS))? {
        return Ok(false);
    }
    Ok(true)
}

/// A record as its document holds it: the document's schema version
/// apart.
struct Versioned<T> {
    schema: i64,
    record: T,
}

/// Whether `hex` is exactly 64 hex digits: a SHA-256 digest.
fn hex32_valid(hex: &[u8; 65]) -> bool {
    hex::decode(cstr(hex), &mut [0; 32]).is_ok()
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

/// The pending record `body` holds: -EINVAL for one that lacks its
/// schema, sequence number, upatch name or digest.
fn pending_parse(body: &[u8]) -> Result<TreePending, c_int> {
    let mut pending = Versioned {
        schema: 0,
        record: TreePending::default(),
    };
    let fields = [
        JsonField::int(c"schema", |p: &mut Versioned<TreePending>| &mut p.schema),
        JsonField::int(c"seq", |p| &mut p.record.seq),
        JsonField::string(c"id", |p| &mut p.record.id),
        JsonField::string(c"operation_digest", |p| &mut p.record.operation_digest),
    ];

    parse_schema(body, &fields, &mut pending)?;
    let Versioned { schema, record } = pending;
    if schema != 1
        || record.seq <= 0
        || !upatch::name_valid(Some(cstr(&record.id)))
        || digest_bytes(&record.operation_digest).is_none()
    {
        return Err(-EINVAL);
    }
    Ok(record)
}

/// The pending record, -ENOENT for none.
pub(crate) fn pending_read() -> Result<TreePending, c_int> {
    pending_parse(&read(&tree_path(PENDING), 64 * 1024)?)
}

/// The operation a sync starts recorded as pending.
pub(crate) fn pending_write(op: &TreeOperation) -> Result<(), c_int> {
    let mut buf = [0u8; 1024];
    let mut e = JsonEmit::fixed(&mut buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_int(b"seq", op.seq);
    e.kv_string(b"id", cstr(&op.id));
    e.kv_string(b"operation_digest", cstr(&op.operation_digest));
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    seal::mkdir_p(tree_path(b"").to_bytes(), 0o700)?;
    seal::write_file(tree_path(PENDING).to_bytes(), e.output(), 0o600)
}

/// The tree state at `path`.
fn state_read_at(path: &CStr) -> Result<TreeState, c_int> {
    let body = read(path, MAX_BYTES)?;
    let mut state = Versioned {
        schema: 0,
        record: TreeState::default(),
    };
    let f = [
        JsonField::int(c"schema", |s: &mut Versioned<TreeState>| &mut s.schema),
        JsonField::string(c"tree_id", |s| &mut s.record.tree_id),
        JsonField::int(c"generation", |s| &mut s.record.generation),
        JsonField::int(c"last_seq", |s| &mut s.record.last_seq),
        JsonField::string(c"projection_root", |s| &mut s.record.projection_root),
        JsonField::string(c"projection_root_tpm", |s| {
            &mut s.record.projection_root_tpm
        }),
        JsonField::string(c"manifest_digest", |s| &mut s.record.manifest_digest),
        JsonField::int(c"head_seq", |s| &mut s.record.head_seq),
        JsonField::int(c"segment_base_seq", |s| &mut s.record.segment_base_seq),
    ];
    // tree_id, last_seq, both projection roots, head and segment base.
    let required = [1, 3, 4, 5, 7, 8];

    parse_schema(&body, &f, &mut state)?;
    let Versioned { schema, mut record } = state;
    if schema != 1 || !required.iter().all(|&i| f[i].seen()) {
        return Err(-EINVAL);
    }
    if !hex32_valid(&record.projection_root) || !hex32_valid(&record.projection_root_tpm) {
        return Err(-EINVAL);
    }
    if record.manifest_digest[0] != 0 && digest_bytes(&record.manifest_digest).is_none() {
        return Err(-EINVAL);
    }
    record.schema = schema;
    Ok(record)
}

/// The node's tree state, -ENOENT for none.
pub(crate) fn state_read() -> Result<TreeState, c_int> {
    state_read_at(&tree_path(STATE))
}

/// The tree state written whole in place of what was there.
pub(crate) fn state_write(s: &TreeState) -> Result<(), c_int> {
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
        return Err(e.err());
    }
    let dir = tree_path(b"");

    if let Err(ret) = seal::mkdir_p(dir.to_bytes(), 0o700) {
        crate::log::err(
            &[
                &b"tree state mkdir "[..],
                dir.to_bytes(),
                b": ",
                text(ret).as_bytes(),
            ]
            .concat(),
        );
        return Err(ret);
    }
    seal::write_file(tree_path(STATE).to_bytes(), e.output(), 0o600)
}

/// An operation applied, appended to the tree eventlog with its digest,
/// "sha256:" and 64 hex digits, and the projection root it leads to.
pub(crate) fn event_append(
    seq: i64,
    operation_digest: &[u8],
    projection_root: &[u8; 32],
) -> Result<(), c_int> {
    let operation_digest = cstr(operation_digest);
    let mut buf = [0u8; 1024];

    if digest_bytes(operation_digest).is_none() {
        return Err(-EINVAL);
    }
    let mut e = JsonEmit::fixed(&mut buf);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.kv_int(b"seq", seq);
    e.kv_string(b"digest", operation_digest);
    e.kv_string(b"projection_root", &hex::encode(projection_root));
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    seal::mkdir_p(tree_path(b"").to_bytes(), 0o700)?;
    seal::append(&tree_path(EVENTLOG), e.output())
}

/// What a line of the eventlog gives.
struct EventLine {
    seq: i64,
    digest: [u8; 128],
    projection: [u8; 65],
}

/// What the eventlog at `path`, its whole lines in order, chains to:
/// each SHA-256 of the chain so far and the record's operation digest,
/// which must be the projection root it recorded.
fn event_replay_at(path: &CStr) -> Result<[u8; 32], c_int> {
    let text = read(path, MAX_BYTES)?;
    let mut chain = [0u8; 32];
    let mut previous_seq = 0i64;

    // A NUL would end the walk early and replay a shorter chain.
    if text.contains(&0) {
        return Err(-EINVAL);
    }
    // Whole lines only: a record cut short at the end is not one yet.
    let whole = text.iter().rposition(|&c| c == b'\n').map_or(0, |i| i + 1);

    for line in text[..whole]
        .split(|&c| c == b'\n')
        .filter(|l| !l.is_empty())
    {
        let mut record = EventLine {
            seq: 0,
            digest: [0; 128],
            projection: [0; 65],
        };
        let f = [
            JsonField::int(c"seq", |r: &mut EventLine| &mut r.seq),
            JsonField::string(c"digest", |r| &mut r.digest),
            JsonField::string(c"projection_root", |r| &mut r.projection),
        ];
        let mut recorded = [0u8; 32];
        let parsed = parse_schema(line, &f, &mut record);
        let EventLine {
            seq,
            digest,
            projection,
        } = record;

        if parsed.is_err()
            || !f[0].seen()
            || !f[1].seen()
            || !f[2].seen()
            || seq <= previous_seq
            || cstr(&projection).len() != 64
            || hex::decode(cstr(&projection), &mut recorded).is_err()
        {
            return Err(-EINVAL);
        }
        previous_seq = seq;
        let d = digest_bytes(&digest).ok_or(-EINVAL)?;
        let mut next = [0u8; 64];

        next[..32].copy_from_slice(&chain);
        next[32..].copy_from_slice(&d);
        match sha256_into(&next, &mut chain) {
            0 => {}
            err => return Err(err),
        }
        if differ(&chain, &recorded) {
            return Err(-EINVAL);
        }
    }
    Ok(chain)
}

/// What the node's tree eventlog chains to.
pub(crate) fn event_replay() -> Result<[u8; 32], c_int> {
    event_replay_at(&tree_path(EVENTLOG))
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

/// What a line of the record gives, its roots in hex.
struct OutcomeJson {
    schema: i64,
    line: OutcomeLine,
    projection: [u8; 65],
    history: [u8; 65],
}

fn outcome_parse(text: &[u8]) -> Result<OutcomeLine, c_int> {
    let mut json = OutcomeJson {
        schema: 0,
        line: OutcomeLine::default(),
        projection: [0; 65],
        history: [0; 65],
    };
    let f = [
        JsonField::int(c"schema", |j: &mut OutcomeJson| &mut j.schema),
        JsonField::int(c"seq", |j| &mut j.line.seq),
        JsonField::int(c"outcome", |j| &mut j.line.outcome),
        JsonField::string(c"projection_root", |j| &mut j.projection),
        JsonField::string(c"history_root", |j| &mut j.history),
    ];
    let parsed = parse_schema(text, &f, &mut json);
    let OutcomeJson {
        schema,
        mut line,
        projection,
        history,
    } = json;

    if parsed.is_err()
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
    /// The record open at `fd`.
    fn new(fd: OwnedFd) -> Self {
        Outcomes {
            file: std::fs::File::from(fd),
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
    seal::mkdir_p(tree_path(b"").to_bytes(), 0o700)
        .and_then(|()| seal::append(&tree_path(OUTCOMES), &buf[..len]))
        .err()
        .unwrap_or(0)
}

/// The projection and history roots after an operation.
pub(crate) type Roots = ([u8; 32], [u8; 32]);

/// What the record holds of the operations of seq `from` + 1 through
/// `to`: their outcomes and the roots at `from`. -ENOENT without a
/// record unless it asks for no line, -EBADMSG for one that ends early
/// or is out of order.
pub(crate) fn outcomes_read(from: i64, to: i64) -> Result<(Vec<u8>, Roots), c_int> {
    if from < 0 || to < from {
        return Err(-EINVAL);
    }
    let fd = match seal::open_read(tree_path(OUTCOMES).to_bytes()) {
        Ok(fd) => fd,
        Err(err) if err == -ENOENT && to == 0 => return Ok((Vec::new(), ([0; 32], [0; 32]))),
        Err(err) => return Err(err),
    };
    let mut o = Outcomes::new(fd);
    let read = (|| {
        let mut codes = Vec::new();

        o.seek(from)?;
        let roots = (o.line.projection_root, o.line.history_root);
        while o.line.seq < to {
            o.next()?;
            codes.push(u8::try_from(o.line.outcome).map_err(|_| -EBADMSG)?);
        }
        Ok((codes, roots))
    })();
    let _ = o.close();
    read
}

/// The projection and history roots the record holds at `seq`.
pub(crate) fn outcome_roots(seq: i64) -> Result<Roots, c_int> {
    outcomes_read(seq, seq).map(|(_, roots)| roots)
}

/// The history root at `last_seq`, the lines past it dropped, which a
/// sync that stopped left: under the bpm lock and the record's own.
pub(crate) fn outcomes_resume(last_seq: i64) -> Result<[u8; 32], c_int> {
    if last_seq < 0 {
        return Err(-EINVAL);
    }
    let fd = match seal::open(tree_path(OUTCOMES).to_bytes(), crate::sys::libc::O_RDWR, 0) {
        Err(err) if err == -ENOENT && last_seq == 0 => return Ok([0; 32]),
        fd => fd?,
    };
    let mut o = Outcomes::new(fd);
    let resumed = match lock_exclusive(o.file.as_raw_fd()) {
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
/// `state`: no state, one that could not be read, matches no replay.
pub(crate) fn eventlog_matches(state: Option<&TreeState>) -> Result<([u8; 32], bool), c_int> {
    eventlog_matches_at(&tree_path(EVENTLOG), state)
}

/// [`eventlog_matches`] of the eventlog at `path`.
fn eventlog_matches_at(path: &CStr, state: Option<&TreeState>) -> Result<([u8; 32], bool), c_int> {
    let replay = event_replay_at(path)?;
    let mut live = [0u8; 32];
    let matches = state.is_some_and(|s| {
        hex::decode(cstr(&s.projection_root), &mut live).is_ok() && !differ(&live, &replay)
    });

    Ok((replay, matches))
}

/// The tree's part of `shirudo status --json`: whether one is configured
/// and an operation pending, its state, and whether the eventlog replays
/// to the projection root the state recorded.
pub(crate) fn emit_status(e: &mut JsonEmit) {
    let configured = configured();

    e.obj_open_key(b"upatch_tree");
    e.kv_bool(b"configured", configured);
    e.kv_bool(b"pending", readable(&tree_path(PENDING)));
    let state = state_read().ok();
    match &state {
        Some(s) => {
            e.kv_string(b"tree_id", cstr(&s.tree_id));
            e.kv_int(b"generation", s.generation);
            e.kv_int(b"last_seq", s.last_seq);
            e.kv_string(b"projection_root", cstr(&s.projection_root));
            e.kv_string(b"manifest_digest", cstr(&s.manifest_digest));
        }
        None => e.kv_null(b"state"),
    }
    match eventlog_matches(state.as_ref()) {
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

/// For the unit test and fuzz targets: the values a config at `path`
/// gives the selector's kconfig pairs, as the selector match reads them.
#[cfg(any(test, shirudo_fuzz))]
fn kconfig_read(path: &CStr, s: &TreeSelector, gz: bool) -> Result<Vec<Option<Vec<u8>>>, c_int> {
    let mut kv = KconfigValues::new(at_most(&s.kconfig, MAX_KCONFIG));

    read_selector_config_file(path, &mut kv, gz)?;
    Ok(kv.values)
}

/// Whether an operation is pending: pending.json exists.
pub(crate) fn tree_pending_exists() -> bool {
    std::fs::metadata(OsStr::from_bytes(tree_path(PENDING).to_bytes())).is_ok()
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
