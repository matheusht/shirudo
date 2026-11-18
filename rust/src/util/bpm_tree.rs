// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The signed upatch tree's publications, behind `util/bpm_tree.h`: the
//! operations a publication carries, the canonical form and operation
//! digests that publisher and target share, and what a sync checks
//! before it applies anything.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::{mem, ptr};

use crate::errno::{E2BIG, EINVAL, EIO, EKEYREJECTED, ENOMEM, EOPNOTSUPP, ERANGE};
use crate::ffi;
use crate::heap::{xcalloc, xfree, xmalloc, xreallocarray};
use crate::text::{cstr, strscpy};
use crate::util::crypto_openssl::sha256_into;
use crate::util::json::{JsonArray, JsonEmit, JsonField, JsonMap, MAX_BYTES, parse_schema};
use crate::util::upatch;

/// `TREE_MAX_OPS`: the most operations a publication holds.
pub(crate) const MAX_OPS: usize = 512;
/// `TREE_MAX_KCONFIG` and `TREE_MAX_LABELS`: the most kernel config and
/// label pairs a selector names, and the most labels a node has.
pub(crate) const MAX_KCONFIG: usize = 64;
pub(crate) const MAX_LABELS: usize = 64;
/// `TREE_MAX_SELECTOR_VALUES`: the most values one selector key takes.
pub(crate) const MAX_VALUES: usize = 16;
/// `TREE_STRING_MAX`.
pub(crate) const STRING_MAX: usize = 256;

/// A string of the tree, as C holds it: NUL-terminated in a fixed array.
pub(crate) type Text = [u8; STRING_MAX];

/// The canonical operation an operation digest hashes takes at most this.
const DIGEST_BODY_MAX: usize = 1024 * 1024;

/// `struct tree_kv`.
#[repr(C)]
pub struct TreeKv {
    pub(crate) key: Text,
    pub(crate) value: Text,
}

/// `struct tree_selector_kv`.
#[repr(C)]
pub struct TreeSelectorKv {
    pub(crate) key: Text,
    pub(crate) values: [Text; MAX_VALUES],
    pub(crate) n_values: c_int,
}

/// `struct tree_selector`, whose pairs come from the xmalloc family.
#[repr(C)]
pub struct TreeSelector {
    pub(crate) kernel_release_prefix: [Text; MAX_VALUES],
    pub(crate) n_kernel_release_prefix: c_int,
    pub(crate) kernel_build_id: [Text; MAX_VALUES],
    pub(crate) n_kernel_build_id: c_int,
    pub(crate) architecture: [Text; MAX_VALUES],
    pub(crate) n_architecture: c_int,
    pub(crate) kconfig: *mut TreeSelectorKv,
    pub(crate) n_kconfig: c_int,
    pub(crate) labels: *mut TreeSelectorKv,
    pub(crate) n_labels: c_int,
}

/// `struct tree_artifact`.
#[repr(C)]
pub struct TreeArtifact {
    pub(crate) repository: [u8; 512],
    pub(crate) manifest_digest: [u8; 128],
    pub(crate) layer_digest: [u8; 128],
    pub(crate) payload_sha256: [u8; 128],
}

/// `struct tree_operation`.
#[repr(C)]
pub struct TreeOperation {
    pub(crate) seq: i64,
    pub(crate) op: [u8; 16],
    pub(crate) id: Text,
    pub(crate) selector: TreeSelector,
    pub(crate) artifact: TreeArtifact,
    pub(crate) operation_digest: [u8; 128],
}

/// `struct tree_publication`, whose operations come from the xmalloc
/// family.
#[repr(C)]
pub struct TreePublication {
    pub(crate) schema: c_int,
    pub(crate) tree_id: Text,
    _pad: [u8; 4],
    pub(crate) generation: i64,
    pub(crate) parent_manifest_digest: [u8; 128],
    pub(crate) base_seq: i64,
    pub(crate) operations: *mut TreeOperation,
    pub(crate) operations_capacity: c_int,
    pub(crate) n_operations: c_int,
    pub(crate) head_seq: i64,
}

/// `struct tree_pending`.
#[repr(C)]
pub struct TreePending {
    pub(crate) seq: i64,
    pub(crate) id: Text,
    pub(crate) operation_digest: [u8; 128],
}

/// `struct tree_state`.
#[repr(C)]
pub struct TreeState {
    pub(crate) schema: c_int,
    pub(crate) tree_id: Text,
    pub(crate) generation: i64,
    pub(crate) last_seq: i64,
    pub(crate) projection_root: [u8; 65],
    pub(crate) projection_root_tpm: [u8; 65],
    pub(crate) manifest_digest: [u8; 128],
}

const _: () = assert!(size_of::<TreeKv>() == 512);
const _: () = assert!(size_of::<TreeSelectorKv>() == 4356);
const _: () = assert!(size_of::<TreeSelector>() == 12336);
const _: () = assert!(size_of::<TreeOperation>() == 13640);
const _: () = assert!(size_of::<TreePublication>() == 432);
const _: () = assert!(size_of::<TreePending>() == 392);
const _: () = assert!(size_of::<TreeState>() == 544);

/// How many of the `cap` entries of a selector array its count `n`
/// stands for: none below one, and no more than the array holds.
pub(crate) fn count(n: c_int, cap: usize) -> usize {
    usize::try_from(n).map_or(0, |n| n.min(cap))
}

/// The pairs a selector holds at `kvs`, as many as its count `n` says up
/// to `cap`.
///
/// # Safety
///
/// `kvs` is NULL or points to the pairs of a live selector, at least as
/// many as `n` and `cap` allow.
pub(crate) unsafe fn pairs<'a>(
    kvs: *const TreeSelectorKv,
    n: c_int,
    cap: usize,
) -> &'a [TreeSelectorKv] {
    if kvs.is_null() {
        return &[];
    }
    // SAFETY: the caller's pairs.
    unsafe { ffi::slice(kvs, count(n, cap)) }
}

/// The values a list holds, as many as its count says.
fn listed(values: &[Text], n: c_int) -> impl Iterator<Item = &[u8]> {
    values[..count(n, values.len())].iter().map(|v| cstr(v))
}

impl TreeSelector {
    /// The three lists in the canonical form's order, with their keys.
    fn lists(&self) -> [(&'static [u8], &[Text], c_int); 3] {
        [
            (b"architecture", &self.architecture, self.n_architecture),
            (
                b"kernel_build_id",
                &self.kernel_build_id,
                self.n_kernel_build_id,
            ),
            (
                b"kernel_release_prefix",
                &self.kernel_release_prefix,
                self.n_kernel_release_prefix,
            ),
        ]
    }

    /// # Safety
    ///
    /// The selector's pairs are as its counts say.
    unsafe fn kconfig(&self) -> &[TreeSelectorKv] {
        // SAFETY: the caller's selector.
        unsafe { pairs(self.kconfig, self.n_kconfig, usize::MAX) }
    }

    /// # Safety
    ///
    /// The selector's pairs are as its counts say.
    unsafe fn labels(&self) -> &[TreeSelectorKv] {
        // SAFETY: the caller's selector.
        unsafe { pairs(self.labels, self.n_labels, usize::MAX) }
    }
}

impl TreePublication {
    /// # Safety
    ///
    /// The publication holds the operations its count says.
    pub(crate) unsafe fn operations(&self) -> &[TreeOperation] {
        if self.operations.is_null() {
            return &[];
        }
        // SAFETY: the caller's publication.
        unsafe { ffi::slice(self.operations, count(self.n_operations, usize::MAX)) }
    }
}

/// A new zeroed pair after the `n` at `kvs`, of at most `max`: the pair,
/// or -E2BIG or -ENOMEM.
///
/// # Safety
///
/// `kvs` and `n` are a selector's pairs from the xmalloc family.
unsafe fn kv_add(
    kvs: *mut *mut TreeSelectorKv,
    n: *mut c_int,
    max: c_int,
) -> Result<*mut TreeSelectorKv, c_int> {
    // SAFETY: the caller's pairs.
    let (old, held) = unsafe { (*kvs, *n) };

    if held >= max {
        return Err(-E2BIG);
    }
    let held = usize::try_from(held).map_err(|_| -ENOMEM)?;
    // SAFETY: xreallocarray() hands back the held pairs and a zeroed one
    // after them in a new block, scrubbing and freeing the old one.
    let grown: *mut TreeSelectorKv =
        unsafe { xreallocarray(old.cast(), held, held + 1, size_of::<TreeSelectorKv>()) }.cast();
    if grown.is_null() {
        return Err(-ENOMEM);
    }
    // SAFETY: the caller's pairs, now one more, the last of them zeroed.
    unsafe {
        *kvs = grown;
        *n += 1;
        Ok(grown.add(held))
    }
}

/// A copy of the `n` pairs at `src`, or NULL for none.
///
/// # Safety
///
/// `src` holds `n` pairs.
unsafe fn pairs_dup(src: *const TreeSelectorKv, n: c_int) -> Result<*mut TreeSelectorKv, c_int> {
    if n == 0 {
        return Ok(ptr::null_mut());
    }
    let n = usize::try_from(n).map_err(|_| -ENOMEM)?;
    // SAFETY: xcalloc() takes any count.
    let dst: *mut TreeSelectorKv = unsafe { xcalloc(n, size_of::<TreeSelectorKv>()) }.cast();
    if dst.is_null() {
        return Err(-ENOMEM);
    }
    // SAFETY: n pairs at src and room for them at dst.
    unsafe { ptr::copy_nonoverlapping(src, dst, n) };
    Ok(dst)
}

/// Releases a selector's pairs, leaving it with none.
fn selector_free(s: &mut TreeSelector) {
    // SAFETY: a selector's pairs come from the xmalloc family, as many as
    // its counts say.
    unsafe {
        xfree(
            s.kconfig.cast(),
            count(s.n_kconfig, usize::MAX) * size_of::<TreeSelectorKv>(),
        );
        xfree(
            s.labels.cast(),
            count(s.n_labels, usize::MAX) * size_of::<TreeSelectorKv>(),
        );
    }
    s.kconfig = ptr::null_mut();
    s.labels = ptr::null_mut();
    s.n_kconfig = 0;
    s.n_labels = 0;
}

/// Fills `dst` with `src` and copies of its pairs; a copy that fails
/// holds none, and `src` keeps its own.
///
/// # Safety
///
/// `src` is a selector whose pairs are as its counts say, and `dst` room
/// for one, which may be `src` itself.
unsafe fn selector_copy(dst: *mut TreeSelector, src: *const TreeSelector) -> c_int {
    // SAFETY: the caller's selectors; src is read whole before dst is
    // written, and dst gets no pair of src's before its own copies.
    unsafe {
        let (kconfig, n_kconfig) = ((*src).kconfig, (*src).n_kconfig);
        let (labels, n_labels) = ((*src).labels, (*src).n_labels);

        ptr::copy(src, dst, 1);
        (*dst).kconfig = ptr::null_mut();
        (*dst).labels = ptr::null_mut();
        let copied = pairs_dup(kconfig, n_kconfig).and_then(|kvs| {
            (*dst).kconfig = kvs;
            pairs_dup(labels, n_labels).map(|kvs| (*dst).labels = kvs)
        });
        if copied.is_err() {
            selector_free(&mut *dst);
            return -ENOMEM;
        }
    }
    0
}

fn publication_free(p: &mut TreePublication) {
    let held = count(p.operations_capacity, usize::MAX);

    if !p.operations.is_null() {
        // A slot past n_operations may hold an operation that failed to
        // parse.
        for i in 0..held {
            // SAFETY: the publication's slots, up to its capacity.
            selector_free(unsafe { &mut (*p.operations.add(i)).selector });
        }
    }
    // SAFETY: the operations come from the xmalloc family, as many as
    // the capacity says.
    unsafe { xfree(p.operations.cast(), held * size_of::<TreeOperation>()) };
    // SAFETY: an all-zero publication holds nothing.
    *p = unsafe { mem::zeroed() };
}

/// Room for one more operation: the slots double from 16 up to MAX_OPS.
fn operations_reserve(p: &mut TreePublication) -> Result<(), c_int> {
    let old = p.operations_capacity;

    if p.n_operations >= MAX_OPS as c_int {
        return Err(-E2BIG);
    }
    if p.n_operations < old {
        return Ok(());
    }
    let new = if old != 0 { old.saturating_mul(2) } else { 16 }.min(MAX_OPS as c_int);
    let (Ok(old_n), Ok(new_n)) = (usize::try_from(old), usize::try_from(new)) else {
        return Err(-ENOMEM);
    };
    // SAFETY: the publication's slots from the xmalloc family, grown into
    // a new zeroed block.
    let grown = unsafe {
        xreallocarray(
            p.operations.cast(),
            old_n,
            new_n,
            size_of::<TreeOperation>(),
        )
    };
    if grown.is_null() {
        return Err(-ENOMEM);
    }
    p.operations = grown.cast();
    p.operations_capacity = new;
    Ok(())
}

/// Appends a copy of `op`, its pairs included.
///
/// # Safety
///
/// `op` is an operation whose selector's pairs are as its counts say.
unsafe fn publication_append(p: &mut TreePublication, op: *const TreeOperation) -> c_int {
    if let Err(err) = operations_reserve(p) {
        return err;
    }
    let slot = count(p.n_operations, usize::MAX);
    // SAFETY: room for the slot past the operations, and the caller's
    // operation; the selector copy owns its pairs or is zeroed whole.
    unsafe {
        let dst = p.operations.add(slot);

        ptr::copy_nonoverlapping(op, dst, 1);
        let ret = selector_copy(&raw mut (*dst).selector, &raw const (*op).selector);
        if ret != 0 {
            ptr::write_bytes(dst, 0, 1);
            return ret;
        }
    }
    p.n_operations += 1;
    0
}

/// What tree_parse() reads into before the publication takes it: the
/// operation in hand, the string just read and the values of a pair.
struct Reader {
    publication: *mut TreePublication,
    op: TreeOperation,
    value: Text,
    pair: [Text; MAX_VALUES],
    n_pair: c_int,
    /// The selector's three lists, whose seen flags say which ones an
    /// operation gave.
    lists: *const JsonField,
}

/// A list the string just read joins.
struct List {
    reader: *mut Reader,
    values: *mut Text,
    n: *mut c_int,
}

/// A map of pairs each member joins, of at most `max`.
struct Map {
    reader: *mut Reader,
    kvs: *mut *mut TreeSelectorKv,
    n: *mut c_int,
    max: c_int,
}

/// # Safety
///
/// `ctx` is a List of a live reader.
unsafe extern "C" fn list_value(ctx: *mut c_void) -> c_int {
    // SAFETY: tree_parse() passes a List, whose values hold MAX_VALUES.
    unsafe {
        let l = &*ctx.cast::<List>();
        let held = count(*l.n, MAX_VALUES);

        if *l.n >= MAX_VALUES as c_int {
            return -E2BIG;
        }
        let value = cstr(&(*l.reader).value);
        let _ = strscpy(&mut *l.values.add(held), value);
        *l.n += 1;
    }
    0
}

/// Each key of a kconfig or labels map once, with a list of one value or
/// more: a key twice would leave its order in the canonical form to the
/// sort.
///
/// # Safety
///
/// `ctx` is a Map of a live reader, and `key` a C string.
unsafe extern "C" fn map_pair(ctx: *mut c_void, key: *const c_char) -> c_int {
    // SAFETY: tree_parse() passes a Map and the member's key; no
    // reference outlives a statement, as the map's pairs are the
    // reader's.
    unsafe {
        let m = &*ctx.cast::<Map>();
        let key = ffi::c_str(key);
        let r = m.reader;

        if (*r).n_pair == 0 {
            return -EINVAL;
        }
        if pairs(*m.kvs, *m.n, usize::MAX)
            .iter()
            .any(|kv| cstr(&kv.key) == key)
        {
            return -EINVAL;
        }
        let kv = match kv_add(m.kvs, m.n, m.max) {
            Ok(kv) => kv,
            Err(err) => return err,
        };
        let _ = strscpy(&mut (*kv).key, key);
        (*kv).values = (*r).pair;
        (*kv).n_values = (*r).n_pair;
        (*r).n_pair = 0;
    }
    0
}

/// The publication takes the operation once it is whole, with its pairs.
///
/// # Safety
///
/// `ctx` is a live reader.
unsafe extern "C" fn take_operation(ctx: *mut c_void) -> c_int {
    let r = ctx.cast::<Reader>();

    // SAFETY: tree_parse() passes its reader, whose lists are the three
    // fields at the start of the selector's.
    unsafe {
        let o = &(*r).op;
        let a = &o.artifact;
        let s = &o.selector;
        let whole = o.seq > 0
            && [
                &o.id[..],
                &o.op,
                &o.operation_digest,
                &a.repository,
                &a.manifest_digest,
                &a.layer_digest,
                &a.payload_sha256,
            ]
            .iter()
            .all(|text| text[0] != 0);
        if !whole {
            return -EINVAL;
        }
        // A selector list is one value or more, never [].
        let counts = [
            s.n_kernel_release_prefix,
            s.n_kernel_build_id,
            s.n_architecture,
        ];
        for (i, n) in counts.into_iter().enumerate() {
            if (*(*r).lists.add(i)).seen() && n == 0 {
                return -EINVAL;
            }
        }
        let p = &mut *(*r).publication;
        if let Err(err) = operations_reserve(p) {
            return err;
        }
        ptr::copy_nonoverlapping(
            &raw const (*r).op,
            p.operations.add(count(p.n_operations, usize::MAX)),
            1,
        );
        p.n_operations += 1;
        ptr::write_bytes(&raw mut (*r).op, 0, 1);
    }
    0
}

/// The publication the JSON at `body` describes, into `out`.
///
/// # Safety
///
/// `out` is room for a publication, which the parse owns.
unsafe fn parse(body: &[u8], out: *mut TreePublication) -> c_int {
    // SAFETY: an all-zero reader holds nothing.
    let mut reader: Box<Reader> = Box::new(unsafe { mem::zeroed() });
    let r: *mut Reader = &mut *reader;
    let mut schema: i64 = 0;
    let mut ret;

    // SAFETY: every field and sink points into the reader or out, which
    // outlive the parse; the callbacks take what their sinks name.
    unsafe {
        (*r).publication = out;
        let o = &raw mut (*r).op;
        let sel = &raw mut (*o).selector;
        let art = &raw mut (*o).artifact;
        let mut release = List {
            reader: r,
            values: (&raw mut (*sel).kernel_release_prefix).cast(),
            n: &raw mut (*sel).n_kernel_release_prefix,
        };
        let mut build_id = List {
            reader: r,
            values: (&raw mut (*sel).kernel_build_id).cast(),
            n: &raw mut (*sel).n_kernel_build_id,
        };
        let mut arch = List {
            reader: r,
            values: (&raw mut (*sel).architecture).cast(),
            n: &raw mut (*sel).n_architecture,
        };
        let mut pair = List {
            reader: r,
            values: (&raw mut (*r).pair).cast(),
            n: &raw mut (*r).n_pair,
        };
        let mut kconfig = Map {
            reader: r,
            kvs: &raw mut (*sel).kconfig,
            n: &raw mut (*sel).n_kconfig,
            max: MAX_KCONFIG as c_int,
        };
        let mut labels = Map {
            reader: r,
            kvs: &raw mut (*sel).labels,
            n: &raw mut (*sel).n_labels,
            max: MAX_LABELS as c_int,
        };
        let mut release_sink = JsonArray::new(list_value, (&raw mut release).cast());
        let mut build_id_sink = JsonArray::new(list_value, (&raw mut build_id).cast());
        let mut arch_sink = JsonArray::new(list_value, (&raw mut arch).cast());
        let mut pair_sink = JsonArray::new(list_value, (&raw mut pair).cast());
        let mut kconfig_map = JsonMap::new(map_pair, (&raw mut kconfig).cast());
        let mut labels_map = JsonMap::new(map_pair, (&raw mut labels).cast());
        let mut operations = JsonArray::new(take_operation, r.cast());
        let mut value = [JsonField::string(
            c"",
            (&raw mut (*r).value).cast(),
            STRING_MAX,
        )];
        let v = value.as_mut_ptr();
        let mut pair_value = [JsonField::array(c"", &raw mut pair_sink, v, 1)];
        let pv = pair_value.as_mut_ptr();
        let mut selector = [
            JsonField::array(c"kernel_release_prefix", &raw mut release_sink, v, 1),
            JsonField::array(c"kernel_build_id", &raw mut build_id_sink, v, 1),
            JsonField::array(c"architecture", &raw mut arch_sink, v, 1),
            JsonField::map(c"kconfig", &raw mut kconfig_map, pv, 1),
            JsonField::map(c"kernel_config", &raw mut kconfig_map, pv, 1),
            JsonField::map(c"labels", &raw mut labels_map, pv, 1),
        ];
        let mut artifact = [
            text_field(c"repository", &raw mut (*art).repository),
            text_field(c"manifest_digest", &raw mut (*art).manifest_digest),
            text_field(c"layer_digest", &raw mut (*art).layer_digest),
            text_field(c"payload_sha256", &raw mut (*art).payload_sha256),
        ];
        let mut operation = [
            JsonField::int(c"seq", &raw mut (*o).seq),
            text_field(c"op", &raw mut (*o).op),
            text_field(c"id", &raw mut (*o).id),
            JsonField::object(c"selector", selector.as_mut_ptr(), selector.len()),
            JsonField::object(c"artifact", artifact.as_mut_ptr(), artifact.len()),
            text_field(c"operation_digest", &raw mut (*o).operation_digest),
        ];
        let mut base = [JsonField::int(c"seq", &raw mut (*out).base_seq)];
        let mut head = [JsonField::int(c"seq", &raw mut (*out).head_seq)];
        let mut root = [
            JsonField::int(c"schema", &raw mut schema),
            text_field(c"tree_id", &raw mut (*out).tree_id),
            JsonField::int(c"generation", &raw mut (*out).generation),
            text_field(
                c"parent_manifest_digest",
                &raw mut (*out).parent_manifest_digest,
            ),
            JsonField::object(c"base", base.as_mut_ptr(), base.len()),
            JsonField::array(
                c"operations",
                &raw mut operations,
                operation.as_mut_ptr(),
                operation.len(),
            ),
            JsonField::object(c"head", head.as_mut_ptr(), head.len()),
        ];

        (*r).lists = selector.as_ptr();
        ret = parse_schema(body, root.as_mut_ptr(), root.len());
        let required = [
            &root[0], &root[2], &root[4], &base[0], &root[5], &root[6], &head[0],
        ];
        if ret == 0 && !required.iter().all(|f| f.seen()) {
            ret = -EINVAL;
        }
    }
    if ret != 0 && ret != -E2BIG && ret != -ENOMEM {
        ret = -EINVAL;
    }
    // SAFETY: the parse is over; nothing else points into out.
    let p = unsafe { &mut *out };
    if ret == 0
        && (schema != 1
            || p.tree_id[0] == 0
            || p.generation < 0
            || p.generation == i64::MAX
            || p.base_seq < 0
            || p.head_seq < p.base_seq
            || p.head_seq == i64::MAX)
    {
        ret = -EINVAL;
    }
    p.schema = schema as c_int;
    // SAFETY: the operations the parse kept.
    let ops = unsafe { p.operations() };
    // Every operation's seq is positive, so seq - 1 cannot overflow.
    if ret == 0 && ops.windows(2).any(|w| w[1].seq - 1 != w[0].seq) {
        ret = -EINVAL;
    }
    selector_free(&mut reader.op.selector);
    if ret != 0 {
        publication_free(p);
    }
    ret
}

/// A string field into the array at `dst`.
fn text_field<const N: usize>(key: &'static CStr, dst: *mut [u8; N]) -> JsonField {
    JsonField::string(key, dst.cast(), N)
}

/// A tree string holds no control character: the node cannot compute the
/// digest of an operation with one and refuses it, so a publication that
/// held one would go out signed and fail every later sync of the tree.
fn text_ok(s: &[u8]) -> bool {
    cstr(s).iter().all(|&c| c >= 0x20)
}

/// # Safety
///
/// The operation's selector's pairs are as its counts say.
unsafe fn operation_text(op: &TreeOperation) -> bool {
    let s = &op.selector;
    let a = &op.artifact;
    let kvs_ok = |kvs: &[TreeSelectorKv]| {
        kvs.iter()
            .all(|kv| text_ok(&kv.key) && listed(&kv.values, kv.n_values).all(text_ok))
    };

    // SAFETY: the caller's selector.
    let (kconfig, labels) = unsafe { (s.kconfig(), s.labels()) };
    text_ok(&op.op)
        && text_ok(&op.id)
        && s.lists()
            .iter()
            .all(|(_, values, n)| listed(values, *n).all(text_ok))
        && kvs_ok(kconfig)
        && kvs_ok(labels)
        && [
            &a.repository[..],
            &a.manifest_digest,
            &a.layer_digest,
            &a.payload_sha256,
        ]
        .iter()
        .all(|t| text_ok(t))
}

/// A list of the canonical selector, when it has values.
fn emit_list(e: &mut JsonEmit, key: &[u8], values: &[Text], n: c_int) {
    if n == 0 {
        return;
    }
    e.arr_open(key);
    for value in listed(values, n) {
        e.str(value);
    }
    e.arr_close();
}

/// A map of the canonical selector, its keys in order, when it has any.
fn emit_pairs(e: &mut JsonEmit, key: &[u8], kvs: &[TreeSelectorKv], n: c_int) {
    if n == 0 {
        return;
    }
    let mut sorted: Vec<&TreeSelectorKv> = kvs.iter().collect();
    sorted.sort_by(|a, b| cstr(&a.key).cmp(cstr(&b.key)));
    e.obj_open_key(key);
    for kv in sorted {
        e.arr_open(cstr(&kv.key));
        for value in listed(&kv.values, kv.n_values) {
            e.str(value);
        }
        e.arr_close();
    }
    e.obj_close();
}

/// The canonical selector object: keys in lexicographic order, each list
/// in the publisher's order. Targets recompute operation digests from
/// this form, so publisher and consumer share one emitter.
///
/// # Safety
///
/// The selector's pairs are as its counts say.
unsafe fn emit_selector(e: &mut JsonEmit, s: &TreeSelector) -> Result<(), c_int> {
    if s.n_kconfig > MAX_KCONFIG as c_int || s.n_labels > MAX_LABELS as c_int {
        return Err(-E2BIG);
    }
    let [arch, build_id, release] = s.lists();

    e.obj_open_key(b"selector");
    emit_list(e, arch.0, arch.1, arch.2);
    // SAFETY: the caller's selector.
    emit_pairs(e, b"kconfig", unsafe { s.kconfig() }, s.n_kconfig);
    emit_list(e, build_id.0, build_id.1, build_id.2);
    emit_list(e, release.0, release.1, release.2);
    // SAFETY: the caller's selector.
    emit_pairs(e, b"labels", unsafe { s.labels() }, s.n_labels);
    e.obj_close();
    Ok(())
}

fn emit_artifact(e: &mut JsonEmit, a: &TreeArtifact) {
    e.obj_open_key(b"artifact");
    e.kv_string(b"repository", cstr(&a.repository));
    e.kv_string(b"manifest_digest", cstr(&a.manifest_digest));
    e.kv_string(b"layer_digest", cstr(&a.layer_digest));
    e.kv_string(b"payload_sha256", cstr(&a.payload_sha256));
    e.obj_close();
}

/// # Safety
///
/// The operation's selector's pairs are as its counts say.
unsafe fn emit_operation(e: &mut JsonEmit, op: &TreeOperation, with_digest: bool) -> c_int {
    // SAFETY: the caller's operation.
    if !unsafe { operation_text(op) } {
        return -EINVAL;
    }
    e.obj_open();
    e.kv_int(b"seq", op.seq);
    e.kv_string(b"op", cstr(&op.op));
    e.kv_string(b"id", cstr(&op.id));
    // SAFETY: the caller's operation.
    if let Err(err) = unsafe { emit_selector(e, &op.selector) } {
        return err;
    }
    emit_artifact(e, &op.artifact);
    if with_digest {
        e.kv_string(b"operation_digest", cstr(&op.operation_digest));
    }
    e.obj_close();
    e.err()
}

/// A zeroed buffer of `n` bytes, or -ENOMEM.
fn buffer(n: usize) -> Result<Vec<u8>, c_int> {
    let mut buf = Vec::new();

    buf.try_reserve_exact(n).map_err(|_| -ENOMEM)?;
    buf.resize(n, 0);
    Ok(buf)
}

/// The operation digest, "sha256:" and 64 hex digits, over the canonical
/// operation without its digest field: seq, op, id, selector and
/// artifact.
///
/// # Safety
///
/// The operation's selector's pairs are as its counts say.
pub(crate) unsafe fn operation_digest(op: &TreeOperation) -> Result<[u8; 72], c_int> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut body = buffer(DIGEST_BODY_MAX)?;
    let mut e = JsonEmit::fixed(body.as_mut_ptr().cast(), body.len());
    let mut digest = [0; 32];
    let mut out = [0; 72];

    // SAFETY: the caller's operation.
    let ret = unsafe { emit_operation(&mut e, op, false) };
    if ret != 0 {
        return Err(ret);
    }
    if sha256_into(&body[..e.written()], &mut digest) != 0 {
        return Err(-EIO);
    }
    out[..7].copy_from_slice(b"sha256:");
    for (i, b) in digest.iter().enumerate() {
        out[7 + 2 * i] = HEX[usize::from(b >> 4)];
        out[8 + 2 * i] = HEX[usize::from(b & 0xf)];
    }
    Ok(out)
}

/// The bytes a JSON string of `s` takes at most, quotes and separator
/// included.
fn json_bound(s: &[u8]) -> usize {
    2 * cstr(s).len() + 4
}

fn pair_bound(kv: &TreeSelectorKv) -> usize {
    8 + json_bound(&kv.key)
        + listed(&kv.values, kv.n_values)
            .map(json_bound)
            .sum::<usize>()
}

/// # Safety
///
/// The operation's selector's pairs are as its counts say.
unsafe fn operation_bound(op: &TreeOperation) -> usize {
    let s = &op.selector;
    let a = &op.artifact;
    // SAFETY: the caller's selector.
    let (kconfig, labels) = unsafe { (s.kconfig(), s.labels()) };

    512 + [
        &op.op[..],
        &op.id,
        &op.operation_digest,
        &a.repository,
        &a.manifest_digest,
        &a.layer_digest,
        &a.payload_sha256,
    ]
    .iter()
    .map(|t| json_bound(t))
    .sum::<usize>()
        + s.lists()
            .iter()
            .map(|(_, values, n)| listed(values, *n).map(json_bound).sum::<usize>())
            .sum::<usize>()
        + kconfig.iter().chain(labels).map(pair_bound).sum::<usize>()
}

/// The publication in the field order every publisher has used: schema,
/// tree_id, generation, parent_manifest_digest when it names one, base,
/// operations, head; in an xmalloc'd buffer of `.1` bytes holding the
/// `.2` written.
///
/// # Safety
///
/// The publication's operations and their pairs are as its counts say.
unsafe fn emit_publication(p: &TreePublication) -> Result<(*mut c_char, usize, usize), c_int> {
    // SAFETY: the caller's publication.
    let ops = unsafe { p.operations() };
    // SAFETY: the caller's operations.
    let cap = 4096
        + ops
            .iter()
            .map(|op| unsafe { operation_bound(op) })
            .sum::<usize>();
    // SAFETY: xmalloc() takes any size.
    let body: *mut c_char = unsafe { xmalloc(cap) }.cast();
    let mut ret = 0;

    if body.is_null() {
        return Err(-ENOMEM);
    }
    let mut e = JsonEmit::fixed(body, cap);
    e.obj_open();
    e.kv_int(b"schema", p.schema.into());
    e.kv_string(b"tree_id", cstr(&p.tree_id));
    e.kv_int(b"generation", p.generation);
    if p.parent_manifest_digest[0] != 0 {
        e.kv_string(b"parent_manifest_digest", cstr(&p.parent_manifest_digest));
    }
    e.obj_open_key(b"base");
    e.kv_int(b"seq", p.base_seq);
    e.obj_close();
    e.arr_open(b"operations");
    for op in ops {
        // SAFETY: the caller's operation.
        ret = unsafe { emit_operation(&mut e, op, true) };
        if ret != 0 {
            break;
        }
    }
    e.arr_close();
    e.obj_open_key(b"head");
    e.kv_int(b"seq", p.head_seq);
    e.obj_close();
    e.obj_close();
    if ret == 0 {
        ret = e.err();
    }
    // tree_parse() takes MAX_BYTES at most.
    if ret == 0 && e.written() > MAX_BYTES {
        ret = -E2BIG;
    }
    if ret != 0 {
        // SAFETY: the buffer xmalloc() gave.
        unsafe { xfree(body.cast(), cap) };
        return Err(ret);
    }
    Ok((body, cap, e.written()))
}

fn nibble(c: u8) -> Option<u8> {
    char::from(c).to_digit(16).map(|d| d as u8)
}

/// The 32 bytes of a "sha256:" digest of 64 hex digits of either case.
pub(crate) fn digest_bytes(text: &[u8]) -> Option<[u8; 32]> {
    let hex = cstr(text).strip_prefix(b"sha256:")?;
    let mut out = [0; 32];

    if hex.len() != 64 {
        return None;
    }
    for (b, pair) in out.iter_mut().zip(hex.chunks_exact(2)) {
        *b = nibble(pair[0])? << 4 | nibble(pair[1])?;
    }
    Some(out)
}

/// An operation has a positive sequence number, an upatch name, add or
/// delete, well-formed digests and the operation digest its fields hash
/// to: 0, -EINVAL, or -EKEYREJECTED for a digest that does not match.
///
/// # Safety
///
/// The operation's selector's pairs are as its counts say.
pub(crate) unsafe fn operation_validate(op: &TreeOperation) -> c_int {
    let kind = cstr(&op.op);
    let a = &op.artifact;

    if op.seq <= 0
        || !upatch::name_valid(Some(cstr(&op.id)))
        || (kind != b"add" && kind != b"delete")
    {
        return -EINVAL;
    }
    if [
        &op.operation_digest,
        &a.manifest_digest,
        &a.layer_digest,
        &a.payload_sha256,
    ]
    .iter()
    .any(|d| digest_bytes(&d[..]).is_none())
    {
        return -EINVAL;
    }
    // SAFETY: the caller's operation.
    match unsafe { operation_digest(op) } {
        Err(_) => -EINVAL,
        Ok(expected) if cstr(&op.operation_digest) != cstr(&expected) => -EKEYREJECTED,
        Ok(_) => 0,
    }
}

/// A publication names a well-formed parent digest if any, and its
/// operations run from base_seq + 1 to head_seq, or head_seq is base_seq
/// without them: 0 or -EINVAL, and -ENOTSUP for a base past 0, which
/// snapshot compaction, a later schema, would need.
///
/// # Safety
///
/// The publication's operations are as its count says.
pub(crate) unsafe fn publication_check(p: &TreePublication) -> c_int {
    if p.parent_manifest_digest[0] != 0 && digest_bytes(&p.parent_manifest_digest).is_none() {
        return -EINVAL;
    }
    if p.base_seq != 0 {
        return -EOPNOTSUPP;
    }
    // SAFETY: the caller's publication.
    let ops = unsafe { p.operations() };
    let runs = match (ops.first(), ops.last()) {
        (Some(first), Some(last)) => first.seq == p.base_seq + 1 && p.head_seq == last.seq,
        _ => p.head_seq == p.base_seq,
    };
    if runs { 0 } else { -EINVAL }
}

/// Whether a publication may follow the state the node recorded, None
/// for none, with `manifest_digest` its manifest's: the same tree, a
/// later generation unless it is the same manifest, the parent the node
/// recorded when it is the next generation and names one, no head
/// before the node's cursor and no base after it. 0, -EINVAL for another
/// tree, or -ERANGE.
pub(crate) fn publication_follows(
    p: &TreePublication,
    state: Option<&TreeState>,
    manifest_digest: &[u8],
) -> c_int {
    let Some(s) = state else {
        return if p.base_seq != 0 { -ERANGE } else { 0 };
    };
    if cstr(&s.tree_id) != cstr(&p.tree_id) {
        return -EINVAL;
    }
    let same = cstr(&s.manifest_digest) == manifest_digest;
    if !same && p.generation <= s.generation {
        return -ERANGE;
    }
    // Only a direct successor names the manifest this node recorded as
    // its parent; one that missed a generation never saw the parent.
    if !same
        && p.generation.checked_sub(1) == Some(s.generation)
        && p.parent_manifest_digest[0] != 0
        && cstr(&p.parent_manifest_digest) != cstr(&s.manifest_digest)
    {
        return -ERANGE;
    }
    if p.head_seq < s.last_seq || p.base_seq > s.last_seq {
        return -ERANGE;
    }
    0
}

/// A publication Rust code owns, released when it goes.
pub(crate) struct Publication(Box<TreePublication>);

impl Publication {
    pub(crate) fn new() -> Self {
        // SAFETY: an all-zero publication holds nothing.
        Publication(Box::new(unsafe { mem::zeroed() }))
    }

    pub(crate) fn get(&self) -> &TreePublication {
        &self.0
    }

    pub(crate) fn get_mut(&mut self) -> &mut TreePublication {
        &mut self.0
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        publication_free(&mut self.0);
    }
}

pub(crate) use capi::{
    tree_emit_publication, tree_operation_digest, tree_parse, tree_publication_append,
    tree_publication_free, tree_selector_copy, tree_selector_free, tree_selector_kv_add,
};

mod capi {
    use core::ffi::{c_char, c_int};

    use super::{TreeOperation, TreePublication, TreeSelector, TreeSelectorKv, TreeState};
    use crate::errno::EINVAL;
    use crate::ffi;
    use crate::util::json::MAX_BYTES;

    /// # Safety
    ///
    /// `kvs` and `n` are a selector's pairs from the xmalloc family, and
    /// `kv` room for a pointer.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_selector_kv_add(
        kvs: *mut *mut TreeSelectorKv,
        n: *mut c_int,
        max: c_int,
        kv: *mut *mut TreeSelectorKv,
    ) -> c_int {
        // SAFETY: the caller's pairs and room.
        match unsafe { super::kv_add(kvs, n, max) } {
            Ok(added) => {
                // SAFETY: the caller's room for the pair.
                unsafe { *kv = added };
                0
            }
            Err(err) => err,
        }
    }

    /// # Safety
    ///
    /// `src` is a selector whose pairs are as its counts say, and `dst`
    /// room for one.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_selector_copy(
        dst: *mut TreeSelector,
        src: *const TreeSelector,
    ) -> c_int {
        // SAFETY: the caller's selectors.
        unsafe { super::selector_copy(dst, src) }
    }

    /// # Safety
    ///
    /// `s` is NULL or a selector whose pairs are as its counts say.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_selector_free(s: *mut TreeSelector) {
        // SAFETY: the caller's selector.
        if let Some(s) = unsafe { s.as_mut() } {
            super::selector_free(s);
        }
    }

    /// # Safety
    ///
    /// `body` holds `len` bytes and `out` is room for a publication.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_parse(
        body: *const c_char,
        len: usize,
        out: *mut TreePublication,
    ) -> c_int {
        if body.is_null() || out.is_null() || len > MAX_BYTES {
            return -EINVAL;
        }
        // SAFETY: the caller's room for a publication, and its bytes.
        unsafe {
            out.write_bytes(0, 1);
            super::parse(ffi::slice(body.cast(), len), out)
        }
    }

    /// # Safety
    ///
    /// `p` is NULL or a publication whose operations come from the
    /// xmalloc family, and `op` NULL or an operation, each with pairs as
    /// their counts say.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_publication_append(
        p: *mut TreePublication,
        op: *const TreeOperation,
    ) -> c_int {
        if op.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller's publication.
        let Some(p) = (unsafe { p.as_mut() }) else {
            return -EINVAL;
        };
        // SAFETY: the caller's operation.
        unsafe { super::publication_append(p, op) }
    }

    /// # Safety
    ///
    /// `p` is NULL or a publication whose operations come from the
    /// xmalloc family, as many as its capacity says.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_publication_free(p: *mut TreePublication) {
        // SAFETY: the caller's publication.
        if let Some(p) = unsafe { p.as_mut() } {
            super::publication_free(p);
        }
    }

    /// # Safety
    ///
    /// `op` is an operation whose pairs are as its counts say, and `out`
    /// room for 72 bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_operation_digest(
        op: *const TreeOperation,
        out: *mut [u8; 72],
    ) -> c_int {
        // SAFETY: the caller's operation and room.
        match unsafe { super::operation_digest(&*op) } {
            Ok(digest) => {
                // SAFETY: the caller's room.
                unsafe { *out = digest };
                0
            }
            Err(err) => err,
        }
    }

    /// # Safety
    ///
    /// `p` is a publication whose operations and pairs are as its counts
    /// say, and `out` and `out_len` room for the buffer and its length.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_emit_publication(
        p: *const TreePublication,
        out: *mut *mut c_char,
        out_len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller's publication and room.
        match unsafe { super::emit_publication(&*p) } {
            Ok((body, _, len)) => {
                // SAFETY: the caller's room.
                unsafe {
                    *out = body;
                    *out_len = len;
                }
                0
            }
            Err(err) => err,
        }
    }

    /// # Safety
    ///
    /// `op` is an operation whose pairs are as its counts say.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_operation_validate(op: *const TreeOperation) -> c_int {
        // SAFETY: the caller's operation.
        unsafe { super::operation_validate(&*op) }
    }

    /// # Safety
    ///
    /// `p` is a publication whose operations are as its count says.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_publication_check(p: *const TreePublication) -> c_int {
        // SAFETY: the caller's publication.
        unsafe { super::publication_check(&*p) }
    }

    /// # Safety
    ///
    /// `p` is a publication, `state` NULL or a state, and
    /// `manifest_digest` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn tree_publication_follows(
        p: *const TreePublication,
        state: *const TreeState,
        manifest_digest: *const c_char,
    ) -> c_int {
        // SAFETY: the caller's publication, state and string.
        unsafe { super::publication_follows(&*p, state.as_ref(), ffi::c_str(manifest_digest)) }
    }
}
