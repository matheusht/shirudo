// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The signed upatch tree's publications: the
//! operations a publication carries, the canonical form and operation
//! digests that publisher and target share, and what a sync checks
//! before it applies anything.

use core::ffi::{CStr, c_int};
use core::mem;

use crate::errno::{E2BIG, EINVAL, EIO, EKEYREJECTED, ENOMEM, ERANGE};
use crate::text::cstr;
use crate::util::bpm_oci::package_name_ok;
use crate::util::chain::history_step;
use crate::util::crypto_openssl::sha256_into;
use crate::util::hex::{self, sha256_digest_encode};
use crate::util::json::{JsonEmit, JsonField, MAX_BYTES, parse_schema};
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

/// A string of the tree, NUL-terminated in a fixed array.
pub(crate) type Text = [u8; STRING_MAX];

/// The build's lowered limits, as the C's TREE_LIMIT_CFLAGS gave them:
/// `-D<NAME>=<n>`, which the Makefile hands cargo in SHIRUDO_TREE_LIMITS
/// for a target build of the test VM bundle.
const BUILD_LIMITS: &[u8] = match option_env!("SHIRUDO_TREE_LIMITS") {
    Some(s) => s.as_bytes(),
    None => b"",
};

/// The limit `name` of the build, or `default` where it lowers none.
pub(crate) const fn build_limit(name: &[u8], default: i64) -> i64 {
    let s = BUILD_LIMITS;
    let mut i = 0;

    while i + 3 + name.len() < s.len() {
        let mut j = 0;
        let mut at = s[i] == b'-' && s[i + 1] == b'D';
        while at && j < name.len() {
            at = s[i + 2 + j] == name[j];
            j += 1;
        }
        if at && s[i + 2 + name.len()] == b'=' {
            let (mut k, mut v, mut any) = (i + 3 + name.len(), 0i64, false);
            while k < s.len() && s[k].is_ascii_digit() {
                v = v * 10 + (s[k] - b'0') as i64;
                any = true;
                k += 1;
            }
            if any {
                return v;
            }
        }
        i += 1;
    }
    default
}

/// The most operations a walk back through sealed segments covers from
/// seq 0, as a node that joins a tree does, and from the cursor of a node
/// that has processed one: one past is -E2BIG. A running node walks
/// holding the bpm lock, with its keepalive stopped, so it gets the
/// lower one.
pub(crate) const MAX_JOIN_OPS: i64 = build_limit(b"TREE_MAX_JOIN_OPS", 1 << 20);
pub(crate) const MAX_WALK_OPS: i64 = build_limit(b"TREE_MAX_WALK_OPS", 65536);

/// publication_follows(): the publication's base lies past the node's
/// cursor, which must walk back through the sealed segments before it.
pub(crate) const FOLLOWS_WALK: c_int = 1;

/// The canonical operation an operation digest hashes takes at most this.
const DIGEST_BODY_MAX: usize = 1024 * 1024;

/// The nodes an operation applies to: any value of each list, and each
/// pair of its maps. A list or a map that is empty constrains nothing.
/// The parse and the Beefile reader hold a list to MAX_VALUES values
/// and the maps to MAX_KCONFIG and MAX_LABELS pairs.
#[derive(Clone, Default)]
pub(crate) struct TreeSelector {
    pub(crate) kernel_release_prefix: Vec<Vec<u8>>,
    pub(crate) kernel_build_id: Vec<Vec<u8>>,
    pub(crate) architecture: Vec<Vec<u8>>,
    pub(crate) kconfig: Vec<TreeSelectorKv>,
    pub(crate) labels: Vec<TreeSelectorKv>,
}

/// A key of a selector's map and the values the node may have for it.
#[derive(Clone, Default)]
pub(crate) struct TreeSelectorKv {
    pub(crate) key: Vec<u8>,
    pub(crate) values: Vec<Vec<u8>>,
}

/// The two maps of a selector.
#[derive(Clone, Copy)]
pub(crate) enum SelectorMap {
    Kconfig,
    Labels,
}

// The strings of the records below stay in fixed arrays, NUL-terminated:
// they are the rooms the JSON reader decodes each into, and it refuses a
// string too long for its room.

/// The artifact an operation's upatch is published as.
#[derive(Clone)]
pub(crate) struct TreeArtifact {
    pub(crate) repository: [u8; 512],
    pub(crate) manifest_digest: [u8; 128],
    pub(crate) layer_digest: [u8; 128],
    pub(crate) payload_sha256: [u8; 128],
}

/// An operation of the tree: the upatch it adds or deletes, and on which
/// nodes.
#[derive(Clone)]
pub(crate) struct TreeOperation {
    pub(crate) seq: i64,
    pub(crate) op: [u8; 16],
    pub(crate) id: Text,
    pub(crate) selector: TreeSelector,
    pub(crate) artifact: TreeArtifact,
    pub(crate) operation_digest: [u8; 128],
}

/// A publication: one segment of the tree, its operations in order.
pub(crate) struct TreePublication {
    pub(crate) schema: i64,
    pub(crate) tree_id: Text,
    pub(crate) generation: i64,
    pub(crate) parent_manifest_digest: [u8; 128],
    pub(crate) base_seq: i64,
    /// Past the first segment: its sealed predecessor, and the history
    /// at the base.
    pub(crate) segment_manifest_digest: [u8; 128],
    pub(crate) history_root: [u8; 65],
    pub(crate) operations: Vec<TreeOperation>,
    pub(crate) head_seq: i64,
}

/// The operation a sync started, recorded until it is through.
pub(crate) struct TreePending {
    pub(crate) seq: i64,
    pub(crate) id: Text,
    pub(crate) operation_digest: [u8; 128],
}

/// Where a node is in its tree.
pub(crate) struct TreeState {
    pub(crate) schema: i64,
    pub(crate) tree_id: Text,
    pub(crate) generation: i64,
    pub(crate) last_seq: i64,
    pub(crate) projection_root: [u8; 65],
    pub(crate) projection_root_tpm: [u8; 65],
    pub(crate) manifest_digest: [u8; 128],
    pub(crate) head_seq: i64,
    pub(crate) segment_base_seq: i64,
}

/// What a publisher adds to the operation of an index, into its open
/// object: the fixes, which no node reads.
pub(crate) type Extra<'a> = &'a mut dyn FnMut(&mut JsonEmit, usize) -> c_int;

/// `item` added to `v` of at most `max`: -E2BIG for a full one, or
/// -ENOMEM.
fn push_within<T>(v: &mut Vec<T>, item: T, max: usize) -> Result<(), c_int> {
    if v.len() >= max {
        return Err(-E2BIG);
    }
    v.try_reserve(1).map_err(|_| -ENOMEM)?;
    v.push(item);
    Ok(())
}

impl TreeSelector {
    /// The three lists in the canonical form's order, with their keys.
    fn lists(&self) -> [(&'static [u8], &[Vec<u8>]); 3] {
        [
            (b"architecture", &self.architecture),
            (b"kernel_build_id", &self.kernel_build_id),
            (b"kernel_release_prefix", &self.kernel_release_prefix),
        ]
    }

    /// Whether it names nothing: the tree's explicit wildcard.
    pub(crate) fn is_empty(&self) -> bool {
        self.kernel_release_prefix.is_empty()
            && self.kernel_build_id.is_empty()
            && self.architecture.is_empty()
            && self.kconfig.is_empty()
            && self.labels.is_empty()
    }

    /// The pair of `key`, up to its NUL, and `values` added to the map
    /// `map`: -EINVAL for a key it holds, -E2BIG past the most pairs it
    /// takes, or -ENOMEM.
    pub(crate) fn pair_add(
        &mut self,
        map: SelectorMap,
        key: &[u8],
        values: Vec<Vec<u8>>,
    ) -> Result<(), c_int> {
        let (pairs, max) = match map {
            SelectorMap::Kconfig => (&mut self.kconfig, MAX_KCONFIG),
            SelectorMap::Labels => (&mut self.labels, MAX_LABELS),
        };

        if pairs.iter().any(|kv| kv.key == key) {
            return Err(-EINVAL);
        }
        let key = cstr(key).to_vec();
        push_within(pairs, TreeSelectorKv { key, values }, max)
    }
}

impl Default for TreeArtifact {
    fn default() -> Self {
        TreeArtifact {
            repository: [0; 512],
            manifest_digest: [0; 128],
            layer_digest: [0; 128],
            payload_sha256: [0; 128],
        }
    }
}

impl Default for TreeOperation {
    fn default() -> Self {
        TreeOperation {
            seq: 0,
            op: [0; 16],
            id: [0; STRING_MAX],
            selector: TreeSelector::default(),
            artifact: TreeArtifact::default(),
            operation_digest: [0; 128],
        }
    }
}

impl Default for TreePublication {
    fn default() -> Self {
        TreePublication {
            schema: 0,
            tree_id: [0; STRING_MAX],
            generation: 0,
            parent_manifest_digest: [0; 128],
            base_seq: 0,
            segment_manifest_digest: [0; 128],
            history_root: [0; 65],
            operations: Vec::new(),
            head_seq: 0,
        }
    }
}

impl Default for TreePending {
    fn default() -> Self {
        TreePending {
            seq: 0,
            id: [0; STRING_MAX],
            operation_digest: [0; 128],
        }
    }
}

impl Default for TreeState {
    fn default() -> Self {
        TreeState {
            schema: 0,
            tree_id: [0; STRING_MAX],
            generation: 0,
            last_seq: 0,
            projection_root: [0; 65],
            projection_root_tpm: [0; 65],
            manifest_digest: [0; 128],
            head_seq: 0,
            segment_base_seq: 0,
        }
    }
}

impl TreePublication {
    /// `op` appended: -E2BIG past MAX_OPS operations, or -ENOMEM.
    pub(crate) fn append(&mut self, op: TreeOperation) -> Result<(), c_int> {
        push_within(&mut self.operations, op, MAX_OPS)
    }
}

/// What the parse reads into: the publication, its schema version, and
/// before the publication takes it the operation in hand, the string
/// just read and the values of a pair.
struct Reader {
    publication: TreePublication,
    schema: i64,
    op: TreeOperation,
    value: Text,
    pair: Vec<Vec<u8>>,
}

/// The string just read joins the list `values`.
fn list_add(values: &mut Vec<Vec<u8>>, value: &Text) -> Result<(), c_int> {
    push_within(values, cstr(value).to_vec(), MAX_VALUES)
}

/// Each key of a kconfig or labels map once, with a list of one value or
/// more: a key twice would leave its order in the canonical form to the
/// sort.
fn map_pair(r: &mut Reader, map: SelectorMap, key: &CStr) -> Result<(), c_int> {
    if r.pair.is_empty() {
        return Err(-EINVAL);
    }
    let values = mem::take(&mut r.pair);
    r.op.selector.pair_add(map, key.to_bytes(), values)
}

/// The publication takes the operation once it is whole, with its pairs;
/// `lists` are the selector's three lists, whose seen flags say which
/// ones the operation gave.
fn take_operation(r: &mut Reader, lists: &[JsonField<'_, Reader>]) -> Result<(), c_int> {
    let o = &r.op;
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
        return Err(-EINVAL);
    }
    // A selector list is one value or more, never [].
    let lens = [
        s.kernel_release_prefix.len(),
        s.kernel_build_id.len(),
        s.architecture.len(),
    ];
    for (n, list) in lens.into_iter().zip(lists) {
        if list.seen() && n == 0 {
            return Err(-EINVAL);
        }
    }
    let op = mem::take(&mut r.op);
    r.publication.append(op)
}

impl TreePublication {
    /// The publication the JSON `body` describes: -EINVAL for one that
    /// is none, -E2BIG for one past a limit, or -ENOMEM.
    pub(crate) fn parse(body: &[u8]) -> Result<Self, c_int> {
        if body.len() > MAX_BYTES {
            return Err(-EINVAL);
        }
        let mut reader = Reader {
            publication: TreePublication::default(),
            schema: 0,
            op: TreeOperation::default(),
            value: [0; STRING_MAX],
            pair: Vec::new(),
        };
        let value = [JsonField::string(c"", |r: &mut Reader| &mut r.value)];
        let add_pair_value = |r: &mut Reader| list_add(&mut r.pair, &r.value);
        let pair_value = JsonField::array(c"", &value, &add_pair_value);
        let add_release =
            |r: &mut Reader| list_add(&mut r.op.selector.kernel_release_prefix, &r.value);
        let add_build_id = |r: &mut Reader| list_add(&mut r.op.selector.kernel_build_id, &r.value);
        let add_architecture = |r: &mut Reader| list_add(&mut r.op.selector.architecture, &r.value);
        let kconfig_pair = |r: &mut Reader, key: &CStr| map_pair(r, SelectorMap::Kconfig, key);
        let label_pair = |r: &mut Reader, key: &CStr| map_pair(r, SelectorMap::Labels, key);
        let selector = [
            JsonField::array(c"kernel_release_prefix", &value, &add_release),
            JsonField::array(c"kernel_build_id", &value, &add_build_id),
            JsonField::array(c"architecture", &value, &add_architecture),
            JsonField::map(c"kconfig", &pair_value, &kconfig_pair),
            JsonField::map(c"kernel_config", &pair_value, &kconfig_pair),
            JsonField::map(c"labels", &pair_value, &label_pair),
        ];
        let artifact = [
            JsonField::string(c"repository", |r: &mut Reader| {
                &mut r.op.artifact.repository
            }),
            JsonField::string(c"manifest_digest", |r| &mut r.op.artifact.manifest_digest),
            JsonField::string(c"layer_digest", |r| &mut r.op.artifact.layer_digest),
            JsonField::string(c"payload_sha256", |r| &mut r.op.artifact.payload_sha256),
        ];
        let operation = [
            JsonField::int(c"seq", |r: &mut Reader| &mut r.op.seq),
            JsonField::string(c"op", |r| &mut r.op.op),
            JsonField::string(c"id", |r| &mut r.op.id),
            JsonField::object(c"selector", &selector),
            JsonField::object(c"artifact", &artifact),
            JsonField::string(c"operation_digest", |r| &mut r.op.operation_digest),
        ];
        let take = |r: &mut Reader| take_operation(r, &selector[..3]);
        let base = [
            JsonField::int(c"seq", |r: &mut Reader| &mut r.publication.base_seq),
            JsonField::string(c"segment_manifest_digest", |r| {
                &mut r.publication.segment_manifest_digest
            }),
            JsonField::string(c"history_root", |r| &mut r.publication.history_root),
        ];
        let head = [JsonField::int(c"seq", |r: &mut Reader| {
            &mut r.publication.head_seq
        })];
        let root = [
            JsonField::int(c"schema", |r: &mut Reader| &mut r.schema),
            JsonField::string(c"tree_id", |r| &mut r.publication.tree_id),
            JsonField::int(c"generation", |r| &mut r.publication.generation),
            JsonField::string(c"parent_manifest_digest", |r| {
                &mut r.publication.parent_manifest_digest
            }),
            JsonField::object(c"base", &base),
            JsonField::array(c"operations", &operation, &take),
            JsonField::object(c"head", &head),
        ];

        let mut ret = parse_schema(body, &root, &mut reader).err().unwrap_or(0);
        let required = [
            &root[0], &root[2], &root[4], &base[0], &root[5], &root[6], &head[0],
        ];
        if ret == 0 && !required.iter().all(|f| f.seen()) {
            ret = -EINVAL;
        }
        if ret != 0 && ret != -E2BIG && ret != -ENOMEM {
            ret = -EINVAL;
        }
        let mut p = reader.publication;
        p.schema = reader.schema;
        if ret == 0
            && (p.schema != 1
                || p.tree_id[0] == 0
                || p.generation < 0
                || p.generation == i64::MAX
                || p.base_seq < 0
                || p.head_seq < p.base_seq
                || p.head_seq == i64::MAX)
        {
            ret = -EINVAL;
        }
        // Every operation's seq is positive, so seq - 1 cannot overflow.
        if ret == 0 && p.operations.windows(2).any(|w| w[1].seq - 1 != w[0].seq) {
            ret = -EINVAL;
        }
        if ret != 0 {
            return Err(ret);
        }
        Ok(p)
    }
}

/// A tree string holds no control character: the node cannot compute the
/// digest of an operation with one and refuses it, so a publication that
/// held one would go out signed and fail every later sync of the tree.
fn text_ok(s: &[u8]) -> bool {
    cstr(s).iter().all(|&c| c >= 0x20)
}

fn operation_text(op: &TreeOperation) -> bool {
    let s = &op.selector;
    let a = &op.artifact;
    let kvs_ok = |kvs: &[TreeSelectorKv]| {
        kvs.iter()
            .all(|kv| text_ok(&kv.key) && kv.values.iter().all(|v| text_ok(v)))
    };

    text_ok(&op.op)
        && text_ok(&op.id)
        && s.lists()
            .iter()
            .all(|(_, values)| values.iter().all(|v| text_ok(v)))
        && kvs_ok(&s.kconfig)
        && kvs_ok(&s.labels)
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
fn emit_list(e: &mut JsonEmit, key: &[u8], values: &[Vec<u8>]) {
    if values.is_empty() {
        return;
    }
    e.arr_open(key);
    for value in values {
        e.str(value);
    }
    e.arr_close();
}

/// A map of the canonical selector, its keys in order, when it has any.
fn emit_pairs(e: &mut JsonEmit, key: &[u8], kvs: &[TreeSelectorKv]) {
    if kvs.is_empty() {
        return;
    }
    let mut sorted: Vec<&TreeSelectorKv> = kvs.iter().collect();
    sorted.sort_by(|a, b| a.key.cmp(&b.key));
    e.obj_open_key(key);
    for kv in sorted {
        e.arr_open(&kv.key);
        for value in &kv.values {
            e.str(value);
        }
        e.arr_close();
    }
    e.obj_close();
}

/// The canonical selector object: keys in lexicographic order, each list
/// in the publisher's order. Targets recompute operation digests from
/// this form, so publisher and consumer share one emitter.
fn emit_selector(e: &mut JsonEmit, s: &TreeSelector) -> Result<(), c_int> {
    if s.kconfig.len() > MAX_KCONFIG || s.labels.len() > MAX_LABELS {
        return Err(-E2BIG);
    }
    let [arch, build_id, release] = s.lists();

    e.obj_open_key(b"selector");
    emit_list(e, arch.0, arch.1);
    emit_pairs(e, b"kconfig", &s.kconfig);
    emit_list(e, build_id.0, build_id.1);
    emit_list(e, release.0, release.1);
    emit_pairs(e, b"labels", &s.labels);
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

/// The five keys the operation digest covers, into an open object.
fn emit_operation_keys(e: &mut JsonEmit, op: &TreeOperation) -> Result<(), c_int> {
    if !operation_text(op) {
        return Err(-EINVAL);
    }
    e.kv_int(b"seq", op.seq);
    e.kv_string(b"op", cstr(&op.op));
    e.kv_string(b"id", cstr(&op.id));
    emit_selector(e, &op.selector)?;
    emit_artifact(e, &op.artifact);
    Ok(())
}

/// What the emitter has failed with, if anything.
fn emitted(e: &JsonEmit) -> Result<(), c_int> {
    match e.err() {
        0 => Ok(()),
        err => Err(err),
    }
}

fn emit_operation(
    e: &mut JsonEmit,
    op: &TreeOperation,
    index: usize,
    extra: &mut Option<Extra<'_>>,
) -> Result<(), c_int> {
    e.obj_open();
    emit_operation_keys(e, op)?;
    if let Some(extra) = extra {
        match extra(e, index) {
            0 => {}
            err => return Err(err),
        }
    }
    e.kv_string(b"operation_digest", cstr(&op.operation_digest));
    e.obj_close();
    emitted(e)
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
pub(crate) fn operation_digest(op: &TreeOperation) -> Result<[u8; 72], c_int> {
    let mut body = buffer(DIGEST_BODY_MAX)?;
    let mut e = JsonEmit::fixed(&mut body);
    let mut digest = [0; 32];

    e.obj_open();
    let keys = emit_operation_keys(&mut e, op);
    e.obj_close();
    keys?;
    emitted(&e)?;
    if sha256_into(e.output(), &mut digest) != 0 {
        return Err(-EIO);
    }
    Ok(sha256_digest_encode(&digest))
}

/// The publication in the field order every publisher has used: schema,
/// tree_id, generation, parent_manifest_digest when it names one, base
/// with its segment keys when it has them, operations, head. `extra`
/// adds a publisher's keys to each operation.
pub(crate) fn emit_publication(
    p: &TreePublication,
    mut extra: Option<Extra<'_>>,
) -> Result<Vec<u8>, c_int> {
    // One past what the parse takes, so that a document past it is told
    // from one that fills it.
    let mut e = JsonEmit::growing(MAX_BYTES + 1);
    let mut ops = Ok(());

    e.obj_open();
    e.kv_int(b"schema", p.schema);
    e.kv_string(b"tree_id", cstr(&p.tree_id));
    e.kv_int(b"generation", p.generation);
    if p.parent_manifest_digest[0] != 0 {
        e.kv_string(b"parent_manifest_digest", cstr(&p.parent_manifest_digest));
    }
    e.obj_open_key(b"base");
    e.kv_int(b"seq", p.base_seq);
    if p.segment_manifest_digest[0] != 0 {
        e.kv_string(b"segment_manifest_digest", cstr(&p.segment_manifest_digest));
    }
    if p.history_root[0] != 0 {
        e.kv_string(b"history_root", cstr(&p.history_root));
    }
    e.obj_close();
    e.arr_open(b"operations");
    for (i, op) in p.operations.iter().enumerate() {
        ops = emit_operation(&mut e, op, i, &mut extra);
        if ops.is_err() {
            break;
        }
    }
    e.arr_close();
    e.obj_open_key(b"head");
    e.kv_int(b"seq", p.head_seq);
    e.obj_close();
    e.obj_close();
    ops?;
    emitted(&e)?;
    if e.written() > MAX_BYTES {
        return Err(-E2BIG);
    }
    e.finish()
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
/// to: -EINVAL, or -EKEYREJECTED for a digest that does not match.
pub(crate) fn operation_validate(op: &TreeOperation) -> Result<(), c_int> {
    let kind = cstr(&op.op);
    let a = &op.artifact;

    if op.seq <= 0
        || !upatch::name_valid(Some(cstr(&op.id)))
        || (kind != b"add" && kind != b"delete")
    {
        return Err(-EINVAL);
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
        return Err(-EINVAL);
    }
    match operation_digest(op) {
        Err(_) => Err(-EINVAL),
        Ok(expected) if cstr(&op.operation_digest) != cstr(&expected) => Err(-EKEYREJECTED),
        Ok(_) => Ok(()),
    }
}

/// A segment past the first, its base above 0, holds an operation or
/// more and names a well-formed sealed predecessor digest and history
/// root; the first names neither.
fn base_valid(p: &TreePublication) -> bool {
    match p.base_seq {
        0 => p.segment_manifest_digest[0] == 0 && p.history_root[0] == 0,
        b if b < 0 => false,
        _ => {
            !p.operations.is_empty()
                && digest_bytes(&p.segment_manifest_digest).is_some()
                && hex::decode(cstr(&p.history_root), &mut [0; 32]).is_ok()
        }
    }
}

/// A publication names a well-formed parent digest if any, and its
/// operations run from base_seq + 1 to head_seq, or head_seq is base_seq
/// without them, past a base as [`base_valid`] has it: -EINVAL if not.
pub(crate) fn publication_check(p: &TreePublication) -> Result<(), c_int> {
    if p.parent_manifest_digest[0] != 0 && digest_bytes(&p.parent_manifest_digest).is_none() {
        return Err(-EINVAL);
    }
    if !base_valid(p) {
        return Err(-EINVAL);
    }
    let runs = match (p.operations.first(), p.operations.last()) {
        (Some(first), Some(last)) => first.seq == p.base_seq + 1 && p.head_seq == last.seq,
        _ => p.head_seq == p.base_seq,
    };
    if runs { Ok(()) } else { Err(-EINVAL) }
}

/// What tree sync checks of a publication before it applies anything:
/// its tree ID is a name the node can record, [`publication_check`], and
/// [`operation_validate`] of each operation. The first failure, with the
/// index of the operation that failed, if one did.
pub(crate) fn publication_verify(p: &TreePublication) -> Result<(), (c_int, Option<usize>)> {
    // The node records the tree ID in its state, which takes names
    // alone: one that is not would be applied, measured and logged and
    // then never recorded, failing every later sync.
    if !package_name_ok(cstr(&p.tree_id)) {
        return Err((-EINVAL, None));
    }
    publication_check(p).map_err(|err| (err, None))?;
    for (i, op) in p.operations.iter().enumerate() {
        operation_validate(op).map_err(|err| (err, Some(i)))?;
    }
    Ok(())
}

/// Whether a publication may follow the state the node recorded, None
/// for none, with `manifest_digest` its manifest's: the same tree, a
/// later generation unless it is the same manifest, the parent the node
/// recorded when it is the next generation and names one, and no head
/// before the node's cursor. 0, -EINVAL for another tree, -ERANGE, or
/// [`FOLLOWS_WALK`] when its base lies past the cursor, 0 without a
/// state, and the node must walk back through the sealed segments.
pub(crate) fn publication_follows(
    p: &TreePublication,
    state: Option<&TreeState>,
    manifest_digest: &[u8],
) -> c_int {
    let Some(s) = state else {
        return if p.base_seq != 0 { FOLLOWS_WALK } else { 0 };
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
    if p.head_seq < s.last_seq {
        return -ERANGE;
    }
    if p.base_seq > s.last_seq {
        FOLLOWS_WALK
    } else {
        0
    }
}

/// One step of the walk back: `pred`, whose manifest hashed to
/// `pred_manifest_digest`, is the sealed segment `succ` names, of the
/// same tree, ending where `succ` starts and of a lower generation. 0 or
/// -ERANGE.
pub(crate) fn segment_precedes(
    pred: &TreePublication,
    pred_manifest_digest: &[u8],
    succ: &TreePublication,
) -> c_int {
    if succ.base_seq <= 0
        || cstr(&succ.segment_manifest_digest) != pred_manifest_digest
        || cstr(&pred.tree_id) != cstr(&succ.tree_id)
        || pred.head_seq != succ.base_seq
        || pred.generation >= succ.generation
    {
        return -ERANGE;
    }
    0
}

/// The limit of that walk: 0 when a node whose cursor is `last_seq` may
/// walk back to a segment that starts at `base_seq`, [`MAX_JOIN_OPS`]
/// operations at most from 0 and [`MAX_WALK_OPS`] from any other
/// cursor; -E2BIG past it, -EINVAL for a negative number.
pub(crate) fn walk_within(base_seq: i64, last_seq: i64) -> c_int {
    let limit = if last_seq != 0 {
        MAX_WALK_OPS
    } else {
        MAX_JOIN_OPS
    };

    if base_seq < 0 || last_seq < 0 {
        return -EINVAL;
    }
    if base_seq - last_seq > limit {
        -E2BIG
    } else {
        0
    }
}

/// The history root at `seq` of a publication [`publication_check`]
/// takes: its base's, 32 zero bytes at 0, over the digests of its
/// operations up to `seq`. -EINVAL for a seq outside base to head or a
/// malformed root or digest.
pub(crate) fn history_at(p: &TreePublication, seq: i64) -> Result<[u8; 32], c_int> {
    let mut root = [0; 32];

    if seq < p.base_seq || seq > p.head_seq {
        return Err(-EINVAL);
    }
    if p.base_seq != 0 && hex::decode(cstr(&p.history_root), &mut root).is_err() {
        return Err(-EINVAL);
    }
    for op in p.operations.iter().take_while(|op| op.seq <= seq) {
        let digest = digest_bytes(&op.operation_digest).ok_or(-EINVAL)?;
        root = history_step(&root, &digest)?;
    }
    Ok(root)
}

#[cfg(shirudo_fuzz)]
mod fuzz;
#[cfg(test)]
mod tests;
