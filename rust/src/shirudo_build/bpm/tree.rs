// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `bpm tree append`: the [upatches.tree] entries of a built package
//! published as the next operations of the signed tree at a repository,
//! sealing the segment that holds them when it is full; and `bpm tree
//! show`, in show.rs. Each artifact is checked to be the directive its
//! operation claims, and an XDP upatch to share no device class with a
//! live one on nodes their selectors share, before anything is uploaded,
//! so that a target never meets an operation its own tree sync would
//! reject or fail.

use core::ffi::{CStr, c_char, c_int, c_void};
use core::ptr;

use super::beefile::{MAX_ENTRIES, MAX_FIXES, Spec, Upatch as BuildUpatch, fix_id_ok, parse};
use super::build::cstring;
use super::config_update::Info;
use super::publish::{
    EMPTY_CONFIG_MEDIA, MANIFEST_CAP, emit_descriptor, fail, push_blob, put_manifest, sign_detached,
};
use super::show::{self, Signer, fetch_sealed};
use super::{error, print};
use crate::errno::{
    E2BIG, EACCES, EBUSY, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT, ENOMEM, EOVERFLOW,
};
use crate::shirudo_build::{check_keys, key_path};
use crate::sys::curl::{CURL_GLOBAL_DEFAULT, curl_global_cleanup, curl_global_init};
use crate::text::cstr;
use crate::util::bpm_oci::{
    Client, Descriptor, MANIFEST_MEDIA, digest_matches, package_name_ok, trim,
};
use crate::util::bpm_package::{fetch_document, read_member_in, tree_manifest};
use crate::util::bpm_tree::{
    Extra, MAX_JOIN_OPS, MAX_OPS, MAX_VALUES, Publication, STRING_MAX, Text, TreeArtifact,
    TreeOperation, TreePublication, TreeSelector, count, digest_bytes, emit_publication,
    history_at, operation_digest, operation_validate, publication_verify, tree_parse,
    tree_publication_append, tree_selector_copy, tree_selector_free, walk_within,
};
use crate::util::bpm_tree_overlap::{add_live, add_withdrawn, selectors_disjoint};
use crate::util::help::{Help, HelpSection, is_help, print_help};
use crate::util::hex::{self, sha256_digest_encode};
use crate::util::json::{JsonArray, JsonEmit, JsonField, parse_schema};
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptName, OptParser, OptSpec};
use crate::util::paths::keys_dir_resolve;
use crate::util::upatch::{self, ProgSpec, specs_free, specs_parse, specs_xdp_classes};

const TREE_MEDIA: &CStr = c"application/vnd.shirudo.upatch.tree.v1+json";
const TREE_SIG_MEDIA: &CStr = c"application/vnd.shirudo.upatch.tree.signature.v1";
const UPATCH_MEDIA: &CStr = c"application/vnd.shirudo.upatch.v1";
const BEEFILE_MAX: usize = 4 * 1024 * 1024;
/// The operations a segment holds by default before it is sealed.
const SEGMENT_OPS: i64 = 64;

// One append never splits across segments, so it fits in one.
const _: () = assert!(MAX_ENTRIES <= MAX_OPS);

const APPEND_KEYS_DIR: c_int = 0;
const APPEND_KEY: c_int = 1;
const APPEND_CERT: c_int = 2;
const APPEND_PREVIOUS_CERT: c_int = 3;
const APPEND_TREE_ID: c_int = 4;
const APPEND_REFERENCE: c_int = 5;
const APPEND_OP: c_int = 6;
const APPEND_SEGMENT_OPS: c_int = 7;

static APPEND_OPTS: [OptSpec; 8] = [
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"read signing_key.pem and cert.der from <dir>",
    ),
    OptSpec::new(
        c"--key",
        0,
        0,
        Some(c"<signing_key.pem>"),
        c"the signing key, over --keys-dir",
    ),
    OptSpec::new(
        c"--cert",
        0,
        0,
        Some(c"<cert.der>"),
        c"the certificate, over --keys-dir",
    ),
    OptSpec::new(
        c"--previous-cert",
        0,
        0,
        Some(c"<cert.der>"),
        c"the certificate the tree was signed with so far",
    ),
    OptSpec::new(
        c"--tree-id",
        0,
        0,
        Some(c"<id>"),
        c"the tree to extend, which an existing tree needs",
    ),
    OptSpec::new(
        c"--reference",
        0,
        0,
        Some(c"<ref>"),
        c"the tag of the publication (default stable)",
    ),
    OptSpec::new(
        c"--op",
        0,
        0,
        Some(c"add|delete"),
        c"add the entries, or delete them (default add)",
    ),
    OptSpec::new(
        c"--segment-ops",
        0,
        0,
        Some(c"<n>"),
        c"seal a segment holding n operations and start the next, 1 to 512 (default 64)",
    ),
];

static APPEND_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &APPEND_OPTS)];

static APPEND_HELP: Help = Help::new(
    c"shirudo bpm tree append <package-file> <repository> [options]",
    Some(
        c"Publish the [upatches.tree] entries of a built package as the next\n\
          operations of the signed tree at <repository>:<ref>. The key defaults to\n\
          --keys-dir, SHIRUDO_KEYS_DIR or /var/lib/shirudo/keys.",
    ),
    &APPEND_SECTIONS,
    None,
);

/// Indexed by what each stands for, so that a value names itself.
static OPS: [OptName; 2] = [OptName::new(c"add", 0), OptName::new(c"delete", 1)];

fn err(msg: String) {
    error(msg.as_bytes());
}

fn lossy(s: &[u8]) -> String {
    String::from_utf8_lossy(s).into_owned()
}

fn copy(dst: &mut [u8], src: &[u8]) {
    dst.fill(0);
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
}

/// "sha256:<hex>" of `data`, the form a registry names a blob by.
fn sha256_digest(data: &[u8]) -> Result<Vec<u8>, c_int> {
    let d = crate::util::crypto_openssl::sha256(data).map_err(|_| -EINVAL)?;

    Ok(cstr(&sha256_digest_encode(&d)).to_vec())
}

/// Selector lists are sets: sorted, so equal Beefiles digest equally.
fn canonicalize(s: &mut TreeSelector) {
    let sort = |list: &mut [Text], n: c_int| {
        let n = count(n, MAX_VALUES);
        list[..n].sort_by(|a, b| cstr(a).cmp(cstr(b)));
    };
    sort(&mut s.kernel_release_prefix, s.n_kernel_release_prefix);
    sort(&mut s.kernel_build_id, s.n_kernel_build_id);
    sort(&mut s.architecture, s.n_architecture);
    for (kvs, n, max) in [
        (s.kconfig, s.n_kconfig, crate::util::bpm_tree::MAX_KCONFIG),
        (s.labels, s.n_labels, crate::util::bpm_tree::MAX_LABELS),
    ] {
        if kvs.is_null() {
            continue;
        }
        // SAFETY: the selector's pairs, which it alone holds and which
        // nothing else reaches while they are sorted.
        let kvs = unsafe { core::slice::from_raw_parts_mut(kvs, count(n, max)) };
        for kv in kvs {
            sort(&mut kv.values, kv.n_values);
        }
    }
}

/// An operation being made, its selector freed when it goes.
struct Operation(Box<TreeOperation>);

impl Operation {
    fn new() -> Self {
        // SAFETY: an all-zero operation is an empty one.
        Operation(Box::new(unsafe { core::mem::zeroed() }))
    }

    fn reset(&mut self, seq: i64) {
        // SAFETY: the operation's selector.
        unsafe { tree_selector_free(&mut self.0.selector) };
        // SAFETY: an all-zero operation is an empty one.
        *self.0 = unsafe { core::mem::zeroed() };
        self.0.seq = seq;
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        // SAFETY: the operation's selector.
        unsafe { tree_selector_free(&mut self.0.selector) };
    }
}

/// The deletes of the segments after the one being checked: an add stays
/// live until a delete of a later segment withdraws it.
#[derive(Default)]
struct Later(Vec<TreeOperation>);

impl Later {
    fn take(&mut self, p: &TreePublication) -> c_int {
        // SAFETY: the publication's operations.
        for op in unsafe { p.operations() } {
            if cstr(&op.op) != b"delete" {
                continue;
            }
            // SAFETY: an all-zero operation is an empty one.
            let mut d: TreeOperation = unsafe { core::mem::zeroed() };
            d.seq = op.seq;
            // SAFETY: the empty selector and the operation's.
            if unsafe { tree_selector_copy(&mut d.selector, &op.selector) } != 0 {
                return -ENOMEM;
            }
            copy(&mut d.op, cstr(&op.op));
            copy(&mut d.id, cstr(&op.id));
            self.0.push(d);
        }
        0
    }
}

impl Drop for Later {
    fn drop(&mut self) {
        for d in &mut self.0 {
            // SAFETY: the copy's selector, freed once.
            unsafe { tree_selector_free(&mut d.selector) };
        }
    }
}

/// The classes of a load upatch, none for one without an XDP program.
fn upatch_xdp_classes(body: &[u8]) -> Result<u32, c_int> {
    // SAFETY: an all-zero container is a closed one.
    let mut u: upatch::Upatch = unsafe { core::mem::zeroed() };
    // SAFETY: the bytes and the container to fill.
    match unsafe { upatch::upatch_open_memory(body.as_ptr().cast(), body.len(), &mut u) } {
        0 => {}
        err => return Err(err),
    }
    let mut specs: *mut ProgSpec = ptr::null_mut();
    let (nr_maps, nr_progs) = (u.hdr.nr_maps, u.hdr.nr_progs);
    let ret = if u.signed_attach.is_null() {
        -EINVAL
    } else {
        // SAFETY: the signed metadata of the open container, and room
        // for the specs.
        unsafe {
            specs_parse(
                u.signed_attach.cast(),
                u.signed_attach_len,
                nr_maps,
                nr_progs,
                &mut specs,
            )
        }
    };
    let classes = (ret == 0).then(|| {
        // SAFETY: the nr_progs specs specs_parse() gave, freed once.
        unsafe {
            let c = specs_xdp_classes(crate::ffi::slice(specs, nr_progs as usize));
            specs_free(specs, nr_progs);
            c
        }
    });
    // SAFETY: the container opened above.
    unsafe { upatch::upatch_close(&mut u) };
    classes.ok_or(ret)
}

/// The classes of the artifact of `op`, fetched from its repository,
/// another than the tree's included.
fn fetch_xdp_classes(
    c: &mut Client,
    repository: &[u8],
    repo_ref: &[u8],
    op: &TreeOperation,
) -> Result<u32, c_int> {
    let a = &op.artifact;
    if digest_bytes(&a.layer_digest).is_none() {
        return Err(-EINVAL);
    }
    let mut elsewhere = Client::new();
    let (client, repo) = if cstr(&a.repository) != repo_ref {
        let other = elsewhere.parse_tree_repo(cstr(&a.repository))?;
        (&mut elsewhere, other)
    } else {
        (c, repository.to_vec())
    };
    let url = client.url(&repo, b"blobs", cstr(&a.layer_digest))?;
    let blob = client.get(&url, UPATCH_MEDIA, true)?;
    let hex =
        hex::encode(&crate::util::crypto_openssl::sha256(blob.bytes()).map_err(|_| -EKEYREJECTED)?);
    if !digest_matches(cstr(&a.layer_digest), &hex) {
        return Err(-EKEYREJECTED);
    }
    upatch_xdp_classes(blob.bytes())
}

/// The classes of the operations of one publication, read once each.
struct Seen(Vec<Option<u32>>);

impl Seen {
    fn new() -> Self {
        Seen(vec![None; MAX_OPS])
    }
}

/// An artifact described for its operation and not uploaded yet.
struct Upload {
    body: Vec<u8>,
    tag: Vec<u8>,
    manifest: Vec<u8>,
}

/// A device runs one native XDP program. The second of two upatches that
/// select a class fails its load on every node with such a device, and
/// tree sync stops at the first operation that fails. `later` holds the
/// deletes published after `p`.
#[allow(clippy::too_many_arguments)]
fn refuse_shared_xdp_class(
    c: &mut Client,
    repository: &[u8],
    repo_ref: &[u8],
    p: &TreePublication,
    later: Option<&Later>,
    seen: &mut Seen,
    op: &TreeOperation,
    classes: u32,
) -> c_int {
    if classes == 0 {
        return 0;
    }
    // SAFETY: the publication's operations.
    let ops = unsafe { p.operations() };
    for (i, other) in ops.iter().enumerate() {
        // SAFETY: the operations and their selectors.
        let skip = cstr(&other.op) != b"add"
            || cstr(&other.id) == cstr(&op.id)
            || !unsafe { add_live(p, i) }
            || later.is_some_and(|l| unsafe { add_withdrawn(other, &l.0) })
            || unsafe { selectors_disjoint(&other.selector, &op.selector) };
        if skip {
            continue;
        }
        let theirs = match seen.0[i] {
            Some(c) => c,
            None => match fetch_xdp_classes(c, repository, repo_ref, other) {
                Ok(c) => {
                    seen.0[i] = Some(c);
                    c
                }
                Err(e) => {
                    err(format!(
                        "bpm tree append: cannot read the artifact of {} (seq {}) to compare its XDP device classes",
                        lossy(cstr(&other.id)),
                        other.seq
                    ));
                    return e;
                }
            },
        };
        if theirs & classes == 0 {
            continue;
        }
        err(format!(
            "bpm tree append: {} and {} (seq {}) both select XDP device classes {} on nodes their selectors share; a device runs one XDP program, so give each class to one upatch or the two selectors that exclude each other",
            lossy(cstr(&op.id)),
            lossy(cstr(&other.id)),
            other.seq,
            theirs & classes
        ));
        return -EBUSY;
    }
    0
}

/// The shared class check of an add over the sealed segments before
/// `cur`, back to seq 0: `sealed` when this append seals it, the others
/// fetched by digest. An add stays live until a delete of any later
/// segment withdraws it, so the deletes of every segment walked are kept.
#[allow(clippy::too_many_arguments)]
fn refuse_sealed_xdp_class(
    c: &mut Client,
    repository: &[u8],
    repo_ref: &[u8],
    cert: &CStr,
    cur: &TreePublication,
    sealed: Option<&TreePublication>,
    op: &TreeOperation,
    classes: u32,
) -> c_int {
    let within = walk_within(cur.base_seq, 0);
    if within != 0 {
        err(format!(
            "bpm tree append: a joining node walks back {} operations, past the limit of {MAX_JOIN_OPS}, so the XDP device classes of the sealed segments cannot be checked",
            cur.base_seq
        ));
        return within;
    }
    let mut later = Later::default();
    let mut ret = later.take(cur);
    let mut succ = Segment::Borrowed(cur);
    let mut given = sealed;
    while ret == 0 {
        let segment = match given.take() {
            Some(s) => Segment::Borrowed(s),
            None => {
                if succ.get().base_seq == 0 {
                    break;
                }
                let mut pred = Publication::new();
                if let Err(e) = fetch_sealed(
                    c,
                    repository,
                    Signer::Cert(cert),
                    succ.get(),
                    pred.get_mut(),
                ) {
                    err(format!(
                        "bpm tree append: the sealed segment {}, which ends at seq {}, does not verify",
                        lossy(cstr(&succ.get().segment_manifest_digest)),
                        succ.get().base_seq
                    ));
                    return e;
                }
                Segment::Owned(pred)
            }
        };
        let mut seen = Seen::new();
        ret = refuse_shared_xdp_class(
            c,
            repository,
            repo_ref,
            segment.get(),
            Some(&later),
            &mut seen,
            op,
            classes,
        );
        if ret == 0 {
            ret = later.take(segment.get());
        }
        succ = segment;
    }
    ret
}

/// A segment of a walk back: one the caller holds, or one fetched.
enum Segment<'a> {
    Borrowed(&'a TreePublication),
    Owned(Publication),
}

impl Segment<'_> {
    fn get(&self) -> &TreePublication {
        match self {
            Segment::Borrowed(p) => p,
            Segment::Owned(p) => p.get(),
        }
    }
}

/// The k of a segment-<k> tag: the tag.
fn segment_tag(k: u64) -> Vec<u8> {
    format!("segment-{k}").into_bytes()
}

/// The digest of the manifest segment-<k> tags, -ENOENT without the tag.
fn segment_tag_digest(c: &mut Client, repository: &[u8], k: u64) -> Result<Vec<u8>, c_int> {
    let url = c.url(repository, b"manifests", &segment_tag(k))?;
    let manifest = c.get(&url, MANIFEST_MEDIA, false)?;
    sha256_digest(manifest.bytes())
}

/// The k of the next segment-<k> tag: doubling, then halving, finds a k
/// without a tag in about 2 log2 k requests, so no tag is ever moved. 0
/// when the last tag already names the sealed manifest, which a run that
/// failed after tagging leaves behind.
fn next_segment_tag(c: &mut Client, repository: &[u8], sealed_digest: &[u8]) -> Result<u64, c_int> {
    let (mut present, mut absent) = (0u64, 1u64);
    let mut doubling = true;
    let mut last = Vec::new();

    while doubling || absent - present > 1 {
        let probe = if doubling {
            absent
        } else {
            present + (absent - present) / 2
        };
        match segment_tag_digest(c, repository, probe) {
            Err(e) if e == -ENOENT => {
                absent = probe;
                doubling = false;
                continue;
            }
            Err(e) => return Err(e),
            Ok(d) => {
                present = probe;
                last = d;
            }
        }
        if doubling {
            absent = absent.checked_mul(2).ok_or(-EOVERFLOW)?;
        }
    }
    Ok(if present != 0 && last == sealed_digest {
        0
    } else {
        absent
    })
}

/// The sealed manifest tagged segment-<k>, so that registry garbage
/// collection keeps it; nodes walk back to it by digest and never read
/// the tag.
fn tag_sealed(c: &mut Client, repository: &[u8], sealed_digest: &[u8]) -> c_int {
    let run = (|| -> Result<(), c_int> {
        let k = next_segment_tag(c, repository, sealed_digest)?;
        if k == 0 {
            return Ok(());
        }
        let url = c.url(repository, b"manifests", sealed_digest)?;
        let manifest = c.get(&url, MANIFEST_MEDIA, false)?;
        let hex = hex::encode(
            &crate::util::crypto_openssl::sha256(manifest.bytes()).map_err(|_| -EKEYREJECTED)?,
        );
        if !digest_matches(sealed_digest, &hex) {
            return Err(-EKEYREJECTED);
        }
        put_manifest(c, repository, &segment_tag(k), manifest.bytes()).map(|_| ())
    })();
    match run {
        Ok(()) => 0,
        Err(e) => {
            err(format!(
                "bpm tree append: cannot tag the sealed segment {}",
                lossy(sealed_digest)
            ));
            e
        }
    }
}

/// The segment after `sealed`, whose manifest is `sealed_digest`, as it
/// starts: at the sealed head, with the history root there.
fn start_segment(sealed: &TreePublication, sealed_digest: &[u8], p: &mut TreePublication) -> c_int {
    p.schema = 1;
    p.generation = sealed.generation;
    p.base_seq = sealed.head_seq;
    p.head_seq = sealed.head_seq;
    copy(&mut p.tree_id, cstr(&sealed.tree_id));
    copy(&mut p.segment_manifest_digest, sealed_digest);
    let mut root = [0u8; 32];
    // SAFETY: the sealed publication's operations.
    let ret = unsafe { history_at(sealed, sealed.head_seq, &mut root) };
    if ret == 0 {
        copy(&mut p.history_root, &hex::encode(&root));
    }
    ret
}

/// A new tree's id: the one --tree-id gives, else the package's at stable
/// and the package's with the reference elsewhere, so that a canary tree
/// one key publishes beside stable does not take stable's id, which an
/// append checks to tell the two apart.
fn new_id(tree_id: Option<&[u8]>, package: &[u8], reference: &[u8], out: &mut [u8]) -> c_int {
    let fits = |id: &[u8], out: &mut [u8]| {
        if id.len() < out.len() {
            copy(out, id);
            0
        } else {
            -E2BIG
        }
    };

    if let Some(t) = tree_id {
        return fits(t, out);
    }
    if reference == b"stable" {
        return fits(package, out);
    }
    let id = [package, b"-", reference].concat();
    if id.len() < out.len() && package_name_ok(&id) {
        copy(out, &id);
        return 0;
    }
    err(format!(
        "bpm tree append: {}-{} is no tree id; name the tree with --tree-id",
        lossy(package),
        lossy(reference)
    ));
    -EINVAL
}

/// A tree's fixes as the previous publication carried them: each
/// operation's sorted IDs, read back from its bytes, since tree_parse()
/// is the node's parser and keeps no key a node does not use.
struct FixesReader<'a> {
    ops: &'a [TreeOperation],
    fixes: Vec<Vec<Vec<u8>>>,
    fixes_field: *const JsonField,
    seq: i64,
    ids: Vec<Vec<u8>>,
    id: [u8; STRING_MAX],
}

fn fixes_valid(ids: &[Vec<u8>]) -> bool {
    !ids.is_empty() && ids.iter().all(|id| fix_id_ok(id)) && ids.windows(2).all(|w| w[0] < w[1])
}

unsafe extern "C" fn take_fix(ctx: *mut c_void) -> c_int {
    // SAFETY: the reader the parse is given.
    let r = unsafe { &mut *ctx.cast::<FixesReader<'_>>() };

    if r.ids.len() >= MAX_FIXES {
        return -E2BIG;
    }
    r.ids.push(cstr(&r.id).to_vec());
    0
}

unsafe extern "C" fn take_fixes_operation(ctx: *mut c_void) -> c_int {
    // SAFETY: the reader the parse is given.
    let r = unsafe { &mut *ctx.cast::<FixesReader<'_>>() };
    let n = r.fixes.len();

    let Some(op) = r.ops.get(n) else {
        return -EINVAL;
    };
    if r.seq != op.seq {
        return -EINVAL;
    }
    // SAFETY: the fixes field of the schema, which outlives the parse.
    let seen = unsafe { (*r.fixes_field).seen() };
    if seen && (cstr(&op.op) != b"add" || !fixes_valid(&r.ids)) {
        return -EINVAL;
    }
    let ids = core::mem::take(&mut r.ids);
    r.fixes.push(ids);
    r.seq = 0;
    0
}

/// The fixes of each operation of `p` from its document's bytes.
fn read_fixes(document: &[u8], p: &TreePublication) -> Result<Vec<Vec<Vec<u8>>>, c_int> {
    let mut r = Box::new(FixesReader {
        // SAFETY: the publication's operations.
        ops: unsafe { p.operations() },
        fixes: Vec::new(),
        fixes_field: ptr::null(),
        seq: 0,
        ids: Vec::new(),
        id: [0; STRING_MAX],
    });
    let ctx: *mut c_void = ptr::from_mut(&mut *r).cast();
    let mut id_sink = JsonArray::new(take_fix, ctx);
    let mut operation_sink = JsonArray::new(take_fixes_operation, ctx);
    let mut id = [JsonField::string(c"", r.id.as_mut_ptr(), STRING_MAX)];
    let mut operation = [
        JsonField::int(c"seq", &raw mut r.seq),
        JsonField::array(c"fixes", &raw mut id_sink, id.as_mut_ptr(), id.len()),
    ];
    r.fixes_field = &raw const operation[1];
    let mut root = [JsonField::array(
        c"operations",
        &raw mut operation_sink,
        operation.as_mut_ptr(),
        operation.len(),
    )];
    // SAFETY: the document's bytes, and a schema whose fields and sinks
    // point into the reader and the arrays here, which outlive the parse.
    let ret = unsafe { parse_schema(document, root.as_mut_ptr(), root.len()) };
    if ret != 0 {
        return Err(ret);
    }
    if r.fixes.len() != p.n_operations as usize {
        return Err(-EINVAL);
    }
    Ok(core::mem::take(&mut r.fixes))
}

/// One bpm tree append, filled in by its steps in turn.
struct Append<'a> {
    package: &'a CStr,
    raw_repository: &'a CStr,
    keys_dir_arg: Option<&'a CStr>,
    key: Option<std::ffi::CString>,
    cert: Option<std::ffi::CString>,
    previous_cert: Option<std::ffi::CString>,
    tree_id: Option<&'a [u8]>,
    reference: &'a [u8],
    segment_ops: i64,
    unload: bool,
    repo_ref: Vec<u8>,
    info: Option<Info>,
    spec: Spec,
    package_dir: Vec<u8>,
    entries: usize,
    c: Client,
    repository: Vec<u8>,
    previous: Option<Vec<u8>>,
    parent: Vec<u8>,
    publication: Publication,
    sealed: Option<Publication>,
    fixes: Vec<Vec<Vec<u8>>>,
    op: Operation,
    seen: Seen,
    uploads: Vec<Upload>,
    payload: Vec<u8>,
    sig: Vec<u8>,
}

/// The options, or EXIT_USAGE for a usage error, reported, or OPT_DONE
/// where help or the option list was printed.
fn parse_options<'a>(args: &'a [*const c_char]) -> Result<Append<'a>, c_int> {
    let mut p = OptParser::new(
        c"bpm tree append",
        &APPEND_OPTS,
        Some(&APPEND_HELP),
        args,
        2,
    );
    let mut a = Append {
        package: c"",
        raw_repository: c"",
        keys_dir_arg: None,
        key: None,
        cert: None,
        previous_cert: None,
        tree_id: None,
        reference: b"stable",
        segment_ops: SEGMENT_OPS,
        unload: false,
        repo_ref: Vec::new(),
        info: None,
        spec: Spec::default(),
        package_dir: Vec::new(),
        entries: 0,
        c: Client::new(),
        repository: Vec::new(),
        previous: None,
        parent: Vec::new(),
        publication: Publication::new(),
        sealed: None,
        fixes: Vec::new(),
        op: Operation::new(),
        seen: Seen::new(),
        uploads: Vec::new(),
        payload: Vec::new(),
        sig: Vec::new(),
    };
    let (mut package, mut raw_repository) = (None, None);

    loop {
        let opt = p.next();
        let value = p.value();
        let bytes = value.map_or(&b""[..], CStr::to_bytes);
        match opt {
            OPT_END => break,
            APPEND_KEYS_DIR => a.keys_dir_arg = value,
            APPEND_KEY => a.key = Some(cstring(bytes)),
            APPEND_CERT => a.cert = Some(cstring(bytes)),
            APPEND_PREVIOUS_CERT => a.previous_cert = Some(cstring(bytes)),
            APPEND_TREE_ID => {
                if !package_name_ok(bytes) {
                    p.usage(&[b"invalid --tree-id ", bytes].concat());
                    return Err(EXIT_USAGE);
                }
                a.tree_id = Some(bytes);
            }
            APPEND_REFERENCE => a.reference = bytes,
            APPEND_OP => match p.choice(&OPS) {
                Ok(delete) => a.unload = delete != 0,
                Err(_) => return Err(EXIT_USAGE),
            },
            APPEND_SEGMENT_OPS => match p.number(1, MAX_OPS as u64) {
                Ok(n) => a.segment_ops = n as i64,
                Err(_) => return Err(EXIT_USAGE),
            },
            OPT_ARG => {
                if raw_repository.is_some() {
                    p.usage_arg(b"unexpected argument ");
                    return Err(EXIT_USAGE);
                }
                if package.is_some() {
                    raw_repository = value;
                } else {
                    package = value;
                }
            }
            OPT_DONE => return Err(OPT_DONE),
            _ => return Err(EXIT_USAGE),
        }
    }
    let (Some(package), Some(raw_repository)) = (package, raw_repository) else {
        p.usage(b"takes <package-file> and <repository>");
        return Err(EXIT_USAGE);
    };
    a.package = package;
    a.raw_repository = raw_repository;
    Ok(a)
}

impl Append<'_> {
    fn key(&self) -> &CStr {
        self.key.as_deref().unwrap_or(c"")
    }

    fn cert(&self) -> &CStr {
        self.cert.as_deref().unwrap_or(c"")
    }

    fn previous_cert(&self) -> &CStr {
        self.previous_cert.as_deref().unwrap_or_else(|| self.cert())
    }

    fn signing_keys(&mut self) -> c_int {
        if self.key.is_none() || self.cert.is_none() {
            // SAFETY: NULL or a C string.
            let dir =
                unsafe { keys_dir_resolve(self.keys_dir_arg.map_or(ptr::null(), CStr::as_ptr)) };
            if self.key.is_none() {
                match key_path(dir, c"signing_key.pem") {
                    Ok(k) => self.key = Some(k),
                    Err(_) => return -EINVAL,
                }
            }
            if self.cert.is_none() {
                match key_path(dir, c"cert.der") {
                    Ok(c) => self.cert = Some(c),
                    Err(_) => return -EINVAL,
                }
            }
        }
        if check_keys(self.key(), self.cert()) != 0 {
            return -EACCES;
        }
        0
    }

    fn trim_repository(&mut self) -> c_int {
        let mut out = [0u8; super::MAX_ENDPOINT];
        if trim(self.raw_repository.to_bytes(), &mut out).is_err() {
            err(format!(
                "bpm tree append: repository is longer than {} bytes",
                super::MAX_ENDPOINT - 1
            ));
            return -ENAMETOOLONG;
        }
        self.repo_ref = cstr(&out).to_vec();
        0
    }

    fn read_package(&mut self) -> c_int {
        match Info::load(self.package) {
            Ok(i) => self.info = Some(i),
            Err(e) => return e,
        }
        let mut dir = [0u8; 101];
        let beefile =
            match read_member_in(self.package, b"Beefile", None, Some(&mut dir), BEEFILE_MAX) {
                Ok(m) => m,
                Err(e) => {
                    err(format!(
                        "bpm tree append: package {} does not include Beefile",
                        lossy(self.package.to_bytes())
                    ));
                    return e;
                }
            };
        self.package_dir = cstr(&dir).to_vec();
        let ret = parse(beefile.bytes(), &mut self.spec);
        if ret != 0 {
            err(format!(
                "bpm tree append: cannot parse the Beefile of {}",
                lossy(self.package.to_bytes())
            ));
            return ret;
        }
        self.entries = self.spec.upatches.iter().filter(|u| u.tree.present).count();
        0
    }

    fn seal_if_full(&mut self) -> c_int {
        let n = i64::from(self.publication.get().n_operations);
        if n >= self.segment_ops || n as usize + self.entries > MAX_OPS {
            let sealed = core::mem::replace(&mut self.publication, Publication::new());
            let ret = start_segment(sealed.get(), &self.parent, self.publication.get_mut());
            self.sealed = Some(sealed);
            return ret;
        }
        0
    }

    fn extend(&mut self) -> c_int {
        let pub_id = lossy(cstr(&self.publication.get().tree_id));
        // The registry chooses what the reference holds, another tree the
        // key signs among it: only the operator can say which tree the
        // signature it is about to make belongs to.
        let Some(tree_id) = self.tree_id else {
            err(format!(
                "bpm tree append: {}:{} holds tree {pub_id}; name the tree to extend with --tree-id",
                lossy(&self.repo_ref),
                lossy(self.reference)
            ));
            return -EINVAL;
        };
        if cstr(&self.publication.get().tree_id) != tree_id {
            err(format!(
                "bpm tree append: {}:{} holds tree {pub_id}, not {}; refusing to extend another tree",
                lossy(&self.repo_ref),
                lossy(self.reference),
                lossy(tree_id)
            ));
            return -EINVAL;
        }
        // SAFETY: the publication the parse filled.
        if let Err((e, _)) = unsafe { publication_verify(self.publication.get()) } {
            err(format!(
                "bpm tree append: the publication at {}:{} does not verify",
                lossy(&self.repo_ref),
                lossy(self.reference)
            ));
            return e;
        }
        let ret = self.seal_if_full();
        if ret != 0 {
            return ret;
        }
        let p = self.publication.get_mut();
        match p.generation.checked_add(1).filter(|&g| g != i64::MAX) {
            Some(g) => p.generation = g,
            None => {
                err("bpm tree append: the tree's generation is exhausted".into());
                return -EOVERFLOW;
            }
        }
        0
    }

    /// The next generation of the tree at the reference, or a new tree's
    /// first.
    fn head(&mut self) -> c_int {
        self.repository = match self.c.parse_push_repo(&self.repo_ref) {
            Ok(r) => r,
            Err(e) => {
                err("bpm tree append: the repository must be oci://registry/repository".into());
                return e;
            }
        };
        let previous_cert = self.previous_cert().to_owned();
        let fetched = fetch_document(
            &mut self.c,
            &self.repository,
            self.reference,
            Some(previous_cert.as_c_str()),
            None,
        );
        let mut ret = match fetched {
            Ok((doc, digest)) => {
                self.parent = digest;
                // SAFETY: the document's bytes, and the publication.
                let r = unsafe {
                    tree_parse(doc.as_ptr().cast(), doc.len(), self.publication.get_mut())
                };
                self.previous = Some(doc);
                r
            }
            Err(e) => e,
        };
        if ret == -ENOENT {
            self.publication = Publication::new();
            let p = self.publication.get_mut();
            p.schema = 1;
            p.generation = 1;
            self.parent.clear();
            let name = self
                .info
                .as_ref()
                .map(|i| cstr(&i.0.name).to_vec())
                .unwrap_or_default();
            ret = new_id(self.tree_id, &name, self.reference, &mut p.tree_id);
        } else if ret != 0 {
            err(format!(
                "bpm tree append: cannot read the publication at {}:{}",
                lossy(&self.repo_ref),
                lossy(self.reference)
            ));
        } else {
            ret = self.extend();
        }
        if ret != 0 {
            return ret;
        }
        let p = self.publication.get_mut();
        p.schema = 1;
        copy(&mut p.parent_manifest_digest, &self.parent);
        0
    }

    fn carry_fixes(&mut self) -> c_int {
        let n = (self.publication.get().n_operations as usize + self.spec.upatches.len())
            .clamp(1, MAX_OPS);
        self.fixes = vec![Vec::new(); n];
        if self.sealed.is_some() {
            return 0;
        }
        let Some(doc) = &self.previous else {
            return 0;
        };
        match read_fixes(doc, self.publication.get()) {
            Ok(carried) => {
                for (slot, ids) in self.fixes.iter_mut().zip(carried) {
                    *slot = ids;
                }
                0
            }
            Err(_) => {
                err(format!(
                    "bpm tree append: the publication at {}:{} has a fixes list bpm tree append would not write, so it cannot carry it into the next generation",
                    lossy(&self.repo_ref),
                    lossy(self.reference)
                ));
                -EINVAL
            }
        }
    }

    fn operation_start(&mut self, u: &BuildUpatch, seq: i64) -> c_int {
        self.op.reset(seq);
        let op = &mut self.op.0;
        copy(&mut op.op, if self.unload { b"delete" } else { b"add" });
        copy(&mut op.id, &u.tree.id);
        if let Some(sel) = &u.tree.selector {
            // SAFETY: the operation's empty selector and the Beefile's.
            let ret = unsafe { tree_selector_copy(&mut op.selector, &*sel.0) };
            if ret != 0 {
                return ret;
            }
        }
        canonicalize(&mut op.selector);
        0
    }

    fn refuse_xdp_classes(&mut self, id: &[u8], body: &[u8]) -> Result<u32, c_int> {
        let classes = upatch_xdp_classes(body).inspect_err(|_| {
            err(format!(
                "bpm tree append: {} is not a valid upatch",
                lossy(id)
            ));
        })?;
        let ret = refuse_shared_xdp_class(
            &mut self.c,
            &self.repository,
            &self.repo_ref,
            self.publication.get(),
            None,
            &mut self.seen,
            &self.op.0,
            classes,
        );
        if ret != 0 {
            return Err(ret);
        }
        if classes != 0 {
            let cert = self.previous_cert().to_owned();
            let ret = refuse_sealed_xdp_class(
                &mut self.c,
                &self.repository,
                &self.repo_ref,
                cert.as_c_str(),
                self.publication.get(),
                self.sealed.as_ref().map(Publication::get),
                &self.op.0,
                classes,
            );
            if ret != 0 {
                return Err(ret);
            }
        }
        Ok(classes)
    }

    /// One immutable upatch artifact described for the tree, with the
    /// manifest its upload will put, once its bytes are checked to be the
    /// directive the operation claims: its name, and load or unload.
    fn describe_artifact(&mut self, body: Vec<u8>, id: &[u8]) -> Result<Upload, c_int> {
        // SAFETY: an all-zero container is a closed one.
        let mut u: upatch::Upatch = unsafe { core::mem::zeroed() };
        // SAFETY: the bytes and the container to fill.
        let ret = unsafe { upatch::upatch_open_memory(body.as_ptr().cast(), body.len(), &mut u) };
        if ret != 0 {
            err(format!(
                "bpm tree append: {} is not a valid upatch",
                lossy(id)
            ));
            return Err(ret);
        }
        let mut name = [0u8; upatch::NAME_MAX + 1];
        upatch::header_name(&u, &mut name);
        let payload = u.hdr.payload_sha256;
        let is_unload = upatch::is_unload(&u);
        // SAFETY: the container opened above.
        unsafe { upatch::upatch_close(&mut u) };
        if cstr(&name) != id || is_unload != self.unload {
            err(format!(
                "bpm tree append: the {} artifact for {} is {} directive named {}",
                if self.unload { "unload" } else { "load" },
                lossy(id),
                if is_unload { "an unload" } else { "a load" },
                lossy(cstr(&name))
            ));
            return Err(-EKEYREJECTED);
        }
        let hex = hex::encode(&payload);
        let tag = [b"upatch-", id, b"-", &hex[..16]].concat();
        let title = [id, b".upatch"].concat();
        if tag.len() > 128 || title.len() >= upatch::NAME_MAX + 16 {
            return Err(-ENAMETOOLONG);
        }
        let layer = Descriptor::of(
            UPATCH_MEDIA.to_bytes(),
            &sha256_digest(&body)?,
            body.len() as i64,
        );
        let config = Descriptor::of(EMPTY_CONFIG_MEDIA.to_bytes(), &sha256_digest(b"{}")?, 2);
        let mut buf = vec![0u8; MANIFEST_CAP];
        let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len());
        e.obj_open();
        e.kv_int(b"schemaVersion", 2);
        e.kv_string(b"mediaType", MANIFEST_MEDIA.to_bytes());
        e.kv_string(b"artifactType", UPATCH_MEDIA.to_bytes());
        emit_descriptor(&mut e, Some(c"config"), &config, None);
        e.arr_open(b"layers");
        emit_descriptor(&mut e, None, &layer, None);
        e.arr_close();
        e.obj_open_key(b"annotations");
        e.kv_string(b"org.opencontainers.image.title", &title);
        e.obj_close();
        e.obj_close();
        if e.err() != 0 {
            return Err(e.err());
        }
        buf.truncate(e.written());
        let a: &mut TreeArtifact = &mut self.op.0.artifact;
        copy(&mut a.manifest_digest, &sha256_digest(&buf)?);
        copy(&mut a.payload_sha256, cstr(&sha256_digest_encode(&payload)));
        copy(&mut a.repository, &self.repo_ref);
        copy(&mut a.layer_digest, layer.digest());
        Ok(Upload {
            body,
            tag,
            manifest: buf,
        })
    }

    fn commit(&mut self, u: &BuildUpatch, classes: u32) -> c_int {
        let op = &mut self.op.0;
        // SAFETY: the operation, its selector as its counts say.
        let digest = unsafe { operation_digest(op) };
        let ret = match digest {
            Ok(d) => {
                copy(&mut op.operation_digest, cstr(&d));
                // SAFETY: as above.
                unsafe { operation_validate(op) }
            }
            Err(e) => e,
        };
        if ret != 0 {
            err(format!(
                "bpm tree append: the tree entry of {} makes an operation no target takes",
                lossy(&u.tree.id)
            ));
            return ret;
        }
        let p = self.publication.get_mut();
        // SAFETY: the publication and the operation, which it copies.
        let ret = unsafe { tree_publication_append(p, &*self.op.0) };
        if ret != 0 {
            return ret;
        }
        let n = p.n_operations as usize - 1;
        self.seen.0[n] = Some(classes);
        if !self.unload {
            self.fixes[n].clone_from(&u.tree.fixes);
        }
        p.head_seq = self.op.0.seq;
        0
    }

    fn entry(&mut self, u: &BuildUpatch) -> c_int {
        let Some(seq) = self
            .publication
            .get()
            .head_seq
            .checked_add(1)
            .filter(|&s| s != i64::MAX)
        else {
            err("bpm tree append: the tree's sequence is exhausted".into());
            return -EOVERFLOW;
        };
        let member = if self.unload {
            &u.tree.unload_artifact
        } else {
            &u.tree.load_artifact
        };
        let body = match read_member_in(
            self.package,
            member,
            Some(&self.package_dir),
            None,
            upatch::FILE_MAX,
        ) {
            Ok(m) => m.bytes().to_vec(),
            Err(e) => {
                err(format!(
                    "bpm tree append: package entry {} not found",
                    lossy(member)
                ));
                return e;
            }
        };
        let mut ret = self.operation_start(u, seq);
        let mut classes = 0;
        if ret == 0 && !self.unload {
            match self.refuse_xdp_classes(&u.tree.id, &body) {
                Ok(c) => classes = c,
                Err(e) => ret = e,
            }
        }
        if ret != 0 {
            return ret;
        }
        match self.describe_artifact(body, &u.tree.id) {
            Ok(up) => self.uploads.push(up),
            Err(e) => return e,
        }
        self.commit(u, classes)
    }

    fn operations(&mut self) -> c_int {
        let spec = core::mem::take(&mut self.spec);
        let mut ret = 0;
        for u in spec.upatches.iter().filter(|u| u.tree.present) {
            ret = self.entry(u);
            if ret != 0 {
                break;
            }
        }
        self.spec = spec;
        if ret != 0 {
            return ret;
        }
        if self.uploads.is_empty() {
            err(format!(
                "bpm tree append: {} has no [upatches.tree] entries",
                lossy(self.package.to_bytes())
            ));
            return -ENOENT;
        }
        0
    }

    fn sign(&mut self) -> c_int {
        let fixes = &self.fixes;
        let mut emit_fixes = |e: &mut JsonEmit, index: usize| {
            if let Some(ids) = fixes.get(index).filter(|ids| !ids.is_empty()) {
                e.arr_open(b"fixes");
                for id in ids {
                    e.str(id);
                }
                e.arr_close();
            }
            0
        };
        let extra: Extra<'_> = &mut emit_fixes;
        // SAFETY: the publication, its operations and their pairs.
        let emitted = unsafe { emit_publication(self.publication.get(), Some(extra)) };
        let (body, cap, len) = match emitted {
            Ok(b) => b,
            Err(e) => return e,
        };
        // SAFETY: the len bytes emitted, copied, then the buffer freed.
        unsafe {
            self.payload = crate::ffi::slice(body.cast::<u8>(), len).to_vec();
            crate::heap::xfree(body.cast(), cap);
        }
        match sign_detached(&self.payload, (self.key(), self.cert())) {
            Ok(sig) => {
                self.sig = sig;
                0
            }
            Err(e) => e,
        }
    }

    fn upload_artifacts(&mut self) -> c_int {
        for up in &self.uploads {
            let run = (|| {
                push_blob(&mut self.c, &self.repository, &up.body, UPATCH_MEDIA)?;
                push_blob(&mut self.c, &self.repository, b"{}", EMPTY_CONFIG_MEDIA)?;
                put_manifest(&mut self.c, &self.repository, &up.tag, &up.manifest)
            })();
            if let Err(e) = run {
                return e;
            }
        }
        0
    }

    fn push_document(&mut self) -> c_int {
        let run = (|| {
            push_blob(&mut self.c, &self.repository, b"{}", EMPTY_CONFIG_MEDIA)?;
            let payload = push_blob(&mut self.c, &self.repository, &self.payload, TREE_MEDIA)?;
            let sig = push_blob(&mut self.c, &self.repository, &self.sig, TREE_SIG_MEDIA)?;
            let manifest = tree_manifest(&payload, &sig)?;
            if self.sealed.is_some() {
                match tag_sealed(&mut self.c, &self.repository, &self.parent) {
                    0 => {}
                    e => return Err(e),
                }
            }
            put_manifest(&mut self.c, &self.repository, self.reference, &manifest)
        })();
        match run {
            Ok(digest) => {
                let line = [
                    b"oci://",
                    self.c.registry(),
                    b"/",
                    &self.repository,
                    b":",
                    self.reference,
                    b" ",
                    &digest,
                    b"\n",
                ]
                .concat();
                print(true, &line);
                0
            }
            Err(e) => e,
        }
    }

    fn publish(&mut self) -> c_int {
        let ret = self.sign();
        if ret != 0 {
            return ret;
        }
        // Nothing is uploaded before all of it is known to be publishable.
        let ret = self.upload_artifacts();
        if ret != 0 {
            return ret;
        }
        self.push_document()
    }

    fn run(&mut self) -> c_int {
        for step in [
            Self::signing_keys,
            Self::trim_repository,
            Self::read_package,
            Self::head,
            Self::carry_fixes,
            Self::operations,
            Self::publish,
        ] {
            let ret = step(self);
            if ret != 0 {
                return ret;
            }
        }
        0
    }
}

fn append(args: &[*const c_char]) -> c_int {
    match parse_options(args) {
        Ok(mut a) => a.run(),
        Err(OPT_DONE) => 0,
        Err(e) => e,
    }
}

/// `bpm tree`, from `tree` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let raw: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();

    if args.get(1).map(|a| a.to_bytes()) == Some(b"show") {
        return show::run(&raw[1..]);
    }
    if args.get(1).map(|a| a.to_bytes()) != Some(b"append") {
        // SAFETY: the command's help, of C strings.
        unsafe { print_help(&APPEND_HELP) };
        return if args.len() >= 2 && is_help(Some(args[1].to_bytes())) {
            0
        } else {
            EXIT_USAGE
        };
    }
    // SAFETY: once, before any transfer.
    if unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) } != 0 {
        return fail("initialize curl", -EIO);
    }
    let ret = append(&raw);
    // SAFETY: after every transfer.
    unsafe { curl_global_cleanup() };
    if ret == EXIT_USAGE {
        return EXIT_USAGE;
    }
    if ret != 0 {
        fail("tree append", ret)
    } else {
        0
    }
}
