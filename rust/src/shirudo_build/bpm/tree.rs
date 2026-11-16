// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `bpm tree append`: the [upatches.tree] entries of a built package
//! published as the next operations of the signed tree at a repository.
//! Each artifact is checked to be the directive its operation claims
//! before anything is uploaded, so a target never meets an operation its
//! own tree verification would reject.

use core::ffi::{CStr, c_int};
use core::ptr;
use std::io::Write;

use super::beefile::{Spec, parse};
use super::build::cstring;
use super::config_update::Info;
use super::publish::{
    EMPTY_CONFIG_MEDIA, MANIFEST_CAP, artifact_manifest, emit_descriptor, fail, push_blob,
    put_manifest, sign_detached,
};
use super::{error, hex, print};
use crate::errno::{E2BIG, EACCES, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT, EOVERFLOW};
use crate::shirudo_build::{check_keys, key_path};
use crate::sys::curl::{CURL_GLOBAL_DEFAULT, curl_global_cleanup, curl_global_init};
use crate::sys::paths::keys_dir_resolve;
use crate::util::bpm_oci::{Client, MANIFEST_MEDIA, package_name_ok, trim};
use crate::util::bpm_package::{fetch_publication, read_member_in};
use crate::util::bpm_tree::{
    MAX_VALUES, Text, TreeArtifact, TreeOperation, TreePublication, TreeSelector, count,
    tree_emit_publication, tree_operation_digest, tree_publication_append, tree_publication_free,
    tree_selector_copy, tree_selector_free,
};
use crate::util::json::JsonEmit;
use crate::util::upatch;

const TREE_MEDIA: &CStr = c"application/vnd.shirudo.upatch.tree.v1+json";
const TREE_SIG_MEDIA: &CStr = c"application/vnd.shirudo.upatch.tree.signature.v1";
const TREE_ARTIFACT: &[u8] = b"application/vnd.shirudo.upatch.tree.v1";
const UPATCH_MEDIA: &CStr = c"application/vnd.shirudo.upatch.v1";
const MAX_HTTP_BODY: usize = 256 * 1024 * 1024;
const BEEFILE_MAX: usize = 4 * 1024 * 1024;

fn usage() {
    print(
        false,
        b"usage: shirudo bpm tree append <package-file> <repository>
                               [--keys-dir <dir>] [--key <signing_key.pem>]
                               [--cert <cert.der>] [--tree-id <id>]
                               [--reference <ref>] [--op add|delete]

Publishes the [upatches.tree] entries of a built package as the next
operations of the signed tree at <repository>:<ref> (default stable).
The key defaults to --keys-dir, SHIRUDO_KEYS_DIR or /var/lib/shirudo/keys.
",
    );
}

fn copy(dst: &mut [u8], src: &[u8]) {
    dst.fill(0);
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
}

/// Selector lists are sets: sorted, so equal Beefiles digest equally.
fn canonicalize(s: &mut TreeSelector) {
    let sort = |list: &mut [Text], n: c_int| {
        let n = (n.max(0) as usize).min(MAX_VALUES);
        list[..n].sort_by(|a, b| crate::text::cstr(a).cmp(crate::text::cstr(b)));
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

/// Publishes one immutable upatch artifact and describes it for the
/// tree, once its bytes are checked to be the directive the operation
/// claims: its name and load versus unload.
fn push_artifact(
    c: &mut Client,
    repo: &[u8],
    raw_repo: &[u8],
    body: &[u8],
    id: &[u8],
    unload: bool,
    out: &mut TreeArtifact,
) -> c_int {
    let shown_id = String::from_utf8_lossy(id).into_owned();
    let mut tmpl = *b"/tmp/shirudo-bpm-tree-XXXXXX\0";
    // SAFETY: the template, which mkstemp() fills in.
    let fd = unsafe { crate::sys::libc::mkstemp(tmpl.as_mut_ptr().cast()) };
    if fd < 0 {
        return super::last_err();
    }
    // SAFETY: the descriptor mkstemp() opened, the file's from here.
    let mut file = unsafe { <std::fs::File as std::os::fd::FromRawFd>::from_raw_fd(fd) };
    let mut ret = file
        .write_all(body)
        .map_or_else(|e| -e.raw_os_error().unwrap_or(EIO), |()| 0);
    drop(file);
    // SAFETY: an all-zero container is a closed one.
    let mut u: upatch::Upatch = unsafe { core::mem::zeroed() };
    if ret == 0 {
        // SAFETY: the temporary's path and the container to fill.
        ret = unsafe { upatch::upatch_open(tmpl.as_ptr().cast(), &mut u) };
    }
    let _ = std::fs::remove_file(super::path(crate::text::cstr(&tmpl)));
    if ret != 0 {
        error(format!("bpm tree append: {shown_id} is not a valid upatch").as_bytes());
        return ret;
    }
    let mut name = [0u8; upatch::NAME_MAX + 1];
    upatch::header_name(&u, &mut name);
    let digest = hex(&u.hdr.payload_sha256);
    let name = crate::text::cstr(&name).to_vec();
    let mismatch = name != id || upatch::is_unload(&u) != unload;
    // SAFETY: the container opened above.
    unsafe { upatch::upatch_close(&mut u) };
    if mismatch {
        let (is, other) = if unload {
            ("unload", "load")
        } else {
            ("load", "unload")
        };
        error(
            format!(
                "bpm tree append: the {is} artifact for {shown_id} is a {other} directive named {}",
                String::from_utf8_lossy(&name)
            )
            .as_bytes(),
        );
        return -EKEYREJECTED;
    }
    let tag = [b"upatch-", id, b"-", &digest[..16]].concat();
    let title = [id, b".upatch"].concat();
    if tag.len() > 128 || title.len() >= upatch::NAME_MAX + 16 {
        return -ENAMETOOLONG;
    }
    let result = (|| {
        let layer = push_blob(c, repo, body, UPATCH_MEDIA)?;
        let config = push_blob(c, repo, b"{}", EMPTY_CONFIG_MEDIA)?;
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
        let manifest_digest = put_manifest(c, repo, &tag, &buf)?;
        Ok((manifest_digest, layer))
    })();
    let (manifest_digest, layer) = match result {
        Ok(r) => r,
        Err(err) => return err,
    };
    copy(&mut out.manifest_digest, &manifest_digest);
    copy(&mut out.repository, raw_repo);
    copy(&mut out.layer_digest, layer.digest());
    let payload = [b"sha256:", &digest[..]].concat();
    if payload.len() >= out.payload_sha256.len() {
        return -E2BIG;
    }
    copy(&mut out.payload_sha256, &payload);
    0
}

/// A publication, freed when it goes.
struct Publication(Box<TreePublication>);

impl Drop for Publication {
    fn drop(&mut self) {
        // SAFETY: the publication, its operations from the tree code.
        unsafe { tree_publication_free(&mut *self.0) };
    }
}

/// An operation being made, its selector freed when it goes.
struct Operation(Box<TreeOperation>);

impl Operation {
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

struct Options<'a> {
    package: &'a CStr,
    raw_repo: &'a CStr,
    key: Vec<u8>,
    cert: Vec<u8>,
    tree_id: Option<&'a CStr>,
    reference: &'a [u8],
    operation: &'a [u8],
}

fn options<'a>(args: &[&'a CStr]) -> Result<Options<'a>, c_int> {
    let (mut package, mut raw_repo, mut keys_dir, mut key, mut cert, mut tree_id) =
        (None, None, None, None, None, None);
    let (mut reference, mut operation): (&[u8], &[u8]) = (b"stable", b"add");
    let mut i = 2;

    while i < args.len() {
        let a = args[i];
        let b = a.to_bytes();
        let next = args.get(i + 1).copied();
        let tail = |prefix: &[u8]| {
            b.strip_prefix(prefix).and_then(|_| {
                CStr::from_bytes_with_nul(&a.to_bytes_with_nul()[prefix.len()..]).ok()
            })
        };
        let mut took = false;
        let mut take = |name: &[u8], slot: &mut Option<&'a CStr>| {
            if b == name {
                if let Some(v) = next {
                    *slot = Some(v);
                    took = true;
                    return true;
                }
            }
            let eq = [name, b"="].concat();
            if let Some(v) = tail(&eq) {
                *slot = Some(v);
                return true;
            }
            false
        };
        let (mut r, mut o) = (None, None);
        let matched = take(b"--keys-dir", &mut keys_dir)
            || take(b"--key", &mut key)
            || take(b"--cert", &mut cert)
            || take(b"--tree-id", &mut tree_id)
            || take(b"--reference", &mut r)
            || take(b"--op", &mut o);
        if let Some(r) = r {
            reference = r.to_bytes();
        }
        if let Some(o) = o {
            operation = o.to_bytes();
        }
        if !matched {
            if b.first() == Some(&b'-') || (package.is_some() && raw_repo.is_some()) {
                usage();
                return Err(-EINVAL);
            }
            if package.is_none() {
                package = Some(a);
            } else {
                raw_repo = Some(a);
            }
        }
        i += if took { 2 } else { 1 };
    }
    let (Some(package), Some(raw_repo)) = (package, raw_repo) else {
        usage();
        return Err(-EINVAL);
    };
    if operation != b"add" && operation != b"delete" {
        error(b"bpm tree append: --op must be add or delete");
        return Err(-EINVAL);
    }
    if let Some(t) = tree_id.filter(|t| !package_name_ok(t.to_bytes())) {
        error(&[b"bpm tree append: invalid --tree-id ", t.to_bytes()].concat());
        return Err(-EINVAL);
    }
    let (mut key_out, mut cert_out) = (
        key.map(|k| k.to_bytes().to_vec()),
        cert.map(|c| c.to_bytes().to_vec()),
    );
    if key_out.is_none() || cert_out.is_none() {
        // SAFETY: NULL or a C string.
        let dir = unsafe { keys_dir_resolve(keys_dir.map_or(ptr::null(), CStr::as_ptr)) };
        if key_out.is_none() {
            key_out = Some(
                key_path(dir, c"signing_key.pem")
                    .map_err(|_| -EINVAL)?
                    .into_bytes(),
            );
        }
        if cert_out.is_none() {
            cert_out = Some(
                key_path(dir, c"cert.der")
                    .map_err(|_| -EINVAL)?
                    .into_bytes(),
            );
        }
    }
    Ok(Options {
        package,
        raw_repo,
        key: key_out.unwrap_or_default(),
        cert: cert_out.unwrap_or_default(),
        tree_id,
        reference,
        operation,
    })
}

fn append(args: &[&CStr]) -> c_int {
    let o = match options(args) {
        Ok(o) => o,
        Err(err) => return err,
    };
    let unload = o.operation == b"delete";
    let (key, cert) = (cstring(&o.key), cstring(&o.cert));
    if check_keys(&key, &cert) != 0 {
        return -EACCES;
    }
    let mut repo_ref = [0u8; super::MAX_ENDPOINT];
    if trim(o.raw_repo.to_bytes(), &mut repo_ref).is_err() {
        error(
            format!(
                "bpm tree append: repository is longer than {} bytes",
                super::MAX_ENDPOINT - 1
            )
            .as_bytes(),
        );
        return -ENAMETOOLONG;
    }
    let repo_ref = crate::text::cstr(&repo_ref).to_vec();
    let info = match Info::load(o.package) {
        Ok(i) => i,
        Err(err) => return err,
    };
    let mut package_dir = [0u8; 101];
    let beefile = match read_member_in(
        o.package,
        b"Beefile",
        None,
        Some(&mut package_dir),
        BEEFILE_MAX,
    ) {
        Ok(m) => m,
        Err(err) => {
            error(
                format!(
                    "bpm tree append: package {} does not include Beefile",
                    String::from_utf8_lossy(o.package.to_bytes())
                )
                .as_bytes(),
            );
            return err;
        }
    };
    let package_dir = crate::text::cstr(&package_dir).to_vec();
    let mut spec = Spec::default();
    let ret = parse(beefile.bytes(), &mut spec);
    if ret != 0 {
        error(
            format!(
                "bpm tree append: cannot parse the Beefile of {}",
                String::from_utf8_lossy(o.package.to_bytes())
            )
            .as_bytes(),
        );
        return ret;
    }
    let mut c = Client::new();
    let repo = match c.parse_push_repo(&repo_ref) {
        Ok(r) => r,
        Err(err) => {
            error(b"bpm tree append: the repository must be oci://registry/repository");
            return err;
        }
    };
    // SAFETY: an all-zero publication is an empty one.
    let mut publ = Publication(Box::new(unsafe { core::mem::zeroed() }));
    let mut parent = [0u8; 128];
    let ret = fetch_publication(&mut c, &repo, o.reference, &cert, &mut publ.0, &mut parent);
    let cstr = crate::text::cstr;
    if ret == -ENOENT {
        // SAFETY: the publication, freed and made empty.
        unsafe { tree_publication_free(&mut *publ.0) };
        // SAFETY: an all-zero publication is an empty one.
        *publ.0 = unsafe { core::mem::zeroed() };
        publ.0.schema = 1;
        publ.0.generation = 1;
        parent = [0; 128];
        if let Some(t) = o.tree_id {
            copy(&mut publ.0.tree_id, t.to_bytes());
        }
    } else if ret != 0 {
        error(
            format!(
                "bpm tree append: cannot read the publication at {}:{}",
                String::from_utf8_lossy(&repo_ref),
                String::from_utf8_lossy(o.reference)
            )
            .as_bytes(),
        );
        return ret;
    } else {
        if let Some(t) = o.tree_id.filter(|t| cstr(&publ.0.tree_id) != t.to_bytes()) {
            error(
                format!(
                    "bpm tree append: tree id mismatch: existing {}, requested {}",
                    String::from_utf8_lossy(cstr(&publ.0.tree_id)),
                    String::from_utf8_lossy(t.to_bytes())
                )
                .as_bytes(),
            );
            return -EINVAL;
        }
        match publ.0.generation.checked_add(1).filter(|&g| g != i64::MAX) {
            Some(g) => publ.0.generation = g,
            None => {
                error(b"bpm tree append: the tree's generation is exhausted");
                return -EOVERFLOW;
            }
        }
    }
    publ.0.schema = 1;
    if publ.0.tree_id[0] == 0 {
        copy(&mut publ.0.tree_id, cstr(&info.0.name));
    }
    copy(&mut publ.0.parent_manifest_digest, cstr(&parent));

    // SAFETY: an all-zero operation is an empty one.
    let mut op = Operation(Box::new(unsafe { core::mem::zeroed() }));
    let mut appended = 0;
    for u in spec.upatches.iter().filter(|u| u.tree.present) {
        let Some(seq) = publ.0.head_seq.checked_add(1).filter(|&s| s != i64::MAX) else {
            error(b"bpm tree append: the tree's sequence is exhausted");
            return -EOVERFLOW;
        };
        let member = if unload {
            &u.tree.unload_artifact
        } else {
            &u.tree.load_artifact
        };
        let body = match read_member_in(o.package, member, Some(&package_dir), None, MAX_HTTP_BODY)
        {
            Ok(m) => m,
            Err(err) => {
                error(
                    &[
                        b"bpm tree append: package entry ",
                        &member[..],
                        b" not found",
                    ]
                    .concat(),
                );
                return err;
            }
        };
        op.reset(seq);
        copy(&mut op.0.op, o.operation);
        copy(&mut op.0.id, &u.tree.id);
        if let Some(sel) = &u.tree.selector {
            // SAFETY: the operation's empty selector and the Beefile's.
            let ret = unsafe { tree_selector_copy(&mut op.0.selector, &*sel.0) };
            if ret != 0 {
                return ret;
            }
        }
        canonicalize(&mut op.0.selector);
        let ret = push_artifact(
            &mut c,
            &repo,
            &repo_ref,
            body.bytes(),
            &u.tree.id,
            unload,
            &mut op.0.artifact,
        );
        if ret != 0 {
            return ret;
        }
        let mut digest = [0u8; 72];
        // SAFETY: the operation and room for its digest.
        let mut ret = unsafe { tree_operation_digest(&*op.0, &mut digest) };
        if ret == 0 {
            copy(&mut op.0.operation_digest, cstr(&digest));
            // SAFETY: the publication and the operation, which it copies.
            ret = unsafe { tree_publication_append(&mut *publ.0, &*op.0) };
        }
        if ret != 0 {
            return ret;
        }
        publ.0.head_seq = op.0.seq;
        appended += 1;
    }
    if appended == 0 {
        error(
            format!(
                "bpm tree append: {} has no [upatches.tree] entries",
                String::from_utf8_lossy(o.package.to_bytes())
            )
            .as_bytes(),
        );
        return -ENOENT;
    }
    let (mut payload, mut len): (*mut core::ffi::c_char, usize) = (ptr::null_mut(), 0);
    // SAFETY: the publication and room for its JSON and length.
    let ret = unsafe { tree_emit_publication(&*publ.0, &mut payload, &mut len) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: the JSON's len bytes.
    let body = unsafe { crate::ffi::slice(payload.cast::<u8>(), len) }.to_vec();
    // SAFETY: the JSON tree_emit_publication() allocated.
    unsafe { crate::sys::malloc::xfree(payload.cast(), len) };
    let result = (|| {
        let sig = sign_detached(&body, (&key, &cert))?;
        let config = push_blob(&mut c, &repo, b"{}", EMPTY_CONFIG_MEDIA)?;
        let payload_layer = push_blob(&mut c, &repo, &body, TREE_MEDIA)?;
        let sig_layer = push_blob(&mut c, &repo, &sig, TREE_SIG_MEDIA)?;
        let manifest = artifact_manifest(TREE_ARTIFACT, &config, &[&payload_layer, &sig_layer])?;
        put_manifest(&mut c, &repo, o.reference, &manifest)
    })();
    match result {
        Ok(digest) => {
            let line = [
                b"oci://",
                c.registry(),
                b"/",
                &repo,
                b":",
                o.reference,
                b" ",
                &digest,
                b"\n",
            ]
            .concat();
            print(true, &line);
            0
        }
        Err(err) => err,
    }
}

/// `bpm tree`, from `tree` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    if args.get(1).map(|a| a.to_bytes()) != Some(b"append") {
        usage();
        return if args.len() >= 2 && super::is_help(args[1].to_bytes()) {
            0
        } else {
            2
        };
    }
    if args.len() == 3 && super::is_help(args[2].to_bytes()) {
        usage();
        return 0;
    }
    // SAFETY: once, before any transfer.
    if unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) } != 0 {
        return fail("initialize curl", -EIO);
    }
    let ret = append(args);
    // SAFETY: after every transfer.
    unsafe { curl_global_cleanup() };
    if ret != 0 {
        fail("tree append", ret)
    } else {
        0
    }
}
