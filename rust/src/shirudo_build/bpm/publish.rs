// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `bpm push`: a package published to an OCI registry, by digest first
//! and by version last; its certificate as an OCI referrer, which `bpm
//! key add` fetches without the package; and, with signing material, its
//! entry in the signed index beside the repository's namespace. Also the
//! OCI writing `bpm tree append` shares.

use core::ffi::{CStr, c_int};
use core::ptr;

use super::build::cstring;
use super::config_update::Info;
use super::{archive, error, print, strerr};
use crate::errno::{E2BIG, EEXIST, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT};
use crate::shirudo_build::{check_keys, key_path};
use crate::sys::curl::{CURL_GLOBAL_DEFAULT, curl_global_cleanup, curl_global_init};
use crate::util::bpm_oci::{
    Client, Descriptor, MANIFEST_MEDIA, bpm_oci_emit_descriptor, bpm_oci_push_blob,
    bpm_oci_put_manifest, digest_matches, manifest_layers, sha256_hex,
};
use crate::util::bpm_package::{IndexEntry, index_parse, verify_cms};
use crate::util::json::JsonEmit;
use crate::util::timefmt::iso8601;

/// Room for a manifest.
pub(super) const MANIFEST_CAP: usize = 8192;
/// Room for a detached signature.
const SIGN_MAX: usize = 64 * 1024;
const INDEX_REPOSITORY_NAME: &[u8] = b"bpm-index";
const INDEX_TAG: &[u8] = b"stable";
const INDEX_MEDIA: &CStr = c"application/vnd.shirudo.bpm.index.v1+json";
const INDEX_SIG_MEDIA: &CStr = c"application/vnd.shirudo.bpm.index.signature.v1";
const INDEX_ARTIFACT: &[u8] = b"application/vnd.shirudo.bpm.index.v1";
const PACKAGE_MEDIA: &CStr = c"application/vnd.shirudo.bpm.package.v1+gzip";
const CONFIG_MEDIA: &CStr = c"application/vnd.shirudo.bpm.config.v1+json";
pub(super) const EMPTY_CONFIG_MEDIA: &CStr = c"application/vnd.oci.empty.v1+json";
const PUBLIC_KEY_ARTIFACT: &[u8] = b"application/vnd.shirudo.bpm.public-key.v1+der";
const PUBLIC_KEY_MEDIA: &CStr = c"application/pkix-cert";
const IMAGE_MANIFEST: &[u8] = b"application/vnd.oci.image.manifest.v1+json";
/// BPM_MAX_ENTRIES: the most packages an index lists.
const MAX_ENTRIES: usize = 512;
const MAX_HTTP_BODY: usize = 256 * 1024 * 1024;
const PATH_MAX: usize = 4096;

/// A failure of `bpm <action>`, reported: always exit 1.
pub(super) fn fail(action: &str, ret: c_int) -> c_int {
    if ret < 0 {
        error(format!("bpm {action}: {}", String::from_utf8_lossy(strerr(-ret))).as_bytes());
    } else {
        error(format!("bpm {action} failed").as_bytes());
    }
    1
}

/// Detached CMS over `payload` with the operator key, the form of a
/// loader signature, so the target verifies both with one code path.
pub(super) fn sign_detached(payload: &[u8], keys: (&CStr, &CStr)) -> Result<Vec<u8>, c_int> {
    crate::shirudo_build::sign::cms_sign(payload, &[], SIGN_MAX, keys.0, keys.1).map(|(sig, _)| sig)
}

/// Uploads `body` as a blob of `media` to `repo`.
pub(super) fn push_blob(
    c: &mut Client,
    repo: &[u8],
    body: &[u8],
    media: &CStr,
) -> Result<Descriptor, c_int> {
    let r = cstring(repo);
    let mut d = Descriptor::new();
    // SAFETY: the client, C strings, the body and room for its descriptor.
    match unsafe {
        bpm_oci_push_blob(
            c.as_mut(),
            r.as_ptr(),
            body.as_ptr().cast(),
            body.len(),
            media.as_ptr(),
            &mut d,
        )
    } {
        0 => Ok(d),
        err => Err(err),
    }
}

/// Puts `body` as the manifest `reference` of `repo`: its digest.
pub(super) fn put_manifest(
    c: &mut Client,
    repo: &[u8],
    reference: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, c_int> {
    let (r, re) = (cstring(repo), cstring(reference));
    let mut digest = [0u8; 72];
    // SAFETY: the client, C strings, the body and room for its digest.
    let ret = unsafe {
        bpm_oci_put_manifest(
            c.as_mut(),
            r.as_ptr(),
            re.as_ptr(),
            body.as_ptr(),
            body.len(),
            digest.as_mut_ptr().cast(),
            digest.len(),
        )
    };
    if ret != 0 {
        return Err(ret);
    }
    Ok(crate::text::cstr(&digest).to_vec())
}

/// A descriptor into the manifest being written.
pub(super) fn emit_descriptor(
    e: &mut JsonEmit,
    key: Option<&CStr>,
    d: &Descriptor,
    title: Option<&CStr>,
) {
    // SAFETY: the emitter, C strings or NULL, and the descriptor.
    unsafe {
        bpm_oci_emit_descriptor(
            e,
            key.map_or(ptr::null(), CStr::as_ptr),
            d,
            title.map_or(ptr::null(), CStr::as_ptr),
        )
    };
}

/// A manifest of `artifact`, its config and its layers, as JSON.
pub(super) fn artifact_manifest(
    artifact: &[u8],
    config: &Descriptor,
    layers: &[&Descriptor],
) -> Result<Vec<u8>, c_int> {
    let mut buf = vec![0u8; MANIFEST_CAP];
    let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len());

    e.obj_open();
    e.kv_int(b"schemaVersion", 2);
    e.kv_string(b"mediaType", MANIFEST_MEDIA.to_bytes());
    e.kv_string(b"artifactType", artifact);
    emit_descriptor(&mut e, Some(c"config"), config, None);
    e.arr_open(b"layers");
    for l in layers {
        emit_descriptor(&mut e, None, l, None);
    }
    e.arr_close();
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    buf.truncate(e.written());
    Ok(buf)
}

fn sha256_text(body: &[u8]) -> Result<Vec<u8>, c_int> {
    let mut hex = [0u8; 65];
    if sha256_hex(body.as_ptr(), body.len(), &mut hex) != 0 {
        return Err(-EINVAL);
    }
    Ok(crate::text::cstr(&hex).to_vec())
}

/// `<namespace>/bpm-index` beside the repository.
fn index_repository(repo: &[u8]) -> Result<Vec<u8>, c_int> {
    let slash = repo
        .iter()
        .rposition(|&c| c == b'/')
        .filter(|&s| s > 0)
        .ok_or(-EINVAL)?;
    let out = [&repo[..slash], b"/", INDEX_REPOSITORY_NAME].concat();
    if out.len() >= super::MAX_ENDPOINT {
        return Err(-ENAMETOOLONG);
    }
    Ok(out)
}

/// The signed index at `repo`: -ENOENT when the registry has none.
fn fetch_index(c: &mut Client, repo: &[u8], cert: &CStr) -> Result<Vec<IndexEntry>, c_int> {
    let url = c.url(repo, b"manifests", INDEX_TAG)?;
    let manifest = c.get(&url, MANIFEST_MEDIA, false)?;
    let (layers, _) = manifest_layers(manifest.bytes(), MAX_ENTRIES, false)?;
    let (mut payload, mut sig) = (None, None);
    for l in &layers {
        let slot = if l.media() == INDEX_MEDIA.to_bytes() {
            &mut payload
        } else if l.media() == INDEX_SIG_MEDIA.to_bytes() {
            &mut sig
        } else {
            continue;
        };
        if slot.is_some() {
            return Err(-EINVAL);
        }
        let blob_url = c.url(repo, b"blobs", l.digest())?;
        let media = cstring(l.media());
        let body = c.get(&blob_url, &media, true)?;
        let hex = sha256_text(body.bytes()).map_err(|_| -EKEYREJECTED)?;
        if (l.size() >= 0 && body.bytes().len() as i64 != l.size())
            || !digest_matches(l.digest(), &hex)
        {
            return Err(-EKEYREJECTED);
        }
        *slot = Some(body.bytes().to_vec());
    }
    let (Some(payload), Some(sig)) = (payload, sig) else {
        return Err(-EINVAL);
    };
    if verify_cms(&payload, &sig, cert) != 0 {
        error(
            format!(
                "bpm push: the published repository index is not signed by {}",
                String::from_utf8_lossy(cert.to_bytes())
            )
            .as_bytes(),
        );
        return Err(-EKEYREJECTED);
    }
    index_parse(&payload)
}

fn copy(dst: &mut [u8], src: &[u8]) {
    dst.fill(0);
    let n = src.len().min(dst.len() - 1);
    dst[..n].copy_from_slice(&src[..n]);
}

/// Adds or refreshes the package's entry in the signed index beside its
/// repository's namespace. A version listed already with other content
/// is refused: published versions are immutable. The operator keeps no
/// state, so only `new_index` tells a namespace without an index from a
/// registry that hides one: the index pushed then would be signed
/// without every package listed before.
#[allow(clippy::too_many_arguments)]
fn push_index(
    c: &mut Client,
    index_repo: &[u8],
    repo: &[u8],
    info: &Info,
    manifest_digest: &[u8],
    layer: &Descriptor,
    keys: (&CStr, &CStr),
    new_index: bool,
) -> c_int {
    let mut entries = match fetch_index(c, index_repo, keys.1) {
        Err(err) if err == -ENOENT && new_index => Vec::new(),
        Err(err) if err == -ENOENT => {
            error(format!("bpm push: {} has no repository index; pass --new-index to start one, and only for a namespace that never had one", String::from_utf8_lossy(index_repo)).as_bytes());
            return err;
        }
        Ok(_) if new_index => {
            error(format!("bpm push: {} has a repository index already; --new-index starts one only where there is none", String::from_utf8_lossy(index_repo)).as_bytes());
            return -EEXIST;
        }
        Err(err) => return err,
        Ok(e) => e,
    };
    let cstr = crate::text::cstr;
    let (name, version) = (cstr(&info.0.name), cstr(&info.0.version));
    let mut at = None;
    for (i, e) in entries.iter().enumerate() {
        if cstr(&e.name) != name || cstr(&e.version) != version {
            continue;
        }
        if cstr(&e.manifest_digest) != manifest_digest || cstr(&e.package_digest) != layer.digest()
        {
            error(
                format!(
                    "bpm push: the repository index already lists {} {} with different content",
                    String::from_utf8_lossy(name),
                    String::from_utf8_lossy(version)
                )
                .as_bytes(),
            );
            return -EEXIST;
        }
        at = Some(i);
    }
    let i = match at {
        Some(i) => i,
        None if entries.len() >= MAX_ENTRIES => return -E2BIG,
        None => {
            // SAFETY: an all-zero entry is an empty one.
            entries.push(unsafe { core::mem::zeroed() });
            entries.len() - 1
        }
    };
    let e = &mut entries[i];
    // SAFETY: an all-zero entry is an empty one.
    *e = unsafe { core::mem::zeroed() };
    e.package_size = layer.size();
    copy(&mut e.name, name);
    copy(&mut e.version, version);
    copy(&mut e.repository, repo);
    copy(&mut e.manifest_digest, manifest_digest);
    copy(&mut e.package_digest, layer.digest());
    copy(&mut e.signer, cstr(&info.0.signer));
    entries
        .sort_by(|a, b| (cstr(&a.name), cstr(&a.version)).cmp(&(cstr(&b.name), cstr(&b.version))));

    let mut stamp = [0u8; 32];
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    if iso8601(now, &mut stamp) != 0 {
        return -EIO;
    }
    let mut body = vec![0u8; 4096 + entries.len() * 4096];
    let mut j = JsonEmit::fixed(body.as_mut_ptr().cast(), body.len());
    j.obj_open();
    j.kv_int(b"schema", 1);
    j.kv_string(b"generated_at", cstr(&stamp));
    j.arr_open(b"packages");
    for e in &entries {
        j.obj_open();
        j.kv_string(b"name", cstr(&e.name));
        j.kv_string(b"version", cstr(&e.version));
        j.kv_string(b"repository", cstr(&e.repository));
        j.kv_string(b"manifest_digest", cstr(&e.manifest_digest));
        j.kv_string(b"package_digest", cstr(&e.package_digest));
        j.kv_int(b"package_size", e.package_size);
        j.kv_string(b"signer_fingerprint", cstr(&e.signer));
        j.obj_close();
    }
    j.arr_close();
    j.obj_close();
    if j.err() != 0 {
        return j.err();
    }
    body.truncate(j.written());
    let result = (|| {
        let sig = sign_detached(&body, keys)?;
        let config = push_blob(c, index_repo, b"{}", EMPTY_CONFIG_MEDIA)?;
        let payload_layer = push_blob(c, index_repo, &body, INDEX_MEDIA)?;
        let sig_layer = push_blob(c, index_repo, &sig, INDEX_SIG_MEDIA)?;
        let manifest = artifact_manifest(INDEX_ARTIFACT, &config, &[&payload_layer, &sig_layer])?;
        put_manifest(c, index_repo, INDEX_TAG, &manifest)
    })();
    result.err().unwrap_or(0)
}

/// Publishes the package at `package` to `raw_repo`: the reference it
/// is tagged at.
fn push_package(
    package: &CStr,
    raw_repo: &[u8],
    index_keys: Option<(&CStr, &CStr)>,
    new_index: bool,
) -> Result<Vec<u8>, c_int> {
    let p = package.to_bytes();
    if p.is_empty() {
        return Err(-EINVAL);
    }
    let meta = std::fs::metadata(super::path(p)).map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    if !meta.is_file() {
        return Err(-EINVAL);
    }
    let archive_body = archive::read_file(p, MAX_HTTP_BODY)?;
    let info = Info::load(package)?;
    let mut c = Client::new();
    let repo = c.parse_push_repo(raw_repo)?;
    let index_repo = match index_keys {
        Some(_) => Some(index_repository(&repo)?),
        None => None,
    };
    let base = p
        .iter()
        .rposition(|&ch| ch == b'/')
        .map_or(p, |s| &p[s + 1..]);
    if base.is_empty() || base.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    let cstr = crate::text::cstr;
    let config = push_blob(
        &mut c,
        &repo,
        br#"{"mediaType":"application/vnd.shirudo.bpm.config.v1+json"}"#,
        CONFIG_MEDIA,
    )?;
    let layer = push_blob(&mut c, &repo, &archive_body, PACKAGE_MEDIA)?;

    let mut buf = vec![0u8; MANIFEST_CAP];
    let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len());
    e.obj_open();
    e.kv_int(b"schemaVersion", 2);
    e.kv_string(b"mediaType", IMAGE_MANIFEST);
    emit_descriptor(&mut e, Some(c"config"), &config, None);
    e.arr_open(b"layers");
    emit_descriptor(&mut e, None, &layer, Some(&cstring(base)));
    e.arr_close();
    e.obj_open_key(b"annotations");
    e.kv_string(b"dev.shirudo.bpm.package.name", cstr(&info.0.name));
    e.kv_string(b"dev.shirudo.bpm.package.version", cstr(&info.0.version));
    e.kv_string(b"org.opencontainers.image.title", cstr(&info.0.name));
    e.kv_string(b"org.opencontainers.image.version", cstr(&info.0.version));
    e.obj_close();
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    buf.truncate(e.written());
    let manifest = buf;
    let package_digest = [b"sha256:", &sha256_text(&manifest)?[..]].concat();
    // By digest until the index takes the version, so a refused re-push
    // leaves the tag on the package already published.
    put_manifest(&mut c, &repo, &package_digest, &manifest)?;

    // The certificate as an OCI referrer, so `bpm key add` can fetch it
    // without downloading the package.
    let key_config = push_blob(&mut c, &repo, b"{}", EMPTY_CONFIG_MEDIA)?;
    let key_layer = push_blob(&mut c, &repo, info.cert(), PUBLIC_KEY_MEDIA)?;
    let mut buf = vec![0u8; MANIFEST_CAP];
    let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len());
    e.obj_open();
    e.kv_int(b"schemaVersion", 2);
    e.kv_string(b"mediaType", IMAGE_MANIFEST);
    e.kv_string(b"artifactType", PUBLIC_KEY_ARTIFACT);
    emit_descriptor(&mut e, Some(c"config"), &key_config, None);
    e.arr_open(b"layers");
    emit_descriptor(&mut e, None, &key_layer, None);
    e.arr_close();
    e.obj_open_key(b"subject");
    e.kv_string(b"mediaType", IMAGE_MANIFEST);
    e.kv_string(b"digest", &package_digest);
    e.kv_int(b"size", manifest.len() as i64);
    e.obj_close();
    e.obj_close();
    if e.err() != 0 {
        return Err(e.err());
    }
    buf.truncate(e.written());
    let key_digest = [b"sha256:", &sha256_text(&buf)?[..]].concat();
    put_manifest(&mut c, &repo, &key_digest, &buf)?;
    if let (Some(keys), Some(index_repo)) = (index_keys, &index_repo) {
        match push_index(
            &mut c,
            index_repo,
            &repo,
            &info,
            &package_digest,
            &layer,
            keys,
            new_index,
        ) {
            0 => {}
            err => return Err(err),
        }
    }
    put_manifest(&mut c, &repo, cstr(&info.0.version), &manifest)?;
    let reference = [
        b"oci://",
        c.registry(),
        b"/",
        &repo,
        b":",
        cstr(&info.0.version),
    ]
    .concat();
    if reference.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    Ok(reference)
}

fn usage() {
    print(
        false,
        b"usage: shirudo bpm push <package-file> <repository>
                        [--keys-dir <dir> | --index-cert <cert.der>
                         --index-key <signing_key.pem>] [--new-index]

The repository must start with oci:// and must not include a tag.
With signing material the registry's signed index at
<namespace>/bpm-index:stable gains the package entry, signed with the
operator key; without it only the package is published. A namespace
without an index is refused unless --new-index starts one, which in
turn is refused where an index exists.
Examples:
  shirudo bpm push ./package.bee oci://quay.io/namespace/package
  shirudo bpm push ./package.bee oci://quay.io/namespace/package \\
      --keys-dir /var/lib/shirudo/keys
",
    );
}

/// `bpm push`, from `push` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let (mut package, mut repo, mut keys_dir, mut index_cert, mut index_key) =
        (None, None, None, None, None);
    let mut new_index = false;

    if args.len() == 2 && super::is_help(args[1].to_bytes()) {
        usage();
        return 0;
    }
    let mut i = 1;
    while i < args.len() {
        let a = args[i];
        let b = a.to_bytes();
        let next = args.get(i + 1).copied();
        let tail = |prefix: &[u8]| {
            b.strip_prefix(prefix).and_then(|_| {
                CStr::from_bytes_with_nul(&a.to_bytes_with_nul()[prefix.len()..]).ok()
            })
        };
        match (b, next) {
            (b"--keys-dir", Some(v)) => {
                keys_dir = Some(v);
                i += 1;
            }
            (b"--index-cert", Some(v)) => {
                index_cert = Some(v);
                i += 1;
            }
            (b"--index-key", Some(v)) => {
                index_key = Some(v);
                i += 1;
            }
            _ if tail(b"--keys-dir=").is_some() => keys_dir = tail(b"--keys-dir="),
            _ if tail(b"--index-cert=").is_some() => index_cert = tail(b"--index-cert="),
            _ if tail(b"--index-key=").is_some() => index_key = tail(b"--index-key="),
            (b"--new-index", _) => new_index = true,
            _ if b.first() == Some(&b'-') || (package.is_some() && repo.is_some()) => {
                usage();
                return 2;
            }
            _ if package.is_none() => package = Some(a),
            _ => repo = Some(a),
        }
        i += 1;
    }
    let (Some(package), Some(repo)) = (package, repo) else {
        usage();
        return 2;
    };
    let (mut cert_buf, mut key_buf) = (None, None);
    if let Some(dir) = keys_dir {
        let cert = index_cert
            .is_none()
            .then(|| key_path(dir.as_ptr(), c"cert.der"));
        let key = index_key
            .is_none()
            .then(|| key_path(dir.as_ptr(), c"signing_key.pem"));
        if matches!(cert, Some(Err(_))) || matches!(key, Some(Err(_))) {
            return fail("push", -EINVAL);
        }
        cert_buf = cert.and_then(Result::ok);
        key_buf = key.and_then(Result::ok);
    }
    let index_cert = index_cert.or(cert_buf.as_deref());
    let index_key = index_key.or(key_buf.as_deref());
    if index_cert.is_some() != index_key.is_some() {
        error(b"bpm push: --index-cert and --index-key must be supplied together");
        return 2;
    }
    if new_index && index_key.is_none() {
        error(b"bpm push: --new-index needs --keys-dir, or --index-cert and --index-key");
        return 2;
    }
    let keys = index_key.zip(index_cert);
    if let Some((k, c)) = keys {
        if check_keys(k, c) != 0 {
            return 1;
        }
    }
    // SAFETY: once, before any transfer.
    if unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) } != 0 {
        return fail("initialize curl", -EIO);
    }
    let ret = push_package(package, repo.to_bytes(), keys, new_index);
    // SAFETY: after every transfer.
    unsafe { curl_global_cleanup() };
    match ret {
        Ok(reference) => {
            print(true, &[&reference[..], b"\n"].concat());
            0
        }
        Err(err) => fail("push", err),
    }
}
