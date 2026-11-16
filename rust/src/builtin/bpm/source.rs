// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The repositories a target installs from, registered under
//! /etc/shirudo/bpm/registries.d or held by the config image, and the
//! tree it syncs.

use core::ffi::{CStr, c_int};
use std::ffi::CString;

use super::{
    BPM_KEYS_DIR, DirStream, INDEX_REPOSITORY_NAME, REGISTRIES_DIR, Result, Stream, TREE_ETC_PATH,
    eprint, error, path, print, remove, status,
};
use crate::errno::{E2BIG, EINVAL, ENAMETOOLONG, EPERM};
use crate::sys::libc::{O_DIRECTORY, O_RDONLY, PATH_MAX, close};
use crate::text::{contains, cstr, name_has_suffix, strscpy, strsprintf};
use crate::util::bpm_oci::{Client, MAX_DIGEST, MAX_ENDPOINT, MAX_NAME, name_ok};
use crate::util::bpm_package::{verify_cms, verify_cms_fd};
use crate::util::bpm_source_config::{parse_source_line, parse_tree_line};
use crate::util::crypto_openssl::{Cert, cert_free, cert_read_file};
use crate::util::help::is_help;
use crate::util::image_config::{self, REGISTRIES, TREE_CONF};
use crate::util::io::check_trusted;
use crate::util::json::JsonEmit;
use crate::util::seal::{seal_mkdir_p, seal_write_file};

/// `BPM_MAX_KEY`: the longest key file path, its NUL included.
const MAX_KEY: usize = 256;

/// A registered repository: where it is, the index it publishes and the
/// certificate that signs that index.
pub(super) struct Source {
    name: [u8; MAX_NAME],
    endpoint: [u8; MAX_ENDPOINT],
    index_repository: [u8; MAX_ENDPOINT],
    key_file: [u8; MAX_KEY],
}

impl Source {
    pub(super) fn new() -> Self {
        Source {
            name: [0; MAX_NAME],
            endpoint: [0; MAX_ENDPOINT],
            index_repository: [0; MAX_ENDPOINT],
            key_file: [0; MAX_KEY],
        }
    }

    /// The source a direct reference installs from: its registry alone.
    pub(super) fn direct(endpoint: &[u8]) -> Self {
        let mut s = Source::new();

        let _ = strscpy(&mut s.name, b"direct");
        let _ = strscpy(&mut s.endpoint, endpoint);
        s
    }

    pub(super) fn endpoint(&self) -> &[u8] {
        cstr(&self.endpoint)
    }

    pub(super) fn index_repository(&self) -> &[u8] {
        cstr(&self.index_repository)
    }

    fn key_file(&self) -> &[u8] {
        cstr(&self.key_file)
    }

    /// The key file, open as verification reads it: from the config
    /// image's root when one is active.
    pub(super) fn key_open(&self) -> c_int {
        let Ok(key) = CString::new(self.key_file()) else {
            return -EINVAL;
        };

        if image_config::active() {
            return image_config::open_relative(&key, O_RDONLY);
        }
        // SAFETY: a C string.
        let fd = unsafe { crate::sys::libc::open(key.as_ptr(), O_RDONLY) };
        if fd < 0 { super::last_err() } else { fd }
    }

    /// Whether `sig` signs `data` with the source's certificate: 0 or
    /// -errno.
    pub(super) fn verify(&self, data: &[u8], sig: &[u8]) -> c_int {
        if !image_config::active() {
            let Ok(key) = CString::new(self.key_file()) else {
                return -EINVAL;
            };
            return verify_cms(data, sig, &key);
        }
        let fd = self.key_open();
        if fd < 0 {
            return fd;
        }
        let ret = verify_cms_fd(data, sig, fd);
        // SAFETY: the fd opened above.
        unsafe { close(fd) };
        ret
    }
}

/// The registration file of source `name`.
fn source_path(name: &[u8]) -> Result<CString> {
    if !name_ok(name) {
        return Err(-EINVAL);
    }
    path(&[REGISTRIES_DIR.as_bytes(), b"/", name, b".conf"])
}

/// What comes from the config image is authenticated content, and the
/// host path it is named by in messages is not where it was read from;
/// only a host file has an owner and mode to check.
fn trusted(stream: &Stream, path: &CStr) -> Result {
    if image_config::active() {
        return Ok(());
    }
    // SAFETY: the stream's fd and a C string.
    match unsafe { check_trusted(stream.fd(), path.as_ptr(), false) } {
        0 => Ok(()),
        _ => Err(-EPERM),
    }
}

/// The registrations, from the config image when one is active.
pub(super) fn registries() -> Result<DirStream> {
    if image_config::active() {
        return DirStream::from_fd(image_config::open(REGISTRIES, O_RDONLY | O_DIRECTORY));
    }
    DirStream::open(&message_path(REGISTRIES_DIR))
}

fn message_path(p: &str) -> CString {
    super::message(&[p.as_bytes()])
}

/// The name a registration file gives its source, when it is one.
pub(super) fn registered_name(file: &[u8]) -> Option<&[u8]> {
    name_has_suffix(file, b".conf").then(|| &file[..file.len() - 5])
}

/// That the index repository of a source is `<namespace>/bpm-index` and
/// stays that once parsed against its endpoint.
fn index_repository_valid(endpoint: &[u8], repository: &[u8]) -> Result {
    match repository.iter().rposition(|&c| c == b'/') {
        Some(slash) if slash > 0 && &repository[slash + 1..] == INDEX_REPOSITORY_NAME => {}
        _ => return Err(-EINVAL),
    }
    let raw = [endpoint, b"/", repository].concat();
    if raw.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    if Client::new().parse_push_repo(&raw)? != repository {
        return Err(-EINVAL);
    }
    Ok(())
}

/// Registered source `name`.
pub(super) fn load(name: &[u8]) -> Result<Source> {
    let file = source_path(name)?;
    let mut stream = if image_config::active() {
        Stream::from_fd(image_config::open_relative(
            &CString::new(&file.to_bytes()[1..]).map_err(|_| -EINVAL)?,
            O_RDONLY,
        ))?
    } else {
        Stream::open(&file)?
    };
    let mut s = Source::new();

    trusted(&stream, &file)?;
    strscpy(&mut s.name, name).map_err(|_| -ENAMETOOLONG)?;
    stream.lines(|line| {
        status(parse_source_line(
            line,
            &mut s.endpoint,
            &mut s.index_repository,
            &mut s.key_file,
        ))
    })?;
    drop(stream);
    if s.endpoint[0] == 0 || s.key_file[0] == 0 {
        return Err(-EINVAL);
    }
    if s.index_repository[0] == 0 {
        strsprintf(
            &mut s.index_repository,
            &[name, b"/", INDEX_REPOSITORY_NAME],
        )
        .map_err(|_| -E2BIG)?;
    }
    index_repository_valid(s.endpoint(), s.index_repository())?;
    // With a config image the key file is the image's, named from its
    // root.
    if image_config::active() {
        if s.key_file().starts_with(b"/etc/shirudo/bpm/keys/") {
            s.key_file.copy_within(1.., 0);
        }
        if s.key_file[0] == b'/' || contains(s.key_file(), b"..") {
            return Err(-EINVAL);
        }
    }
    Ok(s)
}

fn save(s: &Source) -> Result {
    let file = source_path(cstr(&s.name))?;
    let data = [
        b"endpoint = ",
        s.endpoint(),
        b"\nindex_repository = ",
        s.index_repository(),
        b"\nkey_file = ",
        s.key_file(),
        b"\n",
    ]
    .concat();

    if data.len() >= 2 * PATH_MAX {
        return Err(-E2BIG);
    }
    // SAFETY: a C string and the data's bytes.
    status(unsafe { seal_write_file(file.as_ptr(), data.as_ptr().cast(), data.len(), 0o644) })
}

const CONFIG_USAGE: &[u8] = b"usage: shirudo bpm config register add <source> \
oci://<registry> [--index-repository <repository>] --cert <certificate>\n       \
shirudo bpm config register {list|remove} ...\n       \
shirudo bpm config update --base-package <package.bee|oci://host/repo:tag> \
--version <version> [--file <name>.bee] [options]\n";

/// `shirudo bpm config`, `args` from "config" on.
pub(super) fn config(args: &[&[u8]]) -> c_int {
    let op = args.get(1).copied();
    let n = args.len();

    if op.is_none() || is_help(op) {
        eprint(CONFIG_USAGE);
        return if op.is_some() { 0 } else { 2 };
    }
    if op != Some(b"register") || n < 3 {
        return 2;
    }
    match args[2] {
        b"list" => list(n == 4 && args[3] == b"--json", n),
        b"add" | b"remove" | b"rm" if image_config::active() => {
            error(&[b"image mode: change repository definitions and keys in \
                     a signed config image, then run `shirudo image update`"]);
            1
        }
        b"remove" | b"rm" if n == 4 => unregister(args[3]),
        b"add" if n >= 5 => register(&args[3..]),
        _ => 2,
    }
}

fn list(json: bool, n: usize) -> c_int {
    let mut buf = [0u8; 8192];
    let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len());
    let mut count = 0;

    if n != 3 && !json {
        return 2;
    }
    if json {
        e.obj_open();
        e.kv_int(b"schema", 1);
        e.arr_open(b"sources");
    } else {
        print(b"Registered sources:\n");
    }
    for file in registries().into_iter().flatten() {
        let Some(name) = registered_name(&file) else {
            continue;
        };
        if name.len() > 255 {
            continue;
        }
        if json {
            e.str(name);
        } else {
            print(&[b"  ", name, b"\n"].concat());
        }
        count += 1;
    }
    if json {
        e.arr_close();
        e.obj_close();
        if e.err() != 0 {
            return 1;
        }
        print(&[&buf[..e.written()], b"\n"].concat());
    } else if count == 0 {
        print(b"  none\n");
    }
    0
}

fn unregister(name: &[u8]) -> c_int {
    let Ok(file) = source_path(name) else {
        return 2;
    };

    if let Ok(s) = load(name) {
        if s.key_file[0] != 0 {
            remove(&super::message(&[s.key_file()]));
        }
    }
    // SAFETY: a C string.
    if unsafe { crate::sys::libc::unlink(file.as_ptr()) } != 0
        && crate::sys::libc::errno() != crate::errno::ENOENT
    {
        return 1;
    }
    if let Ok(key) = path(&[BPM_KEYS_DIR.as_bytes(), b"/", name, b".der"]) {
        remove(&key);
    }
    0
}

/// `register add <source> <endpoint> [options]`, `args` from the source.
fn register(args: &[&[u8]]) -> c_int {
    let mut s = Source::new();
    let mut key: Option<&[u8]> = None;
    let mut i = 2;

    if strscpy(&mut s.name, args[0]).is_err() || strscpy(&mut s.endpoint, args[1]).is_err() {
        error(&[b"bpm: register add: name or endpoint too long"]);
        return 2;
    }
    while i < args.len() {
        let a = args[i];

        if let Some(cert) = a.strip_prefix(b"--cert=") {
            key = Some(cert);
        } else if a == b"--cert" && i + 1 < args.len() {
            i += 1;
            key = Some(args[i]);
        } else if let Some(repo) = a.strip_prefix(b"--index-repository=") {
            if strscpy(&mut s.index_repository, repo).is_err() {
                return 2;
            }
        } else if a == b"--index-repository" && i + 1 < args.len() {
            i += 1;
            if strscpy(&mut s.index_repository, args[i]).is_err() {
                return 2;
            }
        } else if a == b"--index-repository" {
            return 2;
        } else {
            error(&[b"bpm: register add: unknown option '", a, b"'"]);
            return 2;
        }
        i += 1;
    }
    if s.index_repository[0] == 0
        && strsprintf(
            &mut s.index_repository,
            &[cstr(&s.name), b"/", INDEX_REPOSITORY_NAME],
        )
        .is_err()
    {
        return 2;
    }
    let valid = key.is_some_and(|key| {
        let key = super::message(&[key]);
        let mut cert = Cert::new();
        // SAFETY: a C string and a certificate to fill, freed after.
        let read = unsafe { cert_read_file(key.as_ptr(), &mut cert) } == 0;
        // SAFETY: the certificate, read or not.
        unsafe { cert_free(&mut cert) };
        read
    }) && name_ok(cstr(&s.name))
        && Client::new().parse_endpoint(s.endpoint()).is_ok()
        && index_repository_valid(s.endpoint(), s.index_repository()).is_ok();
    if !valid {
        error(&[
            b"bpm: register add requires a valid endpoint, index repository and --cert certificate",
        ]);
        return 2;
    }
    for dir in [REGISTRIES_DIR, BPM_KEYS_DIR] {
        // SAFETY: a C string.
        if unsafe { seal_mkdir_p(message_path(dir).as_ptr(), 0o700) } != 0 {
            return 1;
        }
    }
    let Ok(managed) = path(&[BPM_KEYS_DIR.as_bytes(), b"/", cstr(&s.name), b".der"]) else {
        return 1;
    };
    let key = super::message(&[key.unwrap_or_default()]);
    if super::package::copy_file(&key, &managed, 0o644, false).is_err() {
        return 1;
    }
    if strscpy(&mut s.key_file, managed.to_bytes()).is_err() {
        return 1;
    }
    if save(&s).is_err() { 1 } else { 0 }
}

/// Where the tree is published: the endpoint of its repository and the
/// reference of its publication.
pub(super) struct TreeConfig {
    pub(super) endpoint: [u8; MAX_ENDPOINT],
    pub(super) reference: [u8; MAX_DIGEST],
}

/// The tree configuration, from the config image when one is active:
/// -ENOENT without one.
pub(super) fn load_tree() -> Result<TreeConfig> {
    let mut stream = if image_config::active() {
        Stream::from_fd(image_config::open(TREE_CONF, O_RDONLY))?
    } else {
        Stream::open(TREE_ETC_PATH)?
    };
    let mut cfg = TreeConfig {
        endpoint: [0; MAX_ENDPOINT],
        reference: [0; MAX_DIGEST],
    };

    trusted(&stream, TREE_ETC_PATH)?;
    stream
        .lines(|line| status(parse_tree_line(line, &mut cfg.endpoint, &mut cfg.reference)))
        .map_err(|_| -EINVAL)?;
    if cfg.endpoint[0] == 0 || cfg.reference[0] == 0 {
        return Err(-EINVAL);
    }
    Ok(cfg)
}
