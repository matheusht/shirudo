// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Installed packages: installing one from a repository or an OCI
//! reference, upgrading to newer cached versions, uninstalling and
//! listing them.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use super::fetch::{self, sha256_file};
use super::source::{self, Source};
use super::{
    PACKAGE_MEDIA, PACKAGES_DIR, Result, STAGING_DIR, curl_ready, eprint, error, fail, finish,
    lock, message, os_err, path, print, remove, status, warn,
};
use crate::errno::{E2BIG, EEXIST, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT};
use crate::sys::libc::{F_OK, O_CREAT, O_EXCL, O_NOFOLLOW, O_TRUNC, O_WRONLY, access};
use crate::text::{cstr, strscpy, strsprintf};
use crate::util::bpm_oci::{
    Client, MAX_NAME, digest_matches, manifest_layers, name_ok, version_ok,
};
use crate::util::bpm_package::{
    IndexEntry, UpatchMember, extract, semver_compare, upatch_member, upatch_pair,
};
use crate::util::bpm_state::{self, BpmStateEntry};
use crate::util::help::is_help;
use crate::util::json::JsonEmit;
use crate::util::seal::{seal_mkdir_p, seal_open};

/// The most upatches of one kind a package loads or unloads.
const PATHS_MAX: usize = 128;
/// `BPM_MAX_STATE`: the most packages the state records.
const MAX_STATE: usize = 256;

fn os(path: &CStr) -> &OsStr {
    OsStr::from_bytes(path.to_bytes())
}

/// Copies the file at `src` to `dst`, created as output to /var/lib may
/// be, with `mode`: exclusive, or replacing what is there. A copy onto
/// itself is a copy already made, or -EEXIST when exclusive.
pub(super) fn copy_file(src: &CStr, dst: &CStr, mode: u32, exclusive: bool) -> Result {
    let mut input = fs::File::open(os(src)).map_err(os_err)?;
    let same = match (input.metadata(), fs::metadata(os(dst))) {
        (Ok(a), Ok(b)) => a.dev() == b.dev() && a.ino() == b.ino(),
        _ => false,
    };

    // O_TRUNC on a destination that is the source would empty both.
    if same {
        return if exclusive { Err(-EEXIST) } else { Ok(()) };
    }
    let flags = O_WRONLY | O_CREAT | if exclusive { O_EXCL } else { O_TRUNC };
    // SAFETY: a C string.
    let fd = unsafe { seal_open(dst.as_ptr(), flags, mode) };
    if fd < 0 {
        return Err(fd);
    }
    // SAFETY: the fd seal_open() opened.
    let mut output = fs::File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let mut buf = vec![0u8; 65536];
    let mut ret = Ok(());
    loop {
        match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if let Err(e) = output.write_all(&buf[..n]) {
                    ret = Err(os_err(e));
                    break;
                }
            }
            Err(e) => {
                ret = Err(os_err(e));
                break;
            }
        }
    }
    if let Err(e) = output.sync_all() {
        ret = ret.and(Err(os_err(e)));
    }
    drop(output);
    if ret.is_err() {
        remove(dst);
    }
    ret
}

/// Removes the tree at `path`, its links and not what they point at.
fn remove_tree(path: &CStr) -> Result {
    fs::remove_dir_all(os(path)).map_err(os_err)
}

/// The paths of the upatches of `kind` in `dir`, in the file system's
/// order, at most PATHS_MAX.
fn members(dir: &CStr, kind: UpatchMember) -> Result<Vec<(CString, Vec<u8>)>> {
    let mut found = Vec::new();

    for entry in fs::read_dir(os(dir))
        .map_err(os_err)?
        .map_while(core::result::Result::ok)
    {
        let name = entry.file_name();
        let name = name.as_bytes();

        if upatch_member(name) != kind {
            continue;
        }
        let member = path(&[dir.to_bytes(), b"/", name])?;
        found.push((member, name.to_vec()));
    }
    Ok(found)
}

/// The upatches a package loads: regular files, in name order.
fn loads(package_dir: &CStr) -> Result<Vec<CString>> {
    let updir = path(&[package_dir.to_bytes(), b"/upatches"])?;
    let mut loads = Vec::new();

    for (member, _) in members(&updir, UpatchMember::Load)? {
        if !fs::metadata(os(&member)).is_ok_and(|m| m.is_file()) {
            continue;
        }
        if loads.len() >= PATHS_MAX {
            return Err(-E2BIG);
        }
        loads.push(member);
    }
    // Measured in name order, not in the file system's.
    loads.sort();
    if loads.is_empty() {
        return Err(-EINVAL);
    }
    Ok(loads)
}

/// The unload directives of the version installed at `old`, each with
/// the load it undoes, in reverse name order, as uninstall runs them.
fn old_pairs(old: &[u8]) -> Result<Vec<(CString, CString)>> {
    let olddir = path(&[old, b"/upatches"])?;
    let mut pairs = Vec::new();

    for (unload, name) in members(&olddir, UpatchMember::Unload).unwrap_or_default() {
        let mut load = [0u8; 256];

        if pairs.len() >= PATHS_MAX {
            continue;
        }
        if upatch_pair(&name, &mut load) != 0 {
            return Err(-ENAMETOOLONG);
        }
        pairs.push((unload, path(&[olddir.to_bytes(), b"/", cstr(&load)])?));
    }
    pairs.sort_by(|a, b| b.0.cmp(&a.0));
    Ok(pairs)
}

fn install_one(load: &CStr) -> bool {
    crate::builtin::upatch::install(load) == 0
}

fn remove_one(unload: &CStr) -> bool {
    crate::builtin::upatch::remove(unload) == 0
}

/// Unloads what loaded, newest first, and loads the old version again.
fn rollback(loaded: &[CString], old: &[(CString, CString)]) {
    for load in loaded.iter().rev() {
        let load = load.to_bytes();
        let Some(slash) = load.iter().rposition(|&c| c == b'/') else {
            continue;
        };
        let mut name = [0u8; 256];

        if upatch_pair(&load[slash + 1..], &mut name) != 0 {
            continue;
        }
        if let Ok(unload) = path(&[&load[..slash], b"/", cstr(&name)]) {
            remove_one(&unload);
        }
    }
    for (_, load) in old.iter().rev() {
        install_one(load);
    }
}

/// What an install leaves to clean up should it fail: the staged
/// archive, and the package tree once extraction began, so that it does
/// not block the next attempt.
struct Staging {
    archive: Option<CString>,
    package_dir: Option<CString>,
    extracted: bool,
}

/// Installs the package `entry` names from source `s`: fetched and
/// checked against the index, extracted, and its upatches loaded in
/// name order, after the unload directives of the version at `old` when
/// upgrading. A load that fails rolls back.
pub(super) fn package_install(s: &Source, entry: &IndexEntry, old: Option<&[u8]>) -> Result {
    let mut staging = Staging {
        archive: None,
        package_dir: None,
        extracted: false,
    };
    let ret = stage_and_load(&mut staging, s, entry, old);

    if ret.is_err() {
        if let Some(archive) = &staging.archive {
            remove(archive);
        }
        if let (true, Some(dir)) = (staging.extracted, &staging.package_dir) {
            let _ = remove_tree(dir);
        }
    }
    ret
}

fn stage_and_load(
    staging: &mut Staging,
    s: &Source,
    entry: &IndexEntry,
    old: Option<&[u8]>,
) -> Result {
    let mut c = Client::new();
    let name = cstr(&entry.name);
    let version = cstr(&entry.version);
    let repository = if entry.repository[0] != 0 {
        cstr(&entry.repository)
    } else {
        name
    };
    let reference = cstr(&entry.manifest_digest);

    c.parse_endpoint(s.endpoint())?;
    let body = fetch::manifest(&mut c, repository, reference)?;
    // Repository indexes carry a sha256 manifest digest; direct OCI
    // references carry the tag here and cannot be digest-checked.
    if reference.starts_with(b"sha256:")
        && !fetch::sha256_of(body.bytes()).is_ok_and(|hex| digest_matches(reference, &hex))
    {
        return Err(-EKEYREJECTED);
    }
    let (layers, _) = manifest_layers(body.bytes(), 8, false)?;
    let Some(layer) = layers
        .iter()
        .find(|l| l.media() == PACKAGE_MEDIA.to_bytes())
    else {
        return Err(-EINVAL);
    };
    if entry.package_digest[0] != 0 && cstr(&entry.package_digest) != layer.digest() {
        return Err(-EKEYREJECTED);
    }
    if entry.package_size > 0 && entry.package_size != layer.size() {
        return Err(-EKEYREJECTED);
    }
    let url = c.url(repository, b"blobs", layer.digest())?;
    let dir = path(&[PACKAGES_DIR.as_bytes(), b"/", name])?;
    // SAFETY: a C string.
    status(unsafe { seal_mkdir_p(dir.as_ptr(), 0o700) })?;
    let package_dir = path(&[dir.to_bytes(), b"/", version])?;
    // SAFETY: a C string.
    status(unsafe { seal_mkdir_p(message(&[STAGING_DIR.as_bytes()]).as_ptr(), 0o700) })?;
    let archive = path(&[STAGING_DIR.as_bytes(), b"/", name, b"-", version, b".bee"])?;
    staging.archive = Some(archive.clone());
    staging.package_dir = Some(package_dir.clone());
    // SAFETY: a C string.
    let fd = unsafe {
        seal_open(
            archive.as_ptr(),
            O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return Err(fd);
    }
    // SAFETY: the fd seal_open() opened.
    let file = unsafe { OwnedFd::from_raw_fd(fd) };
    let got = c.get_file(&url, PACKAGE_MEDIA, file.as_raw_fd(), layer.size());
    drop(file);
    got?;
    if !sha256_file(&archive).is_ok_and(|hex| digest_matches(layer.digest(), &hex)) {
        return Err(-EKEYREJECTED);
    }
    // SAFETY: a C string.
    if unsafe { access(package_dir.as_ptr(), F_OK) } == 0 {
        return Err(-EEXIST);
    }
    staging.extracted = true;
    status(extract(&archive, &package_dir))?;
    let cert = path(&[package_dir.to_bytes(), b"/cert.der"])?;
    if !super::key::matches_active(&cert) {
        return Err(-EKEYREJECTED);
    }
    let loads = loads(&package_dir)?;
    let old = match old {
        Some(old) if !old.is_empty() => old_pairs(old)?,
        _ => Vec::new(),
    };
    for (removed, (unload, _)) in old.iter().enumerate() {
        if !remove_one(unload) {
            for (_, load) in old[..removed].iter().rev() {
                install_one(load);
            }
            return Err(-EIO);
        }
    }
    for (active, load) in loads.iter().enumerate() {
        if !install_one(load) {
            rollback(&loads[..active], &old);
            return Err(-EIO);
        }
    }
    let kept = path(&[dir.to_bytes(), b"/", name, b"-", version, b".bee"])
        .is_ok_and(|saved| fs::rename(os(&archive), os(&saved)).is_ok());
    if !kept {
        warn(&[b"bpm: cannot keep ", archive.to_bytes(), b"; dropping it"]);
        remove(&archive);
    }
    Ok(())
}

/// Detaches a package's upatches through the signed unload directives it
/// shipped, in reverse name order, then removes the package tree. The
/// caller drops the state entry only after this succeeded, so a failed
/// detach leaves the package listed and loadable again.
fn package_uninstall(st: &BpmStateEntry) -> Result {
    let updir = path(&[cstr(&st.path), b"/upatches"])?;
    let mut unloads = Vec::new();

    // A tree already gone, from an uninstall that died before it wrote
    // the state, leaves nothing to unload: the retry converges.
    match members(&updir, UpatchMember::Unload) {
        Ok(found) => {
            for (unload, _) in found {
                if unloads.len() >= PATHS_MAX {
                    return Err(-E2BIG);
                }
                unloads.push(unload);
            }
        }
        Err(err) if err == -ENOENT => {}
        Err(err) => return Err(err),
    }
    unloads.sort_by(|a, b| b.cmp(a));
    for unload in &unloads {
        if !remove_one(unload) {
            error(&[b"bpm uninstall: unload ", unload.to_bytes(), b" failed"]);
            return Err(-EIO);
        }
    }
    let dir = path(&[PACKAGES_DIR.as_bytes(), b"/", cstr(&st.name)])?;
    match remove_tree(&dir) {
        Err(err) if err == -ENOENT => Ok(()),
        ret => ret,
    }
}

/// `<source>/<name>[@<version>]`.
fn parse_ref(raw: &[u8]) -> Result<(&[u8], &[u8], &[u8])> {
    let slash = raw
        .iter()
        .position(|&c| c == b'/')
        .filter(|&slash| slash > 0)
        .ok_or(-EINVAL)?;
    let (source, rest) = (&raw[..slash], &raw[slash + 1..]);
    let (name, version) = match rest.iter().position(|&c| c == b'@') {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => (rest, &b""[..]),
    };

    if source.len() >= MAX_NAME || name.len() >= MAX_NAME || version.len() >= MAX_NAME {
        return Err(-ENAMETOOLONG);
    }
    if name_ok(source) && name_ok(name) && (version.is_empty() || version_ok(version)) {
        Ok((source, name, version))
    } else {
        Err(-EINVAL)
    }
}

fn package_path(name: &[u8], version: &[u8]) -> Result<Vec<u8>> {
    path(&[PACKAGES_DIR.as_bytes(), b"/", name, b"/", version]).map(CString::into_bytes)
}

fn set(field: &mut [u8], value: &[u8]) {
    let _ = strscpy(field, value);
}

/// `shirudo bpm install <package>`: idempotent by package name, so that
/// an active package is not even looked up; `bpm upgrade` changes
/// versions.
pub(super) fn install(reference: &[u8]) -> c_int {
    if !curl_ready() {
        return fail(b"initialize curl", -EIO);
    }
    let held = match lock() {
        Ok(held) => held,
        Err(err) => return finish(None, Err(err), b"lock"),
    };
    let direct = reference.starts_with(b"oci://");
    let picked = if direct {
        fetch::direct(reference).map(|(s, e)| (Some((s, e)), None))
    } else {
        parse_ref(reference).map(|r| (None, Some(r)))
    };
    let (prepared, named) = match picked {
        Ok(p) => p,
        Err(err) => return finish(Some(held), Err(err), b"install"),
    };
    let mut state = match bpm_state::read_all() {
        Ok(state) => state,
        Err(err) => return finish(Some(held), Err(err), b"install"),
    };
    let name: Vec<u8> = match (&prepared, named) {
        (Some((_, entry)), _) => cstr(&entry.name).to_vec(),
        (None, Some((_, name, _))) => name.to_vec(),
        (None, None) => unreachable!(),
    };
    if state.iter().any(|st| cstr(&st.name) == name) {
        return finish(Some(held), Ok(()), b"install");
    }
    let chosen = match (prepared, named) {
        (Some(p), _) => Ok(p),
        (None, Some((src, name, version))) => source::load(src).and_then(|s| {
            let entries = fetch::cached_index(src)?;
            let entry =
                fetch::find_entry(&entries, name, (!version.is_empty()).then_some(version))?;
            Ok((s, entry))
        }),
        (None, None) => unreachable!(),
    };
    let (s, entry) = match chosen {
        Ok(c) => c,
        Err(err) => return finish(Some(held), Err(err), b"install"),
    };
    if state.len() >= MAX_STATE {
        return finish(Some(held), Err(-E2BIG), b"install");
    }
    if let Err(err) = package_install(&s, &entry, None) {
        return finish(Some(held), Err(err), b"install");
    }
    let mut added = BpmStateEntry::new();
    set(&mut added.name, &name);
    set(&mut added.version, cstr(&entry.version));
    let src = match named {
        Some((src, _, _)) => src,
        None => b"direct",
    };
    set(&mut added.source, src);
    let Ok(dir) = package_path(&name, cstr(&entry.version)) else {
        return finish(Some(held), Err(-ENAMETOOLONG), b"install");
    };
    if strsprintf(&mut added.path, &[&dir]).is_err() {
        return finish(Some(held), Err(-ENAMETOOLONG), b"install");
    }
    state.push(added);
    let ret = status(bpm_state::write(&state));
    if ret.is_err() {
        // Unlisted, the package could never be removed.
        if package_uninstall(&added).is_err() {
            error(&[b"bpm install: ", &name, b" stays installed but unlisted"]);
        } else {
            error(&[
                b"bpm install: ",
                &name,
                b" removed again, the state could not be written",
            ]);
        }
    }
    finish(Some(held), ret, b"write state")
}

/// `shirudo bpm upgrade`: each package of a repository to the newest
/// version its cached index lists. Packages upgraded before a failure
/// stay on record.
pub(super) fn upgrade() -> c_int {
    if !curl_ready() {
        return fail(b"initialize curl", -EIO);
    }
    let held = match lock() {
        Ok(held) => held,
        Err(err) => return finish(None, Err(err), b"lock"),
    };
    let mut state = match bpm_state::read_all() {
        Ok(state) => state,
        Err(err) => return finish(Some(held), Err(err), b"read state"),
    };
    let mut ret = Ok(());
    for st in &mut state {
        if cstr(&st.source) == b"direct" {
            continue;
        }
        let src = cstr(&st.source).to_vec();
        let newest = source::load(&src).and_then(|s| {
            let entries = fetch::cached_index(&src)?;
            Ok((s, fetch::find_entry(&entries, cstr(&st.name), None)?))
        });
        let (s, entry) = match newest {
            Ok(found) => found,
            Err(err) if err == -ENOENT => continue,
            Err(err) => {
                ret = Err(err);
                break;
            }
        };
        if semver_compare(cstr(&entry.version), cstr(&st.version)) <= 0 {
            continue;
        }
        if let Err(err) = package_install(&s, &entry, Some(cstr(&st.path))) {
            ret = Err(err);
            break;
        }
        set(&mut st.version, cstr(&entry.version));
        match package_path(cstr(&st.name), cstr(&entry.version)) {
            Ok(dir) => set(&mut st.path, &dir),
            Err(err) => {
                ret = Err(err);
                break;
            }
        }
    }
    let written = status(bpm_state::write(&state));
    match ret {
        Err(_) => finish(Some(held), ret, b"upgrade"),
        Ok(()) => finish(Some(held), written, b"write state"),
    }
}

/// `s` left-justified in `width` bytes, as printf's "%-*s".
fn padded(s: &[u8], width: usize) -> Vec<u8> {
    let mut out = s.to_vec();

    out.resize(width.max(s.len()), b' ');
    out
}

/// `shirudo bpm list [--json]`.
pub(super) fn list(args: &[&[u8]]) -> c_int {
    let json = args.len() == 3 && args[2] == b"--json";

    if args.len() != 2 && !json {
        eprint(b"usage: shirudo bpm list [--json]\n");
        return if args.len() == 3 && is_help(Some(args[2])) {
            0
        } else {
            2
        };
    }
    let state = match bpm_state::read_all() {
        Ok(state) => state,
        Err(err) => return fail(b"list", err),
    };
    if json {
        let mut buf = vec![0u8; 256 + state.len() * 3 * MAX_NAME];
        let mut e = JsonEmit::fixed(buf.as_mut_ptr().cast(), buf.len());

        e.obj_open();
        e.kv_int(b"schema", 1);
        e.arr_open(b"packages");
        for st in &state {
            e.obj_open();
            e.kv_string(b"name", cstr(&st.name));
            e.kv_string(b"version", cstr(&st.version));
            e.kv_string(b"source", cstr(&st.source));
            e.obj_close();
        }
        e.arr_close();
        e.obj_close();
        if e.err() != 0 {
            return fail(b"list", e.err());
        }
        print(&[&buf[..e.written()], b"\n"].concat());
        return 0;
    }
    print(b"Installed packages:\n");
    if state.is_empty() {
        print(b"  none\n");
    } else {
        print(
            &[
                b"  ",
                &padded(b"NAME", 24)[..],
                b"  ",
                &padded(b"VERSION", 12),
                b"  SOURCE\n",
            ]
            .concat(),
        );
    }
    for st in &state {
        print(
            &[
                b"  ",
                &padded(cstr(&st.name), 24)[..],
                b"  ",
                &padded(cstr(&st.version), 12),
                b"  ",
                cstr(&st.source),
                b"\n",
            ]
            .concat(),
        );
    }
    0
}

/// `shirudo bpm uninstall <package>`.
pub(super) fn uninstall(args: &[&[u8]]) -> c_int {
    if args.len() != 3 || is_help(Some(args[2])) {
        eprint(b"usage: shirudo bpm uninstall <package>\n");
        return if args.len() == 3 { 0 } else { 2 };
    }
    let name = args[2];
    if !name_ok(name) {
        return fail(b"uninstall", -EINVAL);
    }
    let held = match lock() {
        Ok(held) => held,
        Err(err) => return finish(None, Err(err), b"lock"),
    };
    let ret = bpm_state::read_all().and_then(|mut state| {
        let i = state
            .iter()
            .position(|st| cstr(&st.name) == name)
            .ok_or(-ENOENT)?;
        package_uninstall(&state[i])?;
        state.remove(i);
        status(bpm_state::write(&state))
    });
    finish(Some(held), ret, b"uninstall")
}
