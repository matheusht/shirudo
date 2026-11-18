// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `bpm build`: every upatch of a Beefile compiled and signed in a
//! private stage, its .rodata filled by the converters the Beefile
//! names, its unload directive bound to the payload it ended up with,
//! and the package archived. Also what `bpm config update` shares with
//! it: the paths a Beefile may name, the converters, the stage.

use core::ffi::{CStr, c_int};
use std::ffi::{CString, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::process::Command;

use super::beefile::{MAX_ENTRIES, PATH_MAX, Rodata, Spec, target_ok};
use super::{archive, error, hex, last_err, name_has_suffix, path, strerr};
use crate::errno::{E2BIG, EEXIST, EINVAL, EIO, ENAMETOOLONG, ENOENT};
use crate::shirudo_build::{KeyFiles, compile, package};
use crate::util::crypto_openssl::{Cert, cert_free, cert_pubkey_digest, cert_read_file};
use crate::util::help::{Help, HelpSection};
use crate::util::options::{
    EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OPT_REPEAT, OptParser, OptSpec,
};
use crate::util::upatch::{self, FILE_MAX};

/// A `--rodata-input <name>=<path>`: the input a .rodata converter reads
/// instead of the one the Beefile names.
pub(super) struct Override {
    pub(super) name: Vec<u8>,
    pub(super) path: Vec<u8>,
}

fn realpath(p: &[u8]) -> Result<Vec<u8>, c_int> {
    std::fs::canonicalize(path(p))
        .map(|r| r.as_os_str().as_bytes().to_vec())
        .map_err(|e| -e.raw_os_error().unwrap_or(EIO))
}

/// Whether `p`, resolved, is `dir` or below it.
pub(super) fn within(dir: &[u8], p: &[u8]) -> bool {
    realpath(p).is_ok_and(|r| r.starts_with(dir) && matches!(r.get(dir.len()), None | Some(b'/')))
}

/// A path the Beefile names, resolved: a regular file inside the scope,
/// named relative and without '..'.
pub(super) fn resolve_source(spec: &Spec, source: &[u8]) -> Result<Vec<u8>, c_int> {
    if source.is_empty()
        || source[0] == b'/'
        || source.windows(3).any(|w| w == b"../")
        || source == b".."
    {
        return Err(-EINVAL);
    }
    let p = [&spec.scope[..], b"/", source].concat();
    if p.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    let meta = std::fs::metadata(path(&p)).map_err(|e| -e.raw_os_error().unwrap_or(EIO))?;
    if !meta.is_file() || !within(&spec.scope, &p) {
        return Err(-EINVAL);
    }
    let r = realpath(&p)?;
    if r.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    Ok(r)
}

/// The name a converter input goes by: its file name up to the first
/// '.', which `--rodata-input` matches.
fn input_name(p: &[u8]) -> Option<&[u8]> {
    let base = p
        .iter()
        .rposition(|&c| c == b'/')
        .map_or(p, |s| &p[s + 1..]);
    let name = base
        .iter()
        .position(|&c| c == b'.')
        .map_or(base, |d| &base[..d]);
    (!name.is_empty() && name.len() < 128).then_some(name)
}

/// One `--rodata-input <name>=<path>`: Err(None) for a usage error, or
/// the error of a path that is no regular file.
pub(super) fn parse_override(
    value: &[u8],
    overrides: &mut Vec<Override>,
) -> Result<(), Option<c_int>> {
    let eq = value.iter().position(|&c| c == b'=').ok_or(None)?;
    let (name, p) = (&value[..eq], &value[eq + 1..]);

    if overrides.len() == MAX_ENTRIES || eq == 0 || p.is_empty() || name.len() >= 128 {
        return Err(None);
    }
    if overrides.iter().any(|o| o.name == name) {
        return Err(None);
    }
    let resolved = realpath(p).map_err(Some)?;
    if !std::fs::metadata(path(&resolved)).is_ok_and(|m| m.is_file()) {
        return Err(Some(-EINVAL));
    }
    if resolved.len() >= PATH_MAX {
        return Err(Some(-ENAMETOOLONG));
    }
    overrides.push(Override {
        name: name.to_vec(),
        path: resolved,
    });
    Ok(())
}

/// Every override names an input of some converter.
pub(super) fn overrides_known(spec: &Spec, overrides: &[Override]) -> c_int {
    let known = |name: &[u8]| {
        spec.upatches
            .iter()
            .flat_map(|u| &u.rodata)
            .any(|r| input_name(&r.input) == Some(name))
    };
    if overrides.iter().all(|o| known(&o.name)) {
        0
    } else {
        -ENOENT
    }
}

/// The program a converter runs, which must be in the scope: its first
/// word when a path, else the script its interpreter is given.
fn command_source(r: &Rodata, update: bool) -> Option<&[u8]> {
    let command = if update { &r.update } else { &r.generator };
    let first = command.first()?;
    if first.contains(&b'/') {
        return Some(first);
    }
    command.get(1).map(Vec::as_slice)
}

/// Runs a converter in the scope: its words, then --input, --symbol and
/// --output.
fn run_converter(spec: &Spec, r: &Rodata, update: bool, input: &[u8], output: &[u8]) -> c_int {
    let command = if update { &r.update } else { &r.generator };
    let args = [
        b"--input".as_slice(),
        input,
        b"--symbol",
        &r.symbol,
        b"--output",
        output,
    ];
    let status = Command::new(OsStr::from_bytes(&command[0]))
        .args(command[1..].iter().map(|a| OsStr::from_bytes(a)))
        .args(args.iter().map(|a| OsStr::from_bytes(a)))
        .current_dir(path(&spec.scope))
        .status();
    match status {
        Ok(s) if s.code() == Some(0) => 0,
        _ => -EIO,
    }
}

/// Fills each .rodata symbol of upatch `idx`'s load artifact at `load`
/// with what its converter makes of its input, re-signed in place.
pub(super) fn rodata_apply(
    spec: &Spec,
    idx: usize,
    load: &[u8],
    keys: &KeyFiles,
    overrides: &[Override],
    update: bool,
) -> c_int {
    let u = &spec.upatches[idx];

    for (i, r) in u.rodata.iter().enumerate() {
        let Some(name) = input_name(&r.input) else {
            return -EINVAL;
        };
        let input = match overrides.iter().find(|o| o.name == name) {
            Some(o) => o.path.clone(),
            None => match resolve_source(spec, &r.input) {
                Ok(p) => p,
                Err(err) => return err,
            },
        };
        let generated = format!(
            "{}/rodata-{idx}-{i}.bin",
            String::from_utf8_lossy(&spec.stage)
        )
        .into_bytes();
        let patched = format!(
            "{}/rodata-{idx}-{i}.upatch",
            String::from_utf8_lossy(&spec.stage)
        )
        .into_bytes();
        if generated.len() >= PATH_MAX || patched.len() >= PATH_MAX {
            return -ENAMETOOLONG;
        }
        let _ = std::fs::remove_file(path(&generated));
        let _ = std::fs::remove_file(path(&patched));
        let mut ret = run_converter(spec, r, update, &input, &generated);
        if ret != 0 {
            let what = if update { "config update" } else { "build" };
            error(
                format!(
                    "bpm {what}: converter failed for .rodata symbol {}",
                    String::from_utf8_lossy(&r.symbol)
                )
                .as_bytes(),
            );
        } else {
            ret = match archive::read_file(&generated, FILE_MAX) {
                Ok(value) => {
                    let (l, p) = (cstring(load), cstring(&patched));
                    let s = cstring(&r.symbol);
                    let mut ret = package::patch_rodata(&l, &p, &s, &value, keys);
                    if ret == 0 {
                        if let Err(e) = std::fs::rename(path(&patched), path(load)) {
                            ret = -e.raw_os_error().unwrap_or(EIO);
                        }
                    }
                    ret
                }
                Err(err) => err,
            };
        }
        let _ = std::fs::remove_file(path(&generated));
        if ret != 0 {
            let _ = std::fs::remove_file(path(&patched));
            return ret;
        }
    }
    0
}

pub(super) fn cstring(b: &[u8]) -> CString {
    CString::new(b.to_vec()).unwrap_or_default()
}

/// Whether `path` lies below the directory `dir`.
fn below(dir: &[u8], path: &[u8]) -> bool {
    path.len() > dir.len() && path.starts_with(dir) && path[dir.len()] == b'/'
}

/// A target the archive gets once, and none of the names the package
/// itself carries. A name is a file or a directory, not both: a target
/// below another, or below a member bpm build writes itself, would build
/// and never install.
fn add_target(seen: &mut Vec<Vec<u8>>, target: &[u8]) -> c_int {
    const OWN: [&[u8]; 4] = [
        b"Beefile",
        b"README.md",
        b"cert.der",
        b"build-environment.json",
    ];

    if !target_ok(target) {
        return -EINVAL;
    }
    if OWN.iter().any(|own| *own == target || below(own, target))
        || seen
            .iter()
            .any(|s| s == target || below(s, target) || below(target, s))
    {
        return -EEXIST;
    }
    if seen.len() >= MAX_ENTRIES * 3 {
        return -E2BIG;
    }
    seen.push(target.to_vec());
    0
}

/// The checks the build makes of a Beefile beyond its syntax: every
/// target unique and safe, every source in the scope, every converter
/// input and program there, one input of each name, and each policy one
/// bit throughout.
pub(super) fn validate(spec: &Spec, allow_missing_upatch_source: bool) -> c_int {
    let mut seen = Vec::new();

    for f in &spec.files {
        if add_target(&mut seen, &f.target) != 0 || resolve_source(spec, &f.source).is_err() {
            return -EINVAL;
        }
    }
    for (i, u) in spec.upatches.iter().enumerate() {
        let source_ok = if allow_missing_upatch_source {
            target_ok(&u.source)
        } else {
            resolve_source(spec, &u.source).is_ok()
        };
        if add_target(&mut seen, &u.load_target) != 0
            || add_target(&mut seen, &u.unload_target) != 0
            || !source_ok
        {
            return -EINVAL;
        }
        for (j, r) in u.rodata.iter().enumerate() {
            let Some(name) = resolve_source(spec, &r.input)
                .ok()
                .and(input_name(&r.input))
            else {
                return -EINVAL;
            };
            let earlier = spec.upatches[..i]
                .iter()
                .flat_map(|p| &p.rodata)
                .chain(&u.rodata[..j]);
            for prev in earlier {
                let Some(other) = input_name(&prev.input) else {
                    return -EINVAL;
                };
                if name == other && r.input != prev.input {
                    return -EEXIST;
                }
            }
            for update in [false, true] {
                match command_source(r, update) {
                    Some(s) if resolve_source(spec, s).is_ok() => {}
                    _ => return -EINVAL,
                }
            }
        }
        for (j, p) in u.policies.iter().enumerate() {
            if p.id.is_empty() || p.bit == 0 || p.paths.is_empty() || p.bit & (p.bit - 1) != 0 {
                return -EINVAL;
            }
            if p.paths.iter().any(|path| path.first() != Some(&b'/')) {
                return -EINVAL;
            }
            for (x, other) in spec.upatches[..=i].iter().enumerate() {
                let limit = if x == i { j } else { other.policies.len() };
                for q in &other.policies[..limit] {
                    if (p.id == q.id) != (p.bit == q.bit) {
                        return -EEXIST;
                    }
                }
            }
        }
    }
    0
}

/// The upatch name of a source or object path: its file name without
/// .bpf.c, .bpf.o or .o.
pub(crate) fn upatch_name(source: &[u8]) -> Result<Vec<u8>, c_int> {
    let base = source
        .iter()
        .rposition(|&c| c == b'/')
        .map_or(source, |s| &source[s + 1..]);
    if base.len() >= upatch::NAME_MAX {
        return Err(-E2BIG);
    }
    let strip = if name_has_suffix(base, b".bpf.c") || name_has_suffix(base, b".bpf.o") {
        6
    } else if name_has_suffix(base, b".o") {
        2
    } else {
        0
    };
    Ok(base[..base.len() - strip].to_vec())
}

/// The artifacts are signed into a directory of their own under names of
/// their own, so no target name can reach a file of the operator's and
/// the build leaves nothing behind.
pub(super) fn stage_open(spec: &mut Spec) -> c_int {
    let tmpdir = std::env::var_os("TMPDIR")
        .filter(|t| !t.is_empty())
        .map_or(b"/tmp".to_vec(), |t| t.as_bytes().to_vec());
    let template = [&tmpdir[..], b"/shirudo-bpm-build.XXXXXX\0"].concat();

    if template.len() > PATH_MAX {
        return -ENAMETOOLONG;
    }
    let mut buf = template;
    // SAFETY: the template, which mkdtemp() fills in.
    if unsafe { crate::sys::libc::mkdtemp(buf.as_mut_ptr().cast()) }.is_null() {
        return last_err();
    }
    let made = crate::text::cstr(&buf).to_vec();
    match realpath(&made) {
        Ok(r) if r.len() < PATH_MAX => {
            spec.stage = r;
            0
        }
        Ok(r) => {
            let _ = std::fs::remove_dir(path(&r));
            -ENAMETOOLONG
        }
        Err(err) => {
            let _ = std::fs::remove_dir(path(&made));
            err
        }
    }
}

/// Removes what the build signed and the stage, whatever it holds.
pub(super) fn stage_close(spec: &Spec) {
    for u in spec.upatches.iter().filter(|u| !u.load_path.is_empty()) {
        let _ = std::fs::remove_file(path(&[&u.load_path[..], b".bpf.o"].concat()));
        let _ = std::fs::remove_file(path(&u.load_path));
        let _ = std::fs::remove_file(path(&u.unload_path));
    }
    if !spec.stage.is_empty() {
        let _ = std::fs::remove_dir_all(path(&spec.stage));
    }
}

/// The policy labels of an upatch, `struct upatch_policy_label_entry`
/// each, one per path of each policy.
fn policy_labels(u: &super::beefile::Upatch) -> (Vec<u8>, u32) {
    let mut labels = Vec::new();
    let mut n = 0;

    for p in &u.policies {
        for path in &p.paths {
            let mut e = [0u8; upatch::POLICY_LABEL_ENTRY];
            e[..8].copy_from_slice(&p.bit.to_le_bytes());
            let id = &p.id[..p.id.len().min(63)];
            e[8..8 + id.len()].copy_from_slice(id);
            let path = &path[..path.len().min(4095)];
            e[72..72 + path.len()].copy_from_slice(path);
            labels.extend_from_slice(&e);
            n += 1;
        }
    }
    (labels, n)
}

/// Compiles, packages and signs every upatch, then binds each unload
/// directive to the payload digest its load artifact ended up with.
fn build_upatches(
    spec: &mut Spec,
    keys: &KeyFiles,
    vmlinux: Option<&CStr>,
    incdir: Option<&CStr>,
    overrides: &[Override],
) -> c_int {
    let mut vmlinux_h: Option<CString> = vmlinux.map(CStr::to_owned);

    for i in 0..spec.upatches.len() {
        let Ok(source) = resolve_source(spec, &spec.upatches[i].source) else {
            return -EINVAL;
        };
        let stage = String::from_utf8_lossy(&spec.stage).into_owned();
        let (load, unload) = (
            format!("{stage}/{i}.upatch").into_bytes(),
            format!("{stage}/{i}.unload.upatch").into_bytes(),
        );
        if load.len() >= PATH_MAX || unload.len() >= PATH_MAX {
            return -ENAMETOOLONG;
        }
        spec.upatches[i].load_path = load.clone();
        spec.upatches[i].unload_path = unload.clone();
        let object = [&load[..], b".bpf.o"].concat();
        let (bpf_o, src_path) = if name_has_suffix(&source, b".bpf.c") {
            if vmlinux_h.is_none() {
                match compile::locate_vmlinux(None) {
                    Some(v) => vmlinux_h = Some(v.to_owned()),
                    None => {
                        error(format!("bpm build: vmlinux.h not found (tried ./vmlinux.h, ./vendor/linux/vmlinux.h, {})", compile::VMLINUX_PATH).as_bytes());
                        return -ENOENT;
                    }
                }
            }
            if object.len() >= PATH_MAX {
                return -ENAMETOOLONG;
            }
            let v = vmlinux_h.as_deref().unwrap_or_default();
            if let Err(ret) =
                compile::compile(&cstring(&source), &cstring(&object), v, None, incdir)
            {
                error(
                    &[
                        b"bpm build: compile ",
                        &spec.upatches[i].source[..],
                        b" failed",
                    ]
                    .concat(),
                );
                return if ret < 0 { ret } else { -EIO };
            }
            (object.clone(), Some(cstring(&source)))
        } else if !name_has_suffix(&source, b".o") {
            error(
                &[
                    b"bpm build: ",
                    &spec.upatches[i].source[..],
                    b" is neither .bpf.c nor .bpf.o",
                ]
                .concat(),
            );
            return -EINVAL;
        } else {
            (source.clone(), None)
        };
        let Ok(name) = upatch_name(&source) else {
            return -ENAMETOOLONG;
        };
        let (labels, nr) = policy_labels(&spec.upatches[i]);
        let ret = package::load(
            &cstring(&bpf_o),
            src_path.as_deref(),
            &cstring(&load),
            &cstring(&name),
            &labels,
            nr,
            (&keys.pkey, &keys.cert),
        );
        if bpf_o == object {
            let _ = std::fs::remove_file(path(&object));
        }
        if ret != 0 {
            return if ret < 0 { ret } else { -EIO };
        }
        let ret = rodata_apply(spec, i, &load, keys, overrides, false);
        if ret != 0 {
            return ret;
        }
        let ret = record_payload(spec, i, &load, false);
        if ret != 0 {
            return ret;
        }
        let u = &spec.upatches[i];
        let digest = digest_of(&u.payload_sha256);
        let ret = package::unload(
            &cstring(&u.name),
            &digest,
            &cstring(&unload),
            (&keys.pkey, &keys.cert),
        );
        if ret != 0 {
            return if ret < 0 { ret } else { -EIO };
        }
    }
    0
}

/// The 32 bytes of a hex digest the build recorded.
pub(super) fn digest_of(hex_digest: &[u8]) -> [u8; 32] {
    let mut d = [0u8; 32];
    for (i, b) in d.iter_mut().enumerate() {
        let pair = &hex_digest[2 * i..2 * i + 2];
        *b = u8::from_str_radix(std::str::from_utf8(pair).unwrap_or("00"), 16).unwrap_or(0);
    }
    d
}

/// Records what the signed load artifact at `load` says it is: its
/// name, payload digest and type. Refuses an unload directive and, with
/// `named`, one whose name is empty.
pub(super) fn record_payload(spec: &mut Spec, i: usize, load: &[u8], update: bool) -> c_int {
    // SAFETY: an all-zero container is a closed one.
    let mut u: upatch::Upatch = unsafe { core::mem::zeroed() };
    let p = cstring(load);
    // SAFETY: a C string and the container to fill.
    if unsafe { upatch::upatch_open(p.as_ptr(), &mut u) } != 0 {
        return -EINVAL;
    }
    let refused = upatch::is_unload(&u) || (!update && u.hdr.name[0] == 0);
    let mut name = [0u8; upatch::NAME_MAX + 1];
    if !refused {
        upatch::header_name(&u, &mut name);
    }
    let digest = u.hdr.payload_sha256;
    // SAFETY: the container opened above.
    unsafe { upatch::upatch_close(&mut u) };
    if refused {
        return -EINVAL;
    }
    let up = &mut spec.upatches[i];
    up.name = crate::text::cstr(&name).to_vec();
    up.payload_sha256 = hex(&digest);
    up.ty = b"bpf".to_vec();
    0
}

/// `--version`: a SemVer 2.0.0 version, which the target orders as the
/// operator means it.
pub(super) fn version_ok(v: &CStr) -> bool {
    // SAFETY: a C string.
    v.to_bytes().len() < 128 && unsafe { crate::util::bpm_package::bpm_semver_valid(v.as_ptr()) }
}

/// The SPKI SHA-256 of the certificate at `cert_path`, in hex.
pub(super) fn fingerprint(cert_path: &CStr) -> Result<Vec<u8>, c_int> {
    let mut cert = Cert::new();
    let mut digest = [0u8; 32];

    // SAFETY: a C string and the cert to fill.
    if unsafe { cert_read_file(cert_path.as_ptr(), &mut cert) } != 0 {
        return Err(-ENOENT);
    }
    // SAFETY: the cert read above and room for its digest; then freed.
    let ret = unsafe {
        let ret = cert_pubkey_digest(&cert, digest.as_mut_ptr());
        cert_free(&mut cert);
        ret
    };
    if ret != 0 { Err(ret) } else { Ok(hex(&digest)) }
}

/// The Beefile at `file`, read and checked, into a spec scoped to its
/// directory.
pub(super) fn load_spec(file: &[u8], allow_missing: bool, what: &str) -> Result<Spec, c_int> {
    let resolved = realpath(file)?;
    let slash = resolved.iter().rposition(|&c| c == b'/').ok_or(-EINVAL)?;
    let mut spec = Spec {
        scope: resolved[..slash].to_vec(),
        ..Spec::default()
    };
    let body = archive::read_file(&resolved, archive::MAX_FILE)?;
    let mut ret = super::beefile::parse(&body, &mut spec);
    if ret == 0 && !what.is_empty() {
        ret = validate(&spec, allow_missing);
    }
    if ret != 0 {
        if !what.is_empty() {
            error(
                format!(
                    "bpm {what}: {} is not a valid Beefile",
                    String::from_utf8_lossy(&resolved)
                )
                .as_bytes(),
            );
        }
        return Err(ret);
    }
    Ok(spec)
}

/// `bpm build`, from `build` on.
const BPM_BUILD_FILE: c_int = 0;
const BPM_BUILD_VERSION: c_int = 1;
const BPM_BUILD_KEYS_DIR: c_int = 2;
const BPM_BUILD_VMLINUX: c_int = 3;
const BPM_BUILD_RODATA_INPUT: c_int = 4;

static BPM_BUILD_OPTS: [OptSpec; 5] = [
    OptSpec::new(
        c"--file",
        0,
        0,
        Some(c"<name>.bee"),
        c"the Beefile to build, in the context directory",
    ),
    OptSpec::new(
        c"--version",
        0,
        0,
        Some(c"<version>"),
        c"the SemVer 2.0.0 version of the package",
    ),
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"read signing_key.pem and cert.der from <dir>",
    ),
    OptSpec::new(
        c"--vmlinux",
        0,
        0,
        Some(c"<vmlinux.h>"),
        c"compile against it",
    ),
    OptSpec::new(
        c"--rodata-input",
        0,
        OPT_REPEAT,
        Some(c"<name>=<path>"),
        c"a file for a .rodata input (repeatable)",
    ),
];

static BPM_BUILD_SECTIONS: [HelpSection; 1] = [HelpSection::options(c"options:", &BPM_BUILD_OPTS)];

static BPM_BUILD_HELP: Help = Help::new(
    c"shirudo bpm build [context] --version <version> [--file <name>.bee]\n                         \
      [--keys-dir <dir>] [--vmlinux <vmlinux.h>]\n                         \
      [--rodata-input <name>=<path>]...",
    Some(
        c"Build a signed .bee package from a Beefile. Operator-only; needs the\n\
          signing keys.",
    ),
    &BPM_BUILD_SECTIONS,
    None,
);

/// `bpm build`, from `build` on: 0, EXIT_USAGE, or -errno.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let mut p = OptParser::new(
        c"bpm build",
        &BPM_BUILD_OPTS,
        Some(&BPM_BUILD_HELP),
        args,
        1,
    );
    let mut context: &[u8] = b".";
    let (mut file, mut version): (Option<&CStr>, Option<&CStr>) = (None, None);
    let (mut keys_arg, mut vmlinux_arg): (Option<&CStr>, Option<&CStr>) = (None, None);
    let mut overrides = Vec::new();
    let mut positional = 0;

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            BPM_BUILD_FILE => file = value,
            BPM_BUILD_VERSION => version = value,
            BPM_BUILD_KEYS_DIR => keys_arg = value,
            BPM_BUILD_VMLINUX => vmlinux_arg = value,
            BPM_BUILD_RODATA_INPUT => {
                match parse_override(value.map_or(&b""[..], CStr::to_bytes), &mut overrides) {
                    Ok(()) => {}
                    Err(None) => {
                        p.usage(b"--rodata-input takes <name>=<path>");
                        return EXIT_USAGE;
                    }
                    Err(Some(err)) => return err,
                }
            }
            OPT_ARG => {
                positional += 1;
                if positional > 1 {
                    p.usage_arg(b"unexpected argument ");
                    return EXIT_USAGE;
                }
                context = value.map_or(&b"."[..], CStr::to_bytes);
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let Some(version) = version else {
        p.usage(b"--version <version> is required");
        return EXIT_USAGE;
    };
    if !version_ok(version) {
        error(format!("bpm build: --version {} is not a SemVer 2.0.0 version such as 1.2.0, 1.2.0-rc.1 or 1.2.0+build.5", String::from_utf8_lossy(version.to_bytes())).as_bytes());
        return -EINVAL;
    }
    build(context, file, version, keys_arg, vmlinux_arg, &overrides)
}

fn build(
    context: &[u8],
    file: Option<&CStr>,
    version: &CStr,
    keys_arg: Option<&CStr>,
    vmlinux_arg: Option<&CStr>,
    overrides: &[Override],
) -> c_int {
    let keys_dir = super::resolve_keys_dir(keys_arg);
    let Some(keys_abs) = keys_dir.as_deref().and_then(|d| realpath(d).ok()) else {
        let shown = keys_dir.unwrap_or_default();
        error(
            format!(
                "bpm build: keys directory {} is not usable",
                String::from_utf8_lossy(&shown)
            )
            .as_bytes(),
        );
        return -ENOENT;
    };
    let keys = match KeyFiles::under(&keys_abs) {
        Ok(k) => k,
        Err(err) => return err,
    };
    if crate::shirudo_build::check_keys(&keys.pkey, &keys.cert) != 0 {
        return -crate::errno::EACCES;
    }
    let vmlinux = match vmlinux_arg {
        Some(v) => match realpath(v.to_bytes()) {
            Ok(p) => Some(cstring(&p)),
            Err(err) => {
                error(
                    &[
                        b"bpm build: cannot resolve vmlinux.h ",
                        v.to_bytes(),
                        b": ",
                        strerr(-err),
                    ]
                    .concat(),
                );
                return err;
            }
        },
        None => [&b"./vmlinux.h"[..], b"./vendor/linux/vmlinux.h"]
            .iter()
            .find_map(|p| realpath(p).ok())
            .map(|p| cstring(&p)),
    };
    let out_dir = match std::env::current_dir() {
        Ok(d) => d.as_os_str().as_bytes().to_vec(),
        Err(e) => return -e.raw_os_error().unwrap_or(EIO),
    };
    let incdir = realpath(b"bpf/lib")
        .ok()
        .filter(|d| {
            let h = cstring(&[&d[..], b"/serializer.h"].concat());
            d.len() + 14 < PATH_MAX && compile::readable(&h)
        })
        .map(|d| cstring(&d));
    let build_file = match file {
        Some(f) if f.to_bytes().len() >= PATH_MAX => return -ENAMETOOLONG,
        Some(f) => f.to_bytes().to_vec(),
        None => {
            let p = [context, b"/Beefile"].concat();
            if p.len() >= PATH_MAX {
                return -ENAMETOOLONG;
            }
            p
        }
    };
    if let Err(err) = realpath(&build_file) {
        return err;
    }
    let mut spec = match load_spec(&build_file, false, "build") {
        Ok(s) => s,
        Err(err) => return err,
    };
    let ret = overrides_known(&spec, overrides);
    if ret != 0 {
        return ret;
    }
    let fp = match fingerprint(&keys.cert) {
        Ok(f) => f,
        Err(err) => return err,
    };
    // Compile in the package directory so ./vmlinux.h and the vendored
    // headers resolve the way they do for `shirudo build` run there.
    if let Err(e) = std::env::set_current_dir(path(&spec.scope)) {
        return -e.raw_os_error().unwrap_or(EIO);
    }
    let ret = stage_open(&mut spec);
    if ret != 0 {
        return ret;
    }
    let mut ret = build_upatches(
        &mut spec,
        &keys,
        vmlinux.as_deref(),
        incdir.as_deref(),
        overrides,
    );
    if ret == 0 {
        ret = archive::write(
            "bpm build",
            &spec,
            version.to_bytes(),
            keys.cert.to_bytes(),
            &fp,
            &out_dir,
        );
    }
    stage_close(&spec);
    ret
}
