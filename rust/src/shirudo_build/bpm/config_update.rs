// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `bpm config update`: a published package rebuilt at a later version
//! with only its .rodata changed, by the converters' update commands and
//! the operator's new inputs. The load artifacts are the base package's,
//! verified against the operator's certificate, re-signed with the new
//! .rodata, and their unload directives bound anew.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};

use super::build::{self, Override, cstring};
use super::{archive, error, path};
use crate::errno::{EACCES, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT, ENOTDIR};
use crate::heap::xfree;
use crate::shirudo_build::{KeyFiles, check_keys, package};
use crate::util::bpm_oci::{Client, MANIFEST_MEDIA, digest_matches, manifest_layers, sha256_hex};
use crate::util::bpm_package::{
    PackageInfo, bpm_pkg_load_info, bpm_pkg_read_member, semver_compare,
};
use crate::util::help::{Help, HelpSection};
use crate::util::options::{
    EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OPT_REPEAT, OptParser, OptSpec,
};
use crate::util::upatch;

const PACKAGE_MEDIA: &CStr = c"application/vnd.shirudo.bpm.package.v1+gzip";
const PATH_MAX: usize = 4096;

/// A package's identity, its certificate freed when it goes.
pub(super) struct Info(pub(super) PackageInfo);

impl Info {
    pub(super) fn load(package: &CStr) -> Result<Self, c_int> {
        // SAFETY: an all-zero info is an empty one.
        let mut info = Info(unsafe { core::mem::zeroed() });
        // SAFETY: a C string and the info to fill.
        match unsafe { bpm_pkg_load_info(package.as_ptr(), &mut info.0) } {
            0 => Ok(info),
            err => Err(err),
        }
    }

    pub(super) fn cert(&self) -> &[u8] {
        if self.0.cert.is_null() {
            return &[];
        }
        // SAFETY: the info's certificate.
        unsafe { crate::ffi::slice(self.0.cert, self.0.cert_len) }
    }
}

impl Drop for Info {
    fn drop(&mut self) {
        if !self.0.cert.is_null() {
            // SAFETY: the certificate the info holds, of len + 1 bytes.
            unsafe { xfree(self.0.cert.cast(), self.0.cert_len + 1) };
        }
    }
}

/// Member `member` of the package, at most `max` bytes.
pub(super) fn read_member(package: &CStr, member: &[u8], max: usize) -> Result<Vec<u8>, c_int> {
    let (mut body, mut len): (*mut u8, usize) = (ptr::null_mut(), 0);
    let m = cstring(member);
    // SAFETY: C strings and room for the body and its length.
    let ret =
        unsafe { bpm_pkg_read_member(package.as_ptr(), m.as_ptr(), &mut body, &mut len, max) };
    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the member's len bytes.
    let out = unsafe { crate::ffi::slice(body, len) }.to_vec();
    // SAFETY: the member's buffer of len + 1 bytes.
    unsafe { xfree(body.cast(), len + 1) };
    Ok(out)
}

/// Member `member` of the package, written to `output`, which must not
/// exist, with the directories above it.
fn copy_member(package: &CStr, member: &[u8], output: &[u8]) -> c_int {
    let body = match read_member(package, member, archive::MAX_FILE) {
        Ok(b) => b,
        Err(err) => return err,
    };
    if output.len() >= PATH_MAX {
        return -ENAMETOOLONG;
    }
    if let Some(slash) = output.iter().rposition(|&c| c == b'/') {
        let parent = &output[..slash];
        let start = usize::from(parent.first() == Some(&b'/'));
        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        let ends = parent[start..]
            .iter()
            .enumerate()
            .filter(|&(_, &c)| c == b'/')
            .map(|(i, _)| start + i)
            .chain([parent.len()]);
        for end in ends {
            let dir = &parent[..end];
            if let Err(e) = builder.create(path(dir)) {
                if e.kind() != std::io::ErrorKind::AlreadyExists {
                    return -e.raw_os_error().unwrap_or(EIO);
                }
            }
            match std::fs::symlink_metadata(path(dir)) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => return -ENOTDIR,
                Err(e) => return -e.raw_os_error().unwrap_or(EIO),
            }
        }
    }
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path(output));
    let mut file = match file {
        Ok(f) => f,
        Err(e) => return -e.raw_os_error().unwrap_or(EIO),
    };
    match file.write_all(&body).and_then(|()| file.sync_all()) {
        Ok(()) => 0,
        Err(e) => -e.raw_os_error().unwrap_or(EIO),
    }
}

/// The package an `oci://` reference names, into a temporary file whose
/// path it returns, checked against the digest its manifest gives.
/// The package of the manifest whose digest the operator named, `want`,
/// into a file of /tmp, removed again on a failure once it was made.
fn download(reference: &[u8], want: &[u8]) -> Result<Vec<u8>, c_int> {
    let mut c = Client::new();
    let (repo, tag) = c.parse_pull_ref(reference)?;
    let url = c.url(&repo, b"manifests", &tag)?;
    let manifest = c.get(&url, MANIFEST_MEDIA, false)?;
    let mut hex = [0u8; 65];
    if sha256_hex(manifest.bytes(), &mut hex) != 0 {
        return Err(-EINVAL);
    }
    let served = crate::text::cstr(&hex);
    if !digest_matches(want, served) {
        error(
            format!(
                "bpm config update: {} serves manifest sha256:{}, not {}",
                String::from_utf8_lossy(reference),
                String::from_utf8_lossy(served),
                String::from_utf8_lossy(want)
            )
            .as_bytes(),
        );
        return Err(-EKEYREJECTED);
    }
    let (layers, _) = manifest_layers(manifest.bytes(), 8, false)?;
    let Some(layer) = layers
        .iter()
        .find(|l| l.media() == PACKAGE_MEDIA.to_bytes())
    else {
        return Err(-ENOENT);
    };
    let url = c.url(&repo, b"blobs", layer.digest())?;
    let mut tmpl = *b"/tmp/shirudo-bpm-base-XXXXXX\0";
    // SAFETY: the template, which mkstemp() fills in.
    let fd = unsafe { crate::sys::libc::mkstemp(tmpl.as_mut_ptr().cast()) };
    if fd < 0 {
        return Err(super::last_err());
    }
    let tmp = crate::text::cstr(&tmpl).to_vec();
    let fail = |err: c_int| {
        let _ = std::fs::remove_file(path(&tmp));
        Err(err)
    };
    let mut ret = c
        .get_file(&url, PACKAGE_MEDIA, fd, layer.size())
        .err()
        .unwrap_or(0);
    // SAFETY: the descriptor mkstemp() opened.
    if unsafe { crate::sys::libc::close(fd) } != 0 && ret == 0 {
        ret = super::last_err();
    }
    if ret != 0 {
        return fail(ret);
    }
    let body = match archive::read_file(&tmp, archive::MAX_FILE) {
        Ok(b) => b,
        Err(err) => return fail(err),
    };
    let mut hex = [0u8; 65];
    if sha256_hex(&body, &mut hex) != 0 || !digest_matches(layer.digest(), crate::text::cstr(&hex))
    {
        return fail(-EKEYREJECTED);
    }
    Ok(tmp)
}

/// `bpm config update`, from `update` on.
const CONFIG_UPDATE_FILE: c_int = 0;
const CONFIG_UPDATE_BASE_PACKAGE: c_int = 1;
const CONFIG_UPDATE_BASE_DIGEST: c_int = 2;
const CONFIG_UPDATE_VERSION: c_int = 3;
const CONFIG_UPDATE_KEYS_DIR: c_int = 4;
const CONFIG_UPDATE_RODATA_INPUT: c_int = 5;

static CONFIG_UPDATE_OPTS: [OptSpec; 6] = [
    OptSpec::new(
        c"--file",
        0,
        0,
        Some(c"<name>.bee"),
        c"the Beefile, instead of the base package's",
    ),
    OptSpec::new(
        c"--base-package",
        0,
        0,
        Some(c"<package.bee|oci://host/repo:tag>"),
        c"the package the update builds on",
    ),
    OptSpec::new(
        c"--base-digest",
        0,
        0,
        Some(c"sha256:<manifest>"),
        c"the manifest digest of an oci:// base package",
    ),
    OptSpec::new(
        c"--version",
        0,
        0,
        Some(c"<version>"),
        c"the SemVer 2.0.0 version of the update",
    ),
    OptSpec::new(
        c"--keys-dir",
        0,
        0,
        Some(c"<dir>"),
        c"read signing_key.pem and cert.der from <dir>",
    ),
    OptSpec::new(
        c"--rodata-input",
        0,
        OPT_REPEAT,
        Some(c"<name>=<path>"),
        c"a file for a .rodata input (repeatable)",
    ),
];

static CONFIG_UPDATE_SECTIONS: [HelpSection; 1] =
    [HelpSection::options(c"options:", &CONFIG_UPDATE_OPTS)];

static CONFIG_UPDATE_HELP: Help = Help::new(
    c"shirudo bpm config update --base-package <package.bee|oci://host/repo:tag>\n                                 \
      --version <version> [options]",
    Some(
        c"Build a config update package on a base package. Without --file, the\n\
          Beefile and the updater inputs come from --base-package and are trusted\n\
          as operator-side code. An oci:// base package needs --base-digest, the\n\
          manifest digest bpm push printed for it.",
    ),
    &CONFIG_UPDATE_SECTIONS,
    None,
);

/// Whether `digest` is sha256:<64 lowercase hex>.
fn digest_ok(digest: &[u8]) -> bool {
    digest.strip_prefix(b"sha256:").is_some_and(|hex| {
        hex.len() == 64 && hex.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
    })
}

/// `bpm config update`, from `update` on: 0, EXIT_USAGE, or -errno.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let raw: Vec<*const c_char> = args.iter().map(|a| a.as_ptr()).collect();
    let mut p = OptParser::new(
        c"bpm config update",
        &CONFIG_UPDATE_OPTS,
        Some(&CONFIG_UPDATE_HELP),
        &raw,
        1,
    );
    let (mut file, mut base, mut base_digest) = (None, None, None);
    let (mut version, mut keys_arg) = (None, None);
    let mut overrides = Vec::new();

    loop {
        let opt = p.next();
        let value = p.value();
        match opt {
            OPT_END => break,
            CONFIG_UPDATE_FILE => file = value,
            CONFIG_UPDATE_BASE_PACKAGE => base = value,
            CONFIG_UPDATE_BASE_DIGEST => base_digest = value,
            CONFIG_UPDATE_VERSION => version = value,
            CONFIG_UPDATE_KEYS_DIR => keys_arg = value,
            CONFIG_UPDATE_RODATA_INPUT => {
                match build::parse_override(value.map_or(&b""[..], CStr::to_bytes), &mut overrides)
                {
                    Ok(()) => {}
                    Err(None) => {
                        p.usage(b"--rodata-input takes <name>=<path>");
                        return EXIT_USAGE;
                    }
                    Err(Some(err)) => return err,
                }
            }
            OPT_ARG => {
                p.usage_arg(b"unexpected argument ");
                return EXIT_USAGE;
            }
            OPT_DONE => return 0,
            _ => return EXIT_USAGE,
        }
    }
    let (Some(base), Some(version)) = (base, version) else {
        p.usage(b"takes --base-package and --version");
        return EXIT_USAGE;
    };
    if !build::version_ok(version) {
        error(format!("bpm config update: --version {} is not a SemVer 2.0.0 version such as 1.2.0, 1.2.0-rc.1 or 1.2.0+build.5", String::from_utf8_lossy(version.to_bytes())).as_bytes());
        return -EINVAL;
    }
    // A tag is the registry's to point at any package the key ever
    // signed, an older one included, whose loaders this would sign as a
    // new version: an oci:// base package is the manifest the operator
    // names.
    if base.to_bytes().starts_with(b"oci://") != base_digest.is_some() {
        error(b"bpm config update: --base-digest names the manifest of an oci:// base package, and one needs it");
        return -EINVAL;
    }
    if let Some(d) = base_digest.filter(|d| !digest_ok(d.to_bytes())) {
        error(
            format!(
                "bpm config update: --base-digest {} is not sha256:<64 lowercase hex>",
                String::from_utf8_lossy(d.to_bytes())
            )
            .as_bytes(),
        );
        return -EINVAL;
    }
    let (package, downloaded) = match base_digest {
        Some(want) => match download(base.to_bytes(), want.to_bytes()) {
            Ok(p) => (p, true),
            Err(err) => return err,
        },
        None => match std::fs::canonicalize(path(base.to_bytes())) {
            Ok(p) => (p.as_os_str().as_bytes().to_vec(), false),
            Err(e) => {
                let err = e.raw_os_error().unwrap_or(EIO);
                p.usage(
                    &[
                        b"--base-package ",
                        base.to_bytes(),
                        b": ",
                        super::strerr(err),
                    ]
                    .concat(),
                );
                return EXIT_USAGE;
            }
        },
    };
    let ret = update(&cstring(&package), file, version, keys_arg, &overrides);
    if downloaded {
        let _ = std::fs::remove_file(path(&package));
    }
    ret
}

fn update(
    package: &CStr,
    file: Option<&CStr>,
    version: &CStr,
    keys_arg: Option<&CStr>,
    overrides: &[Override],
) -> c_int {
    let info = match Info::load(package) {
        Ok(i) => i,
        Err(err) => return err,
    };
    if semver_compare(version.to_bytes(), crate::text::cstr(&info.0.version)) <= 0 {
        return -EINVAL;
    }
    let out_dir = match std::env::current_dir() {
        Ok(d) => d.as_os_str().as_bytes().to_vec(),
        Err(e) => return -e.raw_os_error().unwrap_or(EIO),
    };
    let Some(keys_abs) =
        super::resolve_keys_dir(keys_arg).and_then(|d| std::fs::canonicalize(path(&d)).ok())
    else {
        return -ENOENT;
    };
    let keys = match KeyFiles::under(keys_abs.as_os_str().as_bytes()) {
        Ok(k) => k,
        Err(err) => return err,
    };
    if check_keys(&keys.pkey, &keys.cert) != 0 {
        return -EACCES;
    }
    let mut spec = super::beefile::Spec::default();
    let ret = staged(
        &mut spec, package, &info, file, version, &keys, overrides, &out_dir,
    );
    if !spec.stage.is_empty() {
        let back = std::env::set_current_dir(path(&out_dir));
        build::stage_close(&spec);
        if let (Err(e), 0) = (back, ret) {
            return -e.raw_os_error().unwrap_or(EIO);
        }
    }
    ret
}

#[allow(clippy::too_many_arguments)]
fn staged(
    spec: &mut super::beefile::Spec,
    package: &CStr,
    info: &Info,
    file: Option<&CStr>,
    version: &CStr,
    keys: &KeyFiles,
    overrides: &[Override],
    out_dir: &[u8],
) -> c_int {
    let from_package = file.is_none();
    let build_file = if from_package {
        let ret = build::stage_open(spec);
        if ret != 0 {
            return ret;
        }
        let source_dir = [&spec.stage[..], b"/source"].concat();
        if let Err(e) = std::fs::DirBuilder::new()
            .mode(0o700)
            .create(path(&source_dir))
        {
            return -e.raw_os_error().unwrap_or(EIO);
        }
        let bf = [&source_dir[..], b"/Beefile"].concat();
        let ret = copy_member(package, b"Beefile", &bf);
        if ret == -ENOENT {
            error(format!("bpm config update: base package {} has no Beefile; rebuild it with a Beefile or pass --file <name>.bee", String::from_utf8_lossy(package.to_bytes())).as_bytes());
            return -EINVAL;
        }
        if ret != 0 {
            return ret;
        }
        bf
    } else {
        file.map(|f| f.to_bytes().to_vec()).unwrap_or_default()
    };
    let stage = core::mem::take(&mut spec.stage);
    *spec = match build::load_spec(&build_file, false, "") {
        Ok(s) => s,
        Err(err) => {
            spec.stage = stage;
            return err;
        }
    };
    spec.stage = stage;
    let mut ret = 0;
    if from_package {
        for f in &spec.files {
            if !super::beefile::target_ok(&f.source) || !super::beefile::target_ok(&f.target) {
                ret = -EINVAL;
                break;
            }
            let out = [&spec.scope[..], b"/", &f.source].concat();
            ret = copy_member(package, &f.target, &out);
            if ret != 0 {
                break;
            }
        }
        if ret == 0 {
            ret = copy_member(
                package,
                b"README.md",
                &[&spec.scope[..], b"/README.md"].concat(),
            );
            if ret == -ENOENT {
                ret = 0;
            }
        }
    }
    if ret == 0 {
        ret = build::validate(spec, from_package);
    }
    if ret == 0 {
        ret = build::overrides_known(spec, overrides);
    }
    if ret == 0 && spec.name != crate::text::cstr(&info.0.name) {
        ret = -EINVAL;
    }
    if ret == 0 && spec.upatches.iter().all(|u| u.rodata.is_empty()) {
        ret = -EINVAL;
    }
    if ret != 0 {
        return ret;
    }
    let fp = match build::fingerprint(&keys.cert) {
        Ok(f) => f,
        Err(err) => return err,
    };
    if fp != crate::text::cstr(&info.0.signer) {
        return -EKEYREJECTED;
    }
    if let Err(e) = std::env::set_current_dir(path(&spec.scope)) {
        return -e.raw_os_error().unwrap_or(EIO);
    }
    if spec.stage.is_empty() {
        let ret = build::stage_open(spec);
        if ret != 0 {
            return ret;
        }
    }
    for i in 0..spec.upatches.len() {
        let stage = String::from_utf8_lossy(&spec.stage).into_owned();
        let (load, unload) = (
            format!("{stage}/update-{i}.upatch").into_bytes(),
            format!("{stage}/update-{i}.unload.upatch").into_bytes(),
        );
        if load.len() >= PATH_MAX || unload.len() >= PATH_MAX {
            return -ENAMETOOLONG;
        }
        let ret = copy_member(package, &spec.upatches[i].load_target, &load);
        if ret != 0 {
            return ret;
        }
        let ret = package::verify_package(&cstring(&load), &keys.cert);
        if ret != 0 {
            return ret;
        }
        let expected = match build::upatch_name(&spec.upatches[i].source) {
            Ok(n) => n,
            Err(err) => return err,
        };
        let ret = name_matches(&load, &expected);
        if ret != 0 {
            return ret;
        }
        let ret = build::rodata_apply(spec, i, &load, keys, overrides, true);
        if ret != 0 {
            return ret;
        }
        let ret = build::record_payload(spec, i, &load, true);
        if ret != 0 {
            return ret;
        }
        let u = &mut spec.upatches[i];
        u.load_path = load;
        u.unload_path = unload.clone();
        let digest = build::digest_of(&u.payload_sha256);
        let ret = package::unload(
            &cstring(&u.name),
            &digest,
            &cstring(&unload),
            (&keys.pkey, &keys.cert),
        );
        if ret != 0 {
            return ret;
        }
    }
    archive::write(
        "bpm config update",
        spec,
        version.to_bytes(),
        keys.cert.to_bytes(),
        &fp,
        out_dir,
    )
}

/// The load artifact at `load` is a load directive named `expected`.
fn name_matches(load: &[u8], expected: &[u8]) -> c_int {
    // SAFETY: an all-zero container is a closed one.
    let mut u: upatch::Upatch = unsafe { core::mem::zeroed() };
    let p = cstring(load);
    // SAFETY: a C string and the container to fill.
    let ret = unsafe { upatch::upatch_open(p.as_ptr(), &mut u) };
    if ret != 0 {
        return ret;
    }
    let name = &u.hdr.name;
    let n = expected.len().min(name.len());
    let same =
        name[..n] == expected[..n] && (expected.len() >= name.len() || name[expected.len()] == 0);
    let bad = upatch::is_unload(&u) || !same;
    // SAFETY: the container opened above.
    unsafe { upatch::upatch_close(&mut u) };
    if bad { -EINVAL } else { 0 }
}
