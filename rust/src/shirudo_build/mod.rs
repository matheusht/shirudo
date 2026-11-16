// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo-build`, the operator's artifact pipeline: compiles a
//! `.bpf.c` with clang, packages and signs it as a `.upatch`, or signs
//! an unload directive; and dispatches the operator's image, upatch, bpm
//! and keys commands. It runs on the operator only, and is the one
//! binary that links the CMS signer.

mod bpm;
mod compile;
mod image;
mod package;
mod vouch;

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::ffi::CString;

use crate::errno::{EIO, ENAMETOOLONG, EPERM};
use crate::ffi;
use crate::sys::hex::hex_decode;
use crate::sys::libc::{access, close, fwrite, mkstemps, stderr, stdout, strerror, unlink};
use crate::sys::log::{log_init, pr_err, pr_info};
use crate::sys::malloc::xfree;
use crate::sys::paths::{format_key_path, key_paths, keys_dir_resolve};
use crate::sys::sign::open_signing_key;
use crate::sys::string::name_has_suffix;
use crate::text::cstr;
use crate::util::harden::{harden_self, harden_stdio};
use crate::util::upatch::{Upatch, upatch_close, upatch_open};

const KEYS_DIR_ENV: &str = "SHIRUDO_KEYS_DIR";
const SIGNING_KEY_PATH: &CStr = c"/var/lib/shirudo/keys/signing_key.pem";
const CERT_PATH: &CStr = c"/var/lib/shirudo/keys/cert.der";
const SIGNING_KEY_FILE: &CStr = c"signing_key.pem";
const CERT_FILE: &CStr = c"cert.der";
const UPATCHES_DIR: &str = "/var/lib/shirudo/upatches";
const PATH_MAX: usize = 4096;
const R_OK: c_int = 4;

fn say(level: unsafe extern "C" fn(*const c_char, ...), text: &[u8]) {
    let msg = CString::new(cstr(text).to_vec()).unwrap_or_default();

    // SAFETY: a "%s" format with a C string.
    unsafe { level(c"%s".as_ptr(), msg.as_ptr()) };
}

fn error(text: &[u8]) {
    say(pr_err, text);
}

fn info(text: &[u8]) {
    say(pr_info, text);
}

fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

fn last_err() -> c_int {
    -std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EIO)
}

fn print(to_stdout: bool, text: &[u8]) {
    // SAFETY: the bytes, to one of the C library's streams.
    unsafe {
        let f = if to_stdout { stdout } else { stderr };
        fwrite(text.as_ptr().cast(), 1, text.len(), f);
    }
}

fn usage(to_stdout: bool) {
    let key = String::from_utf8_lossy(SIGNING_KEY_PATH.to_bytes());
    let cert = String::from_utf8_lossy(CERT_PATH.to_bytes());
    let vmlinux = compile::VMLINUX_PATH;
    let env = KEYS_DIR_ENV;
    let text = format!(
        "usage:
  shirudo-build <input> [-o <output.upatch>]
                [--name <upatch-name>]
                [--keys-dir <dir>]
                [--key <signing_key.pem>] [--cert <cert.der>]
                [--vmlinux <vmlinux.h>] [--extra-cflags '<flags>']
                [--emit-artifacts]

  shirudo-build --unload <upatch-name> [-o <output.upatch>]
                [--payload-sha256 <64-hex>]
                [--keys-dir <dir>]
                [--key <signing_key.pem>] [--cert <cert.der>]

  shirudo-build image build <filesystem.img> -o <prefix> ...
  shirudo-build bpm <build|push|tree append> ...
  shirudo-build keys vouch <cert.der> [-o <file>] ...

<input> is .bpf.c (compiled via clang) or .bpf.o.
-o defaults to <input> with a trailing .c/.o replaced by
   .upatch (foo/bar.bpf.c -> foo/bar.bpf.upatch), written
   next to the input; for --unload it defaults to
   <name>.unload.upatch in the current directory. Pass -o
   only to write somewhere else.
--keys-dir defaults key/cert to <dir>/signing_key.pem and
           <dir>/cert.der. If omitted, {env} is used when set.
           Explicit --keys-dir overrides the environment;
           explicit --key/--cert override both.
--key default without --keys-dir/{env}: {key}
--cert default without --keys-dir/{env}: {cert}
--vmlinux: explicit; else ./vmlinux.h, ./vendor/linux/vmlinux.h,
           then {vmlinux}.
--payload-sha256: 64 hex chars; if omitted, read from the local
                  archive /var/lib/shirudo/upatches/<name>.upatch,
                  which must then exist.
--emit-artifacts: for a .bpf.c input, also keep the compiled
                  .bpf.o next to the .upatch (instead of a temp
                  file that is removed). Reports every emitted
                  path on stdout. A debugging aid.
bpm: the operator-only package commands (`shirudo bpm build`,
     `push`, `tree append`); see `shirudo-build bpm --help`.
"
    );

    print(to_stdout, text.as_bytes());
}

fn has_suffix(s: &CStr, suffix: &CStr) -> bool {
    // SAFETY: a C string, its length and a suffix.
    unsafe { name_has_suffix(s.as_ptr(), s.to_bytes().len(), suffix.as_ptr()) }
}

/// `stem` and then `ext`, as long as the path fits PATH_MAX.
fn with_ext(stem: &[u8], ext: &[u8]) -> Result<CString, c_int> {
    let path = [stem, ext].concat();

    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(path).map_err(|_| -ENAMETOOLONG)
}

/// foo/bar.bpf.c lands at foo/bar.bpf.upatch beside its input.
fn derive_output(input: &CStr) -> Result<CString, c_int> {
    let s = input.to_bytes();
    let stem = if has_suffix(input, c".c") || has_suffix(input, c".o") {
        &s[..s.len() - 2]
    } else {
        s
    };

    with_ext(stem, b".upatch")
}

/// The .bpf.o sits beside the .upatch.
fn derive_artifact_o(output: &CStr) -> Result<CString, c_int> {
    let s = output.to_bytes();
    let stem = if has_suffix(output, c".upatch") {
        &s[..s.len() - 7]
    } else {
        s
    };

    with_ext(stem, b".o")
}

/// A temporary object clang compiles into, removed when it goes.
struct TempObject(CString);

impl Drop for TempObject {
    fn drop(&mut self) {
        // SAFETY: a C string.
        unsafe { unlink(self.0.as_ptr()) };
    }
}

fn compile_to_temp(
    source: &CStr,
    vmlinux_h: &CStr,
    extra: Option<&CStr>,
) -> Result<TempObject, c_int> {
    let mut tmpl = *b"/tmp/shirudo-build-XXXXXX.bpf.o\0";
    // SAFETY: the template, which mkstemps() fills in.
    let fd = unsafe { mkstemps(tmpl.as_mut_ptr().cast(), b".bpf.o".len() as c_int) };

    if fd < 0 {
        return Err(last_err());
    }
    // SAFETY: the descriptor opened above.
    unsafe { close(fd) };
    let obj = TempObject(CString::new(cstr(&tmpl).to_vec()).unwrap_or_default());
    match compile::compile(source, &obj.0, vmlinux_h, extra, None) {
        0 => Ok(obj),
        err => Err(err),
    }
}

/// Whether the signing key opens as one and the certificate reads: 0,
/// or 1 with the reason logged.
fn check_keys(pkey: &CStr, cert: &CStr) -> c_int {
    // SAFETY: a C string.
    let fd = unsafe { open_signing_key(pkey.as_ptr()) };

    if fd < 0 {
        if fd != -EPERM {
            error(b"run `shirudo genkey` on the operator (or pass --key).");
        }
        return 1;
    }
    // SAFETY: the descriptor opened above.
    unsafe { close(fd) };
    // SAFETY: a C string.
    if unsafe { access(cert.as_ptr(), R_OK) } != 0 {
        let err = last_err();
        error(&[b"cert not readable: ", cert.to_bytes(), b": ", strerr(-err)].concat());
        error(b"run `shirudo genkey` on the operator (or pass --cert).");
        return 1;
    }
    0
}

/// The signing key and certificate a command signs with: named on its
/// command line, else under the keys directory, else the defaults.
struct KeyFiles {
    pkey: CString,
    cert: CString,
    pkey_named: bool,
    cert_named: bool,
}

impl Default for KeyFiles {
    fn default() -> Self {
        KeyFiles {
            pkey: SIGNING_KEY_PATH.into(),
            cert: CERT_PATH.into(),
            pkey_named: false,
            cert_named: false,
        }
    }
}

impl KeyFiles {
    /// The key and certificate under the directory `dir`, as key_paths()
    /// spells them.
    fn under(dir: &[u8]) -> Result<Self, c_int> {
        let d = CString::new(dir.to_vec()).map_err(|_| -crate::errno::EINVAL)?;
        let (mut pkey, mut cert) = ([0u8; PATH_MAX], [0u8; PATH_MAX]);
        // SAFETY: a C string and the rooms for the two paths.
        let ret = unsafe {
            key_paths(
                d.as_ptr(),
                pkey.as_mut_ptr().cast(),
                pkey.len(),
                cert.as_mut_ptr().cast(),
                cert.len(),
            )
        };
        if ret != 0 {
            return Err(ret);
        }
        Ok(KeyFiles {
            pkey: CString::new(cstr(&pkey).to_vec()).unwrap_or_default(),
            cert: CString::new(cstr(&cert).to_vec()).unwrap_or_default(),
            pkey_named: false,
            cert_named: false,
        })
    }

    fn set_pkey(&mut self, path: &CStr) {
        self.pkey = path.into();
        self.pkey_named = true;
    }

    fn set_cert(&mut self, path: &CStr) {
        self.cert = path.into();
        self.cert_named = true;
    }

    /// The keys directory: `dir`, else SHIRUDO_KEYS_DIR, else the
    /// default; NULL for none.
    fn dir(dir: Option<&CStr>) -> *const c_char {
        // SAFETY: NULL or a C string.
        unsafe { keys_dir_resolve(dir.map_or(ptr::null(), CStr::as_ptr)) }
    }

    /// The key and the certificate under the keys directory, those not
    /// named; the directory and the error when one does not fit.
    fn resolve(&mut self, dir: Option<&CStr>) -> Result<(), (Vec<u8>, c_int)> {
        let dir = Self::dir(dir);

        if dir.is_null() {
            return Ok(());
        }
        // SAFETY: the directory, a C string.
        let name = || unsafe { ffi::c_str(dir) }.to_vec();
        if !self.pkey_named {
            self.pkey = key_path(dir, SIGNING_KEY_FILE).map_err(|e| (name(), e))?;
        }
        if !self.cert_named {
            self.cert = key_path(dir, CERT_FILE).map_err(|e| (name(), e))?;
        }
        Ok(())
    }

    /// As resolve(), but both must fit under the directory, named or
    /// not, as key_paths() has them.
    fn resolve_both(&mut self, dir: Option<&CStr>) -> Result<(), c_int> {
        let dir = Self::dir(dir);
        let (mut pkey, mut cert) = ([0u8; PATH_MAX], [0u8; PATH_MAX]);

        if dir.is_null() {
            return Ok(());
        }
        // SAFETY: a C string and the rooms for the two paths.
        let ret = unsafe {
            key_paths(
                dir,
                pkey.as_mut_ptr().cast(),
                pkey.len(),
                cert.as_mut_ptr().cast(),
                cert.len(),
            )
        };
        if ret != 0 {
            return Err(ret);
        }
        if !self.pkey_named {
            self.pkey = CString::new(cstr(&pkey).to_vec()).unwrap_or_default();
        }
        if !self.cert_named {
            self.cert = CString::new(cstr(&cert).to_vec()).unwrap_or_default();
        }
        Ok(())
    }
}

/// A buffer the C allocated, freed when it goes.
struct Bytes(*mut u8, usize);

impl Bytes {
    fn bytes(&self) -> &[u8] {
        if self.0.is_null() {
            return &[];
        }
        // SAFETY: the buffer's bytes.
        unsafe { ffi::slice(self.0, self.1) }
    }
}

impl Drop for Bytes {
    fn drop(&mut self) {
        // SAFETY: the buffer, of its length, or NULL.
        unsafe { xfree(self.0.cast(), self.1) };
    }
}

fn hex(bytes: &[u8]) -> Vec<u8> {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    bytes
        .iter()
        .flat_map(|b| [HEX[usize::from(b >> 4)], HEX[usize::from(b & 0xf)]])
        .collect()
}

fn path(p: &[u8]) -> &std::ffi::OsStr {
    std::os::unix::ffi::OsStrExt::from_bytes(p)
}

#[derive(Default)]
struct Opts<'a> {
    output: Option<&'a CStr>,
    name: Option<&'a CStr>,
    keys_dir: Option<&'a CStr>,
    pkey: Option<&'a CStr>,
    cert: Option<&'a CStr>,
    vmlinux: Option<&'a CStr>,
    extra_cflags: Option<&'a CStr>,
    unload: Option<&'a CStr>,
    payload_sha256: Option<&'a CStr>,
    emit_artifacts: bool,
    input: Option<&'a CStr>,
}

/// The digest of the payload an unload directive names: the one given,
/// else the loaded payload's as the operator's local archive records it,
/// since the target refuses a directive whose digest is not that.
fn unload_digest(name: &CStr, given: Option<&CStr>) -> Result<[u8; 32], c_int> {
    let mut digest = [0u8; 32];

    if let Some(hex) = given {
        // SAFETY: a C string and room for 32 bytes.
        if unsafe { hex_decode(hex.as_ptr(), digest.as_mut_ptr(), 32) } != 0 {
            error(b"--payload-sha256 must be 64 hex chars");
            return Err(2);
        }
        return Ok(digest);
    }
    let archive = [UPATCHES_DIR.as_bytes(), b"/", name.to_bytes(), b".upatch"].concat();
    if archive.len() >= PATH_MAX {
        error(&[b"archive path too long for '", name.to_bytes(), b"'"].concat());
        return Err(1);
    }
    let path = CString::new(archive).unwrap_or_default();
    // SAFETY: an all-zero container is a closed one.
    let mut u: Upatch = unsafe { core::mem::zeroed() };
    // SAFETY: a C string and the container to fill.
    if unsafe { upatch_open(path.as_ptr(), &mut u) } != 0 {
        error(
            &[
                b"--payload-sha256 omitted and no archive at ",
                path.to_bytes(),
                b"; pass the digest upatch info shows",
            ]
            .concat(),
        );
        return Err(2);
    }
    digest = u.hdr.payload_sha256;
    // SAFETY: the container opened above.
    unsafe { upatch_close(&mut u) };
    info(&[b"--payload-sha256 derived from archive ", path.to_bytes()].concat());
    Ok(digest)
}

fn unload(o: &Opts, name: &CStr, pkey: &CStr, cert: &CStr) -> c_int {
    if o.input.is_some() {
        error(b"--unload takes no positional input");
        return 2;
    }
    let digest = match unload_digest(name, o.payload_sha256) {
        Ok(d) => d,
        Err(ret) => return ret,
    };
    let derived;
    let output = match o.output {
        Some(out) => out,
        None => {
            derived = match with_ext(name.to_bytes(), b".unload.upatch") {
                Ok(p) => p,
                Err(_) => {
                    error(&[b"derived output path too long for '", name.to_bytes(), b"'"].concat());
                    return 1;
                }
            };
            info(&[b"writing ", derived.to_bytes(), b" (no -o given)"].concat());
            &derived
        }
    };
    let ret = package::unload_directive(name, &digest, output, pkey, cert);
    if ret == 0 && o.emit_artifacts {
        let text = [
            b"emitted:\n  upatch: ",
            output.to_bytes(),
            b"\n  bpf.o:  (none; --unload embeds the prebuilt unload program)\n",
        ]
        .concat();
        print(true, &text);
    }
    if ret != 0 { 1 } else { 0 }
}

fn load(o: &Opts, input: &CStr, pkey: &CStr, cert: &CStr) -> c_int {
    // The output comes first: --emit-artifacts derives the .bpf.o from
    // it so the object lands in the same directory as the .upatch.
    let derived;
    let output = match o.output {
        Some(out) => out,
        None => {
            derived = match derive_output(input) {
                Ok(p) => p,
                Err(err) => {
                    error(
                        &[
                            b"cannot derive output path from ",
                            input.to_bytes(),
                            b": ",
                            strerr(-err),
                        ]
                        .concat(),
                    );
                    return 1;
                }
            };
            info(&[b"writing ", derived.to_bytes(), b" (no -o given)"].concat());
            &derived
        }
    };
    let mut temp = None;
    let artifact;
    let mut emitted = None;
    // The source anchors relative decoder paths; for an object they
    // resolve from the current directory.
    let (bpf_o, src): (&CStr, Option<&CStr>) = if has_suffix(input, c".bpf.c") {
        let Some(vmlinux_h) = compile::locate_vmlinux(o.vmlinux) else {
            let named = o.vmlinux.map_or(&b"(none)"[..], CStr::to_bytes);
            error(
                &[
                    b"vmlinux.h not found (tried ",
                    named,
                    b", ./vmlinux.h, ./vendor/linux/vmlinux.h, ",
                    compile::VMLINUX_PATH.as_bytes(),
                    b")",
                ]
                .concat(),
            );
            return 1;
        };
        let compiled = if o.emit_artifacts {
            artifact = match derive_artifact_o(output) {
                Ok(p) => p,
                Err(err) => {
                    error(
                        &[
                            b"cannot derive .bpf.o path from ",
                            output.to_bytes(),
                            b": ",
                            strerr(-err),
                        ]
                        .concat(),
                    );
                    return 1;
                }
            };
            match compile::compile(input, &artifact, vmlinux_h, o.extra_cflags, None) {
                0 => {
                    emitted = Some(&*artifact);
                    Ok(&*artifact)
                }
                err => Err(err),
            }
        } else {
            match compile_to_temp(input, vmlinux_h, o.extra_cflags) {
                Ok(t) => Ok(&*temp.insert(t).0),
                Err(err) => Err(err),
            }
        };
        match compiled {
            Ok(obj) => (obj, Some(input)),
            Err(err) => {
                error(
                    format!(
                        "compile {}: {err}",
                        String::from_utf8_lossy(input.to_bytes())
                    )
                    .as_bytes(),
                );
                return 1;
            }
        }
    } else if has_suffix(input, c".o") {
        (input, None)
    } else {
        error(b"input must be .bpf.c or .bpf.o");
        return 2;
    };
    let derived_name;
    let name = match o.name {
        Some(n) => n,
        None => {
            derived_name = match bpm::upatch_name(input.to_bytes()) {
                Ok(n) => CString::new(n).unwrap_or_default(),
                Err(_) => {
                    error(&[b"upatch name from ", input.to_bytes(), b" too long"].concat());
                    return 2;
                }
            };
            &derived_name
        }
    };
    let ret = package::load_object(bpf_o, src, output, name, pkey, cert);
    drop(temp);
    if ret == 0 && o.emit_artifacts {
        let obj: &[u8] = match emitted {
            Some(p) => p.to_bytes(),
            None => b"(none; input was a pre-compiled object, not recompiled)",
        };
        print(
            true,
            &[
                b"emitted:\n  upatch: ",
                output.to_bytes(),
                b"\n  bpf.o:  ",
                obj,
                b"\n",
            ]
            .concat(),
        );
    }
    if ret != 0 { 1 } else { 0 }
}

/// The key or certificate under the keys directory, unless named.
fn key_path(dir: *const c_char, file: &CStr) -> Result<CString, c_int> {
    let mut buf = [0u8; PATH_MAX];

    // SAFETY: room for the path, and C strings.
    match unsafe { format_key_path(buf.as_mut_ptr().cast(), buf.len(), dir, file.as_ptr()) } {
        0 => Ok(CString::new(cstr(&buf).to_vec()).unwrap_or_default()),
        err => Err(err),
    }
}

/// # Safety
///
/// `argv` holds `argc` C strings, writable as main()'s are.
unsafe fn run(argc: c_int, argv: *mut *mut c_char) -> c_int {
    let n = usize::try_from(argc).unwrap_or(0);
    // SAFETY: the caller's words.
    let words = unsafe { ffi::slice(argv.cast_const(), n) };
    // SAFETY: each a C string.
    let word = |i: usize| unsafe { CStr::from_ptr(words[i]) };

    harden_stdio();
    // SAFETY: opens the log once, before anything logs.
    unsafe { log_init() };
    if harden_self() != 0 {
        return 1;
    }
    let all: Vec<&CStr> = (0..n).map(word).collect();
    match all.get(1).map(|w| w.to_bytes()) {
        Some(b"image") => return image::run(&all[1..]),
        Some(b"upatch") => return package::upatch_cli(&all[1..]),
        Some(b"bpm") => return bpm::run(&all[1..]),
        Some(b"keys") if n >= 3 && all[2].to_bytes() == b"vouch" => return vouch::run(&all[2..]),
        _ => {}
    }

    let mut o = Opts::default();
    let mut i = 1;
    while i < n {
        let a = word(i);
        let next = (i + 1 < n).then(|| word(i + 1));
        let slot = match a.to_bytes() {
            b"-o" | b"--output" => Some(&mut o.output),
            b"--name" => Some(&mut o.name),
            b"--keys-dir" => Some(&mut o.keys_dir),
            b"--key" => Some(&mut o.pkey),
            b"--cert" => Some(&mut o.cert),
            b"--vmlinux" => Some(&mut o.vmlinux),
            b"--extra-cflags" => Some(&mut o.extra_cflags),
            b"--unload" => Some(&mut o.unload),
            b"--payload-sha256" => Some(&mut o.payload_sha256),
            _ => None,
        };
        match (slot, next) {
            (Some(slot), Some(value)) => {
                *slot = Some(value);
                i += 1;
            }
            _ if a.to_bytes().starts_with(b"--keys-dir=") => {
                o.keys_dir = CStr::from_bytes_with_nul(&a.to_bytes_with_nul()[11..]).ok();
            }
            _ if a.to_bytes() == b"--emit-artifacts" => o.emit_artifacts = true,
            _ if matches!(a.to_bytes(), b"-h" | b"--help") => {
                usage(true);
                return 0;
            }
            _ if a.to_bytes().first() == Some(&b'-') => {
                error(&[b"unknown option '", a.to_bytes(), b"'"].concat());
                usage(false);
                return 2;
            }
            _ if o.input.is_none() => o.input = Some(a),
            _ => {
                error(&[b"unexpected positional arg '", a.to_bytes(), b"'"].concat());
                return 2;
            }
        }
        i += 1;
    }

    let mut keys = KeyFiles::default();
    if let Some(p) = o.pkey {
        keys.set_pkey(p);
    }
    if let Some(c) = o.cert {
        keys.set_cert(c);
    }
    if let Err((dir, err)) = keys.resolve(o.keys_dir) {
        error(&[b"invalid keys dir ", &dir[..], b": ", strerr(-err)].concat());
        return 2;
    }
    if check_keys(&keys.pkey, &keys.cert) != 0 {
        return 1;
    }
    if let Some(name) = o.unload {
        return unload(&o, name, &keys.pkey, &keys.cert);
    }
    let Some(input) = o.input else {
        usage(false);
        return 2;
    };
    load(&o, input, &keys.pkey, &keys.cert)
}

mod capi {
    use core::ffi::{c_char, c_int};

    /// `shirudo-build`, from its main(): the command line, whole.
    ///
    /// # Safety
    ///
    /// `argv` holds `argc` C strings, as main() receives them.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn shirudo_build_main(argc: c_int, argv: *mut *mut c_char) -> c_int {
        // SAFETY: the caller's command line.
        unsafe { super::run(argc, argv) }
    }
}
