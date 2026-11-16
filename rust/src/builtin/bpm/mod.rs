// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo bpm`: signed target-local packages from OCI repositories,
//! their signing certificates and the signed upatch tree a target
//! syncs. What only an operator runs goes to shirudo-build.

mod fetch;
mod info;
mod key;
mod package;
mod source;
mod tree;

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::errno::{E2BIG, EINVAL, EIO, ENAMETOOLONG};
use crate::ffi;
use crate::sys::curl::{CURL_GLOBAL_DEFAULT, CURLE_OK, curl_global_cleanup, curl_global_init};
use crate::sys::libc::{
    Dir, File, LOCK_UN, PATH_MAX, closedir, errno, fclose, fdopen, fdopendir, flock, fopen, fwrite,
    mkstemp, opendir, readdir, stderr, stdout, strerror, unlink,
};
use crate::sys::log::{pr_err, pr_warn};
use crate::sys::malloc::libc_free;
use crate::util::help::{
    Help, HelpItem, HelpSection, is_help, is_list_cmds, print_help, print_subcmd_list,
    resolve_subcommand,
};
use crate::util::io::read_text_line;
use crate::util::seal::{seal_lock, seal_mkdir_p};

/// A negative errno, or a command's own non-zero status.
type Result<T = ()> = core::result::Result<T, c_int>;

const KEYS_DIR: &str = "/var/lib/shirudo/keys";
const CERT_PATH: &CStr = c"/var/lib/shirudo/keys/cert.der";
const LOCKS_DIR: &CStr = c"/var/lib/shirudo/locks";
const LOCK_PATH: &CStr = c"/var/lib/shirudo/locks/bpm.lock";
const REGISTRIES_DIR: &str = "/etc/shirudo/bpm/registries.d";
const BPM_KEYS_DIR: &str = "/etc/shirudo/bpm/keys";
const REPOS_DIR: &str = "/var/lib/shirudo/bpm/repos";
const PACKAGES_DIR: &str = "/var/lib/shirudo/bpm/packages";
const STAGING_DIR: &str = "/var/lib/shirudo/bpm/staging";
const TREE_ETC_PATH: &CStr = c"/etc/shirudo/bpm/upatch-tree.conf";
const TREE_PENDING_PATH: &CStr = c"/var/lib/shirudo/bpm/upatch-tree/pending.json";
const TREE_ARTIFACTS_DIR: &str = "/var/lib/shirudo/bpm/upatch-tree/artifacts";
const TREE_STATUS_DIR: &str = "/var/lib/shirudo/bpm/upatch-tree/status";
const INDEX_REPOSITORY_NAME: &[u8] = b"bpm-index";
const INDEX_TAG: &[u8] = b"stable";
const INDEX_MEDIA: &CStr = c"application/vnd.shirudo.bpm.index.v1+json";
const INDEX_SIG_MEDIA: &CStr = c"application/vnd.shirudo.bpm.index.signature.v1";
const PACKAGE_MEDIA: &CStr = c"application/vnd.shirudo.bpm.package.v1+gzip";
const UPATCH_MEDIA: &CStr = c"application/vnd.shirudo.upatch.v1";

/// A path of `parts` one after another, as C takes one: shorter than
/// PATH_MAX, or -ENAMETOOLONG.
fn path(parts: &[&[u8]]) -> Result<CString> {
    let joined = parts.concat();

    if joined.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(joined).map_err(|_| -EINVAL)
}

/// The errno of an I/O error, negated.
fn os_err(e: io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

/// The last errno, negated.
fn last_err() -> c_int {
    -errno()
}

fn status(ret: c_int) -> Result {
    if ret == 0 { Ok(()) } else { Err(ret) }
}

/// The text of errno `err`.
fn strerr(err: c_int) -> &'static [u8] {
    // SAFETY: strerror() gives a C string that outlives the message.
    unsafe { ffi::c_str(strerror(err)) }
}

/// Bytes to the stdio stdout the rest of shirudo prints through.
fn print(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stdout.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stdout) };
}

fn eprint(text: &[u8]) {
    // SAFETY: the bytes, to the C library's stderr.
    unsafe { fwrite(text.as_ptr().cast(), 1, text.len(), stderr) };
}

/// A C string of `parts`, a NUL among them cutting it short.
fn message(parts: &[&[u8]]) -> CString {
    let mut text = parts.concat();

    if let Some(nul) = text.iter().position(|&c| c == 0) {
        text.truncate(nul);
    }
    CString::new(text).unwrap_or_default()
}

/// An error through pr_err(), which logs and escapes it.
fn error(parts: &[&[u8]]) {
    let msg = message(parts);

    // SAFETY: a "%s" format with a C string.
    unsafe { pr_err(c"%s".as_ptr(), msg.as_ptr()) };
}

fn warn(parts: &[&[u8]]) {
    let msg = message(parts);

    // SAFETY: a "%s" format with a C string.
    unsafe { pr_warn(c"%s".as_ptr(), msg.as_ptr()) };
}

/// What a failed bpm command says: 1.
fn fail(action: &[u8], ret: c_int) -> c_int {
    if ret < 0 {
        error(&[b"bpm ", action, b": ", strerr(-ret)]);
    } else {
        error(&[b"bpm ", action, b" failed"]);
    }
    1
}

/// The bpm lock, held until it goes.
struct Lock(OwnedFd);

impl Drop for Lock {
    fn drop(&mut self) {
        // SAFETY: the lock's own fd, which closes after.
        unsafe { flock(self.0.as_raw_fd(), LOCK_UN) };
    }
}

fn lock() -> Result<Lock> {
    // SAFETY: C strings.
    status(unsafe { seal_mkdir_p(LOCKS_DIR.as_ptr(), 0o700) })?;
    // SAFETY: a C string.
    let fd = unsafe { seal_lock(LOCK_PATH.as_ptr()) };
    if fd < 0 {
        return Err(fd);
    }
    // SAFETY: seal_lock() hands over the fd it opened.
    Ok(Lock(unsafe { OwnedFd::from_raw_fd(fd) }))
}

/// The end of a command that set curl up: the lock released, curl torn
/// down and a failure said.
fn finish(lock: Option<Lock>, ret: Result, action: &[u8]) -> c_int {
    drop(lock);
    // SAFETY: curl's global state, set up before.
    unsafe { curl_global_cleanup() };
    match ret {
        Ok(()) => 0,
        Err(err) => fail(action, err),
    }
}

fn curl_ready() -> bool {
    // SAFETY: curl's global set-up, which a command runs once.
    unsafe { curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK }
}

/// A new file named after `template`, its X's made unique.
fn temporary(template: &CStr) -> Result<(CString, OwnedFd)> {
    let mut name = template.to_bytes_with_nul().to_vec();

    // SAFETY: a writable C string of the template.
    let fd = unsafe { mkstemp(name.as_mut_ptr().cast()) };
    if fd < 0 {
        return Err(last_err());
    }
    // SAFETY: mkstemp() hands over the fd of the file it made.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok((CString::from_vec_with_nul(name).map_err(|_| -EINVAL)?, fd))
}

fn remove(path: &CStr) {
    // SAFETY: a C string.
    unsafe { unlink(path.as_ptr()) };
}

/// A stdio stream, closed when it goes.
struct Stream(*mut File);

impl Stream {
    fn open(path: &CStr) -> Result<Stream> {
        // SAFETY: C strings.
        let f = unsafe { fopen(path.as_ptr(), c"re".as_ptr()) };
        if f.is_null() {
            return Err(last_err());
        }
        Ok(Stream(f))
    }

    /// A stream on `fd`, which it takes over, or the -errno `fd` is.
    fn from_fd(fd: c_int) -> Result<Stream> {
        if fd < 0 {
            return Err(fd);
        }
        // SAFETY: an fd the caller hands over.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: the fd, which the stream owns once open.
        let f = unsafe { fdopen(fd.as_raw_fd(), c"r".as_ptr()) };
        if f.is_null() {
            return Err(last_err());
        }
        core::mem::forget(fd);
        Ok(Stream(f))
    }

    fn fd(&self) -> c_int {
        // SAFETY: the stream's own FILE.
        unsafe { crate::sys::libc::fileno(self.0) }
    }

    /// Each line of at most PATH_MAX - 1 bytes to `each`, as a C string
    /// in a writable buffer, until one fails; a line read badly is its
    /// error.
    fn lines(&mut self, mut each: impl FnMut(&mut [u8]) -> Result) -> Result {
        let mut line: *mut c_char = ptr::null_mut();
        let mut cap = 0;
        let mut ret = Ok(());

        while ret.is_ok() {
            // SAFETY: the stream, and getline()'s buffer for it.
            let got = unsafe { read_text_line(self.0, &mut line, &mut cap, PATH_MAX - 1) };
            if got == 0 {
                break;
            }
            ret = if got < 0 {
                Err(got)
            } else {
                // SAFETY: getline() leaves a C string in its buffer.
                let len = unsafe { ffi::c_str(line) }.len();
                // SAFETY: the buffer's string and its NUL.
                each(unsafe { core::slice::from_raw_parts_mut(line.cast(), len + 1) })
            };
        }
        // SAFETY: getline()'s buffer, from the C library's malloc.
        unsafe { libc_free(line.cast()) };
        ret
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // SAFETY: the stream's own FILE.
        unsafe { fclose(self.0) };
    }
}

/// A directory stream, closed when it goes.
struct DirStream(*mut Dir);

impl DirStream {
    fn open(path: &CStr) -> Result<DirStream> {
        // SAFETY: a C string.
        let d = unsafe { opendir(path.as_ptr()) };
        if d.is_null() {
            return Err(last_err());
        }
        Ok(DirStream(d))
    }

    /// A stream on `fd`, which it takes over, or the -errno `fd` is.
    fn from_fd(fd: c_int) -> Result<DirStream> {
        if fd < 0 {
            return Err(fd);
        }
        // SAFETY: an fd the caller hands over.
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        // SAFETY: the fd, which the stream owns once open.
        let d = unsafe { fdopendir(fd.as_raw_fd()) };
        if d.is_null() {
            return Err(last_err());
        }
        core::mem::forget(fd);
        Ok(DirStream(d))
    }
}

impl Iterator for DirStream {
    type Item = Vec<u8>;

    /// The next name, ".", ".." and all, until the end or an error.
    fn next(&mut self) -> Option<Vec<u8>> {
        // SAFETY: the stream's own DIR.
        let e = unsafe { readdir(self.0) };
        if e.is_null() {
            return None;
        }
        // SAFETY: readdir() gives an entry whose name is a C string.
        Some(unsafe { ffi::c_str((*e).d_name.as_ptr()) }.to_vec())
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: the stream's own DIR.
        unsafe { closedir(self.0) };
    }
}

const fn item(name: &'static CStr, summary: &'static CStr) -> HelpItem {
    HelpItem {
        name: name.as_ptr(),
        summary: summary.as_ptr(),
    }
}

/// The help of a command with one section of subcommands.
fn show_help(usage: &CStr, summary: &CStr, items: &[HelpItem], footer: Option<&CStr>) {
    let sections = [HelpSection {
        header: c"subcommands:".as_ptr(),
        items: items.as_ptr(),
        n_items: items.len(),
    }];
    let help = Help {
        usage: usage.as_ptr(),
        summary: summary.as_ptr(),
        sections: sections.as_ptr(),
        n_sections: 1,
        footer: footer.map_or(ptr::null(), CStr::as_ptr),
    };

    // SAFETY: the help, its strings constants and its section live.
    unsafe { print_help(&help) };
}

const OPERATOR_SUBCMDS: [HelpItem; 12] = [
    item(c"config", c"manage package inputs and OCI repositories"),
    item(c"repo", c"refresh signed repository indexes"),
    item(c"tree", c"synchronize or publish the signed upatch tree"),
    item(c"key", c"add, fingerprint, and list package certificates"),
    item(
        c"pull",
        c"download an OCI package into the current directory",
    ),
    item(c"info", c"print a local or OCI package README"),
    item(
        c"push",
        c"publish an OCI package and its signed index entry",
    ),
    item(c"build", c"build a signed OCI package from a Beefile"),
    item(
        c"install",
        c"download and activate a repository or OCI package",
    ),
    item(c"upgrade", c"activate newer cached package versions"),
    item(c"list", c"list installed packages"),
    item(c"uninstall", c"unload and remove an installed package"),
];

const TARGET_SUBCMDS: [HelpItem; 10] = [
    item(c"config", c"register and manage OCI repositories"),
    item(c"repo", c"refresh signed repository indexes"),
    item(c"tree", c"synchronize the optional signed upatch tree"),
    item(c"key", c"add, fingerprint, and list package certificates"),
    item(
        c"pull",
        c"download an OCI package into the current directory",
    ),
    item(c"info", c"print a local or OCI package README"),
    item(
        c"install",
        c"download and activate a repository or OCI package",
    ),
    item(c"upgrade", c"activate newer cached package versions"),
    item(c"list", c"list installed packages"),
    item(c"uninstall", c"unload and remove an installed package"),
];

const PULL_USAGE: &[u8] = b"usage: shirudo bpm pull <package-reference>\n\n\
The package reference must start with oci://.\n\
Example:\n  shirudo bpm pull oci://quay.io/namespace/package:tag\n";

const TREE_USAGE: &[u8] = b"usage: shirudo bpm tree sync [--dry-run] [--report=<path>]\n       \
shirudo bpm tree append <package-file> <repository> [options]\n\n\
sync applies the configured tree on a target. append is operator-only:\n\
it runs in shirudo-build and publishes the [upatches.tree] entries of a\n\
built package as the next operations of the signed tree; see\n\
`shirudo bpm tree append --help` where the operator package is installed.\n";

/// Hands an operator-only subcommand's arguments, unchanged, to the
/// shirudo-build helper, which parses them itself.
///
/// # Safety
///
/// `argv` holds `argc` C strings, at least two.
unsafe fn exec_operator(sub: &CStr, argc: c_int, argv: *const *const c_char) -> c_int {
    let label = [b"bpm ", sub.to_bytes()].concat();

    if label.len() >= 64 {
        return fail(sub.to_bytes(), -E2BIG);
    }
    let label = message(&[&label]);
    let words = [c"bpm".as_ptr(), sub.as_ptr(), ptr::null()];
    // SAFETY: a label, the words up to their NULL, and the caller's
    // arguments after the two the helper's words replace.
    unsafe { super::build::forward(label.as_ptr(), words.as_ptr(), argc - 2, argv.add(2)) }
}

/// `shirudo bpm`.
///
/// # Safety
///
/// `argv` holds `argc` C strings.
unsafe fn bpm(argc: c_int, argv: *const *const c_char) -> c_int {
    // SAFETY: the caller's arguments.
    let raw = unsafe { super::words(argc, argv) };
    // SAFETY: each a C string.
    let args: Vec<&[u8]> = raw.iter().map(|&a| unsafe { ffi::c_str(a) }).collect();
    let arg = |i: usize| args.get(i).copied();
    let n = args.len();
    let operator = super::build::available();
    let items: &[HelpItem] = if operator {
        &OPERATOR_SUBCMDS
    } else {
        &TARGET_SUBCMDS
    };

    if n < 2 || is_help(arg(1)) {
        if operator {
            show_help(
                c"shirudo bpm <config|repo|tree|key|pull|info|push|build|install|upgrade|list|uninstall>",
                c"Manage signed OCI packages and publish packages from the operator.",
                items,
                None,
            );
        } else {
            show_help(
                c"shirudo bpm <config|repo|tree|key|pull|info|install|upgrade|list|uninstall>",
                c"Manage signed target-local BPM packages backed by OCI repositories.",
                items,
                None,
            );
        }
        return if n < 2 { 2 } else { 0 };
    }
    if is_list_cmds(arg(1)) {
        // SAFETY: items whose names are C strings.
        unsafe { print_subcmd_list(items) };
        return 0;
    }
    // SAFETY: a label, the caller's word and items with names.
    let sub = unsafe { resolve_subcommand(c"shirudo bpm".as_ptr(), raw[1], items) };
    if sub.is_null() {
        return 2;
    }
    // SAFETY: the name of one of the items.
    let sub = unsafe { CStr::from_ptr(sub) };

    match sub.to_bytes() {
        b"config" if arg(2) == Some(b"update") => {
            // SAFETY: the caller's arguments, at least three.
            unsafe { exec_operator(sub, argc, argv) }
        }
        b"config" => source::config(&args[1..]),
        b"info" => info::info(&args),
        b"tree" if n < 3 || is_help(arg(2)) => {
            eprint(TREE_USAGE);
            if n < 3 { 2 } else { 0 }
        }
        // SAFETY: the caller's arguments, at least three.
        b"tree" if arg(2) == Some(b"append") => unsafe { exec_operator(sub, argc, argv) },
        b"tree" if arg(2) != Some(b"sync") => {
            eprint(TREE_USAGE);
            2
        }
        // SAFETY: the caller's arguments, at least two.
        b"build" | b"push" => unsafe { exec_operator(sub, argc, argv) },
        b"pull" => pull(&args),
        b"repo" if arg(2) == Some(b"update") => fetch::repo_update(&args),
        b"tree" => tree::tree(&args),
        b"key" => key::key(&raw[1..], &args[1..]),
        b"install" if n == 3 && is_help(arg(2)) => {
            eprint(b"usage: shirudo bpm install <package>\n");
            0
        }
        b"install" if n == 3 => package::install(args[2]),
        b"list" => package::list(&args),
        b"uninstall" => package::uninstall(&args),
        b"upgrade" if n == 2 => package::upgrade(),
        _ => 2,
    }
}

fn pull(args: &[&[u8]]) -> c_int {
    if args.len() == 3 && is_help(args.get(2).copied()) {
        eprint(PULL_USAGE);
        return 0;
    }
    if args.len() != 3 {
        eprint(PULL_USAGE);
        return 2;
    }
    if !curl_ready() {
        return fail(b"initialize curl", -EIO);
    }
    finish(None, fetch::download(args[2], None), b"pull")
}

/// For the image CLI test: the key file registered source `name`
/// verifies with, open as `bpm repo update` opens it, or -errno.
fn source_key_open(name: &[u8]) -> c_int {
    match source::load(name) {
        Ok(s) => s.key_open(),
        Err(err) => err,
    }
}

pub(super) use capi::cmd_bpm;

mod capi {
    use core::ffi::{c_char, c_int};

    use crate::ffi;
    use crate::util::initrd;

    /// # Safety
    ///
    /// `argv` holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cmd_bpm(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: the caller's arguments.
        unsafe { super::bpm(argc, argv) }
    }

    /// # Safety
    ///
    /// `name` is a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn bpm_source_key_open(name: *const c_char) -> c_int {
        // SAFETY: the caller's C string.
        super::source_key_open(unsafe { ffi::c_str(name) })
    }

    /// The certificate `bpm tree sync` verifies publications against.
    #[unsafe(no_mangle)]
    pub extern "C" fn bpm_tree_certificate() -> *const c_char {
        initrd::cert_path().as_ptr()
    }
}
