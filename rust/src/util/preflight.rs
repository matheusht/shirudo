// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The pre-flight gate: whether the node has what
//! shirudo needs before init touches any kernel state, each check with
//! why it failed.

use core::ffi::{CStr, c_char, c_int, c_long};

use crate::bpf::lskel::Lskel;
use crate::errno::{ENOENT, ENOPKG};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_FDCWD, R_OK, S_IFMT, S_IFREG, STATX_SIZE, STATX_TYPE, SYS_ADD_KEY, SYS_KEYCTL, Statx, W_OK,
    access, errno, fclose, fgets, fopen, geteuid, statx, strerror, syscall,
};
use crate::text::{cstr, decimal, strscpy, strsprintf};
use crate::util::config::{self, Scrubbed};
use crate::util::crypto_openssl::key_algorithm;
use crate::util::initrd;
use crate::util::kernel_abi;
use crate::util::keys::{self, TrustedSet};

/// `PREFLIGHT_DETAIL_MAX`.
const DETAIL_MAX: usize = 256;

/// `enum preflight_id`, PRE__MAX of them.
const PRE_ROOT: c_int = 0;
const PRE_BPF_LSM: c_int = 1;
const PRE_BPFFS: c_int = 2;
const PRE_SIGNED_LOADER_ABI: c_int = 3;
const PRE_LSM_HOOKS: c_int = 4;
const PRE_CERT_ON_DISK: c_int = 5;
const PRE_CERT_ALGORITHM: c_int = 6;
const PRE_CERT_KERNEL_ALGO: c_int = 7;
const PRE_KEYRING: c_int = 8;
const PRE_EMBEDDED_LOADER: c_int = 9;
const PRE_TPM: c_int = 10;
const PRE_MAX: usize = 11;

/// The keyrings and keyctl(2) commands of linux/keyctl.h the checks use.
const KEY_SPEC_THREAD_KEYRING: c_long = -1;
const KEY_SPEC_USER_KEYRING: c_long = -4;
const KEY_SPEC_BPF_KEYRING: c_long = -9;
const KEYCTL_GET_KEYRING_ID: c_long = 0;
const KEYCTL_CLEAR: c_long = 7;

/// KEYS_REVOKED_DIR of util/paths.h.
const KEYS_REVOKED_DIR: &CStr = c"/var/lib/shirudo/keys/revoked";

/// `struct preflight_check`.
#[repr(C)]
pub struct PreflightCheck {
    pub(crate) id: c_int,
    pub(crate) name: *const c_char,
    pub(crate) ok: bool,
    pub(crate) detail: [u8; DETAIL_MAX],
}

/// `struct preflight_result`.
#[repr(C)]
pub struct PreflightResult {
    pub(crate) checks: [PreflightCheck; PRE_MAX],
    pub(crate) n: c_int,
    pub(crate) n_failed: c_int,
}

const _: () = assert!(size_of::<PreflightCheck>() == 280);
const _: () = assert!(size_of::<PreflightResult>() == 3088);

impl PreflightResult {
    /// The next check's slot, named, its detail emptied: its index.
    fn next_slot(&mut self, id: c_int, name: &'static CStr) -> usize {
        let i = self.n as usize;
        let c = &mut self.checks[i];

        self.n += 1;
        c.id = id;
        c.name = name.as_ptr();
        c.detail[0] = 0;
        i
    }

    fn pass(&mut self, i: usize) {
        self.checks[i].ok = true;
    }

    /// The check failed, for the reason its parts spell, or "?" for one
    /// too long to keep.
    fn fail(&mut self, i: usize, parts: &[&[u8]]) {
        let c = &mut self.checks[i];

        c.ok = false;
        if strsprintf(&mut c.detail, parts).is_err() {
            let _ = strscpy(&mut c.detail, b"?");
        }
        self.n_failed += 1;
    }

    /// Passed, with the detail given.
    fn pass_with(&mut self, i: usize, detail: &[u8]) {
        self.pass(i);
        let _ = strscpy(&mut self.checks[i].detail, detail);
    }
}

/// The C library's message for an errno.
fn errstr(errnum: c_int) -> &'static [u8] {
    // SAFETY: a C string the C library keeps.
    unsafe { CStr::from_ptr(strerror(errnum)) }.to_bytes()
}

fn check_root(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_ROOT, c"root");

    // SAFETY: the process's effective user, asked twice as the C did.
    if unsafe { geteuid() } == 0 {
        r.pass(i);
    } else {
        let mut buf = [0u8; 20];
        // SAFETY: as above.
        let uid = decimal(u64::from(unsafe { geteuid() }), &mut buf);

        r.fail(i, &[b"must run as root (EUID=", uid, b")"]);
    }
}

/// Whether the active LSMs the kernel lists include bpf.
fn lsm_lists_bpf() -> bool {
    use std::io::Read;

    let mut buf = [0u8; 1024];
    // One read into all but the last byte of buf.
    let n = std::fs::File::open("/sys/kernel/security/lsm")
        .and_then(|mut f| f.read(&mut buf[..1023]))
        .unwrap_or(0);
    if n == 0 {
        return false;
    }
    cstr(&buf[..n])
        .split(|&c| c == b',' || c == b'\n')
        .any(|lsm| lsm == b"bpf")
}

/// Whether /proc/filesystems lists bpf.
fn bpffs_in_proc_filesystems() -> bool {
    // SAFETY: two C strings.
    let f = unsafe { fopen(c"/proc/filesystems".as_ptr(), c"re".as_ptr()) };
    let mut line = [0u8; 128];
    let mut found = false;

    if f.is_null() {
        return false;
    }
    // SAFETY: room for a line, and the stream.
    while !unsafe { fgets(line.as_mut_ptr().cast(), line.len() as c_int, f) }.is_null() {
        let text = cstr(&line);
        let Some(tab) = text.iter().position(|&c| c == b'\t') else {
            continue;
        };
        let name = &text[tab + 1..];
        let name = &name[..name.iter().position(|&c| c == b'\n').unwrap_or(name.len())];

        if name == b"bpf" {
            found = true;
            break;
        }
    }
    // SAFETY: the stream fopen() gave, closed once.
    unsafe { fclose(f) };
    found
}

fn check_bpf_lsm(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_BPF_LSM, c"bpf_lsm_active");

    if lsm_lists_bpf() {
        r.pass(i);
    } else {
        r.fail(
            i,
            &[b"/sys/kernel/security/lsm has no \"bpf\" entry (needs CONFIG_BPF_LSM=y, bpf in CONFIG_LSM)"],
        );
    }
}

fn check_bpffs(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_BPFFS, c"bpffs_supported");

    if bpffs_in_proc_filesystems() {
        r.pass(i);
    } else {
        r.fail(
            i,
            &[b"/proc/filesystems does not advertise bpf (needs CONFIG_BPF_FS=y)"],
        );
    }
}

fn check_signed_loader_abi(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_SIGNED_LOADER_ABI, c"signed_loader_kernel_abi");
    if kernel_abi::check_into(&mut r.checks[i].detail) == 0 {
        r.pass(i);
    } else {
        r.checks[i].ok = false;
        r.n_failed += 1;
    }
}

/// The hooks come from the embedded objects themselves, so a program
/// added on a hook only a carried kernel patch provides is checked
/// without a list here to keep in step.
fn check_lsm_hooks(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_LSM_HOOKS, c"kernel_lsm_hooks");
    let mut hooks = kernel_abi::LsmHooks::new();

    for obj in crate::skel::embedded() {
        if obj.is_empty() {
            r.pass_with(i, b"skipped (embedded objects missing)");
            return;
        }
        if let Err(err) = kernel_abi::lsm_hooks(obj, &mut hooks) {
            r.fail(
                i,
                &[
                    b"cannot read the LSM hooks of the embedded ",
                    obj.name(),
                    b" object: ",
                    errstr(-err),
                ],
            );
            return;
        }
    }
    match kernel_abi::check_lsm_hooks(&hooks) {
        Ok(()) => r.pass(i),
        Err(detail) => {
            if strscpy(&mut r.checks[i].detail, &detail).is_err() {
                let _ = strscpy(&mut r.checks[i].detail, b"?");
            }
            r.checks[i].ok = false;
            r.n_failed += 1;
        }
    }
}

fn check_cert(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_CERT_ON_DISK, c"cert_on_disk");
    let mut st = Statx::zeroed();
    // SAFETY: the certificate's path, a C string, and room for its
    // status.
    let found = unsafe {
        statx(
            AT_FDCWD,
            initrd::cert_path().as_ptr(),
            0,
            STATX_TYPE | STATX_SIZE,
            &mut st,
        )
    } == 0;

    if found && st.stx_mode & S_IFMT == S_IFREG && st.stx_size > 0 {
        r.pass(i);
    } else {
        r.fail(
            i,
            &[
                initrd::cert_path().to_bytes(),
                b" missing or empty (copy the operator's cert)",
            ],
        );
    }
}

/// The certificates init would enrol: cert.der and the trusted set
/// beside it. A set that cannot be read is cert_on_disk's to report; the
/// checks after it skip rather than fail twice.
fn preflight_keys() -> Result<TrustedSet, c_int> {
    keys::load(initrd::keys_dir(), Some(KEYS_REVOKED_DIR), true)
}

/// The room for the name of a key's algorithm, its NUL included.
const ALGORITHM_NAME_ROOM: usize = 64;

/// shirudo's trust anchor is ML-DSA-87 alone: a classical certificate on
/// disk is refused before any kernel state is touched, so a fleet cannot
/// drift back to RSA by provisioning the wrong cert.der.
fn check_cert_algorithm(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_CERT_ALGORITHM, c"cert_algorithm");
    let Ok(set) = preflight_keys() else {
        r.pass_with(i, b"skipped (cert unreadable)");
        return;
    };

    for c in keys::members(&set) {
        let path = keys::cert_path(c);
        let Ok(x509) = keys::cert_x509(c) else {
            r.fail(i, &[path, b": cannot parse"]);
            return;
        };
        let Ok(name) = key_algorithm(&x509, ALGORITHM_NAME_ROOM) else {
            r.fail(i, &[path, b": cannot determine public-key algorithm"]);
            return;
        };
        if name.to_bytes() != b"ML-DSA-87" {
            r.fail(
                i,
                &[
                    path,
                    b" is ",
                    name.to_bytes(),
                    b"; shirudo accepts only ML-DSA-87 certificates (re-key with shirudo genkey)",
                ],
            );
            return;
        }
    }
    r.pass(i);
}

/// The only authoritative answer to whether this kernel can use the
/// certificates is its own X.509 parser. An ML-DSA certificate on a
/// kernel without CONFIG_CRYPTO_MLDSA fails add_key(2) with ENOENT, the
/// parser knowing the OID but no mldsa87 registered, or ENOPKG, the
/// parser older than the OID; the probe also loads the algorithm where
/// it is a module. The probe key goes into the thread keyring, private
/// to this thread and gone with it, and is cleared right away.
fn check_cert_kernel_algo(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_CERT_KERNEL_ALGO, c"cert_kernel_support");
    let Ok(set) = preflight_keys() else {
        r.pass_with(i, b"skipped (cert unreadable)");
        return;
    };

    for c in keys::members(&set) {
        let path = keys::cert_path(c);
        let der = match keys::cert_der(c) {
            Ok(der) => der,
            Err(ret) => {
                r.fail(i, &[path, b": ", errstr(-ret)]);
                return;
            }
        };
        // SAFETY: add_key(2) with C strings, the certificate's bytes and
        // a keyring, then keyctl(2) clearing that keyring.
        let ret = unsafe {
            let key = syscall(
                SYS_ADD_KEY,
                c"asymmetric".as_ptr(),
                c"".as_ptr(),
                der.as_ptr(),
                der.len(),
                KEY_SPEC_THREAD_KEYRING,
            );
            let ret = if key < 0 { errno() } else { 0 };

            syscall(
                SYS_KEYCTL,
                KEYCTL_CLEAR,
                KEY_SPEC_THREAD_KEYRING,
                0 as c_long,
                0 as c_long,
                0 as c_long,
            );
            ret
        };
        if ret == 0 {
            continue;
        }
        if ret == ENOENT || ret == ENOPKG {
            r.fail(
                i,
                &[
                    b"kernel cannot verify the public-key algorithm of ",
                    path,
                    b" (ML-DSA certs need CONFIG_CRYPTO_MLDSA=y and CONFIG_CRYPTO_SHA512=y)",
                ],
            );
        } else {
            r.fail(
                i,
                &[
                    b"kernel rejected ",
                    path,
                    b": ",
                    errstr(ret),
                    b" (add_key asymmetric)",
                ],
            );
        }
        return;
    }
    r.pass(i);
}

/// The ID of `keyring`, as keyctl(2) gives it.
fn keyring_id(keyring: c_long) -> c_long {
    // SAFETY: keyctl(2) asking the ID of a keyring.
    unsafe {
        syscall(
            SYS_KEYCTL,
            KEYCTL_GET_KEYRING_ID,
            keyring,
            0 as c_long,
            0 as c_long,
            0 as c_long,
        )
    }
}

fn check_keyring(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_KEYRING, c"kernel_keyring");

    if keyring_id(KEY_SPEC_USER_KEYRING) < 0 {
        r.fail(
            i,
            &[
                b"keyctl(GET_KEYRING_ID, USER) failed: ",
                errstr(errno()),
                b" (needs CONFIG_KEYS=y)",
            ],
        );
        return;
    }
    if keyring_id(KEY_SPEC_BPF_KEYRING) >= 0 {
        r.pass(i);
    } else {
        r.fail(
            i,
            &[
                b"keyctl(GET_KEYRING_ID, BPF) failed: ",
                errstr(errno()),
                b" (the kernel has no bpf keyring)",
            ],
        );
    }
}

fn check_embedded_loader(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_EMBEDDED_LOADER, c"embedded_loader");
    let whole = |b: &[u8]| Lskel::parse(b).is_some();
    let (bpf2, seal) = (crate::skel::bpf2::LOADER, crate::skel::seal::LOADER);

    if whole(bpf2) && whole(seal) {
        r.pass(i);
    } else {
        r.fail(i, &[b"embedded BPF objects missing"]);
    }
}

fn check_tpm(r: &mut PreflightResult) {
    let i = r.next_slot(PRE_TPM, c"tpm2_reachable");

    // A TCTI override points at a software TPM, where the kernel resource
    // manager is not in play, so the device check would refuse a valid
    // setup. The operator's expectation still rejects what a fake TPM
    // produces, so this is a convenience, not a relaxation.
    {
        let mut cfg = Scrubbed::new();
        let loaded = config::load(&mut cfg) == 0;
        let c = &*cfg;

        if loaded && c.tpm_tcti[0] != 0 {
            r.pass(i);
            let detail = &mut r.checks[i].detail;

            if strsprintf(detail, &[b"TCTI from the config: ", cstr(&c.tpm_tcti)]).is_err() {
                let _ = strscpy(detail, b"TCTI from the config");
            }
            return;
        }
    }
    // SAFETY: a C string and a mode.
    if unsafe { access(c"/dev/tpmrm0".as_ptr(), R_OK | W_OK) } == 0 {
        r.pass(i);
    } else {
        r.fail(
            i,
            &[
                b"/dev/tpmrm0: ",
                errstr(errno()),
                b" (shirudo requires a TPM 2.0; for swtpm set tpm.tcti = swtpm:host=...,port=... in \
                  /etc/shirudo/shirudo.conf or SHIRUDO_TPM_TCTI)",
            ],
        );
    }
}

/// Every check, in order, into `out`.
pub(crate) fn run(r: &mut PreflightResult) {
    let out: *mut PreflightResult = r;
    // SAFETY: the caller's result, all of whose bits zeroed are one,
    // zeroed whole first as the C's memset() left it.
    unsafe { out.write_bytes(0, 1) };

    check_root(r);
    check_bpf_lsm(r);
    check_bpffs(r);
    check_signed_loader_abi(r);
    check_lsm_hooks(r);
    check_cert(r);
    check_cert_algorithm(r);
    check_cert_kernel_algo(r);
    check_keyring(r);
    check_embedded_loader(r);
    check_tpm(r);
}
