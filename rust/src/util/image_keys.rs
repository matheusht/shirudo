// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The trusted key set a config image carries: certificates under
//! keys/trusted/, each vouched for by a signer the runtime trusts, and
//! revocations under keys/revoked/, each named by the fingerprint of the
//! certificate it holds. Validation only reads; applying revokes.

use core::ffi::{CStr, c_int};
use std::ffi::CString;

use crate::errno::{EINVAL, EKEYREJECTED, ENOENT, ENOKEY};
use crate::heap::xfree;
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    O_CLOEXEC, O_DIRECTORY, O_NOFOLLOW, O_NONBLOCK, S_IFMT, S_IFREG, Statx, close, closedir,
    fdopendir, openat, readdir, set_errno,
};
use crate::util::image_config;
use crate::util::io::stat_fd;
use crate::util::keyring::{keyring_bpf_serial, keyring_holds_cert};
use crate::util::keys::{
    TrustedSet, keys_cert_der, keys_digest_der, keys_load_image_root, keys_read_der_fd, members,
};

/// KEYS_DER_MAX: the largest certificate a key file holds.
const DER_MAX: u64 = 1024 * 1024;
/// The runtime's certificate, the set's initial signer.
pub(crate) const RUNTIME_CERT_PATH: &CStr = c"/run/shirudo/runtime/keys/cert.der";

const O_RDONLY: c_int = 0;

fn error(text: String) {
    let text = CString::new(text).unwrap_or_default();

    // SAFETY: a "%s" format with a C string.
    unsafe { crate::log::log_c!(crate::log::err, c"%s".as_ptr(), text.as_ptr()) };
}

fn strerror(err: c_int) -> String {
    std::io::Error::from_raw_os_error(-err)
        .to_string()
        .split(" (os error")
        .next()
        .unwrap_or_default()
        .to_owned()
}

fn errno() -> c_int {
    -std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EINVAL)
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// The fingerprint a revocation's name spells: 64 lowercase hex digits
/// and `.der`, nothing else.
fn revoked_fingerprint(name: &[u8]) -> Option<[u8; 32]> {
    let hex = name.strip_suffix(b".der").filter(|h| h.len() == 64)?;
    let mut out = [0u8; 32];
    for (o, pair) in out.iter_mut().zip(hex.chunks(2)) {
        *o = hex_digit(pair[0])? << 4 | hex_digit(pair[1])?;
    }
    // One certificate, one name: uppercase would let a second file
    // revoke the same certificate past the last-signer check.
    (!hex.iter().any(u8::is_ascii_uppercase)).then_some(out)
}

/// An fd, closed when it goes.
struct Fd(c_int);

impl Drop for Fd {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: an fd this module opened, closed once, here.
            unsafe { close(self.0) };
        }
    }
}

fn open_dir(at: c_int, name: &CStr) -> Result<Option<Fd>, c_int> {
    // SAFETY: an open directory and a C string.
    let fd = unsafe {
        openat(
            at,
            name.as_ptr(),
            O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
        )
    };
    if fd >= 0 {
        return Ok(Some(Fd(fd)));
    }
    match errno() {
        e if e == -ENOENT => Ok(None),
        e => Err(e),
    }
}

/// One revocation under `dir`: its certificate, whose fingerprint must
/// be the name's, from a regular file on the image's device.
fn revoked_cert(dir: c_int, name: &CStr, dev: (u32, u32)) -> Result<Vec<u8>, c_int> {
    let expected = revoked_fingerprint(name.to_bytes()).ok_or(-EINVAL)?;
    // SAFETY: the open directory and an entry's name.
    let fd = Fd(unsafe {
        openat(
            dir,
            name.as_ptr(),
            O_RDONLY | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW,
        )
    });
    if fd.0 < 0 {
        return Err(errno());
    }
    let mut st = Statx::zeroed();
    let ret = stat_fd(fd.0, &mut st);
    if ret != 0 {
        return Err(ret);
    }
    if st.stx_mode & S_IFMT != S_IFREG
        || (st.stx_dev_major, st.stx_dev_minor) != dev
        || st.stx_size == 0
        || st.stx_size > DER_MAX
    {
        return Err(-EINVAL);
    }
    let (mut der, mut size) = (core::ptr::null_mut(), 0usize);
    // SAFETY: the open file and rooms for the bytes and their size.
    let ret = unsafe { keys_read_der_fd(fd.0, &mut der, &mut size) };
    drop(fd);
    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the size bytes keys_read_der_fd() allocated.
    let bytes = unsafe { crate::ffi::slice(der, size) }.to_vec();
    // SAFETY: the allocation, freed once.
    unsafe { xfree(der.cast(), size) };
    let (mut digest, mut fingerprint) = ([0u8; 32], [0u8; 32]);
    // SAFETY: the certificate and rooms for its two digests.
    let ret = unsafe {
        keys_digest_der(
            bytes.as_ptr(),
            bytes.len(),
            digest.as_mut_ptr(),
            fingerprint.as_mut_ptr(),
        )
    };
    if ret != 0 {
        return Err(ret);
    }
    if fingerprint != expected {
        return Err(-EKEYREJECTED);
    }
    Ok(bytes)
}

/// Checks every revocation of the image at `root_fd`, in directory
/// order, and with `apply` revokes each from the kernel: 0 or the first
/// error. An image without keys/revoked/ revokes nothing.
fn revocations(root_fd: c_int, apply: bool, boot: bool) -> c_int {
    let mut root = Statx::zeroed();
    let ret = stat_fd(root_fd, &mut root);
    if ret != 0 {
        return ret;
    }
    let dev = (root.stx_dev_major, root.stx_dev_minor);
    let keys = match open_dir(root_fd, c"keys") {
        Ok(Some(fd)) => fd,
        Ok(None) => return 0,
        Err(err) => return err,
    };
    let revoked = match open_dir(keys.0, c"revoked") {
        Ok(Some(fd)) => fd,
        Ok(None) => return 0,
        Err(err) => return err,
    };
    drop(keys);
    let dir_fd = revoked.0;
    // SAFETY: the open directory, whose fd the stream takes over.
    let dir = unsafe { fdopendir(dir_fd) };
    if dir.is_null() {
        return errno();
    }
    core::mem::forget(revoked);

    let mut ret = 0;
    loop {
        // The end of the stream tells from an error by errno alone.
        set_errno(0);
        // SAFETY: the open stream.
        let entry = unsafe { readdir(dir) };
        if entry.is_null() {
            let err = errno();
            if err != 0 {
                ret = err;
            }
            break;
        }
        // SAFETY: the entry readdir() gave, its name a C string.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr().cast()) };
        if matches!(name.to_bytes(), b"." | b"..") {
            continue;
        }
        let result = revoked_cert(dir_fd, name, dev);
        ret = match result {
            Ok(der) if apply => crate::builtin::keys::revoke_image(&der, boot),
            Ok(_) => 0,
            Err(err) => err,
        };
        if ret != 0 {
            break;
        }
    }
    // SAFETY: the stream, closed once with its fd.
    unsafe { closedir(dir) };
    ret
}

/// The trust set of the config image at `root_fd`: its config, its
/// revocations and its certificates checked, without changing anything,
/// with `primary` the signer the vouches lead back to. A set without a
/// certificate or with an unvouched one is refused.
pub(crate) fn validate_set(primary: &CStr, root_fd: c_int, set: &mut TrustedSet) -> c_int {
    let ret = image_config::validate(root_fd);
    if ret != 0 {
        error(format!(
            "image trust set: validate config image: {}",
            strerror(ret)
        ));
        return ret;
    }
    let ret = revocations(root_fd, false, false);
    if ret != 0 {
        error(format!(
            "image trust set: validate revocations: {}",
            strerror(ret)
        ));
        return ret;
    }
    // SAFETY: a C string, the image and the set to fill.
    let ret = unsafe { keys_load_image_root(primary.as_ptr(), root_fd, true, set) };
    if ret != 0 {
        error(format!(
            "image trust set: load certificates: {}",
            strerror(ret)
        ));
        return ret;
    }
    if set.len() == 0 || set.n_unvouched() != 0 {
        error(format!(
            "image trust set: reject set with {} certificates and {} unvouched",
            set.len(),
            set.n_unvouched()
        ));
        return -EKEYREJECTED;
    }
    0
}

/// Whether `holds` finds every certificate of `set`: 0, -ENOKEY for one
/// it does not, or its error. A key set takes effect only at boot, when
/// the kernel enrols its certificates, so a live update can only use the
/// signers the kernel already holds.
pub(crate) fn check_set_with(set: &TrustedSet, mut holds: impl FnMut(&[u8]) -> c_int) -> c_int {
    for cert in members(set) {
        let (mut der, mut size) = (core::ptr::null(), 0usize);
        // SAFETY: a certificate of the set and rooms for its bytes.
        let ret = unsafe { keys_cert_der(cert, &mut der, &mut size) };
        if ret != 0 {
            return ret;
        }
        // SAFETY: the size bytes the set holds.
        let ret = holds(unsafe { crate::ffi::slice(der, size) });
        if ret != 1 {
            return if ret < 0 { ret } else { -ENOKEY };
        }
    }
    0
}

/// [`check_set_with`] the BPF keyring: keys_check_image_set().
pub(crate) fn check_set(set: &TrustedSet) -> c_int {
    let ring = keyring_bpf_serial();
    if ring < 0 {
        return ring;
    }
    // SAFETY: the keyring and a certificate's bytes.
    check_set_with(set, |der| unsafe {
        keyring_holds_cert(ring, der.as_ptr(), der.len())
    })
}

/// Validates the trust set of the image at `root_fd`, from the runtime's
/// signer, and checks the kernel holds all of it.
pub(crate) fn validate(root_fd: c_int) -> c_int {
    // SAFETY: an all-zero set is an empty one.
    let mut set: Box<TrustedSet> = Box::new(unsafe { core::mem::zeroed() });
    let ret = validate_set(RUNTIME_CERT_PATH, root_fd, &mut set);
    if ret != 0 { ret } else { check_set(&set) }
}

/// Validates the trust set of the image at `root_fd`, then revokes what
/// it revokes, as a boot or a live update records it.
pub(crate) fn apply(root_fd: c_int, boot: bool) -> c_int {
    let ret = validate(root_fd);
    if ret != 0 {
        ret
    } else {
        revocations(root_fd, true, boot)
    }
}
