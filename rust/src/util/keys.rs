// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The certificates a target trusts: the primary
//! one, and each certificate under trusted/ that a member vouched for,
//! less those revoked, read from a directory or through a config image's
//! descriptor.

use core::ffi::{CStr, c_char, c_int};
use core::ptr;
use std::sync::{Mutex, MutexGuard, PoisonError};

use openssl::x509::X509;

use crate::errno::{
    E2BIG, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT, ENOKEY, ENOMEM, EPERM, text,
};
use crate::ffi;
use crate::heap::{libc_free, xcalloc, xfree, xmalloc};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_EMPTY_PATH, Dirent, F_OK, O_CLOEXEC, O_DIRECTORY, O_RDONLY, PATH_MAX, S_IFMT, S_IFREG,
    STATX_SIZE, STATX_TYPE, Statx, access, alphasort, close, errno, faccessat, open, read,
    scandirat, statx, unlink,
};
use crate::text::capi::name_has_suffix;
use crate::text::{cstr, strscpy, strsprintf};
use crate::util::crypto_openssl::{self, pubkey_digest, verify_detached_x509, x509_from_der};
use crate::util::hex::encode;
use crate::util::image_config;
use crate::util::io::{check_trusted, open_beneath, read_fd};
use crate::util::seal::{seal_mkdir_p, seal_write_file};
use std::os::fd::{AsRawFd, IntoRawFd};

/// `KEYS_MAX`: the most certificates a set holds.
pub(crate) const KEYS_MAX: usize = 16;
/// `KEYS_DER_MAX`: the largest certificate or vouch read.
pub(crate) const DER_MAX: usize = 1024 * 1024;
/// `KEYS_VOUCH_PREFIX` with the NUL sizeof() counts, which the payload
/// of a vouch starts with.
const VOUCH_PREFIX: &[u8] = b"shirudo-key-vouch\0";
/// Files under trusted/ a load looks at, members or not.
const SCAN_MAX: usize = 64;
/// KEYS_DIR, the runtime's keys and RUNTIME_CERT_PATH of util/paths.h.
const KEYS_DIR: &[u8] = b"/var/lib/shirudo/keys";
const RUNTIME_KEYS_DIR: &[u8] = b"/run/shirudo/runtime/keys";
const RUNTIME_CERT_PATH: &CStr = c"/run/shirudo/runtime/keys/cert.der";

/// `struct trusted_cert`.
#[repr(C)]
pub struct TrustedCert {
    path: [u8; PATH_MAX],
    sha256: [u8; 32],
    fingerprint: [u8; 32],
    voucher: [u8; 32],
    primary: bool,
}

/// `struct trusted_set`.
#[repr(C)]
pub struct TrustedSet {
    certs: [TrustedCert; KEYS_MAX],
    n: usize,
    n_revoked: usize,
    n_unvouched: usize,
}

/// `struct keys_candidate`: a certificate under trusted/ waiting for a
/// vouch, by its path, or by its name under `dirfd` when that is open.
#[repr(C)]
struct Candidate {
    path: [u8; PATH_MAX],
    name: [u8; 256],
    der: *mut u8,
    der_sz: usize,
    sha256: [u8; 32],
    fingerprint: [u8; 32],
    dirfd: c_int,
    done: bool,
}

const _: () = assert!(size_of::<TrustedCert>() == 4193);
const _: () = assert!(size_of::<TrustedSet>() == 67112);
const _: () = assert!(size_of::<Candidate>() == 4440);

/// A certificate a set took, by its digest.
struct Kept {
    sha256: [u8; 32],
    der: &'static [u8],
}

/// The most certificates the store keeps.
const KEPT_MAX: usize = 8 * KEYS_MAX;

/// The DER of every certificate a set took. Whoever needs the bytes
/// later, to enrol, to look in the keyring or to check a vouch, takes
/// them from here: a path reopened then may name other bytes, and a
/// member read from a config image has no path at all. A copy kept
/// lives as long as the process.
static KEPT: Mutex<Vec<Kept>> = Mutex::new(Vec::new());

/// The certificates kept so far.
fn kept() -> MutexGuard<'static, Vec<Kept>> {
    KEPT.lock().unwrap_or_else(PoisonError::into_inner)
}

/// An empty vector with room for `len` bytes, or -ENOMEM.
fn room_for(len: usize) -> Result<Vec<u8>, c_int> {
    let mut v = Vec::new();

    v.try_reserve_exact(len).map_err(|_| -ENOMEM)?;
    Ok(v)
}

/// The certificate open at `fd`, whole, into an allocation xfree()
/// takes: 0, -EINVAL for an empty one, or -errno.
///
/// # Safety
///
/// `fd` is open.
unsafe fn read_der_fd(fd: c_int, out: &mut *mut u8, out_sz: &mut usize) -> c_int {
    // SAFETY: the caller's fd, a C string, and room for the allocation
    // and its length.
    let ret = unsafe {
        read_fd(
            fd,
            c"certificate".as_ptr(),
            DER_MAX,
            (out as *mut *mut u8).cast(),
            out_sz,
        )
    };

    if ret == 0 && *out_sz == 0 {
        // SAFETY: read_fd()'s allocation of one byte, freed once.
        unsafe { xfree((*out).cast(), 1) };
        *out = ptr::null_mut();
        return -EINVAL;
    }
    ret
}

/// read_der_fd() on `name` beneath `dirfd`.
///
/// # Safety
///
/// `name` is a C string.
unsafe fn read_der_at(
    dirfd: c_int,
    name: *const c_char,
    out: &mut *mut u8,
    out_sz: &mut usize,
) -> c_int {
    // SAFETY: the caller's C string.
    let name = unsafe { CStr::from_ptr(name) };
    let fd = match open_beneath(dirfd, name, O_RDONLY) {
        Ok(fd) => fd,
        Err(err) => return err,
    };
    // SAFETY: the fd opened above.
    unsafe { read_der_fd(fd.as_raw_fd(), out, out_sz) }
}

/// [`read_der`] into a vector of its bytes.
pub(crate) fn read_der_bytes(path: &CStr) -> Result<Vec<u8>, c_int> {
    let (mut der, mut len) = (ptr::null_mut(), 0);

    // SAFETY: a C string and where the bytes and their count go.
    match unsafe { read_der(path.as_ptr(), &mut der, &mut len) } {
        0 => {
            // SAFETY: the len bytes read_der() allocated, copied and then
            // freed once.
            let bytes = unsafe { ffi::slice(der, len) }.to_vec();
            // SAFETY: as above.
            unsafe { xfree(der.cast(), len) };
            Ok(bytes)
        }
        err => Err(err),
    }
}

/// The certificate at `path`, a regular file of 1 to KEYS_DER_MAX bytes
/// that check_trusted() lets steer trust, into an allocation of its size:
/// 0, or -errno.
///
/// # Safety
///
/// `path` is a C string.
unsafe fn read_der(path: *const c_char, out: &mut *mut u8, out_sz: &mut usize) -> c_int {
    // SAFETY: the caller's C string, and flags.
    let fd = unsafe { open(path, O_RDONLY | O_CLOEXEC) };

    if fd < 0 {
        return -errno();
    }
    let mut st = Statx::zeroed();

    // SAFETY: the fd, an empty path, and room for its status.
    if unsafe {
        statx(
            fd,
            c"".as_ptr(),
            AT_EMPTY_PATH,
            STATX_TYPE | STATX_SIZE,
            &mut st,
        )
    } < 0
    {
        let ret = -errno();

        // SAFETY: the fd opened above, closed once.
        unsafe { close(fd) };
        return ret;
    }
    // SAFETY: the fd, and the caller's C string; then the fd closed once
    // on a refusal.
    let refused = unsafe {
        let ret = if st.stx_mode & S_IFMT != S_IFREG
            || st.stx_size == 0
            || st.stx_size > DER_MAX as u64
        {
            -EINVAL
        } else if check_trusted(fd, path, false) != 0 {
            -EPERM
        } else {
            0
        };
        if ret != 0 {
            close(fd);
        }
        ret
    };
    if refused != 0 {
        return refused;
    }
    let size = st.stx_size as usize;
    // SAFETY: a size of at most DER_MAX.
    let buf = unsafe { xmalloc(size) }.cast::<u8>();

    if buf.is_null() {
        // SAFETY: the fd opened above, closed once.
        unsafe { close(fd) };
        return -ENOMEM;
    }
    // SAFETY: the fd, read once into the size bytes at buf, and closed.
    let n = unsafe {
        let n = read(fd, buf.cast(), size);

        close(fd);
        n
    };
    if n != size as isize {
        // SAFETY: the allocation of size bytes, freed once.
        unsafe { xfree(buf.cast(), size) };
        return -EIO;
    }
    *out = buf;
    *out_sz = size;
    0
}

/// The SHA-256 of a certificate's DER, and its fingerprint: the SHA-256
/// of its public key.
#[derive(Clone, Copy)]
pub(crate) struct CertDigests {
    pub(crate) sha256: [u8; 32],
    pub(crate) fingerprint: [u8; 32],
}

/// The digests of the certificate `der`: what hashing failed with, or
/// -EINVAL for bytes that are not a certificate.
pub(crate) fn digest_der(der: &[u8]) -> Result<CertDigests, c_int> {
    let sha256 = crypto_openssl::sha256(der)?;
    let x509 = x509_from_der(der)?;

    Ok(CertDigests {
        sha256,
        fingerprint: pubkey_digest(&x509)?,
    })
}

/// A copy of the certificate with digest `sha256` kept for the life of
/// the process, once: -E2BIG with the store full, or -ENOMEM.
fn der_keep(sha256: &[u8; 32], der: &[u8]) -> Result<(), c_int> {
    let mut kept = kept();

    if kept.iter().any(|k| k.sha256 == *sha256) {
        return Ok(());
    }
    if kept.len() >= KEPT_MAX {
        return Err(-E2BIG);
    }
    kept.try_reserve(1).map_err(|_| -ENOMEM)?;
    let mut copy = room_for(der.len())?;

    copy.extend_from_slice(der);
    kept.push(Kept {
        sha256: *sha256,
        der: copy.leak(),
    });
    Ok(())
}

/// The kept bytes of the certificate `c`: -ENOKEY for one no set took.
pub(crate) fn cert_der(c: &TrustedCert) -> Result<&'static [u8], c_int> {
    kept()
        .iter()
        .find(|k| k.sha256 == c.sha256)
        .map(|k| k.der)
        .ok_or(-ENOKEY)
}

/// The certificate `c`, read from its kept bytes: -ENOKEY for one no
/// set took, or -EINVAL.
pub(crate) fn cert_x509(c: &TrustedCert) -> Result<X509, c_int> {
    x509_from_der(cert_der(c)?)
}

/// The certificate at `path`, its digests, and its bytes kept for the
/// set.
///
/// # Safety
///
/// `path` is a C string.
unsafe fn take_file(path: *const c_char) -> Result<CertDigests, c_int> {
    let mut der: *mut u8 = ptr::null_mut();
    let mut der_sz = 0usize;
    // SAFETY: the caller's C string.
    let ret = unsafe { read_der(path, &mut der, &mut der_sz) };

    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the der_sz bytes read.
    let bytes = unsafe { ffi::slice(der, der_sz) };
    let taken = digest_der(bytes).and_then(|d| der_keep(&d.sha256, bytes).map(|()| d));
    // SAFETY: read_der()'s allocation of der_sz bytes, freed once.
    unsafe { xfree(der.cast(), der_sz) };
    taken
}

/// The digests of the certificate at `path`, kept nowhere.
///
/// # Safety
///
/// `path` is a C string.
unsafe fn digest_file(path: *const c_char) -> Result<CertDigests, c_int> {
    let mut der: *mut u8 = ptr::null_mut();
    let mut der_sz = 0usize;
    // SAFETY: the caller's C string.
    let ret = unsafe { read_der(path, &mut der, &mut der_sz) };

    if ret != 0 {
        return Err(ret);
    }
    // SAFETY: the der_sz bytes read.
    let digests = digest_der(unsafe { ffi::slice(der, der_sz) });
    // SAFETY: read_der()'s allocation of der_sz bytes, freed once.
    unsafe { xfree(der.cast(), der_sz) };
    digests
}

/// The hex digits of a fingerprint, and a NUL.
fn fingerprint_hex(fingerprint: &[u8; 32]) -> [u8; 65] {
    let mut hex = [0u8; 65];

    hex[..64].copy_from_slice(&encode(fingerprint));
    hex
}

/// `<dir>/<fingerprint hex><suffix>`, the name of a certificate in a set:
/// 0 or -ENAMETOOLONG.
fn path_for(dir: &[u8], fingerprint: &[u8; 32], suffix: &[u8], out: &mut [u8]) -> c_int {
    let hex = fingerprint_hex(fingerprint);

    if strsprintf(out, &[dir, b"/", cstr(&hex), suffix]).is_err() {
        return -ENAMETOOLONG;
    }
    0
}

/// Whether `revoked_dir` holds the certificate of `fingerprint`.
///
/// # Safety
///
/// `revoked_dir` is NULL or a C string.
unsafe fn is_revoked(revoked_dir: *const c_char, fingerprint: &[u8; 32]) -> bool {
    let mut path = [0u8; PATH_MAX];

    if revoked_dir.is_null() {
        return false;
    }
    // SAFETY: the caller's C string.
    let dir = unsafe { ffi::c_str(revoked_dir) };

    if path_for(dir, fingerprint, b".der", &mut path) != 0 {
        return false;
    }
    // SAFETY: the path, terminated by strsprintf(), and a mode.
    unsafe { access(path.as_ptr().cast(), F_OK) == 0 }
}

/// Whether the revoked directory open as `revoked_fd` holds the
/// certificate of `fingerprint`.
fn is_revoked_at(revoked_fd: c_int, fingerprint: &[u8; 32]) -> bool {
    if revoked_fd < 0 {
        return false;
    }
    let hex = fingerprint_hex(fingerprint);
    let mut name = [0u8; 64 + b".der\0".len()];

    name[..64].copy_from_slice(&hex[..64]);
    name[64..].copy_from_slice(b".der\0");
    // SAFETY: the caller's fd, a C string, a mode and no flags.
    unsafe { faccessat(revoked_fd, name.as_ptr().cast(), F_OK, 0) == 0 }
}

/// The payload a vouch for the certificate `der` signs: VOUCH_PREFIX,
/// its NUL included, and then the DER. -ENOMEM.
pub(crate) fn vouch_payload(der: &[u8]) -> Result<Vec<u8>, c_int> {
    let len = VOUCH_PREFIX.len().checked_add(der.len()).ok_or(-ENOMEM)?;
    let mut payload = room_for(len)?;

    payload.extend_from_slice(VOUCH_PREFIX);
    payload.extend_from_slice(der);
    Ok(payload)
}

/// The fingerprint of the member of `set` that signed the vouch `sig`
/// for the certificate `der`: -EKEYREJECTED for none, or -errno.
pub(crate) fn verify_vouch(set: &TrustedSet, der: &[u8], sig: &[u8]) -> Result<[u8; 32], c_int> {
    verify_signature(set, &vouch_payload(der)?, sig)
}

/// The fingerprint of the member of `set` that signed `payload` with the
/// detached CMS signature `sig`: -EKEYREJECTED when none did, or the
/// error of a member that does not read.
pub(crate) fn verify_signature(
    set: &TrustedSet,
    payload: &[u8],
    sig: &[u8],
) -> Result<[u8; 32], c_int> {
    for c in members(set) {
        let x509 = cert_x509(c)?;

        if verify_detached_x509(payload, sig, &x509) == 0 {
            return Ok(c.fingerprint);
        }
    }
    Err(-EKEYREJECTED)
}

impl TrustedCert {
    pub(crate) fn sha256(&self) -> &[u8; 32] {
        &self.sha256
    }

    pub(crate) fn fingerprint(&self) -> &[u8; 32] {
        &self.fingerprint
    }

    pub(crate) fn voucher(&self) -> &[u8; 32] {
        &self.voucher
    }

    pub(crate) fn primary(&self) -> bool {
        self.primary
    }
}

impl TrustedCert {
    /// The certificate at `path`, by its digests, as a set's primary.
    pub(crate) fn primary_at(path: &CStr) -> Result<Self, c_int> {
        // SAFETY: plain C data, for which all-zero bytes are a value.
        let mut c: TrustedCert = unsafe { core::mem::zeroed() };
        let p = path.to_bytes();
        if p.len() >= c.path.len() {
            return Err(-crate::errno::ENAMETOOLONG);
        }
        c.path[..p.len()].copy_from_slice(p);
        c.primary = true;
        // SAFETY: the C string just copied.
        let digests = unsafe { digest_file(c.path.as_ptr().cast()) }?;
        c.sha256 = digests.sha256;
        c.fingerprint = digests.fingerprint;
        Ok(c)
    }
}

impl TrustedSet {
    /// `c` added; the caller checked there is room.
    pub(crate) fn push(&mut self, c: TrustedCert) {
        self.certs[self.n] = c;
        self.n += 1;
    }

    /// How many certificates the set holds.
    pub(crate) fn len(&self) -> usize {
        self.n.min(KEYS_MAX)
    }

    pub(crate) fn n_revoked(&self) -> usize {
        self.n_revoked
    }

    pub(crate) fn n_unvouched(&self) -> usize {
        self.n_unvouched
    }

    /// The digest the init event covers: [`anchor_digest`] of the
    /// members' SHA-256.
    pub(crate) fn digest(&self) -> Result<[u8; 32], c_int> {
        if self.n > KEYS_MAX {
            return Err(-EINVAL);
        }
        let sha256: Vec<[u8; 32]> = members(self).iter().map(|c| c.sha256).collect();

        anchor_digest(&sha256)
    }
}

pub(crate) use capi::{
    keys_install, keys_is_revoked, keys_load, keys_load_image_at, keys_load_image_root,
    keys_read_der, keys_read_der_fd,
};

/// The members of a set.
pub(crate) fn members(set: &TrustedSet) -> &[TrustedCert] {
    &set.certs[..set.n.min(KEYS_MAX)]
}

/// The path a member was read from.
pub(crate) fn cert_path(c: &TrustedCert) -> &[u8] {
    cstr(&c.path)
}

/// Whether the set holds the certificate of `fingerprint`.
fn set_holds(set: &TrustedSet, fingerprint: &[u8; 32]) -> bool {
    set.certs[..set.n.min(KEYS_MAX)]
        .iter()
        .any(|c| c.fingerprint == *fingerprint)
}

/// A certificate added to the set, its bytes kept when given; a voucher
/// makes it a member, none the primary. 0, -E2BIG or -ENAMETOOLONG.
fn set_add(
    set: &mut TrustedSet,
    path: &[u8],
    sha256: &[u8; 32],
    fingerprint: &[u8; 32],
    voucher: Option<&[u8; 32]>,
    der: Option<&[u8]>,
) -> c_int {
    if set.n >= KEYS_MAX {
        return -E2BIG;
    }
    if let Some(der) = der
        && let Err(err) = der_keep(sha256, der)
    {
        return err;
    }
    let c = &mut set.certs[set.n];

    // SAFETY: the certificate's slot, all of whose bits zeroed are one.
    unsafe { ptr::from_mut(c).write_bytes(0, 1) };
    if strscpy(&mut c.path, path).is_err() {
        return -ENAMETOOLONG;
    }
    c.sha256 = *sha256;
    c.fingerprint = *fingerprint;
    match voucher {
        Some(v) => c.voucher = *v,
        None => c.primary = true,
    }
    set.n += 1;
    0
}

/// scandir()'s filter: the names that end in .der.
unsafe extern "C" fn select_der(e: *const Dirent) -> c_int {
    // SAFETY: the entry scandir() reads, its name a C string.
    unsafe {
        let name = (*e).d_name.as_ptr().cast::<c_char>();

        c_int::from(name_has_suffix(
            name,
            CStr::from_ptr(name).count_bytes(),
            c".der".as_ptr(),
        ))
    }
}

/// The names scandir() gave, freed.
///
/// # Safety
///
/// `names` holds the `n` entries scandir() allocated, or is NULL.
unsafe fn names_free(names: *mut *mut Dirent, n: c_int) {
    // SAFETY: each entry, then the array, freed once.
    unsafe {
        for i in 0..usize::try_from(n).unwrap_or(0) {
            libc_free((*names.add(i)).cast());
        }
        libc_free(names.cast());
    }
}

/// How many certificates the directory at `dir` holds.
///
/// # Safety
///
/// `dir` is a C string.
unsafe fn count_der(dir: *const c_char) -> usize {
    // SAFETY: the caller's C string.
    let dir = unsafe { ffi::c_str(dir) };
    crate::util::io::dir_names(dir, |n| crate::text::name_has_suffix(n, b".der"))
        .map_or(0, |n| n.len())
}

/// How many certificates the directory open as `dirfd` holds.
fn count_der_at(dirfd: c_int) -> usize {
    let mut names: *mut *mut Dirent = ptr::null_mut();

    if dirfd < 0 {
        return 0;
    }
    // SAFETY: the caller's fd, ".", room for the names, and a filter.
    let n = unsafe { scandirat(dirfd, c".".as_ptr(), &mut names, Some(select_der), None) };

    if n < 0 {
        return 0;
    }
    // SAFETY: the names scandirat() gave.
    unsafe { names_free(names, n) };
    n as usize
}

/// The vouch beside the certificate at `der_path`, its .der a .vouch. A
/// name shorter than .der, which the scan never selects, is kept whole,
/// as the C's `%.*s` of a negative length did.
fn vouch_path_for(der_path: &[u8], out: &mut [u8]) -> c_int {
    let stem = der_path
        .get(..der_path.len().wrapping_sub(4))
        .unwrap_or(der_path);

    if strsprintf(out, &[stem, b".vouch"]).is_err() {
        return -ENAMETOOLONG;
    }
    0
}

/// The candidates whose vouch verifies under a member admitted, in
/// rounds, so a certificate vouched for by one admitted later still
/// joins; the rest counted unvouched. 0, or what adding one failed with.
///
/// # Safety
///
/// Each candidate holds its DER, and its `dirfd` is open or -1.
unsafe fn admit_vouched(set: &mut TrustedSet, cand: &mut [Candidate]) -> c_int {
    let mut progress = true;

    while progress {
        progress = false;
        for c in cand.iter_mut() {
            let mut vouch = [0u8; PATH_MAX];
            let mut sig: *mut u8 = ptr::null_mut();
            let mut sig_sz = 0usize;

            if c.done {
                continue;
            }
            if set_holds(set, &c.fingerprint) {
                c.done = true;
                continue;
            }
            let from = if c.dirfd >= 0 {
                cstr(&c.name)
            } else {
                cstr(&c.path)
            };

            if vouch_path_for(from, &mut vouch) != 0 {
                continue;
            }
            // SAFETY: the vouch's name or path, a C string, and room for
            // its bytes.
            let read = unsafe {
                if c.dirfd >= 0 {
                    read_der_at(c.dirfd, vouch.as_ptr().cast(), &mut sig, &mut sig_sz)
                } else {
                    read_der(vouch.as_ptr().cast(), &mut sig, &mut sig_sz)
                }
            };
            if read != 0 {
                continue;
            }
            // SAFETY: the candidate's DER and the vouch read.
            let verified =
                unsafe { verify_vouch(set, ffi::slice(c.der, c.der_sz), ffi::slice(sig, sig_sz)) };
            // SAFETY: the vouch's allocation, freed as the C freed it.
            unsafe { xfree(sig.cast(), sig_sz) };
            let Ok(voucher) = verified else {
                continue;
            };
            // SAFETY: the candidate's DER.
            let der = unsafe { ffi::slice(c.der, c.der_sz) };
            let ret = set_add(
                set,
                cstr(&c.path),
                &c.sha256,
                &c.fingerprint,
                Some(&voucher),
                Some(der),
            );

            if ret != 0 {
                return ret;
            }
            c.done = true;
            progress = true;
        }
    }
    set.n_unvouched += cand.iter().filter(|c| !c.done).count();
    0
}

/// The candidates' DER and their array freed.
///
/// # Safety
///
/// `cand` is the array xcalloc() gave, its first `n` with their DER.
unsafe fn candidates_free(cand: *mut Candidate, n: usize) {
    // SAFETY: each DER, then the array, freed once.
    unsafe {
        for i in 0..n {
            let c = &*cand.add(i);

            xfree(c.der.cast(), c.der_sz);
        }
        xfree(cand.cast(), SCAN_MAX * size_of::<Candidate>());
    }
}

/// The scan's next candidate, or -E2BIG when the array is full.
fn next_slot(cand: &mut [Candidate], n_cand: usize) -> Result<&mut Candidate, c_int> {
    cand.get_mut(n_cand).ok_or(-E2BIG)
}

/// Every .der under `<keys_dir>/trusted` read: the ones not revoked
/// become candidates for admission, which needs the whole list first.
///
/// # Safety
///
/// `revoked_dir` is a C string, and `cand` the SCAN_MAX candidates
/// xcalloc() gave.
unsafe fn scan_trusted(
    keys_dir: &[u8],
    revoked_dir: *const c_char,
    cand: &mut [Candidate],
    n_cand: &mut usize,
) -> c_int {
    let mut dir = [0u8; PATH_MAX];
    let mut ret = 0;

    if strsprintf(&mut dir, &[keys_dir, b"/trusted"]).is_err() {
        return -ENAMETOOLONG;
    }
    let names = match crate::util::io::dir_names(cstr(&dir), |n| {
        crate::text::name_has_suffix(n, b".der")
    }) {
        Ok(names) => names,
        Err(err) if err == -ENOENT => return 0,
        Err(err) => return err,
    };
    for name in &names {
        if ret != 0 {
            break;
        }
        let c = match next_slot(cand, *n_cand) {
            Ok(c) => c,
            Err(e) => {
                ret = e;
                break;
            }
        };
        c.dirfd = -1;
        if strsprintf(&mut c.path, &[cstr(&dir), b"/", name]).is_err() {
            ret = -ENAMETOOLONG;
            break;
        }
        // SAFETY: the candidate's path, terminated by strsprintf().
        ret = unsafe { read_der(c.path.as_ptr().cast(), &mut c.der, &mut c.der_sz) };
        if ret != 0 {
            break;
        }
        // SAFETY: the DER read.
        match digest_der(unsafe { ffi::slice(c.der, c.der_sz) }) {
            Ok(d) => (c.sha256, c.fingerprint) = (d.sha256, d.fingerprint),
            Err(err) => {
                ret = err;
                // SAFETY: read_der()'s allocation, freed once.
                unsafe { xfree(c.der.cast(), c.der_sz) };
                c.der = ptr::null_mut();
                break;
            }
        }
        // SAFETY: the caller's C string.
        if unsafe { is_revoked(revoked_dir, &c.fingerprint) } {
            // SAFETY: as above.
            unsafe { xfree(c.der.cast(), c.der_sz) };
            c.der = ptr::null_mut();
            continue;
        }
        *n_cand += 1;
    }
    ret
}

/// The same scan from the descriptor of the keys directory, which the
/// trusted directory's descriptor outlives into admit_vouched(): the
/// caller closes it after. `display` names the keys directory in the
/// candidates' paths.
///
/// # Safety
///
/// `cand` is the SCAN_MAX candidates xcalloc() gave.
unsafe fn scan_trusted_at(
    keys_fd: c_int,
    display: &[u8],
    cand: &mut [Candidate],
    n_cand: &mut usize,
    trusted_fd: &mut c_int,
) -> c_int {
    let mut names: *mut *mut Dirent = ptr::null_mut();
    let mut ret = 0;

    *trusted_fd = open_beneath(keys_fd, c"trusted", O_RDONLY | O_DIRECTORY)
        .map_or_else(|err| err, IntoRawFd::into_raw_fd);
    if *trusted_fd == -ENOENT {
        return 0;
    }
    if *trusted_fd < 0 {
        return *trusted_fd;
    }
    // SAFETY: the trusted fd, ".", room for the names, a filter and a
    // sort.
    let n = unsafe {
        scandirat(
            *trusted_fd,
            c".".as_ptr(),
            &mut names,
            Some(select_der),
            Some(alphasort),
        )
    };

    if n < 0 {
        return -errno();
    }
    for i in 0..n as usize {
        if ret != 0 {
            break;
        }
        // SAFETY: an entry scandirat() gave, its name a C string.
        let name = unsafe { ffi::c_str((**names.add(i)).d_name.as_ptr().cast()) };
        let c = match next_slot(cand, *n_cand) {
            Ok(c) => c,
            Err(e) => {
                ret = e;
                break;
            }
        };
        c.dirfd = *trusted_fd;
        if strscpy(&mut c.name, name).is_err()
            || strsprintf(&mut c.path, &[display, b"/trusted/", name]).is_err()
        {
            ret = -ENAMETOOLONG;
            break;
        }
        // SAFETY: the trusted fd, the candidate's name, a C string.
        ret = unsafe {
            read_der_at(
                *trusted_fd,
                c.name.as_ptr().cast(),
                &mut c.der,
                &mut c.der_sz,
            )
        };
        if ret != 0 {
            break;
        }
        // SAFETY: the DER read.
        match digest_der(unsafe { ffi::slice(c.der, c.der_sz) }) {
            Ok(d) => (c.sha256, c.fingerprint) = (d.sha256, d.fingerprint),
            Err(err) => {
                ret = err;
                // SAFETY: read_fd()'s allocation, freed as the C freed it.
                unsafe { xfree(c.der.cast(), c.der_sz) };
                c.der = ptr::null_mut();
                break;
            }
        }
        *n_cand += 1;
    }
    // SAFETY: the names scandirat() gave.
    unsafe { names_free(names, n) };
    ret
}

/// The SCAN_MAX candidates a scan fills, zeroed, or NULL.
fn candidates_new() -> *mut Candidate {
    // SAFETY: a count and a size.
    unsafe { xcalloc(SCAN_MAX, size_of::<Candidate>()) }.cast()
}

/// The set sorted by the SHA-256 of each certificate's DER, which no two
/// members share.
fn sort_set(set: &mut TrustedSet) {
    let n = set.n.min(KEYS_MAX);

    if n > 1 {
        set.certs[..n].sort_unstable_by_key(|c| c.sha256);
    }
}

/// The set of a keys directory: the primary at `primary` unless revoked,
/// with `with_trusted` the members trusted/ adds, and the count of what
/// is revoked. 0 or -errno, with what was taken so far in `set`.
///
/// # Safety
///
/// `primary` is a C string, `revoked_dir` NULL or one, and `set` room
/// for a set.
unsafe fn load_set(
    primary: *const c_char,
    keys_dir: &[u8],
    revoked_dir: *const c_char,
    with_trusted: bool,
    set: *mut TrustedSet,
) -> c_int {
    // SAFETY: the caller's room, all of whose bits zeroed are a set.
    let set = unsafe {
        set.write_bytes(0, 1);
        &mut *set
    };
    let mut revoked = [0u8; PATH_MAX];
    let revoked_dir = if revoked_dir.is_null() {
        if strsprintf(&mut revoked, &[keys_dir, b"/revoked"]).is_err() {
            return -ENAMETOOLONG;
        }
        revoked.as_ptr().cast()
    } else {
        revoked_dir
    };
    // SAFETY: the caller's C string.
    let digests = match unsafe { take_file(primary) } {
        Ok(d) => d,
        Err(err) => return err,
    };
    // SAFETY: a C string either way.
    if !unsafe { is_revoked(revoked_dir, &digests.fingerprint) } {
        // SAFETY: the caller's C string.
        let ret = set_add(
            set,
            unsafe { ffi::c_str(primary) },
            &digests.sha256,
            &digests.fingerprint,
            None,
            None,
        );

        if ret != 0 {
            return ret;
        }
    }
    // SAFETY: a C string.
    set.n_revoked = unsafe { count_der(revoked_dir) };
    if with_trusted {
        let cand = candidates_new();

        if cand.is_null() {
            return -ENOMEM;
        }
        let mut n_cand = 0usize;
        // SAFETY: the candidates xcalloc() gave, all of whose bits zeroed
        // are candidates, and a C string; then the candidates freed once.
        let ret = unsafe {
            let slots = core::slice::from_raw_parts_mut(cand, SCAN_MAX);
            let mut ret = scan_trusted(keys_dir, revoked_dir, slots, &mut n_cand);

            if ret == 0 {
                ret = admit_vouched(set, &mut slots[..n_cand]);
            }
            candidates_free(cand, n_cand);
            ret
        };
        if ret != 0 {
            return ret;
        }
    }
    sort_set(set);
    0
}

/// A config image's set: the primary and every vouched certificate
/// under keys/trusted, less what keys/revoked names, all read through
/// the image's descriptor. Historical vouches count before revocation,
/// so a revoked certificate's vouch for another still admits it.
///
/// # Safety
///
/// `primary` is a C string, and `set` room for a set.
unsafe fn load_set_at(
    primary: *const c_char,
    keys_fd: c_int,
    display: &[u8],
    with_trusted: bool,
    set: *mut TrustedSet,
) -> c_int {
    // SAFETY: the caller's room, all of whose bits zeroed are a set.
    let set = unsafe {
        set.write_bytes(0, 1);
        &mut *set
    };
    let mut trusted_fd = -1;
    // SAFETY: the caller's C string.
    let digests = match unsafe { take_file(primary) } {
        Ok(d) => d,
        Err(err) => return err,
    };
    // SAFETY: the caller's C string.
    let ret = set_add(
        set,
        unsafe { ffi::c_str(primary) },
        &digests.sha256,
        &digests.fingerprint,
        None,
        None,
    );

    if ret != 0 {
        return ret;
    }
    if keys_fd == -ENOENT {
        return 0;
    }
    let revoked_fd = open_beneath(keys_fd, c"revoked", O_RDONLY | O_DIRECTORY)
        .map_or_else(|err| err, IntoRawFd::into_raw_fd);

    set.n_revoked = count_der_at(revoked_fd);
    let ret = 'out: {
        if with_trusted {
            let cand = candidates_new();

            if cand.is_null() {
                break 'out -ENOMEM;
            }
            let mut n_cand = 0usize;
            // SAFETY: the candidates xcalloc() gave, all of whose bits
            // zeroed are candidates; then the candidates freed once.
            let ret = unsafe {
                let slots = core::slice::from_raw_parts_mut(cand, SCAN_MAX);
                let mut ret =
                    scan_trusted_at(keys_fd, display, slots, &mut n_cand, &mut trusted_fd);

                if ret == 0 {
                    ret = admit_vouched(set, &mut slots[..n_cand]);
                }
                candidates_free(cand, n_cand);
                ret
            };
            if ret != 0 {
                break 'out ret;
            }
        }
        let mut kept_n = 0usize;

        for i in 0..set.n.min(KEYS_MAX) {
            if !is_revoked_at(revoked_fd, &set.certs[i].fingerprint) {
                if kept_n != i {
                    // SAFETY: two slots of the set, kept_n before i.
                    unsafe {
                        ptr::copy_nonoverlapping(&set.certs[i], &mut set.certs[kept_n], 1);
                    }
                }
                kept_n += 1;
            }
        }
        set.n = kept_n;
        sort_set(set);
        0
    };
    // SAFETY: the fds opened here, each closed once.
    unsafe {
        if trusted_fd >= 0 {
            close(trusted_fd);
        }
        if revoked_fd >= 0 {
            close(revoked_fd);
        }
    }
    ret
}

/// The set of the config image whose root is open as `root_fd`.
///
/// # Safety
///
/// `primary` is a C string, and `set` room for a set.
unsafe fn load_image_root(
    primary: *const c_char,
    root_fd: c_int,
    with_trusted: bool,
    set: *mut TrustedSet,
) -> c_int {
    let keys_fd = open_beneath(root_fd, c"keys", O_RDONLY | O_DIRECTORY)
        .map_or_else(|err| err, IntoRawFd::into_raw_fd);

    if keys_fd < 0 && keys_fd != -ENOENT {
        crate::log::err(
            format!(
                "image trust set: open config image keys/: {}",
                text(keys_fd)
            )
            .as_bytes(),
        );
        return keys_fd;
    }
    // SAFETY: the caller's C string and room, and then the fd closed once.
    unsafe {
        let ret = load_set_at(primary, keys_fd, b"keys", with_trusted, set);

        if keys_fd >= 0 {
            close(keys_fd);
        }
        ret
    }
}

/// The set of the keys directory, from the config image when the
/// directory is the target's and an image is active.
///
/// # Safety
///
/// `keys_dir` is a C string, `revoked_dir` NULL or one, and `set` room
/// for a set.
pub(crate) unsafe fn load(
    keys_dir: *const c_char,
    revoked_dir: *const c_char,
    with_trusted: bool,
    set: *mut TrustedSet,
) -> c_int {
    // SAFETY: the caller's C string.
    let dir = unsafe { ffi::c_str(keys_dir) };
    let root_fd = image_config::root_fd();

    if root_fd >= 0 && (dir == KEYS_DIR || dir == RUNTIME_KEYS_DIR) {
        // SAFETY: a C string, and the caller's room.
        return unsafe {
            load_image_root(
                RUNTIME_CERT_PATH.as_ptr(),
                image_config::root_fd(),
                with_trusted,
                set,
            )
        };
    }
    let mut primary = [0u8; PATH_MAX];

    if strsprintf(&mut primary, &[dir, b"/", b"cert.der"]).is_err() {
        return -ENAMETOOLONG;
    }
    // SAFETY: the path, terminated by strsprintf(), the caller's C
    // strings and room.
    unsafe { load_set(primary.as_ptr().cast(), dir, revoked_dir, with_trusted, set) }
}

/// The digest of a set of anchors: the one, or the SHA-256 of all of
/// them sorted. -EINVAL for none or more than a set holds, or what
/// hashing failed with.
pub(crate) fn anchor_digest(sha256: &[[u8; 32]]) -> Result<[u8; 32], c_int> {
    if let [one] = sha256 {
        return Ok(*one);
    }
    if sha256.is_empty() || sha256.len() > KEYS_MAX {
        return Err(-EINVAL);
    }
    let mut sorted = sha256.to_vec();

    sorted.sort_unstable();
    crypto_openssl::sha256(sorted.as_flattened())
}

/// A certificate installed under `<keys_dir>/trusted` with its vouch, the
/// vouch first, and gone again if the certificate cannot be written. Its
/// path into `out`: 0 or -errno.
///
/// # Safety
///
/// `keys_dir` is a C string, `der` and `sig` hold `der_sz` and `sig_sz`
/// bytes, and `out` has room for `cap`.
unsafe fn install(
    keys_dir: *const c_char,
    der: *const u8,
    der_sz: usize,
    sig: *const u8,
    sig_sz: usize,
    out: *mut u8,
    cap: usize,
) -> c_int {
    let mut vouch = [0u8; PATH_MAX];
    let mut dir = [0u8; PATH_MAX];
    // SAFETY: the caller's bytes.
    let fingerprint = match digest_der(unsafe { ffi::slice(der, der_sz) }) {
        Ok(d) => d.fingerprint,
        Err(err) => return err,
    };
    // SAFETY: the caller's C string.
    if strsprintf(&mut dir, &[unsafe { ffi::c_str(keys_dir) }, b"/trusted"]).is_err() {
        return -ENAMETOOLONG;
    }
    // SAFETY: the path, terminated by strsprintf(), and a mode.
    let ret = unsafe { seal_mkdir_p(dir.as_ptr().cast(), 0o700) };

    if ret != 0 {
        return ret;
    }
    // SAFETY: the caller's room for cap bytes.
    let out = unsafe { ffi::bytes_mut(out, cap) };
    let mut ret = path_for(cstr(&dir), &fingerprint, b".der", out);

    if ret == 0 {
        ret = path_for(cstr(&dir), &fingerprint, b".vouch", &mut vouch);
    }
    if ret != 0 {
        return ret;
    }
    // SAFETY: the vouch's path, the caller's bytes, and a mode.
    let ret = unsafe { seal_write_file(vouch.as_ptr().cast(), sig.cast(), sig_sz, 0o644) };

    if ret != 0 {
        return ret;
    }
    // SAFETY: the certificate's path, the caller's bytes and a mode; then
    // the vouch removed when that failed.
    unsafe {
        let ret = seal_write_file(out.as_ptr().cast(), der.cast(), der_sz, 0o644);

        if ret != 0 {
            unlink(vouch.as_ptr().cast());
        }
        ret
    }
}

mod capi {
    use core::ffi::{c_char, c_int};

    use super::TrustedSet;

    /// # Safety
    ///
    /// `keys_dir` is a C string, `revoked_dir` NULL or one, and `set`
    /// room for a set.
    pub unsafe extern "C" fn keys_load(
        keys_dir: *const c_char,
        revoked_dir: *const c_char,
        with_trusted: bool,
        set: *mut TrustedSet,
    ) -> c_int {
        // SAFETY: the caller passes C strings and room for a set.
        unsafe { super::load(keys_dir, revoked_dir, with_trusted, set) }
    }

    /// # Safety
    ///
    /// `primary` is a C string, and `set` room for a set.
    pub unsafe extern "C" fn keys_load_image_at(
        primary: *const c_char,
        keys_fd: c_int,
        with_trusted: bool,
        set: *mut TrustedSet,
    ) -> c_int {
        // SAFETY: the caller passes a C string and room for a set.
        unsafe { super::load_set_at(primary, keys_fd, b"keys", with_trusted, set) }
    }

    /// # Safety
    ///
    /// `primary` is a C string, and `set` room for a set.
    pub unsafe extern "C" fn keys_load_image_root(
        primary: *const c_char,
        root_fd: c_int,
        with_trusted: bool,
        set: *mut TrustedSet,
    ) -> c_int {
        // SAFETY: the caller passes a C string and room for a set.
        unsafe { super::load_image_root(primary, root_fd, with_trusted, set) }
    }

    /// # Safety
    ///
    /// `path` is a C string, and `out` and `out_sz` room for the bytes
    /// and their length.
    pub unsafe extern "C" fn keys_read_der(
        path: *const c_char,
        out: *mut *mut u8,
        out_sz: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes a C string and room.
        unsafe { super::read_der(path, &mut *out, &mut *out_sz) }
    }

    /// # Safety
    ///
    /// `fd` is open, and `out` and `out_sz` room for the bytes and their
    /// length.
    pub unsafe extern "C" fn keys_read_der_fd(
        fd: c_int,
        out: *mut *mut u8,
        out_sz: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes an fd and room.
        unsafe { super::read_der_fd(fd, &mut *out, &mut *out_sz) }
    }

    /// # Safety
    ///
    /// `revoked_dir` is NULL or a C string, and `fingerprint` 32 bytes.
    pub unsafe extern "C" fn keys_is_revoked(
        revoked_dir: *const c_char,
        fingerprint: *const [u8; 32],
    ) -> bool {
        // SAFETY: the caller passes a C string and 32 bytes.
        unsafe { super::is_revoked(revoked_dir, &*fingerprint) }
    }

    /// # Safety
    ///
    /// `keys_dir` is a C string, `der` and `sig` hold `der_sz` and
    /// `sig_sz` bytes, and `out` has room for `cap`.
    pub unsafe extern "C" fn keys_install(
        keys_dir: *const c_char,
        der: *const u8,
        der_sz: usize,
        sig: *const u8,
        sig_sz: usize,
        out: *mut c_char,
        cap: usize,
    ) -> c_int {
        // SAFETY: the caller passes a C string, the bytes and room.
        unsafe { super::install(keys_dir, der, der_sz, sig, sig_sz, out.cast(), cap) }
    }
}

#[cfg(test)]
mod tests;
