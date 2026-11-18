// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The certificates a target trusts: the primary
//! one, and each certificate under trusted/ that a member vouched for,
//! less those revoked, read from a directory or through a config image's
//! descriptor.

use core::ffi::{CStr, c_int};
use std::ffi::CString;
use std::fs::File;
use std::io::Read;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use openssl::x509::X509;

use crate::errno::{
    E2BIG, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT, ENOKEY, ENOMEM, EPERM, text,
};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    F_OK, O_CLOEXEC, O_DIRECTORY, O_RDONLY, PATH_MAX, S_IFMT, S_IFREG, Statx, access, errno,
    faccessat, open,
};
use crate::text::name_has_suffix;
use crate::util::crypto_openssl::{self, pubkey_digest, verify_detached_x509, x509_from_der};
use crate::util::hex::encode;
use crate::util::image_config;
use crate::util::io::{check_trusted, dir_names, dir_names_at, open_beneath, read_whole, stat_fd};
use crate::util::seal;

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
/// A config image's keys directory, under its root, and the name its
/// members' paths give it.
const IMAGE_KEYS_DIR: &CStr = c"keys";

/// A certificate of a set: the primary, or a member another vouched
/// for.
pub(crate) struct TrustedCert {
    /// The path it was read from, or a config image's member's under
    /// keys/.
    path: Vec<u8>,
    digests: CertDigests,
    /// The fingerprint of the member that vouched for it, None for the
    /// primary.
    voucher: Option<[u8; 32]>,
}

/// The certificates a target trusts, at most KEYS_MAX of them, and how
/// many a load counted revoked and unvouched.
#[derive(Default)]
pub(crate) struct TrustedSet {
    certs: Vec<TrustedCert>,
    n_revoked: usize,
    n_unvouched: usize,
}

/// A certificate under trusted/ waiting for a vouch.
struct Candidate {
    /// The path the set records it by.
    path: Vec<u8>,
    /// Its name in the trusted directory.
    name: Vec<u8>,
    der: Vec<u8>,
    digests: CertDigests,
    done: bool,
}

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

/// The certificate open at `fd`, whole: -EINVAL for an empty one, or
/// what read_whole() refused it with.
pub(crate) fn read_der_fd(fd: c_int) -> Result<Vec<u8>, c_int> {
    let der = read_whole(fd, c"certificate", DER_MAX)?;

    if der.is_empty() {
        return Err(-EINVAL);
    }
    Ok(der)
}

/// [`read_der_fd`] of `name` beneath the directory open as `dir`.
fn read_der_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<Vec<u8>, c_int> {
    read_der_fd(open_beneath(dir.as_raw_fd(), name, O_RDONLY)?.as_raw_fd())
}

/// The certificate at `path`, a regular file of 1 to KEYS_DER_MAX bytes
/// that check_trusted() lets steer trust: -EINVAL for another file,
/// -EPERM for one check_trusted() refuses, -EIO for a short read, or
/// -errno.
pub(crate) fn read_der(path: &CStr) -> Result<Vec<u8>, c_int> {
    // SAFETY: a C string, and flags.
    let fd = unsafe { open(path.as_ptr(), O_RDONLY | O_CLOEXEC) };

    if fd < 0 {
        return Err(-errno());
    }
    // SAFETY: the fd open() just gave, owned from here.
    let file = File::from(unsafe { OwnedFd::from_raw_fd(fd) });
    let size = der_size(&file)?;
    // SAFETY: the file's fd, and a C string.
    if unsafe { check_trusted(file.as_raw_fd(), path.as_ptr(), false) } != 0 {
        return Err(-EPERM);
    }
    let mut der = room_for(size)?;

    der.resize(size, 0);
    match (&file).read(&mut der) {
        Ok(n) if n == size => Ok(der),
        _ => Err(-EIO),
    }
}

/// The size of `file`, a regular file of 1 to KEYS_DER_MAX bytes:
/// -EINVAL for another, or what statx() failed with.
fn der_size(file: &File) -> Result<usize, c_int> {
    let mut st = Statx::zeroed();
    let ret = stat_fd(file.as_raw_fd(), &mut st);

    if ret != 0 {
        return Err(ret);
    }
    if st.stx_mode & S_IFMT != S_IFREG {
        return Err(-EINVAL);
    }
    usize::try_from(st.stx_size)
        .ok()
        .filter(|size| (1..=DER_MAX).contains(size))
        .ok_or(-EINVAL)
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
        .find(|k| k.sha256 == c.digests.sha256)
        .map(|k| k.der)
        .ok_or(-ENOKEY)
}

/// The certificate `c`, read from its kept bytes: -ENOKEY for one no
/// set took, or -EINVAL.
pub(crate) fn cert_x509(c: &TrustedCert) -> Result<X509, c_int> {
    x509_from_der(cert_der(c)?)
}

/// The digests of the certificate at `path`, its bytes kept for the
/// set.
fn take_file(path: &CStr) -> Result<CertDigests, c_int> {
    let der = read_der(path)?;
    let digests = digest_der(&der)?;

    der_keep(&digests.sha256, &der)?;
    Ok(digests)
}

/// `parts` one after another, a path: -ENAMETOOLONG for one of PATH_MAX
/// bytes or more.
fn path_of(parts: &[&[u8]]) -> Result<CString, c_int> {
    let path = parts.concat();

    if path.len() >= PATH_MAX {
        return Err(-ENAMETOOLONG);
    }
    CString::new(path).map_err(|_| -EINVAL)
}

/// `<dir>/<fingerprint hex><suffix>`, the name of a certificate in a set.
fn path_for(dir: &[u8], fingerprint: &[u8; 32], suffix: &[u8]) -> Result<CString, c_int> {
    path_of(&[dir, b"/", &encode(fingerprint), suffix])
}

/// Whether the directory `revoked_dir` holds the certificate of
/// `fingerprint`.
pub(crate) fn is_revoked(revoked_dir: &CStr, fingerprint: &[u8; 32]) -> bool {
    let Ok(path) = path_for(revoked_dir.to_bytes(), fingerprint, b".der") else {
        return false;
    };

    // SAFETY: a C string and a mode.
    unsafe { access(path.as_ptr(), F_OK) == 0 }
}

/// Whether the revoked directory open as `revoked` holds the certificate
/// of `fingerprint`.
fn is_revoked_at(revoked: Option<BorrowedFd<'_>>, fingerprint: &[u8; 32]) -> bool {
    let Some(dir) = revoked else {
        return false;
    };
    let Ok(name) = CString::new([&encode(fingerprint)[..], b".der"].concat()) else {
        return false;
    };

    // SAFETY: the directory's fd, a C string, a mode and no flags.
    unsafe { faccessat(dir.as_raw_fd(), name.as_ptr(), F_OK, 0) == 0 }
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
            return Ok(c.digests.fingerprint);
        }
    }
    Err(-EKEYREJECTED)
}

impl TrustedCert {
    pub(crate) fn sha256(&self) -> &[u8; 32] {
        &self.digests.sha256
    }

    pub(crate) fn fingerprint(&self) -> &[u8; 32] {
        &self.digests.fingerprint
    }

    pub(crate) fn voucher(&self) -> Option<&[u8; 32]> {
        self.voucher.as_ref()
    }

    pub(crate) fn primary(&self) -> bool {
        self.voucher.is_none()
    }

    /// The certificate at `path`, by its digests, as a set's primary.
    pub(crate) fn primary_at(path: &CStr) -> Result<Self, c_int> {
        if path.count_bytes() >= PATH_MAX {
            return Err(-ENAMETOOLONG);
        }
        Ok(TrustedCert {
            path: path.to_bytes().to_vec(),
            digests: digest_der(&read_der(path)?)?,
            voucher: None,
        })
    }
}

impl TrustedSet {
    /// `c` added: -E2BIG when the set holds KEYS_MAX already.
    pub(crate) fn push(&mut self, c: TrustedCert) -> Result<(), c_int> {
        if self.certs.len() >= KEYS_MAX {
            return Err(-E2BIG);
        }
        self.certs.push(c);
        Ok(())
    }

    /// How many certificates the set holds.
    pub(crate) fn len(&self) -> usize {
        self.certs.len()
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
        let sha256: Vec<[u8; 32]> = self.certs.iter().map(|c| c.digests.sha256).collect();

        anchor_digest(&sha256)
    }

    /// Whether the set holds the certificate of `fingerprint`.
    fn holds(&self, fingerprint: &[u8; 32]) -> bool {
        self.certs
            .iter()
            .any(|c| c.digests.fingerprint == *fingerprint)
    }

    /// A certificate added, its bytes kept when given; a voucher makes it
    /// a member, none the primary. -E2BIG, -ENAMETOOLONG, or what keeping
    /// its bytes failed with.
    fn add(
        &mut self,
        path: &[u8],
        digests: &CertDigests,
        voucher: Option<&[u8; 32]>,
        der: Option<&[u8]>,
    ) -> Result<(), c_int> {
        if self.certs.len() >= KEYS_MAX {
            return Err(-E2BIG);
        }
        if let Some(der) = der {
            der_keep(&digests.sha256, der)?;
        }
        if path.len() >= PATH_MAX {
            return Err(-ENAMETOOLONG);
        }
        self.certs.push(TrustedCert {
            path: path.to_vec(),
            digests: *digests,
            voucher: voucher.copied(),
        });
        Ok(())
    }

    /// The members sorted by the SHA-256 of each one's DER, which no two
    /// share.
    fn sort(&mut self) {
        self.certs.sort_unstable_by_key(|c| c.digests.sha256);
    }
}

/// The members of a set.
pub(crate) fn members(set: &TrustedSet) -> &[TrustedCert] {
    &set.certs
}

/// The path a member was read from.
pub(crate) fn cert_path(c: &TrustedCert) -> &[u8] {
    &c.path
}

/// Whether a directory entry's name is a certificate's: a stem and .der.
fn is_der_name(name: &[u8]) -> bool {
    name_has_suffix(name, b".der")
}

/// How many certificates the directory at `dir` holds.
fn count_der(dir: &CStr) -> usize {
    dir_names(dir.to_bytes(), is_der_name).map_or(0, |n| n.len())
}

/// How many certificates the directory open as `dir` holds.
fn count_der_at(dir: Option<BorrowedFd<'_>>) -> usize {
    dir.map_or(0, |dir| {
        dir_names_at(dir, is_der_name).map_or(0, |n| n.len())
    })
}

/// The vouch beside the certificate at `der_path`, its .der a .vouch. A
/// name shorter than .der, which the scan never selects, is kept whole,
/// as the C's `%.*s` of a negative length did.
fn vouch_path_for(der_path: &[u8]) -> Result<CString, c_int> {
    let stem = der_path
        .len()
        .checked_sub(4)
        .and_then(|n| der_path.get(..n))
        .unwrap_or(der_path);

    path_of(&[stem, b".vouch"])
}

/// The vouch of `c`: beside its path, or beside its name in the trusted
/// directory open as `trusted`.
fn read_vouch(c: &Candidate, trusted: Option<BorrowedFd<'_>>) -> Result<Vec<u8>, c_int> {
    match trusted {
        Some(dir) => read_der_at(dir, &vouch_path_for(&c.name)?),
        None => read_der(&vouch_path_for(&c.path)?),
    }
}

/// The candidates whose vouch verifies under a member admitted, in
/// rounds, so a certificate vouched for by one admitted later still
/// joins; the rest counted unvouched. What adding one failed with.
fn admit_vouched(
    set: &mut TrustedSet,
    cands: &mut [Candidate],
    trusted: Option<BorrowedFd<'_>>,
) -> Result<(), c_int> {
    let mut progress = true;

    while progress {
        progress = false;
        for c in cands.iter_mut().filter(|c| !c.done) {
            if set.holds(&c.digests.fingerprint) {
                c.done = true;
                continue;
            }
            let Ok(sig) = read_vouch(c, trusted) else {
                continue;
            };
            let Ok(voucher) = verify_vouch(set, &c.der, &sig) else {
                continue;
            };
            set.add(&c.path, &c.digests, Some(&voucher), Some(&c.der))?;
            c.done = true;
            progress = true;
        }
    }
    set.n_unvouched += cands.iter().filter(|c| !c.done).count();
    Ok(())
}

/// Room for the SCAN_MAX candidates a scan takes, or -ENOMEM.
fn candidates() -> Result<Vec<Candidate>, c_int> {
    let mut cands = Vec::new();

    cands.try_reserve_exact(SCAN_MAX).map_err(|_| -ENOMEM)?;
    Ok(cands)
}

/// Every .der under `<keys_dir>/trusted` read: the ones `revoked_dir`
/// does not hold become candidates for admission, which needs the whole
/// list first. -E2BIG for more than SCAN_MAX, or what reading one
/// failed with.
fn scan_trusted(keys_dir: &[u8], revoked_dir: &CStr) -> Result<Vec<Candidate>, c_int> {
    let mut cands = candidates()?;
    let dir = path_of(&[keys_dir, b"/trusted"])?;
    let names = match dir_names(dir.to_bytes(), is_der_name) {
        Err(err) if err == -ENOENT => return Ok(cands),
        names => names?,
    };

    for name in names {
        if cands.len() >= SCAN_MAX {
            return Err(-E2BIG);
        }
        let path = path_of(&[dir.to_bytes(), b"/", &name])?;
        let der = read_der(&path)?;
        let digests = digest_der(&der)?;

        if !is_revoked(revoked_dir, &digests.fingerprint) {
            cands.push(Candidate {
                path: path.into_bytes(),
                name,
                der,
                digests,
                done: false,
            });
        }
    }
    Ok(cands)
}

/// The same scan through the keys directory open as `keys`, the trusted
/// directory's candidates recorded under keys/trusted. That directory
/// comes back open with them, for their vouches; None without one.
fn scan_trusted_at(keys: BorrowedFd<'_>) -> Result<Option<(OwnedFd, Vec<Candidate>)>, c_int> {
    let mut cands = candidates()?;
    let trusted = match open_beneath(keys.as_raw_fd(), c"trusted", O_RDONLY | O_DIRECTORY) {
        Err(err) if err == -ENOENT => return Ok(None),
        trusted => trusted?,
    };

    for name in dir_names_at(trusted.as_fd(), is_der_name)? {
        if cands.len() >= SCAN_MAX {
            return Err(-E2BIG);
        }
        let name = CString::new(name).map_err(|_| -EINVAL)?;
        let path = path_of(&[IMAGE_KEYS_DIR.to_bytes(), b"/trusted/", name.to_bytes()])?;
        let der = read_der_at(trusted.as_fd(), &name)?;
        let digests = digest_der(&der)?;

        cands.push(Candidate {
            path: path.into_bytes(),
            name: name.into_bytes(),
            der,
            digests,
            done: false,
        });
    }
    Ok(Some((trusted, cands)))
}

/// The set of a keys directory: the primary at `primary` unless revoked,
/// with `with_trusted` the members trusted/ adds, and the count of what
/// is revoked; `<keys_dir>/revoked` without `revoked_dir`.
fn load_set(
    primary: &CStr,
    keys_dir: &[u8],
    revoked_dir: Option<&CStr>,
    with_trusted: bool,
) -> Result<TrustedSet, c_int> {
    let mut set = TrustedSet::default();
    let default_revoked;
    let revoked_dir = match revoked_dir {
        Some(dir) => dir,
        None => {
            default_revoked = path_of(&[keys_dir, b"/revoked"])?;
            default_revoked.as_c_str()
        }
    };
    let digests = take_file(primary)?;

    if !is_revoked(revoked_dir, &digests.fingerprint) {
        set.add(primary.to_bytes(), &digests, None, None)?;
    }
    set.n_revoked = count_der(revoked_dir);
    if with_trusted {
        let mut cands = scan_trusted(keys_dir, revoked_dir)?;

        admit_vouched(&mut set, &mut cands, None)?;
    }
    set.sort();
    Ok(set)
}

/// A config image's set: the primary and every vouched certificate
/// under keys/trusted, less what keys/revoked names, all read through
/// the descriptor of the image's keys directory; the primary alone
/// without one. Historical vouches count before revocation, so a
/// revoked certificate's vouch for another still admits it.
pub(crate) fn load_image_at(
    primary: &CStr,
    keys: Option<BorrowedFd<'_>>,
    with_trusted: bool,
) -> Result<TrustedSet, c_int> {
    let mut set = TrustedSet::default();
    let digests = take_file(primary)?;

    set.add(primary.to_bytes(), &digests, None, None)?;
    let Some(keys) = keys else {
        return Ok(set);
    };
    let revoked = open_beneath(keys.as_raw_fd(), c"revoked", O_RDONLY | O_DIRECTORY).ok();
    let revoked = revoked.as_ref().map(AsFd::as_fd);

    set.n_revoked = count_der_at(revoked);
    if with_trusted && let Some((trusted, mut cands)) = scan_trusted_at(keys)? {
        admit_vouched(&mut set, &mut cands, Some(trusted.as_fd()))?;
    }
    set.certs
        .retain(|c| !is_revoked_at(revoked, &c.digests.fingerprint));
    set.sort();
    Ok(set)
}

/// [`load_image_at`] of the config image whose root is open as
/// `root_fd`.
pub(crate) fn load_image_root(
    primary: &CStr,
    root_fd: c_int,
    with_trusted: bool,
) -> Result<TrustedSet, c_int> {
    let keys = match open_beneath(root_fd, IMAGE_KEYS_DIR, O_RDONLY | O_DIRECTORY) {
        Ok(keys) => Some(keys),
        Err(err) if err == -ENOENT => None,
        Err(err) => {
            crate::log::err(
                format!("image trust set: open config image keys/: {}", text(err)).as_bytes(),
            );
            return Err(err);
        }
    };

    load_image_at(primary, keys.as_ref().map(AsFd::as_fd), with_trusted)
}

/// The set of the keys directory, from the config image when the
/// directory is the target's and an image is active; its revoked/
/// without `revoked_dir`.
pub(crate) fn load(
    keys_dir: &CStr,
    revoked_dir: Option<&CStr>,
    with_trusted: bool,
) -> Result<TrustedSet, c_int> {
    let dir = keys_dir.to_bytes();
    let root_fd = image_config::root_fd();

    if root_fd >= 0 && (dir == KEYS_DIR || dir == RUNTIME_KEYS_DIR) {
        return load_image_root(RUNTIME_CERT_PATH, root_fd, with_trusted);
    }
    load_set(
        &path_of(&[dir, b"/", b"cert.der"])?,
        dir,
        revoked_dir,
        with_trusted,
    )
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

/// The certificate `der` installed under `<keys_dir>/trusted` with its
/// vouch `sig`, the vouch first, and the vouch gone again if the
/// certificate cannot be written: the certificate's path, or -errno.
pub(crate) fn install(keys_dir: &CStr, der: &[u8], sig: &[u8]) -> Result<CString, c_int> {
    let fingerprint = digest_der(der)?.fingerprint;
    let dir = path_of(&[keys_dir.to_bytes(), b"/trusted"])?;
    let ret = seal::mkdir_p(dir.to_bytes(), 0o700);

    if ret != 0 {
        return Err(ret);
    }
    let cert = path_for(dir.to_bytes(), &fingerprint, b".der")?;
    let vouch = path_for(dir.to_bytes(), &fingerprint, b".vouch")?;
    let ret = seal::write_file(vouch.to_bytes(), sig, 0o644);

    if ret != 0 {
        return Err(ret);
    }
    let ret = seal::write_file(cert.to_bytes(), der, 0o644);

    if ret != 0 {
        let _ = std::fs::remove_file(std::ffi::OsStr::from_bytes(vouch.to_bytes()));
        return Err(ret);
    }
    Ok(cert)
}

#[cfg(test)]
mod tests;
