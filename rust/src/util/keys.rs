// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The certificates a target trusts, behind `util/keys.h`: the primary
//! one, and each certificate under trusted/ that a member vouched for,
//! less those revoked, read from a directory or through a config image's
//! descriptor.

use core::cell::UnsafeCell;
use core::ffi::{CStr, c_char, c_int};
use core::ptr;

use crate::errno::{E2BIG, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOENT, ENOKEY, ENOMEM, EPERM};
use crate::ffi;
use crate::sys::hex::hex_encode;
use crate::sys::libc::{
    AT_EMPTY_PATH, Dirent, F_OK, O_CLOEXEC, O_DIRECTORY, O_RDONLY, PATH_MAX, S_IFMT, S_IFREG,
    STATX_SIZE, STATX_TYPE, Statx, access, alphasort, close, errno, faccessat, open, read, scandir,
    scandirat, statx, strerror, unlink,
};
use crate::sys::log::pr_err;
use crate::sys::malloc::{libc_free, xcalloc, xfree, xmalloc};
use crate::sys::string::name_has_suffix;
use crate::text::{cstr, strscpy, strsprintf};
use crate::util::crypto_openssl::{
    Cert, cert_free, cert_pubkey_digest, cert_read_der, sha256_buffer, verify_detached,
};
use crate::util::image_config;
use crate::util::io::{check_trusted, open_beneath, read_fd};
use crate::util::seal::{seal_mkdir_p, seal_write_file};

/// `KEYS_MAX`: the most certificates a set holds.
pub(crate) const KEYS_MAX: usize = 16;
/// `KEYS_DER_MAX`: the largest certificate or vouch read.
const DER_MAX: usize = 1024 * 1024;
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
struct DerEntry {
    sha256: [u8; 32],
    der: *mut u8,
    len: usize,
}

/// The DER of every certificate a set took. Whoever needs the bytes
/// later, to enrol, to look in the keyring or to check a vouch, takes
/// them from here: a path reopened then may name other bytes, and a
/// member read from a config image has no path at all.
struct DerStore {
    entries: UnsafeCell<[DerEntry; 8 * KEYS_MAX]>,
    stored: UnsafeCell<usize>,
}

// SAFETY: the loads run on the main thread, as the C's statics did.
unsafe impl Sync for DerStore {}

static DER_STORE: DerStore = DerStore {
    entries: UnsafeCell::new(
        [const {
            DerEntry {
                sha256: [0; 32],
                der: ptr::null_mut(),
                len: 0,
            }
        }; 8 * KEYS_MAX],
    ),
    stored: UnsafeCell::new(0),
};

/// The certificates kept so far.
fn kept() -> &'static [DerEntry] {
    // SAFETY: the store, which only der_keep() changes, on this thread.
    unsafe {
        let entries: &[DerEntry; 8 * KEYS_MAX] = &*DER_STORE.entries.get();

        &entries[..*DER_STORE.stored.get()]
    }
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
    // SAFETY: the caller's fd and C string, and flags.
    let fd = unsafe { open_beneath(dirfd, name, O_RDONLY) };

    if fd < 0 {
        return fd;
    }
    // SAFETY: the fd opened above, read and closed once.
    unsafe {
        let ret = read_der_fd(fd, out, out_sz);

        close(fd);
        ret
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
        let ret = if st.mode & S_IFMT != S_IFREG || st.size == 0 || st.size > DER_MAX as u64 {
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
    let size = st.size as usize;
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

/// The SHA-256 of a certificate's DER and of its public key: 0, or what
/// reading or hashing it failed with.
///
/// # Safety
///
/// `der` holds `der_sz` bytes, and `sha256` and `fingerprint` are room
/// for 32 bytes each.
unsafe fn digest_der(
    der: *const u8,
    der_sz: usize,
    sha256: *mut u8,
    fingerprint: *mut u8,
) -> c_int {
    // SAFETY: the caller's bytes and room.
    let ret = unsafe { sha256_buffer(der.cast(), der_sz, sha256) };

    if ret != 0 {
        return ret;
    }
    let mut cert = Cert::new();
    // SAFETY: the caller's bytes, into the certificate here.
    let ret = unsafe { cert_read_der(der, der_sz, &mut cert) };

    if ret != 0 {
        return ret;
    }
    // SAFETY: the certificate, and the caller's room; then the
    // certificate freed once.
    unsafe {
        let ret = cert_pubkey_digest(&cert, fingerprint);

        cert_free(&mut cert);
        ret
    }
}

/// A copy of the certificate with digest `sha256` kept for the set, once:
/// 0, -E2BIG with the store full, or -ENOMEM.
fn der_keep(sha256: &[u8; 32], der: &[u8]) -> c_int {
    if kept().iter().any(|e| e.sha256 == *sha256) {
        return 0;
    }
    // SAFETY: the store, which only this changes, on this thread.
    let (entries, stored) =
        unsafe { (&mut *DER_STORE.entries.get(), &mut *DER_STORE.stored.get()) };

    if *stored >= entries.len() {
        return -E2BIG;
    }
    let e = &mut entries[*stored];
    // SAFETY: a size.
    let copy = unsafe { xmalloc(der.len()) }.cast::<u8>();

    if copy.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the allocation of der.len() bytes.
    unsafe { ptr::copy_nonoverlapping(der.as_ptr(), copy, der.len()) };
    e.der = copy;
    e.sha256 = *sha256;
    e.len = der.len();
    *stored += 1;
    0
}

/// The kept bytes of the certificate `c`: 0, or -ENOKEY for one no set
/// took.
pub(crate) fn cert_der(c: &TrustedCert) -> Result<&'static [u8], c_int> {
    kept()
        .iter()
        .find(|e| e.sha256 == c.sha256)
        // SAFETY: the bytes the store keeps for the process.
        .map(|e| unsafe { core::slice::from_raw_parts(e.der, e.len) })
        .ok_or(-ENOKEY)
}

/// The certificate `c` read from its kept bytes: 0 or -errno.
///
/// # Safety
///
/// `cert` is room for a certificate.
pub(crate) unsafe fn cert_read(c: &TrustedCert, cert: *mut Cert) -> c_int {
    match cert_der(c) {
        // SAFETY: the kept bytes, into the caller's certificate.
        Ok(der) => unsafe { cert_read_der(der.as_ptr(), der.len(), cert) },
        Err(e) => e,
    }
}

/// The certificate at `path`, its digests, and its bytes kept for the
/// set.
///
/// # Safety
///
/// `path` is a C string, and `sha256` and `fingerprint` room for 32
/// bytes each.
unsafe fn take_file(
    path: *const c_char,
    sha256: &mut [u8; 32],
    fingerprint: &mut [u8; 32],
) -> c_int {
    let mut der: *mut u8 = ptr::null_mut();
    let mut der_sz = 0usize;
    // SAFETY: the caller's C string.
    let mut ret = unsafe { read_der(path, &mut der, &mut der_sz) };

    if ret != 0 {
        return ret;
    }
    // SAFETY: the der_sz bytes read, and the caller's room.
    ret = unsafe { digest_der(der, der_sz, sha256.as_mut_ptr(), fingerprint.as_mut_ptr()) };
    if ret == 0 {
        // SAFETY: the der_sz bytes read.
        ret = der_keep(sha256, unsafe { ffi::slice(der, der_sz) });
    }
    // SAFETY: read_der()'s allocation of der_sz bytes, freed once.
    unsafe { xfree(der.cast(), der_sz) };
    ret
}

/// The digests of the certificate at `path`, kept nowhere.
///
/// # Safety
///
/// `path` is a C string, and `sha256` and `fingerprint` room for 32
/// bytes each.
unsafe fn digest_file(path: *const c_char, sha256: *mut u8, fingerprint: *mut u8) -> c_int {
    let mut der: *mut u8 = ptr::null_mut();
    let mut der_sz = 0usize;
    // SAFETY: the caller's C string.
    let ret = unsafe { read_der(path, &mut der, &mut der_sz) };

    if ret != 0 {
        return ret;
    }
    // SAFETY: the der_sz bytes read, the caller's room, and then the
    // allocation, freed once.
    unsafe {
        let ret = digest_der(der, der_sz, sha256, fingerprint);

        xfree(der.cast(), der_sz);
        ret
    }
}

/// The hex digits of a fingerprint.
fn fingerprint_hex(fingerprint: &[u8; 32]) -> [u8; 65] {
    let mut hex = [0u8; 65];

    // SAFETY: 32 bytes, and room for their hex digits and a NUL.
    unsafe { hex_encode(fingerprint.as_ptr(), 32, hex.as_mut_ptr().cast()) };
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

/// The payload a vouch for a certificate signs: KEYS_VOUCH_PREFIX, its
/// NUL, and the certificate's DER, in an allocation xfree() takes.
///
/// # Safety
///
/// `der` holds `der_sz` bytes.
unsafe fn vouch_payload(
    der: *const u8,
    der_sz: usize,
    out: &mut *mut u8,
    out_sz: &mut usize,
) -> c_int {
    // size_add(): saturated, for xmalloc() to refuse.
    let n = VOUCH_PREFIX.len().saturating_add(der_sz);
    // SAFETY: a size.
    let buf = unsafe { xmalloc(n) }.cast::<u8>();

    if buf.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the n bytes allocated, the prefix and then the caller's
    // der_sz bytes.
    unsafe {
        ptr::copy_nonoverlapping(VOUCH_PREFIX.as_ptr(), buf, VOUCH_PREFIX.len());
        ptr::copy_nonoverlapping(der, buf.add(VOUCH_PREFIX.len()), der_sz);
    }
    *out = buf;
    *out_sz = n;
    0
}

/// Whether a member of the set signed the vouch `sig` for the certificate
/// `der`: 0 with the member's fingerprint in `voucher`, -EKEYREJECTED for
/// none, or -errno.
///
/// # Safety
///
/// `der` and `sig` hold `der_sz` and `sig_sz` bytes, and `voucher` is
/// room for 32.
unsafe fn verify_vouch(
    set: &TrustedSet,
    der: *const u8,
    der_sz: usize,
    sig: *const u8,
    sig_sz: usize,
    voucher: *mut u8,
) -> c_int {
    let mut payload: *mut u8 = ptr::null_mut();
    let mut payload_sz = 0usize;
    // SAFETY: the caller's bytes.
    let ret = unsafe { vouch_payload(der, der_sz, &mut payload, &mut payload_sz) };

    if ret != 0 {
        return ret;
    }
    let mut ret = -EKEYREJECTED;

    for c in &set.certs[..set.n.min(KEYS_MAX)] {
        if ret == 0 {
            break;
        }
        let mut cert = Cert::new();

        // SAFETY: room for a certificate.
        if unsafe { cert_read(c, &mut cert) } != 0 {
            continue;
        }
        // SAFETY: the payload, the caller's signature and room, and the
        // certificate, freed once.
        unsafe {
            if verify_detached(payload, payload_sz, sig, sig_sz, &cert) == 0 {
                ptr::copy_nonoverlapping(c.fingerprint.as_ptr(), voucher, 32);
                ret = 0;
            }
            cert_free(&mut cert);
        }
    }
    // SAFETY: the payload's allocation, freed once.
    unsafe { xfree(payload.cast(), payload_sz) };
    ret
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
        // SAFETY: the C string just copied and rooms for its digests.
        let ret = unsafe {
            capi::keys_digest_file(
                c.path.as_ptr().cast(),
                c.sha256.as_mut_ptr(),
                c.fingerprint.as_mut_ptr(),
            )
        };
        if ret != 0 { Err(ret) } else { Ok(c) }
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
}

pub(crate) use capi::{
    keys_cert_der, keys_digest_der, keys_install, keys_is_revoked, keys_load, keys_load_image_root,
    keys_read_der, keys_read_der_fd, keys_set_digest, keys_verify_vouch, keys_vouch_payload,
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
    if let Some(der) = der {
        let ret = der_keep(sha256, der);

        if ret != 0 {
            return ret;
        }
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
    let mut names: *mut *mut Dirent = ptr::null_mut();
    // SAFETY: the caller's C string, room for the names, and a filter.
    let n = unsafe { scandir(dir, &mut names, Some(select_der), None) };

    if n < 0 {
        return 0;
    }
    // SAFETY: the names scandir() gave.
    unsafe { names_free(names, n) };
    n as usize
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
            let mut voucher = [0u8; 32];

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
            // SAFETY: the candidate's DER, the vouch read, and room for the
            // voucher; then the vouch's allocation, freed as the C freed
            // it.
            let ret = unsafe {
                let ret = verify_vouch(set, c.der, c.der_sz, sig, sig_sz, voucher.as_mut_ptr());

                xfree(sig.cast(), sig_sz);
                ret
            };
            if ret != 0 {
                continue;
            }
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
    let mut names: *mut *mut Dirent = ptr::null_mut();
    let mut ret = 0;

    if strsprintf(&mut dir, &[keys_dir, b"/trusted"]).is_err() {
        return -ENAMETOOLONG;
    }
    // SAFETY: the path, room for the names, a filter and a sort.
    let n = unsafe {
        scandir(
            dir.as_ptr().cast(),
            &mut names,
            Some(select_der),
            Some(alphasort),
        )
    };

    if n < 0 {
        let err = errno();

        return if err == ENOENT { 0 } else { -err };
    }
    for i in 0..n as usize {
        if ret != 0 {
            break;
        }
        // SAFETY: an entry scandir() gave, its name a C string.
        let name = unsafe { ffi::c_str((**names.add(i)).d_name.as_ptr().cast()) };
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
        // SAFETY: the DER read, and the candidate's room for its digests.
        ret = unsafe {
            digest_der(
                c.der,
                c.der_sz,
                c.sha256.as_mut_ptr(),
                c.fingerprint.as_mut_ptr(),
            )
        };
        if ret != 0 {
            // SAFETY: read_der()'s allocation, freed once.
            unsafe { xfree(c.der.cast(), c.der_sz) };
            c.der = ptr::null_mut();
            break;
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
    // SAFETY: the names scandir() gave.
    unsafe { names_free(names, n) };
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

    // SAFETY: the caller's fd, a C string, and flags.
    *trusted_fd = unsafe { open_beneath(keys_fd, c"trusted".as_ptr(), O_RDONLY | O_DIRECTORY) };
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
        // SAFETY: the DER read, and the candidate's room for its digests.
        ret = unsafe {
            digest_der(
                c.der,
                c.der_sz,
                c.sha256.as_mut_ptr(),
                c.fingerprint.as_mut_ptr(),
            )
        };
        if ret != 0 {
            // SAFETY: read_fd()'s allocation, freed as the C freed it.
            unsafe { xfree(c.der.cast(), c.der_sz) };
            c.der = ptr::null_mut();
            break;
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
    let mut sha256 = [0u8; 32];
    let mut fingerprint = [0u8; 32];
    let revoked_dir = if revoked_dir.is_null() {
        if strsprintf(&mut revoked, &[keys_dir, b"/revoked"]).is_err() {
            return -ENAMETOOLONG;
        }
        revoked.as_ptr().cast()
    } else {
        revoked_dir
    };
    // SAFETY: the caller's C string.
    let ret = unsafe { take_file(primary, &mut sha256, &mut fingerprint) };

    if ret != 0 {
        return ret;
    }
    // SAFETY: a C string either way.
    if !unsafe { is_revoked(revoked_dir, &fingerprint) } {
        // SAFETY: the caller's C string.
        let ret = set_add(
            set,
            unsafe { ffi::c_str(primary) },
            &sha256,
            &fingerprint,
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
    let mut sha256 = [0u8; 32];
    let mut fingerprint = [0u8; 32];
    let mut trusted_fd = -1;
    // SAFETY: the caller's C string.
    let ret = unsafe { take_file(primary, &mut sha256, &mut fingerprint) };

    if ret != 0 {
        return ret;
    }
    // SAFETY: the caller's C string.
    let ret = set_add(
        set,
        unsafe { ffi::c_str(primary) },
        &sha256,
        &fingerprint,
        None,
        None,
    );

    if ret != 0 {
        return ret;
    }
    if keys_fd == -ENOENT {
        return 0;
    }
    // SAFETY: the caller's fd, a C string, and flags.
    let revoked_fd = unsafe { open_beneath(keys_fd, c"revoked".as_ptr(), O_RDONLY | O_DIRECTORY) };

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
    // SAFETY: the caller's fd, a C string, and flags.
    let keys_fd = unsafe { open_beneath(root_fd, c"keys".as_ptr(), O_RDONLY | O_DIRECTORY) };

    if keys_fd < 0 && keys_fd != -ENOENT {
        // SAFETY: the C's format, and the C library's message.
        unsafe {
            pr_err(
                c"image trust set: open config image keys/: %s".as_ptr(),
                strerror(-keys_fd),
            )
        };
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
/// them sorted. 0, -EINVAL for none or more than a set holds, or what
/// hashing failed with, `out` zeroed.
fn anchor_digest(sha256: &[[u8; 32]], out: &mut [u8; 32]) -> c_int {
    if sha256.len() == 1 {
        *out = sha256[0];
        return 0;
    }
    *out = [0; 32];
    if sha256.is_empty() || sha256.len() > KEYS_MAX {
        return -EINVAL;
    }
    let mut sorted = [[0u8; 32]; KEYS_MAX];
    let sorted = &mut sorted[..sha256.len()];

    sorted.copy_from_slice(sha256);
    sorted.sort_unstable();
    // SAFETY: the sorted digests, and room for 32 bytes.
    let ret = unsafe { sha256_buffer(sorted.as_ptr().cast(), sorted.len() * 32, out.as_mut_ptr()) };

    if ret != 0 {
        *out = [0; 32];
    }
    ret
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
    let mut sha256 = [0u8; 32];
    let mut fingerprint = [0u8; 32];
    let mut vouch = [0u8; PATH_MAX];
    let mut dir = [0u8; PATH_MAX];
    // SAFETY: the caller's bytes, and room for the digests.
    let ret = unsafe { digest_der(der, der_sz, sha256.as_mut_ptr(), fingerprint.as_mut_ptr()) };

    if ret != 0 {
        return ret;
    }
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

pub(crate) use capi::keys_anchor_digest;

mod capi {
    use core::ffi::{c_char, c_int};

    use super::{TrustedCert, TrustedSet};
    use crate::ffi;
    use crate::util::crypto_openssl::Cert;

    /// # Safety
    ///
    /// `keys_dir` is a C string, `revoked_dir` NULL or one, and `set`
    /// room for a set.
    #[unsafe(no_mangle)]
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
    #[unsafe(no_mangle)]
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
    #[unsafe(no_mangle)]
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
    /// `set` is a trust set and `fingerprint` holds 32 bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_member(
        set: *const TrustedSet,
        fingerprint: *const [u8; 32],
    ) -> *const TrustedCert {
        // SAFETY: the caller passes the set and fingerprint.
        let (set, fingerprint) = unsafe { (&*set, &*fingerprint) };
        for cert in &set.certs[..set.n.min(super::KEYS_MAX)] {
            if cert.fingerprint == *fingerprint {
                return cert;
            }
        }
        core::ptr::null()
    }

    /// # Safety
    ///
    /// `set` is a trust set, payload and sig hold their lengths of bytes,
    /// and `signer` is NULL or room for 32 bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_verify_signature(
        set: *const TrustedSet,
        payload: *const u8,
        payload_sz: usize,
        sig: *const u8,
        sig_sz: usize,
        signer: *mut u8,
    ) -> c_int {
        // SAFETY: the caller passes a trust set.
        let set = unsafe { &*set };
        for member in &set.certs[..set.n.min(super::KEYS_MAX)] {
            let mut cert = Cert::new();
            // SAFETY: this member is in the set and cert has room.
            let ret = unsafe { super::cert_read(member, &mut cert) };
            if ret != 0 {
                return ret;
            }
            // SAFETY: the caller passes the payload and signature, and
            // the certificate was read above and is released once.
            let ret = unsafe {
                let ret = super::verify_detached(payload, payload_sz, sig, sig_sz, &cert);
                super::cert_free(&mut cert);
                ret
            };
            if ret == 0 {
                if !signer.is_null() {
                    // SAFETY: the caller gave room for a fingerprint.
                    unsafe {
                        core::ptr::copy_nonoverlapping(member.fingerprint.as_ptr(), signer, 32)
                    };
                }
                return 0;
            }
        }
        -crate::errno::EKEYREJECTED
    }

    /// # Safety
    ///
    /// `c` is a certificate of a set, and `der` and `len` room for the
    /// kept bytes and their length.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_cert_der(
        c: *const TrustedCert,
        der: *mut *const u8,
        len: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes a certificate.
        match super::cert_der(unsafe { &*c }) {
            Ok(bytes) => {
                // SAFETY: the caller's room.
                unsafe {
                    *der = bytes.as_ptr();
                    *len = bytes.len();
                }
                0
            }
            Err(e) => e,
        }
    }

    /// # Safety
    ///
    /// `c` is a certificate of a set, and `cert` room for a certificate.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_cert_read(c: *const TrustedCert, cert: *mut Cert) -> c_int {
        // SAFETY: the caller passes a certificate and room.
        unsafe { super::cert_read(&*c, cert) }
    }

    /// # Safety
    ///
    /// `path` is a C string, and `out` and `out_sz` room for the bytes
    /// and their length.
    #[unsafe(no_mangle)]
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
    #[unsafe(no_mangle)]
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
    /// `der` holds `der_sz` bytes, and `sha256` and `fingerprint` are room
    /// for 32 bytes each.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_digest_der(
        der: *const u8,
        der_sz: usize,
        sha256: *mut u8,
        fingerprint: *mut u8,
    ) -> c_int {
        // SAFETY: the caller passes the bytes and room.
        unsafe { super::digest_der(der, der_sz, sha256, fingerprint) }
    }

    /// # Safety
    ///
    /// `path` is a C string, and `sha256` and `fingerprint` room for 32
    /// bytes each.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_digest_file(
        path: *const c_char,
        sha256: *mut u8,
        fingerprint: *mut u8,
    ) -> c_int {
        // SAFETY: the caller passes a C string and room.
        unsafe { super::digest_file(path, sha256, fingerprint) }
    }

    /// # Safety
    ///
    /// `sha256` holds `n` digests, and `out` is room for 32 bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_anchor_digest(
        sha256: *const [u8; 32],
        n: usize,
        out: *mut [u8; 32],
    ) -> c_int {
        if n == 1 {
            // SAFETY: the caller's one digest and room.
            unsafe { *out = *sha256 };
            return 0;
        }
        // SAFETY: the caller's room; a count past what a set holds is
        // refused before its digests are read.
        let out = unsafe { &mut *out };

        if n > super::KEYS_MAX {
            *out = [0; 32];
            return -crate::errno::EINVAL;
        }
        // SAFETY: the caller's n digests.
        super::anchor_digest(unsafe { ffi::slice(sha256, n) }, out)
    }

    /// # Safety
    ///
    /// `set` is a set, and `out` room for 32 bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_set_digest(set: *const TrustedSet, out: *mut [u8; 32]) -> c_int {
        // SAFETY: the caller passes a set and room.
        let (set, out) = unsafe { (&*set, &mut *out) };
        let mut sha = [[0u8; 32]; super::KEYS_MAX];
        let n = set.n.min(super::KEYS_MAX);

        for (d, c) in sha.iter_mut().zip(&set.certs[..n]) {
            *d = c.sha256;
        }
        if set.n > super::KEYS_MAX {
            *out = [0; 32];
            return -crate::errno::EINVAL;
        }
        super::anchor_digest(&sha[..n], out)
    }

    /// # Safety
    ///
    /// `revoked_dir` is NULL or a C string, and `fingerprint` 32 bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_is_revoked(
        revoked_dir: *const c_char,
        fingerprint: *const [u8; 32],
    ) -> bool {
        // SAFETY: the caller passes a C string and 32 bytes.
        unsafe { super::is_revoked(revoked_dir, &*fingerprint) }
    }

    /// # Safety
    ///
    /// `der` holds `der_sz` bytes, and `out` and `out_sz` are room for
    /// the payload and its length.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_vouch_payload(
        der: *const u8,
        der_sz: usize,
        out: *mut *mut u8,
        out_sz: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes the bytes and room.
        unsafe { super::vouch_payload(der, der_sz, &mut *out, &mut *out_sz) }
    }

    /// # Safety
    ///
    /// `set` is a set, `der` and `sig` hold `der_sz` and `sig_sz` bytes,
    /// and `voucher` is room for 32.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keys_verify_vouch(
        set: *const TrustedSet,
        der: *const u8,
        der_sz: usize,
        sig: *const u8,
        sig_sz: usize,
        voucher: *mut u8,
    ) -> c_int {
        // SAFETY: the caller passes a set, the bytes and room.
        unsafe { super::verify_vouch(&*set, der, der_sz, sig, sig_sz, voucher) }
    }

    /// # Safety
    ///
    /// `keys_dir` is a C string, `der` and `sig` hold `der_sz` and
    /// `sig_sz` bytes, and `out` has room for `cap`.
    #[unsafe(no_mangle)]
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
