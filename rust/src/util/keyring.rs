// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The kernel keyrings through raw add_key(2) and keyctl(2),
//! with no libkeyutils: what a keyring links and how
//! the kernel describes it, whether it holds a certificate or exactly a
//! set of them, and the bpf and dm-verity keyrings that anchor trust.

use core::ffi::{CStr, c_int, c_long};

use crate::errno::{ENOKEY, ERANGE, last_errno, text};
use crate::sys::libc::{SYS_ADD_KEY, SYS_KEYCTL, syscall};
use crate::text::cstr;
use crate::util::keys::{self, TrustedSet};

/// The longest description the kernel gives a key, its NUL included.
pub(crate) const DESC_MAX: usize = 512;
/// The longest key type a link keeps, its NUL included.
const TYPE_MAX: usize = 64;

const KEYCTL_GET_KEYRING_ID: c_long = 0;
const KEYCTL_DESCRIBE: c_long = 6;
const KEYCTL_UNLINK: c_long = 9;
const KEYCTL_READ: c_long = 11;
const KEYCTL_RESTRICT_KEYRING: c_long = 29;

const KEY_SPEC_THREAD_KEYRING: i32 = -1;
pub(crate) const KEY_SPEC_BPF_KEYRING: i32 = -9;
const KEY_SPEC_DM_VERITY_KEYRING: i32 = -10;

/// A link of a keyring: its serial, and the type and description the
/// kernel gives it, or the errno that kept it from describing the key.
pub(crate) struct KeyringLink {
    pub(crate) serial: i32,
    pub(crate) err: c_int,
    pub(crate) ty: Vec<u8>,
    pub(crate) description: Vec<u8>,
}

/// keyctl(2) with its four arguments as longs: what it returns, or -1
/// with errno set.
///
/// # Safety
///
/// The arguments are what `cmd` takes, pointers where it takes them.
unsafe fn keyctl(cmd: c_long, a: c_long, b: c_long, c: c_long, d: c_long) -> c_long {
    // SAFETY: as the caller passes them.
    unsafe { syscall(SYS_KEYCTL, cmd, a, b, c, d) }
}

/// keyctl(2) of `cmd` on two numbers: what it returns, or -errno.
fn keyctl_numbers(cmd: c_long, a: c_long, b: c_long) -> c_long {
    // SAFETY: numbers alone.
    let ret = unsafe { keyctl(cmd, a, b, 0, 0) };

    if ret < 0 {
        c_long::from(last_errno())
    } else {
        ret
    }
}

/// keyctl() of `cmd` on `spec` that returns a serial or nothing: the
/// value, or -errno.
fn keyctl_spec(cmd: c_long, spec: i32) -> c_long {
    keyctl_numbers(cmd, c_long::from(spec), 0)
}

/// A DER certificate added to the keyring `ring` as an asymmetric key
/// without a description: its serial, or -errno.
fn add_cert(ring: i32, der: &[u8]) -> i32 {
    // SAFETY: a type, no description, and the certificate's bytes.
    let ret = unsafe {
        syscall(
            SYS_ADD_KEY,
            c"asymmetric".as_ptr(),
            core::ptr::null::<u8>(),
            der.as_ptr(),
            der.len(),
            c_long::from(ring),
        )
    };

    if ret < 0 {
        last_errno()
    } else {
        i32::try_from(ret).unwrap_or(-ERANGE)
    }
}

/// How the kernel describes a key, `type;uid;gid;perm;description`, the
/// type ended in place where its `;` was.
struct Described {
    text: [u8; DESC_MAX],
    description: Option<usize>,
}

impl Described {
    /// How the kernel describes `serial`: -ERANGE when it does not fit,
    /// or -errno.
    fn of(serial: i32) -> Result<Self, c_int> {
        let mut text = [0u8; DESC_MAX];
        // SAFETY: the room of text, and its size.
        let ret = unsafe {
            keyctl(
                KEYCTL_DESCRIBE,
                c_long::from(serial),
                text.as_mut_ptr() as c_long,
                DESC_MAX as c_long,
                0,
            )
        };
        let len = usize::try_from(ret).map_err(|_| last_errno())?;
        if len > DESC_MAX {
            return Err(-ERANGE);
        }
        let description = Self::split(&mut text);
        Ok(Described { text, description })
    }

    /// Ends the type where its `;` is, and finds where the description
    /// starts: none when the text lacks four `;`.
    fn split(text: &mut [u8; DESC_MAX]) -> Option<usize> {
        let mut p = 0;

        for i in 0..4 {
            p += cstr(&text[p..]).iter().position(|&c| c == b';')?;
            if i == 0 {
                text[p] = 0;
            }
            p += 1;
        }
        Some(p)
    }

    fn ty(&self) -> &CStr {
        CStr::from_bytes_until_nul(&self.text).unwrap_or(c"")
    }

    fn description(&self) -> &CStr {
        self.description
            .and_then(|d| CStr::from_bytes_until_nul(&self.text[d..]).ok())
            .unwrap_or(c"")
    }
}

/// KEYCTL_READ of `keyring` into `serials`: the bytes of serials the
/// keyring holds, which may be more than fit, or -errno.
fn read_into(keyring: i32, serials: &mut [i32]) -> Result<usize, c_int> {
    let room = size_of_val(serials);
    // SAFETY: the room of serials, and its size in bytes.
    let ret = unsafe {
        keyctl(
            KEYCTL_READ,
            c_long::from(keyring),
            serials.as_mut_ptr() as c_long,
            room as c_long,
            0,
        )
    };
    usize::try_from(ret).map_err(|_| last_errno())
}

/// Every link of `keyring`, whatever its type, or -errno.
fn read_links(keyring: i32) -> Result<Vec<i32>, c_int> {
    let mut serials = vec![0i32; 64];
    let mut bytes = read_into(keyring, &mut serials)?;

    if bytes > size_of_val(&serials[..]) {
        serials.resize(bytes.div_ceil(size_of::<i32>()), 0);
        // The keyring can grow again between the two reads, KEYCTL_READ
        // then returning the full size while filling only what fits.
        bytes = read_into(keyring, &mut serials)?.min(size_of_val(&serials[..]));
    }
    serials.truncate(bytes / size_of::<i32>());
    Ok(serials)
}

/// The links of `keyring` the kernel describes, each to `f` with its
/// type and description: 0 or -errno.
pub(crate) fn list(keyring: i32, mut f: impl FnMut(i32, &CStr, &CStr)) -> c_int {
    let serials = match read_links(keyring) {
        Ok(serials) => serials,
        Err(err) => return err,
    };
    for serial in serials {
        if let Ok(d) = Described::of(serial) {
            f(serial, d.ty(), d.description());
        }
    }
    0
}

/// `s`, cut to what fits in `room` bytes with a NUL as a C buffer held
/// it, and whether it fitted.
fn clipped(s: &[u8], room: usize) -> (Vec<u8>, bool) {
    let n = s.len().min(room - 1);
    (s[..n].to_vec(), n == s.len())
}

/// Every link of `keyring`, unlike list() also those the kernel will not
/// describe, or -errno.
pub(crate) fn links(keyring: i32) -> Result<Vec<KeyringLink>, c_int> {
    let links = read_links(keyring)?
        .into_iter()
        .map(|serial| {
            let mut l = KeyringLink {
                serial,
                err: 0,
                ty: Vec::new(),
                description: Vec::new(),
            };
            match Described::of(serial) {
                Err(err) => l.err = err,
                Ok(d) => {
                    // A type or description too long for the C's fields
                    // is -ERANGE, and kept as far as it fitted.
                    let (ty, fits) = clipped(d.ty().to_bytes(), TYPE_MAX);
                    l.ty = ty;
                    if !fits {
                        l.err = -ERANGE;
                        return l;
                    }
                    let (description, fits) = clipped(d.description().to_bytes(), DESC_MAX);
                    l.description = description;
                    if !fits {
                        l.err = -ERANGE;
                    }
                }
            }
            l
        })
        .collect();
    Ok(links)
}

/// The description the kernel gives the asymmetric key it parses from
/// `der`, from a throwaway instance on the thread keyring, or -errno.
pub(crate) fn cert_description(der: &[u8]) -> Result<Vec<u8>, c_int> {
    let probe = add_cert(KEY_SPEC_THREAD_KEYRING, der);
    if probe < 0 {
        return Err(probe);
    }
    let d = Described::of(probe);
    unlink_key(KEY_SPEC_THREAD_KEYRING, probe);
    let description = d?.description().to_bytes().to_vec();
    if description.len() >= DESC_MAX {
        return Err(-ERANGE);
    }
    Ok(description)
}

/// The serial of the asymmetric key in `keyring` the kernel describes
/// as it does `der`, the last such link: Ok(None) for none, or -errno.
fn find(keyring: i32, der: &[u8]) -> Result<Option<i32>, c_int> {
    let want = cert_description(der)?;
    let mut found = None;
    let ret = list(keyring, |serial, ty, description| {
        if ty.to_bytes() == b"asymmetric" && description.to_bytes() == want {
            found = Some(serial);
        }
    });
    if ret != 0 {
        return Err(ret);
    }
    Ok(found)
}

/// Whether `keyring` links the certificate `der`: 1, 0, or -errno.
pub(crate) fn holds_cert(keyring: i32, der: &[u8]) -> c_int {
    match find(keyring, der) {
        Ok(found) => c_int::from(found.is_some()),
        Err(ret) => ret,
    }
}

/// The serial of the key of the certificate `der` in `keyring`: -ENOKEY
/// for none, or -errno.
pub(crate) fn find_cert(keyring: i32, der: &[u8]) -> i32 {
    match find(keyring, der) {
        Ok(Some(serial)) => serial,
        Ok(None) => -ENOKEY,
        Err(ret) => ret,
    }
}

/// Whether `keyring` links exactly the certificates and nothing else: 1,
/// 0, or -errno. Every link counts, whatever its type and whether it can
/// be described: the kernel's signature check searches a nested keyring,
/// which the seal does not cover, and a key hidden from view still
/// verifies.
pub(crate) fn holds_exactly(keyring: i32, certs: &[&[u8]]) -> c_int {
    let want = match certs
        .iter()
        .map(|der| cert_description(der))
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(want) => want,
        Err(err) => return err,
    };
    let serials = match read_links(keyring) {
        Ok(serials) => serials,
        Err(err) => return err,
    };
    if serials.len() != want.len() {
        return 0;
    }
    let mut matched = vec![false; want.len()];
    for serial in serials {
        let Ok(d) = Described::of(serial) else {
            return 0;
        };
        if d.ty().to_bytes() != b"asymmetric" {
            return 0;
        }
        let description = d.description().to_bytes();
        let Some(j) = (0..want.len()).find(|&j| !matched[j] && want[j] == description) else {
            return 0;
        };
        matched[j] = true;
    }
    1
}

/// `key` unlinked from `keyring`: 0 or -errno.
pub(crate) fn unlink_key(keyring: i32, key: i32) -> c_int {
    keyctl_numbers(KEYCTL_UNLINK, c_long::from(key), c_long::from(keyring)).min(0) as c_int
}

/// The serial of the kernel's BPF keyring, or -errno.
pub(crate) fn bpf_serial() -> i32 {
    keyctl_spec(KEYCTL_GET_KEYRING_ID, KEY_SPEC_BPF_KEYRING) as i32
}

/// The serial of the kernel's dm-verity keyring, never one found by
/// name, or -errno.
pub(crate) fn dm_verity_serial() -> i32 {
    keyctl_spec(KEYCTL_GET_KEYRING_ID, KEY_SPEC_DM_VERITY_KEYRING) as i32
}

/// A certificate added to the dm-verity keyring: its serial, or -errno.
pub(crate) fn dm_verity_add_cert(der: &[u8]) -> i32 {
    add_cert(KEY_SPEC_DM_VERITY_KEYRING, der)
}

/// The dm-verity keyring restricted with no restriction type, so that it
/// rejects every further addition: 0 or -errno.
pub(crate) fn dm_verity_seal() -> c_int {
    keyctl_spec(KEYCTL_RESTRICT_KEYRING, KEY_SPEC_DM_VERITY_KEYRING).min(0) as c_int
}

/// A line of the log at `level`, err() or its kin, up to any NUL.
fn say(level: fn(&[u8]), text: &[u8]) {
    level(cstr(text));
}

/// Whether the keyring holds the certificates of `set` and nothing else:
/// 1, 0, or -errno.
fn holds_set(ring: i32, set: &TrustedSet) -> c_int {
    let mut certs = Vec::with_capacity(set.len());

    for c in keys::members(set) {
        match keys::cert_der(c) {
            Ok(der) => certs.push(der),
            Err(err) => return err,
        }
    }
    holds_exactly(ring, &certs)
}

/// Enrols every certificate of `set` in the keyring `spec` names, whose
/// serial is `ring`, and seals it.
///
/// The bpf keyring is the trust anchor a signed loader is verified
/// against once it is sealed. Booted with bpf.keyring_unsealed=1 it
/// takes keys until the first seal, which is init's job from the initrd.
/// Found sealed, it was sealed by init earlier this boot (-EEXIST: use
/// it) or empty by the kernel at boot (-ENOKEY). Either way it must then
/// hold exactly the trusted set; a key another task linked before the
/// seal, or a restriction init did not install, is refused
/// (-EKEYREJECTED).
pub(crate) fn seal_set(spec: i32, ring: i32, set: &TrustedSet) -> c_int {
    use crate::errno::{EACCES, EEXIST, EKEYREJECTED, ENOENT, ENOKEY, ENOPKG, EPERM};

    let n = set.len();
    let plural: &str = if n == 1 { "" } else { "s" };
    let mut sealed = false;

    for (i, c) in keys::members(set).iter().enumerate() {
        let path = keys::cert_path(c);
        let der = match keys::cert_der(c) {
            Ok(der) => der,
            Err(err) => {
                say(
                    crate::log::err,
                    &[b"read ", path, b": ", text(err).as_bytes()].concat(),
                );
                return err;
            }
        };
        let key = add_cert(spec, der);
        if key >= 0 {
            let head = format!("bpf keyring serial={ring}: ");
            let tail = format!(" enrolled (key serial={key})");
            say(
                crate::log::info,
                &[head.as_bytes(), path, tail.as_bytes()].concat(),
            );
            continue;
        }
        if key != -EPERM && key != -EACCES {
            say(
                crate::log::err,
                &[b"bpf keyring: add ", path, b": ", text(key).as_bytes()].concat(),
            );
            if key == -ENOENT || key == -ENOPKG {
                say(
                    crate::log::err,
                    b"kernel cannot verify this cert's public-key algorithm (ML-DSA needs CONFIG_CRYPTO_MLDSA=y and CONFIG_CRYPTO_SHA512=y)",
                );
            }
            return key;
        }
        if i > 0 {
            let msg = format!(
                "bpf keyring serial={ring} was sealed while init enrolled the certificates (tampered)"
            );
            say(crate::log::err, msg.as_bytes());
            return -EKEYREJECTED;
        }
        sealed = true;
        break;
    }
    if !sealed {
        let ret = keyctl_spec(KEYCTL_RESTRICT_KEYRING, spec).min(0) as c_int;
        if ret == -EEXIST {
            let msg = format!(
                "bpf keyring serial={ring} carries a restriction init did not install (tampered)"
            );
            say(crate::log::err, msg.as_bytes());
            return -EKEYREJECTED;
        }
        if ret != 0 {
            say(
                crate::log::err,
                &[
                    b"bpf keyring: certificates enrolled but the keyring could not be sealed: ",
                    text(ret).as_bytes(),
                ]
                .concat(),
            );
            return ret;
        }
    }
    let ret = holds_set(ring, set);
    if ret < 0 {
        say(
            crate::log::err,
            &[b"bpf keyring: compare: ", text(ret).as_bytes()].concat(),
        );
        return ret;
    }
    if ret == 0 && sealed && holds_exactly(ring, &[]) == 1 {
        let msg = format!(
            "bpf keyring serial={ring} was sealed empty at boot; boot with bpf.keyring_unsealed=1"
        );
        say(crate::log::err, msg.as_bytes());
        return -ENOKEY;
    }
    if ret == 0 {
        let msg = format!(
            "bpf keyring serial={ring} is sealed around keys other than the {n} trusted certificate{plural} (tampered)"
        );
        say(crate::log::err, msg.as_bytes());
        return -EKEYREJECTED;
    }
    if sealed {
        let msg = format!(
            "bpf keyring serial={ring}: already holds the {n} trusted certificate{plural}, sealed this boot"
        );
        say(crate::log::info, msg.as_bytes());
        return -EEXIST;
    }
    let msg = format!("bpf keyring serial={ring}: {n} certificate{plural} enrolled and sealed");
    say(crate::log::info, msg.as_bytes());
    0
}

/// [`seal_set`] of the kernel's bpf keyring, whose serial is `ring`.
pub(crate) fn seal_bpf_set(ring: i32, set: &TrustedSet) -> c_int {
    seal_set(KEY_SPEC_BPF_KEYRING, ring, set)
}
