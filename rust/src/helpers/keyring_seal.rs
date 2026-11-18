// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-keyring-seal: init's enrolment, keyring::seal_set(), run
//! against a private keyring rather than the sealed .bpf, and
//! holds_exactly() against keys of every kind.
//!
//!   test-keyring-seal exact|fresh|foreign|nested|restricted|empty <keys dir> <revoked dir> <other.der>

use core::ffi::{CStr, c_int, c_long, c_void};
use std::ffi::CString;

use super::{err, helper_main, strerror};
use crate::errno::{EEXIST, EINVAL, EIO, EKEYREJECTED, ENOKEY};
use crate::util::keyring::{KeyringCert, holds_exactly, keyring_unlink_key, seal_set};
use crate::util::keys::{TrustedSet, read_der_bytes};

helper_main!(shirudo_helper_test_keyring_seal, run);

fn errno() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(EIO)
}

/// add_key(2): the key's serial or -errno.
fn add(ty: &CStr, description: Option<&CStr>, payload: &[u8], ring: i32) -> i32 {
    // SAFETY: C strings, NULL or one, and the payload's bytes.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_add_key,
            ty.as_ptr(),
            description.map_or(core::ptr::null(), CStr::as_ptr),
            if payload.is_empty() {
                core::ptr::null()
            } else {
                payload.as_ptr().cast::<c_void>()
            },
            payload.len(),
            ring,
        )
    };
    if ret < 0 { -errno() } else { ret as i32 }
}

/// keyctl(2) of numbers and pointers: its result, or -errno.
fn keyctl(cmd: c_int, a: c_long, b: c_long, c: c_long) -> c_long {
    // SAFETY: a command of the caller's arguments, which name no memory
    // the call would write.
    let ret = unsafe { libc::syscall(libc::SYS_keyctl, cmd, a, b, c, c_long::from(0u8)) };
    if ret < 0 { -c_long::from(errno()) } else { ret }
}

fn expect(what: &str, got: c_int, want: c_int) -> u32 {
    if got == want {
        return 0;
    }
    err(&format!("{what}: got {got}, want {want}\n"));
    1
}

fn holds(ring: i32, certs: &[KeyringCert]) -> c_int {
    // SAFETY: certificates whose bytes outlive the call.
    unsafe { holds_exactly(ring, certs) }
}

fn cert(der: &[u8]) -> KeyringCert {
    KeyringCert {
        der: der.as_ptr(),
        len: der.len(),
    }
}

/// A key `add` makes in `ring` around `check`, unlinked after: what
/// check() gives, or the add's error.
fn with_key(ring: i32, key: i32, check: impl FnOnce() -> c_int) -> c_int {
    let ret = if key < 0 { key } else { check() };
    if key > 0 {
        keyring_unlink_key(ring, key);
    }
    ret
}

/// Every link counts, of any type and whether it can be described.
fn exact(a: &[u8], b: &[u8]) -> c_int {
    let both = [cert(a), cert(b)];
    let swapped = [cert(b), cert(a)];
    let twice = [cert(a), cert(a)];
    let ring = add(
        c"keyring",
        Some(c"shirudo-test-exact"),
        &[],
        libc::KEY_SPEC_THREAD_KEYRING,
    );
    if ring < 0 {
        return ring;
    }
    let mut fails = 0;
    fails += expect("empty, none", holds(ring, &[]), 1);
    fails += expect("empty, one", holds(ring, &both[..1]), 0);
    if add(c"asymmetric", None, a, ring) < 0 {
        return -EIO;
    }
    fails += expect("one, one", holds(ring, &both[..1]), 1);
    fails += expect("one, none", holds(ring, &[]), 0);
    fails += expect("one, two", holds(ring, &both), 0);
    if add(c"asymmetric", None, b, ring) < 0 {
        return -EIO;
    }
    fails += expect("two, two", holds(ring, &both), 1);
    fails += expect("two, swapped", holds(ring, &swapped), 1);
    fails += expect("two, twice", holds(ring, &twice), 0);
    fails += expect("two, one", holds(ring, &both[..1]), 0);
    let key = add(c"keyring", Some(c"shirudo-test-nested"), &[], ring);
    fails += expect(
        "nested keyring",
        with_key(ring, key, || holds(ring, &both)),
        0,
    );
    let key = add(c"user", Some(c"shirudo-test-user"), b"x", ring);
    fails += expect("user key", with_key(ring, key, || holds(ring, &both)), 0);
    let mut key = add(c"user", Some(c"shirudo-test-hidden"), b"x", ring);
    if key > 0 && keyctl(libc::KEYCTL_SETPERM as c_int, key.into(), 0, 0) < 0 {
        key = -errno();
    }
    fails += expect(
        "key hidden from view",
        with_key(ring, key, || holds(ring, &both)),
        0,
    );
    fails += expect("two again", holds(ring, &both), 1);
    keyring_unlink_key(libc::KEY_SPEC_THREAD_KEYRING, ring);
    if fails > 0 { -EKEYREJECTED } else { 0 }
}

/// `set` is the trusted set init enrols, `own` its primary and `other` a
/// certificate outside it.
fn seal(mode: &[u8], set: &TrustedSet, own: &[u8], other: &[u8]) -> c_int {
    let ring = add(
        c"keyring",
        Some(c"shirudo-test-seal"),
        &[],
        libc::KEY_SPEC_THREAD_KEYRING,
    );
    if ring < 0 {
        return ring;
    }
    // Init's enrolment into the private ring, sealing it as init does
    // the .bpf.
    let enrol = || seal_set(ring, ring, set);
    let restrict = |ty: Option<&CStr>, restriction: Option<&CStr>| {
        keyctl(
            libc::KEYCTL_RESTRICT_KEYRING as c_int,
            ring.into(),
            ty.map_or(0, |t| t.as_ptr() as c_long),
            restriction.map_or(0, |r| r.as_ptr() as c_long),
        )
    };
    let mut fails = 0;
    match mode {
        b"fresh" => {
            fails += expect("enrol and seal", enrol(), 0);
            fails += expect("found sealed with the set", enrol(), -EEXIST);
        }
        b"foreign" => {
            if add(c"asymmetric", None, other, ring) < 0 {
                return -EIO;
            }
            fails += expect("foreign key sealed in", enrol(), -EKEYREJECTED);
            fails += expect("found sealed with a foreign key", enrol(), -EKEYREJECTED);
        }
        b"nested" => {
            if add(c"keyring", Some(c"shirudo-test-nested"), &[], ring) < 0 {
                return -EIO;
            }
            fails += expect("nested keyring sealed in", enrol(), -EKEYREJECTED);
        }
        b"restricted" => {
            if add(c"asymmetric", None, own, ring) < 0
                || restrict(Some(c"asymmetric"), Some(c"key_or_keyring:0:chain")) < 0
            {
                return -EIO;
            }
            let ret = enrol();
            fails += expect(
                "restriction init did not install",
                c_int::from(ret == 0 || ret == -EEXIST),
                0,
            );
        }
        b"empty" => {
            // Sealed as init seals the bpf keyring: no type, nothing more.
            if restrict(None, None) < 0 {
                return -EIO;
            }
            fails += expect("sealed empty", enrol(), -ENOKEY);
        }
        _ => return -EINVAL,
    }
    keyring_unlink_key(libc::KEY_SPEC_THREAD_KEYRING, ring);
    if fails > 0 { -EKEYREJECTED } else { 0 }
}

/// The case `mode` with the keys directory's primary, `own`, and
/// `other`: 0 or -errno.
fn case(mode: &[u8], keys: &CStr, revoked: &CStr, own: &CStr, other: &CStr) -> c_int {
    let (own, other) = match (read_der_bytes(own), read_der_bytes(other)) {
        (Ok(own), Ok(other)) => (own, other),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    if mode == b"exact" {
        return exact(&own, &other);
    }
    // SAFETY: a set of no member, for which zeros are the value.
    let mut set: Box<TrustedSet> = Box::new(unsafe { core::mem::zeroed() });
    // SAFETY: two C strings and room for the set.
    let ret = unsafe { crate::util::keys::load(keys.as_ptr(), revoked.as_ptr(), false, &mut *set) };
    if ret != 0 {
        return ret;
    }
    seal(mode, &set, &own, &other)
}

fn run(args: &[&CStr]) -> c_int {
    let [_, mode, keys, revoked, other] = args else {
        let me = args
            .first()
            .map_or("test-keyring-seal".into(), |a| a.to_string_lossy());
        err(&format!(
            "usage: {me} exact|fresh|foreign|nested|restricted|empty <keys-dir> <revoked-dir> <other.der>\n"
        ));
        return 2;
    };
    let Ok(own) = CString::new([keys.to_bytes(), b"/cert.der"].concat()) else {
        return 2;
    };
    let ret = case(mode.to_bytes(), keys, revoked, &own, other);
    if ret != 0 {
        err(&format!(
            "keyring seal test {}: {}\n",
            mode.to_string_lossy(),
            strerror(-ret)
        ));
    }
    c_int::from(ret != 0)
}
