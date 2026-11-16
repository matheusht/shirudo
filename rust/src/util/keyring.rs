// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The kernel keyrings through raw add_key(2) and keyctl(2), behind
//! `util/keyring.h`, with no libkeyutils: what a keyring links and how
//! the kernel describes it, whether it holds a certificate or exactly a
//! set of them, and the bpf and dm-verity keyrings that anchor trust.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};

use crate::errno::{ENOMEM, ERANGE};
use crate::sys::libc::{SYS_ADD_KEY, SYS_KEYCTL, abort, errno, syscall};
use crate::sys::malloc::{xcalloc, xfree, xmalloc, xreallocarray};
use crate::text::{cstr, strscpy};

/// `KEYRING_DESC_MAX`.
const DESC_MAX: usize = 512;

const KEYCTL_GET_KEYRING_ID: c_long = 0;
const KEYCTL_DESCRIBE: c_long = 6;
const KEYCTL_UNLINK: c_long = 9;
const KEYCTL_READ: c_long = 11;
const KEYCTL_RESTRICT_KEYRING: c_long = 29;
const KEY_SPEC_THREAD_KEYRING: i32 = -1;
const KEY_SPEC_BPF_KEYRING: i32 = -9;
const KEY_SPEC_DM_VERITY_KEYRING: i32 = -10;

/// `shirudo_keyring_cb`.
type KeyringCb = unsafe extern "C" fn(
    serial: i32,
    ty: *const c_char,
    description: *const c_char,
    ud: *mut c_void,
);

/// `struct keyring_link`.
#[repr(C)]
pub struct KeyringLink {
    serial: i32,
    err: c_int,
    ty: [u8; 64],
    description: [u8; DESC_MAX],
}

const _: () = assert!(size_of::<KeyringLink>() == 584);

/// `struct keyring_cert`.
#[repr(C)]
pub struct KeyringCert {
    der: *const u8,
    len: usize,
}

/// add_key(2): the key's serial, or -1 with errno set.
///
/// # Safety
///
/// `ty` is a C string, `desc` NULL or one, and `payload` holds `plen`
/// bytes.
unsafe fn add_key(
    ty: &CStr,
    desc: *const c_char,
    payload: *const u8,
    plen: usize,
    ring: i32,
) -> c_long {
    // SAFETY: the syscall's arguments, as the caller passes them.
    unsafe {
        syscall(
            SYS_ADD_KEY,
            ty.as_ptr(),
            desc,
            payload,
            plen,
            c_long::from(ring),
        )
    }
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

/// How the kernel describes `serial`, `type;uid;gid;perm;description`,
/// into `out`: 0, -ERANGE when it does not fit, or -errno.
fn describe_key(serial: i32, out: &mut [u8; DESC_MAX]) -> c_int {
    // SAFETY: the room of out.
    let ret = unsafe {
        keyctl(
            KEYCTL_DESCRIBE,
            c_long::from(serial),
            out.as_mut_ptr() as c_long,
            out.len() as c_long,
            0,
        )
    };
    if ret < 0 {
        return -errno();
    }
    if ret as usize > out.len() {
        return -ERANGE;
    }
    0
}

/// The type and the description in a description the kernel gave, the
/// type ended in place where its `;` was: where each starts, the
/// description at the NUL that ends the buffer when it lacks four `;`.
fn split_describe(desc: &mut [u8; DESC_MAX]) -> (usize, Option<usize>) {
    let mut p = 0;

    for i in 0..4 {
        let Some(at) = cstr(&desc[p..]).iter().position(|&c| c == b';') else {
            return (0, None);
        };

        p += at;
        if i == 0 {
            desc[p] = 0;
        }
        p += 1;
    }
    (0, Some(p))
}

/// Every link of `keyring`, whatever its type, in an allocation of
/// `cap` bytes from xmalloc() or xreallocarray().
fn read_links(keyring: i32, out: &mut *mut i32, n: &mut usize, size: &mut usize) -> c_int {
    let mut cap = 64 * size_of::<i32>();
    // SAFETY: a size alone.
    let mut serials: *mut i32 = unsafe { xmalloc(cap) }.cast();

    if serials.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the room of serials.
    let mut ret = unsafe {
        keyctl(
            KEYCTL_READ,
            c_long::from(keyring),
            serials as c_long,
            cap as c_long,
            0,
        )
    };
    if ret < 0 {
        let err = -errno();

        // SAFETY: what xmalloc() gave, and its size.
        unsafe { xfree(serials.cast(), cap) };
        return err;
    }
    if ret as usize > cap {
        // SAFETY: the serials, cap bytes, grown to what the keyring needs.
        let bigger: *mut i32 =
            unsafe { xreallocarray(serials.cast(), cap, ret as usize, 1) }.cast();

        if bigger.is_null() {
            // SAFETY: what xmalloc() gave, and its size.
            unsafe { xfree(serials.cast(), cap) };
            return -ENOMEM;
        }
        serials = bigger;
        cap = ret as usize;
        // SAFETY: the room of serials.
        ret = unsafe {
            keyctl(
                KEYCTL_READ,
                c_long::from(keyring),
                serials as c_long,
                cap as c_long,
                0,
            )
        };
        if ret < 0 {
            let err = -errno();

            // SAFETY: what xreallocarray() gave, and its size.
            unsafe { xfree(serials.cast(), cap) };
            return err;
        }
        // The keyring can grow again between the two reads, KEYCTL_READ
        // then returning the full size while filling only cap bytes.
        if ret as usize > cap {
            ret = cap as c_long;
        }
    }
    *out = serials;
    *n = ret as usize / size_of::<i32>();
    *size = cap;
    0
}

/// The links of `keyring` the kernel describes, each to `f` with its
/// type and description: 0 or -errno.
fn list(keyring: i32, mut f: impl FnMut(i32, &CStr, &CStr)) -> c_int {
    let (mut serials, mut n, mut cap) = (core::ptr::null_mut(), 0, 0);
    let ret = read_links(keyring, &mut serials, &mut n, &mut cap);

    if ret != 0 {
        return ret;
    }
    for i in 0..n {
        let mut desc = [0u8; DESC_MAX];
        // SAFETY: n serials at serials, which read_links() filled.
        let serial = unsafe { *serials.add(i) };

        if describe_key(serial, &mut desc) != 0 {
            continue;
        }
        let (ty, description) = split_describe(&mut desc);
        let ty = CStr::from_bytes_until_nul(&desc[ty..]).unwrap_or(c"");
        let description = description.map_or(c"", |d| {
            CStr::from_bytes_until_nul(&desc[d..]).unwrap_or(c"")
        });

        f(serial, ty, description);
    }
    // SAFETY: what read_links() allocated, and its size.
    unsafe { xfree(serials.cast(), cap) };
    0
}

/// Every link of `keyring`, unlike list() also those the kernel will not
/// describe, in an allocation the caller frees with
/// `xfree(*links, *n * sizeof(**links))`.
fn links(keyring: i32, links: &mut *mut KeyringLink, n: &mut usize) -> c_int {
    let (mut serials, mut count, mut cap) = (core::ptr::null_mut(), 0, 0);
    let mut out: *mut KeyringLink = core::ptr::null_mut();
    let ret = read_links(keyring, &mut serials, &mut count, &mut cap);

    if ret != 0 {
        return ret;
    }
    if count != 0 {
        // SAFETY: a count and a size.
        out = unsafe { xcalloc(count, size_of::<KeyringLink>()) }.cast();
        if out.is_null() {
            // SAFETY: what read_links() allocated, and its size.
            unsafe { xfree(serials.cast(), cap) };
            return -ENOMEM;
        }
    }
    for i in 0..count {
        let mut desc = [0u8; DESC_MAX];
        // SAFETY: count serials, and count zeroed links from xcalloc().
        let (serial, l) = unsafe { (*serials.add(i), &mut *out.add(i)) };

        l.serial = serial;
        l.err = describe_key(serial, &mut desc);
        if l.err != 0 {
            continue;
        }
        let (ty, description) = split_describe(&mut desc);
        let ty = cstr(&desc[ty..]);
        let description = description.map_or(&b""[..], |d| cstr(&desc[d..]));

        if strscpy(&mut l.ty, ty).is_err() || strscpy(&mut l.description, description).is_err() {
            l.err = -ERANGE;
        }
    }
    // SAFETY: what read_links() allocated, and its size.
    unsafe { xfree(serials.cast(), cap) };
    *links = out;
    *n = count;
    0
}

/// The description the kernel gives the asymmetric key it parses from
/// `der`, from a throwaway instance on the thread keyring.
///
/// # Safety
///
/// `der` holds `der_len` bytes.
unsafe fn cert_description(der: *const u8, der_len: usize, out: &mut [u8; DESC_MAX]) -> c_int {
    let mut desc = [0u8; DESC_MAX];
    // SAFETY: a type, no description, and the caller's certificate.
    let probe = unsafe {
        add_key(
            c"asymmetric",
            core::ptr::null(),
            der,
            der_len,
            KEY_SPEC_THREAD_KEYRING,
        )
    };

    if probe < 0 {
        return -errno();
    }
    let ret = describe_key(probe as i32, &mut desc);
    // SAFETY: numbers alone.
    unsafe {
        keyctl(
            KEYCTL_UNLINK,
            probe,
            c_long::from(KEY_SPEC_THREAD_KEYRING),
            0,
            0,
        )
    };
    if ret != 0 {
        return ret;
    }
    let (_, description) = split_describe(&mut desc);
    let description = description.map_or(&b""[..], |d| cstr(&desc[d..]));

    if strscpy(out, description).is_err() {
        -ERANGE
    } else {
        0
    }
}

/// The serial of the asymmetric key in `keyring` the kernel describes
/// as it does `der`, the last such link: Ok(None) for none, or -errno.
///
/// # Safety
///
/// `der` holds `der_len` bytes.
unsafe fn find(keyring: i32, der: *const u8, der_len: usize) -> Result<Option<i32>, c_int> {
    let mut want = [0u8; DESC_MAX];
    let mut found = None;
    // SAFETY: the caller's certificate.
    let mut ret = unsafe { cert_description(der, der_len, &mut want) };

    if ret == 0 {
        let want = cstr(&want);

        ret = list(keyring, |serial, ty, description| {
            if ty.to_bytes() == b"asymmetric" && description.to_bytes() == want {
                found = Some(serial);
            }
        });
    }
    if ret != 0 {
        return Err(ret);
    }
    Ok(found)
}

/// Whether `keyring` links exactly the certificates and nothing else: 1,
/// 0, or -errno. Every link counts, whatever its type and whether it can
/// be described: the kernel's signature check searches a nested keyring,
/// which the seal does not cover, and a key hidden from view still
/// verifies.
///
/// # Safety
///
/// Each of `certs` holds its `len` bytes at `der`.
unsafe fn holds_exactly(keyring: i32, certs: &[KeyringCert]) -> c_int {
    let n = certs.len();
    let mut want: *mut [u8; DESC_MAX] = core::ptr::null_mut();
    let mut matched: *mut bool = core::ptr::null_mut();
    let (mut serials, mut links, mut cap) = (core::ptr::null_mut::<i32>(), 0usize, 0usize);
    let mut ret = -ENOMEM;

    'out: {
        if n != 0 {
            // SAFETY: counts and sizes.
            unsafe {
                want = xcalloc(n, DESC_MAX).cast();
                matched = xcalloc(n, 1).cast();
            }
            if want.is_null() || matched.is_null() {
                break 'out;
            }
        }
        for (i, cert) in certs.iter().enumerate() {
            // SAFETY: the caller's certificate, and the zeroed room of
            // want[i] xcalloc() gave.
            ret = unsafe { cert_description(cert.der, cert.len, &mut *want.add(i)) };
            if ret != 0 {
                break 'out;
            }
        }
        ret = read_links(keyring, &mut serials, &mut links, &mut cap);
        if ret != 0 || links != n {
            break 'out;
        }
        for i in 0..links {
            let mut desc = [0u8; DESC_MAX];
            // SAFETY: links serials, which read_links() filled.
            let serial = unsafe { *serials.add(i) };

            if describe_key(serial, &mut desc) != 0 {
                break 'out;
            }
            let (ty, description) = split_describe(&mut desc);
            let description = description.map_or(&b""[..], |d| cstr(&desc[d..]));

            if cstr(&desc[ty..]) != b"asymmetric" {
                break 'out;
            }
            // SAFETY: n descriptions and n flags from xcalloc().
            let j =
                (0..n).find(|&j| unsafe { !*matched.add(j) && cstr(&*want.add(j)) == description });
            let Some(j) = j else {
                break 'out;
            };
            // SAFETY: flag j of the n from xcalloc().
            unsafe { *matched.add(j) = true };
        }
        ret = 1;
    }
    // SAFETY: the allocations above, NULL where none was made, and their
    // sizes.
    unsafe {
        xfree(serials.cast(), cap);
        xfree(want.cast(), n * DESC_MAX);
        xfree(matched.cast(), n);
    }
    ret
}

/// keyctl() of `cmd` on `spec` that returns a serial or nothing: the
/// value, or -errno.
fn keyctl_spec(cmd: c_long, spec: i32) -> c_long {
    // SAFETY: numbers alone.
    let ret = unsafe { keyctl(cmd, c_long::from(spec), 0, 0, 0) };

    if ret < 0 { -c_long::from(errno()) } else { ret }
}

/// A DER certificate added to the special keyring `spec`: its serial, or
/// -errno.
///
/// # Safety
///
/// `cert` holds `cert_len` bytes.
unsafe fn add_cert(spec: i32, cert: *const u8, cert_len: usize) -> i32 {
    // SAFETY: a type, no description, and the caller's certificate.
    let ret = unsafe { add_key(c"asymmetric", core::ptr::null(), cert, cert_len, spec) };

    if ret < 0 { -errno() } else { ret as i32 }
}

pub(crate) use capi::{
    keyring_bpf_serial, keyring_dm_verity_serial, keyring_find_cert, keyring_holds_cert,
    keyring_links, keyring_unlink_key,
};

impl KeyringLink {
    pub(crate) fn serial(&self) -> i32 {
        self.serial
    }

    /// The errno that kept the key from being described, or 0.
    pub(crate) fn err(&self) -> c_int {
        self.err
    }

    pub(crate) fn ty(&self) -> &[u8] {
        cstr(&self.ty)
    }

    pub(crate) fn description(&self) -> &[u8] {
        cstr(&self.description)
    }
}

mod capi {
    use core::ffi::{c_char, c_int, c_long, c_void};

    use super::{
        DESC_MAX, KEY_SPEC_BPF_KEYRING, KEY_SPEC_DM_VERITY_KEYRING, KEYCTL_GET_KEYRING_ID,
        KEYCTL_RESTRICT_KEYRING, KEYCTL_UNLINK, KeyringCb, KeyringCert, KeyringLink, abort, errno,
        keyctl,
    };
    use crate::errno::ENOKEY;
    use crate::ffi;

    /// # Safety
    ///
    /// `cb` takes `ud`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keyring_list(
        keyring: i32,
        cb: Option<KeyringCb>,
        ud: *mut c_void,
    ) -> c_int {
        super::list(keyring, |serial, ty, description| {
            let Some(cb) = cb else {
                // SAFETY: a call that takes no pointer; the C called a
                // NULL callback here.
                unsafe { abort() }
            };

            // SAFETY: the caller's callback and context, and two C
            // strings that last the call.
            unsafe { cb(serial, ty.as_ptr(), description.as_ptr(), ud) }
        })
    }

    /// # Safety
    ///
    /// `links` and `n` point to where the links and their count go.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keyring_links(
        keyring: i32,
        links: *mut *mut KeyringLink,
        n: *mut usize,
    ) -> c_int {
        // SAFETY: the caller passes the two places.
        unsafe { super::links(keyring, &mut *links, &mut *n) }
    }

    /// # Safety
    ///
    /// `der` holds `der_len` bytes, and `out` has room for
    /// `KEYRING_DESC_MAX`.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keyring_cert_description(
        der: *const u8,
        der_len: usize,
        out: *mut c_char,
    ) -> c_int {
        // SAFETY: the caller passes the certificate and the room.
        unsafe { super::cert_description(der, der_len, &mut *out.cast::<[u8; DESC_MAX]>()) }
    }

    /// # Safety
    ///
    /// `der` holds `der_len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keyring_holds_cert(
        keyring: i32,
        der: *const u8,
        der_len: usize,
    ) -> c_int {
        // SAFETY: the caller passes the certificate.
        match unsafe { super::find(keyring, der, der_len) } {
            Ok(found) => c_int::from(found.is_some()),
            Err(ret) => ret,
        }
    }

    /// # Safety
    ///
    /// `der` holds `der_len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keyring_find_cert(
        keyring: i32,
        der: *const u8,
        der_len: usize,
    ) -> i32 {
        // SAFETY: the caller passes the certificate.
        match unsafe { super::find(keyring, der, der_len) } {
            Ok(Some(serial)) => serial,
            Ok(None) => -ENOKEY,
            Err(ret) => ret,
        }
    }

    /// # Safety
    ///
    /// `certs` holds `n` certificates.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keyring_holds_exactly(
        keyring: i32,
        certs: *const KeyringCert,
        n: usize,
    ) -> c_int {
        // SAFETY: the caller passes the certificates.
        unsafe { super::holds_exactly(keyring, ffi::slice(certs, n)) }
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn keyring_unlink_key(keyring: i32, key: i32) -> c_int {
        // SAFETY: numbers alone.
        if unsafe {
            keyctl(
                KEYCTL_UNLINK,
                c_long::from(key),
                c_long::from(keyring),
                0,
                0,
            )
        } < 0
        {
            return -errno();
        }
        0
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn keyring_bpf_serial() -> i32 {
        super::keyctl_spec(KEYCTL_GET_KEYRING_ID, KEY_SPEC_BPF_KEYRING) as i32
    }

    /// # Safety
    ///
    /// `cert` holds `cert_len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keyring_bpf_add_cert(cert: *const u8, cert_len: usize) -> i32 {
        // SAFETY: the caller passes the certificate.
        unsafe { super::add_cert(KEY_SPEC_BPF_KEYRING, cert, cert_len) }
    }

    /// No restriction type: the keyring rejects every further link.
    #[unsafe(no_mangle)]
    pub extern "C" fn keyring_bpf_seal() -> c_int {
        super::keyctl_spec(KEYCTL_RESTRICT_KEYRING, KEY_SPEC_BPF_KEYRING).min(0) as c_int
    }

    /// The kernel-owned ring itself, never one found by name.
    #[unsafe(no_mangle)]
    pub extern "C" fn keyring_dm_verity_serial() -> i32 {
        super::keyctl_spec(KEYCTL_GET_KEYRING_ID, KEY_SPEC_DM_VERITY_KEYRING) as i32
    }

    /// # Safety
    ///
    /// `cert` holds `cert_len` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn keyring_dm_verity_add_cert(cert: *const u8, cert_len: usize) -> i32 {
        // SAFETY: the caller passes the certificate.
        unsafe { super::add_cert(KEY_SPEC_DM_VERITY_KEYRING, cert, cert_len) }
    }

    /// No restriction type: the keyring rejects every further addition.
    #[unsafe(no_mangle)]
    pub extern "C" fn keyring_dm_verity_seal() -> c_int {
        super::keyctl_spec(KEYCTL_RESTRICT_KEYRING, KEY_SPEC_DM_VERITY_KEYRING).min(0) as c_int
    }
}
