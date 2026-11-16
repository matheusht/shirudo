// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo-build keys vouch`: the operator key signs a vouch for
//! another certificate, which `shirudo keys add --vouch` takes on the
//! targets that enrol this key.

use core::ffi::{CStr, c_int};
use core::ptr;
use std::ffi::CString;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::IntoRawFd;

use super::{Bytes, KeyFiles, error, hex, info, last_err, print, strerr};
use crate::errno::{EINVAL, EIO, EKEYREJECTED};
use crate::sys::libc::close;
use crate::sys::sign::{SignIo, cms_sign};
use crate::util::crypto_openssl::{Cert, cert_free, cert_key_algorithm, cert_read_der};
use crate::util::keys::{keys_digest_der, keys_read_der, keys_vouch_payload};

/// The room a vouch's CMS signature gets.
const SIG_MAX: usize = 64 * 1024;
const PATH_MAX: usize = 4096;

fn usage(to_stdout: bool) {
    print(
        to_stdout,
        b"usage: shirudo-build keys vouch <cert.der> [-o <file>]
                [--keys-dir <dir>] [--key <signing_key.pem>]
                [--cert <cert.der>]

Sign a vouch for <cert.der> with the operator key, for
`shirudo keys add --vouch` on the targets that enrol this
key. -o defaults to <cert.der>.vouch.
",
    );
}

/// Whether the certificate's key is ML-DSA-87, the one algorithm
/// shirudo accepts.
fn algorithm_ok(der: &[u8], what: &CStr) -> c_int {
    let mut cert = Cert::new();
    let mut name = [0u8; 64];

    // SAFETY: the DER and the cert to fill.
    let ret = unsafe { cert_read_der(der.as_ptr(), der.len(), &mut cert) };
    if ret != 0 {
        error(&[what.to_bytes(), b" is not a certificate"].concat());
        return ret;
    }
    // SAFETY: the cert read above and room for the name; then freed.
    let ret = unsafe {
        let ret = cert_key_algorithm(&cert, name.as_mut_ptr().cast(), name.len());
        cert_free(&mut cert);
        ret
    };
    let name = crate::text::cstr(&name);
    if ret != 0 || name != b"ML-DSA-87" {
        let alg: &[u8] = if ret != 0 {
            b"of an unknown algorithm"
        } else {
            name
        };
        error(
            &[
                what.to_bytes(),
                b" is ",
                alg,
                b"; shirudo accepts only ML-DSA-87",
            ]
            .concat(),
        );
        return -EKEYREJECTED;
    }
    0
}

/// `data` at `path`, created or truncated, mode 0644; removed again if
/// any of it fails, its close included.
fn write_file(path: &CStr, data: &[u8]) -> c_int {
    let p = super::path(path.to_bytes());
    let file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .open(p);
    let mut file = match file {
        Ok(f) => f,
        Err(e) => return -e.raw_os_error().unwrap_or(EIO),
    };
    let mut ret = match file.write_all(data) {
        Ok(()) => 0,
        Err(e) => -e.raw_os_error().unwrap_or(EIO),
    };
    // SAFETY: the descriptor the file gives up.
    if unsafe { close(file.into_raw_fd()) } != 0 && ret == 0 {
        ret = last_err();
    }
    if ret != 0 {
        let _ = std::fs::remove_file(p);
    }
    ret
}

/// The DER at `path`.
fn read_der(path: &CStr) -> Result<Bytes, c_int> {
    let (mut der, mut len) = (ptr::null_mut(), 0);

    // SAFETY: a C string and room for the buffer and its length.
    match unsafe { keys_read_der(path.as_ptr(), &mut der, &mut len) } {
        0 => Ok(Bytes(der, len)),
        err => Err(err),
    }
}

/// The certificate's SHA-256 and the fingerprint of its key.
fn digests(der: &[u8]) -> Result<[u8; 32], c_int> {
    let (mut sha, mut fp) = ([0u8; 32], [0u8; 32]);

    // SAFETY: the DER and room for the two digests.
    match unsafe { keys_digest_der(der.as_ptr(), der.len(), sha.as_mut_ptr(), fp.as_mut_ptr()) } {
        0 => Ok(fp),
        err => Err(err),
    }
}

fn vouch(input: &CStr, output: &CStr, keys: &KeyFiles) -> c_int {
    let der = match read_der(input) {
        Ok(d) => d,
        Err(err) => {
            error(&[b"keys vouch: read ", input.to_bytes(), b": ", strerr(-err)].concat());
            return err;
        }
    };
    let Ok(fp) = digests(der.bytes()) else {
        error(&[b"keys vouch: ", input.to_bytes(), b" is not a certificate"].concat());
        return 1;
    };
    let ret = algorithm_ok(der.bytes(), input);
    if ret != 0 {
        return ret;
    }
    let own = match read_der(&keys.cert) {
        Ok(d) => d,
        Err(err) => {
            error(
                &[
                    b"keys vouch: read ",
                    keys.cert.to_bytes(),
                    b": ",
                    strerr(-err),
                ]
                .concat(),
            );
            return err;
        }
    };
    let Ok(own_fp) = digests(own.bytes()) else {
        error(
            &[
                b"keys vouch: ",
                keys.cert.to_bytes(),
                b" is not a certificate",
            ]
            .concat(),
        );
        return 1;
    };
    if fp == own_fp {
        error(
            &[
                b"keys vouch: ",
                input.to_bytes(),
                b" holds the signing key itself; a key cannot vouch for its own certificate",
            ]
            .concat(),
        );
        return -EINVAL;
    }
    let (mut payload, mut payload_len) = (ptr::null_mut(), 0);
    // SAFETY: the DER and room for the payload and its length.
    let ret = unsafe { keys_vouch_payload(der.0, der.1, &mut payload, &mut payload_len) };
    if ret != 0 {
        return ret;
    }
    let payload = Bytes(payload, payload_len);
    let mut signature = vec![0u8; SIG_MAX];
    let mut io = SignIo {
        insns: payload.0.cast_const().cast(),
        insns_sz: payload.1,
        data: ptr::null(),
        data_sz: 0,
        signature: signature.as_mut_ptr().cast(),
        signature_sz: signature.len(),
        payload_sha256: [0; 32],
    };
    // SAFETY: the payload, the room for the signature and C strings.
    let ret = unsafe { cms_sign(&mut io, keys.pkey.as_ptr(), keys.cert.as_ptr()) };
    if ret != 0 {
        error(&[b"keys vouch: sign: ", strerr(-ret)].concat());
        return ret;
    }
    let ret = write_file(output, &signature[..io.signature_sz]);
    if ret != 0 {
        error(
            &[
                b"keys vouch: write ",
                output.to_bytes(),
                b": ",
                strerr(-ret),
            ]
            .concat(),
        );
        return ret;
    }
    let (fp_hex, own_hex) = (hex(&fp), hex(&own_fp));
    info(
        &[
            b"keys vouch: ",
            &fp_hex[..],
            b" vouched for by ",
            &own_hex,
            b", written to ",
            output.to_bytes(),
        ]
        .concat(),
    );
    print(true, &[&fp_hex[..], b"\n"].concat());
    0
}

/// `shirudo-build keys vouch`, from `vouch` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let mut keys = KeyFiles::default();
    let (mut input, mut output): (Option<&CStr>, Option<&CStr>) = (None, None);
    let mut keys_dir = None;
    let mut i = 1;

    while i < args.len() {
        let a = args[i].to_bytes();
        let next = args.get(i + 1).copied();
        match (a, next) {
            (b"-o" | b"--output", Some(v)) => {
                output = Some(v);
                i += 1;
            }
            (b"--keys-dir", Some(v)) => {
                keys_dir = Some(v);
                i += 1;
            }
            (b"--key", Some(v)) => {
                keys.set_pkey(v);
                i += 1;
            }
            (b"--cert", Some(v)) => {
                keys.set_cert(v);
                i += 1;
            }
            _ if a.starts_with(b"--keys-dir=") => {
                keys_dir = CStr::from_bytes_with_nul(&args[i].to_bytes_with_nul()[11..]).ok()
            }
            (b"-h" | b"--help", _) => {
                usage(true);
                return 0;
            }
            _ if a.first() == Some(&b'-') => {
                error(&[b"keys vouch: unknown option '", a, b"'"].concat());
                usage(false);
                return 2;
            }
            _ if input.is_none() => input = Some(args[i]),
            _ => {
                error(&[b"keys vouch: unexpected argument '", a, b"'"].concat());
                return 2;
            }
        }
        i += 1;
    }
    let Some(input) = input else {
        usage(false);
        return 2;
    };
    if let Err((dir, _)) = keys.resolve(keys_dir) {
        error(&[b"invalid keys dir ", &dir[..]].concat());
        return 2;
    }
    if super::check_keys(&keys.pkey, &keys.cert) != 0 {
        return 1;
    }
    let derived;
    let output = match output {
        Some(o) => o,
        None => {
            let path = [input.to_bytes(), b".vouch"].concat();
            if path.len() >= PATH_MAX {
                error(b"keys vouch: output path too long");
                return 2;
            }
            derived = CString::new(path).unwrap_or_default();
            &derived
        }
    };
    if vouch(input, output, &keys) != 0 {
        1
    } else {
        0
    }
}
