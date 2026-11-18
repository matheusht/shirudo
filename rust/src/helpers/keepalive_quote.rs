// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-keepalive-quote: a keepalive body file quoted with the TPM as
//! `status --otel` quotes its own body, printed as the row of
//! testing/fixtures/keepalive/quotes.tsv: the file name, attest, sig, ak
//! and body_sha256, tab-separated.
//!
//!   test-keepalive-quote <body>

use core::ffi::{CStr, c_int};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use super::{err, helper_main, out};
use crate::util::crypto_openssl::sha256;
use crate::util::keepalive::BODY_MAX;
use crate::util::keepalive_quote::quote;

helper_main!(shirudo_helper_test_keepalive_quote, run);

/// The values of `attest=...;sig=...;ak=...`.
fn quote_values(quote: &str) -> Option<[&str; 3]> {
    let mut fields = quote.split(';');
    let mut values = [""; 3];
    for (value, key) in values.iter_mut().zip(["attest=", "sig=", "ak="]) {
        *value = fields.next()?.strip_prefix(key)?;
    }
    fields.next().is_none().then_some(values)
}

fn strerror(e: c_int) -> String {
    // SAFETY: the C library's text for an errno, static.
    unsafe { CStr::from_ptr(crate::sys::libc::strerror(e)) }
        .to_string_lossy()
        .into_owned()
}

fn print_row(path: &str, body: &[u8]) -> Result<(), c_int> {
    let text = quote(body).inspect_err(|&e| err(&format!("quote {path}: {}\n", strerror(-e))))?;
    let text = String::from_utf8_lossy(crate::text::cstr(&text)).into_owned();
    let [attest, sig, ak] = quote_values(&text).ok_or_else(|| {
        err(&format!("quote {path}: not attest=;sig=;ak=\n"));
        -crate::errno::EINVAL
    })?;
    let hash = crate::util::hex::encode(&sha256(body)?);
    let name = path.rsplit('/').next().unwrap_or(path);
    out(&format!(
        "{name}\t{attest}\t{sig}\t{ak}\t{}\n",
        String::from_utf8_lossy(&hash)
    ));
    Ok(())
}

fn run(args: &[&CStr]) -> c_int {
    let [_, path] = args else {
        let me = args
            .first()
            .map_or("test-keepalive-quote".into(), |a| a.to_string_lossy());
        err(&format!("usage: {me} <body>\n"));
        return 2;
    };
    let shown = path.to_string_lossy();
    let read = match std::fs::read(OsStr::from_bytes(path.to_bytes())) {
        Ok(body) if body.len() < BODY_MAX => Ok(body),
        Ok(_) => Err(crate::errno::EFBIG),
        Err(e) => Err(e.raw_os_error().unwrap_or(crate::errno::EIO)),
    };
    match read {
        Ok(body) => c_int::from(print_row(&shown, &body).is_err()),
        Err(e) => {
            err(&format!("read {shown}: {}\n", strerror(e)));
            1
        }
    }
}
