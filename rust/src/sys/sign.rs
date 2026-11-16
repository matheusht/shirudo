// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The CMS signer of `util/sign.h`, which only `shirudo-build` links.

use core::ffi::{c_char, c_int};

unsafe extern "C" {
    /// Opens the private key at `pkey_path` and checks, on that
    /// descriptor, that it is a regular file of mode 0600: the
    /// descriptor, or -errno logged.
    pub fn open_signing_key(pkey_path: *const c_char) -> c_int;
}
