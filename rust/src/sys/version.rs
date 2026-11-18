// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The build identity of `util/version.h`, which the generated
//! build/main/version_id.rs defines, an object of its own: each the
//! first byte of a C string.

use core::ffi::c_char;

unsafe extern "C" {
    pub static shirudo_version: c_char;
    pub static shirudo_version_id: c_char;
    pub static shirudo_extraversion: c_char;
    pub static shirudo_release_name: c_char;
}

/// The build identity a test build of the crate links, which has no
/// build/main/version_id.o: each a C string.
#[cfg(test)]
mod test_identity {
    #[unsafe(no_mangle)]
    static shirudo_version: [u8; 4] = *b"0.0\0";
    #[unsafe(no_mangle)]
    static shirudo_version_id: [u8; 65] =
        *b"0000000000000000000000000000000000000000000000000000000000000000\0";
    #[unsafe(no_mangle)]
    static shirudo_extraversion: [u8; 1] = *b"\0";
    #[unsafe(no_mangle)]
    static shirudo_release_name: [u8; 5] = *b"test\0";
}
