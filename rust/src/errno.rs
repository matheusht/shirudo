// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The errno values the C interface returns negated, the same on every
//! architecture shirudo supports.

use core::ffi::c_int;

pub const EPERM: c_int = 1;
pub const ENOENT: c_int = 2;
pub const EINTR: c_int = 4;
pub const EIO: c_int = 5;
pub const E2BIG: c_int = 7;
pub const EBADF: c_int = 9;
pub const EAGAIN: c_int = 11;
pub const ENOMEM: c_int = 12;
pub const EACCES: c_int = 13;
pub const EBUSY: c_int = 16;
pub const EINVAL: c_int = 22;
pub const EFBIG: c_int = 27;
pub const ENOSPC: c_int = 28;
pub const ERANGE: c_int = 34;
pub const ENAMETOOLONG: c_int = 36;
pub const EBADMSG: c_int = 74;
pub const EOVERFLOW: c_int = 75;
pub const EILSEQ: c_int = 84;
pub const EPROTONOSUPPORT: c_int = 93;
pub const EHOSTUNREACH: c_int = 113;
pub const EINPROGRESS: c_int = 115;
pub const ESTALE: c_int = 116;
pub const EUCLEAN: c_int = 117;
pub const ENOKEY: c_int = 126;
pub const EKEYREJECTED: c_int = 129;
