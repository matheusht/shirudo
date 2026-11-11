// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The errno values the C interface returns negated, the same on every
//! architecture shirudo supports.

use core::ffi::c_int;

pub const E2BIG: c_int = 7;
pub const ENOMEM: c_int = 12;
pub const EINVAL: c_int = 22;
pub const ENOSPC: c_int = 28;
pub const EILSEQ: c_int = 84;
