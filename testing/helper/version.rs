// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The version a test helper reports that does not link shirudo's own:
//! "test-1", which the OTLP tests find in the resource and scope.

#![no_std]

#[unsafe(no_mangle)]
pub static shirudo_version: [u8; 7] = *b"test-1\0";
