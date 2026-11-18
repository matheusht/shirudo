// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-image-cleanup: the retry of a candidate mapping's removal for
//! t5005, with a removal that answers as the argument says and the pauses
//! between attempts counted.
//!
//!   test-image-cleanup immediate|transient|persistent|io|permission

use core::cell::Cell;
use core::ffi::{CStr, c_int};
use std::time::Duration;

use super::{helper_main, out};
use crate::errno::{EBUSY, EIO, EPERM};
use crate::util::image_runtime::retry_busy_with;

helper_main!(shirudo_helper_test_image_cleanup, run);

fn run(args: &[&CStr]) -> c_int {
    // Removals answer EBUSY this often, then this; so many removals and
    // what the retry gives are expected.
    let (busy, result, expected_calls, expected) =
        match (args.len(), args.get(1).map(|a| a.to_bytes())) {
            (2, Some(b"immediate")) => (0, 0, 1, 0),
            (2, Some(b"transient")) => (2, 0, 3, 0),
            (2, Some(b"persistent")) => (100, 0, 100, -EBUSY),
            (2, Some(b"io")) => (0, -EIO, 1, -EIO),
            (2, Some(b"permission")) => (0, -EPERM, 1, -EPERM),
            _ => return 2,
        };
    let (removes, sleeps, invalid) = (Cell::new(0u32), Cell::new(0u32), Cell::new(false));
    let ret = retry_busy_with(
        || {
            // A removal follows the pause after the one before.
            if removes.get() != sleeps.get() {
                invalid.set(true);
            }
            removes.set(removes.get() + 1);
            if removes.get() <= busy {
                -EBUSY
            } else {
                result
            }
        },
        |pause: Duration| {
            if pause != Duration::from_millis(10) || removes.get() != sleeps.get() + 1 {
                invalid.set(true);
            }
            sleeps.set(sleeps.get() + 1);
        },
    );
    let (removes, sleeps, invalid) = (removes.get(), sleeps.get(), invalid.get());
    out(&format!(
        "rc={ret} removes={removes} sleeps={sleeps} invalid={}\n",
        c_int::from(invalid)
    ));
    c_int::from(
        ret != expected || removes != expected_calls || sleeps != expected_calls - 1 || invalid,
    )
}
