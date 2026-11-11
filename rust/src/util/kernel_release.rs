// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The kernel release match behind `util/kernel_release.h`.

use crate::text::at;

/// Whether `release` is `prefix` or goes on from it at a `.` or a `-`:
/// 6.12 matches 6.12, 6.12.3 and 6.12-rc1, not 6.120. Every release
/// matches an empty prefix.
pub(crate) fn prefix_matches(release: &[u8], prefix: &[u8]) -> bool {
    prefix.is_empty()
        || (release.starts_with(prefix) && matches!(at(release, prefix.len()), 0 | b'.' | b'-'))
}

mod capi {
    use core::ffi::c_char;

    use super::prefix_matches;
    use crate::ffi;

    /// # Safety
    ///
    /// `release` and `prefix` are NULL or C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn kernel_release_prefix_matches(
        release: *const c_char,
        prefix: *const c_char,
    ) -> bool {
        if release.is_null() || prefix.is_null() {
            return false;
        }
        // SAFETY: the caller passes two C strings.
        unsafe { prefix_matches(ffi::c_str(release), ffi::c_str(prefix)) }
    }
}
