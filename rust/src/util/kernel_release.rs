// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The kernel release match.

use crate::text::at;

/// Whether `release` is `prefix` or goes on from it at a `.` or a `-`:
/// 6.12 matches 6.12, 6.12.3 and 6.12-rc1, not 6.120. Every release
/// matches an empty prefix.
pub(crate) fn prefix_matches(release: &[u8], prefix: &[u8]) -> bool {
    prefix.is_empty()
        || (release.starts_with(prefix) && matches!(at(release, prefix.len()), 0 | b'.' | b'-'))
}

#[cfg(test)]
mod tests;
