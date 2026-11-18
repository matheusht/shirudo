// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

#[test]
fn bpffs_name_round_trips() {
    assert_eq!(pin_name(b"a.b..c"), b"a~db~d~dc");
    assert_eq!(name_from_pin(b"a~db~d~dc").as_deref(), Some(&b"a.b..c"[..]));
    assert_eq!(name_from_pin(b"a~x"), None);
    assert_eq!(name_from_pin(b"a~"), None);
}
