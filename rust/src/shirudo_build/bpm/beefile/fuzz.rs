// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-beefile: a Beefile parsed as bpm build reads it. Of one taken,
//! each tree entry's fixes are what the publisher may emit, valid IDs in
//! byte order, each once, or the process aborts.

use crate::fuzzing::fuzz_target;

fuzz_target!(shirudo_fuzz_beefile, shirudo_fuzz_beefile_init, |data| {
    let mut spec = super::Spec::default();
    if super::parse(data, &mut spec) != 0 {
        return;
    }
    for u in &spec.upatches {
        let fixes = &u.tree.fixes;
        if fixes.len() > super::MAX_FIXES
            || !fixes.iter().all(|id| super::fix_id_ok(id))
            || !fixes.windows(2).all(|w| w[0] < w[1])
        {
            std::process::abort();
        }
    }
});
