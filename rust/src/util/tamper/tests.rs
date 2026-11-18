// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;

/// The backend reads a counter by its place in the array: a counter is
/// appended to enum tamper_point and to this table, never put between
/// two.
#[test]
fn tamper_counters_keep_their_places() {
    let order = [
        "LoadNotLoader",
        "LoadUnsigned",
        "LoadUnverified",
        "LoadKeyringKind",
        "LoadKeyring",
        "MapCreate",
        "MapWrite",
        "MapFdWrite",
        "ProgRun",
        "ProgAttach",
        "ObjPin",
        "BpfCommand",
        "ExeIdentity",
        "KeyringWrite",
        "PinUnlink",
        "PinRename",
        "PinXattr",
        "BpffsUmount",
        "BpffsUmountAbove",
        "BpffsMount",
        "SealWrite",
        "SealUnlink",
        "SealRename",
        "SealSetattr",
        "SealXattr",
        "SealLabel",
        "SealPtrace",
        "SealPerf",
        "ExecTraced",
        "SealEntry",
        "PerfAttach",
        "PinEntry",
        "SealCopyUp",
        "Kexec",
        "TpmExtend",
        "ObjGet",
        "SealSignal",
        "SealCoreDump",
        "SealUprobe",
        "ExecShared",
        "XattrHandle",
        "SealRlimit",
        "TpmWrite",
    ];

    assert_eq!((order.len(), TAMPER_MAX), (43, 43));
    for (i, name) in order.iter().enumerate() {
        assert_eq!(point_name(&POINTS, i).to_bytes(), name.as_bytes(), "{i}");
    }
}
