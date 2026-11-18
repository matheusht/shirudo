// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

use super::*;
use crate::util::tamper::{point_meaning, point_name};

/// The same for enum integrity_point.
#[test]
fn integrity_counters_keep_their_places() {
    let order = [
        "ModuleSignature",
        "DevMem",
        "EfiTest",
        "KexecSignature",
        "PciAccess",
        "IoPort",
        "Msr",
        "AcpiTables",
        "DeviceTree",
        "PcmciaCis",
        "Tiocsserial",
        "ModuleParameters",
        "Mmiotrace",
        "Debugfs",
        "XmonWrite",
        "BpfWriteUser",
        "DbgWriteKernel",
        "RtasErrorInjection",
        "XenUserActions",
        "Kcore",
        "HibernateLocation",
        "Other",
    ];

    assert_eq!((order.len(), INTEGRITY_MAX), (22, 22));
    for (i, name) in order.iter().enumerate() {
        assert_eq!(point_name(&POINTS, i).to_bytes(), name.as_bytes(), "{i}");
        assert_ne!(point_meaning(&POINTS, i), c"?");
    }
    assert_eq!(point_name(&POINTS, INTEGRITY_MAX), c"?");
}
