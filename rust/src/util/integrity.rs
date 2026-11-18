// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The integrity counters: what lockdown in integrity mode refused this
//! boot, one counter per reason, read back from the map init pinned in
//! the private bpffs. The tamper counters account for attempts on
//! shirudo's own state; these guard the running kernel.

use core::ffi::{CStr, c_int};

use crate::util::tamper::{Counters, Point, counters_read, point_meaning, point_name};

/// `INTEGRITY_MAX` of `bpf/lib/integrity.h`: the integrity points there
/// are.
pub(crate) const INTEGRITY_MAX: usize = 22;
/// INTEGRITY_PIN of util/paths.h.
pub(crate) const INTEGRITY_PIN: &CStr = c"/run/shirudo/bpffs/integrity";

pub(crate) type IntegrityCounts = Counters<INTEGRITY_MAX>;

/// Each point, in the order of `enum integrity_point` of
/// bpf/lib/integrity.h, under the member's name, which t6003 checks
/// against the header.
const POINTS: [Point; INTEGRITY_MAX] = [
    // INTEGRITY_MODULE_SIGNATURE
    Point {
        name: "ModuleSignature",
        meaning: "module load without a valid signature",
    },
    // INTEGRITY_DEV_MEM
    Point {
        name: "DevMem",
        meaning: "/dev/mem or /dev/port",
    },
    // INTEGRITY_EFI_TEST
    Point {
        name: "EfiTest",
        meaning: "EFI runtime services through efi_test",
    },
    // INTEGRITY_KEXEC
    Point {
        name: "KexecSignature",
        meaning: "kexec of a kernel without a valid signature",
    },
    // INTEGRITY_PCI_ACCESS
    Point {
        name: "PciAccess",
        meaning: "PCI configuration write or BAR mapping",
    },
    // INTEGRITY_IOPORT
    Point {
        name: "IoPort",
        meaning: "raw I/O port access",
    },
    // INTEGRITY_MSR
    Point {
        name: "Msr",
        meaning: "model-specific register write",
    },
    // INTEGRITY_ACPI_TABLES
    Point {
        name: "AcpiTables",
        meaning: "ACPI table override or custom method",
    },
    // INTEGRITY_DEVICE_TREE
    Point {
        name: "DeviceTree",
        meaning: "device tree overlay",
    },
    // INTEGRITY_PCMCIA_CIS
    Point {
        name: "PcmciaCis",
        meaning: "PCMCIA CIS override",
    },
    // INTEGRITY_TIOCSSERIAL
    Point {
        name: "Tiocsserial",
        meaning: "serial port I/O or IRQ reconfiguration",
    },
    // INTEGRITY_MODULE_PARAMETERS
    Point {
        name: "ModuleParameters",
        meaning: "module parameter that sets hardware addresses",
    },
    // INTEGRITY_MMIOTRACE
    Point {
        name: "Mmiotrace",
        meaning: "MMIO tracing",
    },
    // INTEGRITY_DEBUGFS
    Point {
        name: "Debugfs",
        meaning: "debugfs file that writes or maps",
    },
    // INTEGRITY_XMON_WR
    Point {
        name: "XmonWrite",
        meaning: "xmon write access",
    },
    // INTEGRITY_BPF_WRITE_USER
    Point {
        name: "BpfWriteUser",
        meaning: "BPF program that writes user memory",
    },
    // INTEGRITY_DBG_WRITE_KERNEL
    Point {
        name: "DbgWriteKernel",
        meaning: "kernel debugger write",
    },
    // INTEGRITY_RTAS_ERROR_INJECTION
    Point {
        name: "RtasErrorInjection",
        meaning: "RTAS error injection",
    },
    // INTEGRITY_XEN_USER_ACTIONS
    Point {
        name: "XenUserActions",
        meaning: "Xen user action that writes memory",
    },
    // INTEGRITY_KCORE
    Point {
        name: "Kcore",
        meaning: "/proc/kcore, the kernel's memory",
    },
    // INTEGRITY_HIBERNATE_LOCATION
    Point {
        name: "HibernateLocation",
        meaning: "EFI variable naming a resume device",
    },
    // INTEGRITY_OTHER
    Point {
        name: "Other",
        meaning: "lockdown reason this build does not name",
    },
];

/// The name of integrity point `point`, "?" past the last.
pub(crate) fn name(point: usize) -> &'static [u8] {
    point_name(&POINTS, point)
}

/// What integrity point `point` counts, "?" past the last.
pub(crate) fn meaning(point: usize) -> &'static [u8] {
    point_meaning(&POINTS, point)
}

/// The integrity counters, as tamper::read() reads the tamper counters.
pub(crate) fn read() -> Result<IntegrityCounts, c_int> {
    counters_read(INTEGRITY_PIN)
}
