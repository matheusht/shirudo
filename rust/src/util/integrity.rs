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
        name: c"ModuleSignature",
        meaning: c"module load without a valid signature",
    },
    // INTEGRITY_DEV_MEM
    Point {
        name: c"DevMem",
        meaning: c"/dev/mem or /dev/port",
    },
    // INTEGRITY_EFI_TEST
    Point {
        name: c"EfiTest",
        meaning: c"EFI runtime services through efi_test",
    },
    // INTEGRITY_KEXEC
    Point {
        name: c"KexecSignature",
        meaning: c"kexec of a kernel without a valid signature",
    },
    // INTEGRITY_PCI_ACCESS
    Point {
        name: c"PciAccess",
        meaning: c"PCI configuration write or BAR mapping",
    },
    // INTEGRITY_IOPORT
    Point {
        name: c"IoPort",
        meaning: c"raw I/O port access",
    },
    // INTEGRITY_MSR
    Point {
        name: c"Msr",
        meaning: c"model-specific register write",
    },
    // INTEGRITY_ACPI_TABLES
    Point {
        name: c"AcpiTables",
        meaning: c"ACPI table override or custom method",
    },
    // INTEGRITY_DEVICE_TREE
    Point {
        name: c"DeviceTree",
        meaning: c"device tree overlay",
    },
    // INTEGRITY_PCMCIA_CIS
    Point {
        name: c"PcmciaCis",
        meaning: c"PCMCIA CIS override",
    },
    // INTEGRITY_TIOCSSERIAL
    Point {
        name: c"Tiocsserial",
        meaning: c"serial port I/O or IRQ reconfiguration",
    },
    // INTEGRITY_MODULE_PARAMETERS
    Point {
        name: c"ModuleParameters",
        meaning: c"module parameter that sets hardware addresses",
    },
    // INTEGRITY_MMIOTRACE
    Point {
        name: c"Mmiotrace",
        meaning: c"MMIO tracing",
    },
    // INTEGRITY_DEBUGFS
    Point {
        name: c"Debugfs",
        meaning: c"debugfs file that writes or maps",
    },
    // INTEGRITY_XMON_WR
    Point {
        name: c"XmonWrite",
        meaning: c"xmon write access",
    },
    // INTEGRITY_BPF_WRITE_USER
    Point {
        name: c"BpfWriteUser",
        meaning: c"BPF program that writes user memory",
    },
    // INTEGRITY_DBG_WRITE_KERNEL
    Point {
        name: c"DbgWriteKernel",
        meaning: c"kernel debugger write",
    },
    // INTEGRITY_RTAS_ERROR_INJECTION
    Point {
        name: c"RtasErrorInjection",
        meaning: c"RTAS error injection",
    },
    // INTEGRITY_XEN_USER_ACTIONS
    Point {
        name: c"XenUserActions",
        meaning: c"Xen user action that writes memory",
    },
    // INTEGRITY_KCORE
    Point {
        name: c"Kcore",
        meaning: c"/proc/kcore, the kernel's memory",
    },
    // INTEGRITY_HIBERNATE_LOCATION
    Point {
        name: c"HibernateLocation",
        meaning: c"EFI variable naming a resume device",
    },
    // INTEGRITY_OTHER
    Point {
        name: c"Other",
        meaning: c"lockdown reason this build does not name",
    },
];

/// The name of integrity point `point`, "?" past the last.
pub(crate) fn name(point: usize) -> &'static [u8] {
    point_name(&POINTS, point).to_bytes()
}

/// What integrity point `point` counts, "?" past the last.
pub(crate) fn meaning(point: usize) -> &'static [u8] {
    point_meaning(&POINTS, point).to_bytes()
}

/// The integrity counters, as tamper::read() reads the tamper counters.
pub(crate) fn read() -> Result<IntegrityCounts, c_int> {
    counters_read(INTEGRITY_PIN)
}

mod capi {
    use core::ffi::c_char;

    use super::POINTS;
    use crate::util::tamper::{point_meaning, point_name};

    #[unsafe(no_mangle)]
    pub extern "C" fn integrity_name(point: u32) -> *const c_char {
        point_name(&POINTS, point as usize).as_ptr()
    }

    #[unsafe(no_mangle)]
    pub extern "C" fn integrity_meaning(point: u32) -> *const c_char {
        point_meaning(&POINTS, point as usize).as_ptr()
    }
}

#[cfg(test)]
mod tests;
