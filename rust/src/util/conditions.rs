// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The local security conditions `shirudo status` shows, behind
//! `util/conditions.h`: one condition for each guarantee, and the
//! verdict and reason that sum them up.

use core::ffi::{CStr, c_char, c_int};

use crate::errno::{EINPROGRESS, EKEYREJECTED, ENOENT, ESTALE};
use crate::sys::libc::{printf, snprintf, strerror};
use crate::text::strscpy;

/// `struct conditions_input`: what the status JSON said, its `*_seen`
/// flags telling whether it carried a value that was not null.
#[repr(C)]
pub struct ConditionsInput {
    reachable: bool,
    parsed: bool,
    unreach: *const c_char,
    lsm_attached: c_int,
    keyring_present: c_int,
    keyring_mode: *const c_char,
    keyring_serial: i64,
    keyring_serial_pinned: i64,
    keyring_serial_matches: c_int,
    ks_seen: c_int,
    ksp_seen: c_int,
    ksm_seen: c_int,
    bpf_unfrozen: c_int,
    dmv_present: c_int,
    dmv_serial: i64,
    dmv_serial_pinned: i64,
    dmv_serial_matches: c_int,
    dmvp_seen: c_int,
    dmvm_seen: c_int,
    dmv_unfrozen: c_int,
    dmv_key_missing: c_int,
    tpm_reachable: c_int,
    chain_seen: c_int,
    chain_matches: c_int,
    cm_seen: c_int,
    nv_index: *const c_char,
    config_seen: c_int,
    config_state: c_int,
    config_root: *const c_char,
    pins_rc: c_int,
    pins_unmeasured: c_int,
    pins_detail: *const c_char,
}

const _: () = assert!(size_of::<ConditionsInput>() == 168);
const _: () = assert!(core::mem::offset_of!(ConditionsInput, keyring_serial) == 32);
const _: () = assert!(core::mem::offset_of!(ConditionsInput, nv_index) == 128);
const _: () = assert!(core::mem::offset_of!(ConditionsInput, pins_detail) == 160);

/// `struct condition`.
#[repr(C)]
pub struct Condition {
    kind: *const c_char,
    status: *const c_char,
    detail: [u8; 192],
}

const _: () = assert!(size_of::<Condition>() == 208);

/// `CONDITIONS_MAX`: the conditions there are.
const CONDITIONS_MAX: usize = 6;

const OK: &CStr = c"OK";
const WARN: &CStr = c"WARN";
const ALERT: &CStr = c"ALERT";

/// The status and the detail of a condition, the detail as snprintf()
/// prints the format and its arguments, or "?" when that does not fit.
macro_rules! set_detail {
    ($c:expr, $status:expr, $fmt:expr $(, $arg:expr)* $(,)?) => {{
        let c: &mut Condition = $c;

        c.status = $status.as_ptr();
        // SAFETY: the room of the detail, and a format whose
        // conversions take the arguments given, in their C types.
        let n = unsafe { snprintf(c.detail.as_mut_ptr().cast(), c.detail.len(), $fmt.as_ptr() $(, $arg)*) };

        if n < 0 || n as usize >= c.detail.len() {
            c.detail[0] = 0;
            let _ = strscpy(&mut c.detail, b"?");
        }
    }};
}

/// What a nullable C string field holds, or `?` for NULL.
fn or_unknown(s: *const c_char) -> *const c_char {
    if s.is_null() { c"?".as_ptr() } else { s }
}

fn config_untrusted(i: &ConditionsInput) -> bool {
    i.config_seen != 0 && i.config_state != 0 && i.config_state != -EINPROGRESS
}

fn config_untrusted_detail(state: c_int) -> &'static CStr {
    if state == -ESTALE {
        c"the config activation record does not belong to this TPM boot"
    } else if state == -EKEYREJECTED {
        c"the mounted config does not match the selected root"
    } else {
        c"the config PCR, activation records and mounted config disagree"
    }
}

fn keyring_tampered(i: &ConditionsInput) -> bool {
    (i.ksp_seen != 0 && i.keyring_present == 0)
        || (i.ksm_seen != 0 && i.keyring_serial_matches == 0)
        || (i.dmvp_seen != 0 && i.dmv_present == 0)
        || (i.dmvm_seen != 0 && i.dmv_serial_matches == 0)
        || i.bpf_unfrozen != 0
        || i.dmv_unfrozen != 0
        || i.dmv_key_missing != 0
}

/// "" for one link, "s" for more.
fn plural(n: c_int) -> *const c_char {
    if n == 1 { c"".as_ptr() } else { c"s".as_ptr() }
}

fn keyring_condition(i: &ConditionsInput, c: &mut Condition) {
    c.kind = c"KeyringSealed".as_ptr();
    if i.keyring_present == 0 && i.ksp_seen != 0 {
        set_detail!(
            c,
            ALERT,
            c"pinned serial %lld, the .bpf keyring is gone",
            i.keyring_serial_pinned
        );
    } else if i.keyring_present == 0 {
        set_detail!(c, WARN, c".bpf keyring absent before init");
    } else if i.ksm_seen != 0 && i.keyring_serial_matches == 0 {
        set_detail!(
            c,
            ALERT,
            c"pinned serial %lld, live serial %lld: swapped",
            i.keyring_serial_pinned,
            i.keyring_serial,
        );
    } else if i.bpf_unfrozen != 0 {
        set_detail!(
            c,
            ALERT,
            c"the BPF keyring holds %d link%s init did not freeze",
            i.bpf_unfrozen,
            plural(i.bpf_unfrozen),
        );
    } else if i.dmvp_seen != 0 && i.dmv_present == 0 {
        set_detail!(
            c,
            ALERT,
            c"dm-verity pinned serial %lld, the dm-verity keyring is gone",
            i.dmv_serial_pinned,
        );
    } else if i.dmvm_seen != 0 && i.dmv_serial_matches == 0 {
        set_detail!(
            c,
            ALERT,
            c"dm-verity pinned serial %lld, live serial %lld: swapped",
            i.dmv_serial_pinned,
            i.dmv_serial,
        );
    } else if i.dmv_unfrozen != 0 {
        set_detail!(
            c,
            ALERT,
            c"the dm-verity keyring holds %d link%s init did not freeze",
            i.dmv_unfrozen,
            plural(i.dmv_unfrozen),
        );
    } else if i.dmv_key_missing != 0 {
        set_detail!(
            c,
            ALERT,
            c"the config key init froze is gone from the dm-verity keyring"
        );
    } else if i.ksp_seen != 0 && i.dmvp_seen != 0 {
        set_detail!(
            c,
            OK,
            c"bpf serial %lld, dm-verity serial %lld, pins match",
            i.keyring_serial,
            i.dmv_serial,
        );
    } else {
        let pin = if i.ksp_seen != 0 {
            c"pin matches"
        } else {
            c"no pin recorded"
        };

        set_detail!(
            c,
            OK,
            c"bpf serial %lld, %s",
            i.keyring_serial,
            pin.as_ptr()
        );
    }
}

/// A condition whose detail is fixed text.
fn set_fixed(c: &mut Condition, status: &CStr, detail: &CStr) {
    c.status = status.as_ptr();
    let _ = strscpy(&mut c.detail, detail.to_bytes());
}

/// The conditions, as many as `out` holds, in their order: LsmAttached,
/// KeyringSealed, ChainIntact, UpatchesMeasured, TpmMeasured and
/// ConfigActive; returns how many it wrote.
fn conditions(i: &ConditionsInput, out: &mut [Condition]) -> usize {
    let n = out.len().min(CONDITIONS_MAX);
    let mut it = out[..n].iter_mut();

    if let Some(c) = it.next() {
        c.kind = c"LsmAttached".as_ptr();
        if i.lsm_attached != 0 {
            set_fixed(c, OK, c"lsm/bpf link present and pinned");
        } else {
            set_fixed(c, ALERT, c"lsm/bpf link absent, enforcement off");
        }
    }
    if let Some(c) = it.next() {
        keyring_condition(i, c);
    }
    if let Some(c) = it.next() {
        c.kind = c"ChainIntact".as_ptr();
        if i.chain_seen == 0 {
            let detail = if i.tpm_reachable != 0 {
                c"no register bound this boot (init incomplete)"
            } else {
                c"no TPM answered, no register to replay"
            };

            set_fixed(c, WARN, detail);
        } else if i.cm_seen != 0 && i.chain_matches != 0 {
            set_fixed(c, OK, c"live register equals the eventlog replay");
        } else if i.cm_seen != 0 {
            set_fixed(c, ALERT, c"live register differs from the eventlog replay");
        } else {
            set_fixed(c, WARN, c"chain present, replay not evaluated");
        }
    }
    if let Some(c) = it.next() {
        c.kind = c"UpatchesMeasured".as_ptr();
        if i.pins_rc == -ENOENT {
            set_detail!(c, WARN, c"no record of this boot to check the pins against");
        } else if i.pins_rc != 0 {
            // SAFETY: a call that takes no pointer.
            let reason = unsafe { strerror(-i.pins_rc) };

            set_detail!(c, WARN, c"pins not checked against the records: %s", reason);
        } else if i.pins_unmeasured != 0 {
            set_detail!(
                c,
                ALERT,
                c"%d pinned or archived without a record of this boot: %s",
                i.pins_unmeasured,
                or_unknown(i.pins_detail),
            );
        } else {
            set_detail!(
                c,
                OK,
                c"every pinned or archived upatch is in this boot's records"
            );
        }
    }
    if let Some(c) = it.next() {
        c.kind = c"TpmMeasured".as_ptr();
        if i.chain_seen != 0 {
            set_detail!(c, OK, c"NV index %s readable", or_unknown(i.nv_index));
        } else if i.tpm_reachable != 0 {
            set_detail!(
                c,
                WARN,
                c"NV index %s not bound this boot",
                or_unknown(i.nv_index)
            );
        } else {
            set_fixed(c, WARN, c"no TPM answered");
        }
    }
    if let Some(c) = it.next() {
        let root = or_unknown(i.config_root);

        c.kind = c"ConfigActive".as_ptr();
        if i.config_seen == 0 {
            set_fixed(c, WARN, c"no config activation state before init");
        } else if i.config_state == -EINPROGRESS {
            set_detail!(
                c,
                WARN,
                c"the activation of config %.12s.. is pending until the next reboot",
                root,
            );
        } else if config_untrusted(i) {
            set_fixed(c, ALERT, config_untrusted_detail(i.config_state));
        } else {
            set_detail!(c, OK, c"config %.12s.. is active", root);
        }
    }
    n
}

/// The conditions as the table `shirudo status` prints.
fn conditions_print(conds: &[Condition]) {
    let row = c"  %-18s %-7s %s\n";

    // SAFETY: formats of C strings, and the conditions' strings.
    unsafe {
        printf(c"Conditions:\n".as_ptr());
        printf(
            row.as_ptr(),
            c"TYPE".as_ptr(),
            c"STATUS".as_ptr(),
            c"DETAIL".as_ptr(),
        );
        for c in conds {
            printf(row.as_ptr(), c.kind, c.status, c.detail.as_ptr());
        }
    }
}

/// The verdict in one word, from worst to best: unreachable,
/// unparseable, tampered, lsm-off, init-pending, reboot-pending,
/// degraded, ok.
fn status_verdict(i: &ConditionsInput) -> &'static CStr {
    if !i.reachable {
        c"unreachable"
    } else if !i.parsed {
        c"unparseable"
    } else if (i.cm_seen != 0 && i.chain_matches == 0)
        || i.pins_unmeasured != 0
        || keyring_tampered(i)
        || config_untrusted(i)
    {
        c"tampered"
    } else if i.lsm_attached == 0 {
        c"lsm-off"
    } else if i.keyring_present == 0 {
        c"init-pending"
    } else if i.config_seen != 0 && i.config_state == -EINPROGRESS {
        c"reboot-pending"
    } else if i.chain_seen == 0 {
        c"degraded"
    } else {
        c"ok"
    }
}

/// Why the verdict is what it is, into `buf`; empty for ok, and for an
/// unreachable status without a reason.
///
/// # Safety
///
/// `i.unreach` is NULL or a C string.
unsafe fn status_reason(i: &ConditionsInput, buf: &mut [u8]) {
    let verdict = status_verdict(i).to_bytes();
    let reason: Option<&[u8]> = match verdict {
        b"unreachable" if !i.unreach.is_null() => {
            // SAFETY: the caller passes a C string.
            Some(unsafe { CStr::from_ptr(i.unreach) }.to_bytes())
        }
        b"unparseable" => Some(b"status JSON unparseable"),
        b"tampered" => Some(if i.cm_seen != 0 && i.chain_matches == 0 {
            b"live register differs from the eventlog replay"
        } else if i.pins_unmeasured != 0 {
            b"a upatch is pinned or archived without a record of this boot"
        } else if config_untrusted(i) {
            b"the selected config cannot be verified against its records"
        } else if i.ksp_seen != 0 && i.keyring_present == 0 {
            b"the keyring init froze is gone"
        } else if i.ksm_seen != 0 && i.keyring_serial_matches == 0 {
            b"keyring serial swap detected"
        } else if i.dmvp_seen != 0 && i.dmv_present == 0 {
            b"the dm-verity keyring init froze is gone"
        } else if i.dmvm_seen != 0 && i.dmv_serial_matches == 0 {
            b"dm-verity keyring serial swap detected"
        } else if i.bpf_unfrozen != 0 || i.dmv_unfrozen != 0 {
            b"a keyring holds a link init did not freeze"
        } else {
            b"the config key init froze is gone"
        }),
        b"lsm-off" => Some(b"LSM not attached, enforcement off"),
        b"init-pending" => Some(b".bpf keyring absent before init"),
        b"reboot-pending" => Some(b"a config activation is pending until the next reboot"),
        b"degraded" => Some(if i.tpm_reachable != 0 {
            b"no register bound this boot"
        } else {
            b"no TPM answered"
        }),
        _ => None,
    };

    if let Some(first) = buf.first_mut() {
        *first = 0;
    }
    if let Some(reason) = reason {
        let _ = strscpy(buf, reason);
    }
}

mod capi {
    use core::ffi::c_char;

    use super::{Condition, ConditionsInput};
    use crate::ffi;

    /// # Safety
    ///
    /// `input` points to an input whose strings are NULL or C strings,
    /// and `out` has room for `cap` conditions.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn conditions(
        input: *const ConditionsInput,
        out: *mut Condition,
        cap: usize,
    ) -> usize {
        let n = cap.min(super::CONDITIONS_MAX);
        let out = if n == 0 {
            &mut [][..]
        } else {
            // SAFETY: the caller passes room for cap conditions, of
            // which the first n are written here before anything reads
            // them.
            unsafe { core::slice::from_raw_parts_mut(out, n) }
        };

        // SAFETY: the caller passes an input.
        super::conditions(unsafe { &*input }, out)
    }

    /// # Safety
    ///
    /// `c` holds `n` conditions.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn conditions_print(c: *const Condition, n: usize) {
        // SAFETY: the caller passes the conditions.
        super::conditions_print(unsafe { ffi::slice(c, n) })
    }

    /// # Safety
    ///
    /// `input` points to an input.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn status_verdict(input: *const ConditionsInput) -> *const c_char {
        // SAFETY: the caller passes an input.
        super::status_verdict(unsafe { &*input }).as_ptr()
    }

    /// # Safety
    ///
    /// `input` points to an input whose strings are NULL or C strings,
    /// and `buf` has room for `cap` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn status_reason(
        input: *const ConditionsInput,
        buf: *mut c_char,
        cap: usize,
    ) {
        // SAFETY: the caller passes an input and the room.
        unsafe { super::status_reason(&*input, ffi::bytes_mut(buf.cast(), cap)) }
    }
}
