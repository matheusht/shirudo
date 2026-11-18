// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config's history as attestation evidence:
//! collected from the update records, emitted
//! with a quote, parsed back by a verifier, and checked there against
//! the quoted PCR, the TPM boot and the root an operator approved.

use core::ffi::{CStr, c_int, c_void};

use crate::errno::{E2BIG, EINVAL, EKEYREJECTED, ENOMEM, EOVERFLOW, EUCLEAN};
use crate::heap::{xfree, xreallocarray};
use crate::text::cstr;
use crate::util::chain::fold;
use crate::util::config_measure::{
    EVENT_BOOT, EVENT_UPDATE, event as measure_event, nvpcr, nvpcr_initial, pcr_valid,
};
use crate::util::config_update::{
    ConfigUpdate, ConfigUpdateRecord, config_update_check, config_update_events,
};
use crate::util::hex::{hex_decode, hex_encode};
use crate::util::json::{JsonEmit, JsonField, parse_schema};

/// `CONFIG_EVIDENCE_EVENTS_MAX`.
const EVENTS_MAX: usize = 4096;

/// `struct config_evidence_event`.
#[repr(C)]
pub struct EvidenceEvent {
    root_hash: [u8; 32],
    sequence: u64,
    kind: c_int,
}

const _: () = assert!(size_of::<EvidenceEvent>() == 48);

/// `struct config_evidence`.
#[repr(C)]
pub struct Evidence {
    events: *mut EvidenceEvent,
    initial_pcr: [u8; 32],
    pub(crate) value: [u8; 32],
    pub(crate) n_events: usize,
    capacity: usize,
    pub(crate) reset_count: u32,
    pub(crate) restart_count: u32,
    pub(crate) pcr: u32,
    pub(crate) present: bool,
}

const _: () = assert!(size_of::<Evidence>() == 104);
const _: () = assert!(core::mem::offset_of!(Evidence, present) == 100);

/// The view zeroed whole, padding too.
///
/// # Safety
///
/// `view` points to room for a view.
unsafe fn zero(view: *mut Evidence) {
    // SAFETY: the caller passes the room.
    unsafe { view.write_bytes(0, 1) };
}

fn append_event(view: &mut Evidence, root_hash: &[u8; 32], sequence: u64, kind: c_int) -> c_int {
    if view.n_events >= EVENTS_MAX {
        return -E2BIG;
    }
    if view.n_events == view.capacity {
        let capacity = if view.capacity != 0 {
            view.capacity * 2
        } else {
            16
        };
        // SAFETY: the events so far, from xreallocarray() or NULL.
        let events: *mut EvidenceEvent = unsafe {
            xreallocarray(
                view.events.cast(),
                view.capacity,
                capacity,
                size_of::<EvidenceEvent>(),
            )
        }
        .cast();

        if events.is_null() {
            return -ENOMEM;
        }
        view.events = events;
        view.capacity = capacity;
    }
    // SAFETY: room for entry n_events, zeroed whole, then filled field
    // by field as the C's assignment of a zeroed local left it.
    unsafe {
        let e = view.events.add(view.n_events);

        e.write_bytes(0, 1);
        (*e).root_hash = *root_hash;
        (*e).sequence = sequence;
        (*e).kind = kind;
    }
    view.n_events += 1;
    0
}

/// The events of the view.
fn events(view: &Evidence) -> &[EvidenceEvent] {
    if view.events.is_null() {
        return &[];
    }
    // SAFETY: n_events entries at events, which append_event() wrote.
    unsafe { core::slice::from_raw_parts(view.events, view.n_events) }
}

/// The PCR the events fold to from the initial value: 0, -EINVAL for no
/// events, -EKEYREJECTED for a history out of order.
fn replay(view: &Evidence, out: &mut [u8; 32]) -> c_int {
    let mut sequence = 0u64;

    if view.events.is_null() || view.n_events == 0 || view.n_events > EVENTS_MAX {
        return -EINVAL;
    }
    *out = view.initial_pcr;
    for (i, event) in events(view).iter().enumerate() {
        let kind = if i != 0 { EVENT_UPDATE } else { EVENT_BOOT };

        if event.sequence == 0
            || event.sequence > i64::MAX as u64
            || (i != 0 && event.sequence != sequence.wrapping_add(1))
            || event.kind != kind
        {
            return -EKEYREJECTED;
        }
        let digest = match measure_event(event.kind, &event.root_hash) {
            Ok(digest) => digest,
            Err(err) => return err,
        };
        let ret = fold(out, &digest);
        if ret != 0 {
            return ret;
        }
        sequence = event.sequence;
    }
    0
}

unsafe extern "C" fn collect_event(
    record: *const ConfigUpdateRecord,
    opaque: *mut c_void,
) -> c_int {
    // SAFETY: config_update_events() passes a record, and the view
    // collect() made the context, touched through this pointer alone
    // while the walk runs.
    let (r, view) = unsafe { (&*record, &mut *opaque.cast::<Evidence>()) };

    if r.reset_count != view.reset_count {
        return 0;
    }
    if r.pcr != view.pcr || r.sequence > i64::MAX as u64 || r.initial_pcr != view.initial_pcr {
        return -EUCLEAN;
    }
    append_event(view, &r.target.root_hash, r.sequence, r.kind)
}

/// The evidence of the active config from the update records, or none
/// without an update: 0, or -errno with the view cleared.
///
/// # Safety
///
/// `update` is NULL or an open update, and `out` points to room for a
/// view.
unsafe fn collect(update: *mut ConfigUpdate, out: *mut Evidence) -> c_int {
    let mut active = ConfigUpdateRecord::zeroed();

    // SAFETY: the caller passes the room.
    unsafe { zero(out) };
    if update.is_null() {
        return 0;
    }
    // SAFETY: the caller's update, and a record to fill.
    let mut ret = unsafe { config_update_check(update, &mut active) };
    if ret != 0 {
        return ret;
    }
    // SAFETY: the view, zeroed above.
    let view = unsafe { &mut *out };

    view.pcr = active.pcr;
    view.reset_count = active.reset_count;
    view.restart_count = active.restart_count;
    view.initial_pcr = active.initial_pcr;
    // SAFETY: the caller's update, the callback, and the view it takes,
    // not touched here while the walk runs.
    ret = unsafe { config_update_events(update, Some(collect_event), out.cast()) };
    // SAFETY: as above, the walk is over.
    let view = unsafe { &mut *out };
    if ret == 0 {
        let mut value = [0u8; 32];

        ret = replay(view, &mut value);
        if ret == 0 {
            view.value = value;
        }
    }
    if ret == 0 {
        let last = &events(view)[view.n_events - 1];

        if last.sequence != active.sequence || last.root_hash != active.target.root_hash {
            ret = -EUCLEAN;
        }
    }
    if ret != 0 {
        // SAFETY: the view, its events from xreallocarray().
        unsafe { clear(out) };
        return ret;
    }
    view.present = true;
    0
}

/// Frees the view's events and zeroes it.
///
/// # Safety
///
/// `view` is NULL or points to a view whose events are NULL or from
/// xreallocarray().
pub(crate) unsafe fn clear(view: *mut Evidence) {
    if view.is_null() {
        return;
    }
    // SAFETY: the caller passes the view and its events, freed once.
    unsafe {
        xfree(
            (*view).events.cast(),
            (*view).capacity * size_of::<EvidenceEvent>(),
        );
        zero(view);
    }
}

fn emit_hash(e: &mut JsonEmit, key: &[u8], bytes: &[u8; 32]) {
    let mut hex = [0u8; 65];

    // SAFETY: 32 bytes, and room for their 64 digits and a NUL.
    unsafe { hex_encode(bytes.as_ptr(), 32, hex.as_mut_ptr().cast()) };
    e.kv_string(key, cstr(&hex));
}

/// The view as the `config` object of the evidence: 0, -EOVERFLOW for a
/// sequence past an int64, or the emitter's error.
fn emit(e: &mut JsonEmit, view: &Evidence) -> c_int {
    if !view.present {
        return 0;
    }
    e.obj_open_key(b"config");
    e.kv_int(b"schema", 1);
    e.kv_int(b"pcr", i64::from(view.pcr));
    e.kv_int(b"reset_count", i64::from(view.reset_count));
    e.kv_int(b"restart_count", i64::from(view.restart_count));
    emit_hash(e, b"initial_pcr", &view.initial_pcr);
    e.arr_open(b"events");
    for event in events(view) {
        if event.sequence > i64::MAX as u64 {
            return -EOVERFLOW;
        }
        e.obj_open();
        e.kv_int(b"sequence", event.sequence as i64);
        e.kv_int(b"kind", i64::from(event.kind));
        emit_hash(e, b"root_hash", &event.root_hash);
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    e.err()
}

/// What the schema of the `config` object fills, and the view its
/// events go to.
struct ConfigParser<'v> {
    view: &'v mut Evidence,
    schema: i64,
    pcr: i64,
    reset: i64,
    restart: i64,
    initial: [u8; 65],
    sequence: i64,
    kind: i64,
    root_hash: [u8; 65],
}

/// Adds the event the parser holds to its view; `fields` are the
/// event's, every one of which it must give.
fn on_event(p: &mut ConfigParser, fields: &[JsonField<'_, ConfigParser>]) -> Result<(), c_int> {
    let mut root_hash = [0u8; 32];

    if !fields.iter().all(JsonField::seen) {
        return Err(-EINVAL);
    }
    let (sequence, kind) = (p.sequence, p.kind);

    if sequence <= 0
        || (kind != i64::from(EVENT_BOOT) && kind != i64::from(EVENT_UPDATE))
        || cstr(&p.root_hash).len() != 64
        // SAFETY: a C string the parser wrote, and room for 32 bytes.
        || unsafe { hex_decode(p.root_hash.as_ptr().cast(), root_hash.as_mut_ptr(), 32) } != 0
    {
        return Err(-EINVAL);
    }
    match append_event(p.view, &root_hash, sequence as u64, kind as c_int) {
        0 => Ok(()),
        err => Err(err),
    }
}

/// The `config` object of evidence a verifier received into `out`: 0,
/// with the view not present when there is none, or -errno with the view
/// cleared.
///
/// # Safety
///
/// `out` points to room for a view.
pub(crate) unsafe fn parse(evidence: &[u8], out: *mut Evidence) -> c_int {
    // SAFETY: the caller passes the room.
    unsafe { zero(out) };
    let mut parser = ConfigParser {
        // SAFETY: the view, zeroed above.
        view: unsafe { &mut *out },
        schema: 0,
        pcr: 0,
        reset: 0,
        restart: 0,
        initial: [0; 65],
        sequence: 0,
        kind: 0,
        root_hash: [0; 65],
    };
    let event_fields = [
        JsonField::int(c"sequence", |p: &mut ConfigParser| &mut p.sequence),
        JsonField::int(c"kind", |p| &mut p.kind),
        JsonField::string(c"root_hash", |p| &mut p.root_hash),
    ];
    let take_event = |p: &mut ConfigParser| on_event(p, &event_fields);
    let config_fields = [
        JsonField::int(c"schema", |p: &mut ConfigParser| &mut p.schema),
        JsonField::int(c"pcr", |p| &mut p.pcr),
        JsonField::int(c"reset_count", |p| &mut p.reset),
        JsonField::int(c"restart_count", |p| &mut p.restart),
        JsonField::string(c"initial_pcr", |p| &mut p.initial),
        JsonField::array(c"events", &event_fields, &take_event),
    ];
    let top = [JsonField::object(c"config", &config_fields)];
    let mut ret = parse_schema(evidence, &top, &mut parser).err().unwrap_or(0);

    if ret == 0 {
        if !top[0].seen() {
            return 0;
        }
        let ConfigParser {
            view,
            schema,
            pcr,
            reset,
            restart,
            initial,
            ..
        } = parser;
        let fields_ok = config_fields.iter().all(JsonField::seen)
            && schema == 1
            && (0..=i64::from(u32::MAX)).contains(&reset)
            && (0..=i64::from(u32::MAX)).contains(&restart)
            && (0..=i64::from(u32::MAX)).contains(&pcr)
            && pcr_valid(pcr as u32) == 0
            && cstr(&initial).len() == 64;
        let decoded = fields_ok && {
            // SAFETY: a C string of 64 digits, and the room of the
            // initial value.
            let r =
                unsafe { hex_decode(initial.as_ptr().cast(), view.initial_pcr.as_mut_ptr(), 32) };

            r == 0
        };

        ret = if !decoded {
            -EINVAL
        } else {
            view.pcr = pcr as u32;
            view.reset_count = reset as u32;
            view.restart_count = restart as u32;
            let mut value = [0u8; 32];
            let ret = replay(view, &mut value);

            if ret == 0 {
                view.value = value;
                view.present = true;
            }
            ret
        };
    }
    if ret != 0 {
        // SAFETY: the view, its events from xreallocarray().
        unsafe { clear(out) };
    }
    ret
}

/// What a quote says: the PCRs it covers, the TPM boot it was made in,
/// and the PCR values.
pub(crate) struct Quote<'a> {
    pub(crate) mask: u32,
    pub(crate) reset: u32,
    pub(crate) pcrs: &'a [[u8; 32]; 24],
    pub(crate) nvpcr: Option<&'a [u8; 32]>,
}

/// Whether the evidence is the history of the quoted config PCR, in the
/// quote's TPM boot, ending in the root an operator approved: 0 or
/// -EKEYREJECTED, and the reason.
pub(crate) fn verify(
    view: &Evidence,
    quote: &Quote,
    expected_root: Option<&[u8; 32]>,
    expected_pcr: c_int,
) -> (c_int, &'static CStr) {
    let mut value = [0u8; 32];

    if !view.present {
        let ret = if expected_root.is_some() || expected_pcr >= 0 {
            -EKEYREJECTED
        } else {
            0
        };

        return (ret, c"configuration evidence is missing");
    }
    if pcr_valid(view.pcr) != 0 || (expected_pcr >= 0 && view.pcr != expected_pcr as u32) {
        return (-EKEYREJECTED, c"config PCR is unquoted or unexpected");
    }
    let live = if nvpcr(view.pcr) {
        let Some(certified) = quote.nvpcr else {
            return (-EKEYREJECTED, c"config NvPCR is not certified");
        };
        let mut initial = [0u8; 32];
        let ret = nvpcr_initial(&mut initial);
        if ret != 0 {
            return (ret, c"config root history matches the certified NvPCR");
        }
        if view.initial_pcr != initial {
            return (
                -EKEYREJECTED,
                c"config history does not start at the NvPCR's initial value",
            );
        }
        certified
    } else {
        if quote.mask & (1u32 << view.pcr) == 0 {
            return (-EKEYREJECTED, c"config PCR is unquoted or unexpected");
        }
        &quote.pcrs[view.pcr as usize]
    };
    if view.reset_count != quote.reset {
        return (-EKEYREJECTED, c"config history belongs to another TPM boot");
    }
    if expected_root.is_some() && expected_pcr < 0 {
        return (-EKEYREJECTED, c"expected config root needs an expected PCR");
    }
    let ret = replay(view, &mut value);
    if ret != 0 || value != *live {
        let reason = if nvpcr(view.pcr) {
            c"config history does not match the certified NvPCR"
        } else {
            c"config history does not match the quoted PCR"
        };
        return (if ret != 0 { ret } else { -EKEYREJECTED }, reason);
    }
    if let Some(root) = expected_root
        && events(view)[view.n_events - 1].root_hash != *root
    {
        return (
            -EKEYREJECTED,
            c"config root was not approved by the operator",
        );
    }
    (
        0,
        if nvpcr(view.pcr) {
            c"config root history matches the certified NvPCR"
        } else {
            c"config root history matches the quoted PCR"
        },
    )
}

pub(crate) use capi::{
    config_evidence_clear, config_evidence_collect, config_evidence_emit, config_evidence_parse,
    config_evidence_verify,
};

mod capi {
    use core::ffi::{c_char, c_int};

    use super::Evidence;
    use crate::ffi;
    use crate::util::config_update::ConfigUpdate;
    use crate::util::json::JsonEmit;

    /// # Safety
    ///
    /// `update` is NULL or an open update, and `out` points to room for a
    /// view.
    pub unsafe extern "C" fn config_evidence_collect(
        update: *mut ConfigUpdate,
        out: *mut Evidence,
    ) -> c_int {
        // SAFETY: the caller passes the update and the room.
        unsafe { super::collect(update, out) }
    }

    /// # Safety
    ///
    /// `view` is NULL or points to a view whose events are NULL or from
    /// xreallocarray().
    pub unsafe extern "C" fn config_evidence_clear(view: *mut Evidence) {
        // SAFETY: the caller passes the view.
        unsafe { super::clear(view) }
    }

    /// # Safety
    ///
    /// `emit` points to an emitter and `view` to a view.
    pub unsafe extern "C" fn config_evidence_emit(
        emit: *mut JsonEmit,
        view: *const Evidence,
    ) -> c_int {
        // SAFETY: the caller passes the emitter and the view.
        unsafe { super::emit(&mut *emit, &*view) }
    }

    /// # Safety
    ///
    /// `evidence` holds `length` bytes, and `out` points to room for a
    /// view.
    pub unsafe extern "C" fn config_evidence_parse(
        evidence: *const c_char,
        length: usize,
        out: *mut Evidence,
    ) -> c_int {
        // SAFETY: the caller passes the evidence and the room.
        unsafe { super::parse(ffi::slice(evidence.cast(), length), out) }
    }

    /// # Safety
    ///
    /// `view` points to a view, `pcrs` to 24 PCR values, `expected_root`
    /// is NULL or points to 32 bytes, and `reason` points to where the
    /// reason goes.
    pub unsafe extern "C" fn config_evidence_verify(
        view: *const Evidence,
        quote_mask: u32,
        reset: u32,
        pcrs: *const [u8; 32],
        nvpcr_value: *const u8,
        expected_root: *const u8,
        expected_pcr: c_int,
        reason: *mut *const c_char,
    ) -> c_int {
        // SAFETY: the caller passes the view, the PCRs, the root and the
        // place of the reason.
        unsafe {
            let quote = super::Quote {
                mask: quote_mask,
                reset,
                pcrs: &*pcrs.cast::<[[u8; 32]; 24]>(),
                nvpcr: nvpcr_value.cast::<[u8; 32]>().as_ref(),
            };
            let (ret, why) = super::verify(
                &*view,
                &quote,
                expected_root.cast::<[u8; 32]>().as_ref(),
                expected_pcr,
            );

            *reason = why.as_ptr();
            ret
        }
    }
}
