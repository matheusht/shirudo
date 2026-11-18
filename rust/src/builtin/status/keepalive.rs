// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The keepalive of `shirudo status`: the body a node's TPM quotes, read
//! as one point of the tree and of the loaded set, which --keepalive
//! prints and --otel quotes and sends.

use core::ffi::{CStr, c_int};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use super::{Report, hex, print, strerr, version_id};
use crate::errno::EBADMSG;
use crate::util::bpm_tree::{TreeState, build_limit};
use crate::util::bpm_tree_state::{
    eventlog_matches, tree_outcomes_read, tree_pending_exists, tree_state_read, tree_status_path,
};
use crate::util::chain::{self, MeasuredUpatch};
use crate::util::conditions::{self, CONDITIONS_MAX, Condition, ConditionsInput};
use crate::util::keepalive::{
    self, BOUND_LATE, INTEGRITY_UNAVAILABLE, Input, MASK_B64_MAX, MASK_OPS, REGISTER_REBOUND,
    SnapshotOps, TAMPER_UNAVAILABLE, TREE_LOG_MISMATCH, Tree,
};
use crate::util::keepalive_quote;
use crate::util::measured::name_from_bpffs;
use crate::util::otel::{OtelOpts, send_log_string, status_severity};
use crate::util::sysinfo::{self, Sysinfo};
use crate::util::upatch_resolve::{BPFFS_UPATCHES_DIR, payload_sha256};

/// The body reports the last this many operations up to the head of the
/// tree, whatever segments hold them. The test VM bundle lowers it, so
/// that the window of a short tree starts past seq 0, inside an older
/// segment.
const WINDOW_OPS: i64 = build_limit(b"KEEPALIVE_WINDOW_OPS", MASK_OPS as i64);

const _: () = assert!(WINDOW_OPS >= 1 && WINDOW_OPS <= MASK_OPS as i64);

fn log_err(text: &[u8]) {
    let text = std::ffi::CString::new(
        text.iter()
            .copied()
            .filter(|&c| c != 0)
            .collect::<Vec<u8>>(),
    )
    .unwrap_or_default();
    crate::log::err(text.to_bytes());
}

/// What a snapshot reads past the tree state, for one try.
struct View {
    base_seq: i64,
    outcomes_rc: c_int,
    codes: [u8; MASK_OPS],
    base_root: Vec<u8>,
    mask: Vec<u8>,
    log_mismatch: bool,
    set_sha256: Vec<u8>,
    count: u64,
    not_ok: u64,
}

impl View {
    /// The outcomes of the window, which reaches past the recorded
    /// segment's base into the segments before it, whose outcomes the
    /// record keeps from seq 1.
    fn window(&mut self, s: &TreeState) {
        self.codes = [0; MASK_OPS];
        if s.last_seq < 0 || s.last_seq > s.head_seq {
            self.outcomes_rc = -EBADMSG;
            return;
        }
        self.base_seq = (s.head_seq - WINDOW_OPS).max(0);
        if s.last_seq < self.base_seq {
            self.outcomes_rc = -EBADMSG;
            return;
        }
        let (mut projection, mut history) = ([0u8; 32], [0u8; 32]);
        // SAFETY: room for the outcomes up to last_seq, at most the
        // window, and for the two roots.
        self.outcomes_rc = unsafe {
            tree_outcomes_read(
                self.base_seq,
                s.last_seq,
                self.codes.as_mut_ptr(),
                &mut projection,
                &mut history,
            )
        };
        if self.outcomes_rc == 0 {
            let mut b64 = [0u8; MASK_B64_MAX];
            let n = (s.head_seq - self.base_seq) as usize;
            self.outcomes_rc = keepalive::mask(&self.codes[..n], &mut b64);
            self.mask = crate::text::cstr(&b64).to_vec();
        }
        if self.outcomes_rc == 0 {
            self.base_root = hex(&projection);
        }
    }

    /// The set digest of an init event over every upatch pinned now, and
    /// how many of them a tree status file says the tree left not loaded.
    fn loaded_set(&mut self) -> c_int {
        let mut names: Vec<Vec<u8>> = std::fs::read_dir(BPFFS_UPATCHES_DIR)
            .map(|d| {
                d.filter_map(Result::ok)
                    .map(|e| e.file_name().as_bytes().to_vec())
                    .collect()
            })
            .unwrap_or_default();
        names.sort();
        let mut set: Vec<MeasuredUpatch> = Vec::with_capacity(names.len());
        self.not_ok = 0;
        for pin in &names {
            // SAFETY: an all-zero member is an empty one.
            let mut u: MeasuredUpatch = unsafe { core::mem::zeroed() };
            if name_from_bpffs(&mut u.name, pin) != 0 {
                continue;
            }
            let name = crate::text::cstr(&u.name).to_vec();
            payload_sha256(&name, &mut u.payload_hex);
            let status = tree_status_path(&name);
            if std::fs::metadata(OsStr::from_bytes(status.to_bytes())).is_ok() {
                self.not_ok += 1;
            }
            set.push(u);
        }
        let none = [0u8; 32];
        let (mut digest, mut event) = ([0u8; 32], [0u8; 32]);
        let ret = chain::init_event(&none, &mut set, &none, &mut digest, &mut event);
        if ret == 0 {
            self.set_sha256 = hex(&digest);
            self.count = set.len() as u64;
        }
        ret
    }
}

impl SnapshotOps for View {
    fn read_state(&mut self, state: &mut TreeState) -> c_int {
        // SAFETY: room for a state.
        unsafe { tree_state_read(state) }
    }

    fn pending(&mut self) -> bool {
        tree_pending_exists()
    }

    fn collect(&mut self, state: &TreeState, state_rc: c_int) -> c_int {
        if state_rc == 0 {
            self.window(state);
        }
        // eventlog_matches_state of the status document, false only.
        self.log_mismatch = matches!(eventlog_matches(state, state_rc), Ok((_, false)));
        self.loaded_set()
    }
}

fn flags(r: &Report, v: &View, state_rc: c_int) -> u32 {
    let c = &r.cst;
    let mut flags = 0;
    if c.rebound {
        flags |= REGISTER_REBOUND;
    }
    if c.logged && !c.init.initrd {
        flags |= BOUND_LATE;
    }
    if v.log_mismatch || (state_rc == 0 && v.outcomes_rc != 0) {
        flags |= TREE_LOG_MISMATCH;
    }
    if r.tamper.is_err() {
        flags |= TAMPER_UNAVAILABLE;
    }
    if r.integrity.is_err() {
        flags |= INTEGRITY_UNAVAILABLE;
    }
    flags
}

/// The body of this host; a tree state that cannot be read is a node that
/// follows no tree.
fn body(r: &Report, cin: &ConditionsInput, config_root: Option<&[u8]>) -> Result<Vec<u8>, c_int> {
    let mut v = View {
        base_seq: 0,
        outcomes_rc: 0,
        codes: [0; MASK_OPS],
        base_root: Vec::new(),
        mask: Vec::new(),
        log_mismatch: false,
        set_sha256: Vec::new(),
        count: 0,
        not_ok: 0,
    };
    let mut state = TreeState::zeroed();
    let (mut state_rc, mut flags_read) = (0, 0);
    let ret = keepalive::snapshot(&mut v, &mut state, &mut state_rc, &mut flags_read);
    if ret != 0 {
        log_err(&[b"status: read the keepalive inputs: ", strerr(-ret)].concat());
        return Err(ret);
    }
    // SAFETY: an all-zero sysinfo is an empty one.
    let mut si: Box<Sysinfo> = Box::new(unsafe { core::mem::zeroed() });
    sysinfo::gather(&mut si);
    let img = sysinfo::image_read();
    // SAFETY: plain data, whose NULL strings nothing reads before
    // conditions() sets them.
    let mut conds: [Condition; CONDITIONS_MAX] = unsafe { core::mem::zeroed() };
    let nc = conditions::conditions(cin, &mut conds);
    let text = |b: &[u8]| crate::text::cstr(b).to_vec();
    let (boot_id, kernel_release) = (text(&si.boot_id), text(&si.kernel_release));
    let (id, version, root) = (text(&img.id), text(&img.version), text(&img.root));
    let tree = (state_rc == 0).then(|| Tree {
        tree_id: Some(crate::text::cstr(&state.tree_id)),
        generation: state.generation as u64,
        base_seq: v.base_seq as u64,
        last_seq: state.last_seq as u64,
        base_root: (v.outcomes_rc == 0).then_some(&v.base_root[..]),
        projection_root: Some(crate::text::cstr(&state.projection_root)),
        mask: (v.outcomes_rc == 0).then_some(&v.mask[..]),
    });
    let input = Input {
        boot_id: Some(&boot_id),
        version_id: Some(version_id()),
        config_root,
        kernel_release: Some(&kernel_release),
        image_id: Some(&id),
        image_version: Some(&version),
        image_root: Some(&root),
        verdict: Some(conditions::status_verdict(cin).to_bytes()),
        cond: keepalive::cond(&conds[..nc]),
        flags: flags_read | flags(r, &v, state_rc),
        tamper: r.tamper.as_ref().ok().map(|t| &t.count),
        integrity: r.integrity.as_ref().ok().map(|t| &t.count),
        tree,
        set_sha256: Some(&v.set_sha256),
        count: v.count,
        not_ok: v.not_ok,
    };
    keepalive::body(&input).inspect_err(|&err| {
        log_err(&[b"status: build the keepalive body: ", strerr(-err)].concat());
    })
}

/// One OTLP log: the body as a string and its quote as the one
/// attribute. Without a quote nothing is sent: the backend has no use
/// for a keepalive it cannot check.
fn send(opts: &OtelOpts, verdict: &CStr, body: &[u8]) -> c_int {
    let quote = match keepalive_quote::quote(body) {
        Ok(q) => q,
        Err(err) => {
            log_err(
                &[
                    b"status: quote the keepalive: ",
                    strerr(-err),
                    b"; nothing is sent",
                ]
                .concat(),
            );
            return err;
        }
    };
    let quote = std::ffi::CString::new(quote).unwrap_or_default();
    let (number, text) = status_severity(verdict.to_bytes());
    let ret = send_log_string(
        Some(opts),
        b"shirudo.keepalive",
        b"shirudo.keepalive",
        number,
        text.to_bytes(),
        body,
        b"shirudo.quote",
        quote.as_bytes(),
    );
    if ret != 0 {
        log_err(&[b"status: send the keepalive: ", strerr(-ret)].concat());
    }
    ret
}

/// Prints the body, or with `opts` quotes it and sends it there: 0, or
/// 1 when it could not.
pub(super) fn run(
    r: &Report,
    cin: &ConditionsInput,
    config_root: Option<&[u8]>,
    opts: Option<&OtelOpts>,
) -> c_int {
    let Ok(body) = body(r, cin, config_root) else {
        return 1;
    };
    match opts {
        None => {
            print(&[&body[..], b"\n"].concat());
            0
        }
        Some(o) => c_int::from(send(o, conditions::status_verdict(cin), &body) != 0),
    }
}
