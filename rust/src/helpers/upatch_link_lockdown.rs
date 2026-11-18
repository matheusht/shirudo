// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! test-upatch-link-lockdown: an untrusted caller cannot take hold of a
//! pinned upatch link, by its pin or by its id, to keep it attached or to
//! detach or update it.
//!
//!   test-upatch-link-lockdown <pinned link>

use core::ffi::{CStr, c_int, c_long};

use super::{err, helper_main, out};
use crate::util::bpf_sys::Attr;

helper_main!(shirudo_helper_test_upatch_link_lockdown, run);

const BPF_OBJ_GET: c_long = 7;
const BPF_LINK_GET_FD_BY_ID: c_long = 30;
const BPF_LINK_GET_NEXT_ID: c_long = 31;

fn run(args: &[&CStr]) -> c_int {
    let [_, pin] = args else {
        let me = args
            .first()
            .map_or("test-upatch-link-lockdown".into(), |a| a.to_string_lossy());
        err(&format!("usage: {me} <pinned-link>\n"));
        return 2;
    };
    let pin_errno = match Attr::new().ptr(0, pin.as_ptr()).fd(BPF_OBJ_GET) {
        Ok(_) => {
            err(&format!(
                "BPF_OBJ_GET of {} was allowed\n",
                pin.to_string_lossy()
            ));
            return 1;
        }
        Err(e) => e,
    };
    let (mut id, mut id_errno, mut links) = (0u32, 0, 0);
    loop {
        let mut next = Attr::new().u32(0, id);
        if next.call(BPF_LINK_GET_NEXT_ID).is_err() {
            break;
        }
        id = next.u32_at(4);
        match Attr::new().u32(0, id).fd(BPF_LINK_GET_FD_BY_ID) {
            Ok(_) => {
                err(&format!("BPF_LINK_GET_FD_BY_ID {id} was allowed\n"));
                return 1;
            }
            Err(e) => {
                if id_errno != 0 && e != id_errno {
                    err(&format!("link {id}: errno={e} after errno={id_errno}\n"));
                    return 1;
                }
                id_errno = e;
            }
        }
        links += 1;
    }
    out(&format!(
        "pin_errno={pin_errno} id_errno={id_errno} links={links}\n"
    ));
    c_int::from(!(pin_errno == libc::EACCES && id_errno == libc::EACCES && links > 0))
}
