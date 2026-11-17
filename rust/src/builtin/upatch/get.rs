// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch get`: a loaded upatch described from the kernel,
//! where it attaches, its source as the signed loader's BTF line_info
//! gives it, and every map it pins with their contents. It reads only
//! what the LSM allows: bpf() info and lookups, xattrs and stat.

use core::ffi::{CStr, c_int, c_long};
use std::ffi::CString;

use super::{JSON_MAX, Summaries, err, help, item, log_err, out, print_json, strerr, type_name};
use crate::ffi;
use crate::sys::btf::{
    Btf, btf__free, btf__load_from_kernel_by_id, btf__load_vmlinux_btf, btf__name_by_offset,
};
use crate::sys::libc::{close, errno};
use crate::sys::upatch::MapSummary;
use crate::sys::upatch_maps::{MAP_ENTRIES_DEFAULT, MAP_READ_PEEK, MapView};
use crate::text::cstr;
use crate::util::bpf_info::{Info, LINK_INFO_SIZE, PROG_INFO_SIZE};
use crate::util::bpf_sys::bpf_prog_get_fd_by_id;
use crate::util::help::{HelpItem, is_help};
use crate::util::json::JsonEmit;
use crate::util::map_read;
use crate::util::map_render;
use crate::util::timefmt::format_duration;
use crate::util::upatch::name_valid;
use crate::util::upatch_resolve::{loaded_at, open_first_link, payload_sha256, resolve_location};
use crate::util::upatch_table::age_sec;

const EINVAL: c_int = 22;

/// Where `struct bpf_link_info` and `struct bpf_prog_info` keep what is
/// read of them.
const LINK_PROG_ID: usize = 8;
const PROG_BTF_ID: usize = 128;
const PROG_NR_LINE_INFO: usize = 148;
const PROG_LINE_INFO: usize = 152;
const PROG_LINE_INFO_REC_SIZE: usize = 172;
/// `struct bpf_line_info`: insn_off, file_name_off, line_off, line_col.
const LINE_INFO_SIZE: usize = 16;

const OPTIONS: [HelpItem; 2] = [
    item(c"--json", c"machine-readable JSON output"),
    item(c"--show-full", c"lift the per-map 256-entry truncation cap"),
];

fn usage() {
    help(
        c"shirudo upatch get <name> [--json] [--show-full]",
        c"Describe a loaded upatch from the target kernel:\n  - the SEC()-style attach hook (e.g. fexit/tcp_v4_connect),\n  - the prog source via BTF line_info installed by the\n    signed loader (authoritative, but sparse),\n  - every pinned map: BTF key/value type definitions plus\n    the live key/value contents.\nRead-only; uses only LSM-allowed bpf() ops, xattr and stat.",
        &[(c"options:", &OPTIONS)],
        Some(c"Examples:\n  shirudo upatch get cve-2026-31431\n  shirudo upatch get cve-2026-31431 --json | jq"),
    );
}

/// A source line of the program.
struct Line {
    file: Vec<u8>,
    line: u32,
    src: Vec<u8>,
}

/// The upatch as the kernel has it loaded.
struct Loaded {
    prog_id: u32,
    location: Vec<u8>,
    loaded_at: Vec<u8>,
    payload: Vec<u8>,
    /// Unique, by file and then line: line_info follows the instructions,
    /// so a line recurs and lines come out of order.
    lines: Vec<Line>,
}

/// The source lines the `rec_size`-byte line_info records `recs` name in
/// `btf`, skipping any blank.
fn lines(btf: *const Btf, recs: &[u8], rec_size: usize) -> Vec<Line> {
    if rec_size < LINE_INFO_SIZE {
        return Vec::new();
    }
    let string = |off: u32| -> Option<&[u8]> {
        // SAFETY: the BTF, which bounds the offset; NULL or a C string in it.
        let p = unsafe { btf__name_by_offset(btf, off) };
        // SAFETY: as above.
        (!p.is_null()).then(|| unsafe { ffi::c_str(p) })
    };
    let mut v: Vec<Line> = recs
        .chunks_exact(rec_size)
        .filter_map(|r| {
            let word =
                |i: usize| u32::from_ne_bytes(r[i * 4..i * 4 + 4].try_into().unwrap_or_default());
            let src = string(word(2))?;
            let start = src.iter().position(|&c| c != b' ' && c != b'\t')?;
            let file = string(word(1)).filter(|f| !f.is_empty()).unwrap_or(b"?");
            Some(Line {
                file: file.to_vec(),
                line: word(3) >> 10,
                src: src[start..].to_vec(),
            })
        })
        .collect();
    v.sort_by(|a, b| a.file.cmp(&b.file).then(a.line.cmp(&b.line)));
    v.dedup_by(|b, a| a.file == b.file && a.line == b.line);
    v
}

/// The source lines of program `prog`, none when it was built without
/// them, or -errno.
fn source(prog: c_int) -> Result<Vec<Line>, c_int> {
    let mut info = Info::<PROG_INFO_SIZE>::new();
    info.read(prog)?;
    let nr = info.u32_at(PROG_NR_LINE_INFO);
    let rec_size = info.u32_at(PROG_LINE_INFO_REC_SIZE);
    let btf_id = info.u32_at(PROG_BTF_ID);
    if nr == 0 || btf_id == 0 || rec_size == 0 {
        return Ok(Vec::new());
    }
    let mut recs = vec![0u8; nr as usize * rec_size as usize];
    let mut info = Info::<PROG_INFO_SIZE>::new();
    info.set(PROG_NR_LINE_INFO, &nr.to_ne_bytes());
    info.set(PROG_LINE_INFO_REC_SIZE, &rec_size.to_ne_bytes());
    info.set(PROG_LINE_INFO, &(recs.as_mut_ptr() as u64).to_ne_bytes());
    info.read(prog)?;
    // SAFETY: a call that takes no pointer.
    let btf = unsafe { btf__load_from_kernel_by_id(btf_id) };
    if btf.is_null() {
        return Err(-errno());
    }
    let lines = lines(btf, &recs, rec_size as usize);
    // SAFETY: the BTF loaded above, freed once.
    unsafe { btf__free(btf) };
    Ok(lines)
}

/// A C string the call writes into `N` bytes.
fn filled<const N: usize>(f: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut buf = [0u8; N];
    f(&mut buf);
    cstr(&buf).to_vec()
}

/// Upatch `name` as loaded, or -errno. Missing line_info is no failure:
/// the rest still describes it.
fn collect(name: &CStr) -> Result<Loaded, c_int> {
    let link = open_first_link(name.to_bytes());
    if link < 0 {
        return Err(link);
    }
    let mut linfo = Info::<LINK_INFO_SIZE>::new();
    let read = linfo.read(link);
    // SAFETY: the descriptor opened above.
    unsafe { close(link) };
    read?;
    let prog_id = linfo.u32_at(LINK_PROG_ID);
    if prog_id == 0 {
        return Err(-EINVAL);
    }
    let n = name.to_bytes();
    let loaded_at = filled::<32>(|o| loaded_at(n, o));
    let payload = filled::<65>(|o| payload_sha256(n, o));
    // SAFETY: libbpf's loader, NULL when there is none.
    let vbtf = unsafe { btf__load_vmlinux_btf() };
    let location = filled::<160>(|o| {
        resolve_location(vbtf, n, o);
    });
    // SAFETY: the BTF loaded above, or NULL, freed once.
    unsafe { btf__free(vbtf) };

    let prog = bpf_prog_get_fd_by_id(prog_id);
    if prog < 0 {
        return Err(prog);
    }
    let lines = source(prog);
    // SAFETY: the descriptor opened above.
    unsafe { close(prog) };
    Ok(Loaded {
        prog_id,
        location,
        loaded_at,
        payload,
        lines: lines?,
    })
}

/// How long ago the time `ts` was, as format_duration() puts it, or
/// nothing when it is none.
fn age(ts: &[u8]) -> Vec<u8> {
    let Ok(ts) = CString::new(ts) else {
        return Vec::new();
    };
    // SAFETY: a C string.
    let secs = unsafe { age_sec(ts.as_ptr()) };
    if secs < 0 {
        return Vec::new();
    }
    let mut buf = [0u8; 16];
    format_duration(secs as c_long, &mut buf);
    cstr(&buf).to_vec()
}

/// Hands `f` what map `m` of upatch `upatch` holds, its first `cap`
/// entries or all for 0, without draining a serializer: the view, or
/// -errno.
fn read_map(upatch: &CStr, m: &MapSummary, cap: u32, f: impl FnOnce(Result<&MapView, c_int>)) {
    // SAFETY: an all-zero view is an empty one.
    let mut v: Box<MapView> = Box::new(unsafe { core::mem::zeroed() });
    let r = map_read::read(upatch.to_bytes(), cstr(&m.name), cap, MAP_READ_PEEK, &mut v);
    f(if r == 0 { Ok(&v) } else { Err(r) });
    map_read::view_free(&mut v);
}

fn text(name: &CStr, l: &Loaded, maps: &[MapSummary], cap: u32) {
    let kv = |label: &str, v: &[u8]| [format!("{label:<22} ").as_bytes(), v, b"\n"].concat();
    let mut t = Vec::new();

    t.extend(kv("Name:", name.to_bytes()));
    t.extend(kv(
        "Location:",
        if l.location.is_empty() {
            b"?"
        } else {
            &l.location
        },
    ));
    t.extend(kv("Program ID:", l.prog_id.to_string().as_bytes()));
    if !l.loaded_at.is_empty() {
        let age = age(&l.loaded_at);
        let ago = if age.is_empty() {
            Vec::new()
        } else {
            [&b"  ("[..], &age, b" ago)"].concat()
        };
        t.extend(kv("Loaded at:", &[&l.loaded_at[..], &ago].concat()));
    }
    if l.payload.is_empty() {
        t.extend(kv("Payload sha256:", b"unavailable"));
    } else {
        t.extend(kv(
            "Payload sha256:",
            &[&l.payload[..], b"  (signature-bound)"].concat(),
        ));
    }
    let names = maps
        .iter()
        .map(|m| cstr(&m.name))
        .collect::<Vec<_>>()
        .join(&b", "[..]);
    t.extend(kv("Maps:", if maps.is_empty() { b"none" } else { &names }));

    t.extend_from_slice(b"\nSource (kernel BTF line_info):\n\n");
    if l.lines.is_empty() {
        t.extend_from_slice(b"  no line info: built without clang -g\n");
    }
    for file in l.lines.chunk_by(|a, b| a.file == b.file) {
        t.extend([&b"  "[..], &file[0].file, b":\n"].concat());
        for x in file {
            t.extend([format!("    {:>5}: ", x.line).as_bytes(), &x.src, b"\n"].concat());
        }
    }
    out(&t);

    for m in maps {
        read_map(name, m, cap, |v| {
            out(&[b"\n== Map: ", cstr(&m.name), b" ==\n"].concat());
            match v {
                Ok(v) => map_render::print_detail(v),
                Err(e) => out(&[b"  (read failed: ", strerr(-e), b")\n"].concat()),
            }
        });
    }
}

fn json(name: &CStr, l: &Loaded, maps: &[MapSummary], cap: u32) -> c_int {
    let mut e = JsonEmit::growing(JSON_MAX);

    e.obj_open();
    e.kv_int(b"schema", 1);
    e.obj_open_key(b"upatch");
    e.kv_string(b"name", name.to_bytes());
    e.kv_string(b"location", &l.location);
    e.kv_int(b"prog_id", i64::from(l.prog_id));
    e.kv_string(b"loaded_at", &l.loaded_at);
    e.kv_string(b"age", &age(&l.loaded_at));
    if l.payload.is_empty() {
        e.kv_null(b"payload_sha256");
    } else {
        e.kv_string(b"payload_sha256", &l.payload);
    }
    e.obj_open_key(b"source");
    e.arr_open(b"files");
    for file in l.lines.chunk_by(|a, b| a.file == b.file) {
        e.obj_open();
        e.kv_string(b"path", &file[0].file);
        e.arr_open(b"lines");
        for x in file {
            e.obj_open();
            e.kv_int(b"line", i64::from(x.line));
            e.kv_string(b"src", &x.src);
            e.obj_close();
        }
        e.arr_close();
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    e.arr_open(b"maps");
    for m in maps {
        read_map(name, m, cap, |v| match v {
            Ok(v) => map_render::emit_json_object(&mut e, v),
            Err(err) => {
                e.obj_open();
                e.kv_string(b"name", cstr(&m.name));
                e.kv_string(b"type", type_name(m));
                e.kv_int(b"max_entries", i64::from(m.max_entries));
                e.kv_string(b"error", strerr(-err));
                e.obj_close();
            }
        });
    }
    e.arr_close();
    e.obj_close();
    e.obj_close();
    print_json(e, b"upatch get")
}

/// `upatch get`, from `get` on.
pub(super) fn run(args: &[&[u8]]) -> c_int {
    let (mut json_out, mut show_full) = (false, false);
    let mut want: Option<&[u8]> = None;

    for &a in &args[1..] {
        if is_help(Some(a)) {
            usage();
            return 0;
        }
        if a == b"--json" {
            json_out = true;
        } else if a == b"--show-full" {
            show_full = true;
        } else if a.first() == Some(&b'-') {
            err(&[b"upatch get: unknown option '", a, b"'\n"].concat());
            return 2;
        } else if want.is_none() {
            want = Some(a);
        } else {
            err(&[b"upatch get: unexpected argument '", a, b"'\n"].concat());
            return 2;
        }
    }
    let Some(want) = want else {
        usage();
        return 2;
    };
    if !name_valid(Some(want)) {
        log_err(&[b"upatch get: invalid name '", want, b"'"].concat());
        return 2;
    }
    let Ok(name) = CString::new(want) else {
        return 2;
    };
    let loaded = match collect(&name) {
        Ok(l) => l,
        Err(e) => {
            log_err(&[b"upatch get: '", want, b"': ", strerr(-e)].concat());
            return 1;
        }
    };
    let maps = Summaries::of(Some(&name));
    let cap = if show_full { 0 } else { MAP_ENTRIES_DEFAULT };
    if json_out {
        json(&name, &loaded, maps.as_slice(), cap)
    } else {
        text(&name, &loaded, maps.as_slice(), cap);
        0
    }
}
