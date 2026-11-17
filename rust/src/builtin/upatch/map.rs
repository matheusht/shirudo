// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo upatch map`: the maps the loaded upatches pin, listed, or
//! one map's or every map's contents read from the kernel. Contents are
//! printed, appended as JSON records through the upatch's signed
//! decoders, or exported over OTLP, from the command line or the
//! map_export configuration.

use core::ffi::{CStr, c_char, c_int};
use core::mem::MaybeUninit;
use std::fs::File;
use std::io::Write;
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::fs::FileExt;

use super::{JSON_MAX, Opt, Summaries, err, help, item, log_err, log_warn, opt, strerr, type_name};
use crate::errno::{EINVAL, EIO, ENODATA};
use crate::heap::xfree;
use crate::sys::libc::{
    LOCK_UN, O_APPEND, O_CREAT, O_RDWR, STDOUT_FILENO, close, errno, ferror, flock, stdout,
};
use crate::sys::upatch_maps::{MAP_ENTRIES_DEFAULT, MAP_READ_PEEK, MapView};
use crate::text::{cstr, parse_u64};
use crate::util::config::{self, Scrubbed};
use crate::util::decode;
use crate::util::help::{HelpItem, is_help};
use crate::util::io::{lock_exclusive, write_complete};
use crate::util::json::JsonEmit;
use crate::util::map_read;
use crate::util::map_render;
use crate::util::otel::{self, OtelOpts};
use crate::util::seal::seal_output_open;
use crate::util::upatch::name_valid;

const OPTIONS: [HelpItem; 10] = [
    item(c"--all", c"export every map from every loaded upatch"),
    item(c"--json[=<path>]", c"print JSON or append it to path"),
    item(c"--show-full", c"lift the per-map 256-entry truncation cap"),
    item(
        c"--peek",
        c"read serializer-backed maps without draining them",
    ),
    item(
        c"--otel",
        c"export maps through signed decoders or automatic classification",
    ),
    item(
        c"--otel-endpoint=<url>",
        c"OTLP base URL (signal path is appended)",
    ),
    item(c"--tenant-id=<id>", c"add X-Tenant-ID to OTLP requests"),
    item(
        c"--otel-insecure",
        c"allow cleartext remote OTLP or disable HTTPS verification",
    ),
    item(
        c"--otel-retries=<0-10>",
        c"OTLP retries after the first attempt (default: 3)",
    ),
    item(
        c"--s3-uri=<uri>",
        c"S3 overflow destination for OTLP payloads",
    ),
];

fn usage() {
    help(
        c"shirudo upatch map [--all] [<upatch>] [<map>] [--json[=<path>]] [--show-full] [--peek]\n                          [--otel] [--otel-endpoint=<url>]\n                          [--otel-insecure] [--otel-retries=<0-10>] [--s3-uri=<uri>]",
        c"Read the contents of a pinned upatch map from the\ntarget kernel. With no positional args, list every pinned\nmap across every loaded upatch. With <upatch>, list maps\nfor that upatch only. With <upatch> <map>, dump the map's\ncontents, BTF type-aware where the build embedded `-g`. If the upatch\npins a serializer for the map, run it and print the serialized\npages. With --all, export detailed contents for every loaded map\nusing command-line or map_export.* configuration.",
        &[(c"options:", &OPTIONS)],
        Some(c"Examples:\n  shirudo upatch map\n  shirudo upatch map --all\n  shirudo upatch map kernel-obs exec --json\n  shirudo upatch map cve-2026-31431-counter\n  shirudo upatch map cve-2026-31431-counter blocked_af_alg\n  shirudo upatch map cve-2026-31431-counter blocked_af_alg \\\n    --json=/var/log/shirudo/maps.ndjson\n  shirudo upatch map cve-2026-31431-counter blocked_af_alg --otel\n  shirudo upatch map foo values --otel \\\n    --otel-endpoint=https://collector:4318\n  shirudo upatch map cve-2026-31431-counter big_hash --show-full"),
    );
}

/// What the command line asks for, and the configuration fills in.
#[derive(Default)]
struct Args<'a> {
    all: bool,
    json: bool,
    json_path: Option<&'a CStr>,
    show_full: bool,
    peek: bool,
    otel: bool,
    endpoint: Option<&'a CStr>,
    tenant_id: Option<&'a CStr>,
    insecure: Option<bool>,
    retries: Option<u32>,
    s3_uri: Option<&'a CStr>,
    upatch: Option<&'a CStr>,
    map: Option<&'a CStr>,
}

/// A tenant ID: 1 to 128 of `[A-Za-z0-9._-]`.
fn tenant_id_valid(id: &[u8]) -> bool {
    (1..=128).contains(&id.len())
        && id
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
}

/// Fails the command line with `msg`: exit 2.
fn bad(msg: &[u8]) -> Result<Args<'static>, c_int> {
    err(&[b"upatch map: ", msg, b"\n"].concat());
    Err(2)
}

/// The command line, or how the command exits without running.
fn parse<'a>(args: &[&'a CStr]) -> Result<Args<'a>, c_int> {
    let mut o = Args::default();
    let mut i = 1;

    while i < args.len() {
        let a = args[i].to_bytes();
        if is_help(Some(a)) {
            usage();
            return Err(0);
        }
        if a == b"--all" {
            if o.all {
                return bad(b"duplicate --all");
            }
            o.all = true;
        } else if let Some(path) = a.strip_prefix(b"--json=") {
            if o.json || path.is_empty() {
                return bad(b"invalid or duplicate --json");
            }
            o.json = true;
            o.json_path = CStr::from_bytes_with_nul(&args[i].to_bytes_with_nul()[7..]).ok();
        } else if a == b"--json" {
            if o.json {
                return bad(b"duplicate --json");
            }
            o.json = true;
        } else if a == b"--show-full" {
            o.show_full = true;
        } else if a == b"--peek" {
            o.peek = true;
        } else if a == b"--otel" {
            if o.otel {
                return bad(b"duplicate --otel");
            }
            o.otel = true;
        } else if a == b"--otel-insecure" {
            if o.insecure.is_some() {
                return bad(b"duplicate --otel-insecure");
            }
            o.insecure = Some(true);
        } else if let Some((name, v)) = [
            &b"--otel-endpoint"[..],
            b"--tenant-id",
            b"--otel-retries",
            b"--s3-uri",
        ]
        .iter()
        .find_map(|&n| match opt(n, args, &mut i) {
            Opt::No => None,
            r => Some((n, r)),
        }) {
            let Opt::Value(v) = v else {
                return bad(&[a, b" takes a value"].concat());
            };
            let vb = v.to_bytes();
            match name {
                b"--otel-endpoint" if o.endpoint.is_none() && !vb.is_empty() => {
                    o.endpoint = Some(v)
                }
                b"--tenant-id" if o.tenant_id.is_none() && tenant_id_valid(vb) => {
                    o.tenant_id = Some(v)
                }
                b"--tenant-id" => {
                    return bad(b"invalid or duplicate --tenant-id; expected 1..128 characters using A-Z, a-z, 0-9, '.', '_', or '-'");
                }
                b"--otel-retries" if o.retries.is_none() && !vb.is_empty() => {
                    match parse_u64(vb, 10) {
                        Ok(r) => o.retries = Some(r as u32),
                        Err(_) => return bad(b"--otel-retries must be 0..10"),
                    }
                }
                b"--s3-uri" if o.s3_uri.is_none() && !vb.is_empty() => o.s3_uri = Some(v),
                _ => return bad(&[b"invalid or duplicate ", name].concat()),
            }
        } else if a.first() == Some(&b'-') {
            return bad(&[b"unknown option '", a, b"'"].concat());
        } else if o.upatch.is_none() {
            o.upatch = Some(args[i]);
        } else if o.map.is_none() {
            o.map = Some(args[i]);
        } else {
            return bad(&[b"unexpected argument '", a, b"'"].concat());
        }
        i += 1;
    }
    Ok(o)
}

/// A configured string, none when empty.
fn configured(field: &[u8]) -> Option<&CStr> {
    CStr::from_bytes_until_nul(field)
        .ok()
        .filter(|s| !s.is_empty())
}

fn os_err(e: &std::io::Error) -> c_int {
    -e.raw_os_error().unwrap_or(EIO)
}

/// Appends `json` and a newline to the locked `file` of `size` bytes,
/// after a newline when it lacks a last one; rolls a partial append back.
fn append_locked(mut file: &File, path: &CStr, json: &[u8]) -> c_int {
    let size = match file.metadata() {
        Ok(m) if m.file_type().is_file() => m.len(),
        Ok(_) => return -EINVAL,
        Err(e) => return os_err(&e),
    };
    let wrote = (|| {
        if size > 0 {
            let mut last = [0u8];
            match file.read_at(&mut last, size - 1) {
                Ok(1) => {}
                Ok(_) => return Err(-EIO),
                Err(e) => return Err(os_err(&e)),
            }
            if last[0] != b'\n' {
                file.write_all(b"\n").map_err(|e| os_err(&e))?;
            }
        }
        file.write_all(json).map_err(|e| os_err(&e))?;
        file.write_all(b"\n").map_err(|e| os_err(&e))?;
        file.sync_all().map_err(|e| os_err(&e))
    })();
    match wrote {
        Ok(()) => 0,
        Err(ret) => {
            if let Err(e) = file.set_len(size) {
                log_warn(
                    &[
                        b"upatch map: could not roll back partial JSON append to ",
                        path.to_bytes(),
                        b": ",
                        strerr(-os_err(&e)),
                    ]
                    .concat(),
                );
            }
            ret
        }
    }
}

/// Appends the record `json` to the file at `path`, under its lock: 0 or
/// -errno.
fn append_record(path: &CStr, json: &[u8]) -> c_int {
    // SAFETY: a C string.
    let fd = unsafe { seal_output_open(path.as_ptr(), O_RDWR | O_CREAT | O_APPEND, 0o644) };
    if fd < 0 {
        return fd;
    }
    // SAFETY: the descriptor just opened, which the file owns.
    let file = unsafe { File::from_raw_fd(fd) };
    let mut ret = lock_exclusive(fd);
    if ret == 0 {
        ret = append_locked(&file, path, json);
        // SAFETY: the descriptor locked above.
        unsafe { flock(fd, LOCK_UN) };
    }
    // SAFETY: the descriptor, closed once, its error kept.
    if unsafe { close(file.into_raw_fd()) } != 0 && ret == 0 {
        ret = -errno();
    }
    ret
}

/// The record `json` and its newline, appended to the file at `path` or
/// written to stdout: 0 or -errno.
fn emit_record(path: Option<&CStr>, json: &[u8]) -> c_int {
    match path {
        Some(p) => append_record(p, json),
        None => {
            // SAFETY: the bytes, then a newline, to stdout.
            let r = unsafe { write_complete(STDOUT_FILENO, json.as_ptr().cast(), json.len()) };
            if r == 0 {
                // SAFETY: as above.
                unsafe { write_complete(STDOUT_FILENO, c"\n".as_ptr().cast(), 1) }
            } else {
                r
            }
        }
    }
}

/// Reports an emit_record() failure for `path`.
fn emit_failed(path: Option<&CStr>, e: c_int) {
    match path {
        Some(p) => log_err(
            &[
                b"upatch map: append JSON to ",
                p.to_bytes(),
                b": ",
                strerr(-e),
            ]
            .concat(),
        ),
        None => log_err(&[b"upatch map: print JSON: ", strerr(-e)].concat()),
    }
}

/// The map's JSON record as its decoder makes it, without trailing line
/// ends: 0 or -errno.
fn append_json(path: Option<&CStr>, v: &MapView) -> c_int {
    match decode::map_json(v) {
        Ok(o) => {
            // SAFETY: the decoder's output, its len bytes.
            let json = unsafe { crate::ffi::slice(o.ptr.cast::<u8>(), o.len) };
            let end = json
                .iter()
                .rposition(|&c| c != b'\n' && c != b'\r')
                .map_or(0, |i| i + 1);
            let ret = emit_record(path, &json[..end]);
            // SAFETY: the output and its NUL, freed once.
            unsafe { xfree(o.ptr.cast(), o.len + 1) };
            ret
        }
        Err(e) => e,
    }
}

/// Map `map` of upatch `upatch` read and exported as `a` asks, printed
/// in detail when `detail`: 0 or 1.
fn export(
    upatch: *const c_char,
    map: *const c_char,
    a: &Args,
    opts: &OtelOpts,
    detail: bool,
) -> c_int {
    let cap = if a.show_full || a.json || a.otel {
        0
    } else {
        MAP_ENTRIES_DEFAULT
    };
    // SAFETY: an all-zero view is an empty one.
    let mut v: Box<MapView> = Box::new(unsafe { core::mem::zeroed() });
    // SAFETY: the caller's C strings.
    let (u, m) = unsafe { (crate::ffi::c_str(upatch), crate::ffi::c_str(map)) };
    let r = map_read::read(u, m, cap, if a.peek { MAP_READ_PEEK } else { 0 }, &mut v);
    // SAFETY: the caller's C strings.
    let (u, m) = unsafe { (crate::ffi::c_str(upatch), crate::ffi::c_str(map)) };
    let mut ret = 0;

    if r != 0 {
        log_err(&[b"upatch map: read ", u, b"/", m, b": ", strerr(-r)].concat());
        ret = 1;
    } else {
        if a.json {
            let e = append_json(a.json_path, &v);
            if e != 0 {
                emit_failed(a.json_path, e);
                ret = 1;
            }
        }
        if a.otel {
            let e = match decode::signal(&v) {
                Err(e) if e == -ENODATA => otel::send_auto(&v, Some(opts)),
                Ok(s) => otel::send_decoded(&v, s as c_int, Some(opts)),
                Err(e) => e,
            };
            if e != 0 {
                log_err(&[b"upatch map: OTLP export ", u, b"/", m, b": ", strerr(-e)].concat());
                ret = 1;
            }
        }
        if detail {
            map_render::print_detail(&v);
            // SAFETY: the C library's stdout, whose error flag the print
            // leaves.
            if unsafe { ferror(stdout) } != 0 {
                ret = 1;
            }
        }
    }
    map_read::view_free(&mut v);
    ret
}

/// The maps listed, as a table or a JSON record: 0 or 1.
fn summary(a: &Args, maps: &Summaries) -> c_int {
    if !a.json {
        map_render::print_summary(maps.as_slice());
        return 0;
    }
    let mut e = JsonEmit::growing(JSON_MAX);
    e.obj_open();
    e.kv_int(b"schema", 1);
    e.arr_open(b"maps");
    for m in maps.as_slice() {
        e.obj_open();
        e.kv_string(b"upatch", cstr(&m.upatch));
        e.kv_string(b"name", cstr(&m.name));
        e.kv_string(b"type", type_name(m));
        e.kv_int(b"max_entries", i64::from(m.max_entries));
        if m.n_cpus > 1 {
            e.kv_int(b"n_cpus", i64::from(m.n_cpus));
        }
        e.obj_close();
    }
    e.arr_close();
    e.obj_close();
    let (buf, cap, len) = e.parts();
    let ret = if e.err() != 0 {
        1
    } else {
        // SAFETY: the len bytes the emitter wrote.
        let r = emit_record(a.json_path, unsafe {
            crate::ffi::slice(buf.cast::<u8>(), len)
        });
        if r != 0 {
            emit_failed(a.json_path, r);
        }
        c_int::from(r != 0)
    };
    // SAFETY: the buffer the emitter grew, freed once.
    unsafe { xfree(buf.cast(), cap) };
    ret
}

/// `upatch map`, from `map` on.
pub(super) fn run(args: &[&CStr]) -> c_int {
    let mut cfg = Scrubbed(MaybeUninit::zeroed());
    let mut a = match parse(args) {
        Ok(a) => a,
        Err(code) => return code,
    };
    let mut opts = OtelOpts {
        endpoint: core::ptr::null(),
        tenant_id: core::ptr::null(),
        s3_uri: core::ptr::null(),
        allow_insecure: a.insecure.unwrap_or(false),
        retries: a.retries.unwrap_or(3),
        log_record_max_bytes: 0,
        otlp_max_bytes: 0,
    };

    if a.all {
        // SAFETY: room for the configuration.
        let e = unsafe { config::load(cfg.ptr()) };
        if e != 0 {
            log_err(&[b"upatch map: load export configuration: ", strerr(-e)].concat());
            return 1;
        }
        // SAFETY: the configuration loaded above.
        let c = unsafe { cfg.0.assume_init_ref() };
        if !c.map_export_valid {
            log_err(b"upatch map: invalid map_export configuration");
            return 2;
        }
        if !a.json {
            if let Some(p) = configured(&c.map_export_json_path) {
                a.json_path = Some(p);
                a.json = true;
            }
        }
        a.otel |= configured(&c.map_export_otel_endpoint).is_some();
        if a.otel {
            a.endpoint = a.endpoint.or(configured(&c.map_export_otel_endpoint));
            a.tenant_id = a.tenant_id.or(configured(&c.map_export_tenant_id));
            a.s3_uri = a.s3_uri.or(configured(&c.map_export_s3_uri));
            opts.allow_insecure = a.insecure.unwrap_or(c.map_export_otel_insecure);
            opts.retries = a.retries.unwrap_or(c.map_export_otel_retries);
            opts.log_record_max_bytes = c.map_export_log_record_max_bytes;
            opts.otlp_max_bytes = c.map_export_otlp_max_bytes;
        }
    }
    let ptr = |s: Option<&CStr>| s.map_or(core::ptr::null(), CStr::as_ptr);
    opts.endpoint = ptr(a.endpoint);
    opts.tenant_id = ptr(a.tenant_id);
    opts.s3_uri = ptr(a.s3_uri);

    let otlp_options = a.endpoint.is_some()
        || a.tenant_id.is_some()
        || a.insecure.is_some()
        || a.retries.is_some()
        || a.s3_uri.is_some();
    if otlp_options && !a.otel {
        err(b"upatch map: OTLP options require --otel\n");
        return 2;
    }
    if a.all && (a.upatch.is_some() || a.map.is_some()) {
        err(b"upatch map: --all does not accept positional arguments\n");
        return 2;
    }
    if a.otel && !a.all && (a.upatch.is_none() || a.map.is_none()) {
        err(b"upatch map: --otel requires <upatch> and <map>\n");
        return 2;
    }
    let detail = !a.json && !a.otel;
    if let Some(u) = a.upatch {
        if !name_valid(Some(u.to_bytes())) {
            log_err(&[b"upatch map: invalid upatch name '", u.to_bytes(), b"'"].concat());
            return 2;
        }
    }
    if let (Some(u), Some(m)) = (a.upatch, a.map) {
        return export(u.as_ptr(), m.as_ptr(), &a, &opts, detail);
    }
    let maps = Summaries::of(a.upatch);
    if a.all {
        let mut ret = 0;
        for m in maps.as_slice() {
            if export(
                m.upatch.as_ptr().cast(),
                m.name.as_ptr().cast(),
                &a,
                &opts,
                detail,
            ) != 0
            {
                ret = 1;
            }
        }
        return ret;
    }
    summary(&a, &maps)
}
