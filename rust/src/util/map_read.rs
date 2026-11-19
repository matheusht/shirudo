// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Reading the maps a loaded upatch pins. A map is read generically, an
//! array by index and a hash by its keys, or through the serializer the
//! upatch pins beside it. A serializer is a BPF program that BPF_PROG_TEST_RUN
//! runs a page at a time, writing chunks to the upatch's output map. The
//! maps of one upatch or of all are listed.

use core::ffi::{CStr, c_int, c_long, c_void};
use core::sync::atomic::{AtomicI32, Ordering};
use std::ffi::OsStr;
use std::fs;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::errno::{
    E2BIG, EBADMSG, EINVAL, EIO, ENAMETOOLONG, ENOENT, ENOMEM, EOPNOTSUPP, EOVERFLOW,
};
use crate::sys::libc::{errno, syscall};
use crate::sys::upatch::MapSummary;
use crate::sys::upatch_maps::{MAP_READ_PEEK, MapEntry, MapView, SerialPage};
use crate::text::strscpy;
use crate::util::bpf_info::{Info, MAP_INFO_SIZE};
use crate::util::bpf_sys::{
    BPF_ANY, bpf_map_get_next_key, bpf_map_lookup_elem, bpf_map_update_elem, obj_get, prog_test_run,
};
use crate::util::kernel_btf;
use crate::util::map_format::{is_percpu, type_def, type_name, value_stride};
use crate::util::serializer::{SERIAL_CHUNK_PAYLOAD, SERIAL_MAGIC, SERIAL_VERSION};
use crate::util::serializer::{SerialChunk, chunk_validate, new_invocation_id};
use crate::util::upatch::name_from_pin;
use crate::util::upatch_pins::pin_payload;
use crate::util::upatch_resolve::{BPFFS_UPATCHES_DIR, pin_path, resolve_location};

/// What bpf/lib/serializer.h fixes of the serializer protocol.
const SERIAL_MAP_NAME: &[u8] = b"shirudo_ser";
const SERIAL_MAX_CHUNKS: u32 = 256;
const SERIAL_MAX_PAGES: u32 = 256;
const SERIAL_F_DONE: u32 = 1;
const SERIAL_CTX_F_PEEK: u32 = 1;
const SERIAL_MAX_BYTES: u32 = SERIAL_MAX_CHUNKS * SERIAL_CHUNK_PAYLOAD;
const SERIAL_MAX_TOTAL_BYTES: u64 = SERIAL_MAX_PAGES as u64 * SERIAL_MAX_BYTES as u64;

/// BPF_MAP_TYPE_* the reader tells apart.
const HASH: u32 = 1;
const ARRAY: u32 = 2;
const PROG_ARRAY: u32 = 3;
const PERF_EVENT_ARRAY: u32 = 4;
const PERCPU_HASH: u32 = 5;
const PERCPU_ARRAY: u32 = 6;
const STACK_TRACE: u32 = 7;
const LRU_HASH: u32 = 9;
const LRU_PERCPU_HASH: u32 = 10;
const RINGBUF: u32 = 27;
const ARENA: u32 = 33;

/// `struct bpf_map_info`: where the fields read here sit.
const MAP_TYPE: usize = 0;
const MAP_ID: usize = 4;
const MAP_KEY_SIZE: usize = 8;
const MAP_VALUE_SIZE: usize = 12;
const MAP_MAX_ENTRIES: usize = 16;
const MAP_BTF_ID: usize = 64;
const MAP_BTF_KEY_TYPE_ID: usize = 68;
const MAP_BTF_VALUE_TYPE_ID: usize = 72;

#[cfg(target_arch = "x86_64")]
const SYS_SCHED_GETAFFINITY: c_long = 204;
#[cfg(target_arch = "aarch64")]
const SYS_SCHED_GETAFFINITY: c_long = 123;

/// The name status and the table give BPF_MAP_TYPE_* `ty`.
pub(crate) fn map_type_name(ty: u32) -> &'static CStr {
    match ty {
        ARRAY => c"array",
        PERCPU_ARRAY => c"percpu_array",
        HASH => c"hash",
        PERCPU_HASH => c"percpu_hash",
        LRU_HASH => c"lru_hash",
        LRU_PERCPU_HASH => c"lru_percpu_hash",
        RINGBUF => c"ringbuf",
        PERF_EVENT_ARRAY => c"perf_event_array",
        STACK_TRACE => c"stack_trace",
        PROG_ARRAY => c"prog_array",
        ARENA => c"arena",
        _ => c"unknown",
    }
}

/// Why a map of type `ty` is not read generically, if it is not.
pub(crate) fn map_skip_reason(ty: u32) -> Option<&'static CStr> {
    match ty {
        RINGBUF => Some(c"use `shirudo upatch ringbuf` (future work)"),
        PERF_EVENT_ARRAY => Some(c"perf-event-array: use `shirudo upatch perfbuf` (future work)"),
        STACK_TRACE => Some(c"stack-trace: use `shirudo upatch stacktrace` (future work)"),
        PROG_ARRAY => Some(c"prog-array carries function pointers; not dumpable"),
        ARENA => Some(c"arena map contents require a serializer"),
        _ => None,
    }
}

/// The bytes a CPU's value takes in a lookup: rounded to 8 per CPU.
fn stride_of(ty: u32, value_size: u32) -> u32 {
    if is_percpu(ty) {
        (value_size + 7) & !7
    } else {
        value_size
    }
}

fn is_array(ty: u32) -> bool {
    ty == ARRAY || ty == PERCPU_ARRAY
}

fn is_hash(ty: u32) -> bool {
    matches!(ty, HASH | PERCPU_HASH | LRU_HASH | LRU_PERCPU_HASH)
}

/// The CPUs a per-CPU lookup copies a value for. The kernel keeps the
/// count to itself: sysconf counts the present ones, and the sysfs file
/// libbpf would read is root's to replace in a mount namespace of its
/// own, so either undersizes the buffer the kernel fills. The shortest
/// mask sched_getaffinity accepts is the kernel's own cpumask,
/// nr_cpu_ids bits rounded up, and bounds what a lookup writes.
fn nproc_possible() -> c_int {
    static CACHED: AtomicI32 = AtomicI32::new(0);
    let cached = CACHED.load(Ordering::Relaxed);
    if cached != 0 {
        return cached;
    }
    let mut mask = [0u8; 1024];
    let mut len = 8usize;
    while len <= mask.len() {
        // SAFETY: the raw syscall, with room for `len` bytes of mask.
        let n = unsafe {
            syscall(
                SYS_SCHED_GETAFFINITY,
                0 as c_long,
                len as c_long,
                mask.as_mut_ptr(),
            )
        };
        if n > 0 {
            let cpus = (n * 8) as c_int;
            CACHED.store(cpus, Ordering::Relaxed);
            return cpus;
        }
        if errno() != EINVAL {
            return -errno();
        }
        len *= 2;
    }
    -E2BIG
}

fn os(b: &[u8]) -> &OsStr {
    OsStr::from_bytes(b)
}

/// The pin of map `map` of upatch `upatch`, opened, and its info.
fn open_map_pin(upatch: &[u8], map: &[u8]) -> Result<(OwnedFd, Info<MAP_INFO_SIZE>), c_int> {
    let fd = obj_get(&pin_path(upatch, &[b"maps", map])?)?;
    let mut info = Info::<MAP_INFO_SIZE>::new();
    info.read(fd.as_raw_fd())?;
    Ok((fd, info))
}

/// The serializer upatch `upatch` pins for map `map`, opened.
fn open_serializer_pin(upatch: &[u8], map: &[u8]) -> Result<OwnedFd, c_int> {
    obj_get(&pin_path(upatch, &[b"serializers", map])?)
}

/// The output map of a serializer: an array of 4-byte keys and chunk
/// values, of at most SERIAL_MAX_CHUNKS entries.
fn validate_serial_map(info: &Info<MAP_INFO_SIZE>) -> Result<(), c_int> {
    if info.u32_at(MAP_TYPE) != ARRAY
        || info.u32_at(MAP_KEY_SIZE) != 4
        || info.u32_at(MAP_VALUE_SIZE) as usize != size_of::<SerialChunk>()
    {
        return Err(-EINVAL);
    }
    let max = info.u32_at(MAP_MAX_ENTRIES);
    if max == 0 || max > SERIAL_MAX_CHUNKS {
        return Err(-E2BIG);
    }
    Ok(())
}

/// Zeroes every chunk of the output map before a run.
fn clear_serial_map(fd: c_int, max_entries: u32, value_size: u32) -> Result<(), c_int> {
    let zero = vec![0u8; value_size as usize];
    for i in 0..max_entries {
        // SAFETY: the map, a key and a value of its sizes.
        if unsafe { bpf_map_update_elem(fd, (&raw const i).cast(), zero.as_ptr().cast(), BPF_ANY) }
            != 0
        {
            return Err(-errno());
        }
    }
    Ok(())
}

/// The page the serializer wrote: its chunks checked against each other
/// and the request, their payloads joined.
fn read_serial_page(
    fd: c_int,
    max_entries: u32,
    want_page: u32,
    want_cursor: u64,
    invocation_id: u64,
) -> Result<SerialPage, c_int> {
    // SAFETY: an all-zero chunk is a valid one.
    let mut chunk: Box<SerialChunk> = Box::new(unsafe { core::mem::zeroed() });
    let lookup = |key: u32, chunk: &mut SerialChunk| -> Result<(), c_int> {
        // SAFETY: the map, a key and room for a chunk, its value size.
        match unsafe {
            bpf_map_lookup_elem(
                fd,
                (&raw const key).cast(),
                core::ptr::from_mut(chunk).cast(),
            )
        } {
            0 => Ok(()),
            _ => Err(-errno()),
        }
    };
    lookup(0, &mut chunk)?;
    if chunk.magic != SERIAL_MAGIC
        || chunk.version != SERIAL_VERSION
        || chunk.invocation_id != invocation_id
    {
        return Err(-EBADMSG);
    }
    if chunk.status != 0 {
        return Err(if chunk.status < 0 { chunk.status } else { -EIO });
    }
    let (total, bytes_total) = (chunk.total_chunks, chunk.bytes_total);
    let (page_index, cursor, next_cursor, flags) = (
        chunk.page_index,
        chunk.cursor,
        chunk.next_cursor,
        chunk.flags,
    );
    if total == 0
        || total > max_entries
        || total > SERIAL_MAX_CHUNKS
        || bytes_total > SERIAL_MAX_BYTES
        || bytes_total > total.wrapping_mul(SERIAL_CHUNK_PAYLOAD)
    {
        return Err(-EBADMSG);
    }
    if page_index != want_page || cursor != want_cursor || next_cursor < cursor {
        return Err(-EBADMSG);
    }
    let mut data = Vec::with_capacity(bytes_total as usize);
    for key in 0..total {
        if key != 0 {
            lookup(key, &mut chunk)?;
        }
        let ret = chunk_validate(
            Some(&chunk),
            key,
            total,
            page_index,
            cursor,
            next_cursor,
            invocation_id,
        );
        if ret != 0 {
            return Err(ret);
        }
        if chunk.status != 0 {
            return Err(if chunk.status < 0 { chunk.status } else { -EIO });
        }
        let n = chunk.bytes_in_chunk;
        if chunk.bytes_total != bytes_total
            || data.len() as u64 + u64::from(n) > u64::from(bytes_total)
        {
            return Err(-EBADMSG);
        }
        data.extend_from_slice(&chunk.data[..n as usize]);
    }
    if data.len() != bytes_total as usize {
        return Err(-EBADMSG);
    }
    Ok(SerialPage {
        page_index,
        cursor,
        next_cursor,
        flags,
        chunks: total,
        done: flags & SERIAL_F_DONE != 0,
        data,
    })
}

/// `struct serialize_ctx` of bpf/lib/serializer.h.
#[repr(C)]
#[derive(Default)]
struct SerializeCtx {
    magic: u32,
    version: u32,
    flags: u32,
    max_chunks: u32,
    chunk_payload_size: u32,
    page_index: u32,
    cursor: u64,
    invocation_id: u64,
}

const _: () = assert!(size_of::<SerializeCtx>() == 40);

/// The map through the serializer upatch `upatch` pins for it, into
/// `out` page by page until the serializer says it is done: whether the
/// map has a serializer.
fn read_serialized(
    upatch: &[u8],
    map: &[u8],
    flags: u32,
    out: &mut MapView,
) -> Result<bool, c_int> {
    if map == SERIAL_MAP_NAME {
        return Ok(false);
    }
    let prog = match open_serializer_pin(upatch, map) {
        Ok(fd) => fd,
        Err(e) if e == -ENOENT => return Ok(false),
        Err(e) => return Err(e),
    };
    let (serial, info) = open_map_pin(upatch, SERIAL_MAP_NAME)?;
    validate_serial_map(&info)?;
    // Clearing, running and reading are one transaction, under a lock
    // keyed by the output map's kernel ID: every process sharing the map
    // contends, and unrelated upatches stay independent.
    let _lock = crate::util::serializer::lock_acquire(info.u32_at(MAP_ID))?;
    let mut invocation_id = 0u64;
    let ret = new_invocation_id(&mut invocation_id);
    if ret != 0 {
        return Err(ret);
    }
    let max = info.u32_at(MAP_MAX_ENTRIES);
    let (mut cursor, mut bytes_total) = (0u64, 0u64);
    for page_index in 0..SERIAL_MAX_PAGES {
        clear_serial_map(serial.as_raw_fd(), max, info.u32_at(MAP_VALUE_SIZE))?;
        let mut ctx = SerializeCtx {
            magic: SERIAL_MAGIC,
            version: SERIAL_VERSION,
            flags: if flags & MAP_READ_PEEK != 0 {
                SERIAL_CTX_F_PEEK
            } else {
                0
            },
            max_chunks: max,
            chunk_payload_size: SERIAL_CHUNK_PAYLOAD,
            page_index,
            cursor,
            invocation_id,
        };
        // SAFETY: the context's bytes, a structure of integers the program
        // reads and the kernel writes back whole.
        let ctx_bytes = unsafe {
            core::slice::from_raw_parts_mut((&raw mut ctx).cast::<u8>(), size_of::<SerializeCtx>())
        };
        let retval = prog_test_run(prog.as_raw_fd(), ctx_bytes)?;
        if (retval as i32) < 0 {
            return Err(retval as i32);
        }
        if ctx.magic != SERIAL_MAGIC
            || ctx.version != SERIAL_VERSION
            || ctx.page_index != page_index
            || ctx.cursor != cursor
            || ctx.invocation_id != invocation_id
        {
            return Err(-EBADMSG);
        }
        let page = read_serial_page(serial.as_raw_fd(), max, page_index, cursor, invocation_id)?;
        if bytes_total + u64::from(page.bytes()) > SERIAL_MAX_TOTAL_BYTES {
            return Err(-E2BIG);
        }
        bytes_total += u64::from(page.bytes());
        let (done, next) = (page.done, page.next_cursor);
        out.serial_pages.try_reserve(1).map_err(|_| -ENOMEM)?;
        out.serial_pages.push(page);
        if done {
            break;
        }
        if next == cursor {
            return Err(-EBADMSG);
        }
        cursor = next;
    }
    if !out.serial_pages.last().is_some_and(|page| page.done) {
        return Err(-E2BIG);
    }
    out.serialized = true;
    out.serial_bytes_total = bytes_total;
    Ok(true)
}

/// `len` zero bytes, or -ENOMEM.
fn zeroed(len: usize) -> Result<Vec<u8>, c_int> {
    let mut buf = Vec::new();
    buf.try_reserve_exact(len).map_err(|_| -ENOMEM)?;
    buf.resize(len, 0);
    Ok(buf)
}

/// The map's entries, at most `cap` of them or all for 0: an array by
/// index, holes left out, a hash by its keys.
fn read_entries(fd: c_int, v: &mut MapView, cap: u32) -> Result<(), c_int> {
    let count = if is_percpu(v.ty) {
        v.n_cpus as usize
    } else {
        1
    };
    let value_len = (value_stride(v) as usize)
        .checked_mul(count)
        .ok_or(-EOVERFLOW)?;
    let key_len = v.key_size as usize;
    v.entries = Vec::new();
    v.truncated = false;
    v.n_truncated_at = cap;
    if is_array(v.ty) {
        read_array(fd, v, cap, key_len, value_len)
    } else if is_hash(v.ty) {
        read_hash(fd, v, cap, key_len, value_len)
    } else {
        Err(-EOPNOTSUPP)
    }
}

/// The array's entries by index, the first `cap` or all for 0: -ENOMEM
/// when a buffer cannot be had.
fn read_array(
    fd: c_int,
    v: &mut MapView,
    cap: u32,
    key_len: usize,
    value_len: usize,
) -> Result<(), c_int> {
    let mut take = v.max_entries;
    if cap != 0 && take > cap {
        take = cap;
        v.truncated = true;
    }
    v.entries
        .try_reserve_exact(take as usize)
        .map_err(|_| -ENOMEM)?;
    for index in 0..take {
        let mut key = zeroed(key_len)?;
        let mut value = zeroed(value_len)?;
        key.iter_mut()
            .zip(index.to_ne_bytes())
            .for_each(|(k, b)| *k = b);
        // SAFETY: the map, a key and room for a value of its sizes.
        if unsafe { bpf_map_lookup_elem(fd, key.as_ptr().cast(), value.as_mut_ptr().cast()) } != 0 {
            continue;
        }
        v.entries.push(MapEntry { key, value });
    }
    Ok(())
}

/// The hash's entries in the kernel's order, the first `cap` or all for
/// 0; as many as fit when a buffer cannot be had.
fn read_hash(
    fd: c_int,
    v: &mut MapView,
    cap: u32,
    key_len: usize,
    value_len: usize,
) -> Result<(), c_int> {
    let mut next = zeroed(key_len)?;
    let mut prev: *const c_void = core::ptr::null();
    // SAFETY: the map, the key before the next or NULL for the first, and
    // room for the next, of its key size.
    while unsafe { bpf_map_get_next_key(fd, prev, next.as_mut_ptr().cast()) } == 0 {
        prev = next.as_ptr().cast();
        let (Ok(mut key), Ok(mut value)) = (zeroed(key_len), zeroed(value_len)) else {
            break;
        };
        key.copy_from_slice(&next);
        // SAFETY: the map, a key and room for a value of its sizes.
        if unsafe { bpf_map_lookup_elem(fd, key.as_ptr().cast(), value.as_mut_ptr().cast()) } != 0 {
            continue;
        }
        if v.entries.try_reserve(1).is_err() {
            break;
        }
        v.entries.push(MapEntry { key, value });
        if cap != 0 && v.n_entries() >= cap {
            v.truncated = true;
            break;
        }
    }
    Ok(())
}

fn fill(dst: &mut [u8], src: &[u8]) -> Result<(), c_int> {
    strscpy(dst, src).map(|_| ()).map_err(|_| -ENAMETOOLONG)
}

/// Map `map` of upatch `upatch`: at most `cap` entries or all for 0,
/// through its serializer if it has one, MAP_READ_PEEK in `flags` to
/// leave the serializer's interval to the exporter.
pub(crate) fn read(upatch: &[u8], map: &[u8], cap: u32, flags: u32) -> Result<MapView, c_int> {
    let mut out = MapView::default();
    fill(&mut out.upatch, upatch)?;
    fill(&mut out.name, map)?;
    let (fd, info) = open_map_pin(upatch, map)?;
    let ty = info.u32_at(MAP_TYPE);
    out.ty = ty;
    out.type_name = Some(map_type_name(ty));
    out.key_size = info.u32_at(MAP_KEY_SIZE);
    out.value_size = info.u32_at(MAP_VALUE_SIZE);
    out.value_stride = stride_of(ty, out.value_size);
    out.max_entries = info.u32_at(MAP_MAX_ENTRIES);
    out.n_cpus = 1;
    if is_percpu(ty) {
        let n = nproc_possible();
        if n < 0 {
            return Err(n);
        }
        out.n_cpus = n as u32;
    }
    resolve_location(kernel_btf::vmlinux(), upatch, &mut out.location);
    if let Ok(dir) = pin_path(upatch, &[]) {
        if let Ok(st) = fs::metadata(os(dir.as_bytes())) {
            out.lifetime_start_ns = (st.ctime() as u64)
                .wrapping_mul(1_000_000_000)
                .wrapping_add(st.ctime_nsec() as u64);
        }
    }
    // What a decoder export checks the archive against.
    if let Ok(payload) = pin_payload(upatch) {
        out.payload = payload;
        out.has_payload = true;
    }

    if read_serialized(upatch, map, flags, &mut out)? {
        return Ok(out);
    }
    if let Some(reason) = map_skip_reason(ty) {
        out.skipped = true;
        out.skipped_reason = Some(reason);
        return Ok(out);
    }
    let btf_id = info.u32_at(MAP_BTF_ID);
    out.btf = (btf_id != 0)
        .then(|| kernel_btf::by_id(btf_id).ok())
        .flatten();
    if let Some(btf) = &out.btf {
        let (kid, vid) = (
            info.u32_at(MAP_BTF_KEY_TYPE_ID),
            info.u32_at(MAP_BTF_VALUE_TYPE_ID),
        );
        out.key_type_id = kid;
        out.value_type_id = vid;
        type_name(Some(btf), kid, &mut out.btf_key_type);
        type_name(Some(btf), vid, &mut out.btf_value_type);
        type_def(Some(btf), kid, &mut out.key_type_def);
        type_def(Some(btf), vid, &mut out.value_type_def);
    }
    read_entries(fd.as_raw_fd(), &mut out, cap)?;
    Ok(out)
}

/// The maps upatch `upatch` pins, onto `list`, in directory order: each
/// that opens, but the serializers' output map.
fn scan(upatch: &[u8], list: &mut Vec<MapSummary>) {
    let Ok(dir) = pin_path(upatch, &[b"maps"]) else {
        return;
    };
    let Ok(entries) = fs::read_dir(os(dir.as_bytes())) else {
        return;
    };
    for e in entries.map_while(Result::ok) {
        let name = e.file_name();
        let name = name.as_bytes();
        if name.first() == Some(&b'.') || name == SERIAL_MAP_NAME {
            continue;
        }
        let Ok((fd, info)) = open_map_pin(upatch, name) else {
            continue;
        };
        drop(fd);
        // SAFETY: an all-zero summary is an empty one.
        let mut one: MapSummary = unsafe { core::mem::zeroed() };
        let _ = strscpy(&mut one.upatch, upatch);
        let _ = strscpy(&mut one.name, name);
        let ty = info.u32_at(MAP_TYPE);
        one.ty = ty;
        one.type_name = Some(map_type_name(ty));
        one.max_entries = info.u32_at(MAP_MAX_ENTRIES);
        one.n_cpus = 1;
        if is_percpu(ty) {
            let cpus = nproc_possible();
            if cpus < 0 {
                continue;
            }
            one.n_cpus = cpus as u32;
        }
        list.push(one);
    }
}

/// The maps upatch `upatch` pins, or with none every loaded upatch's.
pub(crate) fn list(upatch: Option<&[u8]>) -> Vec<MapSummary> {
    let mut list = Vec::new();
    match upatch {
        Some(u) => scan(u, &mut list),
        None => {
            if let Ok(entries) = fs::read_dir(BPFFS_UPATCHES_DIR) {
                for e in entries.map_while(Result::ok) {
                    let pin = e.file_name();
                    let pin = pin.as_bytes();
                    if pin.first() == Some(&b'.') {
                        continue;
                    }
                    if let Some(name) = name_from_pin(pin).filter(|n| n.len() <= 256) {
                        scan(&name, &mut list);
                    }
                }
            }
        }
    }
    list
}

#[cfg(shirudo_fuzz)]
mod fuzz;
