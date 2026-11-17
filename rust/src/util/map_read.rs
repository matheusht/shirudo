// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! Reading the maps a loaded upatch pins. A map is read generically, an
//! array by index and a hash by its keys, or through the serializer the
//! upatch pins beside it. A serializer is a BPF program that BPF_PROG_TEST_RUN
//! runs a page at a time, writing chunks to the upatch's output map. The
//! maps of one upatch or of all are listed.
//!
//! A view keeps the C's allocations, xmalloc()'d and freed by size, so
//! that map_view_free() frees a view whoever filled it.

use core::ffi::{CStr, c_int, c_long, c_void};
use core::sync::atomic::{AtomicI32, Ordering};
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;

use crate::errno::{
    E2BIG, EBADMSG, EINVAL, EIO, ENAMETOOLONG, ENOENT, ENOMEM, EOPNOTSUPP, EOVERFLOW,
};
use crate::sys::bpf::{
    bpf_map_get_next_key, bpf_map_lookup_elem, bpf_map_update_elem, bpf_obj_get,
};
use crate::sys::btf::{
    btf__free, btf__load_from_kernel_by_id, btf__load_vmlinux_btf, libbpf_get_error,
};
use crate::sys::libc::{close, errno, syscall};
use crate::sys::malloc::{xcalloc, xfree, xmalloc, xreallocarray};
use crate::sys::upatch::MapSummary;
use crate::sys::upatch_maps::{MAP_READ_PEEK, MapEntry, MapView, SerialPage};
use crate::text::strscpy;
use crate::util::bpf_info::{Info, MAP_INFO_SIZE};
use crate::util::map_format::{is_percpu, type_def, type_name, value_stride};
use crate::util::serializer::{
    SerialChunk, chunk_validate, new_invocation_id, serializer_lock_acquire,
};
use crate::util::upatch::name_from_pin;
use crate::util::upatch_resolve::{BPFFS_UPATCHES_DIR, pin_path, resolve_location};

/// What bpf/lib/serializer.h fixes of the serializer protocol.
const SERIAL_MAP_NAME: &[u8] = b"shirudo_ser";
const SERIAL_MAGIC: u32 = 0x5a4c_5253;
const SERIAL_VERSION: u32 = 1;
const SERIAL_MAX_CHUNKS: u32 = 256;
const SERIAL_MAX_PAGES: u32 = 256;
const SERIAL_F_DONE: u32 = 1;
const SERIAL_CTX_F_PEEK: u32 = 1;
const SERIAL_CHUNK_PAYLOAD: u32 = 4032;
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
const SYS_BPF: c_long = 321;
#[cfg(target_arch = "x86_64")]
const SYS_SCHED_GETAFFINITY: c_long = 204;
#[cfg(target_arch = "aarch64")]
const SYS_BPF: c_long = 280;
#[cfg(target_arch = "aarch64")]
const SYS_SCHED_GETAFFINITY: c_long = 123;
const BPF_PROG_TEST_RUN: c_long = 10;
const BPF_ANY: u64 = 0;
/// `union bpf_attr`: its size and where the test run's fields sit.
const ATTR_SIZE: usize = 168;
const ATTR_PROG_FD: usize = 0;
const ATTR_RETVAL: usize = 4;
const ATTR_CTX_SIZE_IN: usize = 40;
const ATTR_CTX_IN: usize = 48;

/// The name status and the table give BPF_MAP_TYPE_* `ty`.
fn map_type_name(ty: u32) -> &'static CStr {
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
fn map_skip_reason(ty: u32) -> Option<&'static CStr> {
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
fn open_map_pin(upatch: &[u8], map: &[u8]) -> Result<(c_int, Info<MAP_INFO_SIZE>), c_int> {
    let path = pin_path(upatch, &[b"maps", map])?;
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(path.as_ptr()) };
    if fd < 0 {
        return Err(-errno());
    }
    let mut info = Info::<MAP_INFO_SIZE>::new();
    if info.read(fd).is_err() {
        let e = -errno();
        // SAFETY: the pin opened above.
        unsafe { close(fd) };
        return Err(e);
    }
    Ok((fd, info))
}

/// The serializer upatch `upatch` pins for map `map`, opened, or -errno.
fn open_serializer_pin(upatch: &[u8], map: &[u8]) -> c_int {
    let path = match pin_path(upatch, &[b"serializers", map]) {
        Ok(p) => p,
        Err(e) => return e,
    };
    // SAFETY: a C string.
    let fd = unsafe { bpf_obj_get(path.as_ptr()) };
    if fd < 0 { -errno() } else { fd }
}

/// One BPF_PROG_TEST_RUN of `prog_fd` over `ctx`: its return value, or
/// -errno.
pub(crate) fn prog_test_run(prog_fd: c_int, ctx: *mut c_void, ctx_size: u32) -> Result<u32, c_int> {
    #[repr(C, align(8))]
    struct Attr([u8; ATTR_SIZE]);
    let mut attr = Attr([0; ATTR_SIZE]);
    attr.0[ATTR_PROG_FD..ATTR_PROG_FD + 4].copy_from_slice(&(prog_fd as u32).to_ne_bytes());
    attr.0[ATTR_CTX_IN..ATTR_CTX_IN + 8].copy_from_slice(&(ctx as u64).to_ne_bytes());
    attr.0[ATTR_CTX_SIZE_IN..ATTR_CTX_SIZE_IN + 4].copy_from_slice(&ctx_size.to_ne_bytes());
    // SAFETY: the bpf() syscall with an attribute of its size, whose
    // context the caller passes.
    let ret = unsafe {
        syscall(
            SYS_BPF,
            BPF_PROG_TEST_RUN,
            attr.0.as_mut_ptr(),
            ATTR_SIZE as c_long,
        )
    };
    if ret < 0 {
        return Err(-errno());
    }
    Ok(u32::from_ne_bytes(
        attr.0[ATTR_RETVAL..ATTR_RETVAL + 4]
            .try_into()
            .unwrap_or_default(),
    ))
}

/// The output map of a serializer: an array of 4-byte keys and chunk
/// values, of at most SERIAL_MAX_CHUNKS entries.
fn validate_serial_map(info: &Info<MAP_INFO_SIZE>) -> c_int {
    if info.u32_at(MAP_TYPE) != ARRAY
        || info.u32_at(MAP_KEY_SIZE) != 4
        || info.u32_at(MAP_VALUE_SIZE) as usize != size_of::<SerialChunk>()
    {
        return -EINVAL;
    }
    let max = info.u32_at(MAP_MAX_ENTRIES);
    if max == 0 || max > SERIAL_MAX_CHUNKS {
        return -E2BIG;
    }
    0
}

/// Zeroes every chunk of the output map before a run.
fn clear_serial_map(fd: c_int, max_entries: u32, value_size: u32) -> c_int {
    let zero = vec![0u8; value_size as usize];
    for i in 0..max_entries {
        // SAFETY: the map, a key and a value of its sizes.
        if unsafe { bpf_map_update_elem(fd, (&raw const i).cast(), zero.as_ptr().cast(), BPF_ANY) }
            != 0
        {
            return -errno();
        }
    }
    0
}

/// The page the serializer wrote: its chunks checked against each other
/// and the request, their payloads joined into an xmalloc()'d buffer.
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
    let buf = if bytes_total == 0 {
        core::ptr::null_mut()
    } else {
        // SAFETY: a size alone.
        let p = unsafe { xmalloc(bytes_total as usize) }.cast::<u8>();
        if p.is_null() {
            return Err(-ENOMEM);
        }
        // SAFETY: the allocation, of the page's bytes.
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), p, data.len()) };
        p.cast()
    };
    Ok(SerialPage {
        page_index,
        cursor,
        next_cursor,
        flags,
        chunks: total,
        bytes: bytes_total,
        done: flags & SERIAL_F_DONE != 0,
        data: buf,
    })
}

/// Appends `page` to the view's pages, which own its data.
fn append_serial_page(out: &mut MapView, page: SerialPage) -> Result<(), SerialPage> {
    let n = out.n_serial_pages as usize;
    // SAFETY: the view's pages, grown by one.
    let p = unsafe { xreallocarray(out.serial_pages.cast(), n, n + 1, size_of::<SerialPage>()) }
        .cast::<SerialPage>();
    if p.is_null() {
        return Err(page);
    }
    // SAFETY: the slot just made.
    unsafe { p.add(n).write(page) };
    out.serial_pages = p;
    out.n_serial_pages += 1;
    Ok(())
}

fn free_pages(out: &mut MapView) {
    if out.serial_pages.is_null() {
        return;
    }
    for i in 0..out.n_serial_pages as usize {
        // SAFETY: the view's pages, each its data's owner.
        unsafe {
            let page = &*out.serial_pages.add(i);
            xfree(page.data, page.bytes as usize);
        }
    }
    // SAFETY: the pages, by their count.
    unsafe {
        xfree(
            out.serial_pages.cast(),
            out.n_serial_pages as usize * size_of::<SerialPage>(),
        )
    };
    out.serial_pages = core::ptr::null_mut();
    out.n_serial_pages = 0;
    out.serial_bytes_total = 0;
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

/// The descriptors a serialized read holds, closed when dropped.
struct Fds(Vec<c_int>);

impl Drop for Fds {
    fn drop(&mut self) {
        for &fd in self.0.iter().filter(|&&fd| fd >= 0) {
            // SAFETY: a descriptor opened here, closed once.
            unsafe { close(fd) };
        }
    }
}

/// The map through the serializer upatch `upatch` pins for it, page by
/// page until the serializer says it is done: 1, 0 for a map without a
/// serializer, or -errno with no pages kept.
fn try_read_serialized(upatch: &[u8], map: &[u8], flags: u32, out: &mut MapView) -> c_int {
    let ret = read_serialized(upatch, map, flags, out);
    if ret < 0 {
        free_pages(out);
    }
    ret
}

fn read_serialized(upatch: &[u8], map: &[u8], flags: u32, out: &mut MapView) -> c_int {
    if map == SERIAL_MAP_NAME {
        return 0;
    }
    let prog = open_serializer_pin(upatch, map);
    if prog < 0 {
        return if prog == -ENOENT { 0 } else { prog };
    }
    let mut fds = Fds(vec![prog]);
    let (serial, info) = match open_map_pin(upatch, SERIAL_MAP_NAME) {
        Ok(p) => p,
        Err(e) => return e,
    };
    fds.0.push(serial);
    let ret = validate_serial_map(&info);
    if ret != 0 {
        return ret;
    }
    // Clearing, running and reading are one transaction, under a lock
    // keyed by the output map's kernel ID: every process sharing the map
    // contends, and unrelated upatches stay independent.
    let lock = serializer_lock_acquire(info.u32_at(MAP_ID));
    if lock < 0 {
        return lock;
    }
    fds.0.push(lock);
    let mut invocation_id = 0u64;
    let ret = new_invocation_id(&mut invocation_id);
    if ret != 0 {
        return ret;
    }
    let max = info.u32_at(MAP_MAX_ENTRIES);
    let (mut cursor, mut bytes_total) = (0u64, 0u64);
    for page_index in 0..SERIAL_MAX_PAGES {
        let ret = clear_serial_map(serial, max, info.u32_at(MAP_VALUE_SIZE));
        if ret != 0 {
            return ret;
        }
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
        let retval = match prog_test_run(
            prog,
            (&raw mut ctx).cast(),
            size_of::<SerializeCtx>() as u32,
        ) {
            Ok(r) => r,
            Err(e) => return e,
        };
        if (retval as i32) < 0 {
            return retval as i32;
        }
        if ctx.magic != SERIAL_MAGIC
            || ctx.version != SERIAL_VERSION
            || ctx.page_index != page_index
            || ctx.cursor != cursor
            || ctx.invocation_id != invocation_id
        {
            return -EBADMSG;
        }
        let page = match read_serial_page(serial, max, page_index, cursor, invocation_id) {
            Ok(p) => p,
            Err(e) => return e,
        };
        if bytes_total + u64::from(page.bytes) > SERIAL_MAX_TOTAL_BYTES {
            // SAFETY: the page's data, freed once.
            unsafe { xfree(page.data, page.bytes as usize) };
            return -E2BIG;
        }
        bytes_total += u64::from(page.bytes);
        let (done, next) = (page.done, page.next_cursor);
        if let Err(page) = append_serial_page(out, page) {
            // SAFETY: as above.
            unsafe { xfree(page.data, page.bytes as usize) };
            return -ENOMEM;
        }
        if done {
            break;
        }
        if next == cursor {
            return -EBADMSG;
        }
        cursor = next;
    }
    // SAFETY: the view's pages, its last when there is one.
    let last_done = out.n_serial_pages != 0
        && unsafe { (*out.serial_pages.add(out.n_serial_pages as usize - 1)).done };
    if !last_done {
        return -E2BIG;
    }
    out.serialized = true;
    out.serial_bytes_total = bytes_total;
    1
}

/// The map's entries, at most `cap` of them or all for 0: an array by
/// index, holes left out, a hash by its keys.
fn read_entries(fd: c_int, v: &mut MapView, cap: u32) -> c_int {
    let count = if is_percpu(v.ty) {
        v.n_cpus as usize
    } else {
        1
    };
    let Some(value_alloc) = (value_stride(v) as usize).checked_mul(count) else {
        return -EOVERFLOW;
    };
    let key_size = v.key_size as usize;
    v.entries = core::ptr::null_mut();
    v.n_entries = 0;
    v.truncated = false;
    v.n_truncated_at = cap;

    // SAFETY: sizes alone, and buffers freed by them.
    let alloc = |n: usize| unsafe { xmalloc(n) };
    // SAFETY: as above.
    let free = |p: *mut c_void, n: usize| unsafe { xfree(p, n) };
    let push = |v: &mut MapView, key: *mut c_void, value: *mut c_void| {
        // SAFETY: a slot below entries_cap.
        unsafe {
            v.entries
                .add(v.n_entries as usize)
                .write(MapEntry { key, value })
        };
        v.n_entries += 1;
    };

    if is_array(v.ty) {
        let mut take = v.max_entries;
        if cap != 0 && take > cap {
            take = cap;
            v.truncated = v.max_entries > cap;
        }
        if take == 0 {
            return 0;
        }
        // SAFETY: a count and a size.
        v.entries = unsafe { xcalloc(take as usize, size_of::<MapEntry>()) }.cast();
        v.entries_cap = take as usize;
        if v.entries.is_null() {
            return -ENOMEM;
        }
        for i in 0..take {
            let (key, value) = (alloc(key_size), alloc(value_alloc));
            if key.is_null() || value.is_null() {
                free(key, key_size);
                free(value, value_alloc);
                return -ENOMEM;
            }
            let idx = i.to_ne_bytes();
            // SAFETY: the key's bytes, the index and zeros after it.
            unsafe {
                let n = key_size.min(4);
                core::ptr::copy_nonoverlapping(idx.as_ptr(), key.cast::<u8>(), n);
                if key_size > 4 {
                    core::ptr::write_bytes(key.cast::<u8>().add(4), 0, key_size - 4);
                }
            }
            // SAFETY: the map, a key and room for a value of its sizes.
            if unsafe { bpf_map_lookup_elem(fd, key, value) } != 0 {
                free(key, key_size);
                free(value, value_alloc);
                continue;
            }
            push(v, key, value);
        }
        return 0;
    }
    if !is_hash(v.ty) {
        return -EOPNOTSUPP;
    }
    v.entries_cap = 32;
    // SAFETY: a count and a size.
    v.entries = unsafe { xcalloc(v.entries_cap, size_of::<MapEntry>()) }.cast();
    if v.entries.is_null() {
        return -ENOMEM;
    }
    let next = alloc(key_size);
    if next.is_null() {
        return -ENOMEM;
    }
    let mut prev: *const c_void = core::ptr::null();
    // SAFETY: the map, the previous key or NULL, and room for the next.
    while unsafe { bpf_map_get_next_key(fd, prev, next) } == 0 {
        let (key, value) = (alloc(key_size), alloc(value_alloc));
        if key.is_null() || value.is_null() {
            free(key, key_size);
            free(value, value_alloc);
            break;
        }
        // SAFETY: two buffers of the key's size.
        unsafe { core::ptr::copy_nonoverlapping(next.cast::<u8>(), key.cast::<u8>(), key_size) };
        // SAFETY: the map, a key and room for a value of its sizes.
        if unsafe { bpf_map_lookup_elem(fd, key, value) } != 0 {
            free(key, key_size);
            free(value, value_alloc);
            prev = next;
            continue;
        }
        if v.n_entries as usize == v.entries_cap {
            let cap2 = v.entries_cap * 2;
            // SAFETY: the entries, grown, and the new half zeroed.
            let p = unsafe {
                xreallocarray(v.entries.cast(), v.entries_cap, cap2, size_of::<MapEntry>())
            }
            .cast::<MapEntry>();
            if p.is_null() {
                free(key, key_size);
                free(value, value_alloc);
                break;
            }
            // SAFETY: as above.
            unsafe { core::ptr::write_bytes(p.add(v.entries_cap), 0, v.entries_cap) };
            v.entries = p;
            v.entries_cap = cap2;
        }
        push(v, key, value);
        if cap != 0 && v.n_entries >= cap {
            v.truncated = true;
            break;
        }
        prev = next;
    }
    free(next, key_size);
    0
}

/// Frees what a read put in `v`: entries, BTF and serialized pages.
pub(crate) fn view_free(v: &mut MapView) {
    if !v.entries.is_null() {
        let count = if is_percpu(v.ty) {
            v.n_cpus as usize
        } else {
            1
        };
        let value_alloc = value_stride(v) as usize * count;
        for i in 0..v.n_entries as usize {
            // SAFETY: the view's entries, each its key's and value's owner.
            unsafe {
                let en = &*v.entries.add(i);
                xfree(en.key, v.key_size as usize);
                xfree(en.value, value_alloc);
            }
        }
        // SAFETY: the entries, by their capacity.
        unsafe { xfree(v.entries.cast(), v.entries_cap * size_of::<MapEntry>()) };
        v.entries = core::ptr::null_mut();
        v.entries_cap = 0;
        v.n_entries = 0;
    }
    if !v.btf.is_null() {
        // SAFETY: the view's BTF, freed once.
        unsafe { btf__free(v.btf) };
        v.btf = core::ptr::null_mut();
    }
    free_pages(v);
}

fn fill(dst: &mut [u8], src: &[u8]) -> Result<(), c_int> {
    strscpy(dst, src).map(|_| ()).map_err(|_| -ENAMETOOLONG)
}

/// Map `map` of upatch `upatch` into `out`, which it zeroes first: at
/// most `cap` entries or all for 0, through its serializer if it has one,
/// MAP_READ_PEEK in `flags` to leave the serializer's interval to the
/// exporter. 0 or -errno; view_free() frees what it holds either way.
pub(crate) fn read(upatch: &[u8], map: &[u8], cap: u32, flags: u32, out: &mut MapView) -> c_int {
    // SAFETY: an all-zero view is an empty one.
    *out = unsafe { core::mem::zeroed() };
    if fill(&mut out.upatch, upatch).is_err() || fill(&mut out.name, map).is_err() {
        return -ENAMETOOLONG;
    }
    let (fd, info) = match open_map_pin(upatch, map) {
        Ok(p) => p,
        Err(e) => return e,
    };
    let fd = Fds(vec![fd]);
    let ty = info.u32_at(MAP_TYPE);
    out.ty = ty;
    out.type_name = map_type_name(ty).as_ptr();
    out.key_size = info.u32_at(MAP_KEY_SIZE);
    out.value_size = info.u32_at(MAP_VALUE_SIZE);
    out.value_stride = stride_of(ty, out.value_size);
    out.max_entries = info.u32_at(MAP_MAX_ENTRIES);
    out.n_cpus = 1;
    if is_percpu(ty) {
        let n = nproc_possible();
        if n < 0 {
            return n;
        }
        out.n_cpus = n as u32;
    }
    // SAFETY: libbpf's loader; an error pointer libbpf_get_error() reads,
    // NULL, or a BTF freed once.
    unsafe {
        let mut vbtf = btf__load_vmlinux_btf();
        if libbpf_get_error(vbtf.cast()) != 0 {
            vbtf = core::ptr::null_mut();
        }
        resolve_location(vbtf, upatch, &mut out.location);
        btf__free(vbtf);
    }
    if let Ok(dir) = pin_path(upatch, &[]) {
        if let Ok(st) = fs::metadata(os(dir.as_bytes())) {
            out.lifetime_start_ns = (st.ctime() as u64)
                .wrapping_mul(1_000_000_000)
                .wrapping_add(st.ctime_nsec() as u64);
        }
    }

    match try_read_serialized(upatch, map, flags, out) {
        r if r < 0 => return r,
        r if r > 0 => return 0,
        _ => {}
    }
    if let Some(reason) = map_skip_reason(ty) {
        out.skipped = true;
        out.skipped_reason = reason.as_ptr();
        return 0;
    }
    let btf_id = info.u32_at(MAP_BTF_ID);
    out.btf = if btf_id == 0 {
        core::ptr::null_mut()
    } else {
        // SAFETY: a call that takes no pointer.
        unsafe { btf__load_from_kernel_by_id(btf_id) }
    };
    if !out.btf.is_null() {
        let (kid, vid) = (
            info.u32_at(MAP_BTF_KEY_TYPE_ID),
            info.u32_at(MAP_BTF_VALUE_TYPE_ID),
        );
        out.key_type_id = kid;
        out.value_type_id = vid;
        type_name(out.btf, kid, &mut out.btf_key_type);
        type_name(out.btf, vid, &mut out.btf_value_type);
        type_def(out.btf, kid, &mut out.key_type_def);
        type_def(out.btf, vid, &mut out.value_type_def);
    }
    read_entries(fd.0[0], out, cap)
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
        // SAFETY: the pin opened above.
        unsafe { close(fd) };
        // SAFETY: an all-zero summary is an empty one.
        let mut one: MapSummary = unsafe { core::mem::zeroed() };
        let _ = strscpy(&mut one.upatch, upatch);
        let _ = strscpy(&mut one.name, name);
        let ty = info.u32_at(MAP_TYPE);
        one.ty = ty;
        one.type_name = map_type_name(ty).as_ptr();
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

mod capi {
    use core::ffi::{CStr, c_char, c_int};

    /// The name BPF_MAP_TYPE_* `ty` goes by, "unknown" for one not
    /// told apart.
    #[unsafe(no_mangle)]
    pub extern "C" fn map_type_name(ty: u32) -> *const c_char {
        super::map_type_name(ty).as_ptr()
    }

    /// Why a map of type `ty` is not read generically, or NULL when it
    /// is.
    #[unsafe(no_mangle)]
    pub extern "C" fn map_skip_reason(ty: u32) -> *const c_char {
        super::map_skip_reason(ty).map_or(core::ptr::null(), CStr::as_ptr)
    }

    /// For the fuzzer: the page the reader would take from output map
    /// `fd` of `max_entries` chunks for page `page_index` at `cursor` of
    /// invocation `invocation_id`, into `out`, its data for
    /// xfree(data, bytes): 0 or -errno.
    ///
    /// # Safety
    ///
    /// `out` is room for a page.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn upatch_maps_read_serial_page(
        fd: c_int,
        max_entries: u32,
        page_index: u32,
        cursor: u64,
        invocation_id: u64,
        out: *mut crate::sys::upatch_maps::SerialPage,
    ) -> c_int {
        match super::read_serial_page(fd, max_entries, page_index, cursor, invocation_id) {
            Ok(p) => {
                // SAFETY: the caller's room.
                unsafe { out.write(p) };
                0
            }
            Err(e) => e,
        }
    }
}
