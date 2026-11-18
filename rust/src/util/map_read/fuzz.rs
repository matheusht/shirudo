// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! fuzz-serializer: a serialized map's page read from chunks of the
//! input, which a wrap of syscall() hands the reader as its map's
//! lookups; the page asked for is the one the first chunk names, as a
//! consistent serializer wrote it.

use core::ffi::{c_int, c_long};
use core::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use super::capi::upatch_maps_read_serial_page;
use crate::fuzzing::fuzz_target;
use crate::heap::xfree;
use crate::sys::upatch_maps::SerialPage;
use crate::util::serializer::SerialChunk;

const BPF_MAP_LOOKUP_ELEM: c_long = 1;

static CHUNKS: AtomicPtr<u8> = AtomicPtr::new(core::ptr::null_mut());
static CHUNKS_LEN: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn __real_syscall(number: c_long, ...) -> c_long;
}

/// The map's lookups, answered from the input: the chunk at the key's
/// index, zero-padded, or ENOENT past its end.
///
/// # Safety
///
/// As syscall(2) with these arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __wrap_syscall(
    number: c_long,
    a0: c_long,
    a1: c_long,
    a2: c_long,
    a3: c_long,
    a4: c_long,
    a5: c_long,
) -> c_long {
    if number != libc::SYS_bpf || a0 != BPF_MAP_LOOKUP_ELEM {
        // SAFETY: the caller's call, made.
        return unsafe { __real_syscall(number, a0, a1, a2, a3, a4, a5) };
    }
    let attr = a1 as *const u8;
    let size = size_of::<SerialChunk>();
    // SAFETY: the lookup's attribute, its key an index and its value room
    // for a chunk; the input, of its length.
    unsafe {
        let key = attr.add(8).cast::<u64>().read_unaligned() as *const u32;
        let value = attr.add(16).cast::<u64>().read_unaligned() as *mut u8;
        let off = key.read_unaligned() as usize * size;
        let len = CHUNKS_LEN.load(Ordering::Relaxed);
        if off >= len {
            *libc::__errno_location() = libc::ENOENT;
            return -1;
        }
        let n = (len - off).min(size);
        value.write_bytes(0, size);
        core::ptr::copy_nonoverlapping(CHUNKS.load(Ordering::Relaxed).add(off), value, n);
    }
    0
}

fuzz_target!(
    shirudo_fuzz_serializer,
    shirudo_fuzz_serializer_init,
    |data| {
        CHUNKS.store(data.as_ptr().cast_mut(), Ordering::Relaxed);
        CHUNKS_LEN.store(data.len(), Ordering::Relaxed);
        // SAFETY: a chunk of nothing, for which zeros are the value, its
        // first bytes the input's.
        let first: SerialChunk = unsafe {
            let mut first: SerialChunk = core::mem::zeroed();
            core::ptr::copy_nonoverlapping(
                data.as_ptr(),
                (&raw mut first).cast::<u8>(),
                data.len().min(size_of::<SerialChunk>()),
            );
            first
        };
        // SAFETY: a page of nothing, which the read fills, its data freed.
        unsafe {
            let mut page: SerialPage = core::mem::zeroed();
            let ret: c_int = upatch_maps_read_serial_page(
                0,
                64,
                first.page_index,
                first.cursor,
                first.invocation_id,
                &mut page,
            );
            if ret == 0 {
                xfree(page.data, page.bytes as usize);
            }
        }
    }
);
