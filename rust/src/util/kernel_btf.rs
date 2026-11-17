// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The kernel's BTF, read with shirudo's own BTF reader: the running
//! kernel's, as btf__load_vmlinux_btf() reads it from sysfs, and the BTF
//! object of an ID, a program's or a map's, as
//! btf__load_from_kernel_by_id() fetches it.

use core::ffi::{c_int, c_void};
use std::sync::OnceLock;

use crate::bpf::btf::Btf;
use crate::errno::{E2BIG, ESRCH};
use crate::sys::libc::close;
use crate::util::bpf_sys::{bpf_btf_get_fd_by_id, bpf_obj_get_info_by_fd};

const VMLINUX: &str = "/sys/kernel/btf/vmlinux";
/// `struct bpf_btf_info`: its size, and where the BTF's address and size
/// sit in it.
const BTF_INFO_SIZE: usize = 32;
const INFO_BTF: usize = 0;
const INFO_BTF_SIZE: usize = 8;

/// The running kernel's BTF, read once: none when sysfs has none, the
/// kernel built without CONFIG_DEBUG_INFO_BTF, or it does not parse.
pub(crate) fn vmlinux() -> Option<&'static Btf> {
    static VMLINUX_BTF: OnceLock<Option<Btf>> = OnceLock::new();
    VMLINUX_BTF.get_or_init(|| load_vmlinux().ok()).as_ref()
}

/// The running kernel's BTF; -ESRCH when sysfs has none.
pub(crate) fn load_vmlinux() -> Result<Btf, c_int> {
    match std::fs::read(VMLINUX) {
        Ok(raw) => Btf::parse(&raw),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(-ESRCH),
        Err(e) => Err(-e.raw_os_error().unwrap_or(crate::errno::EIO)),
    }
}

/// The BTF object `fd` names into `buf`: the size it has, which may be
/// more than `buf` holds.
fn btf_info(fd: c_int, buf: &mut [u8]) -> Result<usize, c_int> {
    let mut info = [0u8; BTF_INFO_SIZE];
    info[INFO_BTF..INFO_BTF + 8].copy_from_slice(&(buf.as_mut_ptr() as u64).to_ne_bytes());
    info[INFO_BTF_SIZE..INFO_BTF_SIZE + 4].copy_from_slice(&(buf.len() as u32).to_ne_bytes());
    let mut len = BTF_INFO_SIZE as u32;
    // SAFETY: the info and its size, its buffer of `buf.len()` bytes.
    let ret = unsafe { bpf_obj_get_info_by_fd(fd, info.as_mut_ptr().cast::<c_void>(), &mut len) };
    if ret != 0 {
        return Err(ret);
    }
    let mut size = [0u8; 4];
    size.copy_from_slice(&info[INFO_BTF_SIZE..INFO_BTF_SIZE + 4]);
    Ok(u32::from_ne_bytes(size) as usize)
}

/// The kernel's BTF object `id`, as btf_get_from_fd() reads it: into 4
/// KiB, and again into what it says it takes if more.
pub(crate) fn by_id(id: u32) -> Result<Btf, c_int> {
    let fd = bpf_btf_get_fd_by_id(id);
    if fd < 0 {
        return Err(fd);
    }
    let mut buf = vec![0u8; 4096];
    let mut got = btf_info(fd, &mut buf);
    if let Ok(size) = got
        && size > buf.len()
    {
        buf = vec![0u8; size];
        got = btf_info(fd, &mut buf);
    }
    // SAFETY: the descriptor opened above, closed once.
    unsafe { close(fd) };
    match got {
        Ok(size) if size <= buf.len() => Btf::parse(&buf[..size]),
        Ok(_) => Err(-E2BIG),
        Err(e) => Err(e),
    }
}

mod capi {
    use core::ffi::c_void;
    use core::ptr;

    use crate::bpf::btf::Btf;
    use crate::errno::EINVAL;
    use crate::sys::libc::set_errno;

    /// The BTF in the `size` bytes at `data`, parsed for a map view or a
    /// check to read; NULL with errno set for none.
    ///
    /// # Safety
    ///
    /// `data` is NULL or holds `size` bytes.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn shirudo_btf_new(data: *const c_void, size: u32) -> *mut Btf {
        if data.is_null() {
            set_errno(EINVAL);
            return ptr::null_mut();
        }
        // SAFETY: the caller's `size` bytes.
        let raw = unsafe { crate::ffi::slice(data.cast::<u8>(), size as usize) };
        match Btf::parse(raw) {
            Ok(btf) => Box::into_raw(Box::new(btf)),
            Err(e) => {
                set_errno(-e);
                ptr::null_mut()
            }
        }
    }

    /// Frees what shirudo_btf_new() made, NULL for none.
    ///
    /// # Safety
    ///
    /// `btf` is NULL or what shirudo_btf_new() returned, freed once.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn shirudo_btf_free(btf: *mut Btf) {
        if !btf.is_null() {
            // SAFETY: the caller's BTF, boxed by shirudo_btf_new().
            drop(unsafe { Box::from_raw(btf) });
        }
    }
}
