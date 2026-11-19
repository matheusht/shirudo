// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The `.upatch` container parser: the header and
//! the bounds of its sections, the signed sections behind the loader
//! data, the programs' metadata, and the names of upatches.

use core::ffi::{c_char, c_int, c_void};
use core::ptr;

use crate::errno::{EFBIG, EINTR, EINVAL, EIO, ENOENT, ENOMEM, EOPNOTSUPP, EOVERFLOW};
use crate::ffi;
use crate::heap::{xcalloc, xfree, xmalloc, xstrfree, xstrndup};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{O_CLOEXEC, O_RDONLY, S_IFMT, S_IFREG, Statx, close, errno, open, pread};
use crate::util::hex::hex_decode;
use crate::util::io::stat_fd;

pub(crate) const NAME_MAX: usize = 256;
pub(crate) const PAYLOAD_HASH_LEN: usize = 32;
/// The largest container a reader takes; .upatch is small.
pub(crate) const FILE_MAX: usize = 16 * 1024 * 1024;
/// The NAME_MAX of `<limits.h>` a pin directory's name must fit.
const PIN_NAME_MAX: usize = 255;

pub(crate) const MAGIC: u64 = 0x5348_5244_554e_4150;
pub(crate) const VERSION: u32 = 1;
pub(crate) const HEADER_SIZE: usize = 360;
pub(crate) const DIRECTIVE_UNLOAD: u32 = 1;
pub(crate) const TYPE_BPF: u32 = 1;

pub(crate) const SIGNED_TRAILER_MAGIC: u32 = 0x5254_4753;
pub(crate) const SIGNED_VERSION: u32 = 1;
pub(crate) const SIGNED_SECTIONS_MAX: u32 = 8;
pub(crate) const SECTION_NAME: u32 = 0x454d_414e;
pub(crate) const SECTION_ATTACH: u32 = 0x4d47_5055;
pub(crate) const SECTION_UNLOAD: u32 = 0x444c_4e55;
pub(crate) const SECTION_DECODERS: u32 = 0x4244_4344;
pub(crate) const SECTION_POLICY_LABELS: u32 = 0x4c50_4853;

pub(crate) const POLICY_LABELS_MAGIC: u32 = 0x4c50_4853;
pub(crate) const POLICY_LABELS_VERSION: u32 = 1;
pub(crate) const MAPS_MAX: u32 = 64;
const POLICY_NAME_MAX: usize = 64;
const POLICY_PATH_MAX: usize = 4096;

pub(crate) const DECODER_MAGIC: u32 = 0x4244_4344;
pub(crate) const DECODER_VERSION: u32 = 1;

pub(crate) const ATTACH_TARGET_MAX: usize = 128;
pub(crate) const PROG_MAGIC: u32 = 0x4d47_5055;
pub(crate) const PROG_VERSION: u32 = 1;
pub(crate) const PROG_MAP_MAX: usize = 16;
pub(crate) const UPROBE_TARGET_MAGIC: u32 = 0x5455_5055;
pub(crate) const UPROBE_TARGET_VERSION: u32 = 1;
pub(crate) const UPROBE_PATH_MAX: u32 = 4096;
pub(crate) const BUILD_ID_MAX: usize = 64;
const UPROBE_OFFSETS_MAX: u32 = 1 << 20;

pub(crate) const ATTACH_RAW_TRACEPOINT: u32 = 0;
pub(crate) const ATTACH_KPROBE: u32 = 1;
pub(crate) const ATTACH_KRETPROBE: u32 = 2;
pub(crate) const ATTACH_CGROUP_SKB_INGRESS: u32 = 3;
pub(crate) const ATTACH_CGROUP_SKB_EGRESS: u32 = 4;
pub(crate) const ATTACH_FMOD_RET: u32 = 5;
pub(crate) const ATTACH_NETFILTER_IPV6_PRE_ROUTING: u32 = 6;
pub(crate) const ATTACH_UPROBE_MULTI: u32 = 7;
pub(crate) const ATTACH_XDP: u32 = 8;
pub(crate) const ATTACH_URETPROBE_MULTI: u32 = 9;
pub(crate) const ATTACH_UPROBE: u32 = 10;
pub(crate) const ATTACH_URETPROBE: u32 = 11;

/// `enum upatch_xdp_device_class`: the classes of device an XDP program
/// attaches to. Bit 4 is none: loopback has no native XDP, so nothing
/// selects it.
pub(crate) const XDP_NETWORK: u32 = 1;
pub(crate) const XDP_VIRTUAL: u32 = 2;
pub(crate) const XDP_VM: u32 = 8;
pub(crate) const XDP_UNKNOWN: u32 = 16;
pub(crate) const XDP_ALL: u32 = XDP_NETWORK | XDP_VIRTUAL | XDP_VM | XDP_UNKNOWN;

pub(crate) const ROLE_ATTACH: u32 = 0;
pub(crate) const ROLE_SERIALIZER: u32 = 1;
pub(crate) const ROLE_TEST_RUN: u32 = 2;

/// The sizes of the records of the .upatch format, which the
/// parser reads at their offsets, little-endian.
pub(crate) const POLICY_LABEL_HEADER: usize = 20;
pub(crate) const POLICY_LABEL_ENTRY: usize = 8 + POLICY_NAME_MAX + POLICY_PATH_MAX;
pub(crate) const SIGNED_SECTION: usize = 16;
pub(crate) const SIGNED_TRAILER: usize = 16;
pub(crate) const DECODER_BLOB: usize = 16;
pub(crate) const DECODER_ENTRY: usize = 16 + 64 + 16 + 64 + 32 + 8;
pub(crate) const PROG_METADATA: usize = 16;
pub(crate) const PROG_ENTRY: usize = 16 + ATTACH_TARGET_MAX + PROG_MAP_MAX;
pub(crate) const UPROBE_TARGETS: usize = 16;
pub(crate) const UPROBE_TARGET: usize = 16;

/// `struct upatch_host_header`: the container's header in host order.
#[repr(C)]
pub struct UpatchHostHeader {
    pub(crate) magic: u64,
    pub(crate) version: u32,
    pub(crate) flags: u32,
    pub(crate) name: [u8; NAME_MAX],
    pub(crate) payload_sha256: [u8; PAYLOAD_HASH_LEN],
    pub(crate) loader_insns_off: u32,
    pub(crate) loader_insns_len: u32,
    pub(crate) signature_off: u32,
    pub(crate) signature_len: u32,
    pub(crate) metadata_off: u32,
    pub(crate) metadata_len: u32,
    pub(crate) data_off: u32,
    pub(crate) data_len: u32,
    pub(crate) log_buf_sz: u32,
    pub(crate) nr_maps: u32,
    pub(crate) nr_progs: u32,
    pub(crate) rodata_data_off: u32,
    pub(crate) ty: u32,
    pub(crate) reserved1: u32,
}

/// `struct upatch`: a container opened, its bytes owned when read from
/// a file, which upatch_close() releases.
#[repr(C)]
pub struct Upatch {
    pub(crate) hdr: UpatchHostHeader,
    pub(crate) map: *const u8,
    pub(crate) map_size: usize,
    pub(crate) owned: bool,
    pub(crate) rodata_offset_in_header: bool,
    pub(crate) decoder_blob: *const c_void,
    pub(crate) decoder_blob_len: u32,
    pub(crate) nr_decoders: u32,
    pub(crate) signed_name: *const c_char,
    pub(crate) signed_attach: *const u8,
    pub(crate) signed_attach_len: u32,
    pub(crate) signed_unload_payload: *const u8,
    pub(crate) signed_policy_labels: *const c_void,
    pub(crate) signed_policy_labels_len: u32,
    pub(crate) signed_policy_map_idx: u32,
    pub(crate) signed_socket_policy_map_idx: u32,
}

const _: () = assert!(size_of::<UpatchHostHeader>() == HEADER_SIZE);
const _: () = assert!(core::mem::offset_of!(UpatchHostHeader, payload_sha256) == 272);
const _: () = assert!(size_of::<Upatch>() == 456);
const _: () = assert!(core::mem::offset_of!(Upatch, decoder_blob) == 384);
const _: () = assert!(core::mem::offset_of!(Upatch, signed_unload_payload) == 424);

/// `struct upatch_decoder_view`: a decoder of the signed blob, its
/// source within the container.
#[repr(C)]
pub struct DecoderView {
    pub(crate) language: u32,
    pub(crate) api_version: u32,
    pub(crate) input_format: u32,
    pub(crate) export_signal: u32,
    pub(crate) upatch: [u8; 64],
    pub(crate) map: [u8; 16],
    pub(crate) source_name: [u8; 64],
    pub(crate) entrypoint: [u8; 32],
    pub(crate) source: *const c_char,
    pub(crate) source_len: u32,
}

const _: () = assert!(size_of::<DecoderView>() == 208);

/// `struct stat` of the C library, which a program's spec carries for
/// its callers.
#[cfg(target_arch = "x86_64")]
const STAT_SIZE: usize = 144;
#[cfg(target_arch = "aarch64")]
const STAT_SIZE: usize = 128;

/// `struct prog_spec`: a program of the metadata, what attaches it, and
/// for a uprobe the binary's path, build ID and offsets.
#[repr(C)]
pub struct ProgSpec {
    pub(crate) role: u32,
    pub(crate) kind: u32,
    /// An XDP program's: the classes of device it attaches to.
    pub(crate) device_classes: u32,
    pub(crate) offset: u64,
    pub(crate) target: [u8; ATTACH_TARGET_MAX],
    pub(crate) map: [u8; PROG_MAP_MAX],
    pub(crate) uprobe_path: *mut c_char,
    pub(crate) uprobe_path_len: u32,
    pub(crate) build_id: [u8; BUILD_ID_MAX],
    pub(crate) build_id_len: u32,
    pub(crate) uprobe_offsets: *mut u64,
    pub(crate) nr_uprobe_offsets: u32,
    pub(crate) target_fd: c_int,
    pub(crate) target_stat: [u64; STAT_SIZE / 8],
}

const _: () = assert!(core::mem::offset_of!(ProgSpec, target_stat) == 264);
const _: () = assert!(size_of::<ProgSpec>() == 264 + STAT_SIZE);

/// uprobe.multi and uretprobe.multi: a glob over a binary's functions.
pub(crate) fn kind_is_uprobe_multi(kind: u32) -> bool {
    kind == ATTACH_UPROBE_MULTI || kind == ATTACH_URETPROBE_MULTI
}

/// uprobe and uretprobe: one place in a binary.
pub(crate) fn kind_is_uprobe_single(kind: u32) -> bool {
    kind == ATTACH_UPROBE || kind == ATTACH_URETPROBE
}

/// The kinds that attach to a userspace binary named in the UPUT block.
pub(crate) fn kind_has_uprobe_target(kind: u32) -> bool {
    kind_is_uprobe_multi(kind) || kind_is_uprobe_single(kind)
}

/// Every device class an XDP program among the specs selects.
pub(crate) fn specs_xdp_classes(specs: &[ProgSpec]) -> u32 {
    specs
        .iter()
        .filter(|s| s.kind == ATTACH_XDP)
        .fold(0, |classes, s| classes | s.device_classes)
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn le64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];

    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

fn has_nul(b: &[u8]) -> bool {
    b.contains(&0)
}

/// The header at the start of `m` into `out`: 0, or -EINVAL with what
/// was read so far left there.
fn parse_header(m: &[u8], out: &mut UpatchHostHeader) -> c_int {
    if m.len() < HEADER_SIZE {
        return -EINVAL;
    }
    out.magic = le64(m, 0);
    if out.magic != MAGIC {
        return -EINVAL;
    }
    out.version = le32(m, 8);
    if out.version != VERSION {
        return -EINVAL;
    }
    out.flags = le32(m, 12);
    out.name.copy_from_slice(&m[16..16 + NAME_MAX]);
    if !has_nul(&out.name) {
        return -EINVAL;
    }
    out.payload_sha256
        .copy_from_slice(&m[272..272 + PAYLOAD_HASH_LEN]);
    let fields = [
        &mut out.loader_insns_off,
        &mut out.loader_insns_len,
        &mut out.signature_off,
        &mut out.signature_len,
        &mut out.metadata_off,
        &mut out.metadata_len,
        &mut out.data_off,
        &mut out.data_len,
        &mut out.log_buf_sz,
        &mut out.nr_maps,
        &mut out.nr_progs,
        &mut out.rodata_data_off,
        &mut out.ty,
        &mut out.reserved1,
    ];
    for (i, field) in fields.into_iter().enumerate() {
        *field = le32(m, 304 + 4 * i);
    }
    if out.reserved1 != 0 {
        return -EINVAL;
    }
    0
}

fn section_inside(off: u32, len: u32, n: usize) -> bool {
    let end = u64::from(off) + u64::from(len);

    if end > n as u64 {
        return false;
    }
    !(len != 0 && (off as usize) < HEADER_SIZE)
}

fn validate_bounds(h: &UpatchHostHeader, n: usize) -> c_int {
    if h.ty != TYPE_BPF {
        return -EINVAL;
    }
    if (h.loader_insns_off as usize) < HEADER_SIZE
        || h.loader_insns_off % 8 != 0
        || h.loader_insns_len % 8 != 0
        || !section_inside(h.loader_insns_off, h.loader_insns_len, n)
    {
        return -EINVAL;
    }
    if !section_inside(h.signature_off, h.signature_len, n)
        || !section_inside(h.metadata_off, h.metadata_len, n)
        || !section_inside(h.data_off, h.data_len, n)
    {
        return -EINVAL;
    }
    if h.rodata_data_off > h.data_len {
        return -EINVAL;
    }
    if h.loader_insns_len == 0 || h.signature_len == 0 {
        return -EINVAL;
    }
    0
}

/// The policy labels section `p`: its map indexes when it holds `count`
/// well-formed labels for maps the loader has.
fn parse_policy_labels(p: &[u8], nr_maps: u32) -> Option<(u32, u32)> {
    if p.len() < POLICY_LABEL_HEADER {
        return None;
    }
    let count = le32(p, 8);
    let idx = le32(p, 12);
    let socket_idx = le32(p, 16);
    if le32(p, 0) != POLICY_LABELS_MAGIC
        || le32(p, 4) != POLICY_LABELS_VERSION
        || idx >= nr_maps
        || idx >= MAPS_MAX
        || socket_idx >= nr_maps
        || socket_idx >= MAPS_MAX
        || idx == socket_idx
        || count == 0
        || (count as usize)
            .checked_mul(POLICY_LABEL_ENTRY)
            .and_then(|n| n.checked_add(POLICY_LABEL_HEADER))
            != Some(p.len())
    {
        return None;
    }
    for i in 0..count as usize {
        let e = &p[POLICY_LABEL_HEADER + i * POLICY_LABEL_ENTRY..][..POLICY_LABEL_ENTRY];
        let bit = le64(e, 0);
        let policy = &e[8..8 + POLICY_NAME_MAX];
        let path = &e[8 + POLICY_NAME_MAX..];

        if bit == 0
            || bit & (bit - 1) != 0
            || !has_nul(policy)
            || policy[0] == 0
            || !has_nul(path)
            || path[0] != b'/'
        {
            return None;
        }
    }
    Some((idx, socket_idx))
}

/// The DECODERS section `bp`, its entries and sources within it, into
/// `u`.
fn parse_decoders(u: &mut Upatch, bp: &[u8]) -> bool {
    if bp.len() < DECODER_BLOB || le32(bp, 0) != DECODER_MAGIC || le32(bp, 4) != DECODER_VERSION {
        return false;
    }
    let nr_decoders = le32(bp, 8);
    if nr_decoders == 0 {
        return false;
    }
    let entries_end = DECODER_BLOB as u64 + u64::from(nr_decoders) * DECODER_ENTRY as u64;
    if entries_end > bp.len() as u64 {
        return false;
    }
    let decoder_len = bp.len() as u32;
    // The blob sits behind the signature, so entries are unaligned.
    for i in 0..nr_decoders as usize {
        let d = &bp[DECODER_BLOB + i * DECODER_ENTRY..][..DECODER_ENTRY];

        if !has_nul(&d[16..80])
            || !has_nul(&d[80..96])
            || !has_nul(&d[96..160])
            || !has_nul(&d[160..192])
        {
            return false;
        }
        if le32(d, 0) == 0 || le32(d, 4) == 0 || le32(d, 8) == 0 || le32(d, 12) == 0 {
            return false;
        }
        let source_off = le32(d, 192);
        let source_len = le32(d, 196);
        if source_len == 0
            || u64::from(source_off) < entries_end
            || source_off > decoder_len
            || source_len > decoder_len - source_off
        {
            return false;
        }
    }
    u.decoder_blob = bp.as_ptr().cast();
    u.decoder_blob_len = decoder_len;
    u.nr_decoders = nr_decoders;
    true
}

fn forget_signed_sections(u: &mut Upatch) {
    u.decoder_blob = ptr::null();
    u.decoder_blob_len = 0;
    u.nr_decoders = 0;
    u.signed_name = ptr::null();
    u.signed_attach = ptr::null();
    u.signed_attach_len = 0;
    u.signed_unload_payload = ptr::null();
    u.signed_policy_labels = ptr::null();
    u.signed_policy_labels_len = 0;
    u.signed_policy_map_idx = 0;
    u.signed_socket_policy_map_idx = 0;
}

/// The signed sections behind the loader data. Each lies below the
/// directory, the directory below the trailer, and each tag appears
/// once; a directory that breaks any of that is taken for none, so a
/// load or unload refuses for what it then lacks.
fn parse_signed_sections(u: &mut Upatch, map: &[u8]) {
    let data_len = u.hdr.data_len as usize;

    if data_len < SIGNED_TRAILER {
        return;
    }
    let data = &map[u.hdr.data_off as usize..][..data_len];
    let tr = &data[data_len - SIGNED_TRAILER..];
    if le32(tr, 0) != SIGNED_TRAILER_MAGIC || le32(tr, 4) != SIGNED_VERSION {
        return;
    }
    let dir_off = le32(tr, 8);
    let nr = le32(tr, 12);
    let end = (data_len - SIGNED_TRAILER) as u64;
    if nr == 0
        || nr > SIGNED_SECTIONS_MAX
        || u64::from(dir_off) > end
        || u64::from(nr) * SIGNED_SECTION as u64 > end - u64::from(dir_off)
    {
        return;
    }
    let mut seen = 0u32;
    for i in 0..nr as usize {
        let s = &data[dir_off as usize + i * SIGNED_SECTION..][..SIGNED_SECTION];
        let tag = le32(s, 0);
        let off = le32(s, 8);
        let len = le32(s, 12);

        if le32(s, 4) != 0 || off > dir_off || len > dir_off - off {
            forget_signed_sections(u);
            return;
        }
        let section = &data[off as usize..][..len as usize];
        let bit = match tag {
            SECTION_NAME => {
                if len as usize != NAME_MAX || !has_nul(section) {
                    forget_signed_sections(u);
                    return;
                }
                u.signed_name = section.as_ptr().cast();
                1
            }
            SECTION_ATTACH => {
                if len == 0 {
                    forget_signed_sections(u);
                    return;
                }
                u.signed_attach = section.as_ptr();
                u.signed_attach_len = len;
                2
            }
            SECTION_UNLOAD => {
                if len as usize != PAYLOAD_HASH_LEN {
                    forget_signed_sections(u);
                    return;
                }
                u.signed_unload_payload = section.as_ptr();
                4
            }
            SECTION_DECODERS => {
                if !parse_decoders(u, section) {
                    forget_signed_sections(u);
                    return;
                }
                8
            }
            SECTION_POLICY_LABELS => {
                let Some((idx, socket_idx)) = parse_policy_labels(section, u.hdr.nr_maps) else {
                    forget_signed_sections(u);
                    return;
                };
                u.signed_policy_map_idx = idx;
                u.signed_socket_policy_map_idx = socket_idx;
                u.signed_policy_labels = section.as_ptr().cast();
                u.signed_policy_labels_len = len;
                16
            }
            _ => {
                forget_signed_sections(u);
                return;
            }
        };
        if seen & bit != 0 {
            forget_signed_sections(u);
            return;
        }
        seen |= bit;
    }
}

/// The container in the `size` bytes at `data`, which stay valid while
/// `out` is open, into `out`: 0, or -errno with `out` zeroed.
///
/// # Safety
///
/// `data` is NULL or points to `size` bytes, and `out` to room for a
/// container.
unsafe fn parse(data: *const u8, size: usize, out: *mut Upatch) -> c_int {
    // SAFETY: the caller's room, every byte of it, padding too, as the
    // C's memset() left it; all zeros make a closed container.
    unsafe { ptr::write_bytes(out, 0, 1) };
    if data.is_null() || size == 0 || size > FILE_MAX {
        return -EINVAL;
    }
    // SAFETY: the caller's container, and its bytes.
    let (u, map) = unsafe { (&mut *out, ffi::slice(data, size)) };
    u.map = data;
    u.map_size = size;
    let mut ret = parse_header(map, &mut u.hdr);
    if ret == 0 {
        u.rodata_offset_in_header = true;
        ret = validate_bounds(&u.hdr, size);
    }
    if ret != 0 {
        // SAFETY: as above.
        unsafe { ptr::write_bytes(out, 0, 1) };
        return ret;
    }
    parse_signed_sections(u, map);
    0
}

/// A copy, not a mapping: a private mapping still shows what is written
/// to the file after mmap(), so the bytes parsed here, the ones handed
/// to the kernel and the ones acted on after its signature check could
/// differ.
///
/// # Safety
///
/// `out` points to room for a container.
unsafe fn open_fd(fd: c_int, out: *mut Upatch) -> c_int {
    let mut st = Statx::zeroed();

    // SAFETY: the caller's room, every byte of it, as parse() zeroes it.
    unsafe { ptr::write_bytes(out, 0, 1) };
    let ret = stat_fd(fd, &mut st);
    if ret != 0 {
        return ret;
    }
    if st.stx_mode & S_IFMT != S_IFREG || st.stx_size == 0 {
        return -EINVAL;
    }
    // Refuse pathologically large inputs; .upatch is small.
    if st.stx_size > FILE_MAX as u64 {
        return -EFBIG;
    }
    let size = st.stx_size as usize;
    // SAFETY: a size.
    let buf = unsafe { xmalloc(size) }.cast::<u8>();
    if buf.is_null() {
        return -ENOMEM;
    }
    let mut off = 0;
    let mut ret = 0;
    while off < size {
        // SAFETY: the caller's fd, and the room left in buf.
        let n = unsafe { pread(fd, buf.add(off).cast(), size - off, off as i64) };

        if n < 0 && errno() == EINTR {
            continue;
        }
        if n <= 0 {
            ret = if n < 0 { -errno() } else { -EIO };
            break;
        }
        off += n as usize;
    }
    if ret == 0 {
        // SAFETY: the size bytes read, and the caller's room.
        ret = unsafe { parse(buf, size, out) };
    }
    if ret != 0 {
        // SAFETY: the block xmalloc() gave, freed once.
        unsafe { xfree(buf.cast(), size) };
        return ret;
    }
    // SAFETY: the caller's container, which parse() filled.
    unsafe { (*out).owned = true };
    0
}

/// # Safety
///
/// `path` is a C string, and `out` points to room for a container.
unsafe fn open_path(path: *const c_char, out: *mut Upatch) -> c_int {
    // SAFETY: the caller's room, every byte of it, as parse() zeroes it.
    unsafe { ptr::write_bytes(out, 0, 1) };
    // SAFETY: the caller's C string, and flags.
    let fd = unsafe { open(path, O_RDONLY | O_CLOEXEC) };
    if fd < 0 {
        return -errno();
    }
    // SAFETY: the fd open() gave, closed once, and the caller's room.
    unsafe {
        let ret = open_fd(fd, out);

        close(fd);
        ret
    }
}

pub(crate) fn close_upatch(u: &mut Upatch) {
    if !u.map.is_null() && u.owned {
        // SAFETY: the bytes open_fd() took from xmalloc(), freed once.
        unsafe { xfree(u.map.cast_mut().cast(), u.map_size) };
    }
    if !u.map.is_null() {
        u.map = ptr::null();
        u.map_size = 0;
        u.owned = false;
        forget_signed_sections(u);
    }
}

/// The header's name, NUL-terminated.
pub(crate) fn header_name(u: &Upatch, out: &mut [u8; NAME_MAX + 1]) {
    out[..NAME_MAX].copy_from_slice(&u.hdr.name);
    out[NAME_MAX] = 0;
}

pub(crate) fn signed_name(u: &Upatch) -> *const c_char {
    if u.map.is_null() {
        ptr::null()
    } else {
        u.signed_name
    }
}

pub(crate) fn name_signed(u: &Upatch) -> bool {
    let name = signed_name(u);

    // SAFETY: a signed name lies within the open container, NAME_MAX
    // bytes of it.
    !name.is_null() && unsafe { ffi::slice(name.cast::<u8>(), NAME_MAX) } == u.hdr.name
}

fn prog_name_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'.'
}

/// The header's name as a program name: up to `out`'s room less one,
/// any other byte than `[A-Za-z0-9_.]` as '_', and zeros after.
pub(crate) fn prog_name(u: &Upatch, out: &mut [u8]) {
    let n = u.hdr.name.iter().position(|&c| c == 0).unwrap_or(NAME_MAX);

    if out.is_empty() {
        return;
    }
    out.fill(0);
    let n = n.min(out.len() - 1);
    for (o, &c) in out.iter_mut().zip(&u.hdr.name[..n]) {
        *o = if prog_name_char(c) { c } else { b'_' };
    }
}

fn at(u: &Upatch, off: u32) -> *const c_void {
    // SAFETY: an offset validate_bounds() kept within the container.
    unsafe { u.map.add(off as usize) }.cast()
}

pub(crate) fn decoder_view(u: &Upatch, idx: u32, out: &mut DecoderView) -> c_int {
    // SAFETY: the view, every byte of it.
    unsafe { ptr::write_bytes(ptr::from_mut(out), 0, 1) };
    if !has_decoders(u) || idx >= u.nr_decoders {
        return -ENOENT;
    }
    // SAFETY: the blob parse_decoders() checked, its entries within it.
    let bp = unsafe { ffi::slice(u.decoder_blob.cast::<u8>(), u.decoder_blob_len as usize) };
    let d = &bp[DECODER_BLOB + idx as usize * DECODER_ENTRY..][..DECODER_ENTRY];
    out.language = le32(d, 0);
    out.api_version = le32(d, 4);
    out.input_format = le32(d, 8);
    out.export_signal = le32(d, 12);
    out.upatch.copy_from_slice(&d[16..80]);
    out.map.copy_from_slice(&d[80..96]);
    out.source_name.copy_from_slice(&d[96..160]);
    out.entrypoint.copy_from_slice(&d[160..192]);
    out.source = bp[le32(d, 192) as usize..].as_ptr().cast();
    out.source_len = le32(d, 196);
    0
}

/// The length of the signed attach metadata, 0 for none.
pub(crate) fn signed_attach_len(u: &Upatch) -> u32 {
    if u.map.is_null() {
        0
    } else {
        u.signed_attach_len
    }
}

/// The signed digest of the payload an unload directive unloads.
pub(crate) fn signed_unload_payload(u: &Upatch) -> Option<&[u8]> {
    if u.map.is_null() || u.signed_unload_payload.is_null() {
        return None;
    }
    // SAFETY: a signed section within the open container, its 32 bytes.
    Some(unsafe { ffi::slice(u.signed_unload_payload, PAYLOAD_HASH_LEN) })
}

/// What the payload is: a BPF program, the one kind there is.
pub(crate) fn payload_type(_u: &Upatch) -> &'static [u8] {
    b"bpf"
}

/// The bpffs name of upatch `name`: bpffs reserves dots in a path
/// component, so each becomes `~d`, which no name has.
pub(crate) fn pin_name(name: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(name.len());
    for &c in name {
        if c == b'.' {
            out.extend_from_slice(b"~d");
        } else {
            out.push(c);
        }
    }
    out
}

/// The upatch name a bpffs pin spells, `~d` a dot again; none for
/// another `~`.
pub(crate) fn name_from_pin(pin: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(pin.len());
    let mut it = pin.iter();

    while let Some(&c) = it.next() {
        if c != b'~' {
            out.push(c);
        } else if it.next() == Some(&b'd') {
            out.push(b'.');
        } else {
            return None;
        }
    }
    Some(out)
}

/// An upatch file opened, closed when dropped.
pub(crate) struct Opened(Box<Upatch>);

impl Opened {
    /// The upatch at `path`, or -errno.
    pub(crate) fn open(path: &core::ffi::CStr) -> Result<Self, c_int> {
        // SAFETY: an all-zero container is a closed one.
        let mut u: Box<Upatch> = Box::new(unsafe { core::mem::zeroed() });
        // SAFETY: a C string and the container to fill.
        match unsafe { capi::upatch_open(path.as_ptr(), &mut *u) } {
            0 => Ok(Opened(u)),
            err => Err(err),
        }
    }
}

impl Opened {
    /// The upatch in the file open on `fd`, or -errno.
    pub(crate) fn open_fd(fd: c_int) -> Result<Self, c_int> {
        // SAFETY: an all-zero container is a closed one.
        let mut u: Box<Upatch> = Box::new(unsafe { core::mem::zeroed() });
        // SAFETY: the caller's descriptor and the container to fill.
        match unsafe { capi::upatch_open_fd(fd, &mut *u) } {
            0 => Ok(Opened(u)),
            err => Err(err),
        }
    }
}

impl core::ops::Deref for Opened {
    type Target = Upatch;

    fn deref(&self) -> &Upatch {
        &self.0
    }
}

impl Drop for Opened {
    fn drop(&mut self) {
        // SAFETY: the container opened, closed once.
        unsafe { capi::upatch_close(&mut *self.0) };
    }
}

pub(crate) fn is_unload(u: &Upatch) -> bool {
    u.hdr.flags & DIRECTIVE_UNLOAD != 0
}

pub(crate) fn has_decoders(u: &Upatch) -> bool {
    !u.map.is_null() && !u.decoder_blob.is_null() && u.nr_decoders > 0
}

/// An upatch name: `[A-Za-z0-9._-]+`, not starting with '.', whose pin
/// name, each dot doubled, fits NAME_MAX.
pub(crate) fn name_valid(name: Option<&[u8]>) -> bool {
    let Some(name) = name else {
        return false;
    };
    if name.first().is_none_or(|&c| c == b'.') {
        return false;
    }
    let mut pin = 0;
    for &c in name {
        if !(c.is_ascii_alphanumeric() || c == b'.' || c == b'_' || c == b'-') {
            return false;
        }
        pin += if c == b'.' { 2 } else { 1 };
        if pin > PIN_NAME_MAX {
            return false;
        }
    }
    true
}

/// # Safety
///
/// `name` and `payload_hex` are NULL or C strings.
pub(crate) unsafe fn member_valid(name: *const c_char, payload_hex: *const c_char) -> bool {
    let mut payload = [0u8; PAYLOAD_HASH_LEN];

    // SAFETY: the caller's C strings, and the room of payload.
    name_valid((!name.is_null()).then(|| unsafe { ffi::c_str(name) }))
        && !payload_hex.is_null()
        && unsafe { hex_decode(payload_hex, payload.as_mut_ptr(), payload.len()) } == 0
}

/// # Safety
///
/// `specs` is NULL or the `nr_progs` specs prog_specs_parse() gave.
pub(crate) unsafe fn specs_free(specs: *mut ProgSpec, nr_progs: u32) {
    if specs.is_null() {
        return;
    }
    // SAFETY: the caller's specs, each with its fd, path and offsets
    // freed once, then the array.
    unsafe {
        for spec in ffi::slice(specs, nr_progs as usize) {
            if spec.target_fd >= 0 {
                close(spec.target_fd);
            }
            xstrfree(spec.uprobe_path);
            xfree(
                spec.uprobe_offsets.cast(),
                spec.nr_uprobe_offsets as usize * size_of::<u64>(),
            );
        }
        xfree(specs.cast(), nr_progs as usize * size_of::<ProgSpec>());
    }
}

/// The spec of a program an attach role gave: its kind, offset and
/// target from its entry `e`, or an XDP program's device classes, each
/// class one program's of the upatch, as `xdp_classes` gathers them: a
/// device runs one native XDP program at a time. Ok(true) for a uprobe,
/// whose binary comes after, Err(()) for an entry that breaks the rules.
fn attach_spec(spec: &mut ProgSpec, e: &[u8], xdp_classes: &mut u32) -> Result<bool, ()> {
    let kind = le32(e, 4);
    let raw_offset = le64(e, 8);
    let target = &e[16..16 + ATTACH_TARGET_MAX];
    let map = &e[16 + ATTACH_TARGET_MAX..];
    let mut uprobe = false;

    if map[0] != 0 {
        return Err(());
    }
    spec.role = ROLE_ATTACH;
    match kind {
        ATTACH_XDP => {
            let classes = le32(e, 8);
            if classes == 0
                || classes & !XDP_ALL != 0
                || classes & *xdp_classes != 0
                || le32(e, 12) != 0
                || target.iter().any(|&c| c != 0)
                || map.iter().any(|&c| c != 0)
            {
                return Err(());
            }
            *xdp_classes |= classes;
            spec.device_classes = classes;
            spec.kind = kind;
            return Ok(false);
        }
        ATTACH_RAW_TRACEPOINT
        | ATTACH_CGROUP_SKB_INGRESS
        | ATTACH_CGROUP_SKB_EGRESS
        | ATTACH_NETFILTER_IPV6_PRE_ROUTING
        | ATTACH_FMOD_RET => {
            spec.kind = kind;
            return if target[0] != 0 || raw_offset != 0 {
                Err(())
            } else {
                Ok(false)
            };
        }
        ATTACH_KPROBE | ATTACH_KRETPROBE => {}
        ATTACH_UPROBE_MULTI | ATTACH_URETPROBE_MULTI => {
            if raw_offset != 0 {
                return Err(());
            }
            uprobe = true;
        }
        ATTACH_UPROBE | ATTACH_URETPROBE => uprobe = true,
        _ => return Err(()),
    }
    if !has_nul(target) || target[0] == 0 {
        return Err(());
    }
    spec.kind = kind;
    spec.offset = raw_offset;
    spec.target.copy_from_slice(target);
    spec.target[ATTACH_TARGET_MAX - 1] = 0;
    if (kind == ATTACH_KRETPROBE || kind == ATTACH_URETPROBE) && spec.offset != 0 {
        return Err(());
    }
    let len = spec.target.iter().position(|&c| c == 0).unwrap_or(0);
    if kind_is_uprobe_multi(kind) && spec.target[..len].iter().any(|&c| c == b',' || c == b'|') {
        return Err(());
    }
    Ok(uprobe)
}

/// The UPUT block at `cursor` of `m`: a target for each of the
/// `nr_uprobes` programs that attach to a binary, one offset for a single
/// probe, onto their specs. The block's end, or -errno.
fn uprobe_targets(
    m: &[u8],
    mut cursor: usize,
    specs: &mut [ProgSpec],
    nr_uprobes: u32,
) -> Result<usize, c_int> {
    let end = m.len();

    if end - cursor < UPROBE_TARGETS {
        return Err(-EINVAL);
    }
    let targets = &m[cursor..cursor + UPROBE_TARGETS];
    cursor += UPROBE_TARGETS;
    let nr_targets = le32(targets, 8);
    if le32(targets, 0) != UPROBE_TARGET_MAGIC
        || le32(targets, 4) != UPROBE_TARGET_VERSION
        || le32(targets, 12) != 0
        || nr_targets != nr_uprobes
    {
        return Err(-EINVAL);
    }
    for _ in 0..nr_targets {
        if end - cursor < UPROBE_TARGET {
            return Err(-EINVAL);
        }
        let record = &m[cursor..cursor + UPROBE_TARGET];
        cursor += UPROBE_TARGET;
        let prog_idx = le32(record, 0) as usize;
        let path_len = le32(record, 4);
        let build_id_len = le32(record, 8);
        let nr_offsets = le32(record, 12);
        let Some(spec) = specs.get_mut(prog_idx) else {
            return Err(-EINVAL);
        };
        if !kind_has_uprobe_target(spec.kind)
            || !spec.uprobe_path.is_null()
            || path_len == 0
            || path_len >= UPROBE_PATH_MAX
            || build_id_len == 0
            || build_id_len as usize > BUILD_ID_MAX
            || nr_offsets == 0
            || nr_offsets > UPROBE_OFFSETS_MAX
            || (kind_is_uprobe_single(spec.kind) && nr_offsets != 1)
        {
            return Err(-EINVAL);
        }
        let (path_len, build_id_len) = (path_len as usize, build_id_len as usize);
        let payload_len = path_len + build_id_len + nr_offsets as usize * size_of::<u64>();
        if end - cursor < payload_len || m[cursor] != b'/' || has_nul(&m[cursor..][..path_len]) {
            return Err(-EINVAL);
        }
        // SAFETY: path_len bytes of the metadata, none a NUL.
        spec.uprobe_path = unsafe { xstrndup(m[cursor..].as_ptr().cast(), path_len) };
        if spec.uprobe_path.is_null() {
            return Err(-ENOMEM);
        }
        spec.uprobe_path_len = path_len as u32;
        cursor += path_len;
        spec.build_id[..build_id_len].copy_from_slice(&m[cursor..][..build_id_len]);
        spec.build_id_len = build_id_len as u32;
        cursor += build_id_len;
        // SAFETY: a count of offsets.
        spec.uprobe_offsets =
            unsafe { xcalloc(nr_offsets as usize, size_of::<u64>()) }.cast::<u64>();
        if spec.uprobe_offsets.is_null() {
            return Err(-ENOMEM);
        }
        spec.nr_uprobe_offsets = nr_offsets;
        // SAFETY: the nr_offsets offsets xcalloc() gave.
        let offsets =
            unsafe { core::slice::from_raw_parts_mut(spec.uprobe_offsets, nr_offsets as usize) };
        for j in 0..offsets.len() {
            offsets[j] = le64(m, cursor);
            cursor += size_of::<u64>();
            if j > 0 && offsets[j] <= offsets[j - 1] {
                return Err(-EINVAL);
            }
        }
    }
    if specs
        .iter()
        .any(|s| kind_has_uprobe_target(s.kind) && s.uprobe_path.is_null())
    {
        return Err(-EINVAL);
    }
    Ok(cursor)
}

/// The programs' specs from the metadata `m` into `specs`, zeroed with
/// no fds: 0, or -errno with what was set for specs_free().
///
/// # Safety
///
/// `specs` holds `nr_progs` specs.
unsafe fn specs_fill(specs: *mut ProgSpec, m: &[u8], nr_progs: u32, base_len: usize) -> c_int {
    // SAFETY: the caller's specs, zeroed but for their fds, which makes
    // each a valid spec.
    let specs = unsafe { core::slice::from_raw_parts_mut(specs, nr_progs as usize) };
    let (mut nr_uprobes, mut xdp_classes) = (0u32, 0u32);

    for (i, spec) in specs.iter_mut().enumerate() {
        let e = &m[PROG_METADATA + i * PROG_ENTRY..][..PROG_ENTRY];
        let map = &e[16 + ATTACH_TARGET_MAX..];

        match le32(e, 0) {
            ROLE_ATTACH => match attach_spec(spec, e, &mut xdp_classes) {
                Ok(uprobe) => nr_uprobes += u32::from(uprobe),
                Err(()) => return -EINVAL,
            },
            ROLE_SERIALIZER => {
                if le32(e, 4) != 0 || le64(e, 8) != 0 || e[16] != 0 {
                    return -EINVAL;
                }
                if !has_nul(map) || map[0] == 0 {
                    return -EINVAL;
                }
                spec.role = ROLE_SERIALIZER;
                spec.map.copy_from_slice(map);
                spec.map[PROG_MAP_MAX - 1] = 0;
            }
            ROLE_TEST_RUN => {
                if le32(e, 4) != 0 || le64(e, 8) != 0 || e[16] != 0 || map[0] != 0 {
                    return -EINVAL;
                }
                spec.role = ROLE_TEST_RUN;
            }
            _ => return -EINVAL,
        }
    }
    let end = if nr_uprobes != 0 {
        match uprobe_targets(m, base_len, specs, nr_uprobes) {
            Ok(end) => end,
            Err(err) => return err,
        }
    } else {
        base_len
    };
    if end != m.len() { -EINVAL } else { 0 }
}

/// The programs of the metadata, `nr_progs` of them for a loader of
/// `nr_maps` maps, into `*out` for prog_specs_free(): 0, or -errno with
/// `*out` NULL.
///
/// # Safety
///
/// `metadata` is NULL or points to `metadata_len` bytes, and `out` to
/// room for a pointer.
pub(crate) unsafe fn specs_parse(
    metadata: *const c_void,
    metadata_len: u32,
    nr_maps: u32,
    nr_progs: u32,
    out: *mut *mut ProgSpec,
) -> c_int {
    // SAFETY: the caller's room.
    unsafe { *out = ptr::null_mut() };
    if metadata.is_null() || (metadata_len as usize) < size_of::<u32>() {
        return -EINVAL;
    }
    // SAFETY: the caller's metadata_len bytes.
    let m = unsafe { ffi::slice(metadata.cast::<u8>(), metadata_len as usize) };
    if le32(m, 0) != PROG_MAGIC || m.len() < PROG_METADATA {
        return -EINVAL;
    }
    if le32(m, 4) != PROG_VERSION {
        return -EOPNOTSUPP;
    }
    if le32(m, 8) != nr_progs || le32(m, 12) != nr_maps {
        return -EINVAL;
    }
    let base_len = PROG_METADATA + nr_progs as usize * PROG_ENTRY;
    if base_len > u32::MAX as usize {
        return -EOVERFLOW;
    }
    if m.len() < base_len {
        return -EINVAL;
    }
    // SAFETY: a count of specs.
    let specs = unsafe { xcalloc(nr_progs as usize, size_of::<ProgSpec>()) }.cast::<ProgSpec>();
    if specs.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the nr_progs zeroed specs xcalloc() gave, handed to the
    // caller whole or freed once.
    unsafe {
        for i in 0..nr_progs as usize {
            (*specs.add(i)).target_fd = -1;
        }
        let ret = specs_fill(specs, m, nr_progs, base_len);
        if ret != 0 {
            specs_free(specs, nr_progs);
            return ret;
        }
        *out = specs;
    }
    0
}

pub(crate) use capi::{
    upatch_close, upatch_data, upatch_header_name, upatch_loader, upatch_member_valid,
    upatch_metadata, upatch_open, upatch_open_fd, upatch_open_memory, upatch_select,
    upatch_signature,
};

#[cfg(test)]
mod tests;

#[cfg(shirudo_fuzz)]
mod fuzz;

mod capi {
    use core::ffi::{c_char, c_int, c_void};
    use core::ptr;

    use super::{NAME_MAX, Upatch, at};
    use crate::ffi;
    use crate::sys::libc::Dirent;
    use crate::text::capi::name_has_suffix;

    /// # Safety
    ///
    /// `path` is a C string, and `out` points to room for a container.
    pub unsafe extern "C" fn upatch_open(path: *const c_char, out: *mut Upatch) -> c_int {
        // SAFETY: the caller passes the path and the room.
        unsafe { super::open_path(path, out) }
    }

    /// # Safety
    ///
    /// `out` points to room for a container.
    pub unsafe extern "C" fn upatch_open_fd(fd: c_int, out: *mut Upatch) -> c_int {
        // SAFETY: the caller passes the room.
        unsafe { super::open_fd(fd, out) }
    }

    /// # Safety
    ///
    /// `data` is NULL or points to `size` bytes that stay valid while
    /// the container is open, and `out` to room for a container.
    pub unsafe extern "C" fn upatch_open_memory(
        data: *const c_void,
        size: usize,
        out: *mut Upatch,
    ) -> c_int {
        // SAFETY: the caller passes the bytes and the room.
        unsafe { super::parse(data.cast(), size, out) }
    }

    /// # Safety
    ///
    /// `u` is a container, open or closed.
    pub unsafe extern "C" fn upatch_close(u: *mut Upatch) {
        // SAFETY: the caller passes a container.
        super::close_upatch(unsafe { &mut *u });
    }

    /// # Safety
    ///
    /// `u` is a container, and `out` room for NAME_MAX + 1 bytes.
    pub unsafe extern "C" fn upatch_header_name(u: *const Upatch, out: *mut c_char) {
        // SAFETY: the caller passes a container and the room.
        unsafe { super::header_name(&*u, &mut *out.cast::<[u8; NAME_MAX + 1]>()) };
    }

    /// # Safety
    ///
    /// `u` is a container.
    pub unsafe extern "C" fn upatch_loader(u: *const Upatch) -> *const c_void {
        // SAFETY: the caller passes a container.
        let u = unsafe { &*u };

        if u.map.is_null() {
            return ptr::null();
        }
        at(u, u.hdr.loader_insns_off)
    }

    /// # Safety
    ///
    /// `u` is a container.
    pub unsafe extern "C" fn upatch_signature(u: *const Upatch) -> *const c_void {
        // SAFETY: the caller passes a container.
        let u = unsafe { &*u };

        if u.map.is_null() {
            return ptr::null();
        }
        at(u, u.hdr.signature_off)
    }

    /// # Safety
    ///
    /// `u` is a container.
    pub unsafe extern "C" fn upatch_metadata(u: *const Upatch) -> *const c_void {
        // SAFETY: the caller passes a container.
        let u = unsafe { &*u };

        if u.map.is_null() || u.hdr.metadata_len == 0 {
            return ptr::null();
        }
        at(u, u.hdr.metadata_off)
    }

    /// # Safety
    ///
    /// `u` is a container.
    pub unsafe extern "C" fn upatch_data(u: *const Upatch) -> *const c_void {
        // SAFETY: the caller passes a container.
        let u = unsafe { &*u };

        if u.map.is_null() || u.hdr.data_len == 0 {
            return ptr::null();
        }
        at(u, u.hdr.data_off)
    }

    /// # Safety
    ///
    /// `name` and `payload_hex` are NULL or C strings.
    pub unsafe extern "C" fn upatch_member_valid(
        name: *const c_char,
        payload_hex: *const c_char,
    ) -> bool {
        // SAFETY: the caller passes NULL or C strings.
        unsafe { super::member_valid(name, payload_hex) }
    }

    /// # Safety
    ///
    /// `e` is a directory entry.
    pub unsafe extern "C" fn upatch_select(e: *const Dirent) -> c_int {
        // SAFETY: the entry's name, a C string, and a suffix.
        unsafe {
            let name = (*e).d_name.as_ptr();

            c_int::from(name_has_suffix(
                name,
                ffi::c_str(name).len(),
                c".upatch".as_ptr(),
            ))
        }
    }
}
