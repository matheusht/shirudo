// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config image behind `util/config_image.h`: a data file, its
//! dm-verity hash tree behind the veritysetup superblock, its root hash,
//! and the signature of the root, opened and checked against each other.

use core::ffi::{CStr, c_int};

use crate::errno::{EFBIG, EINTR, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG};
use crate::sys::hex::hex_decode;
use crate::sys::libc::{
    AT_EMPTY_PATH, O_CLOEXEC, O_NOFOLLOW, O_NONBLOCK, O_RDONLY, PATH_MAX, S_IFMT, S_IFREG,
    STATX_SIZE, STATX_TYPE, Statx, close, errno, open, pread, statx,
};
use crate::text::strsprintf;

const BLOCK_SIZE: u64 = 4096;
const SALT_SIZE: usize = 32;
const SIG_MAX: u64 = 16384;
const MAX_BYTES: u64 = 1 << 40;
const DIGESTS_PER_BLOCK: u64 = BLOCK_SIZE / 32;
const SUPERBLOCK_SIZE: usize = 512;

/// `struct config_image`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ConfigImage {
    data_blocks: u64,
    hash_blocks: u64,
    signed_root: bool,
    salt: [u8; SALT_SIZE],
    root_hash: [u8; 32],
}

/// `struct config_image_open`: an image and its open parts, -1 for one
/// not open.
#[repr(C)]
pub struct ConfigImageOpen {
    image: ConfigImage,
    data_fd: c_int,
    hash_fd: c_int,
    signature_fd: c_int,
}

const _: () = assert!(size_of::<ConfigImage>() == 88);
const _: () = assert!(size_of::<ConfigImageOpen>() == 104);

impl ConfigImage {
    const fn zeroed() -> Self {
        ConfigImage {
            data_blocks: 0,
            hash_blocks: 0,
            signed_root: false,
            salt: [0; SALT_SIZE],
            root_hash: [0; 32],
        }
    }
}

impl ConfigImageOpen {
    const fn closed() -> Self {
        ConfigImageOpen {
            image: ConfigImage::zeroed(),
            data_fd: -1,
            hash_fd: -1,
            signature_fd: -1,
        }
    }

    fn close(&mut self) {
        for fd in [&mut self.data_fd, &mut self.hash_fd, &mut self.signature_fd] {
            if *fd >= 0 {
                // SAFETY: an fd this image opened, closed once, here.
                unsafe { close(*fd) };
            }
            *fd = -1;
        }
    }
}

/// The blocks of the hash tree over `data_blocks`: a level of digests per
/// block of the level below, up to one root block.
fn hash_blocks(mut data_blocks: u64) -> Result<u64, c_int> {
    let mut total = 1;

    if data_blocks == 0 || data_blocks > MAX_BYTES / BLOCK_SIZE {
        return Err(-EFBIG);
    }
    while data_blocks > 1 {
        data_blocks = data_blocks.div_ceil(DIGESTS_PER_BLOCK);
        total += data_blocks;
    }
    Ok(total)
}

/// The size of the regular file open on `fd`.
fn regular_file_size(fd: c_int) -> Result<u64, c_int> {
    let mut st = Statx::zeroed();

    // SAFETY: an empty path with AT_EMPTY_PATH names the fd, and a statx
    // to fill.
    if unsafe {
        statx(
            fd,
            c"".as_ptr(),
            AT_EMPTY_PATH,
            STATX_TYPE | STATX_SIZE,
            &mut st,
        )
    } != 0
    {
        return Err(-errno());
    }
    if st.mode & S_IFMT != S_IFREG {
        return Err(-EINVAL);
    }
    Ok(st.size)
}

/// `buf.len()` bytes from the start of `fd`; -EIO when it ends first.
fn read_exact_at_start(fd: c_int, buf: &mut [u8]) -> c_int {
    let mut done = 0;

    while done < buf.len() {
        // SAFETY: the room left in buf, from the caller's fd.
        let n = unsafe {
            pread(
                fd,
                buf[done..].as_mut_ptr().cast(),
                buf.len() - done,
                done as i64,
            )
        };
        if n < 0 {
            if errno() == EINTR {
                continue;
            }
            return -errno();
        }
        if n == 0 {
            return -EIO;
        }
        done += n as usize;
    }
    0
}

fn le16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn le64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

/// A veritysetup superblock of version 1 and SHA-256 over 4096-byte
/// blocks with a 32-byte salt.
fn superblock_ok(h: &[u8; SUPERBLOCK_SIZE]) -> bool {
    let mut algorithm = [0u8; 32];

    algorithm[..6].copy_from_slice(b"sha256");
    &h[0..8] == b"verity\0\0"
        && le32(&h[8..]) == 1
        && le32(&h[12..]) == 1
        && h[32..64] == algorithm
        && le32(&h[64..]) == BLOCK_SIZE as u32
        && le32(&h[68..]) == BLOCK_SIZE as u32
        && le16(&h[80..]) == SALT_SIZE as u16
}

/// The image the superblock at the start of `hash_fd` describes.
fn read_header(hash_fd: c_int) -> Result<ConfigImage, c_int> {
    let mut header = [0u8; SUPERBLOCK_SIZE];
    let mut image = ConfigImage::zeroed();

    let ret = read_exact_at_start(hash_fd, &mut header);
    if ret != 0 {
        return Err(ret);
    }
    if !superblock_ok(&header) {
        return Err(-EINVAL);
    }
    image.data_blocks = le64(&header[72..]);
    image.hash_blocks = hash_blocks(image.data_blocks)?;
    image.salt.copy_from_slice(&header[88..88 + SALT_SIZE]);
    Ok(image)
}

/// Whether the data and hash files are the sizes `image` gives them.
fn check_files(data_fd: c_int, hash_fd: c_int, image: &ConfigImage) -> c_int {
    let blocks = match hash_blocks(image.data_blocks) {
        Ok(blocks) => blocks,
        Err(e) => return e,
    };
    if blocks != image.hash_blocks {
        return -EINVAL;
    }
    let sizes = regular_file_size(data_fd).and_then(|d| Ok((d, regular_file_size(hash_fd)?)));
    let (data_size, hash_size) = match sizes {
        Ok(sizes) => sizes,
        Err(e) => return e,
    };
    if data_size != image.data_blocks * BLOCK_SIZE || hash_size != image.hash_blocks * BLOCK_SIZE {
        return -EINVAL;
    }
    0
}

/// `<prefix><suffix>` opened for reading, not through a symbolic link.
fn open_part(prefix: &[u8], suffix: &[u8]) -> c_int {
    let mut path = [0u8; PATH_MAX];

    if strsprintf(&mut path, &[prefix, suffix]).is_err() {
        return -ENAMETOOLONG;
    }
    // SAFETY: strsprintf() terminated the path; flags without a mode.
    let fd = unsafe {
        open(
            path.as_ptr().cast(),
            O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK,
        )
    };
    if fd < 0 { -errno() } else { fd }
}

/// The root hash `<prefix>.roothash` holds, 64 lowercase hex digits.
fn read_root(prefix: &[u8], root: &mut [u8; 32]) -> c_int {
    let mut text = [0u8; 65];

    let fd = open_part(prefix, b".roothash");
    if fd < 0 {
        return fd;
    }
    let mut ret = match regular_file_size(fd) {
        Ok(64) => 0,
        Ok(_) => -EINVAL,
        Err(e) => e,
    };
    if ret == 0 {
        ret = read_exact_at_start(fd, &mut text[..64]);
    }
    // SAFETY: the fd open_part() gave, closed once, here.
    unsafe { close(fd) };
    if ret != 0 {
        return ret;
    }
    if !text[..64]
        .iter()
        .all(|&c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    {
        return -EINVAL;
    }
    // SAFETY: 64 digits and a NUL, and room for the 32 bytes.
    unsafe { hex_decode(text.as_ptr().cast(), root.as_mut_ptr(), 32) }
}

/// The image at `prefix`, its parts open and checked against each other
/// and its root against `expected_root`, or else signed.
fn open_image(
    prefix: &CStr,
    expected_root: Option<&[u8; 32]>,
    image: &mut ConfigImageOpen,
) -> c_int {
    let prefix = prefix.to_bytes();

    image.data_fd = open_part(prefix, b".img");
    if image.data_fd < 0 {
        let ret = image.data_fd;

        image.data_fd = -1;
        return ret;
    }
    image.hash_fd = open_part(prefix, b".verity");
    if image.hash_fd < 0 {
        let ret = image.hash_fd;

        image.hash_fd = -1;
        return ret;
    }
    image.image = match read_header(image.hash_fd) {
        Ok(header) => header,
        Err(e) => return e,
    };
    let mut ret = read_root(prefix, &mut image.image.root_hash);
    if ret == 0 {
        ret = check_files(image.data_fd, image.hash_fd, &image.image);
    }
    if ret != 0 {
        return ret;
    }
    match expected_root {
        Some(root) => {
            if *root != image.image.root_hash {
                return -EKEYREJECTED;
            }
            0
        }
        None => {
            image.image.signed_root = true;
            image.signature_fd = open_part(prefix, b".p7s");
            if image.signature_fd < 0 {
                let ret = image.signature_fd;

                image.signature_fd = -1;
                return ret;
            }
            match regular_file_size(image.signature_fd) {
                Ok(0) => -EINVAL,
                Ok(size) if size > SIG_MAX => -EINVAL,
                Ok(_) => 0,
                Err(e) => e,
            }
        }
    }
}

mod capi {
    use core::ffi::{CStr, c_char, c_int};

    use super::{ConfigImage, ConfigImageOpen, check_files, open_image, read_header};
    use crate::errno::EINVAL;

    /// `src` into `dst` field by field after its bytes are zeroed, so that
    /// its padding stays zero, as the C's assignment of a structure it
    /// initialised empty left it.
    ///
    /// # Safety
    ///
    /// `dst` is room for an image nothing else accesses meanwhile.
    unsafe fn store_image(dst: *mut ConfigImage, src: &ConfigImage) {
        // SAFETY: the caller's room.
        unsafe {
            dst.write_bytes(0, 1);
            (*dst).data_blocks = src.data_blocks;
            (*dst).hash_blocks = src.hash_blocks;
            (*dst).signed_root = src.signed_root;
            (*dst).salt = src.salt;
            (*dst).root_hash = src.root_hash;
        }
    }

    /// As [`store_image`], for an image and its fds.
    ///
    /// # Safety
    ///
    /// `dst` is room for an open image nothing else accesses meanwhile.
    unsafe fn store_open(dst: *mut ConfigImageOpen, src: &ConfigImageOpen) {
        // SAFETY: the caller's room.
        unsafe {
            dst.write_bytes(0, 1);
            store_image(&raw mut (*dst).image, &src.image);
            (*dst).data_fd = src.data_fd;
            (*dst).hash_fd = src.hash_fd;
            (*dst).signature_fd = src.signature_fd;
        }
    }

    /// # Safety
    ///
    /// `out` is NULL or an image to fill.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_image_read_header(
        hash_fd: c_int,
        out: *mut ConfigImage,
    ) -> c_int {
        if out.is_null() {
            return -EINVAL;
        }
        match read_header(hash_fd) {
            Ok(image) => {
                // SAFETY: the caller's image.
                unsafe { store_image(out, &image) };
                0
            }
            Err(e) => e,
        }
    }

    /// # Safety
    ///
    /// `image` is NULL or an image.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_image_check_files(
        data_fd: c_int,
        hash_fd: c_int,
        image: *const ConfigImage,
    ) -> c_int {
        if image.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller passes its image.
        check_files(data_fd, hash_fd, unsafe { &*image })
    }

    /// # Safety
    ///
    /// `prefix` is NULL or a C string, `expected_root` NULL or 32 bytes,
    /// and `out` NULL or an image to fill.
    unsafe fn open(
        prefix: *const c_char,
        expected_root: *const u8,
        out: *mut ConfigImageOpen,
    ) -> c_int {
        // SAFETY: the caller passes NULL or a C string.
        if prefix.is_null() || out.is_null() || unsafe { *prefix } == 0 {
            return -EINVAL;
        }
        let mut image = ConfigImageOpen::closed();

        // SAFETY: the caller's image, reset until the open succeeds, and
        // its C string and root.
        unsafe {
            store_open(out, &ConfigImageOpen::closed());
            let root = (!expected_root.is_null()).then(|| &*expected_root.cast::<[u8; 32]>());
            let ret = open_image(CStr::from_ptr(prefix), root, &mut image);

            if ret != 0 {
                image.close();
                return ret;
            }
            store_open(out, &image);
        }
        0
    }

    /// # Safety
    ///
    /// `prefix` is NULL or a C string and `out` NULL or an image to fill.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_image_open(
        prefix: *const c_char,
        out: *mut ConfigImageOpen,
    ) -> c_int {
        // SAFETY: the caller's arguments.
        unsafe { open(prefix, core::ptr::null(), out) }
    }

    /// # Safety
    ///
    /// `prefix` is NULL or a C string, `expected_root` NULL or 32 bytes,
    /// and `out` NULL or an image to fill.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_image_open_root(
        prefix: *const c_char,
        expected_root: *const u8,
        out: *mut ConfigImageOpen,
    ) -> c_int {
        if expected_root.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller's arguments.
        unsafe { open(prefix, expected_root, out) }
    }

    /// # Safety
    ///
    /// `image` is NULL or an image whose fds it may close.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_image_close(image: *mut ConfigImageOpen) {
        if !image.is_null() {
            // SAFETY: the caller passes its image.
            unsafe { (*image).close() };
        }
    }
}
