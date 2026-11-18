// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The config image cache: an image's four
//! parts fetched over HTTPS or copied from a local path into a sealed
//! staging directory, verified through a dm-verity mapping, and published
//! under the image's root hash.

use core::ffi::{CStr, c_char, c_int, c_long, c_void};
use core::mem::MaybeUninit;
use core::ptr;

use crate::errno::{EEXIST, EFBIG, EINTR, EINVAL, EIO, EKEYREJECTED, ENAMETOOLONG, ENOMEM, text};
use crate::sys::curl::{
    CURLE_OK, CURLOPT_CONNECTTIMEOUT, CURLOPT_FAILONERROR, CURLOPT_FOLLOWLOCATION,
    CURLOPT_LOW_SPEED_LIMIT, CURLOPT_LOW_SPEED_TIME, CURLOPT_MAXREDIRS, CURLOPT_PROTOCOLS_STR,
    CURLOPT_REDIR_PROTOCOLS_STR, CURLOPT_URL, CURLOPT_WRITEDATA, CURLOPT_WRITEFUNCTION,
    WriteCallback, curl_easy_cleanup, curl_easy_init, curl_easy_perform, curl_easy_setopt,
};
use crate::sys::libc::Zeroed;
use crate::sys::libc::{
    AT_EMPTY_PATH, O_CLOEXEC, O_CREAT, O_DIRECTORY, O_EXCL, O_NOFOLLOW, O_NONBLOCK, O_RDONLY,
    O_WRONLY, PATH_MAX, S_IFMT, S_IFREG, STATX_BASIC_STATS, Statx, close, errno, fsetxattr, fsync,
    link, mkdtemp, open, read, rmdir, statx, unlink,
};
use crate::util::config_image::{self, ConfigImageOpen, MAX_BYTES, SIG_MAX};
use crate::util::config_update::ConfigUpdateTarget;
use crate::util::dm_verity::{self, DmVerity};
use crate::util::hex::hex_encode;
use crate::util::io::write_complete;
use crate::util::seal::seal_label;
use crate::util::tls_openssl::tls_curl_policy;

/// `IMAGE_CACHE_DIR` of util/paths.h.
const IMAGE_CACHE_DIR: &CStr = c"/var/lib/shirudo/images";
/// `XATTR_SEAL` of util/paths.h.
pub(crate) const XATTR_SEAL: &CStr = c"security.bpf.shirudo";
/// The seal's label, which the image cache's files carry.
pub(crate) const SEAL_LABEL: &CStr =
    c"94442b45cfcdc59aabc2a91364ed2ae129418e05a5c1985231b9c032e673f469";

/// The parts of an image, each with the most a fetch of it may write.
const FILES: [(&CStr, u64); 4] = [
    (c".roothash", 65),
    (c".p7s", SIG_MAX),
    (c".img", MAX_BYTES),
    (c".verity", MAX_BYTES),
];

/// `struct image_download`: the file a fetch writes, why its last write
/// was refused, and how much it may and did write.
#[repr(C)]
struct Download {
    fd: c_int,
    err: c_int,
    limit: u64,
    written: u64,
}

/// `data` written to the download's file: all of it, or 0 with why into
/// `err`.
fn download_write(data: &[u8], d: &mut Download) -> usize {
    let bytes = data.len();
    if bytes as u64 > d.limit - d.written {
        d.err = -EFBIG;
        return 0;
    }
    // SAFETY: the download's fd, and the bytes.
    let ret = unsafe { write_complete(d.fd, data.as_ptr().cast(), bytes) };
    if ret != 0 {
        d.err = ret;
        return 0;
    }
    d.written += bytes as u64;
    bytes
}

/// download_write() as curl's write callback.
///
/// # Safety
///
/// `data` holds `size * count` bytes and `ctx` is the download.
unsafe extern "C" fn curl_write(
    data: *mut c_char,
    size: usize,
    count: usize,
    ctx: *mut c_void,
) -> usize {
    // SAFETY: the download handed to curl, which nothing else touches
    // during the transfer.
    let d = unsafe { &mut *ctx.cast::<Download>() };
    let Some(bytes) = size.checked_mul(count) else {
        d.err = -EFBIG;
        return 0;
    };
    // SAFETY: the bytes curl hands over.
    download_write(unsafe { crate::ffi::slice(data.cast::<u8>(), bytes) }, d)
}

/// The file at the HTTPS URL `source` into the download.
///
/// # Safety
///
/// `source` is a C string.
unsafe fn download_https(source: *const c_char, d: &mut Download) -> c_int {
    // SAFETY: a call that takes nothing.
    let curl = unsafe { curl_easy_init() };
    if curl.is_null() {
        return -ENOMEM;
    }
    // SAFETY: the handle, without a CA of the caller's.
    let mut ret = unsafe { tls_curl_policy(curl, ptr::null_mut()) };
    if ret == 0 {
        let write: WriteCallback = curl_write;

        // SAFETY: the handle, options with the types curl reads them as,
        // and the download, which outlives the transfer.
        unsafe {
            curl_easy_setopt(curl, CURLOPT_URL, source);
            curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, c"https".as_ptr());
            curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, c"https".as_ptr());
            curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1 as c_long);
            curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5 as c_long);
            curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1 as c_long);
            curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30 as c_long);
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1024 as c_long);
            curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 60 as c_long);
            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, ptr::from_mut(d).cast::<c_void>());
            if curl_easy_perform(curl) != CURLE_OK {
                ret = if d.err != 0 { d.err } else { -EIO };
            }
        }
    }
    // SAFETY: the handle, freed once.
    unsafe { curl_easy_cleanup(curl) };
    ret
}

/// The regular file at `source`, no larger than the download may be,
/// into the download.
///
/// # Safety
///
/// `source` is a C string.
unsafe fn copy_local(source: *const c_char, d: &mut Download) -> c_int {
    let mut buffer = [0u8; 65536];
    let mut st = Statx::zeroed();
    let mut ret = 0;

    // SAFETY: the caller's C string.
    let fd = unsafe { open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK) };
    if fd < 0 {
        return -errno();
    }
    // SAFETY: the file's fd, and room for its state.
    if unsafe { statx(fd, c"".as_ptr(), AT_EMPTY_PATH, STATX_BASIC_STATS, &mut st) } != 0 {
        ret = -errno();
    } else if st.stx_mode & S_IFMT != S_IFREG || (st.stx_size as i64) < 0 || st.stx_size > d.limit {
        ret = -EINVAL;
    } else {
        loop {
            // SAFETY: the file's fd, and the buffer's room.
            let n = unsafe { read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };

            if n == 0 {
                break;
            }
            if n < 0 {
                if errno() == EINTR {
                    continue;
                }
                ret = -errno();
                break;
            }
            if download_write(&buffer[..n as usize], d) != n as usize {
                ret = d.err;
                break;
            }
        }
    }
    // SAFETY: the file's fd, closed once.
    unsafe { close(fd) };
    ret
}

/// The part at `source` into a new sealed file at `destination`, of at
/// most `max` bytes.
///
/// # Safety
///
/// `source` and `destination` are C strings.
unsafe fn fetch_file(source: *const c_char, destination: *const c_char, max: u64) -> c_int {
    let mut d = Download {
        fd: 0,
        err: 0,
        limit: max,
        written: 0,
    };

    // SAFETY: the caller's C string, and a mode for the file it creates.
    let fd = unsafe {
        open(
            destination,
            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
            0o600,
        )
    };
    if fd < 0 {
        return -errno();
    }
    d.fd = fd;
    // SAFETY: the file's fd, the attribute's name, and its value.
    let mut ret = if unsafe {
        fsetxattr(
            fd,
            XATTR_SEAL.as_ptr(),
            SEAL_LABEL.as_ptr().cast(),
            SEAL_LABEL.to_bytes().len(),
            0,
        )
    } != 0
    {
        -errno()
    } else {
        0
    };
    if ret == 0 {
        // SAFETY: the caller's C string.
        ret = if unsafe { CStr::from_ptr(source) }
            .to_bytes()
            .starts_with(b"https://")
        {
            // SAFETY: as above.
            unsafe { download_https(source, &mut d) }
        } else {
            // SAFETY: as above.
            unsafe { copy_local(source, &mut d) }
        };
    }
    // SAFETY: the file's fd.
    if ret == 0 && unsafe { fsync(fd) } != 0 {
        ret = -errno();
    }
    // SAFETY: the file's fd, closed once.
    unsafe { close(fd) };
    ret
}

/// The image opened from the staging directory checked through a
/// dm-verity mapping of its own, which is removed after.
///
/// # Safety
///
/// `staging` is a C string with a slash.
unsafe fn verify_incoming(opened: &ConfigImageOpen, staging: *const c_char) -> c_int {
    // SAFETY: a structure of integers and arrays, zeroed as `= {}` does.
    let mut device: DmVerity = unsafe { MaybeUninit::zeroed().assume_init() };
    let mut name = [0u8; 128];

    device.data_loop_fd = -1;
    device.hash_loop_fd = -1;
    // SAFETY: the caller's C string, which holds a slash.
    let base = unsafe {
        let s = CStr::from_ptr(staging).to_bytes();
        let slash = s.iter().rposition(|&c| c == b'/').unwrap_or(0);

        staging.add(slash + 1)
    };
    // SAFETY: the name's room, and the C's format with its argument.
    if unsafe {
        crate::text::csprintf!(
            name.as_mut_ptr().cast(),
            name.len(),
            c"shirudo-verify-%s".as_ptr(),
            base,
        )
    } < 0
    {
        return -ENAMETOOLONG;
    }
    let ret = dm_verity::place(
        dm_verity::create(
            opened,
            CStr::from_bytes_until_nul(&name).unwrap_or_default(),
        ),
        &mut device,
    );
    if ret != 0 {
        return ret;
    }
    let ret = dm_verity::verify(&device, opened);
    let cleanup = dm_verity::remove(&mut device, true);
    if cleanup != 0 {
        crate::log::warn(
            format!("image: cannot remove incoming mapping: {}", text(cleanup)).as_bytes(),
        );
    }
    dm_verity::close_loops(&mut device);
    if ret != 0 { ret } else { cleanup }
}

/// image_cache_fetch(): the image at `source` fetched, verified and
/// published under its root hash, which with its cache prefix goes into
/// `target`.
///
/// # Safety
///
/// `source` is a C string.
unsafe fn fetch(
    source: *const c_char,
    target: &mut ConfigUpdateTarget,
    verify: &mut dyn FnMut(&ConfigImageOpen) -> c_int,
) -> c_int {
    let mut opened = ConfigImageOpen::closed();
    let mut staging = *b"/var/lib/shirudo/images/incoming-XXXXXX\0";
    let mut incoming = [0u8; PATH_MAX];
    let mut from = [0u8; PATH_MAX];
    let mut to = [0u8; PATH_MAX];
    let mut hex = [0u8; 65];
    let mut dir = -1;
    let mut ret;
    let staging_p = staging.as_mut_ptr().cast::<c_char>();

    // SAFETY: the template, which mkdtemp() fills in.
    if unsafe { mkdtemp(staging_p) }.is_null() {
        return -errno();
    }
    // SAFETY: C strings, and rooms with their sizes and the C's formats
    // with what they convert.
    unsafe {
        'out: {
            ret = seal_label(staging_p);
            if ret != 0 {
                break 'out;
            }
            if crate::text::csprintf!(
                incoming.as_mut_ptr().cast(),
                incoming.len(),
                c"%s/image".as_ptr(),
                staging_p,
            ) < 0
            {
                ret = -ENAMETOOLONG;
                break 'out;
            }
            for (suffix, max) in FILES {
                if crate::text::csprintf!(
                    from.as_mut_ptr().cast(),
                    from.len(),
                    c"%s%s".as_ptr(),
                    source,
                    suffix.as_ptr(),
                ) < 0
                    || crate::text::csprintf!(
                        to.as_mut_ptr().cast(),
                        to.len(),
                        c"%s%s".as_ptr(),
                        incoming.as_ptr(),
                        suffix.as_ptr(),
                    ) < 0
                {
                    ret = -ENAMETOOLONG;
                    break 'out;
                }
                ret = fetch_file(from.as_ptr().cast(), to.as_ptr().cast(), max);
                if ret != 0 {
                    break 'out;
                }
            }
            ret = config_image::place(
                ConfigImageOpen::open(
                    CStr::from_bytes_until_nul(&incoming).unwrap_or_default(),
                    None,
                ),
                &mut opened,
            );
            if ret != 0 {
                break 'out;
            }
            ret = verify(&opened);
            if ret == 0 {
                ret = verify_incoming(&opened, staging_p);
            }
            if ret == 0 {
                target.root_hash = opened.image.root_hash;
                hex_encode(target.root_hash.as_ptr(), 32, hex.as_mut_ptr().cast());
                if crate::text::csprintf!(
                    target.prefix.as_mut_ptr().cast(),
                    target.prefix.len(),
                    c"%s/%s".as_ptr(),
                    IMAGE_CACHE_DIR.as_ptr(),
                    hex.as_ptr(),
                ) < 0
                {
                    ret = -ENAMETOOLONG;
                }
            }
            opened.close();
            if ret != 0 {
                break 'out;
            }
            for (suffix, _) in FILES {
                if crate::text::csprintf!(
                    from.as_mut_ptr().cast(),
                    from.len(),
                    c"%s%s".as_ptr(),
                    incoming.as_ptr(),
                    suffix.as_ptr(),
                ) < 0
                    || crate::text::csprintf!(
                        to.as_mut_ptr().cast(),
                        to.len(),
                        c"%s%s".as_ptr(),
                        target.prefix.as_ptr(),
                        suffix.as_ptr(),
                    ) < 0
                {
                    ret = -ENAMETOOLONG;
                    break 'out;
                }
                if link(from.as_ptr().cast(), to.as_ptr().cast()) != 0 && errno() != EEXIST {
                    ret = -errno();
                    break 'out;
                }
            }
            dir = open(
                IMAGE_CACHE_DIR.as_ptr(),
                O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW,
            );
            if dir < 0 || fsync(dir) != 0 {
                ret = -errno();
                break 'out;
            }
            ret = config_image::place(
                ConfigImageOpen::open(
                    CStr::from_bytes_until_nul(&target.prefix).unwrap_or_default(),
                    None,
                ),
                &mut opened,
            );
            if ret == 0 {
                if opened.image.root_hash != target.root_hash {
                    ret = -EKEYREJECTED;
                }
                opened.close();
            }
        }
        if dir >= 0 {
            close(dir);
        }
        for (suffix, _) in FILES {
            if crate::text::csprintf!(
                to.as_mut_ptr().cast(),
                to.len(),
                c"%s/image%s".as_ptr(),
                staging_p,
                suffix.as_ptr(),
            ) >= 0
            {
                unlink(to.as_ptr().cast());
            }
        }
        rmdir(staging_p);
    }
    ret
}

/// Fetches the config image at `source` into the cache, as `target`
/// then names it, `verify` authenticating its root before a kernel
/// mapping is made of it.
pub(crate) fn fetch_verified(
    source: &CStr,
    target: &mut ConfigUpdateTarget,
    mut verify: impl FnMut(&ConfigImageOpen) -> c_int,
) -> c_int {
    // SAFETY: a C string.
    unsafe { fetch(source.as_ptr(), target, &mut verify) }
}
