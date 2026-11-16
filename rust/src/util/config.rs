// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! The site configuration behind `util/config.h`: the `key = value`
//! lines of /etc/shirudo/shirudo.conf, or the settings a config image
//! carries, and the TPM settings the environment overrides.

use core::ffi::{CStr, c_char, c_int};
use core::mem::MaybeUninit;
use core::ptr;

use crate::errno::{EINVAL, EIO, ENOENT, EPERM};
use crate::ffi;
use crate::sys::hex::hex_decode_max;
use crate::sys::libc::{
    BUFSIZ, F_DUPFD_CLOEXEC, File, IOFBF, SEEK_SET, close, env, errno, explicit_bzero, fclose,
    fcntl, fdopen, ferror, fileno, fopen, free, lseek, scrub, setvbuf, strerror,
};
use crate::sys::log::{pr_err, pr_warn};
use crate::sys::string::dns_name_valid;
use crate::text::{parse_u64, strscpy, trim_blanks};
use crate::util::io::{check_trusted, read_text_line};
use crate::util::json::MAX_BYTES;

const OWNER_AUTH_MAX: usize = 256;
const TPM_TCTI_MAX: usize = 256;
const TLS_HOSTS_MAX: usize = 1024;
const MAP_EXPORT_PATH_MAX: usize = 4096;
const MAP_EXPORT_ENDPOINT_MAX: usize = 2048;
const MAP_EXPORT_URI_MAX: usize = 2048;
const TENANT_ID_MAX: usize = 128;
const LOG_RECORD_MAX_DEFAULT: u32 = 1024 * 1024;
const OTLP_MAX_DEFAULT: u32 = 4 * 1024 * 1024;
pub(crate) const CONF_PATH: &CStr = c"/etc/shirudo/shirudo.conf";

/// `struct config`.
#[repr(C)]
pub struct Config {
    pub(crate) eventlog_max_bytes: u64,
    pub(crate) tpm_owner_auth: [u8; OWNER_AUTH_MAX],
    pub(crate) tpm_owner_auth_len: usize,
    pub(crate) tpm_tcti: [u8; TPM_TCTI_MAX],
    pub(crate) tls_classical_hosts_valid: bool,
    pub(crate) tls_classical_hosts: [u8; TLS_HOSTS_MAX],
    pub(crate) map_export_valid: bool,
    pub(crate) map_export_json_path: [u8; MAP_EXPORT_PATH_MAX],
    pub(crate) map_export_otel_endpoint: [u8; MAP_EXPORT_ENDPOINT_MAX],
    pub(crate) map_export_tenant_id: [u8; TENANT_ID_MAX + 1],
    pub(crate) map_export_otel_insecure: bool,
    pub(crate) map_export_otel_retries: u32,
    pub(crate) map_export_s3_uri: [u8; MAP_EXPORT_URI_MAX],
    pub(crate) map_export_log_record_max_bytes: u32,
    pub(crate) map_export_otlp_max_bytes: u32,
}

const _: () = assert!(size_of::<Config>() == 9888);

/// A configuration scrubbed when it goes, as `__cleanup(config_clear)`
/// left the C's.
pub(crate) struct Scrubbed(pub(crate) MaybeUninit<Config>);

impl Scrubbed {
    pub(crate) fn ptr(&mut self) -> *mut Config {
        self.0.as_mut_ptr()
    }
}

impl Drop for Scrubbed {
    fn drop(&mut self) {
        // SAFETY: the bytes of the configuration.
        unsafe { explicit_bzero(self.0.as_mut_ptr().cast(), size_of::<Config>()) };
    }
}

/// A tenant ID: 1 to 128 of `[A-Za-z0-9._-]`.
fn tenant_id_valid(id: &[u8]) -> bool {
    !id.is_empty()
        && id.len() <= TENANT_ID_MAX
        && id
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// A list of exact DNS names apart by single commas, or none.
fn tls_classical_hosts_valid(value: &[u8]) -> bool {
    if value.is_empty() {
        return true;
    }
    let mut rest = value;
    loop {
        let len = rest.iter().position(|&c| c == b',').unwrap_or(rest.len());
        let mut name = [0u8; 254];

        if len == 0 || len >= name.len() {
            return false;
        }
        name[..len].copy_from_slice(&rest[..len]);
        // SAFETY: name is terminated within its room.
        if !unsafe { dns_name_valid(name.as_ptr().cast()) } {
            return false;
        }
        if len == rest.len() {
            return true;
        }
        rest = &rest[len + 1..];
        if rest.is_empty() {
            return false;
        }
    }
}

/// `cfg` cleared and given its defaults, its padding zeroed.
///
/// # Safety
///
/// `cfg` is a configuration nothing else accesses meanwhile.
unsafe fn defaults(cfg: *mut Config) {
    // SAFETY: the caller's configuration, all of whose bits zeroed are a
    // valid one.
    let cfg = unsafe {
        cfg.write_bytes(0, 1);
        &mut *cfg
    };
    cfg.map_export_valid = true;
    cfg.tls_classical_hosts_valid = true;
    cfg.map_export_otel_retries = 3;
    cfg.map_export_log_record_max_bytes = LOG_RECORD_MAX_DEFAULT;
    cfg.map_export_otlp_max_bytes = OTLP_MAX_DEFAULT;
}

/// A setting of the map export refused: the export goes idle.
fn map_export_bad(cfg: &mut Config, key: &CStr, val: &CStr, reason: &CStr) {
    cfg.map_export_valid = false;
    // SAFETY: the C's format and three C strings.
    unsafe {
        pr_warn(
            c"config: %s: bad value '%s' (%s)".as_ptr(),
            key.as_ptr(),
            val.as_ptr(),
            reason.as_ptr(),
        )
    };
}

/// Owner auth is a literal passphrase, or `hex:<even hex>` for a binary
/// auth value, what provisioning tools that randomise owner auth emit.
fn set_owner_auth(cfg: &mut Config, val: &CStr) {
    let bytes = val.to_bytes();

    if let Some(hex) = bytes.strip_prefix(b"hex:") {
        let mut auth = [0u8; OWNER_AUTH_MAX];
        let mut n = 0;
        // SAFETY: a C string after its prefix, and room for the bytes.
        let ret = unsafe {
            hex_decode_max(
                val.as_ptr().add(bytes.len() - hex.len()),
                auth.as_mut_ptr(),
                auth.len(),
                &mut n,
            )
        };

        // An ignored value leaves the one set before intact.
        if ret == 0 {
            cfg.tpm_owner_auth[..n].copy_from_slice(&auth[..n]);
            cfg.tpm_owner_auth_len = n;
        } else {
            // SAFETY: the C's format and its argument.
            unsafe {
                pr_warn(
                    c"config: tpm.owner_auth: not an even count of up to %zu hex digits (ignored)"
                        .as_ptr(),
                    2 * auth.len(),
                )
            };
        }
        scrub(&mut auth);
        return;
    }
    if bytes.len() > cfg.tpm_owner_auth.len() {
        // SAFETY: the C's format.
        unsafe { pr_warn(c"config: tpm.owner_auth too long (ignored)".as_ptr()) };
        return;
    }
    cfg.tpm_owner_auth[..bytes.len()].copy_from_slice(bytes);
    cfg.tpm_owner_auth_len = bytes.len();
}

/// `strscpy()` into a field: whether the whole value fit.
fn set_string(dst: &mut [u8], val: &CStr) -> bool {
    strscpy(dst, val.to_bytes()).is_ok()
}

/// The terminated text at `start` of `buf`.
fn text_at(buf: &[u8], start: usize) -> &CStr {
    CStr::from_bytes_until_nul(&buf[start..]).unwrap_or(c"")
}

/// One `key = value` line into `cfg`.
fn apply(cfg: &mut Config, key: &CStr, val: &CStr) {
    let k = key.to_bytes();
    let v = val.to_bytes();

    match k {
        b"eventlog.max_bytes" => match parse_u64(v, u64::MAX) {
            Ok(n) => cfg.eventlog_max_bytes = n,
            // SAFETY: the C's format and a C string.
            Err(_) => unsafe {
                pr_warn(
                    c"config: eventlog.max_bytes: bad value '%s' (ignored)".as_ptr(),
                    val.as_ptr(),
                )
            },
        },
        b"tpm.owner_auth" => set_owner_auth(cfg, val),
        b"tpm.tcti" => {
            if v.len() >= cfg.tpm_tcti.len() {
                // SAFETY: the C's format.
                unsafe { pr_warn(c"config: tpm.tcti too long (ignored)".as_ptr()) };
            } else {
                set_string(&mut cfg.tpm_tcti, val);
            }
        }
        b"tls.classical_hosts" => {
            if !set_string(&mut cfg.tls_classical_hosts, val) || !tls_classical_hosts_valid(v) {
                cfg.tls_classical_hosts_valid = false;
                // SAFETY: the C's format.
                unsafe {
                    pr_warn(c"config: tls.classical_hosts: invalid exact DNS host list".as_ptr())
                };
            }
        }
        b"map_export.json_path" => {
            if !set_string(&mut cfg.map_export_json_path, val) {
                map_export_bad(cfg, key, val, c"value too long");
            } else if !v.is_empty() && v[0] != b'/' {
                map_export_bad(cfg, key, val, c"path must be absolute");
            }
        }
        b"map_export.otel_endpoint" => {
            if !set_string(&mut cfg.map_export_otel_endpoint, val) {
                map_export_bad(cfg, key, val, c"value too long");
            }
        }
        b"map_export.tenant_id" => {
            if !v.is_empty() && !tenant_id_valid(v) {
                map_export_bad(
                    cfg,
                    key,
                    val,
                    c"expected 1..128 characters from A-Z, a-z, 0-9, '.', '_', '-'",
                );
            } else {
                set_string(&mut cfg.map_export_tenant_id, val);
            }
        }
        b"map_export.otel_insecure" => match v {
            b"true" => cfg.map_export_otel_insecure = true,
            b"false" => cfg.map_export_otel_insecure = false,
            _ => map_export_bad(cfg, key, val, c"expected true or false"),
        },
        b"map_export.otel_retries" => match parse_u64(v, 10) {
            Ok(n) => cfg.map_export_otel_retries = n as u32,
            Err(_) => map_export_bad(cfg, key, val, c"expected 0..10"),
        },
        b"map_export.s3_uri" => {
            if !set_string(&mut cfg.map_export_s3_uri, val) {
                map_export_bad(cfg, key, val, c"value too long");
            }
        }
        b"map_export.log_record_max_bytes" | b"map_export.otlp_max_bytes" => {
            match parse_u64(v, MAX_BYTES as u64) {
                Ok(n) if n != 0 => {
                    if k == b"map_export.log_record_max_bytes" {
                        cfg.map_export_log_record_max_bytes = n as u32;
                    } else {
                        cfg.map_export_otlp_max_bytes = n as u32;
                    }
                }
                _ => map_export_bad(cfg, key, val, c"expected 1..8388608 bytes"),
            }
        }
        _ if k.starts_with(b"config.") || k.starts_with(b"runtime.") => {}
        _ if k.starts_with(b"map_export.") => map_export_bad(cfg, key, val, c"unknown key"),
        _ if k.starts_with(b"tls.") => {
            cfg.tls_classical_hosts_valid = false;
            // SAFETY: the C's format and a C string.
            unsafe { pr_warn(c"config: %s: unknown TLS setting".as_ptr(), key.as_ptr()) };
        }
        // SAFETY: the C's format and a C string.
        _ => unsafe { pr_warn(c"config: unknown key '%s' (ignored)".as_ptr(), key.as_ptr()) },
    }
}

/// The lines of the stream `f`, which this consumes and closes, into
/// `cfg`; `path` names the file for the log.
///
/// # Safety
///
/// `f` is an open stream nothing else uses, and `path` a C string.
unsafe fn parse(cfg: &mut Config, f: *mut File, path: *const c_char) -> c_int {
    const MAX: usize = MAP_EXPORT_PATH_MAX + 127;
    let mut buffer = [0u8; BUFSIZ];
    let mut line: *mut c_char = ptr::null_mut();
    let mut capacity = 0usize;
    let mut ret = 0;

    // SAFETY: the caller's stream and path; the buffer stdio takes lives
    // until the stream closes below, and the line is getline()'s, the
    // len bytes before its NUL.
    unsafe {
        if check_trusted(fileno(f), path, false) != 0 {
            fclose(f);
            return -EPERM;
        }
        // stdio's own buffer would keep the owner's authorization after
        // fclose().
        setvbuf(f, buffer.as_mut_ptr().cast(), IOFBF, buffer.len());
        loop {
            let got = read_text_line(f, &mut line, &mut capacity, MAX);

            if got == 0 {
                break;
            }
            if got == -crate::errno::E2BIG {
                pr_warn(
                    c"config: line longer than %zu bytes (ignored)".as_ptr(),
                    MAX,
                );
                continue;
            }
            if got < 0 {
                pr_err(
                    c"config: %s: unreadable line: %s".as_ptr(),
                    path,
                    strerror(-got),
                );
                ret = got;
                break;
            }
            let len = CStr::from_ptr(line).to_bytes().len();
            let buf = ffi::bytes_mut(line.cast(), len + 1);
            let (ps, pe) = trim_blanks(buf, 0, len);
            if ps == pe || buf[ps] == b'#' {
                continue;
            }
            let Some(eq) = buf[ps..pe].iter().position(|&c| c == b'=').map(|i| ps + i) else {
                continue;
            };
            buf[eq] = 0;
            let (ks, _) = trim_blanks(buf, ps, eq);
            let (vs, _) = trim_blanks(buf, eq + 1, pe);
            apply(cfg, text_at(buf, ks), text_at(buf, vs));
        }
        if ferror(f) != 0 && ret == 0 {
            ret = -EIO;
        }
        // The TPM owner's authorization is for no other user's eyes.
        if cfg.tpm_owner_auth_len != 0 && check_trusted(fileno(f), path, true) != 0 {
            scrub(&mut cfg.tpm_owner_auth);
            cfg.tpm_owner_auth_len = 0;
            ret = -EPERM;
        }
        if !line.is_null() {
            // The owner's authorization may have been read into it.
            explicit_bzero(line.cast(), capacity);
            free(line.cast());
        }
        if fclose(f) != 0 && ret == 0 {
            ret = -errno();
        }
    }
    scrub(&mut buffer);
    ret
}

fn finish(cfg: &mut Config, ret: c_int) -> c_int {
    if cfg.map_export_s3_uri[0] != 0 && cfg.map_export_otel_endpoint[0] == 0 {
        map_export_bad(
            cfg,
            c"map_export.s3_uri",
            c"",
            c"requires map_export.otel_endpoint for its reference event",
        );
    }
    if cfg.map_export_log_record_max_bytes > cfg.map_export_otlp_max_bytes {
        map_export_bad(
            cfg,
            c"map_export.log_record_max_bytes",
            c"",
            c"must not exceed otlp_max_bytes",
        );
    }
    ret
}

/// # Safety
///
/// `cfg` is a configuration and `path` a C string.
unsafe fn load_path(cfg: *mut Config, path: *const c_char) -> c_int {
    let mut ret = 0;

    // SAFETY: the caller's configuration and C string.
    unsafe {
        defaults(cfg);
        let f = fopen(path, c"re".as_ptr());
        if f.is_null() {
            if errno() != ENOENT {
                // The environment's overrides still apply.
                ret = -errno();
            }
        } else {
            ret = parse(&mut *cfg, f, path);
        }
        finish(&mut *cfg, ret)
    }
}

/// The configuration from the image, or else the file and then the
/// environment, which wins so that one dev run can point at swtpm while
/// the file is shared.
///
/// # Safety
///
/// `cfg` is a configuration.
pub(crate) unsafe fn load(cfg: *mut Config) -> c_int {
    // SAFETY: the caller's configuration.
    unsafe {
        if crate::util::image_config::get(cfg) != 0 {
            return 0;
        }
        let ret = load_path(cfg, CONF_PATH.as_ptr());
        if ret != 0 && ret != -ENOENT {
            return ret;
        }
        let cfg = &mut *cfg;
        if let Some(auth) = env(c"SHIRUDO_TPM_OWNER_AUTH") {
            set_owner_auth(cfg, auth);
        }
        if let Some(tcti) = env(c"SHIRUDO_TPM_TCTI").filter(|t| !t.is_empty()) {
            if tcti.to_bytes().len() < cfg.tpm_tcti.len() {
                set_string(&mut cfg.tpm_tcti, tcti);
            } else {
                pr_warn(c"SHIRUDO_TPM_TCTI too long (ignored)".as_ptr());
            }
        }
        if ret == -ENOENT { 0 } else { ret }
    }
}

/// The configuration in the file open on `fd`, read from its start
/// through a copy of the fd; the caller keeps its own.
///
/// # Safety
///
/// `cfg` is a configuration to fill, and `label` a C string.
pub(crate) unsafe fn load_fd(cfg: *mut Config, fd: c_int, label: *const c_char) -> c_int {
    if fd < 0 {
        return -EINVAL;
    }
    // SAFETY: the caller's configuration and label, and the copy of its
    // fd, which the stream takes over or which is closed here.
    unsafe {
        defaults(cfg);
        let copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if copy < 0 {
            return -errno();
        }
        if lseek(copy, 0, SEEK_SET) < 0 {
            let ret = -errno();

            close(copy);
            return ret;
        }
        let f = fdopen(copy, c"r".as_ptr());
        if f.is_null() {
            let ret = -errno();

            close(copy);
            return ret;
        }
        let ret = parse(&mut *cfg, f, label);
        finish(&mut *cfg, ret)
    }
}

pub(crate) use capi::{config_load_fd, config_load_path};

mod capi {
    use core::ffi::{c_char, c_int};

    use super::{Config, load, load_path};
    use crate::errno::EINVAL;
    use crate::sys::libc::explicit_bzero;

    /// # Safety
    ///
    /// `cfg` is a configuration to fill.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_load(cfg: *mut Config) -> c_int {
        // SAFETY: the caller passes its configuration.
        unsafe { load(cfg) }
    }

    /// # Safety
    ///
    /// `cfg` is a configuration to fill.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_clear(cfg: *mut Config) {
        // SAFETY: the caller passes its configuration.
        unsafe { explicit_bzero(cfg.cast(), size_of::<Config>()) };
    }

    /// # Safety
    ///
    /// `cfg` is NULL or a configuration to fill, and `path` NULL or a C
    /// string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_load_path(cfg: *mut Config, path: *const c_char) -> c_int {
        if cfg.is_null() || path.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller passes its configuration and a C string.
        unsafe { load_path(cfg, path) }
    }

    /// A copy of `fd` is read from its start; the caller keeps its own.
    ///
    /// # Safety
    ///
    /// `cfg` is NULL or a configuration to fill, and `label` a C string.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn config_load_fd(
        cfg: *mut Config,
        fd: c_int,
        label: *const c_char,
    ) -> c_int {
        if cfg.is_null() {
            return -EINVAL;
        }
        // SAFETY: the caller passes its configuration and label.
        unsafe { super::load_fd(cfg, fd, label) }
    }
}
