// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo config`: the effective shirudo.conf, or without one the
//! defaults in the same syntax, as a template.

use core::ffi::{CStr, c_char, c_int};
use core::mem::MaybeUninit;
use core::ptr;

use super::word;
use crate::errno::ENOENT;
use crate::ffi::c_splice;
use crate::sys::libc::{F_OK, access, env, fprintf, printf, stderr, strerror};
use crate::util::config::{CONF_PATH, Scrubbed, load};
use crate::util::help::{Help, is_help, print_help};
use crate::util::image_config;

const USAGE: &CStr = c"shirudo config";
/// CONF_PATH, as text for the help and the line that splice it in.
const CONF: &str = match CONF_PATH.to_str() {
    Ok(path) => path,
    Err(_) => panic!("CONF_PATH is not UTF-8"),
};
const SUMMARY: &CStr = c_splice!(
    "Print the effective shirudo configuration in shirudo.conf syntax.\nWhen ",
    CONF,
    " is absent, prints the defaults.\nLocal-only.",
);
const FOOTER: &CStr = c_splice!(
    "Starting point for a new config file:\n  shirudo config > ",
    CONF,
);
const FROM_CONF: &CStr = c_splice!("; from ", CONF);

/// The command on `args`, its name first.
///
/// # Safety
///
/// Each of `args` is NULL or a C string.
unsafe fn config(args: &[*const c_char]) -> c_int {
    let mut cfg = Scrubbed(MaybeUninit::uninit());
    let image_mode = image_config::active();

    if let Some(&arg) = args.get(1) {
        // SAFETY: the caller's word.
        if is_help(unsafe { word(arg) }) {
            let help = Help {
                usage: USAGE.as_ptr(),
                summary: SUMMARY.as_ptr(),
                sections: ptr::null(),
                n_sections: 0,
                footer: FOOTER.as_ptr(),
            };

            // SAFETY: the help, its strings literals.
            unsafe { print_help(&help) };
            return 0;
        }
        // SAFETY: the C's formats, the caller's word, the usage and the
        // C library's stderr.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"config: unknown option '%s'".as_ptr(),
                arg
            );
            fprintf(stderr, c"usage: %s\n".as_ptr(), USAGE.as_ptr());
        }
        return 2;
    }

    // SAFETY: a path, and a mode.
    let file_present = unsafe { access(CONF_PATH.as_ptr(), F_OK) } == 0;
    // SAFETY: the room for the configuration.
    let ret = unsafe { load(cfg.ptr()) };
    if ret != 0 && ret != -ENOENT {
        // SAFETY: the C's format, the path and the error's text.
        unsafe {
            crate::log::log_c!(
                crate::log::err,
                c"config: load %s: %s".as_ptr(),
                CONF_PATH.as_ptr(),
                strerror(-ret),
            )
        };
        return 1;
    }
    // SAFETY: the configuration load() filled, which cfg scrubs when it
    // goes at the end.
    let c = unsafe { &*cfg.ptr() };

    // SAFETY: the C's formats, with the configuration's numbers and its
    // strings, each ending within its array.
    unsafe {
        if image_mode {
            printf(
                c"# shirudo config (authenticated config image; \
                  TPM settings from runtime image)\n\n"
                    .as_ptr(),
            );
        } else if file_present {
            printf(
                c"# shirudo config (effective, loaded from %s)\n\n".as_ptr(),
                CONF_PATH.as_ptr(),
            );
        } else {
            printf(
                c"# shirudo config (no %s present; defaults shown)\n\n".as_ptr(),
                CONF_PATH.as_ptr(),
            );
        }

        printf(
            c"# Eventlog cap; 0 = unlimited. When the log would exceed this,\n\
              # the state-changing op refuses with category: eventlog_full.\n"
                .as_ptr(),
        );
        printf(
            c"eventlog.max_bytes = %llu\n\n".as_ptr(),
            c.eventlog_max_bytes,
        );

        printf(
            c"# TPM owner-hierarchy password used at NV-index define time.\n\
              # Empty by default (works on fresh TPMs, swtpm, most cloud VMs);\n\
              # set on TPMs whose owner auth was already provisioned by\n\
              # another tool. Literal string, or `hex:<even hex>` for a\n\
              # binary auth value. May also be supplied via the\n\
              # SHIRUDO_TPM_OWNER_AUTH env var; that override wins.\n"
                .as_ptr(),
        );
        if c.tpm_owner_auth_len > 0 {
            let var = if image_mode {
                None
            } else {
                env(c"SHIRUDO_TPM_OWNER_AUTH")
            };
            let from = if image_mode {
                c"; from runtime image"
            } else if var.is_some() {
                c"; from $SHIRUDO_TPM_OWNER_AUTH"
            } else {
                FROM_CONF
            };

            printf(
                c"# tpm.owner_auth = (set, %zu bytes; redacted%s)\n\n".as_ptr(),
                c.tpm_owner_auth_len,
                from.as_ptr(),
            );
        } else {
            printf(c"# tpm.owner_auth = (unset)\n\n".as_ptr());
        }

        printf(
            c"# TCTI override for the TPM library connection. Empty (default)\n\
              # means the kernel resource manager at `device:/dev/tpmrm0`.\n\
              # Set to `swtpm:host=<addr>,port=<port>` for a software TPM\n\
              # emulator (dev/CI without real hardware); testing/swtpm.sh\n\
              # in the source tree starts one. Pre-flight skips the\n\
              # /dev/tpmrm0 check when this is set. The SHIRUDO_TPM_TCTI\n\
              # env var overrides this in turn.\n"
                .as_ptr(),
        );
        if c.tpm_tcti[0] != 0 {
            let var = if image_mode {
                None
            } else {
                env(c"SHIRUDO_TPM_TCTI")
            };
            let from = if image_mode {
                c"runtime image"
            } else if var.is_some_and(|var| !var.is_empty()) {
                c"$SHIRUDO_TPM_TCTI"
            } else {
                CONF_PATH
            };

            printf(
                c"tpm.tcti = %s  # from %s\n\n".as_ptr(),
                c.tpm_tcti.as_ptr(),
                from.as_ptr(),
            );
        } else {
            printf(c"# tpm.tcti = (unset, using device:/dev/tpmrm0)\n\n".as_ptr());
        }

        printf(
            c"# Exact DNS hosts that may use classical TLS key exchange.\n\
              # Targets honor this only from the immutable runtime image;\n\
              # operators use the root-managed /etc/shirudo/shirudo.conf.\n\
              # Leave empty for hybrid-only TLS.\n"
                .as_ptr(),
        );
        printf(
            c"tls.classical_hosts = %s\n\n".as_ptr(),
            c.tls_classical_hosts.as_ptr(),
        );

        printf(
            c"# Periodic `shirudo upatch map --all` export. Empty JSON and\n\
              # OTLP destinations leave the installed timer idle. Every emitted\n\
              # map must carry a signed Lua decoder declaring log or metric.\n\
              # OTEL headers, TLS material, and AWS credentials belong in\n\
              # /etc/shirudo/map-export.env for the systemd service.\n"
                .as_ptr(),
        );
        printf(
            c"map_export.json_path = %s\n".as_ptr(),
            c.map_export_json_path.as_ptr(),
        );
        printf(
            c"map_export.otel_endpoint = %s\n".as_ptr(),
            c.map_export_otel_endpoint.as_ptr(),
        );
        printf(
            c"map_export.tenant_id = %s\n".as_ptr(),
            c.map_export_tenant_id.as_ptr(),
        );
        printf(
            c"map_export.otel_insecure = %s\n".as_ptr(),
            if c.map_export_otel_insecure {
                c"true"
            } else {
                c"false"
            }
            .as_ptr(),
        );
        printf(
            c"map_export.otel_retries = %u\n".as_ptr(),
            c.map_export_otel_retries,
        );
        printf(
            c"map_export.s3_uri = %s\n".as_ptr(),
            c.map_export_s3_uri.as_ptr(),
        );
        printf(
            c"map_export.log_record_max_bytes = %u\n".as_ptr(),
            c.map_export_log_record_max_bytes,
        );
        printf(
            c"map_export.otlp_max_bytes = %u\n".as_ptr(),
            c.map_export_otlp_max_bytes,
        );
    }
    c_int::from(!(c.map_export_valid && c.tls_classical_hosts_valid))
}

pub(super) use capi::cmd_config;

mod capi {
    use core::ffi::{c_char, c_int};

    use super::super::words;

    /// # Safety
    ///
    /// `argv` holds `argc` C strings.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn cmd_config(argc: c_int, argv: *const *const c_char) -> c_int {
        // SAFETY: the caller passes the command line.
        unsafe { super::config(words(argc, argv)) }
    }
}
