// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo

//! `shirudo config`: the effective shirudo.conf, or without one the
//! defaults in the same syntax, as a template.

use core::ffi::{CStr, c_int};

use crate::errno::{ENOENT, text};
use crate::ffi::c_splice;
use crate::sys::libc::{F_OK, access, env, printf};
use crate::util::config::{CONF_PATH, Scrubbed, load};
use crate::util::help::Help;
use crate::util::image_config;
use crate::util::options::{EXIT_USAGE, OPT_ARG, OPT_DONE, OPT_END, OptParser};

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

static HELP: Help = Help::new(USAGE, Some(SUMMARY), &[], Some(FOOTER));

/// The command on `args`, its name first.
pub(crate) fn cmd_config(args: &[&CStr]) -> c_int {
    let mut cfg = Scrubbed::new();
    let image_mode = image_config::active();

    let mut p = OptParser::new(c"config", &[], Some(&HELP), args, 1);
    match p.next() {
        OPT_END => {}
        OPT_DONE => return 0,
        OPT_ARG => {
            p.usage_arg(b"unexpected argument ");
            return EXIT_USAGE;
        }
        _ => return EXIT_USAGE,
    }

    // SAFETY: a path, and a mode.
    let file_present = unsafe { access(CONF_PATH.as_ptr(), F_OK) } == 0;
    let ret = load(&mut cfg);
    if ret != 0 && ret != -ENOENT {
        crate::log::err(
            &[
                &b"config: load "[..],
                CONF_PATH.to_bytes(),
                b": ",
                text(ret).as_bytes(),
            ]
            .concat(),
        );
        return 1;
    }
    let c = &*cfg;

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
