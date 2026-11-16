/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Subcommand entry points dispatched from shirudo.c, each in its
 * builtin-<command>.c or, for build, config, genkey and version, in
 * rust/src/builtin/<command>.rs.
 */

#ifndef SHIRUDO_BUILTIN_H
#define SHIRUDO_BUILTIN_H

#include <stdbool.h>

/* Operator-side. */
int cmd_genkey(int argc, const char **argv);
int cmd_build(int argc, const char **argv);

/*
 * The operator package's helper: whether it is there, and the one exec
 * site, which returns only on failure.
 */
bool build_available(void);
int build_exec(const char *label, const char **argv);
/*
 * Run shirudo-build with words, up to their NULL, and then the argc
 * arguments at argv: the operator half of a command shirudo dispatches.
 */
int build_forward(const char *label, const char *const words[], int argc,
		  const char **argv);

/* Target-side. */
int cmd_init(int argc, const char **argv);
int cmd_upatch(int argc, const char **argv);
int cmd_bpm(int argc, const char **argv);
/*
 * For the image CLI test, which reached these by including builtin-bpm.c:
 * the key file of registered source name, open as `bpm repo update`
 * opens it to verify an index, or -errno; and the certificate `bpm tree
 * sync` verifies publications against.
 */
int bpm_source_key_open(const char *name);
const char *bpm_tree_certificate(void);

/* Either-side. */
int cmd_status(int argc, const char **argv);
int cmd_attest(int argc, const char **argv);
int cmd_version(int argc, const char **argv);
int cmd_keys(int argc, const char **argv);
int cmd_config(int argc, const char **argv);
int cmd_image(int argc, const char **argv);

#endif /* SHIRUDO_BUILTIN_H */
