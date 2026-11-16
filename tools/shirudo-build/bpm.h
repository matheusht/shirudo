/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What C still reaches of shirudo-build, which is Rust in
 * rust/src/shirudo_build/: its command line, for main(), and the Beefile
 * reader, for the fuzzer.
 */

#ifndef SHIRUDO_BUILD_BPM_H
#define SHIRUDO_BUILD_BPM_H

#include <stddef.h>

#include <shirudo/misc.h>

/* The command line, from main(). */
int shirudo_build_main(int argc, char **argv);

/* Whether the len bytes at body are a Beefile bpm build takes: 0 or -errno. */
int bpm_build_parse_beefile(const __u8 *body, size_t len);

#endif /* SHIRUDO_BUILD_BPM_H */
