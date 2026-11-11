/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The running kernel's build ID, which rust/src/util/kernel_build_id.rs
 * implements.
 */

#ifndef SHIRUDO_KERNEL_BUILD_ID_H
#define SHIRUDO_KERNEL_BUILD_ID_H

#include <stddef.h>

#define KERNEL_BUILD_ID_MAX 64u
#define KERNEL_BUILD_ID_STRING_MAX \
	(KERNEL_BUILD_ID_MAX * 2u + 1u)

int kernel_build_id_from_notes(const void *notes, size_t notes_len,
			       char out[KERNEL_BUILD_ID_STRING_MAX]);

int kernel_build_id_read(char out[KERNEL_BUILD_ID_STRING_MAX]);

#endif /* SHIRUDO_KERNEL_BUILD_ID_H */
