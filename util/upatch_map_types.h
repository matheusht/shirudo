/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Shared BPF map type labels and generic-read policy for upatch map views.
 */

#ifndef SHIRUDO_UTIL_UPATCH_MAP_TYPES_H
#define SHIRUDO_UTIL_UPATCH_MAP_TYPES_H

#include <linux/bpf.h>

#include <shirudo/misc.h>

/* In rust/src/util/map_read.rs: the name BPF_MAP_TYPE_* type goes by. */
const char *map_type_name(__u32 type);
/* Why a map of the type is not read generically, or NULL when it is. */
const char *map_skip_reason(__u32 type);

#endif /* SHIRUDO_UTIL_UPATCH_MAP_TYPES_H */
