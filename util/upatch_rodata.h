/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Read the signed .rodata initial value from a gen_loader upatch, which
 * rust/src/util/upatch_rodata.rs implements.
 */

#ifndef SHIRUDO_UTIL_UPATCH_RODATA_H
#define SHIRUDO_UTIL_UPATCH_RODATA_H

#include <stdbool.h>

#include "upatch.h"

struct rodata_range {
	__u32 offset;
	__u32 size;
};

int upatch_rodata_print(const struct upatch *u, const char *path,
			bool json);
int upatch_rodata_symbol_range(const struct upatch *u,
			       const char *symbol,
			       struct rodata_range *range);
int upatch_rodata_data_offset(const struct upatch *u, __u32 *offset);

struct btf;

/*
 * For the unit test: the name the text output gives type id, appended at
 * *off of the cap bytes at buf, and the walk that guards libbpf's dumper,
 * with a cost for each type of btf.
 */
struct rodata_dump_cost {
	__u32 values;
	__u32 height;
};

int upatch_rodata_type_name(const struct btf *btf, __u32 id, char *buf,
			    size_t cap, size_t *off, __u32 depth);
int upatch_rodata_dump_cost(const struct btf *btf, __u32 id, __u32 depth,
			    struct rodata_dump_cost *cost);

#endif /* SHIRUDO_UTIL_UPATCH_RODATA_H */
