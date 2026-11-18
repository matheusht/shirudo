/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Where a loaded upatch attaches, from its pins.
 */

#ifndef SHIRUDO_UTIL_UPATCH_RESOLVE_H
#define SHIRUDO_UTIL_UPATCH_RESOLVE_H

#include <stddef.h>

#include <shirudo/types.h>

struct bpf_link_info;

#define UPATCH_LOCATION_MAX	160

/*
 * As upatch_each_link(), with what the kernel says of each link; a link
 * whose pin cannot be opened or read ends the walk with its -errno.
 */
int upatch_each_link_info(const char *name,
			  int (*cb)(__u32 index, const char *pin,
				    const struct bpf_link_info *info, void *ctx),
			  void *ctx);

/* From the first link, or from an XDP program pin when it has none. */
int upatch_first_prog_id(const char *name, __u32 *out);

#endif /* SHIRUDO_UTIL_UPATCH_RESOLVE_H */
