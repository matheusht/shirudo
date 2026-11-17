/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Where a loaded upatch attaches, from its pins.
 */

#ifndef SHIRUDO_UTIL_UPATCH_RESOLVE_H
#define SHIRUDO_UTIL_UPATCH_RESOLVE_H

#include <stddef.h>

struct btf;

#define UPATCH_LOCATION_MAX	160

/*
 * The SEC()-style hook upatch name attaches to, as a C string into the
 * cap bytes at out: 0 or -errno. vbtf may be NULL; the location then
 * degrades to the bare prefix. In rust/src/util/upatch_resolve.rs.
 */
int upatch_resolve_location(struct btf *vbtf, const char *name,
			    char *out, size_t cap);

#endif /* SHIRUDO_UTIL_UPATCH_RESOLVE_H */
