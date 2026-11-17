// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * upatch_pin_path() and path_join() of util/paths.h. The other path
 * helpers are in rust/src/util/paths.rs.
 */

#include <errno.h>
#include <stdarg.h>

#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "paths.h"

int upatch_pin_path(char *out, size_t cap, const char *name, ...)
{
	char bpffs_name[UPATCH_BPFFS_NAME_MAX + 1];
	const char *part;
	int n, ret = 0;
	size_t len;
	va_list ap;

	if (upatch_bpffs_name(bpffs_name, sizeof(bpffs_name), name))
		goto too_long;
	n = strsprintf(out, cap, "%s/%s", BPFFS_UPATCHES_DIR, bpffs_name);
	if (n < 0)
		goto too_long;
	len = n;
	va_start(ap, name);
	while ((part = va_arg(ap, const char *))) {
		n = strsprintf(out + len, cap - len, "/%s", part);
		if (n < 0) {
			ret = -ENAMETOOLONG;
			break;
		}
		len += n;
	}
	va_end(ap);
	if (!ret)
		return 0;
too_long:
	if (cap)
		out[0] = '\0';
	return -ENAMETOOLONG;
}

int path_join(char *out, size_t cap, const char *dir, const char *name)
{
	if (strsprintf(out, cap, "%s/%s", dir, name) >= 0)
		return 0;
	if (cap)
		out[0] = '\0';
	return -ENAMETOOLONG;
}
