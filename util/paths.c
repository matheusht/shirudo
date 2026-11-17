// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * path_join() of util/paths.h. The other path helpers are in Rust.
 */

#include <errno.h>

#include <shirudo/string.h>

#include "paths.h"

int path_join(char *out, size_t cap, const char *dir, const char *name)
{
	if (strsprintf(out, cap, "%s/%s", dir, name) >= 0)
		return 0;
	if (cap)
		out[0] = '\0';
	return -ENAMETOOLONG;
}
