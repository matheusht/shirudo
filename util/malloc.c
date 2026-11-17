// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * xasprintf() of the zeroing allocator (see util/malloc.h). The rest of
 * it is in rust/src/heap.rs; a C-variadic function is C's to define.
 */

#include <stdarg.h>
#include <stdio.h>

/* xasprintf() formats with vsnprintf(), which <shirudo/string.h> poisons. */
#define STRING_INTERNAL
#include <shirudo/string.h>

#include "malloc.h"

char *xasprintf(const char *fmt, ...)
{
	va_list ap;
	char *p;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(NULL, 0, fmt, ap);
	va_end(ap);
	if (n < 0)
		return NULL;
	p = xmalloc((size_t)n + 1);
	if (!p)
		return NULL;
	va_start(ap, fmt);
	vsnprintf(p, (size_t)n + 1, fmt, ap);
	va_end(ap);
	return p;
}
