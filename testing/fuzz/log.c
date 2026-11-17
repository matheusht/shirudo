// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * util/log.c for the fuzz targets: format each message, then drop it.
 */

#include <stdarg.h>
#include <stdio.h>

#include "log.h"

/*
 * A parser rejecting a mutated input logs, millions of times a minute:
 * not to the journal. Formatting still runs, so a message that reads
 * past what it prints is caught.
 */
static __printf(1, 0) void drop(const char *fmt, va_list ap)
{
	char msg[8192];

	vsnprintf(msg, sizeof(msg), fmt, ap);
}

#define PR_DEFINE(name)						\
	void name(const char *fmt, ...)				\
	{							\
		va_list ap;					\
		va_start(ap, fmt);				\
		drop(fmt, ap);					\
		va_end(ap);					\
	}

PR_DEFINE(pr_err)
PR_DEFINE(pr_warn)
PR_DEFINE(pr_info)
PR_DEFINE(pr_audit)
