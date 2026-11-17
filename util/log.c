// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * pr_err() and its kin: each formats its message and hands it to
 * log_emit() of rust/src/log.rs, which escapes it and writes it to
 * syslog(3) under LOG_AUTHPRIV and to stderr. A C-variadic function is
 * C's to define.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <syslog.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "log.h"

#define LOG_MSG_MAX	8192

bool log_stream_is(const char *stream, __u64 dev, __u64 ino)
{
	const char *colon;
	__u64 d, i;

	if (!stream)
		return false;
	colon = strchr(stream, ':');
	if (!colon)
		return false;
	return !parse_u64(stream, colon - stream, ~0ULL, &d) &&
	       !parse_u64(colon + 1, strlen(colon + 1), ~0ULL, &i) &&
	       d == dev && i == ino;
}

/* errno as the caller left it, for the -errno it returns after. */
static __printf(2, 0) void emit(int priority, const char *fmt, va_list ap)
{
	char msg[LOG_MSG_MAX];
	int saved_errno = errno;

	if (vstrsprintf(msg, sizeof(msg), fmt, ap) < 0)
		strscpy(msg, fmt, sizeof(msg));
	log_emit(priority, msg);
	errno = saved_errno;
}

#define PR_DEFINE(name, prio)					\
	void name(const char *fmt, ...)				\
	{							\
		va_list ap;					\
		va_start(ap, fmt);				\
		emit((prio), fmt, ap);				\
		va_end(ap);					\
	}

PR_DEFINE(pr_err,   LOG_ERR)
PR_DEFINE(pr_warn,  LOG_WARNING)
PR_DEFINE(pr_info,  LOG_INFO)
PR_DEFINE(pr_audit, LOG_NOTICE)
