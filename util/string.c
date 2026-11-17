// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Formatting and the newer span, token and glob helpers. The other
 * helpers of <shirudo/string.h> are in rust/src/text.rs.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

/* Implements the wrappers; opt out of the poison in <shirudo/string.h>. */
#define STRING_INTERNAL
#include <shirudo/string.h>

int span_to_str(char *dst, size_t cap, const void *src, size_t len)
{
	if (memchr(src, '\0', len))
		return -EINVAL;
	if (len >= cap)
		return -E2BIG;
	memmove(dst, src, len);
	dst[len] = '\0';
	return 0;
}

static bool among(char c, const char *set)
{
	for (; *set; set++)
		if (c == *set)
			return true;
	return false;
}

size_t token_next(const char *s, size_t len, const char *delims, size_t *pos,
		  size_t *start)
{
	size_t at = min(*pos, len), n;

	while (at < len && among(s[at], delims))
		at++;
	n = span_until(s + at, len - at, delims);
	*start = at;
	*pos = at + n + (n < len - at);
	return n;
}


static bool name_is_dot_or_dotdot(const char *name, size_t len)
{
	return (len == 1 || len == 2) && name[0] == '.' && name[len - 1] == '.';
}

bool name_glob_match(const char *pattern, const char *name, size_t len)
{
	const char *after_star = NULL;
	size_t i = 0, retry_at = 0;

	if (name_is_dot_or_dotdot(name, len))
		return false;
	while (i < len) {
		if (*pattern == '*') {
			after_star = ++pattern;
			retry_at = i;
		} else if (*pattern == '?' ||
			   (*pattern && *pattern == name[i])) {
			pattern++;
			i++;
		} else if (after_star) {
			pattern = after_star;
			i = ++retry_at;
		} else {
			return false;
		}
	}
	while (*pattern == '*')
		pattern++;
	return !*pattern;
}

int vstrsprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
	int n = vsnprintf(buf, size, fmt, ap);

	if (n >= 0 && (size_t)n < size)
		return n;
	if (size)
		buf[0] = '\0';
	return -E2BIG;
}

int strsprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vstrsprintf(buf, size, fmt, ap);
	va_end(ap);
	return n;
}
