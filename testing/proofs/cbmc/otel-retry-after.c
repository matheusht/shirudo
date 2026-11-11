// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The Retry-After parser of util/upatch_maps_otel.c on every header line
 * of up to LEN bytes and every value it holds: a delay of digits is read
 * exactly, up to 30 seconds, and whatever date strptime() makes of the
 * rest, the wait is at most 30 seconds and nothing past the line is read.
 * A LEN past 32 runs a line as long as the copy of its value instead.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/upatch_maps_otel.c"

#define YEAR_10000	253402300800LL
#define YEAR_0		(-62167219200LL)

/* Any prefix of the date taken, or none, into any broken-down time. */
char *strptime(const char *s, const char *format, struct tm *tm)
{
	bool fails;
	size_t n;

	__CPROVER_assume(n <= strlen(s));
	return fails ? NULL : (char *)s + n;
}

/* Any time the four-digit years of strptime() reach, or -1. */
time_t timegm(struct tm *tm)
{
	time_t t;

	__CPROVER_assume(t >= YEAR_0 && t < YEAR_10000);
	return t;
}

/* Now, before the year 10000, or -1 for a clock it cannot read. */
time_t time(time_t *out)
{
	time_t t;

	__CPROVER_assume(t >= -1 && t < YEAR_10000);
	if (out)
		*out = t;
	return t;
}

static void delay(void)
{
	__u64 seconds = 31, want = 0;
	size_t len, i;
	bool digits;
	time_t now;
	char *s;
	int ret;

	s = any_bytes(LEN + 1);
	s[LEN] = '\0';
	len = strlen(s);
	__CPROVER_assume(now >= -1 && now < YEAR_10000);
	digits = len;
	for (i = 0; i < len; i++) {
		digits = digits && s[i] >= '0' && s[i] <= '9';
		if (digits)
			want = min(want * 10 + s[i] - '0', 31U);
	}
	ret = otel_retry_after(s, now, &seconds);
	__CPROVER_assert(!ret || ret == -EINVAL,
			 "a delay, a date or -EINVAL");
	__CPROVER_assert(len || ret == -EINVAL, "no empty value");
	__CPROVER_assert(ret || seconds <= 30, "at most 30 seconds");
	if (digits)
		__CPROVER_assert(!ret && seconds == min(want, 30U),
				 "the delay given");
	__CPROVER_assert(otel_retry_after(NULL, now, &seconds) == -EINVAL,
			 "a value needed");
}

static void header_line(void)
{
	struct otel_response *r;
	char *line;
	size_t n;

	r = any_bytes(sizeof(*r));
	r->retry_after_valid = false;
	line = any_bytes(LEN);
	__CPROVER_assume(n <= LEN);
	__CPROVER_assert(response_header(line, 1, n, r) == n,
			 "the whole line taken");
	__CPROVER_assert(!r->retry_after_valid || r->retry_after <= 30,
			 "a wait of at most 30 seconds");
}

/*
 * A line whose value is cut to about the 128 bytes the callback copies it
 * into: the name, two bytes of any value, digits, and three bytes of any
 * value at the end, so that the blanks trimmed off leave 122 to 130.
 */
static void long_line(void)
{
	static const char name[] = "Retry-After:";
	struct otel_response *r;
	size_t n, i;
	char *line;

	r = any_bytes(sizeof(*r));
	r->retry_after_valid = false;
	line = any_bytes(LEN);
	memcpy(line, name, sizeof(name) - 1);
	for (i = sizeof(name) + 1; i < LEN - 3; i++)
		line[i] = '7';
	__CPROVER_assume(n >= LEN - 3 && n <= LEN);
	__CPROVER_assert(response_header(line, 1, n, r) == n,
			 "the whole line taken");
	__CPROVER_assert(!r->retry_after_valid || r->retry_after <= 30,
			 "a wait of at most 30 seconds");
}

void harness(void)
{
	if (LEN > 32) {
		long_line();
		return;
	}
	delay();
	header_line();
}
