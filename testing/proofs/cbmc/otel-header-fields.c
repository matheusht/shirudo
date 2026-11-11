// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The header field checks of util/upatch_maps_otel.c on every string of up
 * to LEN bytes: a name is a token of RFC 9110, a value holds no control
 * character but tab, and percent-decoding turns each %XX but %00 into its
 * byte in place, refusing any other '%'.
 */

#include "proof.h"
#include "../../../util/malloc.c"
#include "../../../util/string.c"
#include "../../../util/hex.c"
#include "../../../util/upatch_maps_otel.c"

/* RFC 9110, 5.6.2. */
static bool tchar(__u8 c)
{
	switch (c) {
	case '!': case '#': case '$': case '%': case '&': case '\'': case '*':
	case '+': case '-': case '.': case '^': case '_': case '`': case '|':
	case '~':
		return true;
	}
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
	       (c >= 'A' && c <= 'Z');
}

static int hex_value(__u8 c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static void name_and_value(const char *s, size_t len)
{
	bool token = len, field = true;
	size_t i;

	for (i = 0; i < len; i++) {
		token = token && tchar(s[i]);
		field = field && (s[i] == '\t' ||
				  ((__u8)s[i] >= 0x20 && s[i] != 0x7f));
	}
	__CPROVER_assert(header_name_ok(s) == token, "a token");
	__CPROVER_assert(header_value_ok(s) == field,
			 "no control character but tab");
}

static void percent(char *s, size_t len)
{
	size_t i = 0, k = 0;
	char want[LEN + 1];
	bool ok = true;
	int hi, lo;

	while (i < len) {
		if (s[i] != '%') {
			want[k++] = s[i++];
			continue;
		}
		hi = i + 1 < len ? hex_value(s[i + 1]) : -1;
		lo = i + 2 < len ? hex_value(s[i + 2]) : -1;
		if (hi < 0 || lo < 0 || !(hi * 16 + lo)) {
			ok = false;
			break;
		}
		want[k++] = hi * 16 + lo;
		i += 3;
	}
	if (percent_decode(s)) {
		__CPROVER_assert(!ok, "a stray '%' or %00 refused");
		return;
	}
	__CPROVER_assert(ok && !memcmp(s, want, k) && !s[k],
			 "each %XX decoded in place");
}

void harness(void)
{
	size_t len;
	char *s;

	s = any_bytes(LEN + 1);
	s[LEN] = '\0';
	len = strlen(s);
	name_and_value(s, len);
	percent(s, len);
}
