// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What an OTLP collector answers, the response header lines and the
 * partial-success body, the decoded map JSON a log record carries, and
 * the configured OTEL_EXPORTER_OTLP_HEADERS.
 */

#include "fuzz.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>

#include "json.h"
#include "malloc.h"
#include "upatch_maps_otel.h"

static const struct json_visitor any_value = {};

static size_t deepest_nesting(const char *s, size_t len)
{
	size_t depth = 0, deepest = 0, i;
	bool in_string = false;

	for (i = 0; i < len; i++) {
		if (in_string) {
			if (s[i] == '\\')
				i++;
			else if (s[i] == '"')
				in_string = false;
		} else if (s[i] == '"') {
			in_string = true;
		} else if (s[i] == '{' || s[i] == '[') {
			if (++depth > deepest)
				deepest = depth;
		} else if ((s[i] == '}' || s[i] == ']') && depth) {
			depth--;
		}
	}
	return deepest;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct curl_slist *headers = NULL;
	__u64 seconds;
	size_t off, n;
	char *body, *line;
	int ret;

	/*
	 * curl hands the header callback one line at a time, end included
	 * and not NUL-terminated: each line in a buffer of its own size.
	 */
	for (off = 0; off < size; off += n) {
		const __u8 *nl = memchr(data + off, '\n', size - off);

		n = nl ? (size_t)(nl - data) - off + 1 : size - off;
		line = xmalloc(n);
		if (!line)
			return 0;
		memcpy(line, data + off, n);
		if (otel_header_retry_after(line, n, &seconds) && seconds > 30)
			abort();
		xfree(line, n);
	}

	body = xmalloc(size + 1);
	if (!body)
		return 0;
	memcpy(body, data, size);
	body[size] = '\0';
	otel_partial_success(OTEL_LOG, body, size);
	otel_partial_success(OTEL_METRIC, body, size);

	if (!memchr(data, '\0', size)) {
		if (!otel_configured_headers(body, &headers)) {
			for (struct curl_slist *h = headers; h; h = h->next) {
				char *colon = strchr(h->data, ':');
				bool ok;

				if (!colon)
					abort();
				*colon = '\0';
				ok = otel_header_name_ok(h->data) &&
				     otel_header_value_ok(colon + 1);
				*colon = ':';
				if (!ok)
					abort();
			}
		}
		curl_slist_free_all(headers);
	}
	xfree(body, size + 1);
	return 0;
}
