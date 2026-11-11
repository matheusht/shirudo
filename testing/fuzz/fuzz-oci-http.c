// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * What a registry and its token server answer: the header lines, the
 * challenge and upload location taken from them, and the token.
 */

#include <limits.h>
#include <string.h>

#include "bpm_oci.h"
#include "fuzz.h"
#include "malloc.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	char realm[PATH_MAX] = {}, service[256] = {}, scope[512] = {};
	struct bpm_http_response r = {};
	struct bpm_oci_client c = {};
	char upload[PATH_MAX], *body;
	size_t off, n;

	/* curl hands the header callback one line at a time, end included. */
	for (off = 0; off < size; off += n) {
		const __u8 *nl = memchr(data + off, '\n', size - off);

		n = nl ? (size_t)(nl - data) - off + 1 : size - off;
		bpm_oci_header((void *)(data + off), 1, n, &r);
	}
	bpm_oci_parse_challenge(r.www_auth, realm, sizeof(realm), service,
				sizeof(service), scope, sizeof(scope));
	bpm_copy_string(c.base_url, sizeof(c.base_url),
			"https://registry.example:5000");
	bpm_oci_upload_location(&c, r.location, upload, sizeof(upload));

	body = xmalloc(size + 1);
	if (!body)
		return 0;
	memcpy(body, data, size);
	body[size] = '\0';
	bpm_oci_token_from_body(body, c.token, sizeof(c.token));
	xfree(body, size + 1);
	return 0;
}
