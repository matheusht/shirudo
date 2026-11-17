// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A serializer page as map export reassembles it from the chunks of the
 * output map, here read from the input, 4096 bytes a chunk.
 */

#include <errno.h>
#include <string.h>

#include "fuzz.h"

#include "malloc.h"
#include "upatch_maps.h"
#include "bpf/lib/serializer.h"

static const __u8 *chunks;
static size_t chunks_len;

int __wrap_bpf_map_lookup_elem(int fd, const void *key, void *value);

/* The output map the reader looks the page's chunks up in: the input. */
int __wrap_bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	size_t off = (size_t)*(const __u32 *)key *
		     sizeof(struct serial_chunk);
	size_t n;

	(void)fd;
	if (off >= chunks_len) {
		errno = ENOENT;
		return -1;
	}
	n = chunks_len - off;
	if (n > sizeof(struct serial_chunk))
		n = sizeof(struct serial_chunk);
	memset(value, 0, sizeof(struct serial_chunk));
	memcpy(value, chunks + off, n);
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct serial_chunk first = {};
	struct serial_page page;

	chunks = data;
	chunks_len = size;
	/* The page the reader asks for is the one a consistent serializer wrote. */
	memcpy(&first, data, min(size, sizeof(first)));
	if (!upatch_maps_read_serial_page(0, 64, first.page_index, first.cursor,
					  first.invocation_id, &page))
		xfree(page.data, page.bytes);
	return 0;
}
