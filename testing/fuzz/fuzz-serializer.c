// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * A serializer page as map export reassembles it from the chunks of the
 * output map, here read from the input, 4096 bytes a chunk.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/bpf.h>

#include "fuzz.h"

#include "malloc.h"
#include "upatch_maps.h"
#include "bpf/lib/serializer.h"

static const __u8 *chunks;
static size_t chunks_len;

long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...);

/*
 * The output map the reader looks the page's chunks up in, faked at the
 * bpf() syscall: the input.
 */
long __wrap_syscall(long number, ...)
{
	union bpf_attr *attr;
	size_t off, n;
	va_list ap;
	long a[6];
	int i;

	va_start(ap, number);
	for (i = 0; i < 6; i++)
		a[i] = va_arg(ap, long);
	va_end(ap);
	if (number != SYS_bpf || a[0] != BPF_MAP_LOOKUP_ELEM)
		return __real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
	attr = (union bpf_attr *)a[1];
	off = (size_t)*(const __u32 *)(uintptr_t)attr->key * sizeof(struct serial_chunk);
	if (off >= chunks_len) {
		errno = ENOENT;
		return -1;
	}
	n = chunks_len - off;
	if (n > sizeof(struct serial_chunk))
		n = sizeof(struct serial_chunk);
	memset((void *)(uintptr_t)attr->value, 0, sizeof(struct serial_chunk));
	memcpy((void *)(uintptr_t)attr->value, chunks + off, n);
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
