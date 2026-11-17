// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/*
 * Lists what the light skeletons of bpf2 and the seal built into shirudo
 * load: their maps, their programs and the kernel symbols their loaders
 * resolve, read from the format of rust/src/bpf/lskel.rs.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "util/loader.h"

#define LSKEL_HEADER 40

static uint32_t le32(const unsigned char *p)
{
	return p[0] | p[1] << 8 | p[2] << 16 | (uint32_t)p[3] << 24;
}

/* The NUL-terminated name at *p, before end; *p moves past it. */
static const char *next_name(const unsigned char **p, const unsigned char *end)
{
	const unsigned char *nul = memchr(*p, 0, end - *p);
	const char *name = (const char *)*p;

	if (!nul)
		return NULL;
	*p = nul + 1;
	return name;
}

static int list(const char *kind, const char *selection, uint32_t n,
		size_t skip, const unsigned char **p, const unsigned char *end)
{
	const char *name;
	uint32_t i;

	for (i = 0; i < n; i++) {
		if ((size_t)(end - *p) < skip)
			return 1;
		*p += skip;
		name = next_name(p, end);
		if (!name)
			return 1;
		printf("%s %s %s\n", kind, selection, name);
	}
	return 0;
}

static int inspect(const char *selection, const struct embedded_bpf *blob)
{
	const unsigned char *b = blob->data, *p, *end;
	uint32_t names_len;

	if (!b || blob->size < LSKEL_HEADER || memcmp(b, "SHLSKEL1", 8))
		return 1;
	names_len = le32(b + 28);
	if (names_len > blob->size - LSKEL_HEADER)
		return 1;
	p = b + LSKEL_HEADER;
	end = p + names_len;
	printf("blob %s %s\n", selection, blob->name);
	/* Each program's type and attach type come before its name. */
	return list("map", selection, le32(b + 8), 0, &p, end) ||
	       list("program", selection, le32(b + 12), 8, &p, end) ||
	       list("extern", selection, le32(b + 16), 0, &p, end);
}

int main(void)
{
	return inspect("admission", bpf2_blob()) ||
	       inspect("seal", seal_blob());
}
