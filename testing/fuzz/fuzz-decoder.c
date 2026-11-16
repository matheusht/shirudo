// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The map data a signed Lua decoder reads through the host API: a page
 * at a cursor and array entries made of the input, under the kernel-obs
 * decoders and the fixture that reads fixed records.
 */

#include <limits.h>
#include <stdlib.h>

#include "fuzz.h"

#include <shirudo/string.h>

#include "io.h"
#include "json.h"
#include "malloc.h"
#include "upatch.h"
#include "upatch_decode.h"
#include "upatch_maps.h"
#include "bpf/lib/serializer.h"

static const char * const sources[] = {
	"upatches/kernel-obs/decoders/dns.lua",
	"upatches/kernel-obs/decoders/exec.lua",
	"upatches/kernel-obs/decoders/file.lua",
	"upatches/kernel-obs/decoders/listen.lua",
	"upatches/kernel-obs/decoders/net.lua",
	"upatches/kernel-obs/decoders/priv.lua",
	"upatches/kernel-obs/decoders/watch.lua",
	"upatches/kernel-obs/decoders/watch_stat.lua",
	"testing/fixtures/decoders/counters.lua",
};

static struct upatch_decoder_view views[ARRAY_SIZE(sources)];

/*
 * The decoders are read from the tree the target was built from, which
 * the build names: the target itself may be built anywhere, AFL++'s in
 * build/fuzz-afl.
 */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	char path[PATH_MAX];
	size_t len;
	char *src;

	for (size_t i = 0; i < ARRAY_SIZE(sources); i++) {
		if (strsprintf(path, sizeof(path), "%s/%s", FUZZ_SOURCE_TREE,
			       sources[i]) < 0)
			abort();
		if (read_file(path, 1 << 20, &src, &len))
			abort();
		views[i].source = src;
		views[i].source_len = (__u32)len;
		if (strscpy(views[i].source_name, strrchr(sources[i], '/') + 1,
			    sizeof(views[i].source_name)) < 0)
			abort();
		strscpy_literal(views[i].entrypoint, "decode");
	}
	return 0;
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct map_entry entries[32];
	struct upatch_decoder_view *d;
	struct serial_page page = {};
	struct map_view v = {
		.type_name = "array",
		.key_size = 4,
		.value_size = 8,
		.value_stride = 8,
		.n_cpus = 1,
		.max_entries = ARRAY_SIZE(entries),
		.serialized = true,
		.n_serial_pages = 1,
	};
	size_t out_len;
	char *out;

	/* A decoder, the page's cursor and the page. */
	if (size < 9)
		return 0;
	d = &views[data[0] % ARRAY_SIZE(views)];
	memcpy(&page.cursor, data + 1, sizeof(page.cursor));
	data += 9;
	size -= 9;
	/* The longest name, which the decoder gets in its input. */
	memset(v.upatch, 'u', UPATCH_NAME_MAX - 1);
	strscpy_literal(v.name, "fuzz_map");

	page.data = xmalloc(size + 1);
	if (!page.data)
		return 0;
	memcpy(page.data, data, size);
	page.bytes = (__u32)size;
	page.chunks = size ? (__u32)((size - 1) / SERIAL_CHUNK_PAYLOAD + 1) : 1;
	page.done = true;
	v.serial_pages = &page;
	v.serial_bytes_total = size;

	for (v.n_entries = 0; v.n_entries < ARRAY_SIZE(entries) &&
	     (v.n_entries + 1) * 12 <= size; v.n_entries++) {
		entries[v.n_entries].key = (__u8 *)page.data + v.n_entries * 12;
		entries[v.n_entries].value = (__u8 *)page.data +
					     v.n_entries * 12 + 4;
	}
	v.entries = entries;

	if (!upatch_decode_run(d, &v, false, JSON_MAX_BYTES, &out,
			       &out_len))
		xfree(out, out_len + 1);
	if (!upatch_decode_run(d, &v, true, JSON_MAX_BYTES, &out,
			       &out_len))
		xfree(out, out_len + 1);
	xfree(page.data, size + 1);
	return 0;
}
