// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_build_parse_beefile() on a Beefile, which bpm build reads from the
 * package source and bpm tree append from a package archive.
 */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "fuzz.h"
#include "malloc.h"
#include "tools/shirudo-build/bpm.h"
#include "tools/shirudo-build/compile.h"
#include "tools/shirudo-build/package.h"
#include "tools/shirudo-build/vmlinux.h"
#include "util/loader.h"

/* What bpm build does with a parsed Beefile is out of reach from here. */
int build_bpm_push(int argc, const char **argv)
{
	return -ENOSYS;
}

int build_bpm_tree(int argc, const char **argv)
{
	return -ENOSYS;
}

const struct embedded_bpf *unload_blob(void)
{
	return NULL;
}

#define FIX_ID_BYTES \
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:-"

/* The publisher emits fixes as parsed: valid IDs in byte order, each once. */
static void check_fixes(const struct bpm_fixes *fixes)
{
	if (fixes->n < 0 || fixes->n > BPM_BUILD_MAX_FIXES)
		abort();
	for (int i = 0; i < fixes->n; i++) {
		const char *id = fixes->ids[i];

		if (!id[0])
			abort();
		for (const char *p = id; *p; p++)
			if (!strchr(FIX_ID_BYTES, *p))
				abort();
		if (i && strcmp(fixes->ids[i - 1], id) >= 0)
			abort();
	}
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct bpm_build_spec *spec = xcalloc(1, sizeof(*spec));

	if (!spec)
		return 0;
	if (!bpm_build_parse_beefile(data, size, spec)) {
		for (size_t i = 0; i < spec->n_upatches; i++)
			check_fixes(&spec->upatches[i].tree.fixes);
	}
	bpm_build_spec_free(spec);
	return 0;
}
