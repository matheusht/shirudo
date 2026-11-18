// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * bpm_build_parse_beefile() on a Beefile, which bpm build reads from the
 * package context the operator gives it. Of a Beefile it takes, the fixes
 * of each tree entry must be what the publisher emits, valid IDs in byte
 * order, each once, which the function checks, aborting where not.
 */

#include <stddef.h>

#include "fuzz.h"
#include "tools/shirudo-build/bpm.h"

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	bpm_build_parse_beefile(data, size);
	return 0;
}
