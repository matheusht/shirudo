/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The tamper counters the LSM keeps, read back from their bpffs pin.
 */
#ifndef SHIRUDO_UTIL_TAMPER_H
#define SHIRUDO_UTIL_TAMPER_H

#include <shirudo/misc.h>

#include "bpf/lib/tamper.h"

struct tamper_counts {
	__u64		count[TAMPER_MAX];
	__u64		total;
};

const char *tamper_name(enum tamper_point point);
const char *tamper_meaning(enum tamper_point point);

/*
 * The counters the LSM has kept this boot. -ENOENT when init has not
 * run, -EPROTO when the pinned map is not the shape this binary knows,
 * another -errno when the pin cannot be read.
 */
int tamper_read(struct tamper_counts *out);

/* tamper_read() of the n counters of any such map, pinned at pin. */
int counters_read(const char *pin, __u32 n, __u64 *count, __u64 *total);

#endif /* SHIRUDO_UTIL_TAMPER_H */
