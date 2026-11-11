/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Compact durations, 12s, 5m, 3h, 7d, and ISO-8601 times, which
 * rust/src/util/timefmt.rs implements.
 */

#ifndef SHIRUDO_TIMEFMT_H
#define SHIRUDO_TIMEFMT_H

#include <stddef.h>
#include <time.h>

#include <shirudo/compiler.h>

/* A negative seconds writes "?"; -E2BIG, buf empty, when it does not fit. */
int format_duration(long seconds, char *buf, size_t cap) __must_check;

/* UTC to the second; "" and -EINVAL when t cannot be rendered. */
int iso8601(time_t t, char *out, size_t cap);

#endif /* SHIRUDO_TIMEFMT_H */
