/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The user side of the map serializer, which rust/src/util/serializer.rs
 * implements.
 */

#ifndef SHIRUDO_UTIL_SERIALIZER_H
#define SHIRUDO_UTIL_SERIALIZER_H

#include <shirudo/misc.h>

#include "bpf/lib/serializer.h"

int serializer_lock_acquire(__u32 map_id);
int serializer_lock_acquire_at(const char *dir, __u32 map_id);
int serializer_new_invocation_id(__u64 *out);

int serial_chunk_validate(const struct serial_chunk *chunk,
			  __u32 want_index,
			  __u32 total_chunks,
			  __u32 page_index,
			  __u64 cursor,
			  __u64 next_cursor,
			  __u64 invocation_id);

#endif /* SHIRUDO_UTIL_SERIALIZER_H */
