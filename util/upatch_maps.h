/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The pinned maps of loaded upatches, for `upatch map` and status.
 * Arena maps are read through the upatch's serializer alone.
 */

#ifndef SHIRUDO_UTIL_UPATCH_MAPS_H
#define SHIRUDO_UTIL_UPATCH_MAPS_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>
#include <shirudo/upatch.h>

#include "upatch_resolve.h"

/* Default truncation cap; --show-full lifts it. */
#define MAP_ENTRIES_DEFAULT	256

#define MAP_NAME_MAX		16	/* BPF_OBJ_NAME_LEN */
#define MAP_TYPENAME_MAX	64

struct json_emit;

struct map_entry {
	void		*key;		/* key_size bytes */
	void		*value;		/* value_stride * (per-CPU ? n_cpus : 1) */
};

/*
 * MAP_TYPEDEF_MAX bounds the multi-line struct/array
 * "definition" string captured at read time (struct foo { __u32 a; ... }).
 * Big enough for the common shirudo case (~10 fields); structs larger
 * than this are truncated with "; ..." and the renderer still works.
 */
#define MAP_TYPEDEF_MAX		1024

struct shirudo_btf;

struct serial_page {
	__u32		page_index;
	__u64		cursor;
	__u64		next_cursor;
	__u32		flags;
	__u32		chunks;
	__u32		bytes;
	bool		done;
	void		*data;
};

struct map_view {
	char		upatch[UPATCH_NAME_MAX + 1];
	char		name[MAP_NAME_MAX + 1];
	char		location[UPATCH_LOCATION_MAX];
	__u32		type;		/* BPF_MAP_TYPE_* */
	const char	*type_name;	/* "percpu_array" / "hash" / ... */
	__u32		key_size;
	__u32		value_size;	/* per-CPU value size (not multiplied) */
	__u32		value_stride;	/* per-CPU kernel ABI stride; else value_size */
	__u32		max_entries;
	__u32		n_entries;	/* live entries iterated */
	__u32		n_cpus;		/* 1 for non-percpu types */
	__u64		lifetime_start_ns; /* pin-dir ctime; metric reset boundary */
	bool		has_payload;	/* the pin directory's payload digest */
	__u8		payload[UPATCH_PAYLOAD_HASH_LEN];
	bool		truncated;
	__u32		n_truncated_at;
	bool		serialized;
	__u32		n_serial_pages;
	__u64		serial_bytes_total;
	struct serial_page *serial_pages;
	bool		skipped;
	const char	*skipped_reason;
	char		btf_key_type[MAP_TYPENAME_MAX];
	char		btf_value_type[MAP_TYPENAME_MAX];
	char		key_type_def[MAP_TYPEDEF_MAX];
	char		value_type_def[MAP_TYPEDEF_MAX];
	__u32		key_type_id;
	__u32		value_type_id;
	struct shirudo_btf *btf;	/* heap; owned by the view */
	struct map_entry	*entries;	/* n_entries long */
	size_t		entries_cap;
};

/* Name, type and max_entries alone, without reading entries. */
struct map_summary {
	char		upatch[UPATCH_NAME_MAX + 1];
	char		name[MAP_NAME_MAX + 1];
	__u32		type;
	const char	*type_name;
	__u32		max_entries;
	__u32		n_cpus;
};

/*
 * A read, in rust/src/util/map_read.rs, takes MAP_ENTRIES_DEFAULT
 * entries, or all for --show-full. It drains a serializer, as the
 * map-export timer expects; MAP_READ_PEEK asks for the interval being
 * collected without taking it from the exporter.
 */
#define MAP_READ_PEEK	(1u << 0)

/* In rust/src/util/map_render.rs. */
void upatch_maps_print_summary(const struct map_summary *list,
			       size_t n);
void upatch_maps_print_detail(const struct map_view *v);

/* NULL v emits nothing. The shape is part of the status report. */
void upatch_maps_emit_json_fields(struct json_emit *e,
				  const struct map_view *v);
void upatch_maps_emit_json_object(struct json_emit *e,
				  const struct map_view *v);

bool upatch_map_is_percpu(__u32 type);

__u32 upatch_map_value_stride(const struct map_view *v);
char *upatch_map_format_cell(const struct map_view *v,
			     __u32 type_id, const void *value,
			     __u32 value_size,
			     const char *btf_type);
char *upatch_map_format_percpu_sum(const struct map_view *v,
				   const void *values_per_cpu,
				   const char *btf_type);

/*
 * For the fuzzer: the page the reader takes from output map fd of
 * max_entries chunks for page_index at cursor of invocation_id, into
 * out, its data for xfree(data, bytes): 0 or -errno.
 */
int upatch_maps_read_serial_page(int fd, __u32 max_entries, __u32 page_index,
				 __u64 cursor, __u64 invocation_id,
				 struct serial_page *out);

#endif /* SHIRUDO_UTIL_UPATCH_MAPS_H */
