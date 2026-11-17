// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Reader of the pinned upatch maps, generic or through the upatch's
 * serializer.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>
#include <shirudo/upatch.h>

#include "json.h"
#include "hex.h"
#include "malloc.h"
#include "paths.h"
#include "serializer.h"
#include "upatch_map_types.h"
#include "upatch_maps.h"
#include "upatch_resolve.h"
#include "bpf/lib/serializer.h"

/*
 * Per-call recursion bound for the BTF value renderer. Real-world map
 * value structs are flat; nested-struct chains beyond ~4 hops would
 * either be an attacker-crafted BTF or a layout we should not be
 * pretty-printing in a "shirudo upatch get" view.
 */
#define BTF_MAX_DEPTH		6

static void resolve_map_location(struct map_view *v)
{
	struct btf *vbtf;

	if (!v)
		return;
	vbtf = btf__load_vmlinux_btf();
	if (libbpf_get_error(vbtf))
		vbtf = NULL;
	upatch_resolve_location(vbtf, v->upatch,
				v->location, sizeof(v->location));
	btf__free(vbtf);
}

#define SERIAL_MAX_BYTES \
	(SERIAL_MAX_CHUNKS * SERIAL_CHUNK_PAYLOAD)
#define SERIAL_MAX_TOTAL_BYTES \
	((__u64)SERIAL_MAX_PAGES * SERIAL_MAX_BYTES)

static __u32 map_value_stride(__u32 type, __u32 value_size)
{
	if (!upatch_map_is_percpu(type))
		return value_size;
	return (value_size + 7U) & ~7U;
}

static bool is_array_type(__u32 type)
{
	return type == BPF_MAP_TYPE_ARRAY ||
	       type == BPF_MAP_TYPE_PERCPU_ARRAY;
}

static bool is_hash_type(__u32 type)
{
	return type == BPF_MAP_TYPE_HASH ||
	       type == BPF_MAP_TYPE_PERCPU_HASH ||
	       type == BPF_MAP_TYPE_LRU_HASH ||
	       type == BPF_MAP_TYPE_LRU_PERCPU_HASH;
}

/*
 * A lookup of a per-CPU value copies one for every possible CPU, a
 * figure the kernel keeps to itself: sysconf counts the present ones,
 * and the sysfs file libbpf would read is root's to replace in a mount
 * namespace of its own, so either undersizes the buffer the kernel
 * fills. The shortest mask sched_getaffinity accepts is the kernel's
 * own cpumask, nr_cpu_ids bits rounded up, and bounds what a lookup
 * writes.
 */
static int nproc_possible(void)
{
	static int cached;
	__u8 mask[1024];
	size_t len;

	if (cached)
		return cached;
	for (len = 8; len <= sizeof(mask); len *= 2) {
		long n = syscall(__NR_sched_getaffinity, 0, len, mask);

		if (n > 0) {
			cached = (int)(n * 8);
			return cached;
		}
		if (errno != EINVAL)
			return -errno;
	}
	return -E2BIG;
}

static int open_map_pin(const char *upatch, const char *map_name,
			int *fd_out, struct bpf_map_info *info_out)
{
	char path[PATH_MAX];
	__u32 info_len = sizeof(*info_out);
	int fd;

	if (upatch_pin_path(path, sizeof(path), upatch, "maps", map_name, NULL))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(path);
	if (fd < 0)
		return -errno;
	memset(info_out, 0, sizeof(*info_out));
	if (bpf_map_get_info_by_fd(fd, info_out, &info_len)) {
		int e = -errno;

		close(fd);
		return e;
	}
	*fd_out = fd;
	return 0;
}

static struct btf *try_load_btf(__u32 btf_id)
{
	if (!btf_id)
		return NULL;
	return btf__load_from_kernel_by_id(btf_id);
}

static int open_serializer_pin(const char *upatch, const char *map_name)
{
	char path[PATH_MAX];
	int fd;

	if (upatch_pin_path(path, sizeof(path), upatch, "serializers",
			    map_name, NULL))
		return -ENAMETOOLONG;
	fd = bpf_obj_get(path);
	if (fd < 0)
		return -errno;
	return fd;
}

int prog_test_run(int prog_fd, void *ctx, __u32 ctx_sz,
		  __u32 *retval)
{
	union bpf_attr attr = {};
	long ret;

	attr.test.prog_fd = prog_fd;
	attr.test.ctx_in = ptr_to_u64(ctx);
	attr.test.ctx_size_in = ctx_sz;
	ret = syscall(__NR_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
	if (ret < 0)
		return -errno;
	*retval = attr.test.retval;
	return 0;
}

static int validate_serial_map(const struct bpf_map_info *info)
{
	if (info->type != BPF_MAP_TYPE_ARRAY)
		return -EINVAL;
	if (info->key_size != sizeof(__u32))
		return -EINVAL;
	if (info->value_size != sizeof(struct serial_chunk))
		return -EINVAL;
	if (info->max_entries == 0 ||
	    info->max_entries > SERIAL_MAX_CHUNKS)
		return -E2BIG;
	return 0;
}

static int clear_serial_map(int fd, const struct bpf_map_info *info)
{
	void *zero;
	__u32 i;

	zero = xcalloc(1, info->value_size);
	if (!zero)
		return -ENOMEM;
	for (i = 0; i < info->max_entries; i++) {
		if (bpf_map_update_elem(fd, &i, zero, BPF_ANY) != 0) {
			int e = -errno;

			xfree(zero, info->value_size);
			return e;
		}
	}
	xfree(zero, info->value_size);
	return 0;
}

static int append_serial_page(struct map_view *out,
			      struct serial_page *page)
{
	void *p;

	p = xreallocarray(out->serial_pages, out->n_serial_pages,
			  out->n_serial_pages + 1, sizeof(*out->serial_pages));
	if (!p)
		return -ENOMEM;
	out->serial_pages = p;
	out->serial_pages[out->n_serial_pages++] = *page;
	memset(page, 0, sizeof(*page));
	return 0;
}

static int read_serial_page(int serial_fd,
			    const struct bpf_map_info *serial_info,
			    __u32 want_page_index, __u64 want_cursor,
			    __u64 invocation_id,
			    struct serial_page *page)
{
	struct serial_chunk *chunk;
	__u32 key, total_chunks, bytes_total, copied = 0;
	__u32 page_index, flags;
	__u64 cursor, next_cursor;
	__u8 *data = NULL;
	int ret;

	chunk = xmalloc(sizeof(*chunk));
	if (!chunk)
		return -ENOMEM;
	key = 0;
	if (bpf_map_lookup_elem(serial_fd, &key, chunk) != 0) {
		ret = -errno;
		goto out_chunk;
	}
	if (chunk->magic != SERIAL_MAGIC ||
	    chunk->version != SERIAL_VERSION ||
	    chunk->invocation_id != invocation_id) {
		ret = -EBADMSG;
		goto out_chunk;
	}
	if (chunk->status != 0) {
		ret = chunk->status < 0 ? chunk->status : -EIO;
		goto out_chunk;
	}
	total_chunks = chunk->total_chunks;
	bytes_total = chunk->bytes_total;
	page_index = chunk->page_index;
	cursor = chunk->cursor;
	next_cursor = chunk->next_cursor;
	flags = chunk->flags;
	if (total_chunks == 0 || total_chunks > serial_info->max_entries ||
	    total_chunks > SERIAL_MAX_CHUNKS ||
	    bytes_total > SERIAL_MAX_BYTES ||
	    bytes_total > total_chunks * SERIAL_CHUNK_PAYLOAD) {
		ret = -EBADMSG;
		goto out_chunk;
	}
	if (page_index != want_page_index || cursor != want_cursor ||
	    next_cursor < cursor) {
		ret = -EBADMSG;
		goto out_chunk;
	}
	data = bytes_total ? xmalloc(bytes_total) : NULL;
	if (bytes_total && !data) {
		ret = -ENOMEM;
		goto out_chunk;
	}
	for (key = 0; key < total_chunks; key++) {
		if (key != 0 &&
		    bpf_map_lookup_elem(serial_fd, &key, chunk) != 0) {
			ret = -errno;
			goto out_data;
		}
		ret = serial_chunk_validate(chunk, key, total_chunks,
					    page_index, cursor,
					    next_cursor, invocation_id);
		if (ret)
			goto out_data;
		if (chunk->status != 0) {
			ret = chunk->status < 0 ? chunk->status : -EIO;
			goto out_data;
		}
		if (chunk->bytes_total != bytes_total ||
		    copied + chunk->bytes_in_chunk > bytes_total) {
			ret = -EBADMSG;
			goto out_data;
		}
		if (chunk->bytes_in_chunk)
			memcpy(data + copied, chunk->data,
			       chunk->bytes_in_chunk);
		copied += chunk->bytes_in_chunk;
	}
	if (copied != bytes_total) {
		ret = -EBADMSG;
		goto out_data;
	}

	memset(page, 0, sizeof(*page));
	page->page_index = page_index;
	page->cursor = cursor;
	page->next_cursor = next_cursor;
	page->flags = flags;
	page->chunks = total_chunks;
	page->bytes = bytes_total;
	page->done = (page->flags & SERIAL_F_DONE) != 0;
	page->data = data;
	xfree(chunk, sizeof(*chunk));
	return 0;

out_data:
	xfree(data, bytes_total);
out_chunk:
	xfree(chunk, sizeof(*chunk));
	return ret;
}

static int try_read_serialized(const char *upatch, const char *map,
			       __u32 flags, struct map_view *out)
{
	struct bpf_map_info serial_info = {};
	__u64 cursor = 0, bytes_total = 0, invocation_id;
	__u32 page_index;
	int prog_fd = -1, serial_fd = -1, lock_fd = -1, ret;

	if (strcmp(map, SERIAL_MAP_NAME) == 0)
		return 0;
	prog_fd = open_serializer_pin(upatch, map);
	if (prog_fd < 0) {
		if (prog_fd == -ENOENT)
			return 0;
		return prog_fd;
	}
	ret = open_map_pin(upatch, SERIAL_MAP_NAME,
			   &serial_fd, &serial_info);
	if (ret)
		goto out;
	ret = validate_serial_map(&serial_info);
	if (ret)
		goto out;
	/*
	 * Clearing, running and reading are one transaction. Key the lock by
	 * the kernel map ID so every process sharing this exact output map
	 * contends, while unrelated upatches remain independent.
	 */
	lock_fd = serializer_lock_acquire(serial_info.id);
	if (lock_fd < 0) {
		ret = lock_fd;
		lock_fd = -1;
		goto out;
	}
	ret = serializer_new_invocation_id(&invocation_id);
	if (ret)
		goto out;

	for (page_index = 0; page_index < SERIAL_MAX_PAGES;
	     page_index++) {
		struct serialize_ctx ctx = {};
		struct serial_page page = {};
		__u32 retval = 0;

		ret = clear_serial_map(serial_fd, &serial_info);
		if (ret)
			goto out;

		ctx.magic = SERIAL_MAGIC;
		ctx.version = SERIAL_VERSION;
		ctx.flags = (flags & MAP_READ_PEEK) ?
			    SERIAL_CTX_F_PEEK : 0;
		ctx.max_chunks = serial_info.max_entries;
		ctx.chunk_payload_size = SERIAL_CHUNK_PAYLOAD;
		ctx.page_index = page_index;
		ctx.cursor = cursor;
		ctx.invocation_id = invocation_id;

		ret = prog_test_run(prog_fd, &ctx, sizeof(ctx), &retval);
		if (ret)
			goto out;
		if ((__s32)retval < 0) {
			ret = (__s32)retval;
			goto out;
		}
		if (ctx.magic != SERIAL_MAGIC ||
		    ctx.version != SERIAL_VERSION ||
		    ctx.page_index != page_index ||
		    ctx.cursor != cursor ||
		    ctx.invocation_id != invocation_id) {
			ret = -EBADMSG;
			goto out;
		}

		ret = read_serial_page(serial_fd, &serial_info, page_index,
				       cursor, invocation_id, &page);
		if (ret)
			goto out;
		if (bytes_total + page.bytes > SERIAL_MAX_TOTAL_BYTES) {
			xfree(page.data, page.bytes);
			ret = -E2BIG;
			goto out;
		}
		bytes_total += page.bytes;
		ret = append_serial_page(out, &page);
		if (ret) {
			xfree(page.data, page.bytes);
			goto out;
		}

		page = out->serial_pages[out->n_serial_pages - 1];
		if (page.done)
			break;
		if (page.next_cursor == cursor) {
			ret = -EBADMSG;
			goto out;
		}
		cursor = page.next_cursor;
	}
	if (out->n_serial_pages == 0 ||
	    !out->serial_pages[out->n_serial_pages - 1].done) {
		ret = -E2BIG;
		goto out;
	}

	out->serialized = true;
	out->serial_bytes_total = bytes_total;
	close(lock_fd);
	close(serial_fd);
	close(prog_fd);
	return 1;

out:
	if (ret < 0 && out->serial_pages) {
		__u32 i;

		for (i = 0; i < out->n_serial_pages; i++)
			xfree(out->serial_pages[i].data,
			      out->serial_pages[i].bytes);
		xfree(out->serial_pages,
		      out->n_serial_pages * sizeof(*out->serial_pages));
		out->serial_pages = NULL;
		out->n_serial_pages = 0;
		out->serial_bytes_total = 0;
	}
	if (serial_fd >= 0)
		close(serial_fd);
	if (lock_fd >= 0)
		close(lock_fd);
	if (prog_fd >= 0)
		close(prog_fd);
	return ret;
}

static int read_entries(int fd, struct map_view *v,
			__u32 cap)
{
	size_t value_count = upatch_map_is_percpu(v->type) ?
		v->n_cpus : 1;
	size_t value_alloc;
	__u32 i;
	int err;

	if (check_mul_overflow(upatch_map_value_stride(v), value_count,
			       &value_alloc))
		return -EOVERFLOW;

	v->entries = NULL;
	v->n_entries = 0;
	v->truncated = false;
	v->n_truncated_at = cap;

	if (is_array_type(v->type)) {
		__u32 take = v->max_entries;

		if (cap && take > cap) {
			take = cap;
			v->truncated = (v->max_entries > cap);
		}
		if (take == 0)
			return 0;
		v->entries = xcalloc(take, sizeof(*v->entries));
		v->entries_cap = take;
		if (!v->entries)
			return -ENOMEM;
		for (i = 0; i < take; i++) {
			void *key = xmalloc(v->key_size);
			void *value = xmalloc(value_alloc);

			if (!key || !value) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				return -ENOMEM;
			}
			memcpy(key, &i, min(v->key_size, sizeof(i)));
			if (v->key_size > sizeof(i))
				memset((char *)key + sizeof(i), 0,
				       v->key_size - sizeof(i));
			err = bpf_map_lookup_elem(fd, key, value);
			if (err) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				continue;	/* hole; rare for ARRAY */
			}
			v->entries[v->n_entries].key = key;
			v->entries[v->n_entries].value = value;
			v->n_entries++;
		}
		return 0;
	}
	if (is_hash_type(v->type)) {
		void *prev_key = NULL;
		void *next_key;
		v->entries_cap = 32;
		v->entries = xcalloc(v->entries_cap, sizeof(*v->entries));
		if (!v->entries)
			return -ENOMEM;
		next_key = xmalloc(v->key_size);
		if (!next_key)
			return -ENOMEM;
		while (bpf_map_get_next_key(fd, prev_key, next_key) == 0) {
			void *key = xmalloc(v->key_size);
			void *value = xmalloc(value_alloc);

			if (!key || !value) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				break;
			}
			memcpy(key, next_key, v->key_size);
			if (bpf_map_lookup_elem(fd, key, value) != 0) {
				xfree(key, v->key_size);
				xfree(value, value_alloc);
				prev_key = next_key;
				continue;
			}
			if (v->n_entries == v->entries_cap) {
				void *p = xreallocarray(v->entries,
							v->entries_cap,
							v->entries_cap * 2,
							sizeof(*v->entries));
				if (!p) {
					xfree(key, v->key_size);
					xfree(value, value_alloc);
					break;
				}
				v->entries = p;
				memset((char *)v->entries +
				       v->entries_cap * sizeof(*v->entries),
				       0, v->entries_cap * sizeof(*v->entries));
				v->entries_cap *= 2;
			}
			v->entries[v->n_entries].key = key;
			v->entries[v->n_entries].value = value;
			v->n_entries++;
			if (cap && v->n_entries >= cap) {
				v->truncated = true;
				break;
			}
			prev_key = next_key;
		}
		xfree(next_key, v->key_size);
		return 0;
	}
	return -EOPNOTSUPP;
}

void map_view_free(struct map_view *v)
{
	size_t value_alloc;
	__u32 i;

	if (!v)
		return;
	if (v->entries) {
		value_alloc = (size_t)upatch_map_value_stride(v) *
			      (upatch_map_is_percpu(v->type) ?
			       v->n_cpus : 1);
		for (i = 0; i < v->n_entries; i++) {
			xfree(v->entries[i].key, v->key_size);
			xfree(v->entries[i].value, value_alloc);
		}
		xfree(v->entries, v->entries_cap * sizeof(*v->entries));
		v->entries = NULL;
		v->entries_cap = 0;
		v->n_entries = 0;
	}
	if (v->btf) {
		btf__free(v->btf);
		v->btf = NULL;
	}
	if (v->serial_pages) {
		for (i = 0; i < v->n_serial_pages; i++)
			xfree(v->serial_pages[i].data,
			      v->serial_pages[i].bytes);
		xfree(v->serial_pages,
		      v->n_serial_pages * sizeof(*v->serial_pages));
		v->serial_pages = NULL;
		v->n_serial_pages = 0;
		v->serial_bytes_total = 0;
	}
}

int upatch_maps_read(const char *upatch, const char *map,
		     __u32 max_entries_cap, __u32 flags,
		     struct map_view *out)
{
	struct bpf_map_info info = {};
	char upatch_dir[PATH_MAX];
	struct stat upatch_st;
	int fd = -1;
	int ret;

	memset(out, 0, sizeof(*out));
	if (strscpy(out->upatch, upatch, sizeof(out->upatch)) < 0 ||
	    strscpy(out->name, map, sizeof(out->name)) < 0)
		return -ENAMETOOLONG;

	ret = open_map_pin(upatch, map, &fd, &info);
	if (ret)
		return ret;
	out->type = info.type;
	out->type_name = map_type_name(info.type);
	out->key_size = info.key_size;
	out->value_size = info.value_size;
	out->value_stride = map_value_stride(info.type, info.value_size);
	out->max_entries = info.max_entries;
	out->n_cpus = 1;
	if (upatch_map_is_percpu(info.type)) {
		int n = nproc_possible();

		if (n < 0) {
			close(fd);
			return n;
		}
		out->n_cpus = (__u32)n;
	}
	resolve_map_location(out);
	if (!upatch_pin_path(upatch_dir, sizeof(upatch_dir), upatch, NULL) &&
	    stat(upatch_dir, &upatch_st) == 0)
		out->lifetime_start_ns =
			(__u64)upatch_st.st_ctim.tv_sec * 1000000000ULL +
			(__u64)upatch_st.st_ctim.tv_nsec;

	ret = try_read_serialized(upatch, map, flags, out);
	if (ret < 0) {
		close(fd);
		return ret;
	}
	if (ret > 0) {
		close(fd);
		return 0;
	}

	if (map_skip_reason(info.type)) {
		out->skipped = true;
		out->skipped_reason = map_skip_reason(info.type);
		close(fd);
		return 0;
	}

	out->btf = try_load_btf(info.btf_id);
	if (out->btf) {
		out->key_type_id = info.btf_key_type_id;
		out->value_type_id = info.btf_value_type_id;
		upatch_map_btf_type_name(out->btf, info.btf_key_type_id,
					 out->btf_key_type,
					 sizeof(out->btf_key_type));
		upatch_map_btf_type_name(out->btf, info.btf_value_type_id,
					 out->btf_value_type,
					 sizeof(out->btf_value_type));
		upatch_map_btf_type_def(out->btf, info.btf_key_type_id,
					out->key_type_def,
					sizeof(out->key_type_def));
		upatch_map_btf_type_def(out->btf, info.btf_value_type_id,
					out->value_type_def,
					sizeof(out->value_type_def));
	}

	ret = read_entries(fd, out, max_entries_cap);

	close(fd);
	return ret;
}

static void summary_append(struct map_summary **list, size_t *n,
			   size_t *cap, const struct map_summary *one)
{
	if (*n == *cap) {
		size_t nc = *cap ? *cap * 2 : 8;
		void *p = xreallocarray(*list, *cap, nc, sizeof(**list));

		if (!p)
			return;
		*list = p;
		*cap = nc;
	}
	(*list)[(*n)++] = *one;
}

static void scan_upatch_maps(const char *upatch,
			     struct map_summary **list, size_t *n,
			     size_t *cap)
{
	char dir[PATH_MAX];
	struct dirent *e;
	DIR *d;

	if (upatch_pin_path(dir, sizeof(dir), upatch, "maps", NULL))
		return;
	d = opendir(dir);
	if (!d)
		return;
	while ((e = readdir(d))) {
		struct bpf_map_info info = {};
		struct map_summary one = {};
		int fd, ret;

		if (e->d_name[0] == '.')
			continue;
		if (strcmp(e->d_name, SERIAL_MAP_NAME) == 0)
			continue;
		ret = open_map_pin(upatch, e->d_name, &fd, &info);
		if (ret)
			continue;
		close(fd);
		strscpy(one.upatch, upatch, sizeof(one.upatch));
		strscpy(one.name, e->d_name, sizeof(one.name));
		one.type = info.type;
		one.type_name = map_type_name(info.type);
		one.max_entries = info.max_entries;
		one.n_cpus = 1;
		if (upatch_map_is_percpu(info.type)) {
			int cpus = nproc_possible();

			if (cpus < 0)
				continue;
			one.n_cpus = (__u32)cpus;
		}
		summary_append(list, n, cap, &one);
	}
	closedir(d);
}

int upatch_maps_list_one(const char *upatch,
			 struct map_summary **out,
			 size_t *n_out)
{
	struct map_summary *list = NULL;
	size_t n = 0, cap = 0;

	scan_upatch_maps(upatch, &list, &n, &cap);
	*out = list;
	*n_out = n;
	return 0;
}

int upatch_maps_list_all(struct map_summary **out,
			 size_t *n_out)
{
	struct map_summary *list = NULL;
	size_t n = 0, cap = 0;
	struct dirent *e;
	DIR *d;

	d = opendir(BPFFS_UPATCHES_DIR);
	if (!d) {
		*out = NULL;
		*n_out = 0;
		return 0;
	}
	while ((e = readdir(d))) {
		char raw_name[UPATCH_NAME_MAX + 1];

		if (e->d_name[0] == '.')
			continue;
		if (upatch_name_from_bpffs(raw_name, sizeof(raw_name),
					   e->d_name))
			continue;
		scan_upatch_maps(raw_name, &list, &n, &cap);
	}
	closedir(d);
	*out = list;
	*n_out = n;
	return 0;
}

void map_summary_free(struct map_summary *list, size_t n)
{
	xfree(list, n * sizeof(*list));
}
