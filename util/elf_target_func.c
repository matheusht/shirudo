// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The packager's single uprobe offset still has a C caller.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/overflow.h>

#include "elf_target.h"
#include "libbpf_internal.h"
#include "malloc.h"

int elf_target_resolve_func(const char *path, const char *func, __u64 offset,
			    struct elf_target *out)
{
	struct stat st;
	__u64 base = 0;
	long func_off;
	int fd, err;

	if (!path || path[0] != '/' || (func && !func[0]) || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) != 0) {
		err = -errno;
		close(fd);
		return err;
	}
	err = elf_build_id_fd(fd, out->build_id, &out->build_id_len);
	close(fd);
	if (err)
		return err;
	if (func) {
		func_off = elf_find_func_offset_from_file(path, func);
		if (func_off < 0)
			return (int)func_off;
		base = (__u64)func_off;
	}
	if (check_add_overflow(base, offset, &base) || base >= (__u64)st.st_size)
		return -ERANGE;
	out->offsets = xcalloc(1, sizeof(*out->offsets));
	if (!out->offsets)
		return -ENOMEM;
	out->offsets_cap = 1;
	out->offsets[0] = base;
	out->nr_offsets = 1;
	return 0;
}
