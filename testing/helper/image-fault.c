// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <tss2/tss2_esys.h>

#include <shirudo/misc.h>

#include "image-fault.h"
#include "util/config_image.h"
#include "util/dm_verity.h"
#include "util/identity.h"
#include "util/io.h"
#include "util/paths.h"

enum root_test_mode {
	ROOT_NORMAL,
	ROOT_MISSING,
	ROOT_WRONG,
	ROOT_MATCH,
};

static enum root_test_mode root_mode;
static __u32 begin_calls, end_calls;
static int consumed_valid = -1;

static int roots_fd = -1;


static long real_bpf(long cmd, void *attr, long size)
{
	return __real_syscall(SYS_bpf, cmd, (long)attr, size, 0L, 0L, 0L);
}

/*
 * The writes of config_root_begin() and config_root_end() to the map of
 * the roots tasks expect: the staging of the image's root is left out,
 * or staged off by a bit; its clearing first notes whether the guard
 * consumed it.
 */
static long roots_update(union bpf_attr *attr, long size)
{
	const struct expected_root *want = (const void *)(uintptr_t)attr->value;
	struct expected_root staged, current = {};
	unsigned char changed[256];
	int lookup;
	long ret;

	if (want->valid) {
		begin_calls++;
		if (root_mode == ROOT_MISSING)
			return 0;
		if (size < 0 || (size_t)size > sizeof(changed)) {
			errno = E2BIG;
			return -1;
		}
		staged = *want;
		if (root_mode == ROOT_WRONG)
			staged.root[0] ^= 1;
		memcpy(changed, attr, size);
		((union bpf_attr *)changed)->value = (uintptr_t)&staged;
		return real_bpf(BPF_MAP_UPDATE_ELEM, changed, size);
	}
	end_calls++;
	lookup = bpf_map_lookup_elem(attr->map_fd, (const void *)(uintptr_t)attr->key,
				     &current) ? -errno : 0;
	if (root_mode == ROOT_MISSING && lookup == -ENOENT)
		lookup = 0;
	consumed_valid = current.valid;
	ret = real_bpf(BPF_MAP_UPDATE_ELEM, attr, size);
	if (lookup) {
		errno = -lookup;
		return -1;
	}
	return ret;
}

/*
 * The bpf() syscalls of the image's config root: the map of the roots
 * tasks expect, opened, which the staging writes go to, and those writes.
 */
long __wrap_syscall(long number, ...)
{
	union bpf_attr *attr;
	long ret;
	va_list ap;
	long a[6];
	int i;

	va_start(ap, number);
	for (i = 0; i < 6; i++)
		a[i] = va_arg(ap, long);
	va_end(ap);
	if (number != SYS_bpf)
		goto real;
	attr = (union bpf_attr *)a[1];
	if (a[0] == BPF_OBJ_GET) {
		ret = real_bpf(BPF_OBJ_GET, attr, a[2]);
		if (ret >= 0 &&
		    !strcmp((const char *)(uintptr_t)attr->pathname, BPFFS_DIR "/config_roots"))
			roots_fd = ret;
		return ret;
	}
	if (a[0] == BPF_MAP_UPDATE_ELEM && root_mode != ROOT_NORMAL &&
	    (int)attr->map_fd == roots_fd)
		return roots_update(attr, a[2]);
real:
	return __real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);
}

static int check_root_cleared(void)
{
	struct expected_root expected = {}, empty = {};
	int map, task, ret;

	map = bpf_obj_get(BPFFS_DIR "/config_roots");
	if (map < 0)
		return -errno;
	task = syscall(SYS_pidfd_open, getpid(), 0);
	if (task < 0) {
		ret = -errno;
		goto out;
	}
	ret = bpf_map_lookup_elem(map, &task, &expected) ? -errno : 0;
	if (root_mode == ROOT_MISSING && ret == -ENOENT)
		ret = 0;
	if (!ret && memcmp(&expected, &empty, sizeof(empty)))
		ret = -EUCLEAN;
	close(task);
out:
	close(map);
	return ret;
}

static int check_classification(const struct dm_verity *device)
{
	__u32 dev = kernel_dev(device->device);
	struct device_authority entry;
	__u64 key, next, diskseq;
	__u32 matches = 0;
	int map, block, ret = 0;
	void *cursor = NULL;

	block = open(device->path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (block < 0)
		return -errno;
	if (ioctl(block, BLKGETDISKSEQ, &diskseq)) {
		ret = -errno;
		goto out_block;
	}
	map = bpf_obj_get(BPFFS_DIR "/devices");
	if (map < 0) {
		ret = -errno;
		goto out_block;
	}
	while (!bpf_map_get_next_key(map, cursor, &next)) {
		if (bpf_map_lookup_elem(map, &next, &entry)) {
			ret = -errno;
			break;
		}
		if (entry.dev == dev)
			printf("device=%u diskseq=%llu record_diskseq=%llu "
			       "kind=%u root_match=%d\n", dev,
			       (__u64)diskseq,
			       (__u64)entry.diskseq, entry.kind,
			       !memcmp(entry.root, device->image.root_hash,
				       sizeof(entry.root)));
		if (entry.dev == dev && entry.diskseq == diskseq) {
			matches++;
			if (entry.kind != DEVICE_CONFIG ||
			    memcmp(entry.root, device->image.root_hash, 32)) {
				ret = -EUCLEAN;
				break;
			}
		}
		key = next;
		cursor = &key;
	}
	if (!ret && errno != ENOENT)
		ret = -errno;
	if (!ret && matches != (root_mode == ROOT_MATCH ? 1u : 0u))
		ret = -EACCES;
	printf("classified=%u consumed_valid=%d\n", matches, consumed_valid);
	close(map);
out_block:
	close(block);
	return ret;
}

static int config_root_test(const char *mode, const char *prefix)
{
	struct config_image_open opened;
	struct dm_verity device;
	bool created = false;
	int ret, cleanup;
	char name[128];

	if (!strcmp(mode, "missing"))
		root_mode = ROOT_MISSING;
	else if (!strcmp(mode, "wrong"))
		root_mode = ROOT_WRONG;
	else if (!strcmp(mode, "match"))
		root_mode = ROOT_MATCH;
	else
		return 2;
	ret = config_image_open(prefix, &opened);
	if (ret)
		goto done;
	snprintf(name, sizeof(name), "shirudo-verify-root-test-%ld",
		 (long)getpid());
	ret = dm_verity_create(&opened, name, &device);
	created = !ret;
	if (!ret && (begin_calls != 1 || end_calls != 1 ||
		     consumed_valid != (root_mode == ROOT_WRONG ? 1 : 0)))
		ret = -EUCLEAN;
	if (!ret)
		ret = check_root_cleared();
	if (!ret)
		ret = dm_verity_verify(&device, &opened);
	if (!ret)
		ret = check_classification(&device);
	if (created) {
		cleanup = dm_verity_remove(&device, true);
		dm_verity_close(&device);
		if (!ret)
			ret = cleanup;
	}
	config_image_close(&opened);
done:
	if (ret)
		fprintf(stderr, "config root test: %s\n", strerror(-ret));
	return ret ? 1 : 0;
}

int __wrap_main(int argc, const char **argv)
{
	if (argc == 4 && !strcmp(argv[1], "config-root"))
		return config_root_test(argv[2], argv[3]);
	if (argc != 4 || strcmp(argv[1], "image") ||
	    strcmp(argv[2], "update")) {
		fprintf(stderr, "usage: shirudo-image-fault "
			"image update <prefix>\n");
		return 2;
	}
	return __real_main(argc, argv);
}

TSS2_RC __wrap_Esys_PCR_Extend(ESYS_CONTEXT *context, ESYS_TR pcr,
			       ESYS_TR first, ESYS_TR second, ESYS_TR third,
			       const TPML_DIGEST_VALUES *digests)
{
	TSS2_RC ret;

	ret = __real_Esys_PCR_Extend(context, pcr, first, second, third,
				     digests);
	if (!ret)
		_exit(99);
	return ret;
}
