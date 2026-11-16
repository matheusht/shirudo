// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * seal_output_create() and seal_output_commit() with the write failing,
 * as a file size limit of 0 makes every write to a regular file fail,
 * and root's move made before it: test-seal-output <how> <path> [<dir>],
 * how being fail, swap-dir, which puts a symbolic link to dir in place of
 * the path's directory, or swap-file, which puts another file in place of
 * the one being written. Prints what the commit returned.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "util/seal.h"

static const char *how, *path, *dir;

static int swap_dir(void)
{
	char parent[4096], moved[4096 + 8];
	const char *slash = strrchr(path, '/');

	if (!slash ||
	    strsprintf(parent, sizeof(parent), "%.*s", (int)(slash - path),
		       path) < 0 ||
	    strsprintf(moved, sizeof(moved), "%s.moved", parent) < 0 ||
	    rename(parent, moved) || symlink(dir, parent))
		return -errno;
	return 0;
}

static int swap_file(void)
{
	char moved[4096 + 8];
	int fd;

	if (strsprintf(moved, sizeof(moved), "%s.moved", path) < 0 ||
	    rename(path, moved))
		return -errno;
	fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	close(fd);
	return 0;
}

/* Every write to a regular file from here fails with EFBIG. */
static int fail_writes(void)
{
	struct rlimit lim;

	if (signal(SIGXFSZ, SIG_IGN) == SIG_ERR ||
	    getrlimit(RLIMIT_FSIZE, &lim))
		return -errno;
	lim.rlim_cur = 0;
	return setrlimit(RLIMIT_FSIZE, &lim) ? -errno : 0;
}

int main(int argc, char **argv)
{
	struct seal_output out;
	int ret, err = 0;

	if (argc < 3) {
		fprintf(stderr, "usage: test-seal-output <how> <path> [<dir>]\n");
		return 2;
	}
	how = argv[1];
	path = argv[2];
	dir = argc > 3 ? argv[3] : "";
	ret = seal_output_create(&out, path, 0600);
	if (!ret) {
		if (!strcmp(how, "swap-dir"))
			err = swap_dir();
		else if (!strcmp(how, "swap-file"))
			err = swap_file();
		if (!err)
			err = fail_writes();
		if (err)
			fprintf(stderr, "test-seal-output: %s: %s\n", how,
				strerror(-err));
		ret = seal_output_commit(&out, "{}", 2);
	}
	printf("%d\n", ret);
	return 0;
}
