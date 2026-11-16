// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "builtin.h"
#include "util/config.h"
#include "util/image_config.h"

int main(int argc, const char **argv)
{
	struct config bootstrap;
	int fd, ret;

	if (argc < 3)
		return 2;
	fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return 1;
	ret = config_load_path(&bootstrap, "/dev/null");
	if (!ret) {
		memcpy(bootstrap.tpm_owner_auth, "bootstrap-owner", 15);
		bootstrap.tpm_owner_auth_len = 15;
		ret = strscpy(bootstrap.tpm_tcti, "bootstrap-tcti",
			      sizeof(bootstrap.tpm_tcti));
		if (ret >= 0)
			ret = image_config_set(&bootstrap, fd);
	}
	close(fd);
	if (ret)
		return 1;
	if (!strcmp(argv[2], "bpm")) {
		ret = cmd_bpm(argc - 2, argv + 2);
	} else if (!strcmp(argv[2], "keys")) {
		ret = cmd_keys(argc - 2, argv + 2);
	} else if (!strcmp(argv[2], "config")) {
		ret = cmd_config(argc - 2, argv + 2);
	} else if (!strcmp(argv[2], "source") && argc == 4) {
		char content[64];
		int kfd = bpm_source_key_open(argv[3]);
		FILE *file = kfd < 0 ? NULL : fdopen(kfd, "r");

		if (!file) {
			ret = kfd < 0 ? kfd : -errno;
			if (kfd >= 0)
				close(kfd);
		} else {
			if (!fgets(content, sizeof(content), file))
				ret = -EIO;
			else
				fputs(content, stdout);
			fclose(file);
		}
	} else if (!strcmp(argv[2], "tree")) {
		puts(bpm_tree_certificate());
		ret = 0;
	} else {
		ret = 2;
	}
	image_config_clear();
	return ret ? 1 : 0;
}
