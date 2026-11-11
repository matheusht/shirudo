/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * dm-verity mappings of config images, which rust/src/util/dm_verity.rs
 * implements.
 */

#ifndef SHIRUDO_DM_VERITY_H
#define SHIRUDO_DM_VERITY_H

#include <limits.h>
#include <stdbool.h>
#include <sys/types.h>

#include "config_image.h"

struct dm_verity {
	struct config_image image;
	char name[128];
	char path[PATH_MAX];
	dev_t device;
	dev_t data_device;
	dev_t hash_device;
	int data_loop_fd;
	int hash_loop_fd;
};

typedef int (*shirudo_dm_verity_cb)(const char *name, dev_t device, void *ctx);

int dm_verity_list(shirudo_dm_verity_cb callback, void *ctx);
int dm_verity_create(const struct config_image_open *image,
		     const char *name, struct dm_verity *out);
/* Require the active readonly table to match the image parameters exactly. */
int dm_verity_inspect(const char *name,
		      const struct config_image *image,
		      struct dm_verity *out);
/* Read every data block through the mapping bound to these retained files. */
int dm_verity_verify(const struct dm_verity *device,
		     const struct config_image_open *image);
int dm_verity_mount(const struct dm_verity *device,
		    const char *mountpoint, bool executable);
int dm_verity_remove(struct dm_verity *device, bool deferred);
void dm_verity_close(struct dm_verity *device);

#endif /* SHIRUDO_DM_VERITY_H */
