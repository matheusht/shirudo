/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The config image a target runs from, its verified root and the
 * configuration it carries, which rust/src/util/image_config.rs keeps.
 */

#ifndef SHIRUDO_IMAGE_CONFIG_H
#define SHIRUDO_IMAGE_CONFIG_H

#include <shirudo/misc.h>

#include <stdbool.h>

struct config;

enum image_path {
	IMAGE_ETC,
	IMAGE_REGISTRIES,
	IMAGE_REPOSITORY_KEYS,
	IMAGE_TREE_CONF,
	IMAGE_NODE_LABELS,
	IMAGE_TRUSTED_KEYS,
	IMAGE_REVOKED_KEYS,
	IMAGE_PATH_COUNT,
};

bool image_config_active(void);
int image_config_get(struct config *out);
int image_config_set(const struct config *bootstrap,
		     int root_fd);
int image_config_validate(int root_fd);
void image_config_clear(void);
/* An entry of the config image, opened from its verified root; -errno. */
int image_open(enum image_path which, int flags);
int image_open_relative(const char *path, int flags);
int image_config_root_fd(void);

#endif /* SHIRUDO_IMAGE_CONFIG_H */
