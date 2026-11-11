/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The config image and its dm-verity hash tree, which
 * rust/src/util/config_image.rs implements.
 */

#ifndef SHIRUDO_CONFIG_IMAGE_H
#define SHIRUDO_CONFIG_IMAGE_H

#include <shirudo/misc.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define CONFIG_IMAGE_BLOCK_SIZE 4096u
#define CONFIG_IMAGE_SALT_SIZE 32u
#define CONFIG_IMAGE_SIG_MAX 16384u
#define CONFIG_IMAGE_MAX_BYTES (1ull << 40)

struct config_image {
	__u64 data_blocks;
	__u64 hash_blocks;
	bool signed_root;
	__u8 salt[CONFIG_IMAGE_SALT_SIZE];
	__u8 root_hash[32];
};

struct config_image_open {
	struct config_image image;
	int data_fd;
	int hash_fd;
	int signature_fd;
};

/* Read the standard veritysetup superblock; no trust decision is made. */
int config_image_read_header(int hash_fd,
			     struct config_image *out);
int config_image_check_files(int data_fd, int hash_fd,
			     const struct config_image *image);
/* Hold config inputs for kernel root-signature and mapped-data verification. */
int config_image_open(const char *prefix,
		      struct config_image_open *out);
int config_image_open_root(const char *prefix,
			   const __u8 expected_root[32],
			   struct config_image_open *out);
void config_image_close(struct config_image_open *image);

#endif /* SHIRUDO_CONFIG_IMAGE_H */
