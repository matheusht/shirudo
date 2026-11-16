/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_KEYS_H
#define SHIRUDO_IMAGE_KEYS_H

#include <shirudo/misc.h>

#include <stddef.h>

struct trusted_set;

/*
 * The trust set of the config image at root_fd, from the signer at
 * primary, validated without changing anything: 0 or -errno. The
 * runtime's checks are in rust/src/util/image_keys.rs.
 */
int keys_validate_image_set(const char *primary, int root_fd,
			    struct trusted_set *set);

/*
 * The check a live update makes that the kernel holds every certificate
 * of set, with holds() in place of the BPF keyring: called with each
 * certificate and ctx, it gives 1 when held, 0 when not, or -errno.
 * Returns 0, -ENOKEY or -errno.
 */
int keys_check_image_set_with(const struct trusted_set *set,
			      int (*holds)(const __u8 *der, size_t len,
					   void *ctx),
			      void *ctx);

#endif /* SHIRUDO_IMAGE_KEYS_H */
