/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_TEST_IMAGE_CLEANUP_H
#define SHIRUDO_TEST_IMAGE_CLEANUP_H

#include <time.h>

/*
 * The retry with which rust/src/util/image_runtime.rs removes a rejected
 * candidate's mapping, with remove() in place of the removal.
 */
int image_retry_busy(int (*remove)(void *ctx), void *ctx);
int __wrap_nanosleep(const struct timespec *req, struct timespec *rem);

#endif /* SHIRUDO_TEST_IMAGE_CLEANUP_H */
