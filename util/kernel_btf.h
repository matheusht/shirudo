/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * BTF as shirudo reads it, which rust/src/util/kernel_btf.rs implements:
 * what a map view and the kernel ABI check take.
 */

#ifndef SHIRUDO_KERNEL_BTF_H
#define SHIRUDO_KERNEL_BTF_H

#include <linux/types.h>

struct shirudo_btf;

/* The BTF in the size bytes at data, or NULL with errno set. */
struct shirudo_btf *shirudo_btf_new(const void *data, __u32 size);
void shirudo_btf_free(struct shirudo_btf *btf);

#endif /* SHIRUDO_KERNEL_BTF_H */
