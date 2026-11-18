/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Live-kernel capability checks required by shirudo's signed BPF loader,
 * which rust/src/util/kernel_abi.rs implements.
 */

#ifndef SHIRUDO_KERNEL_ABI_H
#define SHIRUDO_KERNEL_ABI_H

#include <stddef.h>

struct shirudo_btf;

#define KERNEL_ABI_DETAIL_MAX 256

/*
 * Validate an already-parsed vmlinux BTF object.  Exposed separately so the
 * structural contract can be tested with synthetic BTF without depending on
 * the kernel running the test.
 */
int kernel_abi_validate_btf(const struct shirudo_btf *btf,
			    char *detail, size_t detail_sz);

int kernel_abi_check(char *detail, size_t detail_sz);

struct embedded_bpf;

#define LSM_HOOKS_MAX		128
#define LSM_HOOK_NAME_MAX	64

struct lsm_hooks {
	char	name[LSM_HOOKS_MAX][LSM_HOOK_NAME_MAX];
	size_t	n;
};

/*
 * Adds the hooks the lsm and lsm.s programs of obj attach to, each name
 * once: 0, -E2BIG when they do not fit, or the error of opening obj.
 */
int kernel_abi_lsm_hooks(const struct embedded_bpf *obj,
			 struct lsm_hooks *hooks);

/*
 * Whether btf has a bpf_lsm_<hook> function for every hook: 0, or
 * -EOPNOTSUPP with the hooks it lacks named in detail.
 */
int kernel_abi_validate_lsm_hooks(const struct shirudo_btf *btf,
				  const struct lsm_hooks *hooks,
				  char *detail, size_t detail_sz);

/* kernel_abi_validate_lsm_hooks() on the running kernel's BTF. */
int kernel_abi_check_lsm_hooks(const struct lsm_hooks *hooks,
			       char *detail, size_t detail_sz);

#endif /* SHIRUDO_KERNEL_ABI_H */
