/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_TEST_TPM_SESSION_H
#define SHIRUDO_TEST_TPM_SESSION_H

#include "identity.h"

extern int enforcing;

int __wrap_prctl(int option, ...);
int __wrap_bpf_obj_get(const char *path);
int __wrap_bpf_obj_get_info_by_fd(int fd, void *info, __u32 *len);
int __wrap_bpf_map_lookup_elem(int fd, const void *key, void *value);

#endif
