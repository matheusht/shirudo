/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_TEST_TPM_SESSION_H
#define SHIRUDO_TEST_TPM_SESSION_H

#include "identity.h"

extern int enforcing;

int __wrap_prctl(int option, ...);
long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...);

#endif
