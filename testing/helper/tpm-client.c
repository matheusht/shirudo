// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <stdarg.h>

#include <shirudo/enforcement.h>

#include "tpm-session.h"

int enforcing;

int __real_prctl(int option, ...);

/*
 * Untrusted clients use the default; session tests select guarded
 * states. What the kernel answers PR_GET_ENFORCEMENT: enforcing for 1,
 * a kernel without the question for 0, the error for a negative errno.
 */
int __wrap_prctl(int option, ...)
{
	unsigned long a[4];
	va_list ap;

	va_start(ap, option);
	for (int i = 0; i < 4; i++)
		a[i] = va_arg(ap, unsigned long);
	va_end(ap);
	if (option != PR_GET_ENFORCEMENT)
		return __real_prctl(option, a[0], a[1], a[2], a[3]);
	errno = enforcing == 1 ? PR_ENFORCING_ERR :
		enforcing == 0 ? EINVAL : -enforcing;
	return -1;
}
