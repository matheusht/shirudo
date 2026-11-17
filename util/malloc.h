/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Zeroing allocator: zero on alloc, scrub on free. In rust/src/heap.rs,
 * but for xasprintf() in util/malloc.c.
 */

#ifndef SHIRUDO_MALLOC_H
#define SHIRUDO_MALLOC_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <shirudo/compiler.h>

/*
 * NULL on failure, never die(): a one-shot CLI reports -ENOMEM up its
 * normal path. A zero size still returns a freeable pointer, so NULL
 * means out of memory and nothing else.
 */
void *xmalloc(size_t size);

/* NULL when nmemb * size would overflow. */
void *xcalloc(size_t nmemb, size_t size);

/*
 * Always a fresh zeroed block, the old one scrubbed and freed, so no
 * content lingers where realloc would shrink in place or move. NULL on
 * overflow or failure leaves ptr untouched.
 */
void *xreallocarray(void *ptr, size_t old_nmemb, size_t new_nmemb,
		    size_t size);

/*
 * xstrdup() copies a string, xstrndup() at most n bytes of one. A NUL
 * ends either copy without an error, so bytes that come with a length
 * become a string through span_to_str() instead.
 */
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

/* A formatted string, freed with xstrfree(); NULL if formatting fails. */
char *xasprintf(const char *fmt, ...) __printf(1, 2);

/*
 * Scrubs, so key material, signatures and TPM auth do not linger in
 * freed heap or a core dump.
 */
void xfree(void *ptr, size_t size);

/*
 * The length is strlen, so a string shortened in place leaves its tail
 * unscrubbed.
 */
void xstrfree(char *s);

/*
 * The one path for memory libc allocated, as scandir, getline and
 * realpath do; free() itself is poisoned below.
 */
void libc_free(void *p);

/*
 * Refused once the headers included above have declared them, so that a
 * later include of those still works; a file that must name them opts
 * out with MALLOC_INTERNAL.
 */
#ifndef MALLOC_INTERNAL
/* Fortified glibc makes these macros for clang; poison the names alone. */
# undef asprintf
# undef vasprintf
# pragma GCC poison malloc calloc realloc reallocarray free strdup strndup asprintf vasprintf
#endif

#endif /* SHIRUDO_MALLOC_H */
