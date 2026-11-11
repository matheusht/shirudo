/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The did-you-mean helpers of the dispatchers, allocation-free, which
 * rust/src/util/similar.rs implements.
 */

#ifndef SHIRUDO_SIMILAR_H
#define SHIRUDO_SIMILAR_H

#include <stddef.h>

/*
 * Soft upper bound on the length of a string compared here. Strings
 * longer than this short-circuit to "no match" rather than allocating.
 * Comfortably larger than every shirudo subcommand and option name.
 */
#define SIMILAR_MAX_LEN	64

struct suggestion {
	const char	*name;
	int		dist;
};

size_t suggest(const char *name,
	       const char *const *commands, size_t n_commands,
	       int max_dist,
	       struct suggestion *out, size_t cap);

/*
 * Three tiers, the first that hits wins: exact, input a prefix of a
 * candidate, candidate a prefix of input. The count tells unique from
 * none from ambiguous.
 */
size_t resolve(const char *input,
	       const char *const *candidates, size_t n,
	       size_t *matches, size_t cap);

#endif /* SHIRUDO_SIMILAR_H */
