/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Lowercase hex encoding of digests, in rust/src/util/hex.rs.
 */

#ifndef SHIRUDO_HEX_H
#define SHIRUDO_HEX_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

/* out needs 2 * n + 1 bytes. */
void hex_encode(const __u8 *in, size_t n, char *out);
/* The same, xmalloc'd to 2 * n + 1 bytes. */
char *hex_alloc(const void *in, size_t n);

/* The value of one hex digit, -1 for any other byte. */
int hex_nibble(int c);
/*
 * Whether the n bytes at s are all lowercase hex digits; it reads no
 * further than the first that is not, a terminator included.
 */
bool hex_is_lower(const char *s, size_t n);

/* Exactly 2 * n hex digits, either case. 0 or -EINVAL. */
int hex_decode(const char *hex, __u8 *out, size_t n);
/*
 * An even count of hex digits, either case and none at all included, of
 * at most cap bytes, into *len bytes at out. 0 or -EINVAL.
 */
int hex_decode_max(const char *hex, __u8 *out, size_t cap, size_t *len);

/*
 * An OCI digest, "sha256:" and 64 hex digits of either case, into its 32
 * bytes. 0 or -EINVAL. sha256_digest_encode() writes the 32 bytes at in
 * as one, in lowercase and terminated.
 */
#define SHA256_DIGEST_STR_SIZE	72
int sha256_digest_decode(const char *digest, __u8 out[32]);
void sha256_digest_encode(const __u8 in[32],
			  char out[SHA256_DIGEST_STR_SIZE]);

#endif /* SHIRUDO_HEX_H */
