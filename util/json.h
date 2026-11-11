/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * In-tree JSON emitter and schema-callback parser, which
 * rust/src/util/json/ implements.
 */

#ifndef SHIRUDO_JSON_H
#define SHIRUDO_JSON_H

#include <stdbool.h>
#include <stddef.h>

#include <shirudo/misc.h>

#ifndef JSON_MAX_BYTES
#define JSON_MAX_BYTES		(8u * 1024u * 1024u)
#endif
#ifndef JSON_MAX_DEPTH
#define JSON_MAX_DEPTH		32u
#endif
/* The declared keys of one object, which json_parse() tells apart. */
#define JSON_MAX_FIELDS		64u
#ifndef JSON_MAX_STRING_BYTES
#define JSON_MAX_STRING_BYTES	(16u * 1024u * 1024u)
#endif

/* An OTLP AnyValue nests four levels for each level of a decoder table. */
#define JSON_EMIT_MAX_DEPTH	192u

/*
 * buf and cap are the caller's, or with max set the emitter's: it grows
 * buf, xfree(buf, cap) releases it, and a document past max bytes is
 * -E2BIG.
 */
struct json_emit {
	char		*buf;
	size_t		cap;
	size_t		len;
	size_t		max;
	int		err;	/* sticky; -ENOSPC, -EILSEQ, -E2BIG, -ENOMEM */
	__u32		depth;	/* open-container nesting */
	/* bit d set: the container at depth d has a member */
	__u64		nonempty[JSON_EMIT_MAX_DEPTH / 64];
	bool		value_pending;
};

/*
 * Commas and escaping are automatic. On any error the sticky err
 * latches and later calls are no-ops: check it once after the final
 * close.
 */
void json_obj_open(struct json_emit *e);
void json_obj_open_key(struct json_emit *e, const char *key);
/* Value containers and scalars consume a pending json_key or array slot. */
void json_obj_value_open(struct json_emit *e);
void json_obj_close(struct json_emit *e);
void json_arr_open(struct json_emit *e, const char *key);
void json_arr_open_value(struct json_emit *e);
void json_arr_close(struct json_emit *e);
void json_key(struct json_emit *e, const char *key);
void json_kv_string(struct json_emit *e,
		    const char *key, const char *val);
/* A NUL among the len bytes is -EILSEQ, as malformed UTF-8 is. */
void json_kv_string_n(struct json_emit *e, const char *key,
		      const char *val, size_t len);
void json_kv_int(struct json_emit *e,
		 const char *key, __s64 val);
/* json_kv_int() takes an __s64, and these all 64 bits of a __u64. */
void json_kv_u64(struct json_emit *e, const char *key, __u64 val);
void json_u64_value(struct json_emit *e, __u64 val);
void json_kv_bool(struct json_emit *e,
		  const char *key, int val);
void json_kv_null(struct json_emit *e, const char *key);
/* Insert an internally-generated, already-valid JSON value verbatim. */
void json_kv_raw(struct json_emit *e, const char *key,
		 const char *value, size_t value_len);
void json_str(struct json_emit *e, const char *val);
void json_str_value(struct json_emit *e, const char *val);
void json_raw_value(struct json_emit *e, const char *value,
		    size_t value_len);
void json_raw(struct json_emit *e, const char *value,
	      size_t value_len);
/*
 * The n bytes at s as a value or a key, with U+FFFD for each byte that
 * starts no well-formed UTF-8 character and for each NUL: for bytes
 * from outside, cut mid-character as often as not, where one bad byte
 * must not cost the whole document.
 */
void json_str_lossy(struct json_emit *e, const char *s, size_t n);
void json_key_lossy(struct json_emit *e, const char *s, size_t n);
/* A key shirudo names, written strictly, with such a value. */
void json_kv_string_lossy(struct json_emit *e, const char *key,
			  const char *val);

/*
 * Not a generic deserialiser: declared keys are dispatched, everything
 * else is parsed and discarded, within bounds so hostile input cannot
 * exhaust the stack or a buffer.
 */
enum json_vtype {
	JSON_T_STRING,	/* dst: char[dst_cap] (NUL-terminated)   */
	JSON_T_INT,	/* dst: __s64 *                          */
	JSON_T_BOOL,	/* dst: int *  (0/1)                     */
	JSON_T_OBJECT,	/* nested object -> sub[] sub-schema     */
	JSON_T_ARRAY,	/* sub[] schema; dst = shirudo_json_array * */
	JSON_T_MAP,	/* object of any keys: sub[0] each value; dst = json_map * */
};

/*
 * An array of scalars declares one sub field with an empty key, which
 * takes each element; any other sub[] takes objects alone, and none
 * discards the elements. The seen flags of the sub fields, and of the
 * fields nested in them, reset per element; the dst buffers do not. on_elem may copy the
 * element out of the scratch dst buffers before the next one overwrites
 * them, and returns a negative errno to abort.
 */
struct json_array {
	int	(*on_elem)(void *ctx);
	void	*ctx;
};

/*
 * A map takes an object whose keys the schema does not name: each value
 * goes into sub[0], its seen flags and those nested in it reset first,
 * and on_member then gets its key, at most 255 bytes, to copy the value
 * out or return a negative errno, a repeated key included where the
 * caller refuses one.
 */
struct json_map {
	int	(*on_member)(void *ctx, const char *key);
	void	*ctx;
};

struct json_field {
	const char			*key;
	enum json_vtype		type;
	void				*dst;
	size_t				dst_cap;	/* STRING only */
	int				seen;		/* set by the parser */
	struct json_field	*sub;		/* OBJECT/ARRAY schema */
	size_t				n_sub;		/* OBJECT/ARRAY schema */
};

/*
 * -EINVAL on malformed input, a type mismatch or a declared key named
 * twice in one object, null or not, -E2BIG on a bounds violation or more
 * than JSON_MAX_FIELDS declared keys, -ENOSPC when a string exceeds its
 * dst_cap.
 */
int json_parse(const char *data, size_t len,
	       struct json_field *fields, size_t n_fields);

/*
 * Both readers take JSON text as ECMA-404, 2nd edition, defines it,
 * under the restrictions its section 2 lets a processor impose:
 * json_parse() takes an object alone and a declared key once, and both
 * refuse \u0000 and a lone surrogate escape, which no C string or UTF-8
 * holds, bytes that are no well-formed UTF-8, more than JSON_MAX_DEPTH
 * levels and more than JSON_MAX_BYTES.
 *
 * json_walk() reports every token of a document of any one value, in
 * order and checked as json_parse() checks one: strings and keys
 * decoded and terminated, numbers as their text, with integer set when
 * it has no fraction or exponent, literals as 1 for true, 0 for false
 * and -1 for null. A callback may be NULL; one that returns a negative
 * errno stops the walk with it.
 */
struct json_visitor {
	int	(*open)(void *ctx, bool array);
	int	(*close)(void *ctx, bool array);
	int	(*key)(void *ctx, const char *key);
	int	(*string)(void *ctx, const char *s);
	int	(*number)(void *ctx, const char *text, size_t len,
			  bool integer);
	int	(*literal)(void *ctx, int value);
};

int json_walk(const char *data, size_t len,
	      const struct json_visitor *v, void *ctx);

#endif /* SHIRUDO_JSON_H */
