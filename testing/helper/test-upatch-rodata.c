// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <stdio.h>
#include <string.h>

#include <bpf/btf.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "malloc.h"
#include "upatch_rodata.h"

/*
 * A typedef of len characters behind ptrs pointers, named into a buffer
 * of cap bytes: the result, and whether the buffer kept its terminator.
 */
static int name_into(size_t len, int ptrs, size_t cap)
{
	char name[512], buf[512];
	struct btf *btf;
	size_t off = 0;
	int id, ret;

	if (len >= sizeof(name) || cap > sizeof(buf))
		return 2;
	memset(name, 'n', len);
	name[len] = '\0';
	memset(buf, 'x', sizeof(buf));
	btf = btf__new_empty();
	if (!btf)
		return 2;
	id = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	if (id > 0)
		id = btf__add_typedef(btf, name, id);
	while (id > 0 && ptrs--)
		id = btf__add_ptr(btf, id);
	if (id <= 0) {
		btf__free(btf);
		return 2;
	}
	ret = upatch_rodata_type_name(btf, (__u32)id, buf, cap, &off, 0);
	btf__free(btf);
	printf("rc=%d off=%zu terminated=%d\n", ret, off,
	       !!memchr(buf, '\0', cap));
	if (!memchr(buf, '\0', cap))
		return 1;
	return ret ? 3 : 0;
}

/* A chain of n typedefs to type, or -1. */
static int typedefs(struct btf *btf, const char *prefix, int n, int type)
{
	char name[16];

	while (type > 0 && n--) {
		if (strsprintf(name, sizeof(name), "%s%d", prefix, n) < 0)
			return -1;
		type = btf__add_typedef(btf, name, type);
	}
	return type;
}

/* Four levels of 64 members all laid over the bytes of an int, or -1. */
static int overlaid(struct btf *btf, int type)
{
	int level, inner, i;

	for (level = 0; type > 0 && level < 4; level++) {
		inner = type;
		type = btf__add_struct(btf, NULL, 4);
		for (i = 0; type > 0 && i < 64; i++)
			if (btf__add_field(btf, NULL, inner, 0, 0))
				type = -1;
	}
	return type;
}

/*
 * A struct of an int, an enum and a pointer, spoiled as what says,
 * through the walk that guards libbpf's dumper: 0 when it may be dumped,
 * 1 when it is refused.
 */
static int dumpable(const char *what)
{
	const char *member = "a", *value = "E", *pointee = "int";
	int ints, en, target, ptr, st, a, b, ret = 2;
	struct rodata_dump_cost *cost;
	struct btf_type *t;
	struct btf *btf;
	__u32 types;

	if (!strcmp(what, "member"))
		member = "a\x1b[2J";
	else if (!strcmp(what, "enum"))
		value = "E\x07";
	else if (!strcmp(what, "pointee"))
		pointee = "int\xc2\x9b";
	btf = btf__new_empty();
	if (!btf)
		return 2;
	ints = btf__add_int(btf, "int", 4, BTF_INT_SIGNED);
	target = btf__add_int(btf, pointee, 4, BTF_INT_SIGNED);
	en = btf__add_enum(btf, "e", 4);
	if (en > 0 && btf__add_enum_value(btf, value, 0))
		en = -1;
	if (!strcmp(what, "proto")) {
		target = btf__add_func_proto(btf, ints);
		if (target > 0 && btf__add_func_param(btf, "x", ints))
			target = -1;
	}
	ptr = btf__add_ptr(btf, target);
	if (ptr > 0 && !strcmp(what, "loop")) {
		t = (struct btf_type *)btf__type_by_id(btf, ptr);
		t->type = ptr;
	}
	a = ints;
	b = en;
	if (!strcmp(what, "elements")) {
		a = btf__add_array(btf, ints, ints, 1u << 20);
	} else if (!strcmp(what, "overlaid")) {
		a = overlaid(btf, ints);
	} else if (!strcmp(what, "shared") || !strcmp(what, "deep")) {
		a = typedefs(btf, "t", 6, ints);
		b = !strcmp(what, "deep") ? typedefs(btf, "u", 2, a) : a;
	}
	st = btf__add_struct(btf, "s", 16);
	if (ints <= 0 || target <= 0 || en <= 0 || ptr <= 0 || a <= 0 ||
	    b <= 0 || st <= 0 ||
	    btf__add_field(btf, member, a, 0, 0) ||
	    btf__add_field(btf, "b", b, 32, 0) ||
	    btf__add_field(btf, "p", ptr, 64, 0))
		goto out;
	types = btf__type_cnt(btf);
	cost = xcalloc(types, sizeof(*cost));
	if (!cost)
		goto out;
	ret = upatch_rodata_dump_cost(btf, (__u32)st, 0, cost);
	printf("%s dumpable=%d rc=%d\n", what, !ret, ret);
	ret = ret ? 1 : 0;
	xfree(cost, types * sizeof(*cost));
out:
	btf__free(btf);
	return ret;
}

int main(int argc, char **argv)
{
	__u64 len, ptrs;

	if (argc == 3 && !strcmp(argv[1], "dumpable"))
		return dumpable(argv[2]);
	if (argc != 3 || parse_u64(argv[1], strlen(argv[1]), 500, &len) ||
	    parse_u64(argv[2], strlen(argv[2]), 4, &ptrs))
		return 2;
	return name_into((size_t)len, (int)ptrs, 256);
}
