// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright (C) 2019 Facebook
 * Copyright (c) 2026 Authors of shirudo
 *
 * gen-vmlinux-h <btf> -- vmlinux.h as the vendored libbpf's btf_dump
 * writes it, adapted from bpftool's `btf dump file ... format c`
 * (tools/bpf/bpftool/btf.c, dual-licensed (GPL-2.0-only OR BSD-2-Clause);
 * shirudo consumes the BSD branch): every type of one BTF blob, then the
 * kfunc prototypes. The oracle t1012 holds tools/gen-vmlinux-h, which does
 * the same in Rust, to. Test-only; never shipped.
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/btf.h>
#include <bpf/hashmap.h>
#include <bpf/libbpf.h>

#include <shirudo/compiler.h>

#define KFUNC_DECL_TAG		"bpf_kfunc"
#define FASTCALL_DECL_TAG	"bpf_fastcall"

struct ptr_array {
	__u32		cnt;
	__u32		cap;
	const void	**elems;
};

static int ptr_array_push(const void *ptr, struct ptr_array *arr)
{
	__u32 new_cap;
	void *tmp;

	if (arr->cnt == arr->cap) {
		new_cap = (arr->cap ?: 16) * 2;
		tmp = realloc(arr->elems, sizeof(*arr->elems) * new_cap);
		if (!tmp)
			return -ENOMEM;
		arr->elems = tmp;
		arr->cap = new_cap;
	}
	arr->elems[arr->cnt++] = ptr;
	return 0;
}

static int cmp_kfuncs(const void *pa, const void *pb, void *ctx)
{
	const struct btf_type *a = *(const struct btf_type **)pa;
	const struct btf_type *b = *(const struct btf_type **)pb;
	struct btf *btf = ctx;

	return strcmp(btf__str_by_offset(btf, a->name_off),
		      btf__str_by_offset(btf, b->name_off));
}

static __printf(2, 0) void emit(void *ctx, const char *fmt, va_list args)
{
	vprintf(fmt, args);
}

/*
 * bpftool emits the C dump sorted by kind rank, resolved name and a
 * member-name hash rather than by type id, so vmlinux.h stays stable
 * across kernel builds that merely reorder BTF. Same ordering here.
 */
struct sort_datum {
	int		index;
	int		type_rank;
	const char	*sort_name;
	const char	*own_name;
	__u64		disambig_hash;
};

static int type_rank(const struct btf *btf, __u32 index, bool has_name)
{
	const struct btf_type *t = btf__type_by_id(btf, index);
	const int kind = btf_kind(t);
	const int max_rank = 10;

	if (t->name_off)
		has_name = true;

	switch (kind) {
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		return has_name ? 1 : 0;
	case BTF_KIND_INT:
	case BTF_KIND_FLOAT:
		return 2;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		return has_name ? 3 : max_rank;
	case BTF_KIND_FUNC_PROTO:
		return has_name ? 4 : max_rank;
	case BTF_KIND_ARRAY:
		if (has_name)
			return type_rank(btf, btf_array(t)->type, has_name);
		return max_rank;
	case BTF_KIND_TYPE_TAG:
	case BTF_KIND_CONST:
	case BTF_KIND_PTR:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_DECL_TAG:
		if (has_name)
			return type_rank(btf, t->type, has_name);
		return max_rank;
	default:
		return max_rank;
	}
}

static const char *type_sort_name(const struct btf *btf, __u32 index,
				  bool from_ref)
{
	const struct btf_type *t = btf__type_by_id(btf, index);

	switch (btf_kind(t)) {
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64: {
		int name_off = t->name_off;

		if (!from_ref && !name_off && btf_vlen(t))
			name_off = btf_kind(t) == BTF_KIND_ENUM64 ?
				btf_enum64(t)->name_off :
				btf_enum(t)->name_off;
		return btf__name_by_offset(btf, name_off);
	}
	case BTF_KIND_ARRAY:
		return type_sort_name(btf, btf_array(t)->type, true);
	case BTF_KIND_TYPE_TAG:
	case BTF_KIND_CONST:
	case BTF_KIND_PTR:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_DECL_TAG:
		return type_sort_name(btf, t->type, true);
	default:
		return btf__name_by_offset(btf, t->name_off);
	}
}

static __u64 hasher(__u64 hash, __u64 val)
{
	return hash * 31 + val;
}

static __u64 name_hasher(__u64 hash, const struct btf *btf, __u32 name_off)
{
	if (!name_off)
		return hash;
	return hasher(hash, str_hash(btf__name_by_offset(btf, name_off)));
}

static __u64 type_disambig_hash(const struct btf *btf, __u32 id,
				bool include_members)
{
	const struct btf_type *t = btf__type_by_id(btf, id);
	__u64 hash = 0;
	__u32 i;

	hash = name_hasher(hash, btf, t->name_off);

	switch (btf_kind(t)) {
	case BTF_KIND_ENUM:
	case BTF_KIND_ENUM64:
		for (i = 0; i < btf_vlen(t); i++) {
			__u32 name_off = btf_is_enum(t) ?
				btf_enum(t)[i].name_off :
				btf_enum64(t)[i].name_off;

			hash = name_hasher(hash, btf, name_off);
		}
		break;
	case BTF_KIND_STRUCT:
	case BTF_KIND_UNION:
		if (!include_members)
			break;
		for (i = 0; i < btf_vlen(t); i++) {
			const struct btf_member *m = btf_members(t) + i;

			hash = name_hasher(hash, btf, m->name_off);
			hash = hasher(hash, type_disambig_hash(btf, m->type, false));
		}
		break;
	case BTF_KIND_TYPE_TAG:
	case BTF_KIND_CONST:
	case BTF_KIND_PTR:
	case BTF_KIND_VOLATILE:
	case BTF_KIND_RESTRICT:
	case BTF_KIND_TYPEDEF:
	case BTF_KIND_DECL_TAG:
		hash = hasher(hash, type_disambig_hash(btf, t->type, include_members));
		break;
	case BTF_KIND_ARRAY: {
		struct btf_array *arr = btf_array(t);

		hash = hasher(hash, arr->nelems);
		hash = hasher(hash, type_disambig_hash(btf, arr->type, include_members));
		break;
	}
	default:
		break;
	}
	return hash;
}

static int type_compare(const void *left, const void *right)
{
	const struct sort_datum *d1 = left;
	const struct sort_datum *d2 = right;
	int r;

	r = d1->type_rank - d2->type_rank;
	r = r ?: strcmp(d1->sort_name, d2->sort_name);
	r = r ?: strcmp(d1->own_name, d2->own_name);
	if (r)
		return r;
	if (d1->disambig_hash != d2->disambig_hash)
		return d1->disambig_hash < d2->disambig_hash ? -1 : 1;
	return d1->index - d2->index;
}

static struct sort_datum *sort_types(const struct btf *btf)
{
	int n = btf__type_cnt(btf);
	struct sort_datum *datums;

	datums = malloc(sizeof(*datums) * n);
	if (!datums)
		return NULL;
	for (int i = 0; i < n; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		struct sort_datum *d = datums + i;

		d->index = i;
		d->type_rank = type_rank(btf, i, false);
		d->sort_name = type_sort_name(btf, i, false);
		d->own_name = btf__name_by_offset(btf, t->name_off);
		d->disambig_hash = type_disambig_hash(btf, i, true);
	}
	qsort(datums, n, sizeof(*datums), type_compare);
	return datums;
}

/*
 * Every function carrying the bpf_kfunc decl tag becomes an extern weak
 * ksym prototype, sorted by name so the output is stable across BTF
 * orderings; bpf_fastcall-tagged ones keep that calling convention.
 */
static int dump_kfuncs(struct btf_dump *d, struct btf *btf)
{
	LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts);
	__u32 cnt = btf__type_cnt(btf), i, j;
	struct ptr_array fastcalls = {};
	struct ptr_array kfuncs = {};
	int err = 0;

	printf("\n/* BPF kfuncs */\n");
	printf("#ifndef BPF_NO_KFUNC_PROTOTYPES\n");

	for (i = 1; i < cnt; i++) {
		const struct btf_type *t = btf__type_by_id(btf, i);
		const struct btf_type *ft;
		const char *name;

		if (!btf_is_decl_tag(t))
			continue;
		if (btf_decl_tag(t)->component_idx != -1)
			continue;
		ft = btf__type_by_id(btf, t->type);
		if (!btf_is_func(ft))
			continue;

		name = btf__name_by_offset(btf, t->name_off);
		if (strncmp(name, KFUNC_DECL_TAG, sizeof(KFUNC_DECL_TAG)) == 0) {
			err = ptr_array_push(ft, &kfuncs);
			if (err)
				goto out;
		}
		if (strncmp(name, FASTCALL_DECL_TAG, sizeof(FASTCALL_DECL_TAG)) == 0) {
			err = ptr_array_push(ft, &fastcalls);
			if (err)
				goto out;
		}
	}

	if (kfuncs.cnt)
		qsort_r(kfuncs.elems, kfuncs.cnt, sizeof(*kfuncs.elems),
			cmp_kfuncs, btf);
	for (i = 0; i < kfuncs.cnt; i++) {
		const struct btf_type *t = kfuncs.elems[i];

		printf("extern ");
		for (j = 0; j < fastcalls.cnt; j++) {
			if (fastcalls.elems[j] == t) {
				printf("__bpf_fastcall ");
				break;
			}
		}
		opts.field_name = btf__name_by_offset(btf, t->name_off);
		err = btf_dump__emit_type_decl(d, t->type, &opts);
		if (err)
			goto out;
		printf(" __weak __ksym;\n");
	}

	printf("#endif\n\n");
out:
	free(fastcalls.elems);
	free(kfuncs.elems);
	return err;
}

static int dump_c(struct btf *btf)
{
	struct sort_datum *datums;
	struct btf_dump *d;
	int cnt, i, err;

	datums = sort_types(btf);
	if (!datums)
		return -ENOMEM;
	d = btf_dump__new(btf, emit, NULL, NULL);
	if (!d) {
		free(datums);
		return -errno;
	}

	printf("#ifndef __VMLINUX_H__\n");
	printf("#define __VMLINUX_H__\n");
	printf("\n");
	printf("#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n");
	printf("#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)\n");
	printf("#endif\n\n");
	printf("#ifndef __ksym\n");
	printf("#define __ksym __attribute__((section(\".ksyms\")))\n");
	printf("#endif\n\n");
	printf("#ifndef __weak\n");
	printf("#define __weak __attribute__((weak))\n");
	printf("#endif\n\n");
	printf("#ifndef __bpf_fastcall\n");
	printf("#if __has_attribute(bpf_fastcall)\n");
	printf("#define __bpf_fastcall __attribute__((bpf_fastcall))\n");
	printf("#else\n");
	printf("#define __bpf_fastcall\n");
	printf("#endif\n");
	printf("#endif\n\n");

	cnt = btf__type_cnt(btf);
	for (i = 0; i < cnt; i++) {
		if (datums[i].index == 0)	/* type 0 is void */
			continue;
		err = btf_dump__dump_type(d, datums[i].index);
		if (err)
			goto out;
	}
	err = dump_kfuncs(d, btf);
	if (err)
		goto out;

	printf("#ifndef BPF_NO_PRESERVE_ACCESS_INDEX\n");
	printf("#pragma clang attribute pop\n");
	printf("#endif\n");
	printf("\n");
	printf("#endif /* __VMLINUX_H__ */\n");
out:
	btf_dump__free(d);
	free(datums);
	return err;
}

int main(int argc, char **argv)
{
	const char *path = argc > 1 ? argv[1] : "/sys/kernel/btf/vmlinux";
	struct btf *btf;
	int err;

	if (argc > 2 || (argc == 2 && strcmp(argv[1], "--help") == 0)) {
		fprintf(stderr, "usage: %s [vmlinux.btf | ELF with .BTF] > vmlinux.h\n",
			argv[0]);
		return 2;
	}
	btf = btf__parse(path, NULL);
	if (!btf) {
		fprintf(stderr, "%s: cannot parse BTF from %s: %s\n",
			argv[0], path, strerror(errno));
		return 1;
	}
	err = dump_c(btf);
	btf__free(btf);
	if (err) {
		fprintf(stderr, "%s: BTF dump failed: %s\n", argv[0], strerror(-err));
		return 1;
	}
	if (fflush(stdout) != 0)
		return 1;
	return 0;
}
