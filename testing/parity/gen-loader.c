// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * gen-loader <object.bpf.o> <name> <reuse-map-mask> <insns> <data> --
 * the loader libbpf's gen_loader generates for an object named <name>,
 * the maps of <reuse-map-mask> taken from the loader's caller: its
 * instructions into <insns> and its data into <data>. The oracle the
 * parity test holds tools/bpf-lskel to.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <bpf/libbpf.h>

static int write_file(const char *path, const void *buf, size_t len)
{
	FILE *f = fopen(path, "wb");
	int ret = 0;

	if (!f)
		return -errno;
	if (len && fwrite(buf, 1, len, f) != len)
		ret = -EIO;
	if (fclose(f) && !ret)
		ret = -errno;
	return ret;
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	LIBBPF_OPTS(gen_loader_opts, gen_opts);
	struct bpf_object *obj;
	char *end;
	int ret;

	if (argc != 6) {
		fprintf(stderr, "usage: %s <object.bpf.o> <name> <reuse-map-mask> <insns> <data>\n",
			argv[0]);
		return 2;
	}
	open_opts.object_name = argv[2];
	errno = 0;
	gen_opts.reuse_map_mask = strtoull(argv[3], &end, 0);
	if (errno || *end || end == argv[3]) {
		fprintf(stderr, "%s: bad mask %s\n", argv[0], argv[3]);
		return 2;
	}
	gen_opts.gen_hash = false;

	obj = bpf_object__open_file(argv[1], &open_opts);
	if (!obj) {
		fprintf(stderr, "%s: cannot open %s: %s\n", argv[0], argv[1], strerror(errno));
		return 1;
	}
	ret = bpf_object__gen_loader(obj, &gen_opts);
	if (!ret)
		ret = bpf_object__load(obj);
	if (ret) {
		fprintf(stderr, "%s: cannot generate the loader of %s: %s\n", argv[0], argv[1],
			strerror(-ret));
		bpf_object__close(obj);
		return 1;
	}
	ret = write_file(argv[4], gen_opts.insns, gen_opts.insns_sz);
	if (!ret)
		ret = write_file(argv[5], gen_opts.data, gen_opts.data_sz);
	bpf_object__close(obj);
	if (ret) {
		fprintf(stderr, "%s: cannot write the loader: %s\n", argv[0], strerror(-ret));
		return 1;
	}
	return 0;
}
