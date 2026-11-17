// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo upatch load and unload, which rust/src/builtin/upatch
 * dispatches to.
 */

#include <endian.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <linux/bpf.h>
#include <linux/perf_event.h>
#include <linux/if_link.h>
#include <linux/keyctl.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

#include <shirudo/misc.h>
#include <shirudo/overflow.h>
#include <shirudo/string.h>

#include "builtin.h"
#include "util/chain.h"
#include "util/config.h"
#include "util/crypto.h"
#include "util/eventlog.h"
#include "util/elf_target.h"
#include "util/format.h"
#include "util/help.h"
#include "util/io.h"
#include "util/json.h"
#include "util/kernel_abi.h"
#include "util/identity.h"
#include "util/keyring.h"
#include "util/tpm.h"
#include "util/log.h"
#include "util/measured.h"
#include "util/options.h"
#include "util/hex.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/report.h"
#include "util/seal.h"
#include "util/timefmt.h"
#include "util/upatch.h"
#include "util/upatch_decode.h"
#include "util/upatch_maps.h"
#include "util/upatch_maps_otel.h"
#include "util/upatch_pins.h"
#include "util/upatch_resolve.h"
#include "util/upatch_verify.h"
#include "util/upatch_table.h"
#include "util/version.h"
#include "util/xdp.h"

#ifndef NFPROTO_IPV6
#define NFPROTO_IPV6			10
#endif
#ifndef NF_INET_PRE_ROUTING
#define NF_INET_PRE_ROUTING		0
#endif
#ifndef NF_IP6_PRI_RAW_BEFORE_DEFRAG
#define NF_IP6_PRI_RAW_BEFORE_DEFRAG	(-450)
#endif

static void rep_fail(struct op_report *rep, const char *phase,
		     const char *cat, int err, const char *msg)
{
	if (!rep)
		return;
	rep->ok = false;
	rep->phase = phase;
	rep->category = cat;
	rep->err = err < 0 ? -err : err;
	if (msg && strscpy(rep->message, msg, sizeof(rep->message)) < 0)
		memcpy(rep->message + sizeof(rep->message) - 4, "...", 4);
}

/*
 * ENOPKG is the kernel's X.509 parser meeting an algorithm it was not
 * built with: an ML-DSA signature without CONFIG_CRYPTO_MLDSA.
 */
static const char *cat_from_load_errno(int e)
{
	switch (e) {
	case EKEYREJECTED:
		return "signature_rejected";
	case ENOKEY:
		return "keyring_missing";
	case ENOPKG:
		return "signature_unsupported";
	case EACCES:
	case EPERM:
		return "lsm_denied";
	default:
		return "verifier_rejected";
	}
}

static const struct help upatch_load_help = {
	.usage   = "shirudo upatch load [--expect-chain=<hex>] "
		   "[--expect-version-id=<hex>]\n"
		   "                       [--no-precheck] [--no-version-check] "
		   "[--report=<path>]\n"
		   "                       <file.upatch>",
	.summary = "Load a signed LOAD .upatch into the target kernel: verify "
		   "the\nsignature, run the loader, pin the resulting link, "
		   "and extend this\nboot's TPM measurement register. "
		   "Target-only.",
	.footer  =
"Examples:\n"
"  shirudo upatch load cve-2026-31431.upatch\n"
"  shirudo upatch load --expect-chain=$(...) foo.upatch\n"
"  shirudo upatch load --report=- foo.upatch | jq",
	.sections   = upatch_op_sections,
	.n_sections = ARRAY_SIZE(upatch_op_sections),
};

static const struct help upatch_unload_help = {
	.usage   = "shirudo upatch unload [--expect-chain=<hex>] "
		   "[--expect-version-id=<hex>]\n"
		   "                       [--no-precheck] [--no-version-check] "
		   "[--report=<path>]\n"
		   "                       <unload-directive.upatch>",
	.summary = "Apply a signed UNLOAD directive: detach the named upatch,\n"
		   "remove its pin, and extend the TPM measurement register "
		   "(unloads\nmove the register forward, never roll it back). "
		   "Target-only.",
	.footer  =
"Examples:\n"
"  shirudo upatch unload cve-2026-31431.unload.upatch\n"
"  shirudo upatch unload --report=- foo.unload.upatch | jq",
	.sections   = upatch_op_sections,
	.n_sections = ARRAY_SIZE(upatch_op_sections),
};

/*
 * The context and the descriptors trailing it mirror
 * tools/lib/bpf/skel_internal.h, which the loader writes and
 * BPF_PROG_TEST_RUN copies back. libbpf's load wrapper exposes no
 * signature or keyring, so the attr is built by hand.
 */

struct loader_ctx {
	__u32		sz;
	__u32		flags;
	__u32		log_level;
	__u32		log_size;
	__u64		log_buf;
};

struct map_desc {
	int		map_fd;
	__u32		max_entries;
	__u64		initial_value;
};

struct prog_desc {
	int		prog_fd;
};

static int loader_map_create(__u32 value_size, const void *excl_prog_hash,
			     __u32 excl_prog_hash_sz)
{
	union bpf_attr attr = {};
	long fd;

	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = 4;
	attr.value_size = value_size ? value_size : 4;
	attr.max_entries = 1;
	attr.excl_prog_hash = ptr_to_u64(excl_prog_hash);
	attr.excl_prog_hash_size = excl_prog_hash_sz;
	strscpy_literal(attr.map_name, "__loader.map");

	fd = syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
	return (int)fd;
}

static int loader_map_update(int map_fd, const void *value, __u32 value_sz)
{
	union bpf_attr attr = {};
	__u8 zero[4] = {};
	__u32 key = 0;
	long ret;

	attr.map_fd = map_fd;
	attr.key = ptr_to_u64(&key);
	attr.value = ptr_to_u64(value_sz ? value : zero);
	attr.flags = 0;
	ret = syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
	return (int)ret;
}

static int loader_map_freeze(int map_fd)
{
	union bpf_attr attr = {};
	long ret;

	attr.map_fd = map_fd;
	ret = syscall(__NR_bpf, BPF_MAP_FREEZE, &attr, sizeof(attr));
	return (int)ret;
}

static int prog_load_signed(const struct bpf_insn *insns, size_t insn_cnt,
			    const char *prog_name,
			    const void *signature, __u32 signature_sz,
			    __s32 keyring_id, int loader_map_fd,
			    char *log_buf, size_t log_sz)
{
	union bpf_attr attr = {};
	int fd_array[1] = { loader_map_fd };
	long fd;

	attr.prog_type = BPF_PROG_TYPE_SYSCALL;
	attr.insn_cnt = (__u32)insn_cnt;
	attr.insns = ptr_to_u64(insns);
	attr.license = ptr_to_u64("Dual BSD/GPL");
	attr.prog_flags = BPF_F_SLEEPABLE;
	attr.log_level = log_buf ? 1 : 0;
	attr.log_size = (__u32)log_sz;
	attr.log_buf = ptr_to_u64(log_buf);
	attr.signature = ptr_to_u64(signature);
	attr.signature_size = signature_sz;
	attr.keyring_id = keyring_id;
	attr.fd_array = ptr_to_u64(fd_array);
	/*
	 * fd_array_cnt makes the verifier resolve the exclusive metadata
	 * map up front and fold its frozen contents into the signed buffer
	 * (insns || metadata). A signed load without it is rejected: the
	 * kernel refuses to bind a map through the sparse fd_array path.
	 */
	attr.fd_array_cnt = 1;
	memcpy(attr.prog_name, prog_name,
	       strnlen(prog_name, sizeof(attr.prog_name)));

	fd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	return (int)fd;
}

/* A NULL name attaches at the attach_btf_id the signed program carries. */
static int prog_attach_raw_tp(int prog_fd)
{
	union bpf_attr attr = {};
	long fd;

	attr.raw_tracepoint.name = 0;
	attr.raw_tracepoint.prog_fd = (__u32)prog_fd;
	fd = syscall(__NR_bpf, BPF_RAW_TRACEPOINT_OPEN, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_attach_cgroup_skb(int prog_fd,
				  enum bpf_attach_type attach_type);

static int prog_attach_btf_link(int prog_fd, enum bpf_attach_type attach_type)
{
	union bpf_attr attr = {};
	long fd;

	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.target_fd = 0;
	attr.link_create.attach_type = attach_type;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_func_name(int prog_fd, const struct bpf_prog_info *base,
			  char *out, size_t cap)
{
	struct bpf_prog_info info = {};
	struct bpf_func_info fi;
	struct btf *btf;
	const struct btf_type *t;
	const char *name;
	void *recs;
	size_t recs_sz;
	__u32 len;
	int ret = 0;

	if (!out || cap == 0)
		return -EINVAL;
	out[0] = '\0';
	if (base->nr_func_info == 0 || base->func_info_rec_size == 0 ||
	    base->btf_id == 0)
		return -ENOENT;
	if (base->func_info_rec_size < sizeof(struct bpf_func_info))
		return -EINVAL;
	recs_sz = (size_t)base->nr_func_info * base->func_info_rec_size;
	recs = xmalloc(recs_sz);
	if (!recs)
		return -ENOMEM;

	info.nr_func_info = base->nr_func_info;
	info.func_info_rec_size = base->func_info_rec_size;
	info.func_info = ptr_to_u64(recs);
	len = sizeof(info);
	if (bpf_prog_get_info_by_fd(prog_fd, &info, &len) != 0) {
		ret = -errno;
		goto out_free;
	}
	memcpy(&fi, recs, sizeof(fi));
	btf = btf__load_from_kernel_by_id(base->btf_id);
	if (!btf) {
		ret = -errno;
		goto out_free;
	}
	t = btf__type_by_id(btf, fi.type_id);
	name = t ? btf__name_by_offset(btf, t->name_off) : NULL;
	if (!name || !name[0]) {
		ret = -ENOENT;
	} else if (strscpy(out, name, cap) < 0) {
		out[0] = '\0';
		ret = -ENAMETOOLONG;
	} else {
		ret = 0;
	}
	btf__free(btf);
out_free:
	xfree(recs, recs_sz);
	return ret;
}

static int cgroup_skb_attach_type_from_name(const char *name,
					    enum bpf_attach_type *attach_type)
{
	if (!name || !name[0])
		return -EINVAL;
	if (str_contains(name, "egress") || str_contains(name, "query") ||
	    str_contains(name, "send")) {
		*attach_type = BPF_CGROUP_INET_EGRESS;
		return 0;
	}
	if (str_contains(name, "ingress") || str_contains(name, "response") ||
	    str_contains(name, "recv") || str_contains(name, "receive")) {
		*attach_type = BPF_CGROUP_INET_INGRESS;
		return 0;
	}
	return -EINVAL;
}

static int prog_attach_cgroup_skb_fallback(int prog_fd,
					   const struct bpf_prog_info *info)
{
	enum bpf_attach_type attach_type;
	char func[128];
	int ret;

	ret = prog_func_name(prog_fd, info, func, sizeof(func));
	if (ret) {
		pr_err("program metadata says raw_tracepoint, but loaded "
		       "program type is cgroup_skb and function name is "
		       "unavailable; rebuild the upatch with cgroup_skb "
		       "metadata");
		return ret;
	}
	ret = cgroup_skb_attach_type_from_name(func, &attach_type);
	if (ret) {
		pr_err("program metadata says raw_tracepoint, but loaded "
		       "program type is cgroup_skb and function '%s' does "
		       "not identify ingress or egress; rebuild the upatch "
		       "with cgroup_skb metadata", func);
		return ret;
	}
	pr_warn("program metadata says raw_tracepoint, but loaded program "
		"type is cgroup_skb; inferring %s from function '%s'",
		attach_type == BPF_CGROUP_INET_EGRESS ? "egress" : "ingress",
		func);
	ret = prog_attach_cgroup_skb(prog_fd, attach_type);
	if (ret >= 0)
		pr_info("attached cgroup_skb fallback as %s",
			attach_type == BPF_CGROUP_INET_EGRESS ?
			"egress" : "ingress");
	return ret;
}

static int prog_attach_default(int prog_fd)
{
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	enum bpf_attach_type attach_type;

	if (bpf_prog_get_info_by_fd(prog_fd, &info, &info_len) != 0)
		return -errno;

	switch (info.type) {
	case BPF_PROG_TYPE_LSM:
		attach_type = BPF_LSM_MAC;
		break;
	case BPF_PROG_TYPE_CGROUP_SKB:
		return prog_attach_cgroup_skb_fallback(prog_fd, &info);
	default:
		return prog_attach_raw_tp(prog_fd);
	}

	return prog_attach_btf_link(prog_fd, attach_type);
}

static int prog_attach_cgroup_skb(int prog_fd, enum bpf_attach_type attach_type)
{
	union bpf_attr attr = {};
	int cgroup_fd, ret;
	long fd;

	cgroup_fd = open("/sys/fs/cgroup", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cgroup_fd < 0)
		return -errno;

	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.target_fd = (__u32)cgroup_fd;
	attr.link_create.attach_type = attach_type;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	ret = fd >= 0 ? (int)fd : -errno;
	close(cgroup_fd);
	return ret;
}

static int prog_attach_netfilter_ipv6_pre_routing(int prog_fd)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts,
		    .netfilter.pf = NFPROTO_IPV6,
		    .netfilter.hooknum = NF_INET_PRE_ROUTING,
		    .netfilter.priority = NF_IP6_PRI_RAW_BEFORE_DEFRAG,
		    .netfilter.flags = 0);

	return bpf_link_create(prog_fd, 0, BPF_NETFILTER, &opts);
}

/* The number after prefix in the file at path, up to INT_MAX. */
static int read_int_file(const char *path, const char *prefix)
{
	size_t skip = strlen(prefix);
	char buf[64];
	__u64 value;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, sizeof(buf) - 1);
	if (n < 0) {
		int e = -errno;

		close(fd);
		return e;
	}
	close(fd);
	if (n == 0)
		return -EINVAL;
	buf[n] = '\0';
	if ((size_t)n < skip || memcmp(buf, prefix, skip) ||
	    parse_u64(buf + skip, digits(buf + skip, (size_t)n - skip),
		      INT_MAX, &value))
		return -EINVAL;
	return (int)value;
}

static int pmu_read_int(const char *pmu, const char *file, const char *prefix)
{
	char path[128];

	if (strsprintf(path, sizeof(path), "/sys/bus/event_source/devices/%s/%s",
		       pmu, file) < 0)
		return -E2BIG;
	return read_int_file(path, prefix);
}

/*
 * A perf event of the kprobe or uprobe PMU on every CPU at name, a kernel
 * symbol or a binary's path, and offset.
 */
static int perf_event_open_probe(const char *pmu, const char *name,
				 __u64 offset, bool retprobe)
{
	struct perf_event_attr attr = {};
	int type, bit;
	long fd;

	type = pmu_read_int(pmu, "type", "");
	if (type < 0)
		return type;
	attr.size = sizeof(attr);
	attr.type = (__u32)type;
	attr.config1 = ptr_to_u64(name);
	attr.config2 = offset;
	if (retprobe) {
		bit = pmu_read_int(pmu, "format/retprobe", "config:");
		if (bit < 0)
			return bit;
		if (bit >= 64)
			return -EINVAL;
		attr.config |= 1ULL << bit;
	}

	fd = syscall(__NR_perf_event_open, &attr,
		     -1 /* pid */, 0 /* cpu */,
		     -1 /* group_fd */, PERF_FLAG_FD_CLOEXEC);
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_attach_perf_event(int prog_fd, int perf_fd)
{
	union bpf_attr attr = {};
	long fd;

	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.target_fd = (__u32)perf_fd;
	attr.link_create.attach_type = BPF_PERF_EVENT;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

static const char *attach_kind_name(__u32 kind)
{
	switch (kind) {
	case UPATCH_ATTACH_RAW_TRACEPOINT:
		return "raw_tracepoint";
	case UPATCH_ATTACH_KPROBE:
		return "kprobe";
	case UPATCH_ATTACH_KRETPROBE:
		return "kretprobe";
	case UPATCH_ATTACH_CGROUP_SKB_INGRESS:
		return "cgroup_skb/ingress";
	case UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		return "cgroup_skb/egress";
	case UPATCH_ATTACH_FMOD_RET:
		return "fmod_ret";
	case UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
		return "netfilter/ipv6-pre-routing";
	case UPATCH_ATTACH_UPROBE_MULTI:
		return "uprobe.multi";
	case UPATCH_ATTACH_XDP:
		return "xdp";
	case UPATCH_ATTACH_KPROBE_MULTI:
		return "kprobe.multi";
	case UPATCH_ATTACH_KRETPROBE_MULTI:
		return "kretprobe.multi";
	case UPATCH_ATTACH_URETPROBE_MULTI:
		return "uretprobe.multi";
	case UPATCH_ATTACH_UPROBE:
		return "uprobe";
	case UPATCH_ATTACH_URETPROBE:
		return "uretprobe";
	default:
		return "unknown";
	}
}

/*
 * UPATCH_ATTACH_RAW_TRACEPOINT is the kind of every program the builder
 * gave none of its own: fentry, fexit, lsm and tp_btf. The link says which.
 */
static const char *link_kind_name(const struct prog_spec *spec, int link_fd)
{
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	const char *kind = NULL;

	if (spec->kind == UPATCH_ATTACH_RAW_TRACEPOINT &&
	    !bpf_link_get_info_by_fd(link_fd, &info, &len))
		kind = upatch_tracing_link_kind(&info);
	return kind ? kind : attach_kind_name(spec->kind);
}

static int prepare_uprobe_targets(struct prog_spec *specs,
				  __u32 nr_progs)
{
	__u32 i;

	for (i = 0; i < nr_progs; i++) {
		struct prog_spec *spec = &specs[i];
		__u8 build_id[UPATCH_BUILD_ID_MAX];
		__u32 build_id_len = 0;
		char proc_path[64];
		struct stat opened_stat;
		int path_fd, fd, ret;

		if (!kind_has_uprobe_target(spec->kind))
			continue;
		path_fd = open(spec->uprobe_path, O_PATH | O_CLOEXEC);
		if (path_fd < 0)
			return -errno;
		if (fstat(path_fd, &spec->target_stat) != 0) {
			ret = -errno;
			close(path_fd);
			return ret;
		}
		if (!S_ISREG(spec->target_stat.st_mode)) {
			close(path_fd);
			return -ESTALE;
		}
		if (strsprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d",
			       path_fd) < 0) {
			close(path_fd);
			return -E2BIG;
		}
		fd = open(proc_path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			ret = -errno;
			close(path_fd);
			return ret;
		}
		close(path_fd);
		if (fstat(fd, &opened_stat) != 0) {
			ret = -errno;
			close(fd);
			return ret;
		}
		if (opened_stat.st_dev != spec->target_stat.st_dev ||
		    opened_stat.st_ino != spec->target_stat.st_ino) {
			close(fd);
			return -ESTALE;
		}
		for (__u32 j = 0; j < spec->nr_uprobe_offsets; j++) {
			if (spec->uprobe_offsets[j] >= (__u64)opened_stat.st_size) {
				close(fd);
				return -ERANGE;
			}
		}
		ret = elf_build_id_fd(fd, build_id, &build_id_len);
		if (ret) {
			close(fd);
			return ret == -EACCES || ret == -EPERM ? ret : -ESTALE;
		}
		if (build_id_len != spec->build_id_len ||
		    memcmp(build_id, spec->build_id, build_id_len) != 0) {
			close(fd);
			return -ESTALE;
		}
		spec->target_fd = fd;
	}
	return 0;
}

static int prog_attach_uprobe_multi(int prog_fd,
				    const struct prog_spec *spec)
{
	union bpf_attr attr = {};
	long fd;

	if (spec->target_fd < 0 || !spec->uprobe_path ||
	    !spec->uprobe_offsets || !spec->nr_uprobe_offsets)
		return -EINVAL;
	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.attach_type = BPF_TRACE_UPROBE_MULTI;
	attr.link_create.uprobe_multi.offsets =
		ptr_to_u64(spec->uprobe_offsets);
	attr.link_create.uprobe_multi.cnt = spec->nr_uprobe_offsets;
	attr.link_create.uprobe_multi.flags = BPF_F_UPROBE_MULTI_PATH_FD;
	if (spec->kind == UPATCH_ATTACH_URETPROBE_MULTI)
		attr.link_create.uprobe_multi.flags |= BPF_F_UPROBE_MULTI_RETURN;
	attr.link_create.uprobe_multi.path_fd = (__u32)spec->target_fd;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

/*
 * The kernel resolves the binary from a path, so name the descriptor
 * prepare_uprobe_targets() checked: the probe lands in that inode, not in
 * whatever spec->uprobe_path names by now.
 */
static int perf_event_open_uprobe(const struct prog_spec *spec)
{
	char path[64];

	if (spec->target_fd < 0 || !spec->uprobe_offsets || spec->nr_uprobe_offsets != 1)
		return -EINVAL;
	if (strsprintf(path, sizeof(path), "/proc/self/fd/%d", spec->target_fd) < 0)
		return -E2BIG;
	return perf_event_open_probe("uprobe", path, spec->uprobe_offsets[0],
				     spec->kind == UPATCH_ATTACH_URETPROBE);
}

static int prog_attach_kprobe_multi(int prog_fd, const struct prog_spec *spec)
{
	union bpf_attr attr = {};
	long fd;

	if (!spec->kprobe_syms || !spec->nr_kprobe_syms)
		return -EINVAL;
	attr.link_create.prog_fd = (__u32)prog_fd;
	attr.link_create.attach_type = BPF_TRACE_KPROBE_MULTI;
	attr.link_create.kprobe_multi.syms = ptr_to_u64(spec->kprobe_syms);
	attr.link_create.kprobe_multi.cnt = spec->nr_kprobe_syms;
	if (spec->kind == UPATCH_ATTACH_KRETPROBE_MULTI)
		attr.link_create.kprobe_multi.flags = BPF_F_KPROBE_MULTI_RETURN;
	fd = syscall(__NR_bpf, BPF_LINK_CREATE, &attr, sizeof(attr));
	return fd >= 0 ? (int)fd : -errno;
}

static int prog_attach_for_spec(int prog_fd,
				const struct prog_spec *spec)
{
	int perf_fd, link_fd;

	switch (spec->kind) {
	case UPATCH_ATTACH_RAW_TRACEPOINT:
		return prog_attach_default(prog_fd);
	case UPATCH_ATTACH_CGROUP_SKB_INGRESS:
		return prog_attach_cgroup_skb(prog_fd,
					      BPF_CGROUP_INET_INGRESS);
	case UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		return prog_attach_cgroup_skb(prog_fd,
					      BPF_CGROUP_INET_EGRESS);
	case UPATCH_ATTACH_FMOD_RET:
		return prog_attach_btf_link(prog_fd, BPF_MODIFY_RETURN);
	case UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
		return prog_attach_netfilter_ipv6_pre_routing(prog_fd);
	case UPATCH_ATTACH_UPROBE_MULTI:
	case UPATCH_ATTACH_URETPROBE_MULTI:
		return prog_attach_uprobe_multi(prog_fd, spec);
	case UPATCH_ATTACH_KPROBE_MULTI:
	case UPATCH_ATTACH_KRETPROBE_MULTI:
		return prog_attach_kprobe_multi(prog_fd, spec);
	case UPATCH_ATTACH_KPROBE:
	case UPATCH_ATTACH_KRETPROBE:
		perf_fd = perf_event_open_probe("kprobe", spec->target, spec->offset,
						spec->kind == UPATCH_ATTACH_KRETPROBE);
		break;
	case UPATCH_ATTACH_UPROBE:
	case UPATCH_ATTACH_URETPROBE:
		perf_fd = perf_event_open_uprobe(spec);
		break;
	default:
		return -EINVAL;
	}
	if (perf_fd < 0)
		return perf_fd;
	link_fd = prog_attach_perf_event(prog_fd, perf_fd);
	close(perf_fd);
	return link_fd;
}

/* The root of the unified cgroup hierarchy. */
#define ROOT_CGROUP_ID		1ULL

/*
 * The site a kprobe, uprobe, cgroup or netfilter program attaches at is
 * named by the caller, and the caller's cgroup namespace and mount of
 * the cgroup tree, network namespace and sysfs are root's to arrange:
 * a cgroup_skb program attached under a namespace root or a bind mount
 * of a subtree guards a corner, a netfilter program in a namespace of
 * its own guards nothing, a kprobe opened through a sysfs that names
 * another PMU lands elsewhere, and each is measured as loaded. What the
 * kernel reports about the link is compared with the spec before the
 * link is pinned; -EXDEV when they differ. A uprobe's file name is not:
 * the descriptor it was opened through fixes the inode, and the name the
 * kernel reports can differ from the signed path by a symlink.
 */
static int link_matches_spec(int link_fd,
			     const struct prog_spec *spec, __u32 ifindex)
{
	char func[UPATCH_ATTACH_TARGET_MAX] = {};
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	bool ret;

	if (spec->kind == UPATCH_ATTACH_KPROBE ||
	    spec->kind == UPATCH_ATTACH_KRETPROBE) {
		info.perf_event.kprobe.func_name = ptr_to_u64(func);
		info.perf_event.kprobe.name_len = sizeof(func);
	}
	if (bpf_link_get_info_by_fd(link_fd, &info, &len))
		return -errno;
	if (info.type == BPF_LINK_TYPE_CGROUP)
		return info.cgroup.cgroup_id == ROOT_CGROUP_ID ?
		       0 : -EXDEV;
	switch (spec->kind) {
	case UPATCH_ATTACH_XDP:
		if (info.type != BPF_LINK_TYPE_XDP || !ifindex ||
		    info.xdp.ifindex != ifindex)
			return -EXDEV;
		/* The caller's namespace was checked before the devices were read. */
		return 0;
	case UPATCH_ATTACH_CGROUP_SKB_INGRESS:
	case UPATCH_ATTACH_CGROUP_SKB_EGRESS:
		return -EXDEV;
	case UPATCH_ATTACH_NETFILTER_IPV6_PRE_ROUTING:
		if (info.type != BPF_LINK_TYPE_NETFILTER ||
		    info.netfilter.pf != NFPROTO_IPV6 ||
		    info.netfilter.hooknum != NF_INET_PRE_ROUTING ||
		    info.netfilter.priority != NF_IP6_PRI_RAW_BEFORE_DEFRAG)
			return -EXDEV;
		return netns_initial();
	case UPATCH_ATTACH_KPROBE:
	case UPATCH_ATTACH_KRETPROBE:
		ret = spec->kind == UPATCH_ATTACH_KRETPROBE;
		if (info.type != BPF_LINK_TYPE_PERF_EVENT ||
		    info.perf_event.type != (ret ? BPF_PERF_EVENT_KRETPROBE :
						   BPF_PERF_EVENT_KPROBE) ||
		    info.perf_event.kprobe.name_len > sizeof(func) ||
		    info.perf_event.kprobe.offset != spec->offset ||
		    strcmp(func, spec->target))
			return -EXDEV;
		return 0;
	case UPATCH_ATTACH_UPROBE:
	case UPATCH_ATTACH_URETPROBE:
		ret = spec->kind == UPATCH_ATTACH_URETPROBE;
		if (info.type != BPF_LINK_TYPE_PERF_EVENT ||
		    info.perf_event.type != (ret ? BPF_PERF_EVENT_URETPROBE :
						   BPF_PERF_EVENT_UPROBE) ||
		    spec->nr_uprobe_offsets != 1 ||
		    info.perf_event.uprobe.offset != spec->uprobe_offsets[0] ||
		    info.perf_event.uprobe.ref_ctr_offset)
			return -EXDEV;
		return 0;
	case UPATCH_ATTACH_UPROBE_MULTI:
	case UPATCH_ATTACH_URETPROBE_MULTI:
		ret = spec->kind == UPATCH_ATTACH_URETPROBE_MULTI;
		if (info.type != BPF_LINK_TYPE_UPROBE_MULTI ||
		    info.uprobe_multi.count != spec->nr_uprobe_offsets ||
		    !!(info.uprobe_multi.flags & BPF_F_UPROBE_MULTI_RETURN) != ret)
			return -EXDEV;
		return 0;
	case UPATCH_ATTACH_KPROBE_MULTI:
	case UPATCH_ATTACH_KRETPROBE_MULTI:
		ret = spec->kind == UPATCH_ATTACH_KRETPROBE_MULTI;
		if (info.type != BPF_LINK_TYPE_KPROBE_MULTI ||
		    info.kprobe_multi.count != spec->nr_kprobe_syms ||
		    !!(info.kprobe_multi.flags & BPF_F_KPROBE_MULTI_RETURN) != ret)
			return -EXDEV;
		return 0;
	case UPATCH_ATTACH_FMOD_RET:
		if (info.type != BPF_LINK_TYPE_TRACING ||
		    info.tracing.attach_type != BPF_MODIFY_RETURN)
			return -EXDEV;
		return 0;
	default:
		if (info.type != BPF_LINK_TYPE_RAW_TRACEPOINT &&
		    info.type != BPF_LINK_TYPE_TRACING)
			return -EXDEV;
		return 0;
	}
}

static int obj_pin(int fd, const char *path)
{
	union bpf_attr attr = {};
	long ret;

	attr.pathname = ptr_to_u64(path);
	attr.bpf_fd = (__u32)fd;
	ret = syscall(__NR_bpf, BPF_OBJ_PIN, &attr, sizeof(attr));
	return ret >= 0 ? 0 : -errno;
}

/*
 * A pin a load left when it died before its link is bound to maps nothing
 * reaches any more: replace it.
 */
static int obj_repin(int fd, const char *path)
{
	if (unlink(path) && errno != ENOENT)
		return -errno;
	return obj_pin(fd, path);
}

static int mkdir_if_absent(const char *path, mode_t mode, bool *made)
{
	if (mkdir(path, mode) == 0) {
		if (made)
			*made = true;
		return 0;
	}
	return errno == EEXIST ? 0 : -errno;
}

static void count_attach_progs(const struct prog_spec *specs,
			       __u32 nr_progs, __u32 *out)
{
	__u32 i, n = 0;

	for (i = 0; i < nr_progs; i++) {
		if (specs[i].role == UPATCH_PROG_ROLE_ATTACH)
			n++;
	}
	*out = n;
}

static int prog_pin_path(char *pin, size_t sz, const char *dir,
			 const char *serializers_dir,
			 const struct prog_spec *spec,
			 __u32 attach_count, __u32 attach_idx)
{
	if (spec->role == UPATCH_PROG_ROLE_SERIALIZER)
		return path_join(pin, sz, serializers_dir, spec->map);
	if (spec->role == UPATCH_PROG_ROLE_TEST_RUN)
		return path_join(pin, sz, dir, "test");
	if (attach_count == 1)
		return path_join(pin, sz, dir, "link");
	return upatch_link_pin(pin, sz, dir, attach_idx);
}

/*
 * Links exist only per device, so with none attached the pin is what keeps
 * the program loaded, and its index is what ties it to its signed classes.
 */
static int pin_xdp_prog(int prog_fd, const char *name, __u32 index)
{
	char pin[PATH_MAX];
	int ret;

	if (upatch_xdp_prog_pin(pin, sizeof(pin), name, index))
		return -ENAMETOOLONG;
	ret = obj_repin(prog_fd, pin);
	if (ret)
		pr_err("pin XDP program %s: %s", pin, strerror(-ret));
	return ret;
}

/*
 * 0 with the link pinned at pin, an enum xdp_attach_err or a negative errno.
 * Unpinned, a closed link detaches, so a failure here leaves the device as
 * it was.
 */
static int xdp_attach_one(int prog_fd, const struct prog_spec *spec,
			  const struct xdp_device *dev, const char *pin)
{
	LIBBPF_OPTS(bpf_link_create_opts, opts, .flags = XDP_FLAGS_DRV_MODE);
	__u64 features = 0;
	int fd, ret;

	ret = xdp_device_verify(dev);
	if (ret)
		return ret;
	/* Before the attach: it can reconfigure a NIC, and reconcile retries. */
	ret = xdp_device_features(dev->ifindex, &features);
	if (ret)
		return ret;
	if (xdp_multibuf_refused(features))
		return XDP_ERR_NO_MULTIBUF;
	fd = bpf_link_create(prog_fd, (int)dev->ifindex, BPF_XDP, &opts);
	if (xdp_attach_unsupported(fd, features))
		return XDP_ERR_NO_NATIVE;
	if (fd == -EBUSY || fd == -EEXIST)
		return XDP_ERR_OCCUPIED;
	/* Not a kernel without the link type: EOPNOTSUPP would read as one. */
	if (xdp_driver_refused(fd)) {
		pr_info("XDP: the driver of %s refused the program: %s",
			dev->name, strerror(-fd));
		return XDP_ERR_DRIVER_SETTINGS;
	}
	if (fd < 0)
		return fd;
	ret = link_matches_spec(fd, spec, dev->ifindex);
	/* Not to be read as xdp_device_verify()'s "the device changed". */
	if (ret == -EXDEV)
		ret = XDP_ERR_LINK_SCOPE;
	if (!ret)
		ret = xdp_device_verify(dev);
	if (!ret)
		ret = obj_pin(fd, pin);
	close(fd);
	return ret;
}

static int attach_xdp_devices(int prog_fd, const struct prog_spec *spec,
			      const struct xdp_device *devices, size_t count,
			      const char *dir, __u32 *pinned)
{
	__u32 attached = 0;
	size_t i;

	for (i = 0; i < count; i++) {
		const struct xdp_device *dev = &devices[i];
		char pin[PATH_MAX + 32];
		int ret;

		if (!xdp_device_selected(devices, count, i, spec->device_classes))
			continue;
		if (*pinned == UINT32_MAX)
			return -EOVERFLOW;
		if (upatch_link_pin(pin, sizeof(pin), dir, *pinned))
			return -ENAMETOOLONG;
		ret = xdp_attach_one(prog_fd, spec, dev, pin);
		if (ret == XDP_ERR_NO_NATIVE) {
			pr_warn("XDP: skipping %s (ifindex %u, class %u): native XDP unsupported",
				dev->name, dev->ifindex, xdp_device_class(dev));
			continue;
		}
		if (xdp_attach_skippable(ret, dev)) {
			pr_warn("XDP: skipping %s (ifindex %u): %s", dev->name,
				dev->ifindex, xdp_attach_strerror(ret));
			continue;
		}
		if (ret) {
			pr_err("XDP: attach %s (ifindex %u): %s", dev->name,
			       dev->ifindex, xdp_attach_strerror(ret));
			return ret;
		}
		(*pinned)++;
		attached++;
		pr_info("XDP: attached %s (ifindex %u, class %u) at %s",
			dev->name, dev->ifindex, xdp_device_class(dev), pin);
	}
	if (!attached)
		pr_info("XDP: no attachable interface matches signed class mask %u yet",
			spec->device_classes);
	return 0;
}

/*
 * Serializers are pinned as programs for `upatch map`; the rest as links.
 * A failure unpins what this call pinned: the upatch is then neither
 * archived nor measured, so none of its programs may stay attached.
 */
static int attach_and_pin_progs(const struct loader_ctx *cx,
				size_t prog_desc_off, __u32 nr_progs,
				const char *name,
				const struct prog_spec *specs)
{
	char dir[PATH_MAX], serializers_dir[PATH_MAX + 16];
	bool made_dir = false, made_serializers = false;
	__u32 i, attach_count = 0, attach_seen = 0;
	struct xdp_device *devices = NULL;
	char pin[PATH_MAX + 32];
	__u32 pinned_links = 0;
	size_t nr_devices = 0;
	bool has_xdp = false;
	bool *made = NULL;
	int test_fd = -1;
	int ret;

	if (nr_progs == 0) {
		pr_warn("upatch carries no programs to attach");
		return 0;
	}
	if (upatch_pin_path(dir, sizeof(dir), name, NULL))
		return -ENAMETOOLONG;
	for (i = 0; i < nr_progs; i++)
		if (specs[i].kind == UPATCH_ATTACH_XDP)
			has_xdp = true;

	ret = mkdir_if_absent(BPFFS_UPATCHES_DIR, 0700, NULL);
	if (ret) {
		pr_err("mkdir %s: %s", BPFFS_UPATCHES_DIR,
		       strerror(-ret));
		return ret;
	}
	if (strsprintf(serializers_dir, sizeof(serializers_dir),
		       "%s/serializers", dir) < 0)
		return -ENAMETOOLONG;
	made = xcalloc(nr_progs, sizeof(*made));
	if (!made)
		return -ENOMEM;
	if (has_xdp) {
		ret = netns_initial();
		if (!ret)
			ret = xdp_devices_read(&devices, &nr_devices);
		if (ret)
			goto out;
		xdp_devices_warn_unclassified(devices, nr_devices);
	}
	ret = mkdir_if_absent(dir, 0700, &made_dir);
	if (ret) {
		pr_err("mkdir %s: %s", dir, strerror(-ret));
		goto out;
	}
	count_attach_progs(specs, nr_progs, &attach_count);

	for (i = 0; i < nr_progs; i++) {
		const struct prog_desc *pd =
			(const void *)((const char *)cx + prog_desc_off +
				       (size_t)i * sizeof(*pd));
		int inner_fd = pd->prog_fd;
		const struct prog_spec *spec = &specs[i];
		const char *kind;
		int link_fd;

		if (inner_fd <= 0) {
			pr_err("loader produced no fd for prog %u", i);
			ret = -EINVAL;
			goto out;
		}
		ret = prog_pin_path(pin, sizeof(pin), dir, serializers_dir,
				    spec, attach_count, attach_seen);
		if (ret)
			goto out;
		if (spec->role == UPATCH_PROG_ROLE_SERIALIZER) {
			ret = mkdir_if_absent(serializers_dir, 0700,
					      &made_serializers);
			if (ret) {
				pr_err("mkdir %s: %s", serializers_dir,
				       strerror(-ret));
				goto out;
			}
			ret = obj_repin(inner_fd, pin);
			if (ret) {
				pr_err("pin serializer %s: %s", pin,
				       strerror(-ret));
				goto out;
			}
			made[i] = true;
			pr_info("upatch load: serializer program %u pinned at %s",
				i, pin);
			continue;
		}
		if (spec->role == UPATCH_PROG_ROLE_TEST_RUN) {
			test_fd = inner_fd;
			ret = obj_repin(inner_fd, pin);
			if (ret) {
				pr_err("pin test-run program %s: %s", pin,
				       strerror(-ret));
				goto out;
			}
			made[i] = true;
			pr_info("upatch load: test-run program %u pinned at %s",
				i, pin);
			continue;
		}
		attach_seen++;
		if (spec->kind == UPATCH_ATTACH_XDP) {
			ret = pin_xdp_prog(inner_fd, name, i);
			if (ret)
				goto out;
			made[i] = true;
			ret = attach_xdp_devices(inner_fd, spec, devices, nr_devices,
						 dir, &pinned_links);
			if (ret)
				goto out;
			continue;
		}
		if (has_xdp) {
			if (pinned_links == UINT32_MAX) {
				ret = -EOVERFLOW;
				goto out;
			}
			ret = upatch_link_pin(pin, sizeof(pin), dir,
					      pinned_links);
			if (ret)
				goto out;
		}

		link_fd = prog_attach_for_spec(inner_fd, spec);
		if (link_fd < 0) {
			if (kind_has_uprobe_target(spec->kind))
				pr_err("attach prog %u (%s %s:%s): %s", i,
				       attach_kind_name(spec->kind),
				       spec->uprobe_path, spec->target,
				       strerror(-link_fd));
			else if (kind_is_kprobe_multi(spec->kind))
				pr_err("attach prog %u (%s, %u symbols): %s", i,
				       attach_kind_name(spec->kind), spec->nr_kprobe_syms,
				       strerror(-link_fd));
			else if (spec->target[0])
				pr_err("attach prog %u (%s %s): %s",
				       i, attach_kind_name(spec->kind),
				       spec->target, strerror(-link_fd));
			else
				pr_err("attach prog %u (%s): %s",
				       i, attach_kind_name(spec->kind),
				       strerror(-link_fd));
			ret = link_fd;
			goto out;
		}
		/* Unpinned, a closed link detaches. */
		ret = link_matches_spec(link_fd, spec, 0);
		if (ret) {
			if (kind_is_kprobe_multi(spec->kind))
				pr_err("attach prog %u (%s, %u symbols): the link "
				       "is not at the site the metadata names: %s",
				       i, attach_kind_name(spec->kind),
				       spec->nr_kprobe_syms, strerror(-ret));
			else
				pr_err("attach prog %u (%s %s): the link is not at "
				       "the site the metadata names: %s", i,
				       attach_kind_name(spec->kind), spec->target, strerror(-ret));
			close(link_fd);
			goto out;
		}
		kind = link_kind_name(spec, link_fd);
		ret = obj_pin(link_fd, pin);
		close(link_fd);
		if (ret) {
			pr_err("pin %s: %s", pin, strerror(-ret));
			goto out;
		}
		made[i] = true;
		if (has_xdp)
			pinned_links++;
		pr_info("upatch load: program %u (%s) pinned at %s",
			i, kind, pin);
	}
	if (test_fd >= 0) {
		__u64 init_ctx[2] = {};
		__u32 retval = 0;

		/* A zero context is the load-time arena initialization call. */
		ret = prog_test_run(test_fd, init_ctx, sizeof(init_ctx),
				    &retval);
		if (ret || (__s32)retval < 0) {
			pr_err("initialize test-run arena: %s",
			       ret ? strerror(-ret) : strerror(-(__s32)retval));
			if (!ret)
				ret = (__s32)retval;
			goto out;
		}
	}
out:
	if (ret) {
		while (pinned_links) {
			pinned_links--;
			if (!upatch_link_pin(pin, sizeof(pin), dir,
					     pinned_links))
				unlink(pin);
		}
		attach_seen = 0;
		for (i = 0; i < nr_progs; i++) {
			if (made[i] && specs[i].kind == UPATCH_ATTACH_XDP &&
			    !upatch_xdp_prog_pin(pin, sizeof(pin), name, i))
				unlink(pin);
			if (made[i] &&
			    !(has_xdp && specs[i].role == UPATCH_PROG_ROLE_ATTACH) &&
			    !prog_pin_path(pin, sizeof(pin), dir,
					   serializers_dir, &specs[i],
					   attach_count, attach_seen))
				unlink(pin);
			if (specs[i].role == UPATCH_PROG_ROLE_ATTACH)
				attach_seen++;
		}
		if (made_serializers)
			rmdir(serializers_dir);
		if (made_dir)
			rmdir(dir);
	}
	xfree(devices, size_mul(nr_devices, sizeof(*devices)));
	xfree(made, nr_progs * sizeof(*made));
	return ret;
}

/*
 * Best effort: the upatch is loaded, so a map that cannot be pinned is
 * logged and left unobservable until the next load. bpffs reserves dots
 * in path components, so libbpf's .bss, .data and .rodata are skipped.
 */
static int pin_upatch_maps(const struct loader_ctx *cx,
			   __u32 nr_maps, __u32 shared_policy_map_idx,
			   __u32 shared_socket_policy_map_idx,
			   const char *name)
{
	char dir[PATH_MAX], maps_dir[PATH_MAX + 8];
	char pin[PATH_MAX + 32];
	__u32 i;
	int ret;

	if (nr_maps == 0)
		return 0;
	if (upatch_pin_path(dir, sizeof(dir), name, NULL))
		return -ENAMETOOLONG;
	if (strsprintf(maps_dir, sizeof(maps_dir), "%s/maps", dir) < 0)
		return -ENAMETOOLONG;
	ret = mkdir_if_absent(maps_dir, 0700, NULL);
	if (ret) {
		pr_warn("upatch maps: mkdir %s: %s (continuing without "
			"map pins)", maps_dir, strerror(-ret));
		return 0;
	}
	for (i = 0; i < nr_maps; i++) {
		const struct map_desc *md =
			(const void *)((const char *)cx +
				       sizeof(struct loader_ctx) +
				       (size_t)i * sizeof(*md));
		struct bpf_map_info info = {};
		__u32 info_len = sizeof(info);
		struct stat st;
		int err;

		if (i == shared_policy_map_idx ||
		    i == shared_socket_policy_map_idx || md->map_fd <= 0)
			continue;
		err = bpf_map_get_info_by_fd(md->map_fd, &info, &info_len);
		if (err) {
			pr_warn("upatch load: map %u info: %s",
				i, strerror(errno));
			continue;
		}
		if (info.name[0] == '\0')
			continue;
		if (strchr(info.name, '.'))
			continue;
		/* upatch-private maps are intentionally not operator-visible. */
		if (str_has_prefix(info.name, "obs_i_"))
			continue;
		if (strsprintf(pin, sizeof(pin), "%s/%s", maps_dir,
			       info.name) < 0)
			continue;
		if (stat(pin, &st) == 0)
			continue;	/* already pinned (idempotent) */
		if (obj_pin(md->map_fd, pin) != 0) {
			pr_warn("upatch load: pin %s: %s", pin,
				strerror(errno));
			continue;
		}
		pr_info("upatch load: map %u (%s) pinned at %s",
			i, info.name, pin);
	}
	return 0;
}

static int open_shared_policy_map(const char *pin, __u32 type,
				  __u32 value_size, __u32 map_flags)
{
	struct bpf_map_info info = {};
	__u32 info_len = sizeof(info);
	int fd, ret;

	fd = bpf_obj_get(pin);
	if (fd < 0)
		return -errno;
	ret = bpf_map_get_info_by_fd(fd, &info, &info_len);
	if (ret) {
		ret = -errno;
		goto err;
	}
	if (info.type != type || info.key_size != sizeof(__s32) ||
	    info.value_size != value_size || info.map_flags != map_flags) {
		ret = -EINVAL;
		goto err;
	}
	if (fd == 0) {
		int copy_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);

		if (copy_fd < 0) {
			ret = -errno;
			goto err;
		}
		close(fd);
		fd = copy_fd;
	}
	return fd;
err:
	close(fd);
	return ret;
}

static int remove_pin_dir(const char *name);

/*
 * The value `upatch unload` checks and every undo pass compares with the
 * records, unforgeable behind bpf2's xattr guard. Pins without it are
 * ones no record covers, which the next upatch command would take out
 * after this load's own record: the load is taken out here, before it.
 */
static int set_pin_payload(const char *name, const __u8 payload[32])
{
	char dir[PATH_MAX];
	int ret;

	if (upatch_pin_path(dir, sizeof(dir), name, NULL))
		return -ENAMETOOLONG;
	if (!setxattr(dir, XATTR_PAYLOAD, payload, 32, 0))
		return 0;
	ret = -errno;
	pr_err("upatch: cannot record the payload on %s: %s; undoing the load",
	       dir, strerror(-ret));
	if (remove_pin_dir(name))
		pr_err("upatch: %s could not be undone; the next upatch command takes it out",
		       name);
	return ret;
}

/* Resolve the kernel BPF keyring and compare it with the frozen record. */
static int trust_anchor_keyring(key_serial_t *keyring, key_serial_t *serial,
				struct op_report *rep)
{
	struct identity id;
	key_serial_t ring;
	int ret;

	ret = identity_read(&id);
	if (ret) {
		pr_err("no trust anchor frozen this boot: %s (run `shirudo "
		       "init`)", strerror(-ret));
		rep_fail(rep, "pre_flight", "keyring_missing", -ret,
			 "no trust anchor frozen this boot");
		return -1;
	}
	ring = keyring_bpf_serial();
	if (id.keyring_type != SIG_KEYRING_BPF ||
	    ring <= 0 || ring != id.keyring_serial) {
		pr_err("the kernel BPF keyring differs from the frozen anchor");
		rep_fail(rep, "pre_flight", "tampered", 0,
			 "BPF keyring is not the frozen anchor");
		return -1;
	}
	*keyring = KEY_SPEC_BPF_KEYRING;
	*serial = ring;
	return 0;
}

/*
 * The loader hands the programs and maps it created over to the caller,
 * whose pins keep them once attached; boot restore applies every archived
 * upatch in one process.
 */
static void close_loader_fds(const struct loader_ctx *cx,
			     __u32 nr_maps, __u32 nr_progs)
{
	const struct map_desc *md = (const void *)(cx + 1);
	const struct prog_desc *pd = (const void *)(md + nr_maps);
	__u32 i;

	for (i = 0; i < nr_maps; i++) {
		if (md[i].map_fd > 0)
			close(md[i].map_fd);
	}
	for (i = 0; i < nr_progs; i++) {
		if (pd[i].prog_fd > 0)
			close(pd[i].prog_fd);
	}
}

/*
 * From the copy the kernel's signature check covered, not from the file
 * again, which may hold other labels by now.
 */
static void apply_policy_labels(const struct upatch *u)
{
	struct upatch_policy_label_header header;
	struct upatch_policy_label_entry entry;
	const __u8 *labels;
	__u32 len, count;

	labels = upatch_signed_policy_labels(u, &len);
	if (!labels)
		return;
	memcpy(&header, labels, sizeof(header));
	count = le32_to_cpu(header.count);
	for (__u32 i = 0; i < count; i++) {
		__u64 current = 0;
		ssize_t n;
		int fd;

		memcpy(&entry, labels + sizeof(header) + i * sizeof(entry),
		       sizeof(entry));
		fd = open(entry.path, O_RDONLY | O_CLOEXEC);
		if (fd < 0) {
			pr_warn("upatch: cannot label %s for policy %s: %s",
				entry.path, entry.policy, strerror(errno));
			continue;
		}
		n = fgetxattr(fd, XATTR_POLICY, &current, sizeof(current));
		if (n < 0 && (errno == ENODATA || errno == EOPNOTSUPP)) {
			current = 0;
		} else if (n != (ssize_t)sizeof(current)) {
			pr_warn("upatch: cannot read policy label on %s: %s",
				entry.path,
				n < 0 ? strerror(errno) : "invalid length");
			close(fd);
			continue;
		}
		current |= le64_to_cpu(entry.bit);
		if (fsetxattr(fd, XATTR_POLICY, &current, sizeof(current), 0))
			pr_warn("upatch: cannot set policy label on %s: %s",
				entry.path, strerror(errno));
		close(fd);
	}
}

/* What the steps of upatch_apply() share. */
struct signed_load {
	const struct upatch	*u;
	const char		*label;
	struct op_report	*rep;		/* NULL for boot restore */
	bool			verify_only;
	char			upatch_name[UPATCH_NAME_MAX + 1];
	key_serial_t		keyring;
	key_serial_t		serial;
	struct prog_spec	*prog_specs;
	char			*vlog;		/* shared PROG_LOAD / TEST_RUN log_buf */
	int			map_fd;
	int			prog_fd;
	struct loader_ctx	*cx;
	size_t			ctx_sz;
	size_t			prog_desc_off;
	int			policy_map_fd;
	int			socket_policy_map_fd;
	__u32			shared_policy_map_idx;
	__u32			shared_socket_policy_map_idx;
	__u32			retval;
};

/*
 * verify_only loads the signed loader purely to make the kernel
 * verify its CMS signature (the unload-directive authorization
 * gate) -- so it deliberately accepts an UNLOAD directive and
 * stops before TEST_RUN/attach.
 */
static int refuse_unload_directive(const struct signed_load *sl)
{
	if (!sl->verify_only && upatch_is_unload(sl->u)) {
		pr_err("upatch load: %s is an UNLOAD directive; "
		       "use `shirudo upatch unload`", sl->label);
		rep_fail(sl->rep, "parse", "parser_rejected", 0,
			 "is an UNLOAD directive");
		return 1;
	}
	return 0;
}

/* Only a BPF payload has a loader for the kernel to verify and run. */
static int refuse_foreign_payload(const struct signed_load *sl)
{
	if (sl->u->hdr.type == UPATCH_TYPE_BPF)
		return 0;
	pr_err("upatch load: %s carries a %s payload, not BPF", sl->label,
	       upatch_type_str(sl->u));
	rep_fail(sl->rep, "parse", "parser_rejected", 0,
		 "not a BPF payload");
	return 1;
}

/*
 * The pin directory, the archive and unload share the raw name. Boot
 * restore reaches here without the command-level check, so validate it
 * again.
 */
static int upatch_signed_name_check(struct signed_load *sl)
{
	struct op_report *rep = sl->rep;

	upatch_header_name(sl->u, sl->upatch_name);
	if (!upatch_name_valid(sl->upatch_name)) {
		pr_err("upatch: refusing unsafe upatch name '%s'",
		       sl->upatch_name);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "unsafe upatch name");
		return 1;
	}
	/* The header's copy of the name is what everything else reads. */
	if (!upatch_name_signed(sl->u)) {
		pr_err("upatch: the name of '%s' is not signature-covered or "
		       "differs from the signed one; rebuild the artifact",
		       sl->upatch_name);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "name not signed");
		return 1;
	}
	return 0;
}

/*
 * The signature authorises the load, but payload_sha256 is what the pin
 * xattr, the register event and the unload match record, so a header
 * value that is not SHA-256(insns || data) is refused even when signed.
 */
static int upatch_payload_check(const struct signed_load *sl)
{
	__u8 content_digest[UPATCH_PAYLOAD_HASH_LEN];
	struct op_report *rep = sl->rep;
	const struct upatch *u = sl->u;
	int err;

	err = upatch_payload_digest(u, content_digest);
	if (err) {
		pr_err("upatch: cannot hash the payload of '%s': %s",
		       sl->upatch_name, strerror(-err));
		rep_fail(rep, "parse", "unknown", -err,
			 "payload hash failed");
		return 1;
	}
	if (memneq_explicit(content_digest, u->hdr.payload_sha256,
			    sizeof(content_digest))) {
		pr_err("upatch: payload_sha256 does not match signed "
		       "content (insns || data); refusing");
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "payload_sha256 mismatch");
		return 1;
	}
	return 0;
}

/*
 * The attach metadata is signed with the data, which the kernel has
 * not verified yet at this point: parsing it strictly here keeps a
 * malformed artifact from the keyring, the load that follows keeps
 * a forged one from the sites it names. Every uprobe target is bound
 * to its recorded GNU build ID before any BPF program loads, and the
 * open target fds stay live through link creation to prevent
 * pathname replacement races.
 */
static int upatch_attach_prepare(struct signed_load *sl)
{
	struct op_report *rep = sl->rep;
	const struct upatch *u = sl->u;
	const void *attach;
	__u32 attach_len;
	int ret;

	if (sl->verify_only)
		return 0;
	attach = upatch_signed_attach(u, &attach_len);
	if (!attach) {
		pr_err("upatch: the attach metadata of '%s' is not "
		       "signature-covered; rebuild the artifact",
		       sl->upatch_name);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "attach metadata not signed");
		return 1;
	}
	ret = prog_specs_parse(attach, attach_len, u->hdr.nr_maps,
			       u->hdr.nr_progs, &sl->prog_specs);
	if (ret) {
		pr_err("upatch program metadata rejected: %s",
		       strerror(-ret));
		rep_fail(rep, "parse", "parser_rejected", -ret,
			 "invalid program attach metadata");
		return 1;
	}
	ret = prepare_uprobe_targets(sl->prog_specs, u->hdr.nr_progs);
	if (ret) {
		const char *cat = cat_from_target_errno(-ret);

		pr_err("uprobe target verification failed (%s): %s",
		       cat, strerror(-ret));
		rep_fail(rep, "target_verify", cat, -ret,
			 "uprobe target verification failed");
		return 1;
	}
	return 0;
}

/* Called right after the bpf() call that failed, whose errno it reads. */
static int loader_map_failed(struct op_report *rep, const char *what,
			     const char *msg)
{
	int err = errno;

	pr_err("%s: %s", what, strerror(err));
	rep_fail(rep, "signed_loader_load", cat_from_load_errno(err),
		 err, msg);
	return 1;
}

/*
 * The metadata map is exclusive to the loader by the digest of its
 * instructions alone, which the verifier enforces; payload_sha256
 * covers insns || data.
 */
static int loader_map_prepare(struct signed_load *sl)
{
	__u8 loader_digest[UPATCH_PAYLOAD_HASH_LEN];
	struct op_report *rep = sl->rep;
	const struct upatch *u = sl->u;

	if (sha256_buffer(upatch_loader(u), u->hdr.loader_insns_len,
			  loader_digest)) {
		pr_err("__loader.map: cannot hash the loader");
		rep_fail(rep, "signed_loader_load", "unknown", EIO,
			 "loader digest failed");
		return 1;
	}
	sl->map_fd = loader_map_create(u->hdr.data_len, loader_digest,
				       sizeof(loader_digest));
	if (sl->map_fd < 0)
		return loader_map_failed(rep, "__loader.map create",
					 "__loader.map create failed");
	if (loader_map_update(sl->map_fd, upatch_data(u), u->hdr.data_len))
		return loader_map_failed(rep, "__loader.map update",
					 "__loader.map update failed");
	/* The kernel refuses a signed load whose bound map is not frozen. */
	if (loader_map_freeze(sl->map_fd))
		return loader_map_failed(rep, "__loader.map freeze",
					 "__loader.map freeze failed");
	return 0;
}

static int loader_prog_load(struct signed_load *sl)
{
	char prog_name[BPF_OBJ_NAME_LEN];
	struct op_report *rep = sl->rep;
	const struct upatch *u = sl->u;
	const struct bpf_insn *insns;
	char *vlog = sl->vlog;
	size_t insn_cnt;
	const void *sig;

	insns = upatch_loader(u);
	sig   = upatch_signature(u);
	insn_cnt = u->hdr.loader_insns_len / sizeof(struct bpf_insn);

	upatch_prog_name(u, prog_name, sizeof(prog_name));

	/*
	 * The kernel attests the metadata itself; the loader carries no
	 * self-check.
	 */
	vlog[0] = '\0';
	sl->prog_fd = prog_load_signed(insns, insn_cnt, prog_name,
				       sig, u->hdr.signature_len,
				       (__s32)sl->keyring, sl->map_fd,
				       vlog, VERIFIER_LOG_MAX);
	if (sl->prog_fd < 0) {
		int e = errno;

		pr_err("BPF_PROG_LOAD (signed loader): %s", strerror(e));
		if (vlog[0])
			fprintf(stderr, "loader verifier log:\n%s\n", vlog);
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(e), e,
			 "BPF_PROG_LOAD of signed loader failed");
		report_set_log(rep, vlog);
		return 1;
	}

	pr_info("%s: signed loader accepted, keyring %d, %zu instructions",
		sl->verify_only ? "upatch unload" : "upatch load",
		(int)sl->serial, insn_cnt);
	return 0;
}

/*
 * The loader creates the programs and maps from kernel context but
 * cannot attach or pin: gen_loader emits no link-create and
 * bpf_sys_bpf() cannot BPF_OBJ_PIN. Its descriptors trail the context,
 * sized from the header's counts.
 */
static int loader_ctx_alloc(struct signed_load *sl)
{
	struct op_report *rep = sl->rep;
	const struct upatch *u = sl->u;
	size_t ctx_sz, prog_desc_off;
	struct loader_ctx *cx;

	prog_desc_off = size_add(sizeof(struct loader_ctx),
				 size_mul(u->hdr.nr_maps,
					  sizeof(struct map_desc)));
	/*
	 * The loader's max_ctx_offset can exceed the descriptor tail, and
	 * TEST_RUN rejects a smaller ctx_size_in, so pad generously.
	 */
	ctx_sz = size_add(size_add(prog_desc_off,
				   size_mul(u->hdr.nr_progs,
					    sizeof(struct prog_desc))),
			  1024);
	/* TEST_RUN takes no larger a context for a syscall program. */
	if (ctx_sz > UINT16_MAX) {
		pr_err("upatch: %u maps and %u programs do not fit the loader context",
		       u->hdr.nr_maps, u->hdr.nr_progs);
		rep_fail(rep, "payload_load", "unknown", E2BIG,
			 "loader context too large");
		return 1;
	}
	cx = xmalloc(ctx_sz);
	if (!cx) {
		pr_err("ctx alloc");
		rep_fail(rep, "payload_load", "unknown", ENOMEM,
			 "ctx alloc failed");
		return 1;
	}
	sl->vlog[0] = '\0';
	cx->sz = (__u32)ctx_sz;
	/*
	 * Keep inner verifier diagnostics enabled without bpftool's full
	 * accepted-program trace; the verbose mode can make valid payload
	 * loads fail with -ENOSPC when the log buffer fills.
	 */
	cx->log_level = 1;
	cx->log_size = VERIFIER_LOG_MAX;
	cx->log_buf = ptr_to_u64(sl->vlog);
	sl->cx = cx;
	sl->ctx_sz = ctx_sz;
	sl->prog_desc_off = prog_desc_off;
	return 0;
}

static int loader_ctx_bind_policy_maps(struct signed_load *sl)
{
	int policy_map_fd, socket_policy_map_fd;
	struct op_report *rep = sl->rep;
	const struct upatch *u = sl->u;
	struct loader_ctx *cx = sl->cx;
	struct map_desc *md;

	if (!u->signed_policy_labels)
		return 0;
	sl->shared_policy_map_idx = u->signed_policy_map_idx;
	sl->shared_socket_policy_map_idx = u->signed_socket_policy_map_idx;
	policy_map_fd =
		open_shared_policy_map(POLICY_PIN,
				       BPF_MAP_TYPE_TASK_STORAGE,
				       2 * sizeof(__u64),
				       BPF_F_NO_PREALLOC);
	if (policy_map_fd < 0) {
		pr_err("upatch load: open shirudo_task_policy: %s",
		       strerror(-policy_map_fd));
		rep_fail(rep, "payload_load", "unknown", -policy_map_fd,
			 "shirudo_task_policy binding failed");
		return 1;
	}
	socket_policy_map_fd =
		open_shared_policy_map(SOCKET_POLICY_PIN,
				       BPF_MAP_TYPE_SK_STORAGE, sizeof(__u64),
				       BPF_F_NO_PREALLOC | BPF_F_CLONE);
	if (socket_policy_map_fd < 0) {
		int err = -socket_policy_map_fd;

		pr_err("upatch load: open shirudo_sock_policy: %s",
		       strerror(err));
		rep_fail(rep, "payload_load", "unknown", err,
			 "shirudo_sock_policy binding failed");
		close(policy_map_fd);
		return 1;
	}
	md = (struct map_desc *)((__u8 *)cx + sizeof(*cx)) +
		sl->shared_policy_map_idx;
	md->map_fd = policy_map_fd;
	md = (struct map_desc *)((__u8 *)cx + sizeof(*cx)) +
		sl->shared_socket_policy_map_idx;
	md->map_fd = socket_policy_map_fd;
	sl->policy_map_fd = policy_map_fd;
	sl->socket_policy_map_fd = socket_policy_map_fd;
	return 0;
}

static int loader_run(struct signed_load *sl)
{
	struct op_report *rep = sl->rep;
	struct loader_ctx *cx = sl->cx;
	const struct upatch *u = sl->u;
	size_t ctx_sz = sl->ctx_sz;
	char *vlog = sl->vlog;
	__u32 retval = 0;
	int ret;

	ret = prog_test_run(sl->prog_fd, cx, (__u32)ctx_sz, &retval);
	if (ret) {
		int err = errno;

		pr_err("BPF_PROG_TEST_RUN: %s", strerror(err));
		if (vlog[0])
			fprintf(stderr, "loader runtime log:\n%s\n", vlog);
		rep_fail(rep, "payload_load", "verifier_rejected", err,
			 "BPF_PROG_TEST_RUN failed");
		report_set_log(rep, vlog);
		return 1;
	}
	if ((__s32)retval < 0) {
		if (sl->policy_map_fd >= 0)
			close(sl->policy_map_fd);
		if (sl->socket_policy_map_fd >= 0)
			close(sl->socket_policy_map_fd);
		/*
		 * The loader closed what it made before it failed; the
		 * numbers left in the context name nothing of ours now.
		 */
		memset(cx + 1, 0, ctx_sz - sizeof(*cx));
		pr_err("loader returned error: %d", (__s32)retval);
		fprintf(stderr, "loader runtime log (len=%zu):\n%.4096s\n",
			strnlen(vlog, VERIFIER_LOG_MAX), vlog);
		rep_fail(rep, "payload_load", "verifier_rejected",
			 -(__s32)retval, "inner loader returned error");
		if (rep)
			rep->loader_return = (__s32)retval;
		report_set_log(rep, vlog);
		return 1;
	}

	pr_info("upatch load: loader ran, %u maps and %u programs",
		u->hdr.nr_maps, u->hdr.nr_progs);
	sl->retval = retval;
	return 0;
}

/*
 * Without a pinned link a program detaches when this one-shot CLI
 * exits.
 */
static int upatch_attach(const struct signed_load *sl)
{
	int ret;

	ret = attach_and_pin_progs(sl->cx, sl->prog_desc_off,
				   sl->u->hdr.nr_progs, sl->upatch_name,
				   sl->prog_specs);
	if (!ret)
		return 0;
	rep_fail(sl->rep, "link_create", cat_from_attach_err(ret),
		 -xdp_attach_errno(ret), "attach or pin failed");
	return 1;
}

static int signed_load_run(struct signed_load *sl)
{
	const struct upatch *u = sl->u;
	int ret;

	if (refuse_unload_directive(sl) || refuse_foreign_payload(sl) ||
	    trust_anchor_keyring(&sl->keyring, &sl->serial, sl->rep) ||
	    upatch_signed_name_check(sl) || upatch_payload_check(sl) ||
	    upatch_attach_prepare(sl) || loader_map_prepare(sl) ||
	    loader_prog_load(sl))
		return 1;
	if (sl->verify_only)
		return 0;
	if (loader_ctx_alloc(sl) || loader_ctx_bind_policy_maps(sl) ||
	    loader_run(sl) || upatch_attach(sl))
		return 1;

	pin_upatch_maps(sl->cx, u->hdr.nr_maps, sl->shared_policy_map_idx,
			sl->shared_socket_policy_map_idx, sl->upatch_name);

	/* After attach and pin, so the value records a loaded upatch. */
	ret = set_pin_payload(sl->upatch_name, u->hdr.payload_sha256);
	if (ret) {
		rep_fail(sl->rep, "link_create", "unknown", ret,
			 "cannot record the payload on the pin directory; the load was undone");
		return 1;
	}
	apply_policy_labels(u);

	pr_audit("upatch load: %s loaded, %u programs, keyring %d",
		 sl->upatch_name, u->hdr.nr_progs, (int)sl->serial);
	if (sl->rep)
		sl->rep->loader_return = (__s32)sl->retval;
	return 0;
}

static void signed_load_release(struct signed_load *sl)
{
	const struct upatch *u = sl->u;

	prog_specs_free(sl->prog_specs, u->hdr.nr_progs);
	xfree(sl->vlog, VERIFIER_LOG_MAX);
	if (sl->cx)
		close_loader_fds(sl->cx, u->hdr.nr_maps, u->hdr.nr_progs);
	xfree(sl->cx, sl->ctx_sz);
	if (sl->prog_fd >= 0)
		close(sl->prog_fd);
	if (sl->map_fd >= 0)
		close(sl->map_fd);
}

/* Shared by `upatch load` and boot restore: one signature-verified path. */
/*
 * Load and run the signed loader of u, which the caller read once and
 * closes: the name the signature covers, the loader the kernel verifies
 * and what the caller then measures and archives are all those bytes.
 * label names them in messages.
 */
static int upatch_apply(struct upatch *u, const char *label, bool verify_only,
			struct op_report *rep)
{
	struct signed_load sl = {
		.u				= u,
		.label				= label,
		.rep				= rep,
		.verify_only			= verify_only,
		.map_fd				= -1,
		.prog_fd			= -1,
		.policy_map_fd			= -1,
		.socket_policy_map_fd		= -1,
		.shared_policy_map_idx		= UPATCH_MAPS_MAX,
		.shared_socket_policy_map_idx	= UPATCH_MAPS_MAX,
	};
	int ret;

	sl.vlog = xmalloc(VERIFIER_LOG_MAX);
	if (!sl.vlog) {
		rep_fail(rep, "parse", "unknown", ENOMEM, "out of memory");
		return 1;
	}
	sl.vlog[0] = '\0';
	ret = signed_load_run(&sl);
	signed_load_release(&sl);
	return ret;
}

static int __upatch_apply(const char *path, bool verify_only,
			  struct op_report *rep)
{
	struct upatch u;
	int ret;

	ret = upatch_open(path, &u);
	if (ret) {
		pr_err("open %s: %s", path, strerror(-ret));
		rep_fail(rep, "parse", "parser_rejected", -ret,
			 "cannot open .upatch");
		return 1;
	}
	ret = upatch_apply(&u, path, verify_only, rep);
	upatch_close(&u);
	return ret;
}

int upatch_restore(const char *path)
{
	return __upatch_apply(path, false, NULL);
}

static int preflight_lsm_pin_failed(int err, struct op_report *rep)
{
	const char *cat = cat_from_pin_errno(err);

	pr_err("upatch: pre-flight refused (category: %s%s): open %s: %s", cat,
	       err == ENOENT ? ", message: lsm_detached" : "", LSM_LINK_PIN,
	       strerror(err));
	rep_fail(rep, "pre_flight", cat, err, "cannot open the LSM link pin");
	return -1;
}

/*
 * The tamper gate before any BPF_PROG_LOAD: a concurrent operator who
 * advanced the register, a detached LSM or a missing anchor surface
 * here, without touching kernel state.
 */
static int upatch_preflight(const char *expect_chain,
			    struct op_report *rep)
{
	__u8 want[CHAIN_DIGEST_LEN], have[CHAIN_DIGEST_LEN];
	char have_hex[2 * CHAIN_DIGEST_LEN + 1];
	char abi_detail[KERNEL_ABI_DETAIL_MAX];
	key_serial_t keyring, serial;
	int fd, ret;

	ret = kernel_abi_check(abi_detail, sizeof(abi_detail));
	if (ret) {
		pr_err("upatch: pre-flight refused (category: "
		       "kernel_abi_unsupported, message: %s)", abi_detail);
		rep_fail(rep, "pre_flight", "kernel_abi_unsupported",
			 EOPNOTSUPP, abi_detail);
		return ret;
	}

	if (trust_anchor_keyring(&keyring, &serial, rep))
		return -1;

	fd = bpf_obj_get(LSM_LINK_PIN);
	if (fd < 0)
		return preflight_lsm_pin_failed(errno, rep);
	close(fd);

	if (!expect_chain)
		return 0;

	if (hex_decode(expect_chain, want, sizeof(want))) {
		pr_err("upatch load: --expect-chain must be %d hex chars",
		       2 * CHAIN_DIGEST_LEN);
		return -1;
	}
	ret = chain_read(have);
	if (ret == -ENODEV) {
		pr_err("upatch load: pre-flight refused (category: tampered, "
		       "message: chain_drift): register unreadable, cannot "
		       "confirm --expect-chain");
		return -1;
	}
	if (ret) {
		pr_err("upatch load: chain read failed: %s", strerror(-ret));
		return -1;
	}
	if (memneq_explicit(want, have, sizeof(want))) {
		hex_encode(have, sizeof(have), have_hex);
		pr_err("upatch load: pre-flight refused (category: tampered, "
		       "message: chain_drift): live register %s is not the "
		       "expected one; run status and pass the refreshed value",
		       have_hex);
		return -1;
	}
	return 0;
}

/*
 * The register and the log advance together, so an extend that could
 * not be logged must not happen: refuse before any state changes.
 */
static int eventlog_room(struct op_report *rep, const char *op)
{
	struct config cfg __cleanup(config_clear);
	int ret;

	ret = config_load(&cfg);
	if (ret) {
		pr_err("upatch %s: configuration unreadable: %s; refused, nothing loaded or extended",
		       op, strerror(-ret));
		rep_fail(rep, "pre_flight", "unknown", -ret,
			 "configuration unreadable");
		return -1;
	}
	if (eventlog_would_exceed(cfg.eventlog_max_bytes)) {
		pr_err("upatch %s: eventlog %s would exceed "
		       "eventlog.max_bytes %llu; refused, nothing loaded or "
		       "extended",
		       op, eventlog_path(), cfg.eventlog_max_bytes);
		rep_fail(rep, "pre_flight", "eventlog_full", ENOSPC,
			 "eventlog would exceed eventlog.max_bytes");
		return -1;
	}
	return 0;
}

/*
 * A caller built from other sources than this target makes every later
 * comparison meaningless, so the version check runs first.
 */
static int version_gate(const char *expect_version_id, bool no_version_check,
			struct op_report *rep, const char *op)
{
	if (no_version_check || !expect_version_id)
		return 0;
	if (strcmp(expect_version_id, shirudo_version_id) != 0) {
		pr_err("upatch %s: version mismatch, the operator expects %s "
		       "and the target is %s; deploy a matching shirudo or pass "
		       "--no-version-check", op, expect_version_id,
		       shirudo_version_id);
		rep_fail(rep, "pre_flight", "version_mismatch", EPERM,
			 "SHIRUDO_VERSION_ID mismatch (operator vs target)");
		return -1;
	}
	return 0;
}

/* Eventlog entry ("upatch_load" / "upatch_unload") mirroring an extend. */
static int format_upatch_event(const char *type, const char *name,
			       const __u8 payload[32],
			       const __u8 event[32], const char *reason,
			       char *buf, size_t size)
{
	struct json_emit e = { .buf = buf, .cap = size };
	char payload_hex[65];

	hex_encode(payload, 32, payload_hex);
	eventlog_record_open(&e, type, event);
	json_obj_open_key(&e, "upatch");
	json_kv_string(&e, "name", name);
	json_kv_string(&e, "payload_sha256", payload_hex);
	json_obj_close(&e);
	if (reason)
		json_kv_string(&e, "reason", reason);
	json_obj_close(&e);

	if (e.err) {
		pr_err("eventlog: %s entry encode failed: %s", type,
		       strerror(-e.err));
		return e.err;
	}
	return 0;
}

/*
 * Each operator operation is its own register event, where boot restore
 * coalesces into one. A missing TPM or register is an error, never an
 * unmeasured success: init guarantees the register exists. *measured
 * tells a failure after the register moved from one before it.
 */
static int upatch_chain_event_locked(const char *tag, const char *type,
				     const char *op, const char *name,
				     const __u8 payload[32],
				     const char *reason, char out_chain[65],
				     bool *measured)
{
	char record[4096], chain_hex[65];
	__u8 event[32], chain[32];
	int ret;

	if (out_chain)
		out_chain[0] = '\0';
	if (measured)
		*measured = false;
	ret = chain_upatch_event(tag, name, payload, event);
	if (ret) {
		pr_err("upatch %s: cannot hash the event (category: tpm_error)",
		       op);
		return ret;
	}
	/*
	 * The record is written out before the extend, which nothing takes
	 * back: one that cannot be encoded then stops the event unmeasured,
	 * where after the extend it would leave the register ahead of the
	 * log.
	 */
	ret = format_upatch_event(type, name, payload, event, reason, record,
				  sizeof(record));
	if (ret)
		return ret;

	ret = chain_extend(event, chain);
	if (ret == -ENODEV) {
		pr_err("upatch %s: TPM register unavailable (category: tpm_error): not measured; shirudo needs the register init bound this boot",
		       op);
		return ret;
	}
	if (ret == -EACCES) {
		pr_err("upatch %s: register is not the one init bound (category: tampered): not measured; the operator must reconcile",
		       op);
		return ret;
	}
	/* A lost answer or a failed read back: the register may have moved. */
	if (ret) {
		pr_err("upatch %s: register extend failed (category: tpm_error): the TPM may have taken the event without its record; the operator must reconcile",
		       op);
		return ret;
	}
	if (measured)
		*measured = true;
	ret = eventlog_append(record);
	if (ret) {
		pr_err("upatch %s: eventlog append failed after the extend: "
		       "register and log disagree; the operator must reconcile",
		       op);
		return ret;
	}
	hex_encode(chain, 32, chain_hex);
	if (out_chain)
		memcpy(out_chain, chain_hex, sizeof(chain_hex));
	pr_audit("upatch %s: %s measured, register %s", op, name, chain_hex);
	return 0;
}

/* A register other than the one init set up is a verdict, not a TPM fault. */
static const char *chain_event_category(int ret, bool measured)
{
	return !measured && ret == -EACCES ? "tampered" : "tpm_error";
}

static int persist_upatch(const char *src, const char *name)
{
	char dst[PATH_MAX];
	int ret;

	ret = seal_mkdir_p(UPATCHES_DIR, 0700);
	if (ret) {
		pr_err("mkdir %s: %s", UPATCHES_DIR, strerror(-ret));
		return ret;
	}
	if (strsprintf(dst, sizeof(dst), "%s/%s.upatch", UPATCHES_DIR,
		       name) < 0)
		return -ENAMETOOLONG;

	return seal_write_file(dst, buf, len, 0644);
}

/*
 * The options and the file of a load or an unload: 0 to go on, or the
 * status to exit with, 0 after help.
 */
static int parse_op_args(int argc, const char **argv, const char *verb,
			 const struct help *help,
			 const char **file, const char **expect_chain,
			 const char **expect_version_id, bool *no_precheck,
			 bool *no_version_check, const char **report)
{
	__u8 want[CHAIN_DIGEST_LEN];
	struct opt_parser p;
	char command[16];
	int opt;

	*file = NULL;
	*expect_chain = NULL;
	*expect_version_id = NULL;
	*no_precheck = false;
	*no_version_check = false;
	*report = NULL;
	if (strsprintf(command, sizeof(command), "upatch %s", verb) < 0)
		return EXIT_USAGE;
	OPT_INIT(&p, command, upatch_op_opts, help, argc, argv, 1);
	for (opt = opt_next(&p); opt != OPT_END; opt = opt_next(&p)) {
		switch (opt) {
		case UPATCH_OP_EXPECT_CHAIN:
			if (hex_decode(p.value, want, sizeof(want))) {
				opt_usage(&p, "--expect-chain must be %d hexadecimal characters",
					  2 * CHAIN_DIGEST_LEN);
				return EXIT_USAGE;
			}
			*expect_chain = p.value;
			break;
		case UPATCH_OP_EXPECT_VERSION_ID:
			*expect_version_id = p.value;
			break;
		case UPATCH_OP_NO_PRECHECK:
			*no_precheck = true;
			break;
		case UPATCH_OP_NO_VERSION_CHECK:
			*no_version_check = true;
			break;
		case UPATCH_OP_REPORT:
			*report = p.value;
			break;
		case OPT_ARG:
			if (*file) {
				opt_usage(&p, "unexpected argument '%s'",
					  p.value);
				return EXIT_USAGE;
			}
			*file = p.value;
			break;
		case OPT_DONE:
			return OPT_DONE;
		default:
			return EXIT_USAGE;
		}
	}
	if (!*file) {
		opt_usage(&p, "takes the .upatch file");
		return EXIT_USAGE;
	}
	return 0;
}

static int wipe_dir_flat(const char *dir)
{
	struct dirent *e;
	int dfd, ret = 0;
	DIR *d;

	d = opendir(dir);
	if (!d)
		return -errno;
	dfd = dirfd(d);
	if (dfd < 0) {
		ret = -errno;
		closedir(d);
		return ret;
	}
	while ((e = readdir(d))) {
		if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, ".."))
			continue;
		if (unlinkat(dfd, e->d_name, 0) != 0 && errno != ENOENT) {
			ret = -errno;
			break;
		}
	}
	closedir(d);
	if (ret)
		return ret;
	if (rmdir(dir) != 0 && errno != ENOENT)
		return -errno;
	return 0;
}

/*
 * 1 when the upatch has its pin directory, loaded or part way there, 0
 * when it has none, otherwise -errno: a pin directory that cannot be
 * looked at may hold a link, so it is never taken for none.
 */
static int upatch_pinned(const char *name)
{
	char dir[PATH_MAX];
	struct stat st;

	if (upatch_pin_path(dir, sizeof(dir), name, NULL))
		return -ENAMETOOLONG;
	if (stat(dir, &st) == 0)
		return 1;
	return errno == ENOENT ? 0 : -errno;
}

/* Unlinking the link pin drops its last reference, which detaches. */
static int remove_pin_dir(const char *name)
{
	char dir[PATH_MAX], maps_dir[PATH_MAX + 8];
	char serializers_dir[PATH_MAX + 16];
	struct stat st;
	int ret;

	if (upatch_pin_path(dir, sizeof(dir), name, NULL))
		return -ENAMETOOLONG;
	if (strsprintf(maps_dir, sizeof(maps_dir), "%s/maps", dir) < 0)
		return -ENAMETOOLONG;
	if (strsprintf(serializers_dir, sizeof(serializers_dir),
		       "%s/serializers", dir) < 0)
		return -ENAMETOOLONG;
	if (stat(dir, &st) != 0)
		return -errno;
	if (stat(maps_dir, &st) == 0) {
		ret = wipe_dir_flat(maps_dir);
		if (ret)
			return ret;
	}
	if (stat(serializers_dir, &st) == 0) {
		ret = wipe_dir_flat(serializers_dir);
		if (ret)
			return ret;
	}
	return wipe_dir_flat(dir);
}

/*
 * The operator's file is read once, into memory: the name and payload
 * measured, the program loaded and the copy archived all come from that
 * one read. A copy on disk, under a name another command can take, or a
 * file read again, could set them apart.
 */
static int read_upatch(const char *src, __u8 **buf, size_t *len,
		       struct upatch *u)
{
	int ret;

	*buf = NULL;
	*len = 0;
	ret = read_file(src, UPATCH_FILE_MAX, buf, len);
	if (ret)
		return ret;
	ret = upatch_open_memory(*buf, *len, u);
	if (ret) {
		xfree(*buf, *len + 1);
		*buf = NULL;
		*len = 0;
	}
	return ret;
}

/* Take a load the register did not record back out: pins, then archive. */
static int undo_load(const char *name)
{
	char persisted[PATH_MAX];
	int ret;

	ret = remove_pin_dir(name);
	if (!ret && strsprintf(persisted, sizeof(persisted), "%s/%s.upatch",
			       UPATCHES_DIR, name) >= 0 &&
	    unlink(persisted) != 0 && errno != ENOENT)
		ret = -errno;
	return ret;
}

static void unload_unmeasured(const char *name)
{
	int ret = undo_load(name);

	if (ret)
		pr_err("upatch load: %s is loaded but not measured and could "
		       "not be undone: %s; operator must reconcile", name,
		       strerror(-ret));
	else
		pr_err("upatch load: %s was not measured; the load was undone",
		       name);
}

/* The rest are still undone when one fails; *ctx keeps the first error. */
static int undo_unmeasured_pin(const char *name, void *ctx)
{
	int *failed = ctx, ret = undo_load(name);

	if (ret) {
		pr_err("upatch: %s is pinned without a record of this boot and could not be undone: %s; operator must reconcile",
		       name, strerror(-ret));
		if (!*failed)
			*failed = ret;
	} else {
		pr_audit("upatch: %s was pinned without a record of this boot; the load was undone",
			 name);
	}
	return 0;
}

static int undo_unmeasured_archive(const char *name, const char *path,
				   void *ctx)
{
	int *failed = ctx, ret = 0;

	if (unlink(path) != 0 && errno != ENOENT)
		ret = -errno;
	if (ret) {
		pr_err("upatch: %s is archived without a record of its load and could not be removed: %s; operator must reconcile",
		       name, strerror(-ret));
		if (!*failed)
			*failed = ret;
	} else {
		pr_audit("upatch: %s was archived without a record of its load; the archive was removed",
			 name);
	}
	return 0;
}

/*
 * A load that a signal stopped between its pins and its extend, or an
 * unload stopped between its append and its detach, left pins the
 * register does not cover, and an archive root brought back after its
 * unload is one the records do not cover either; status reports both
 * meanwhile. Every upatch command undoes them before it acts, under the
 * register lock a load holds from before its pins to its append, so that
 * the scan never takes a load in flight for one that was stopped. A
 * command whose pass cannot read the records or take out what they do
 * not cover refuses: a load beside such pins could share their directory
 * under one name, and its own record would not tell the two apart. The
 * records count only as the register vouches for them: the eventlog and
 * the boot ID are paths root can bind over in a namespace of its own.
 */
static int undo_unmeasured(struct op_report *rep, const char *op)
{
	struct measured_set *set;
	int failed = 0, ret;

	ret = measured_set_boot(&set);
	if (ret == -EBADMSG) {
		pr_err("upatch %s: this boot's eventlog records do not fold to the measurement register; refused, nothing changed",
		       op);
		rep_fail(rep, "tpm_extend", "tampered", -ret,
			 "this boot's records do not fold to the register");
		return ret;
	}
	if (ret) {
		pr_err("upatch %s: cannot read this boot's records: %s; refused, nothing changed",
		       op, strerror(-ret));
		rep_fail(rep, "tpm_extend", "tpm_error", ret,
			 "cannot read this boot's records");
		return ret;
	}
	ret = measured_unmeasured_pins(set, undo_unmeasured_pin, &failed);
	if (ret >= 0)
		ret = measured_unmeasured_archives(set, undo_unmeasured_archive,
						   &failed);
	measured_set_free(set);
	if (ret >= 0 && !failed)
		return 0;
	ret = ret < 0 ? ret : failed;
	pr_err("upatch %s: cannot undo what this boot's records do not cover: %s; refused",
	       op, strerror(-ret));
	rep_fail(rep, "tpm_extend", "tpm_error", ret,
		 "cannot undo what this boot's records do not cover");
	return ret;
}

struct load_args {
	const char	*file;
	const char	*expect_chain;
	const char	*expect_version_id;
	const char	*report;
	bool		no_precheck;
	bool		no_version_check;
	bool		loaded_is_done;
};

static int upatch_load(const struct load_args *args)
{
	const char *file = args->file, *report = args->report;
	char name[UPATCH_NAME_MAX + 1] = {};
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN], live[UPATCH_PAYLOAD_HASH_LEN];
	struct op_report rep = { .op = "upatch_load", .phase = "done" };
	struct upatch u = {};
	bool measured;
	int err, lock = -1, ret = 1;
	__u8 *buf = NULL;
	size_t len = 0;

	rep.path = file;

	if (version_gate(args->expect_version_id, args->no_version_check, &rep,
			 "load") != 0)
		goto done;

	err = read_upatch(file, &buf, &len, &u);
	if (err) {
		pr_err("upatch load: read %s: %s", file, strerror(-err));
		rep_fail(&rep, "parse", "parser_rejected", -err,
			 "cannot read .upatch");
		goto done;
	}
	upatch_header_name(&u, name);
	memcpy(payload, u.hdr.payload_sha256, sizeof(payload));
	hex_encode(payload, sizeof(payload), rep.payload_hex);
	rep.name = name;

	if (args->no_precheck) {
		pr_warn("upatch load: --no-precheck, pre-flight state check "
			"skipped");
	} else if (upatch_preflight(args->expect_chain, &rep) != 0) {
		if (!rep.category)
			rep_fail(&rep, "pre_flight", "tampered", EPERM,
				 "pre-flight check failed");
		goto done;
	}

	if (eventlog_room(&rep, "load") != 0)
		goto done;
	if (!upatch_name_valid(name)) {
		pr_err("upatch load: refusing unsafe upatch name '%s'", name);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "unsafe upatch name");
		goto done;
	}
	lock = eventlog_lock();
	if (lock < 0) {
		pr_err("upatch load: cannot take the register lock: %s "
		       "(category: tpm_error); nothing loaded",
		       strerror(-lock));
		rep_fail(&rep, "tpm_extend", "tpm_error", -lock,
			 "cannot take the register lock");
		goto done;
	}
	if (undo_unmeasured(&rep, "load"))
		goto done;
	/*
	 * Past the undo pass a payload on the pins is a load this boot's
	 * records hold, and only an unload removes it. A load over a live
	 * upatch rebinds its serializer pins to maps nothing reads, and an
	 * undo of that load would take the live one's pins and archive with
	 * it. An install of the very payload loaded is done: bpm retries one
	 * that a stop cut off between this load and its own record.
	 */
	if (!upatch_pin_payload(name, live)) {
		if (args->loaded_is_done &&
		    !memcmp(live, payload, sizeof(live))) {
			pr_info("upatch load: %s is already loaded with this payload",
				name);
			rep.ok = true;
			rep.category = "already_loaded";
			ret = 0;
			goto done;
		}
		pr_err("upatch load: %s is already loaded; unload it with its signed directive first",
		       name);
		rep_fail(&rep, "pin", "already_loaded", EEXIST,
			 "upatch already loaded");
		goto done;
	}

	if (upatch_apply(&u, file, false, &rep) != 0)
		goto done;

	/*
	 * Persist before measuring: the archive is the intent boot restore
	 * replays, and an event for an upatch that will not survive a reboot
	 * would drift from it. A load whose archive copy fails, a file system
	 * root filled say, or one the register then refuses to take is
	 * undone, pins and archive, so that no upatch runs unmeasured; a
	 * caller who stops this process first gets the same from the next
	 * upatch command, and from the next init, which refuses to restore
	 * what the register does not cover.
	 */
	err = persist_upatch(buf, len, name);
	if (err) {
		pr_err("upatch load: loaded but not archived under %s: %s; "
		       "not measured", UPATCHES_DIR, strerror(-err));
		unload_unmeasured(name);
		rep_fail(&rep, "persist", "unknown", -err,
			 "persist failed; the load was undone");
		goto done;
	}

	err = upatch_chain_event_locked("shirudo-upatch", "upatch_load",
					"load", name, payload, NULL,
					rep.chain_after, &measured);
	if (err) {
		if (!measured)
			unload_unmeasured(name);
		rep_fail(&rep, "tpm_extend", chain_event_category(err, measured),
			 err, measured ?
			 "eventlog append failed after the extend" :
			 "chain extend failed; the load was undone");
		goto done;
	}
	rep.ok = true;
	rep.phase = "done";
	rep.tpm_present = rep.chain_after[0] != '\0';
	ret = 0;
done:
	eventlog_unlock(lock);
	if (ret == 1 && rep.category &&
	    !strcmp(rep.category, "attach_target_missing"))
		ret = UPATCH_INSTALL_TARGET_MISSING;
	upatch_close(&u);
	xfree(buf, len + 1);
	if (report)
		report_emit(report, &rep);
	report_free(&rep);
	return ret;
}

int cmd_upatch_load(int argc, const char **argv)
{
	struct load_args args = {};
	int err;

	err = parse_op_args(argc, argv, "load", &upatch_load_help,
			    &args.file, &args.expect_chain,
			    &args.expect_version_id, &args.no_precheck,
			    &args.no_version_check, &args.report);
	if (err)
		return err == OPT_DONE ? 0 : err;
	return upatch_load(&args);
}

int cmd_upatch_unload(int argc, const char **argv)
{
	const char *file, *expect_chain, *expect_version_id, *report;
	struct op_report rep = { .op = "upatch_unload", .phase = "done" };
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN] = {};
	char name[UPATCH_NAME_MAX + 1] = {};
	bool no_precheck, no_version_check;
	int err, lock = -1, pinned, ret = 1;
	char persisted[PATH_MAX];
	struct upatch u = {};
	__u8 *buf = NULL;
	size_t len = 0;

	err = parse_op_args(argc, argv, "unload", &upatch_unload_help,
			    &file, &expect_chain, &expect_version_id,
			    &no_precheck, &no_version_check, &report);
	if (err)
		return err == OPT_DONE ? 0 : err;
	rep.path = file;

	if (version_gate(expect_version_id, no_version_check, &rep, "unload") != 0)
		goto done;

	/*
	 * Read once, as a load is: the target and the payload the kernel's
	 * signature check covers must be the bytes acted on after it, and a
	 * file of root's is root's to rewrite between the two.
	 */
	err = read_upatch(file, &buf, &len, &u);
	if (err) {
		pr_err("upatch unload: read %s: %s", file, strerror(-err));
		rep_fail(&rep, "parse", "parser_rejected", -err,
			 "cannot read .upatch");
		goto done;
	}
	if (!upatch_is_unload(&u)) {
		pr_err("upatch unload: %s is a LOAD upatch; use "
		       "`shirudo upatch load`", file);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "is a LOAD upatch");
		goto done;
	}
	/*
	 * The target's name and the payload it is expected to carry are the
	 * directive's signed sections; the header's name must be the same,
	 * since status and the package tooling read it.
	 */
	if (!upatch_name_signed(&u) || !upatch_signed_unload_payload(&u)) {
		pr_err("upatch unload: the target of %s is not "
		       "signature-covered or differs from the header; rebuild "
		       "the directive", rep.path);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "directive target not signed");
		goto done;
	}
	upatch_header_name(&u, name);
	memcpy(payload, upatch_signed_unload_payload(&u), sizeof(payload));
	rep.name = name;
	hex_encode(payload, sizeof(payload), rep.payload_hex);

	if (!upatch_name_valid(name)) {
		pr_err("upatch unload: refusing unsafe upatch name '%s'", name);
		rep_fail(&rep, "parse", "parser_rejected", 0,
			 "unsafe upatch name");
		goto done;
	}
	if (strsprintf(persisted, sizeof(persisted), "%s/%s.upatch",
		       UPATCHES_DIR, name) < 0)
		goto done;

	if (no_precheck) {
		pr_warn("upatch unload: --no-precheck, pre-flight state check "
			"skipped");
	} else if (upatch_preflight(expect_chain, &rep) != 0) {
		if (!rep.category)
			rep_fail(&rep, "pre_flight", "tampered", EPERM,
				 "pre-flight check failed");
		goto done;
	}

	if (eventlog_room(&rep, "unload") != 0)
		goto done;

	lock = eventlog_lock();
	if (lock < 0) {
		pr_err("upatch unload: cannot take the register lock: %s "
		       "(category: tpm_error); nothing detached",
		       strerror(-lock));
		rep_fail(&rep, "tpm_extend", "tpm_error", -lock,
			 "cannot take the register lock");
		goto done;
	}
	if (undo_unmeasured(&rep, "unload"))
		goto done;
	/* A bad signature fails here, before anything is removed. */
	if (upatch_apply(&u, file, true, &rep) != 0) {
		pr_err("upatch unload: signature verification failed; refusing");
		goto done;
	}

	/*
	 * The live value is the xattr bpf2 guards; the expected one is
	 * signed, so a directive detaches the upatch its signer made it
	 * for and nothing else. A pin whose value cannot be read is refused;
	 * no pin at all is the already-unloaded case below.
	 */
	{
		__u8 live[UPATCH_PAYLOAD_HASH_LEN];
		int xrc;

		xrc = upatch_pin_payload(name, live);
		if (xrc == 0) {
			if (memneq_explicit(live, payload, sizeof(payload))) {
				pr_err("upatch unload: payload_mismatch, the "
				       "upatch loaded under '%s' is not what the "
				       "directive expects; refused", name);
				rep_fail(&rep, "pin", "payload_mismatch", EPERM,
					 "loaded payload does not match directive");
				goto done;
			}
			pr_info("upatch unload: %s carries the directive's payload",
				name);
		} else if (xrc != -ENOENT) {
			pr_err("upatch unload: cannot read the payload "
			       "recorded for '%s': %s; refusing", name,
			       strerror(-xrc));
			rep_fail(&rep, "pin", "payload_mismatch", -xrc,
				 "payload xattr unreadable");
			goto done;
		}
	}

	/*
	 * An archive with no pins is one init could not restore, or one an
	 * interrupted unload left: the directive removes it only when it is
	 * the payload the directive names, as it would its pins.
	 */
	pinned = upatch_pinned(name);
	if (pinned < 0) {
		pr_err("upatch unload: cannot look at the pins of %s: %s; "
		       "nothing detached", name, strerror(-pinned));
		rep_fail(&rep, "pin", "unknown", -pinned,
			 "pin directory unreadable");
		goto done;
	}
	if (!pinned) {
		struct upatch archived;

		err = upatch_archive_verify(name, payload, &archived);
		if (!err) {
			upatch_close(&archived);
			if (unlink(persisted) != 0 && errno != ENOENT)
				pr_warn("upatch unload: could not remove %s: %s",
					persisted, strerror(errno));
		} else if (err != -ESTALE || !access(persisted, F_OK)) {
			pr_err("upatch unload: payload_mismatch, %s is not the "
			       "upatch the directive expects; it stays",
			       persisted);
			rep_fail(&rep, "pin", "payload_mismatch",
				 err == -ESTALE ? EPERM : -err,
				 "archived payload does not match directive");
			goto done;
		}
		pr_info("upatch unload: %s already unloaded (no pin)", name);
		pr_audit("upatch unload: name=%s already_unloaded", name);
		rep.ok = true;
		rep.phase = "done";
		rep.category = "already_unloaded";
		strscpy_literal(rep.message, "already unloaded");
		ret = 0;
		goto done;
	}

	/*
	 * Measured before it happens: a detach the register does not know
	 * is what a caller who stops this process, or the TPM's path, at
	 * the right moment would get. The other way round, a detach that
	 * fails after the event leaves a shield the register says is gone,
	 * which the next status reports and the operator can repeat.
	 */
	err = upatch_chain_event_locked("shirudo-unload", "upatch_unload",
					"unload", name, payload, NULL,
					rep.chain_after, NULL);
	if (err) {
		rep_fail(&rep, "tpm_extend", chain_event_category(err, false),
			 err, "chain extend failed; nothing detached");
		goto done;
	}

	err = remove_pin_dir(name);
	if (err) {
		pr_err("upatch unload: measured, but failed to remove the pin "
		       "for %s: %s; repeat the unload", name, strerror(-err));
		rep_fail(&rep, "pin", "detach_failed", -err,
			 "pin removal failed after the event was measured");
		goto done;
	}
	pr_info("upatch unload: %s detached and unpinned", name);

	if (unlink(persisted) != 0 && errno != ENOENT)
		pr_warn("upatch unload: could not remove %s: %s",
			persisted, strerror(errno));
	rep.ok = true;
	rep.phase = "done";
	rep.tpm_present = rep.chain_after[0] != '\0';
	ret = 0;
done:
	eventlog_unlock(lock);
	if (ret != 0)
		pr_err("upatch unload failed: name=%s phase=%s category=%s "
		       "err=%d (%s) message=%s",
		       name[0] ? name : "(unknown)",
		       rep.phase ? rep.phase : "(unknown)",
		       rep.category ? rep.category : "(unknown)",
		       rep.err,
		       rep.err ? strerror(rep.err) : "none",
		       rep.message[0] ? rep.message : "(none)");
	upatch_close(&u);
	xfree(buf, len + 1);
	if (report)
		report_emit(report, &rep);
	report_free(&rep);
	return ret;
}

static int upatch_purge_locked(const char *name, const struct cert *signer,
			       const char *reason)
{
	__u8 payload[UPATCH_PAYLOAD_HASH_LEN] = {};
	char persisted[PATH_MAX];
	int fd, loaded, ret;
	struct upatch u;

	if (strsprintf(persisted, sizeof(persisted), "%s/%s.upatch",
		       UPATCHES_DIR, name) < 0)
		return -ENAMETOOLONG;
	ret = seal_open_read(persisted);
	if (ret < 0)
		return ret;
	fd = ret;
	ret = upatch_open_fd(fd, &u);
	close(fd);
	if (ret)
		return ret;
	ret = cms_signed_by(upatch_signature(&u), u.hdr.signature_len, signer);
	memcpy(payload, u.hdr.payload_sha256, sizeof(payload));
	upatch_close(&u);
	if (ret != 1)
		return ret < 0 ? ret : -ESTALE;

	/* As for unload: the event first, then the detach it describes. */
	loaded = upatch_pinned(name);
	if (loaded < 0)
		return loaded;
	if (loaded) {
		ret = upatch_chain_event_locked("shirudo-unload",
						"upatch_unload", "purge", name,
						payload, reason, NULL, NULL);
		if (ret)
			return ret;
		ret = remove_pin_dir(name);
		if (ret) {
			pr_err("upatch purge: measured, but failed to remove "
			       "the pin for %s: %s", name, strerror(-ret));
			return ret;
		}
	}
	if (unlink(persisted) != 0 && errno != ENOENT) {
		pr_err("upatch purge: could not remove %s: %s", persisted,
		       strerror(errno));
		return -errno;
	}
	pr_audit("upatch purge: name=%s reason=%s %s", name, reason,
		 loaded ? "detached" : "archive_only");
	return loaded ? 1 : 0;
}

/*
 * Under the register lock from the archive read to its unlink, as a
 * load and an unload hold it, so that a load of the name that takes the
 * lock after the purge's event is not the one the purge then removes,
 * and with the signer checked on what that read finds: a caller's scan
 * ran before the lock, and an upgrade may have replaced the upatch since
 * with one another key signed.
 */
int upatch_purge(const char *name, const struct cert *signer,
		 const char *reason)
{
	int lock, ret;

	if (!upatch_name_valid(name))
		return -EINVAL;
	lock = eventlog_lock();
	if (lock < 0) {
		pr_err("upatch purge: cannot take the register lock: %s "
		       "(category: tpm_error); nothing measured or detached",
		       strerror(-lock));
		return lock;
	}
	ret = upatch_purge_locked(name, signer, reason);
	eventlog_unlock(lock);
	return ret;
}

/*
 * Package installs take the same path as the upatch commands, and take
 * the payload already loaded under the name for one done.
 */
int upatch_install(const char *path)
{
	const struct load_args args = {
		.file		= path,
		.no_precheck	= true,
		.loaded_is_done	= true,
	};

	return upatch_load(&args);
}

int upatch_remove(const char *path)
{
	const char *argv[] = { "unload", "--no-precheck", path };

	return cmd_upatch_unload(3, argv);
}
