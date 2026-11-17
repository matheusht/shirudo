// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The signed upatch loader, under `upatch load` and `unload` of
 * rust/src/builtin/upatch/ops.rs and init's boot restore.
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
#include "util/help.h"
#include "util/io.h"
#include "util/json.h"
#include "util/kernel_abi.h"
#include "util/identity.h"
#include "util/keyring.h"
#include "util/tpm.h"
#include "util/log.h"
#include "util/measured.h"
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
#include "util/upatch_resolve.h"
#include "util/upatch_table.h"
#include "util/version.h"

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
	if (msg)
		strscpy(rep->message, msg, sizeof(rep->message));
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

static int loader_map_create(const char *name, __u32 value_size,
			     const void *excl_prog_hash,
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
	strscpy(attr.map_name, name, sizeof(attr.map_name));

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
	} else if (strlen(name) >= cap) {
		ret = -ENAMETOOLONG;
	} else {
		strscpy(out, name, cap);
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
	if (strstr(name, "egress") || strstr(name, "query") ||
	    strstr(name, "send")) {
		*attach_type = BPF_CGROUP_INET_EGRESS;
		return 0;
	}
	if (strstr(name, "ingress") || strstr(name, "response") ||
	    strstr(name, "recv") || strstr(name, "receive")) {
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

	strscpy(func, info->name, sizeof(func));
	ret = prog_func_name(prog_fd, info, func, sizeof(func));
	if (ret && !func[0]) {
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

static int determine_kprobe_perf_type(void)
{
	return read_int_file("/sys/bus/event_source/devices/kprobe/type", "");
}

static int determine_kprobe_retprobe_bit(void)
{
	return read_int_file("/sys/bus/event_source/devices/kprobe/format/retprobe",
			     "config:");
}

static int perf_event_open_kprobe(const char *target, __u64 offset,
				  bool retprobe)
{
	struct perf_event_attr attr = {};
	int type, bit;
	long fd;

	type = determine_kprobe_perf_type();
	if (type < 0)
		return type;
	attr.size = sizeof(attr);
	attr.type = (__u32)type;
	attr.config1 = ptr_to_u64(target);
	attr.config2 = offset;
	if (retprobe) {
		bit = determine_kprobe_retprobe_bit();
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
	default:
		return "unknown";
	}
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

		if (spec->kind != UPATCH_ATTACH_UPROBE_MULTI)
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
		ret = fd < 0 ? -errno : 0;
		close(path_fd);
		if (ret)
			return ret;
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
	attr.link_create.uprobe_multi.path_fd = (__u32)spec->target_fd;
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
		return prog_attach_uprobe_multi(prog_fd, spec);
	case UPATCH_ATTACH_KPROBE:
	case UPATCH_ATTACH_KRETPROBE:
		perf_fd = perf_event_open_kprobe(spec->target, spec->offset,
						 spec->kind == UPATCH_ATTACH_KRETPROBE);
		if (perf_fd < 0)
			return perf_fd;
		link_fd = prog_attach_perf_event(prog_fd, perf_fd);
		close(perf_fd);
		return link_fd;
	default:
		return -EINVAL;
	}
}

/* The initial network namespace's cookie, NET_NS_INIT_ID in linux/nsfs.h. */
#define NET_NS_INIT_COOKIE	7ULL
/* The root of the unified cgroup hierarchy. */
#define ROOT_CGROUP_ID		1ULL
#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE			71
#endif

/* A netfilter link hooks the caller's network namespace. */
static int netns_initial(void)
{
	socklen_t len = sizeof(__u64);
	__u64 cookie = 0;
	int fd, ret;

	fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	ret = getsockopt(fd, SOL_SOCKET, SO_NETNS_COOKIE, &cookie, &len) ?
	     -errno : 0;
	close(fd);
	if (ret)
		return ret;
	return cookie == NET_NS_INIT_COOKIE ? 0 : -EXDEV;
}

/*
 * The site a kprobe, uprobe, cgroup or netfilter program attaches at is
 * named by the caller, and the caller's cgroup namespace and mount of
 * the cgroup tree, network namespace and sysfs are root's to arrange:
 * a cgroup_skb program attached under a namespace root or a bind mount
 * of a subtree guards a corner, a netfilter program in a namespace of
 * its own guards nothing, a kprobe opened through a sysfs that names
 * another PMU lands elsewhere, and each is measured as loaded. What the
 * kernel reports about the link is compared with the spec before the
 * link is pinned; -EXDEV when they differ.
 */
static int link_matches_spec(int link_fd,
			     const struct prog_spec *spec)
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
	case UPATCH_ATTACH_UPROBE_MULTI:
		if (info.type != BPF_LINK_TYPE_UPROBE_MULTI ||
		    info.uprobe_multi.count != spec->nr_uprobe_offsets)
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
	int n;

	if (spec->role == UPATCH_PROG_ROLE_SERIALIZER)
		n = strsprintf(pin, sz, "%s/%s", serializers_dir, spec->map);
	else if (spec->role == UPATCH_PROG_ROLE_TEST_RUN)
		n = strsprintf(pin, sz, "%s/test", dir);
	else if (attach_count == 1)
		n = strsprintf(pin, sz, "%s/link", dir);
	else
		n = strsprintf(pin, sz, "%s/link_%u", dir, attach_idx);
	return n < 0 ? -ENAMETOOLONG : 0;
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
	__u32 i, attach_count = 0, attach_seen = 0;
	bool made_dir = false, made_serializers = false;
	char pin[PATH_MAX + 32];
	bool *made = NULL;
	int test_fd = -1;
	int ret;

	if (nr_progs == 0) {
		pr_warn("upatch carries no programs to attach");
		return 0;
	}
	if (upatch_pin_path(dir, sizeof(dir), name, NULL))
		return -ENAMETOOLONG;

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
			struct stat st;

			ret = mkdir_if_absent(serializers_dir, 0700,
					      &made_serializers);
			if (ret) {
				pr_err("mkdir %s: %s", serializers_dir,
				       strerror(-ret));
				goto out;
			}
			/*
			 * A pin a load left when it died before its link is
			 * bound to maps nothing reaches any more: replace it.
			 */
			if (stat(pin, &st) == 0 && unlink(pin)) {
				ret = -errno;
				pr_err("unlink stale serializer pin %s: %s", pin,
				       strerror(-ret));
				goto out;
			}
			ret = obj_pin(inner_fd, pin);
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
			struct stat st;

			test_fd = inner_fd;
			if (stat(pin, &st) == 0 && unlink(pin)) {
				ret = -errno;
				pr_err("unlink stale test-run pin %s: %s", pin,
				       strerror(-ret));
				goto out;
			}
			ret = obj_pin(inner_fd, pin);
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

		link_fd = prog_attach_for_spec(inner_fd, spec);
		if (link_fd < 0) {
			if (spec->kind == UPATCH_ATTACH_UPROBE_MULTI)
				pr_err("attach prog %u (%s %s:%s): %s", i,
				       attach_kind_name(spec->kind),
				       spec->uprobe_path, spec->target,
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
		ret = link_matches_spec(link_fd, spec);
		if (ret) {
			pr_err("attach prog %u (%s %s): the link is not at "
			       "the site the metadata names: %s", i,
			       attach_kind_name(spec->kind), spec->target,
			       strerror(-ret));
			close(link_fd);
			goto out;
		}
		ret = obj_pin(link_fd, pin);
		close(link_fd);
		if (ret) {
			pr_err("pin %s: %s", pin, strerror(-ret));
			goto out;
		}
		made[i] = true;
		pr_info("upatch load: program %u (%s) pinned at %s",
			i, attach_kind_name(spec->kind), pin);
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
		attach_seen = 0;
		for (i = 0; i < nr_progs; i++) {
			if (made[i] &&
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
		if (strncmp(info.name, "obs_i_", 6) == 0)
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
	if (upatch_remove_pins(name))
		pr_err("upatch: %s could not be undone; the next upatch command takes it out",
		       name);
	return ret;
}

/* Resolve the kernel BPF keyring and compare it with the frozen record. */
int upatch_trust_anchor(key_serial_t *keyring, key_serial_t *serial,
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

/* Shared by `upatch load` and boot restore: one signature-verified path. */
int upatch_apply_signed(const char *path, bool verify_only,
			struct op_report *rep)
{
	struct upatch u;
	struct prog_spec *prog_specs = NULL;
	const struct bpf_insn *insns;
	const void *sig, *data;
	key_serial_t keyring, serial;
	char prog_name[BPF_OBJ_NAME_LEN];
	char upatch_name[UPATCH_NAME_MAX + 1];
	char *vlog;			/* shared PROG_LOAD / TEST_RUN log_buf */
	size_t insn_cnt, ctx_sz = 0, prog_desc_off;
	int prog_fd = -1, map_fd = -1, policy_map_fd = -1;
	int socket_policy_map_fd = -1, ret;
	struct loader_ctx *cx = NULL;
	__u32 retval = 0, shared_policy_map_idx = UPATCH_MAPS_MAX;
	__u32 shared_socket_policy_map_idx = UPATCH_MAPS_MAX;

	vlog = xmalloc(VERIFIER_LOG_MAX);
	if (!vlog) {
		rep_fail(rep, "parse", "unknown", ENOMEM, "out of memory");
		return 1;
	}
	vlog[0] = '\0';

	ret = upatch_open(path, &u);
	if (ret) {
		pr_err("open %s: %s", path, strerror(-ret));
		rep_fail(rep, "parse", "parser_rejected", -ret,
			 "cannot open .upatch");
		xfree(vlog, VERIFIER_LOG_MAX);
		return 1;
	}
	/*
	 * verify_only loads the signed loader purely to make the kernel
	 * verify its CMS signature (the unload-directive authorization
	 * gate) -- so it deliberately accepts an UNLOAD directive and
	 * stops before TEST_RUN/attach.
	 */
	if (!verify_only && upatch_is_unload(&u)) {
		pr_err("upatch load: %s is an UNLOAD directive; "
		       "use `shirudo upatch unload`", path);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "is an UNLOAD directive");
		ret = 1;
		goto out;
	}
	if (upatch_trust_anchor(&keyring, &serial, rep)) {
		ret = 1;
		goto out;
	}

	insns = upatch_loader(&u);
	sig   = upatch_signature(&u);
	data  = upatch_data(&u);
	insn_cnt = u.hdr.loader_insns_len / sizeof(struct bpf_insn);

	upatch_prog_name(&u, prog_name, sizeof(prog_name));

	/*
	 * The pin directory, the archive and unload share the raw name. Boot
	 * restore reaches here without the command-level check, so validate it
	 * again.
	 */
	upatch_header_name(&u, upatch_name);
	if (!upatch_name_valid(upatch_name)) {
		pr_err("upatch: refusing unsafe upatch name '%s'", upatch_name);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "unsafe upatch name");
		ret = 1;
		goto out;
	}
	/* The header's copy of the name is what everything else reads. */
	if (!upatch_name_signed(&u)) {
		pr_err("upatch: the name of '%s' is not signature-covered or "
		       "differs from the signed one; rebuild the artifact",
		       upatch_name);
		rep_fail(rep, "parse", "parser_rejected", 0,
			 "name not signed");
		ret = 1;
		goto out;
	}

	/*
	 * The signature authorises the load, but payload_sha256 is what the pin
	 * xattr, the register event and the unload match record, so a header
	 * value that is not SHA-256(insns || data) is refused even when signed.
	 */
	{
		__u8 content_digest[UPATCH_PAYLOAD_HASH_LEN];
		int err;

		err = sha256_2(insns, u.hdr.loader_insns_len,
			       data, u.hdr.data_len, content_digest);
		if (err) {
			pr_err("upatch: cannot hash the payload of '%s': %s",
			       upatch_name, strerror(-err));
			rep_fail(rep, "parse", "unknown", -err,
				 "payload hash failed");
			ret = 1;
			goto out;
		}
		if (memneq_explicit(content_digest, u.hdr.payload_sha256,
				    sizeof(content_digest))) {
			pr_err("upatch: payload_sha256 does not match signed "
			       "content (insns || data); refusing");
			rep_fail(rep, "parse", "parser_rejected", 0,
				 "payload_sha256 mismatch");
			ret = 1;
			goto out;
		}
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
	if (!verify_only) {
		const void *attach;
		__u32 attach_len;

		attach = upatch_signed_attach(&u, &attach_len);
		if (!attach) {
			pr_err("upatch: the attach metadata of '%s' is not "
			       "signature-covered; rebuild the artifact",
			       upatch_name);
			rep_fail(rep, "parse", "parser_rejected", 0,
				 "attach metadata not signed");
			ret = 1;
			goto out;
		}
		ret = prog_specs_parse(attach, attach_len, u.hdr.nr_maps,
				       u.hdr.nr_progs, &prog_specs);
		if (ret) {
			pr_err("upatch program metadata rejected: %s",
			       strerror(-ret));
			rep_fail(rep, "parse", "parser_rejected", -ret,
				 "invalid program attach metadata");
			ret = 1;
			goto out;
		}
		ret = prepare_uprobe_targets(prog_specs, u.hdr.nr_progs);
		if (ret) {
			int e = -ret;
			const char *cat;

			if (e == ENOENT || e == ENOTDIR)
				cat = "attach_target_missing";
			else if (e == ESTALE)
				cat = "binary_mismatch";
			else if (e == EACCES || e == EPERM)
				cat = "lsm_denied";
			else if (e == ERANGE || e == EINVAL || e == E2BIG)
				cat = "parser_rejected";
			else
				cat = "unknown";
			pr_err("uprobe target verification failed (%s): %s",
			       cat, strerror(e));
			rep_fail(rep, "target_verify", cat, e,
				 "uprobe target verification failed");
			ret = 1;
			goto out;
		}
	}

	/*
	 * The metadata map is exclusive to the loader by the digest of its
	 * instructions alone, which the verifier enforces; payload_sha256
	 * covers insns || data.
	 */
	{
		__u8 loader_digest[UPATCH_PAYLOAD_HASH_LEN];

		if (sha256_calc(insns, u.hdr.loader_insns_len,
				loader_digest)) {
			pr_err("__loader.map: cannot hash the loader");
			rep_fail(rep, "signed_loader_load", "unknown", EIO,
				 "loader digest failed");
			ret = 1;
			goto out;
		}
		map_fd = loader_map_create("__loader.map", u.hdr.data_len,
					   loader_digest, sizeof(loader_digest));
	}
	if (map_fd < 0) {
		int err = errno;

		pr_err("__loader.map create: %s", strerror(err));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(err),
			 err, "__loader.map create failed");
		ret = 1;
		goto out;
	}

	ret = loader_map_update(map_fd, data, u.hdr.data_len);
	if (ret) {
		int err = errno;

		pr_err("__loader.map update: %s", strerror(err));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(err),
			 err, "__loader.map update failed");
		ret = 1;
		goto out;
	}

	/* The kernel refuses a signed load whose bound map is not frozen. */
	ret = loader_map_freeze(map_fd);
	if (ret) {
		int err = errno;

		pr_err("__loader.map freeze: %s", strerror(err));
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(err),
			 err, "__loader.map freeze failed");
		ret = 1;
		goto out;
	}

	/*
	 * The kernel attests the metadata itself; the loader carries no
	 * self-check.
	 */
	vlog[0] = '\0';
	prog_fd = prog_load_signed(insns, insn_cnt, prog_name,
				   sig, u.hdr.signature_len,
				   (__s32)keyring, map_fd,
				   vlog, VERIFIER_LOG_MAX);
	if (prog_fd < 0) {
		int e = errno;

		pr_err("BPF_PROG_LOAD (signed loader): %s", strerror(e));
		if (vlog[0])
			fprintf(stderr, "loader verifier log:\n%s\n", vlog);
		rep_fail(rep, "signed_loader_load", cat_from_load_errno(e), e,
			 "BPF_PROG_LOAD of signed loader failed");
		report_set_log(rep, vlog);
		ret = 1;
		goto out;
	}

	pr_info("%s: signed loader accepted, keyring %d, %zu instructions",
		verify_only ? "upatch unload" : "upatch load", (int)serial,
		insn_cnt);

	if (verify_only) {
		ret = 0;
		goto out;
	}

	/*
	 * The loader creates the programs and maps from kernel context but
	 * cannot attach or pin: gen_loader emits no link-create and
	 * bpf_sys_bpf() cannot BPF_OBJ_PIN. Its descriptors trail the context,
	 * sized from the header's counts.
	 */
	prog_desc_off = size_add(sizeof(struct loader_ctx),
				 size_mul(u.hdr.nr_maps,
					  sizeof(struct map_desc)));
	/*
	 * The loader's max_ctx_offset can exceed the descriptor tail, and
	 * TEST_RUN rejects a smaller ctx_size_in, so pad generously.
	 */
	ctx_sz = size_add(size_add(prog_desc_off,
				   size_mul(u.hdr.nr_progs,
					    sizeof(struct prog_desc))),
			  1024);
	/* TEST_RUN takes no larger a context for a syscall program. */
	if (ctx_sz > UINT16_MAX) {
		pr_err("upatch: %u maps and %u programs do not fit the loader context",
		       u.hdr.nr_maps, u.hdr.nr_progs);
		rep_fail(rep, "payload_load", "unknown", E2BIG,
			 "loader context too large");
		ctx_sz = 0;
		ret = 1;
		goto out;
	}
	cx = xmalloc(ctx_sz);
	if (!cx) {
		pr_err("ctx alloc");
		rep_fail(rep, "payload_load", "unknown", ENOMEM,
			 "ctx alloc failed");
		ret = 1;
		goto out;
	}
	vlog[0] = '\0';
	cx->sz = (__u32)ctx_sz;
	/*
	 * Keep inner verifier diagnostics enabled without bpftool's full
	 * accepted-program trace; the verbose mode can make valid payload
	 * loads fail with -ENOSPC when the log buffer fills.
	 */
	cx->log_level = 1;
	cx->log_size = VERIFIER_LOG_MAX;
	cx->log_buf = ptr_to_u64(vlog);
	if (u.signed_policy_labels) {
		struct map_desc *md;

		shared_policy_map_idx = u.signed_policy_map_idx;
		shared_socket_policy_map_idx =
			u.signed_socket_policy_map_idx;
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
			ret = 1;
			goto out;
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
			policy_map_fd = -1;
			ret = 1;
			goto out;
		}
		md = (struct map_desc *)((__u8 *)cx + sizeof(*cx)) +
			shared_policy_map_idx;
		md->map_fd = policy_map_fd;
		md = (struct map_desc *)((__u8 *)cx + sizeof(*cx)) +
			shared_socket_policy_map_idx;
		md->map_fd = socket_policy_map_fd;
	}

	ret = prog_test_run(prog_fd, cx, (__u32)ctx_sz, &retval);
	if (ret) {
		int err = errno;

		pr_err("BPF_PROG_TEST_RUN: %s", strerror(err));
		if (vlog[0])
			fprintf(stderr, "loader runtime log:\n%s\n", vlog);
		rep_fail(rep, "payload_load", "verifier_rejected", err,
			 "BPF_PROG_TEST_RUN failed");
		report_set_log(rep, vlog);
		ret = 1;
		goto out;
	}
	if ((__s32)retval < 0) {
		if (policy_map_fd >= 0) {
			close(policy_map_fd);
			policy_map_fd = -1;
		}
		if (socket_policy_map_fd >= 0) {
			close(socket_policy_map_fd);
			socket_policy_map_fd = -1;
		}
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
		ret = 1;
		goto out;
	}

	pr_info("upatch load: loader ran, %u maps and %u programs",
		u.hdr.nr_maps, u.hdr.nr_progs);

	/*
	 * Without a pinned link a program detaches when this one-shot CLI
	 * exits.
	 */
	ret = attach_and_pin_progs(cx, prog_desc_off, u.hdr.nr_progs,
				   upatch_name, prog_specs);
	if (ret) {
		int e = -ret;
		const char *cat;

		if (e == ENOENT || e == ENOTDIR)
			cat = "attach_target_missing";
		else if (e == ESTALE)
			cat = "binary_mismatch";
		else if (e == EXDEV)
			cat = "attach_scope_mismatch";
		else if (e == EOPNOTSUPP)
			cat = "kernel_abi_unsupported";
		else if (e == EACCES || e == EPERM)
			cat = "lsm_denied";
		else
			cat = "unknown";

		rep_fail(rep, "link_create", cat, e, "attach or pin failed");
		ret = 1;
		goto out;
	}

	pin_upatch_maps(cx, u.hdr.nr_maps, shared_policy_map_idx,
			shared_socket_policy_map_idx, upatch_name);

	/* After attach and pin, so the value records a loaded upatch. */
	ret = set_pin_payload(upatch_name, u.hdr.payload_sha256);
	if (ret) {
		rep_fail(rep, "link_create", "unknown", ret,
			 "cannot record the payload on the pin directory; the load was undone");
		ret = 1;
		goto out;
	}
	apply_policy_labels(&u);

	pr_audit("upatch load: %s loaded, %u programs, keyring %d",
		 upatch_name, u.hdr.nr_progs, (int)serial);
	if (rep)
		rep->loader_return = (__s32)retval;
	ret = 0;
out:
	prog_specs_free(prog_specs, u.hdr.nr_progs);
	xfree(vlog, VERIFIER_LOG_MAX);
	if (cx)
		close_loader_fds(cx, u.hdr.nr_maps, u.hdr.nr_progs);
	xfree(cx, ctx_sz);
	if (prog_fd >= 0)
		close(prog_fd);
	if (map_fd >= 0)
		close(map_fd);
	upatch_close(&u);
	return ret;
}

int upatch_apply(const char *path)
{
	return upatch_apply_signed(path, false, NULL);
}
