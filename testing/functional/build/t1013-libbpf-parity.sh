#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1013 -- the Rust does what the build once took from the vendored libbpf,
# byte for byte: tools/gen-vmlinux-h dumps BTF as libbpf's btf_dump does,
# and tools/bpf-lskel generates the loaders of bpf2 and of the seal, which
# takes bpf2's maps, as its gen_loader does. The C of testing/parity/
# drives the vendored libbpf. A refresh of vendor/libbpf that changes
# what either does fails here until the Rust follows.

cd "$(dirname "$0")/../.."
. ./test-lib.sh
P=parity
GEN=../tools/gen-vmlinux-h/gen-vmlinux-h
[ -x "$P/gen-vmlinux-h" ] && [ -x "$P/gen-loader" ] ||
	test_skip_all "no parity oracles (make -f Makefile.shirudo parity-oracles)"
[ -x "$GEN" ] || test_skip_all "tools/gen-vmlinux-h not built"
[ -s ../bpf/bpf2.lskel ] && [ -s ../bpf/seal.lskel ] ||
	test_skip_all "no light skeletons (make)"
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# The BTF the test kernel's vmlinux.h comes from, each BPF object's, and
# the running kernel's.
btfs()
{
	for f in ../artifacts/bpf-next-kernel-debs/vmlinux.btf ../bpf/*.bpf.o \
		/sys/kernel/btf/vmlinux; do
		[ -r "$f" ] && printf '%s\n' "$f"
	done
}

# A light skeleton's loader, into $W/rust.insns and $W/rust.data, and in
# $mask the maps it takes from its caller: the header is the magic, three
# counts, the mask and the sizes of the names, instructions and data.
loader_of()
{
	mask=$(od -An -t u8 -j 20 -N 8 "$1" | tr -d ' ') &&
	set -- "$1" $(od -An -t u4 -j 28 -N 12 "$1") &&
	tail -c +$((40 + $2 + 1)) "$1" | head -c "$3" >"$W/rust.insns" &&
	tail -c +$((40 + $2 + $3 + 1)) "$1" | head -c "$4" >"$W/rust.data"
}

test_expect_success 'gen-vmlinux-h dumps BTF as libbpf btf_dump does' '
	[ -n "$(btfs)" ] &&
	bad= &&
	for f in $(btfs); do
		"$P/gen-vmlinux-h" "$f" >"$W/c.h" && "$GEN" "$f" >"$W/rust.h" &&
			cmp -s "$W/c.h" "$W/rust.h" || bad="$bad $f"
	done &&
	{ [ -z "$bad" ] || { echo "differs on:$bad"; false; }; }
'

test_expect_success 'bpf-lskel generates the loaders libbpf gen_loader does' '
	bad= &&
	for n in bpf2 seal; do
		loader_of ../bpf/$n.lskel &&
		"$P/gen-loader" ../bpf/$n.bpf.o $n "$mask" "$W/c.insns" "$W/c.data" &&
		cmp -s "$W/c.insns" "$W/rust.insns" && cmp -s "$W/c.data" "$W/rust.data" ||
			bad="$bad $n"
	done &&
	{ [ -z "$bad" ] || { echo "differs for:$bad"; false; }; }
'

test_expect_success 'the seal takes maps from its caller' '
	loader_of ../bpf/seal.lskel &&
	[ "$mask" != 0 ]
'

test_done
