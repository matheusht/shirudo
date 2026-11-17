// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .incbin embedding of the bpf/ objects shipped inside shirudo: the
 * light skeletons of bpf2 and the seal, which init loads, and the unload
 * template, which shirudo-build packages.
 */

#include <stddef.h>

#include "loader.h"

asm(".section .rodata, \"a\"\n"
	".balign 8\n"
	".global shirudo_bpf2_lskel; shirudo_bpf2_lskel:\n"
	".incbin \"bpf/bpf2.lskel\"\n"
	".global shirudo_bpf2_lskel_end; shirudo_bpf2_lskel_end:\n"
	".previous\n");

asm(".section .rodata, \"a\"\n"
	".balign 8\n"
	".global shirudo_seal_lskel; shirudo_seal_lskel:\n"
	".incbin \"bpf/seal.lskel\"\n"
	".global shirudo_seal_lskel_end; shirudo_seal_lskel_end:\n"
	".previous\n");

asm(".section .rodata, \"a\"\n"
	".global shirudo_unload_bpf_o; shirudo_unload_bpf_o:\n"
	".incbin \"bpf/unload.bpf.o\"\n"
	".global shirudo_unload_bpf_o_end; shirudo_unload_bpf_o_end:\n"
	".previous\n");


static const struct embedded_bpf bpf2 = {
	.name = "bpf2",
	.data = shirudo_bpf2_lskel,
	/*
	 * .size set at use-time -- end pointer arithmetic isn't a
	 * constant expression.
	 */
};

static const struct embedded_bpf seal = {
	.name = "seal",
	.data = shirudo_seal_lskel,
};

static const struct embedded_bpf unload = {
	.name = "unload",
	.data = shirudo_unload_bpf_o,
};

const struct embedded_bpf *bpf2_blob(void)
{
	static struct embedded_bpf b;

	b = bpf2;
	b.size = (size_t)(shirudo_bpf2_lskel_end - shirudo_bpf2_lskel);
	return &b;
}

const struct embedded_bpf *seal_blob(void)
{
	static struct embedded_bpf b;

	b = seal;
	b.size = (size_t)(shirudo_seal_lskel_end - shirudo_seal_lskel);
	return &b;
}

const struct embedded_bpf *unload_blob(void)
{
	static struct embedded_bpf b;

	b = unload;
	b.size = (size_t)(shirudo_unload_bpf_o_end - shirudo_unload_bpf_o);
	return &b;
}
