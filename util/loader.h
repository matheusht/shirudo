/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The light skeletons of bpf2 and the seal the binaries embed, in the
 * format of rust/src/bpf/lskel.rs, which rust/src/skel.rs exports for
 * the test that inspects them.
 */

#ifndef SHIRUDO_LOADER_H
#define SHIRUDO_LOADER_H

#include <stddef.h>

struct embedded_bpf {
	const char	*name;
	const void	*data;
	size_t		size;
};

const struct embedded_bpf *bpf2_blob(void);
const struct embedded_bpf *seal_blob(void);

#endif /* SHIRUDO_LOADER_H */
