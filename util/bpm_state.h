/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The packages bpm installed, as /var/lib/shirudo/bpm/state.json records
 * them, which rust/src/util/bpm_state.rs reads and writes.
 */

#ifndef SHIRUDO_BPM_STATE_H
#define SHIRUDO_BPM_STATE_H

#include <limits.h>
#include <stddef.h>

#include "bpm_oci.h"

struct bpm_state_entry {
	char name[BPM_MAX_NAME];
	char version[BPM_MAX_NAME];
	char source[BPM_MAX_NAME];
	char path[PATH_MAX];
};

/*
 * The len bytes at body as up to BPM_MAX_STATE entries: each a package
 * name and version, the name of the source it came from, and the path
 * under BPM_PACKAGES_DIR that name and version make. 0, -EINVAL or
 * -E2BIG.
 */
int bpm_state_parse(const char *body, size_t len,
		    struct bpm_state_entry *st, int *n);
/* The n entries as the document bpm_state_parse() reads. 0 or -E2BIG. */
int bpm_state_emit(const struct bpm_state_entry *st, int n, char *buf,
		   size_t cap, size_t *len);

/* The recorded entries, none when there is no state yet. */
int bpm_state_read(struct bpm_state_entry *st, int *n);
int bpm_state_write(const struct bpm_state_entry *st, int n);

#endif /* SHIRUDO_BPM_STATE_H */
