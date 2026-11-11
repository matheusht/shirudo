// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The upatch tree's state.json, its eventlog and its outcomes record, as
 * a target reads them back before a sync. The eventlog matches a state
 * only when the state was read, and replays the same either way.
 */

#include <stdlib.h>

#include "fuzz.h"
#include "bpm_tree.h"

static char fuzz_path[64];

#undef BPM_TREE_STATE_PATH
#define BPM_TREE_STATE_PATH fuzz_path
#undef BPM_TREE_EVENTLOG_PATH
#define BPM_TREE_EVENTLOG_PATH fuzz_path


/*
 * Each line the reader takes lies within the record, follows the line
 * before it and is written again as a line it takes the same.
 */
static void outcomes_read_back_as_written(int fd, size_t size)
{
	struct outcomes o = { .fd = fd };
	struct outcome_line back;
	char buf[OUTCOME_LINE_MAX];
	__s64 seq = 0;
	size_t len;

	while (!outcomes_next(&o)) {
		if ((size_t)o.end > size || o.line.seq != ++seq ||
		    !outcome_valid(o.line.outcome) ||
		    outcome_emit(&o.line, buf, sizeof(buf), &len) ||
		    outcome_parse(buf, len, &back) ||
		    back.seq != o.line.seq || back.outcome != o.line.outcome ||
		    memcmp(back.projection_root, o.line.projection_root, 32) ||
		    memcmp(back.history_root, o.line.history_root, 32))
			abort();
	}
}

static void eventlog_matches_a_state_read(const struct tree_state *state,
					  int state_rc)
{
	__u8 root[32], again[32];
	bool matches = false;
	int ret;

	ret = tree_event_replay_path(fuzz_path, root);
	if (tree_eventlog_matches(state, state_rc, again, &matches) != ret ||
	    (!ret && memcmp(root, again, sizeof(root))) ||
	    (state_rc && matches))
		abort();
}

int LLVMFuzzerTestOneInput(const __u8 *data, size_t size)
{
	struct tree_state state;
	int fd, rc;

	fd = fuzz_file(data, size, fuzz_path, sizeof(fuzz_path));
	if (fd < 0)
		return 0;
	rc = tree_state_read_path(fuzz_path, &state);
	eventlog_matches_a_state_read(&state, rc);
	outcomes_read_back_as_written(fd, size);
	close(fd);
	return 0;
}
