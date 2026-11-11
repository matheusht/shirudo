// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Tree outcomes remain in C until their Rust port.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "bpm_tree.h"
#include "hex.h"
#include "io.h"
#include "json.h"
#include "paths.h"
#include "seal.h"

/* A line with the longest seq is 218 bytes, its newline included. */
#define OUTCOME_LINE_MAX	256

struct outcome_line {
	__s64	seq;
	__s64	outcome;
	__u8	projection_root[32];
	__u8	history_root[32];
};

static bool outcome_valid(__s64 outcome)
{
	return outcome == TREE_OUTCOME_APPLIED ||
	       outcome == TREE_OUTCOME_UNMATCHED ||
	       outcome == TREE_OUTCOME_MODULE_ABSENT;
}

static int outcome_emit(const struct outcome_line *line, char *buf,
			size_t cap, size_t *len)
{
	struct json_emit e = { .buf = buf, .cap = cap };
	char root[65];

	json_obj_open(&e);
	json_kv_int(&e, "schema", 1);
	json_kv_int(&e, "seq", line->seq);
	json_kv_int(&e, "outcome", line->outcome);
	hex_encode(line->projection_root, 32, root);
	json_kv_string(&e, "projection_root", root);
	hex_encode(line->history_root, 32, root);
	json_kv_string(&e, "history_root", root);
	json_obj_close(&e);
	*len = e.len;
	return e.err;
}

static int outcome_parse(const char *text, size_t len,
			 struct outcome_line *out)
{
	char projection[65] = {}, history[65] = {};
	__s64 schema = 0;
	struct json_field f[] = {
		{ "schema", JSON_T_INT, &schema, 0, 0, NULL, 0 },
		{ "seq", JSON_T_INT, &out->seq, 0, 0, NULL, 0 },
		{ "outcome", JSON_T_INT, &out->outcome, 0, 0, NULL, 0 },
		{ "projection_root", JSON_T_STRING, projection,
		  sizeof(projection), 0, NULL, 0 },
		{ "history_root", JSON_T_STRING, history, sizeof(history),
		  0, NULL, 0 },
	};

	*out = (struct outcome_line){};
	if (json_parse(text, len, f, ARRAY_SIZE(f)) || schema != 1 ||
	    out->seq <= 0 || !outcome_valid(out->outcome) ||
	    hex_decode(projection, out->projection_root, 32) ||
	    hex_decode(history, out->history_root, 32))
		return -EBADMSG;
	return 0;
}

/* line starts as seq 0 with zero roots, where every tree starts. */
struct outcomes {
	int			fd;
	off_t			end;
	struct outcome_line	line;
};

/*
 * Every seq has its line, so the next one is a whole line of seq + 1 or
 * the record is not one. A last line without its newline is an append
 * that did not finish, and counts as no line.
 */
static int outcomes_next(struct outcomes *o)
{
	char buf[OUTCOME_LINE_MAX];
	struct outcome_line next;
	const char *newline;
	size_t have = 0;
	ssize_t got;

	while (have < sizeof(buf)) {
		got = pread(o->fd, buf + have, sizeof(buf) - have,
			    o->end + (off_t)have);
		if (got < 0 && errno == EINTR)
			continue;
		if (got < 0)
			return -errno;
		if (!got)
			break;
		have += (size_t)got;
	}
	newline = memchr(buf, '\n', have);
	if (!newline || outcome_parse(buf, (size_t)(newline - buf), &next) ||
	    next.seq != o->line.seq + 1)
		return -EBADMSG;
	o->line = next;
	o->end += newline - buf + 1;
	return 0;
}

static int outcomes_seek(struct outcomes *o, __s64 seq)
{
	int ret = 0;

	while (!ret && o->line.seq < seq)
		ret = outcomes_next(o);
	return ret;
}

int tree_outcome_append(__s64 seq, enum tree_outcome outcome,
			const __u8 projection_root[32],
			const __u8 history_root[32])
{
	struct outcome_line line = { .seq = seq, .outcome = outcome };
	char buf[OUTCOME_LINE_MAX];
	size_t len;
	int ret;

	if (seq <= 0 || !outcome_valid(outcome))
		return -EINVAL;
	memcpy(line.projection_root, projection_root, 32);
	memcpy(line.history_root, history_root, 32);
	ret = outcome_emit(&line, buf, sizeof(buf), &len);
	if (ret)
		return ret;
	ret = seal_mkdir_p(BPM_TREE_VAR_DIR, 0700);
	if (ret)
		return ret;
	return seal_append_line(BPM_TREE_OUTCOMES_PATH, buf, len);
}

int tree_outcomes_read(__s64 from, __s64 to, __u8 *codes,
		       __u8 projection_root[32], __u8 history_root[32])
{
	struct outcomes o = {};
	int ret;

	if (from < 0 || to < from)
		return -EINVAL;
	o.fd = seal_open_read(BPM_TREE_OUTCOMES_PATH);
	if (o.fd == -ENOENT && !to) {
		memset(projection_root, 0, 32);
		memset(history_root, 0, 32);
		return 0;
	}
	if (o.fd < 0)
		return o.fd;
	ret = outcomes_seek(&o, from);
	if (!ret) {
		memcpy(projection_root, o.line.projection_root, 32);
		memcpy(history_root, o.line.history_root, 32);
	}
	while (!ret && o.line.seq < to) {
		ret = outcomes_next(&o);
		if (!ret)
			*codes++ = (__u8)o.line.outcome;
	}
	close(o.fd);
	return ret;
}

static int outcomes_cut(struct outcomes *o)
{
	struct stat st;

	if (fstat(o->fd, &st))
		return -errno;
	if (st.st_size == o->end)
		return 0;
	if (ftruncate(o->fd, o->end) || fsync(o->fd))
		return -errno;
	return 0;
}

int tree_outcomes_resume(__s64 last_seq, __u8 history_root[32])
{
	struct outcomes o = {};
	int ret;

	if (last_seq < 0)
		return -EINVAL;
	o.fd = seal_open(BPM_TREE_OUTCOMES_PATH, O_RDWR, 0);
	if (o.fd == -ENOENT && !last_seq) {
		memset(history_root, 0, 32);
		return 0;
	}
	if (o.fd < 0)
		return o.fd;
	ret = lock_exclusive(o.fd);
	if (!ret)
		ret = outcomes_seek(&o, last_seq);
	if (!ret)
		ret = outcomes_cut(&o);
	if (!ret)
		memcpy(history_root, o.line.history_root, 32);
	if (close(o.fd) && !ret)
		ret = -errno;
	return ret;
}

int tree_eventlog_matches(const struct tree_state *s, int state_rc,
			  __u8 replay[32], bool *matches)
{
	__u8 live[32];
	int ret;

	ret = tree_event_replay(replay);
	if (ret)
		return ret;
	*matches = !state_rc && !hex_decode(s->projection_root, live, 32) &&
		   !memneq_explicit(live, replay, 32);
	return 0;
}
