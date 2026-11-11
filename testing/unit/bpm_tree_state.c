// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <zlib.h>

#include <shirudo/string.h>

#include "../../util/bpm_tree.h"
#include "../../util/io.h"
static char tree_dir[4200], state_path[4300], outcomes_path[4300];
static char events_path[4300], pending_path[4300];

#include "unit.h"

static char path[4096];

static void write_config_bytes(const char *text, size_t len, bool gz)
{
	const char *tmp = getenv("TMPDIR");
	int fd;

	ASSERT_TRUE(strsprintf(path, sizeof(path), "%s/shirudo-unit-kconfig-XXXXXX",
			       tmp && tmp[0] ? tmp : "/tmp") > 0);
	fd = mkstemp(path);
	ASSERT_TRUE(fd >= 0);
	if (gz) {
		gzFile f = gzdopen(fd, "wb");

		ASSERT_TRUE(f);
		ASSERT_EQ(gzwrite(f, text, (__u32)len), (int)len);
		ASSERT_EQ(gzclose(f), Z_OK);
	} else {
		ASSERT_EQ(write_complete(fd, text, len), 0);
		ASSERT_EQ(close(fd), 0);
	}
}

static void write_config(const char *text, bool gz)
{
	write_config_bytes(text, strlen(text), gz);
}

/* What a config of len bytes reads as, with CONFIG_MODULES in *value. */
static int modules_read(const char *text, size_t len, bool gz,
			const char **value)
{
	static char values[TREE_MAX_KCONFIG][TREE_STRING_MAX];
	static struct tree_selector sel;
	bool found[TREE_MAX_KCONFIG] = {};
	struct tree_selector_kv *kv;
	int ret;

	memset(&sel, 0, sizeof(sel));
	memset(values, 0, sizeof(values));
	ASSERT_EQ(tree_selector_kv_add(&sel.kconfig, &sel.n_kconfig,
				       TREE_MAX_KCONFIG, &kv), 0);
	strscpy(kv->key, "CONFIG_MODULES", sizeof(kv->key));
	write_config_bytes(text, len, gz);
	ret = tree_kconfig_read(path, &sel, values, found, gz);
	tree_selector_free(&sel);
	unlink(path);
	*value = found[0] ? values[0] : "-";
	return ret;
}

static const char *modules_in(const char *text, bool gz)
{
	const char *value;

	ASSERT_EQ(modules_read(text, strlen(text), gz, &value), 0);
	return value;
}

/*
 * A line longer than the read buffer came in parts, and the part from
 * the middle of a long string read as an option of its own.
 */
static void long_line_is_one_line(void)
{
	static const char head[] =
		"# CONFIG_MODULES is not set\nCONFIG_CMDLINE=\"";
	static const char tail[] = "CONFIG_MODULES=y\"\nCONFIG_X=y\n";
	char text[4096];

	memcpy(text, head, sizeof(head) - 1);
	memset(text + sizeof(head) - 1, ' ', 2014);
	memcpy(text + sizeof(head) - 1 + 2014, tail, sizeof(tail));
	EXPECT_STREQ(modules_in(text, false), "n");
	EXPECT_STREQ(modules_in(text, true), "n");
	EXPECT_STREQ(modules_in("CONFIG_MODULES=y\n", false), "y");
	EXPECT_STREQ(modules_in("CONFIG_MODULES=m", true), "m");
}

/*
 * A line is read as a string, which a NUL ends: the option of a line
 * that held one read as set to what stood ahead of it.
 */
static void config_with_a_nul_is_no_config(void)
{
	static const char text[] = "CONFIG_MODULES=y\0es\nCONFIG_X=y\n";
	const char *value;

	EXPECT_EQ(modules_read(text, sizeof(text) - 1, false, &value),
		  -EINVAL);
	EXPECT_EQ(modules_read(text, sizeof(text) - 1, true, &value), -EINVAL);
	ASSERT_EQ(modules_read(text, strlen(text), false, &value), 0);
	EXPECT_STREQ(value, "y");
}

/* A config written gzip'd or not, cut by cut bytes and extra appended. */
static int read_gz(bool gz, off_t cut, const char *extra)
{
	static char values[TREE_MAX_KCONFIG][TREE_STRING_MAX];
	bool found[TREE_MAX_KCONFIG] = {};
	struct tree_selector sel = {};
	struct tree_selector_kv *kv;
	struct stat st;
	int fd, ret;

	ASSERT_EQ(tree_selector_kv_add(&sel.kconfig, &sel.n_kconfig,
				       TREE_MAX_KCONFIG, &kv), 0);
	strscpy(kv->key, "CONFIG_MODULES", sizeof(kv->key));
	write_config("CONFIG_MODULES=y\n", gz);
	ASSERT_EQ(stat(path, &st), 0);
	ASSERT_EQ(truncate(path, st.st_size - cut), 0);
	if (extra) {
		fd = open(path, O_WRONLY | O_APPEND | O_CLOEXEC);
		ASSERT_TRUE(fd >= 0);
		ASSERT_EQ(write_complete(fd, extra, strlen(extra)), 0);
		ASSERT_EQ(close(fd), 0);
	}
	ret = tree_kconfig_read(path, &sel, values, found, true);
	tree_selector_free(&sel);
	unlink(path);
	if (!ret && (!found[0] || strcmp(values[0], "y")))
		return 1;
	return ret;
}

static void gzip_config_is_one_whole_member(void)
{
	EXPECT_EQ(read_gz(true, 0, NULL), 0);
	EXPECT_EQ(read_gz(true, 1, NULL), -EINVAL);
	EXPECT_EQ(read_gz(true, 8, NULL), -EINVAL);
	EXPECT_EQ(read_gz(true, 0, "x"), -EINVAL);
	EXPECT_EQ(read_gz(false, 0, NULL), -EINVAL);
}

#define PENDING_DIGEST \
	"sha256:00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"

static int pending(const char *doc, struct tree_pending *out)
{
	return tree_pending_parse(doc, strlen(doc), out);
}

static void pending_is_an_operation_in_flight(void)
{
	struct tree_pending p;

	ASSERT_EQ(pending("{\"schema\":1,\"seq\":3,\"id\":\"fix\","
			  "\"operation_digest\":\"" PENDING_DIGEST "\"}", &p), 0);
	EXPECT_EQ(p.seq, 3);
	EXPECT_STREQ(p.id, "fix");
	EXPECT_EQ(pending("{\"schema\":2,\"seq\":3,\"id\":\"fix\","
			  "\"operation_digest\":\"" PENDING_DIGEST "\"}", &p),
		  -EINVAL);
	EXPECT_EQ(pending("{\"schema\":1,\"seq\":0,\"id\":\"fix\","
			  "\"operation_digest\":\"" PENDING_DIGEST "\"}", &p),
		  -EINVAL);
	EXPECT_EQ(pending("{\"schema\":1,\"seq\":3,\"id\":\"../fix\","
			  "\"operation_digest\":\"" PENDING_DIGEST "\"}", &p),
		  -EINVAL);
	EXPECT_EQ(pending("{\"schema\":1,\"seq\":3,\"id\":\"fix\","
			  "\"operation_digest\":\"sha256:00\"}", &p), -EINVAL);
}

/* As the format has it: blanks go but for those between a key and its =. */
static void labels_are_cut_at_the_first_equals(void)
{
	static struct tree_kv labels[4];
	int n = -1;

	write_config("# site=x\n  site = a \t\nzone=b=c\njunk\nempty=\t\n",
		     false);
	ASSERT_EQ(tree_labels_read(path, labels, &n, ARRAY_SIZE(labels)), 0);
	unlink(path);
	ASSERT_EQ(n, 3);
	EXPECT_STREQ(labels[0].key, "site ");
	EXPECT_STREQ(labels[0].value, "a");
	EXPECT_STREQ(labels[1].key, "zone");
	EXPECT_STREQ(labels[1].value, "b=c");
	EXPECT_STREQ(labels[2].key, "empty");
	EXPECT_STREQ(labels[2].value, "");
	EXPECT_EQ(tree_labels_read("/nonexistent/node.labels", labels, &n,
				   ARRAY_SIZE(labels)), -ENOENT);
	EXPECT_EQ(n, 0);
}

static char top_dir[4096];

static void use_tree(void)
{
	const char *tmp = getenv("TMPDIR");

	ASSERT_TRUE(strsprintf(top_dir, sizeof(top_dir),
			       "%s/shirudo-unit-tree-XXXXXX",
			       tmp && tmp[0] ? tmp : "/tmp") > 0);
	ASSERT_TRUE(mkdtemp(top_dir));
	ASSERT_TRUE(strsprintf(tree_dir, sizeof(tree_dir), "%s/upatch-tree",
			       top_dir) > 0);
	ASSERT_TRUE(strsprintf(state_path, sizeof(state_path),
			       "%s/state.json", tree_dir) > 0);
	ASSERT_TRUE(strsprintf(outcomes_path, sizeof(outcomes_path),
			       "%s/outcomes", tree_dir) > 0);
	ASSERT_TRUE(strsprintf(events_path, sizeof(events_path),
			       "%s/tree-eventlog", tree_dir) > 0);
	ASSERT_TRUE(strsprintf(pending_path, sizeof(pending_path),
			       "%s/pending.json", tree_dir) > 0);
}

static void drop_tree(void)
{
	unlink(state_path);
	unlink(outcomes_path);
	rmdir(tree_dir);
	rmdir(top_dir);
}

static void write_text(const char *file, const char *text, int flags)
{
	int fd;

	ASSERT_TRUE(mkdir(tree_dir, 0700) == 0 || errno == EEXIST);
	fd = open(file, O_WRONLY | O_CREAT | O_CLOEXEC | flags, 0600);
	ASSERT_TRUE(fd >= 0);
	ASSERT_EQ(write_complete(fd, text, strlen(text)), 0);
	ASSERT_EQ(close(fd), 0);
}

static off_t outcomes_size(void)
{
	struct stat st;

	ASSERT_EQ(stat(outcomes_path, &st), 0);
	return st.st_size;
}

/* The roots a test gives the line of seq: every byte seq, or seq + 100. */
static void append_outcome(__s64 seq, enum tree_outcome outcome)
{
	__u8 projection[32], history[32];

	memset(projection, (int)seq, sizeof(projection));
	memset(history, (int)seq + 100, sizeof(history));
	ASSERT_EQ(tree_outcome_append(seq, outcome, projection, history), 0);
}

static void expect_roots(const __u8 projection[32], const __u8 history[32],
			 __s64 seq)
{
	__u8 want_projection[32] = {}, want_history[32] = {};

	if (seq) {
		memset(want_projection, (int)seq, sizeof(want_projection));
		memset(want_history, (int)seq + 100, sizeof(want_history));
	}
	EXPECT_MEMEQ(projection, want_projection, 32);
	EXPECT_MEMEQ(history, want_history, 32);
}

#define OUTCOME_LINE(seq, outcome)					\
	"{\"schema\":1,\"seq\":" #seq ",\"outcome\":" #outcome ","	\
	"\"projection_root\":\""					\
	"0101010101010101010101010101010101010101010101010101010101010101" \
	"\",\"history_root\":\""					\
	"6565656565656565656565656565656565656565656565656565656565656565" \
	"\"}\n"

static void outcomes_append_and_read_back(void)
{
	__u8 codes[3] = {}, projection[32], history[32];
	char *text;
	size_t len;

	use_tree();
	append_outcome(1, TREE_OUTCOME_APPLIED);
	ASSERT_EQ(read_file(outcomes_path, 4096, &text, &len), 0);
	EXPECT_STREQ(text, OUTCOME_LINE(1, 1));
	xfree(text, len + 1);
	append_outcome(2, TREE_OUTCOME_UNMATCHED);
	append_outcome(3, TREE_OUTCOME_MODULE_ABSENT);

	ASSERT_EQ(tree_outcomes_read(0, 3, codes, projection, history), 0);
	EXPECT_EQ(codes[0], 1);
	EXPECT_EQ(codes[1], 2);
	EXPECT_EQ(codes[2], 3);
	expect_roots(projection, history, 0);

	memset(codes, 0, sizeof(codes));
	ASSERT_EQ(tree_outcomes_read(1, 3, codes, projection, history), 0);
	EXPECT_EQ(codes[0], 2);
	EXPECT_EQ(codes[1], 3);
	EXPECT_EQ(codes[2], 0);
	expect_roots(projection, history, 1);

	ASSERT_EQ(tree_outcomes_read(3, 3, codes, projection, history), 0);
	expect_roots(projection, history, 3);
	ASSERT_EQ(tree_outcomes_read(0, 0, codes, projection, history), 0);
	expect_roots(projection, history, 0);

	EXPECT_EQ(tree_outcomes_read(2, 1, codes, projection, history),
		  -EINVAL);
	EXPECT_EQ(tree_outcomes_read(-1, 1, codes, projection, history),
		  -EINVAL);
	EXPECT_EQ(tree_outcome_append(0, TREE_OUTCOME_APPLIED, projection,
				      history), -EINVAL);
	EXPECT_EQ(tree_outcome_append(4, 0, projection, history), -EINVAL);
	EXPECT_EQ(tree_outcome_append(4, 4, projection, history), -EINVAL);
	drop_tree();
}

static void outcomes_torn_last_line_is_dropped(void)
{
	__u8 codes[3], projection[32], history[32];
	off_t whole;

	use_tree();
	append_outcome(1, TREE_OUTCOME_APPLIED);
	append_outcome(2, TREE_OUTCOME_UNMATCHED);
	whole = outcomes_size();
	write_text(outcomes_path, "{\"schema\":1,\"seq\":3,\"outc", O_APPEND);

	ASSERT_EQ(tree_outcomes_read(0, 2, codes, projection, history), 0);
	EXPECT_EQ(tree_outcomes_read(0, 3, codes, projection, history),
		  -EBADMSG);
	EXPECT_EQ(tree_outcomes_resume(3, history), -EBADMSG);
	ASSERT_EQ(tree_outcomes_resume(2, history), 0);
	EXPECT_EQ(outcomes_size(), whole);

	write_text(outcomes_path, "{\"schema\":1,\"seq\":3,\"outc", O_APPEND);
	append_outcome(3, TREE_OUTCOME_APPLIED);
	ASSERT_EQ(tree_outcomes_read(0, 3, codes, projection, history), 0);
	EXPECT_EQ(codes[2], 1);
	drop_tree();
}

static void outcomes_resume_cuts_past_last_seq(void)
{
	__u8 codes[4], projection[32], history[32], want[32] = {};
	off_t two;

	use_tree();
	memset(history, 0xff, sizeof(history));
	ASSERT_EQ(tree_outcomes_resume(0, history), 0);
	EXPECT_MEMEQ(history, want, sizeof(history));
	EXPECT_EQ(access(outcomes_path, F_OK), -1);
	EXPECT_EQ(tree_outcomes_resume(2, history), -ENOENT);
	EXPECT_EQ(tree_outcomes_resume(-1, history), -EINVAL);

	append_outcome(1, TREE_OUTCOME_APPLIED);
	append_outcome(2, TREE_OUTCOME_UNMATCHED);
	two = outcomes_size();
	append_outcome(3, TREE_OUTCOME_MODULE_ABSENT);
	append_outcome(4, TREE_OUTCOME_APPLIED);

	ASSERT_EQ(tree_outcomes_resume(2, history), 0);
	memset(want, 2 + 100, sizeof(want));
	EXPECT_MEMEQ(history, want, sizeof(history));
	EXPECT_EQ(outcomes_size(), two);
	ASSERT_EQ(tree_outcomes_read(0, 2, codes, projection, history), 0);
	EXPECT_EQ(codes[0], 1);
	EXPECT_EQ(codes[1], 2);
	EXPECT_EQ(tree_outcomes_read(0, 3, codes, projection, history),
		  -EBADMSG);

	EXPECT_EQ(tree_outcomes_resume(5, history), -EBADMSG);
	EXPECT_EQ(outcomes_size(), two);

	/* What follows last_seq goes unread: it need not be a line. */
	write_text(outcomes_path, "not a line\n" OUTCOME_LINE(9, 1),
		   O_APPEND);
	ASSERT_EQ(tree_outcomes_resume(2, history), 0);
	EXPECT_EQ(outcomes_size(), two);

	ASSERT_EQ(tree_outcomes_resume(0, history), 0);
	memset(want, 0, sizeof(want));
	EXPECT_MEMEQ(history, want, sizeof(history));
	EXPECT_EQ(outcomes_size(), 0);
	drop_tree();
}

static int read_outcomes(const char *text, __s64 to)
{
	__u8 codes[8], projection[32], history[32];

	write_text(outcomes_path, text, O_TRUNC);
	return tree_outcomes_read(0, to, codes, projection, history);
}

static void outcomes_gap_and_missing_line(void)
{
	__u8 codes[2], projection[32], history[32];

	use_tree();
	EXPECT_EQ(tree_outcomes_read(0, 1, codes, projection, history),
		  -ENOENT);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 1), 1), 0);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 1), 2), -EBADMSG);
	EXPECT_EQ(read_outcomes("", 1), -EBADMSG);

	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 1) OUTCOME_LINE(3, 1), 3),
		  -EBADMSG);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 1) OUTCOME_LINE(3, 1), 1), 0);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(2, 1), 2), -EBADMSG);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 1) OUTCOME_LINE(1, 1), 2),
		  -EBADMSG);
	EXPECT_EQ(tree_outcomes_resume(2, history), -EBADMSG);

	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 0), 1), -EBADMSG);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(1, 4), 1), -EBADMSG);
	EXPECT_EQ(read_outcomes(OUTCOME_LINE(0, 1), 1), -EBADMSG);
	EXPECT_EQ(read_outcomes("\n" OUTCOME_LINE(1, 1), 1), -EBADMSG);
	EXPECT_EQ(read_outcomes("not a line\n", 1), -EBADMSG);
	EXPECT_EQ(read_outcomes("{\"schema\":2,\"seq\":1,\"outcome\":1,"
				"\"projection_root\":\"\","
				"\"history_root\":\"\"}\n", 1), -EBADMSG);
	EXPECT_EQ(read_outcomes("{\"schema\":1,\"seq\":1,\"outcome\":1,"
				"\"projection_root\":\"01\","
				"\"history_root\":\"65\"}\n", 1), -EBADMSG);
	EXPECT_EQ(read_outcomes("{\"schema\":1,\"seq\":1,\"outcome\":1}\n", 1),
		  -EBADMSG);
	drop_tree();
}

static void outcomes_longer_line_is_malformed(void)
{
	char text[2 * OUTCOME_LINE_MAX];

	use_tree();
	memset(text, ' ', sizeof(text));
	text[sizeof(text) - 2] = '\n';
	text[sizeof(text) - 1] = '\0';
	EXPECT_EQ(read_outcomes(text, 1), -EBADMSG);
	text[sizeof(text) - 2] = ' ';
	EXPECT_EQ(read_outcomes(text, 1), -EBADMSG);
	drop_tree();
}

static void outcomes_cover_the_state(void)
{
	__u8 history[32], zero[32] = {};

	use_tree();
	EXPECT_EQ(tree_outcomes_resume(1, history), -ENOENT);

	write_text(outcomes_path, OUTCOME_LINE(1, 1) OUTCOME_LINE(2, 2),
		   O_TRUNC);
	EXPECT_EQ(tree_outcomes_resume(3, history), -EBADMSG);
	ASSERT_EQ(tree_outcomes_resume(2, history), 0);
	EXPECT_TRUE(memcmp(history, zero, sizeof(history)) != 0);

	write_text(outcomes_path, OUTCOME_LINE(1, 1) OUTCOME_LINE(3, 2),
		   O_TRUNC);
	EXPECT_EQ(tree_outcomes_resume(3, history), -EBADMSG);
	ASSERT_EQ(tree_outcomes_resume(1, history), 0);

	write_text(outcomes_path, "", O_TRUNC);
	EXPECT_EQ(tree_outcomes_resume(1, history), -EBADMSG);
	drop_tree();
}

#define STATE_ROOT \
	"5c7761b120a9cf59e79e5a078227b450b7a39294db74bb3ba28e28c6ae196d27"
#define STATE_HEAD \
	"{\"schema\":1,\"tree_id\":\"prod\",\"generation\":3,\"last_seq\":5," \
	"\"projection_root\":\"" STATE_ROOT "\","			\
	"\"projection_root_tpm\":\"" STATE_ROOT "\","			\
	"\"manifest_digest\":\"" PENDING_DIGEST "\""

static int read_state(const char *text, struct tree_state *out)
{
	write_text(state_path, text, O_TRUNC);
	return tree_state_read(out);
}

static void state_names_its_publication_head_and_base(void)
{
	struct tree_state s, back;

	use_tree();
	EXPECT_EQ(tree_state_read(&s), -ENOENT);
	EXPECT_EQ(read_state(STATE_HEAD "}", &s), -EINVAL);
	EXPECT_EQ(read_state(STATE_HEAD ",\"head_seq\":7}", &s), -EINVAL);
	EXPECT_EQ(read_state(STATE_HEAD ",\"segment_base_seq\":0}", &s),
		  -EINVAL);
	ASSERT_EQ(read_state(STATE_HEAD ",\"head_seq\":7,"
			     "\"segment_base_seq\":2}", &s), 0);
	EXPECT_EQ(s.last_seq, 5);
	EXPECT_EQ(s.head_seq, 7);
	EXPECT_EQ(s.segment_base_seq, 2);

	s.head_seq = 9;
	s.segment_base_seq = 4;
	ASSERT_EQ(tree_state_write(&s), 0);
	ASSERT_EQ(tree_state_read(&back), 0);
	EXPECT_STREQ(back.tree_id, "prod");
	EXPECT_EQ(back.generation, 3);
	EXPECT_EQ(back.last_seq, 5);
	EXPECT_STREQ(back.projection_root, STATE_ROOT);
	EXPECT_STREQ(back.projection_root_tpm, STATE_ROOT);
	EXPECT_STREQ(back.manifest_digest, PENDING_DIGEST);
	EXPECT_EQ(back.head_seq, 9);
	EXPECT_EQ(back.segment_base_seq, 4);
	drop_tree();
}

#define STATE_TAIL \
	"\"manifest_digest\":\"" PENDING_DIGEST "\",\"head_seq\":7,"	\
	"\"segment_base_seq\":0}"
#define STATE_NO_TPM_ROOT \
	"{\"schema\":1,\"tree_id\":\"prod\",\"generation\":3,\"last_seq\":5," \
	"\"projection_root\":\"" STATE_ROOT "\","

static void state_needs_both_projection_roots(void)
{
	struct tree_state s;

	use_tree();
	EXPECT_EQ(read_state(STATE_NO_TPM_ROOT STATE_TAIL, &s), -EINVAL);
	EXPECT_EQ(read_state(STATE_NO_TPM_ROOT "\"projection_root_tpm\":\"\","
			     STATE_TAIL, &s), -EINVAL);
	EXPECT_EQ(read_state(STATE_NO_TPM_ROOT "\"projection_root_tpm\":\"5c\","
			     STATE_TAIL, &s), -EINVAL);
	ASSERT_EQ(read_state(STATE_NO_TPM_ROOT "\"projection_root_tpm\":\""
			     STATE_ROOT "\"," STATE_TAIL, &s), 0);
	EXPECT_STREQ(s.projection_root_tpm, STATE_ROOT);
	drop_tree();
}

/*
 * The tree eventlog matches a state that was read and holds its replay,
 * and no state that could not be read; a log that does not replay
 * leaves the answer unset.
 */
static void eventlog_matches_only_a_state_read(void)
{
	struct tree_state s = {};
	__u8 next[64] = {}, root[32], replay[32];
	bool matches = true;

	use_tree();
	EXPECT_EQ(tree_eventlog_matches(&s, 0, replay, &matches), -ENOENT);
	EXPECT_TRUE(matches);
	ASSERT_EQ(sha256_digest_decode(PENDING_DIGEST, next + 32), 0);
	ASSERT_EQ(sha256_buffer(next, sizeof(next), root), 0);
	ASSERT_EQ(tree_event_append(1, PENDING_DIGEST, root), 0);
	hex_encode(root, sizeof(root), s.projection_root);
	ASSERT_EQ(tree_eventlog_matches(&s, 0, replay, &matches), 0);
	EXPECT_TRUE(matches);
	EXPECT_MEMEQ(replay, root, sizeof(root));
	ASSERT_EQ(tree_eventlog_matches(&s, -EINVAL, replay, &matches), 0);
	EXPECT_FALSE(matches);
	s.projection_root[0] = s.projection_root[0] == '0' ? '1' : '0';
	ASSERT_EQ(tree_eventlog_matches(&s, 0, replay, &matches), 0);
	EXPECT_FALSE(matches);
	s.projection_root[0] = '\0';
	matches = true;
	ASSERT_EQ(tree_eventlog_matches(&s, 0, replay, &matches), 0);
	EXPECT_FALSE(matches);
	unlink(events_path);
	drop_tree();
}

static const struct unit_case cases[] = {
	UNIT_CASE(long_line_is_one_line),
	UNIT_CASE(config_with_a_nul_is_no_config),
	UNIT_CASE(gzip_config_is_one_whole_member),
	UNIT_CASE(pending_is_an_operation_in_flight),
	UNIT_CASE(labels_are_cut_at_the_first_equals),
	UNIT_CASE(outcomes_append_and_read_back),
	UNIT_CASE(outcomes_torn_last_line_is_dropped),
	UNIT_CASE(outcomes_resume_cuts_past_last_seq),
	UNIT_CASE(outcomes_gap_and_missing_line),
	UNIT_CASE(outcomes_longer_line_is_malformed),
	UNIT_CASE(outcomes_cover_the_state),
	UNIT_CASE(state_names_its_publication_head_and_base),
	UNIT_CASE(state_needs_both_projection_roots),
	UNIT_CASE(eventlog_matches_only_a_state_read),
	{}
};

UNIT_SUITE(bpm_tree_state, cases);
