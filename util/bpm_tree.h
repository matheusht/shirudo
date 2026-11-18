/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The signed upatch tree's publications, which rust/src/util/bpm_tree.rs
 * implements, and a target's state of the tree.
 */

#ifndef SHIRUDO_BPM_TREE_H
#define SHIRUDO_BPM_TREE_H

#include <stddef.h>

#include <shirudo/misc.h>

#include "chain.h"

#define TREE_MAX_OPS 512
#define TREE_MAX_KCONFIG 64
/* A proof sets it lower: CBMC's cost grows with the table. */
#ifndef TREE_MAX_LABELS
#define TREE_MAX_LABELS 64
#endif
#define TREE_MAX_SELECTOR_VALUES 16
#define TREE_STRING_MAX 256

/*
 * The most operations a walk back through sealed segments may cover from
 * seq 0, as a node that joins a tree does, and from the cursor of a node
 * that has processed one: one past it is -E2BIG. A running node walks
 * holding the bpm lock, with its keepalive stopped, so it gets the lower
 * one. A test build sets both low.
 */
#ifndef TREE_MAX_JOIN_OPS
#define TREE_MAX_JOIN_OPS 1048576
#endif
#ifndef TREE_MAX_WALK_OPS
#define TREE_MAX_WALK_OPS 65536
#endif

struct json_emit;

struct tree_kv {
	char key[TREE_STRING_MAX];
	char value[TREE_STRING_MAX];
};

struct tree_selector_kv {
	char key[TREE_STRING_MAX];
	char values[TREE_MAX_SELECTOR_VALUES][TREE_STRING_MAX];
	int n_values;
};

struct tree_selector {
	char kernel_release_prefix[TREE_MAX_SELECTOR_VALUES][TREE_STRING_MAX];
	int n_kernel_release_prefix;
	char kernel_build_id[TREE_MAX_SELECTOR_VALUES][TREE_STRING_MAX];
	int n_kernel_build_id;
	char architecture[TREE_MAX_SELECTOR_VALUES][TREE_STRING_MAX];
	int n_architecture;
	/*
	 * Owned and sized to what a selector names: at their full limits,
	 * every operation of a publication took 545 KiB for them.
	 */
	struct tree_selector_kv *kconfig;
	int n_kconfig;
	struct tree_selector_kv *labels;
	int n_labels;
};

/*
 * A new zeroed pair at the end of the n at *kvs, of at most max: 0 with
 * it in *kv, -E2BIG or -ENOMEM. tree_selector_copy() fills dst, which
 * holds no pairs, with copies of src's; tree_selector_free() releases
 * the pairs, and a zeroed selector holds none.
 */
int tree_selector_kv_add(struct tree_selector_kv **kvs, int *n, int max,
			 struct tree_selector_kv **kv);
int tree_selector_copy(struct tree_selector *dst,
		       const struct tree_selector *src);
void tree_selector_free(struct tree_selector *s);

struct tree_artifact {
	char repository[512];
	char manifest_digest[128];
	char layer_digest[128];
	char payload_sha256[128];
};

struct tree_operation {
	__s64 seq;
	char op[16];
	char id[TREE_STRING_MAX];
	struct tree_selector selector;
	struct tree_artifact artifact;
	char operation_digest[128];
};

struct tree_publication {
	int schema;
	char tree_id[TREE_STRING_MAX];
	__s64 generation;
	char parent_manifest_digest[128];
	__s64 base_seq;
	/* Past the first segment: its sealed predecessor, history at base. */
	char segment_manifest_digest[128];
	char history_root[65];
	struct tree_operation *operations;
	int operations_capacity;
	int n_operations;
	__s64 head_seq;
};

struct tree_state {
	int schema;
	char tree_id[TREE_STRING_MAX];
	__s64 generation;
	__s64 last_seq;
	/* Software projection is only a crash-recovery cursor when TPM is absent. */
	char projection_root[65];
	char projection_root_tpm[65];
	char manifest_digest[128];
	__s64 head_seq;
	__s64 segment_base_seq;
};

int tree_parse(const char *body, size_t len,
	       struct tree_publication *out);
/* Appends a copy of op, its selector included. */
int tree_publication_append(struct tree_publication *pub,
			    const struct tree_operation *op);
void tree_publication_free(struct tree_publication *pub);

/*
 * Canonical forms shared by publisher and target: the operation digest
 * ("sha256:" + 64 hex) over an operation without its digest field, and
 * the publication document. The emitted document is xmalloc'd; release
 * it with xfree(out, out_len).
 *
 * extra, NULL for none, adds keys to the operation at index of
 * pub->operations after its artifact, outside the operation digest: the
 * publisher's fixes, which no node reads.
 */
struct tree_emit_extra {
	int	(*operation)(struct json_emit *e, int index, void *ctx);
	void	*ctx;
};

int tree_operation_digest(const struct tree_operation *op,
			  char out[72]);
int tree_emit_publication(const struct tree_publication *pub,
			  const struct tree_emit_extra *extra,
			  char **out, size_t *out_len);

/*
 * What tree sync checks before it applies anything. An operation has a
 * positive sequence number, an upatch name, add or delete, well-formed
 * digests and the operation digest its fields hash to: 0, -EINVAL, or
 * -EKEYREJECTED for a digest that does not match. A publication names a
 * well-formed parent digest if any, and its operations run from
 * base_seq + 1 to head_seq, or head_seq is base_seq without them. A
 * segment past the first, base_seq above 0, holds an operation or more
 * and names a well-formed sealed predecessor digest and history root; the
 * first names neither: 0 or -EINVAL.
 *
 * tree_publication_verify() makes those checks of a publication, and that
 * its tree ID is a name the node can record: 0 or the first failure, with
 * *bad_op, unless NULL, the index of the operation that failed or -1.
 *
 * And it may follow the state the node recorded, NULL for none, with
 * manifest_digest its manifest's: the same tree, a later generation
 * unless it is the same manifest, the parent the node recorded when it is
 * the next generation and names one, and no head before the node's
 * cursor. 0, -EINVAL for another tree, -ERANGE, or TREE_FOLLOWS_WALK when
 * its base lies past the cursor, 0 without a state, and the node must
 * walk back through the sealed segments before it.
 *
 * tree_segment_precedes() is the check of one step of that walk: pred,
 * whose manifest hashed to pred_manifest_digest, is the sealed segment
 * succ names, of the same tree, ending where succ starts and of a lower
 * generation. 0 or -ERANGE.
 */
#define TREE_FOLLOWS_WALK 1

int tree_operation_validate(const struct tree_operation *op);
int tree_publication_check(const struct tree_publication *pub);
int tree_publication_verify(const struct tree_publication *pub,
			    int *bad_op) __must_check;
int tree_publication_follows(const struct tree_publication *pub,
			     const struct tree_state *state,
			     const char *manifest_digest);
int tree_segment_precedes(const struct tree_publication *pred,
			  const char *pred_manifest_digest,
			  const struct tree_publication *succ) __must_check;

/*
 * tree_walk_within() is the limit of that walk: 0 when a node whose cursor
 * is last_seq may walk back to a segment that starts at base_seq,
 * TREE_MAX_JOIN_OPS operations at most from 0 and TREE_MAX_WALK_OPS from
 * any other cursor, -E2BIG past it, -EINVAL for a negative number.
 *
 * tree_history_at() gives the history root at seq of a publication that
 * tree_publication_check() accepts: its base's, 32 zero bytes at 0, over
 * the digests of its operations up to seq. -EINVAL for a seq outside base
 * to head or a malformed root or digest.
 */
int tree_walk_within(__s64 base_seq, __s64 last_seq) __must_check;
int tree_history_at(const struct tree_publication *pub, __s64 seq,
		    __u8 out[32]) __must_check;

/*
 * The selector match and the state below are
 * rust/src/util/bpm_tree_state.rs.
 *
 * Evaluate a publication selector against the running node.  An empty
 * selector is an unconstrained wildcard and matches every node.  1 on a
 * match, 0 without one, -errno when the node's labels or kernel config
 * cannot be read.
 */
int tree_selector_matches(const struct tree_selector *selector);

/*
 * The operation tree sync is applying, recorded before it starts so that
 * a sync after a crash reconciles it with the tree eventlog: its
 * sequence number, upatch name and operation digest. Parsing refuses a
 * record that does not have those; reading is -ENOENT for none.
 */
struct tree_pending {
	__s64 seq;
	char id[TREE_STRING_MAX];
	char operation_digest[128];
};

int tree_pending_parse(const char *body, size_t len,
		       struct tree_pending *out);
int tree_pending_read(struct tree_pending *out);
int tree_pending_write(const struct tree_operation *op);

int tree_state_read(struct tree_state *out);
int tree_state_write(const struct tree_state *state);
int tree_event_append(__s64 seq, const char *operation_digest,
		      const __u8 projection_root[32]);
int tree_event_replay(__u8 out[32]);
/*
 * Replays the tree eventlog into replay and sets *matches when it equals
 * the projection root of s, which tree_state_read() returned state_rc
 * for: a state that could not be read matches no replay. 0, or
 * tree_event_replay()'s error, leaving *matches as it was.
 */
int tree_eventlog_matches(const struct tree_state *s, int state_rc,
			  __u8 replay[32], bool *matches) __must_check;

enum tree_outcome {
	TREE_OUTCOME_APPLIED = 1,
	TREE_OUTCOME_UNMATCHED = 2,
	TREE_OUTCOME_MODULE_ABSENT = 3,
};

/*
 * A writer holds the bpm lock. tree_outcomes_read() gives the outcomes
 * of seq from + 1 through seq to and the roots at from;
 * tree_outcomes_resume() gives the history root at last_seq and drops
 * the lines past it, which a sync that stopped left. Seq 0 has zero
 * roots. Both are -ENOENT without a record unless they ask for no line,
 * and -EBADMSG for one that ends early or is out of order.
 */
int tree_outcome_append(__s64 seq, enum tree_outcome outcome,
			const __u8 projection_root[32],
			const __u8 history_root[32]) __must_check;
int tree_outcomes_read(__s64 from, __s64 to, __u8 *codes,
		       __u8 projection_root[32],
		       __u8 history_root[32]) __must_check;
int tree_outcomes_resume(__s64 last_seq,
			 __u8 history_root[32]) __must_check;

void tree_emit_status(struct json_emit *e);

/* Whether a tree is configured, in the config image when one is active. */
bool tree_configured(void);

/*
 * For the unit test and fuzz targets, which reached these by including
 * the C once: the values the kernel config at path, gzip'd or not,
 * gives the selector's kconfig keys, as the selector match reads
 * /proc/config.gz and /boot/config-*, 0 with found[i] and values[i]
 * for each key i the config sets, or -errno; the key = value lines of
 * a node.labels at path into the max pairs at labels, *n of them; and
 * tree_state_read() and tree_event_replay() on the file at path.
 */
int tree_kconfig_read(const char *path, const struct tree_selector *s,
		      char values[][TREE_STRING_MAX], bool found[], bool gz);
int tree_labels_read(const char *path, struct tree_kv *labels, int *n,
		     int max);
int tree_state_read_path(const char *path, struct tree_state *out);
int tree_event_replay_path(const char *path, __u8 out[32]);
/*
 * The directory of the tree's state, eventlog, outcomes and pending
 * record in place of BPM_TREE_VAR_DIR, for the unit test, which reached
 * them by redefining the paths when it included the C; NULL restores it.
 */
int tree_var_dir_set(const char *dir);
/*
 * For the fuzz target: the file at path, open at fd and of size bytes,
 * read as a state, an eventlog and an outcome record at once, with the
 * checks its harness made of the C; it aborts where one fails.
 */
void tree_state_fuzz(const char *path, int fd, size_t size);

#endif /* SHIRUDO_BPM_TREE_H */
