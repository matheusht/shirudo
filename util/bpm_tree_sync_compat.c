// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <string.h>

#include "bpm_oci.h"
#include "bpm_tree.h"
#include "chain.h"
#include "hex.h"

int tree_publication_verify(const struct tree_publication *pub, int *bad_op)
{
	int ret;

	if (bad_op)
		*bad_op = -1;
	/*
	 * The node records the tree ID in its state, which takes names
	 * alone: one that is not would be applied, measured and logged
	 * and then never recorded, failing every later sync.
	 */
	if (!bpm_package_name_ok(pub->tree_id))
		return -EINVAL;
	ret = tree_publication_check(pub);
	if (ret)
		return ret;
	for (int i = 0; i < pub->n_operations; i++) {
		ret = tree_operation_validate(&pub->operations[i]);
		if (ret) {
			if (bad_op)
				*bad_op = i;
			return ret;
		}
	}
	return 0;
}

int tree_segment_precedes(const struct tree_publication *pred,
			  const char *pred_manifest_digest,
			  const struct tree_publication *succ)
{
	if (succ->base_seq <= 0 ||
	    strcmp(succ->segment_manifest_digest, pred_manifest_digest) ||
	    strcmp(pred->tree_id, succ->tree_id) ||
	    pred->head_seq != succ->base_seq ||
	    pred->generation >= succ->generation)
		return -ERANGE;
	return 0;
}

int tree_walk_within(__s64 base_seq, __s64 last_seq)
{
	__s64 limit = last_seq ? TREE_MAX_WALK_OPS : TREE_MAX_JOIN_OPS;

	if (base_seq < 0 || last_seq < 0)
		return -EINVAL;
	return base_seq - last_seq > limit ? -E2BIG : 0;
}

int tree_history_at(const struct tree_publication *pub, __s64 seq,
		    __u8 out[32])
{
	__u8 digest[32];
	int ret;

	memset(out, 0, 32);
	if (seq < pub->base_seq || seq > pub->head_seq)
		return -EINVAL;
	if (pub->base_seq && hex_decode(pub->history_root, out, 32))
		return -EINVAL;
	for (int i = 0; i < pub->n_operations; i++) {
		if (pub->operations[i].seq > seq)
			break;
		if (sha256_digest_decode(pub->operations[i].operation_digest,
					 digest))
			return -EINVAL;
		ret = chain_history_step(out, digest, out);
		if (ret)
			return ret;
	}
	return 0;
}
