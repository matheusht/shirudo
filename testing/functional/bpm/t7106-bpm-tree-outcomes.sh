#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7106 -- the outcomes record has one line for every operation the node
# processed: applied, unmatched and module absent, after a sync that was
# killed between the register extend and its state, and after one that
# failed at a fetch, which leaves the publication it accepted on record.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
TREE_DIR=/var/lib/shirudo/bpm/upatch-tree
OUTCOMES=$TREE_DIR/outcomes
TREE_EVENTLOG=$TREE_DIR/tree-eventlog
PENDING=$TREE_DIR/pending.json
EVENTLOG=/var/lib/shirudo/eventlog
ABSENT=shirudo-test-uprobe-multi
MATCH_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-match/link
SKIP_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-skip/link
WORK=$(mktemp -d)
SERVED="$WORK/registry"
TREE_REPO="$SERVED/shirudo/upatch-tree"
HOLDER_PID=

for fixture in \
	"$REGISTRY/shirudo/upatch-tree/manifests/outcomes" \
	"$REGISTRY/shirudo/upatch-tree/manifests/stopped" \
	"$REGISTRY/shirudo/upatch-tree/manifests/fetched" \
	"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
	"$FIXTURES/shirudo-test-tree-skip.unload.upatch" \
	"$FIXTURES/cert.der" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing tree fixture: $fixture"
done
[ -d "$REGISTRY/shirudo/tree-absent" ] &&
	[ -d "$REGISTRY/shirudo/tree-skip-unload" ] ||
	test_skip_all "missing tree fixture artifacts"

[ "$(tree_state_field tree_id)" = shirudo-test-tree ] &&
	[ "$(tree_state_field last_seq)" = 7 ] &&
	[ ! -e "$MATCH_PIN" ] && [ ! -e "$SKIP_PIN" ] ||
	test_skip_all "tree state is not where t7105 leaves it"
# The upatch of operation 10 probes this file, which only the upatch
# family's tests put there.
[ ! -e /tmp/shirudo-test-uprobe-target ] ||
	test_skip_all "the uprobe target of operation 10 is present"

release_tree_eventlog()
{
	[ -n "$HOLDER_PID" ] || return 0
	kill "$HOLDER_PID" 2>/dev/null || true
	wait "$HOLDER_PID" 2>/dev/null || true
	HOLDER_PID=
}

cleanup()
{
	release_tree_eventlog
	tree_registry_stop
	for name in shirudo-test-tree-match shirudo-test-tree-skip; do
		[ -e "/run/shirudo/bpffs/upatches/$name/link" ] || continue
		"$SHIRUDO_BIN" upatch unload \
			"$FIXTURES/$name.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	done
	tree_cleanup_config
	rm -rf "$WORK"
}
trap cleanup EXIT

# The record holds exactly the lines of seq 1 to $1, each with the history
# root its operation digests fold to and the projection root the tree
# eventlog has at it: outcome 1 or 3 where the eventlog has a line, 2
# where it has none. The arguments after $1 are the outcomes of the last
# lines.
outcomes_agree()
{
	python3 - "$OUTCOMES" "$TREE_EVENTLOG" "$TREE_REPO" "$@" <<'PY'
import hashlib
import json
import pathlib
import sys

outcomes, eventlog, repo = map(pathlib.Path, sys.argv[1:4])
head = int(sys.argv[4])
want = [int(code) for code in sys.argv[5:]]

manifest = json.loads((repo / "manifests" / "fetched").read_bytes())
document = (repo / "blobs" / manifest["layers"][0]["digest"]).read_bytes()
digests = {op["seq"]: bytes.fromhex(op["operation_digest"][len("sha256:"):])
           for op in json.loads(document)["operations"]}
applied = {}
for text in eventlog.read_text(encoding="utf-8").splitlines():
    event = json.loads(text)
    applied[event["seq"]] = event["projection_root"]

lines = [json.loads(text)
         for text in outcomes.read_text(encoding="utf-8").splitlines()]
seqs = [line["seq"] for line in lines]
if seqs != list(range(1, head + 1)):
    sys.exit(f"outcomes has the lines {seqs}, not 1 to {head}")
if set(applied) - set(seqs):
    sys.exit(f"the tree eventlog has lines past {head}: {sorted(applied)}")
projection = "00" * 32
history = bytes(32)
for line in lines:
    seq = line["seq"]
    history = hashlib.sha256(b"shirudo-tree-history\0" + history +
                             digests[seq]).digest()
    if seq in applied:
        projection = applied[seq]
        codes = (1, 3)
    else:
        codes = (2,)
    if line["schema"] != 1 or line["outcome"] not in codes:
        sys.exit(f"line {seq} has outcome {line['outcome']}, not one of {codes}")
    if line["projection_root"] != projection:
        sys.exit(f"line {seq} has another projection root than the eventlog")
    if line["history_root"] != history.hex():
        sys.exit(f"line {seq} has another history root than its digests give")
got = [line["outcome"] for line in lines][len(lines) - len(want):]
if got != want:
    sys.exit(f"the last outcomes are {got}, not {want}")
PY
}

outcomes_last()
{
	python3 -c '
import json, sys
lines = open(sys.argv[1], encoding="utf-8").read().splitlines()
last = json.loads(lines[-1])
print(len(lines), last["seq"], last["outcome"])
' "$OUTCOMES"
}

# Hold the lock event_append() takes, so that a sync stops where it
# appends an operation's line: after the register extend, before the
# outcomes line and the state.
hold_tree_eventlog()
{
	python3 -c '
import fcntl, os, sys, time
fd = os.open(sys.argv[1], os.O_RDONLY)
fcntl.flock(fd, fcntl.LOCK_EX)
open(sys.argv[2], "w").close()
time.sleep(600)
' "$TREE_EVENTLOG" "$WORK/held" &
	HOLDER_PID=$!
	for _ in 1 2 3 4 5 6 7 8 9 10; do
		[ -e "$WORK/held" ] && return 0
		sleep 1
	done
	return 1
}

# Wait until this boot's eventlog has the tree_op record of seq $1.
tree_op_measured()
{
	python3 - "$EVENTLOG" "$1" <<'PY'
import json
import sys
import time

seq = int(sys.argv[2])
for _ in range(600):
    with open(sys.argv[1], encoding="utf-8") as stream:
        for text in stream:
            try:
                record = json.loads(text)
            except ValueError:
                continue
            if record.get("type") == "tree_op" and \
               record.get("tree", {}).get("seq") == seq:
                sys.exit(0)
    time.sleep(0.1)
sys.exit(1)
PY
}

# The registry serves a copy, so that an artifact can go missing.
cp -R "$REGISTRY" "$SERVED"
tree_configure outcomes
tree_registry_start "$SERVED" "$WORK"

test_expect_success 'the record covers what t7101 to t7105 processed' '
	outcomes_agree 7 1 2 1 1 1 1 1 &&
	[ "$(tree_state_field head_seq)" = 7 ] &&
	[ "$(tree_state_field segment_base_seq)" = 0 ]
'

test_expect_success 'an applied, an unmatched and a module-absent operation get outcomes 1, 2 and 3' '
	tree_sync "$WORK/outcomes.json" &&
	[ "$(report_field selected <"$WORK/outcomes.json")" = 2 ] &&
	[ "$(report_field skipped <"$WORK/outcomes.json")" = 1 ] &&
	[ "$(report_field applied <"$WORK/outcomes.json")" = 2 ] &&
	[ "$(report_field module_skipped <"$WORK/outcomes.json")" = 1 ] &&
	[ "$(report_field last_seq <"$WORK/outcomes.json")" = 10 ] &&
	[ -e "$MATCH_PIN" ] &&
	[ ! -e "/run/shirudo/bpffs/upatches/$ABSENT" ] &&
	[ "$(cat "$TREE_DIR/status/$ABSENT")" = "skipped: module not loaded" ] &&
	outcomes_agree 10 1 2 3 &&
	[ "$(tree_state_field generation)" = 7 ] &&
	[ "$(tree_state_field head_seq)" = 10 ]
'

# A test body runs in a subshell, which could not hand the lock holder
# to the cleanup: stop the sync here and let the body look at what is left.
tree_configure stopped
STOPPED=no
if hold_tree_eventlog; then
	BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
		--report "$WORK/stopped.json" >/dev/null 2>&1 &
	SYNC_PID=$!
	if tree_op_measured 12; then
		STOPPED=yes
	fi
	kill -9 "$SYNC_PID" 2>/dev/null || true
	wait "$SYNC_PID" 2>/dev/null || true
fi
release_tree_eventlog

test_expect_success 'a sync killed after the register extend leaves the cursor and a pending operation' '
	[ "$STOPPED" = yes ] &&
	[ ! -e "$WORK/stopped.json" ] &&
	[ -e "$PENDING" ] &&
	[ -e "$SKIP_PIN" ] &&
	[ "$(tree_state_field last_seq)" = 10 ] &&
	[ "$(tree_state_field generation)" = 8 ] &&
	[ "$(tree_state_field head_seq)" = 12 ] &&
	[ "$(outcomes_last)" = "11 11 2" ]
'

test_expect_success 'the next sync completes it with one line for each seq, 2 for the unmatched one' '
	tree_sync "$WORK/recovered.json" &&
	[ "$(report_field selected <"$WORK/recovered.json")" = 0 ] &&
	[ "$(report_field skipped <"$WORK/recovered.json")" = 0 ] &&
	[ "$(report_field applied <"$WORK/recovered.json")" = 0 ] &&
	[ "$(report_field last_seq <"$WORK/recovered.json")" = 12 ] &&
	[ ! -e "$PENDING" ] &&
	[ -e "$SKIP_PIN" ] &&
	outcomes_agree 12 2 1 &&
	[ "$(tree_state_field last_seq)" = 12 ]
'

test_expect_success 'a sync that fails at a fetch leaves the publication it accepted on record' '
	tree_configure fetched &&
	mv "$SERVED/shirudo/tree-skip-unload" "$WORK/tree-skip-unload" &&
	! BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
		--report "$WORK/failed.json" >/dev/null 2>"$WORK/failed.err" &&
	grep -q "phase=artifact_fetch_or_verify seq=13 " "$WORK/failed.err" &&
	[ ! -e "$WORK/failed.json" ] &&
	[ "$(tree_state_field generation)" = 9 ] &&
	[ "$(tree_state_field head_seq)" = 13 ] &&
	[ "$(tree_state_field last_seq)" = 12 ] &&
	[ -e "$SKIP_PIN" ] &&
	outcomes_agree 12
'

test_expect_success 'the next sync finishes that publication' '
	mv "$WORK/tree-skip-unload" "$SERVED/shirudo/tree-skip-unload" &&
	tree_sync "$WORK/finished.json" &&
	[ "$(report_field selected <"$WORK/finished.json")" = 1 ] &&
	[ "$(report_field applied <"$WORK/finished.json")" = 1 ] &&
	[ "$(report_field last_seq <"$WORK/finished.json")" = 13 ] &&
	[ ! -e "$SKIP_PIN" ] &&
	[ ! -e "$PENDING" ] &&
	outcomes_agree 13 1 &&
	[ "$(tree_state_field generation)" = 9 ] &&
	[ "$(tree_state_field head_seq)" = 13 ] &&
	[ "$(tree_state_field last_seq)" = 13 ]
'

test_done
