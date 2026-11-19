#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7110 -- the keepalive body reports the last operations up to the head of
# a segmented tree whatever segments hold them: its base_seq, base_root and
# mask are those of the outcomes record over a window that starts in an
# older segment than the recorded one, also while an operation is pending.
# In bpm-segments, after t7108, since the bpm VM's node follows another
# tree. The bundle lowers the window to 7 operations, the segments hold 2.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
SOURCE="$FIXTURES/segments-oci"
TREE_DIR=/var/lib/shirudo/bpm/upatch-tree
OUTCOMES=$TREE_DIR/outcomes
TREE_EVENTLOG=$TREE_DIR/tree-eventlog
PENDING=$TREE_DIR/pending.json
EVENTLOG=/var/lib/shirudo/eventlog
WINDOW=7
WORK=$(mktemp -d)
SERVED="$WORK/registry"
REPO="$SERVED/shirudo/segments"
SERVER_PID=
HOLDER_PID=

for fixture in "$SOURCE/port" "$SOURCE/shirudo/segments/manifests/g28" \
	"$SHIRUDO_TEST_KEY_FIXTURES/config-tree-segments.img" \
	./helper/test-oci-registry.py
do
	[ -s "$fixture" ] || test_skip_all "missing segment fixture: $fixture"
done
if [ -e "$TREE_STATE_FILE" ]; then
	[ "$(tree_state_field tree_id)" = shirudo-test-segments ] &&
		[ ! -e "$PENDING" ] &&
		[ "$(tree_state_field last_seq)" -le 24 ] &&
		[ "$(tree_state_field last_seq)" = "$(tree_state_field head_seq)" ] ||
		test_skip_all "the node is not where t7108 leaves it"
fi
PORT=$(cat "$SOURCE/port")

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
	if [ -n "$SERVER_PID" ]; then
		kill "$SERVER_PID" 2>/dev/null || true
		wait "$SERVER_PID" 2>/dev/null || true
	fi
	rm -rf "$WORK"
}
trap cleanup EXIT

# The target follows the reference segments, which names generation $1.
serve()
{
	cp "$REPO/manifests/g$1" "$REPO/manifests/segments"
}

sync_tree()
{
	BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
		--report "$WORK/$1.json" >/dev/null 2>"$WORK/$1.err"
}

keepalive()
{
	"$SHIRUDO_BIN" status --keepalive >"$1"
}

# The body in $1 has the tree keys of state.json, and base_seq, base_root
# and mask of the outcomes record over the last $WINDOW operations up to
# head_seq. With settled as $2 flags bits 2, 4 and 5 are clear, with
# pending bit 4 is set. With $3, the window starts before the recorded
# segment's base and its root is not that of seq 0.
window_agrees()
{
	python3 - "$1" "$2" "${3:-}" "$TREE_STATE_FILE" "$OUTCOMES" \
		"$WINDOW" <<'PY'
import base64
import json
import pathlib
import sys

TREE_LOG_MISMATCH, TREE_OP_PENDING, SNAPSHOT_UNSETTLED = 4, 16, 32

body_path, mode, spans, state_path, outcomes_path = sys.argv[1:6]
window = int(sys.argv[6])
body = json.loads(pathlib.Path(body_path).read_bytes())
state = json.loads(pathlib.Path(state_path).read_bytes())
lines = [json.loads(text) for text in
         pathlib.Path(outcomes_path).read_text(encoding="utf-8").splitlines()]
outcome = {line["seq"]: line for line in lines}
head, last = state["head_seq"], state["last_seq"]
base = max(0, head - window)
for key in ("tree_id", "generation", "last_seq", "projection_root"):
    if body[key] != state[key]:
        sys.exit(f"{key} is {body[key]}, state.json has {state[key]}")
root = outcome[base]["projection_root"] if base else "00" * 32
if body["base_seq"] != base or body["base_root"] != root:
    sys.exit(f"the window starts at {body['base_seq']} {body['base_root']}, "
             f"not {base} {root}")
if spans and (base >= state["segment_base_seq"] or root == "00" * 32):
    sys.exit(f"the window from {base} stays in the segment from "
             f"{state['segment_base_seq']}")

mask = base64.b64decode(body["mask"], validate=True)
if len(mask) != (head - base + 3) // 4:
    sys.exit(f"the mask has {len(mask)} bytes for {head - base} operations")
for i in range(4 * len(mask)):
    seq = base + 1 + i
    code = mask[i // 4] >> (6 - 2 * (i % 4)) & 3
    want = outcome[seq]["outcome"] if seq <= min(last, head) else 0
    if code != want:
        sys.exit(f"the mask gives {code} for {seq}, not {want}")

flags = body["flags"]
if mode == "pending":
    if not flags & TREE_OP_PENDING:
        sys.exit(f"flags {flags} lack the pending operation")
elif flags & (TREE_LOG_MISMATCH | TREE_OP_PENDING | SNAPSHOT_UNSETTLED):
    sys.exit(f"flags {flags} say the tree is busy or does not agree")
PY
}

# Hold the lock event_append() takes, so that a sync stops after an
# operation's load and register extend, before its outcomes line.
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

cp -R "$SOURCE" "$SERVED"
python3 ./helper/test-oci-registry.py --root "$SERVED" --port "$PORT" \
	--ready-file "$WORK/ready" &
SERVER_PID=$!
for _ in 1 2 3 4 5; do
	[ -e "$WORK/ready" ] && break
	sleep 1
done
[ -e "$WORK/ready" ] || test_skip_all "the segment registry did not start"
"$SHIRUDO_BIN" image update "$SHIRUDO_TEST_KEY_FIXTURES/config-tree-segments" \
	>/dev/null || test_skip_all "cannot activate config-tree-segments"

# A node t7108 did not bring along takes the tree one segment at a time.
LAST=$(tree_state_field last_seq)
k=$((${LAST:-0} + 2))
while [ "$k" -le 24 ]; do
	serve "$k" && sync_tree "catch-up-$k" ||
		test_skip_all "cannot sync the segment tree to $k"
	k=$((k + 2))
done

test_expect_success 'a body at seq 24 reports a window that starts in an older segment' '
	[ "$(tree_state_field last_seq)" = 24 ] &&
	[ "$(tree_state_field segment_base_seq)" = 22 ] &&
	keepalive "$WORK/at-24.json" &&
	[ "$(report_field base_seq <"$WORK/at-24.json")" = 17 ] &&
	window_agrees "$WORK/at-24.json" settled spans
'

test_expect_success 'the window slides with the next segment' '
	serve 26 &&
	sync_tree at-26 &&
	[ "$(tree_state_field last_seq)" = 26 ] &&
	keepalive "$WORK/at-26.json" &&
	[ "$(report_field base_seq <"$WORK/at-26.json")" = 19 ] &&
	window_agrees "$WORK/at-26.json" settled spans
'

# A test body runs in a subshell, which could not hand the lock holder to
# the cleanup: stop the sync here and let the bodies look at what is left.
serve 28
STOPPED=no
if hold_tree_eventlog; then
	BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
		--report "$WORK/stopped.json" >/dev/null 2>&1 &
	SYNC_PID=$!
	tree_op_measured 27 && STOPPED=yes
	kill -9 "$SYNC_PID" 2>/dev/null || true
	wait "$SYNC_PID" 2>/dev/null || true
fi
release_tree_eventlog
if [ "$STOPPED" = yes ] && ! keepalive "$WORK/stopped-body.json"; then
	STOPPED=no
fi

test_expect_success 'with an operation pending the window ends at the head and leaves it not reached' '
	[ "$STOPPED" = yes ] &&
	[ -e "$PENDING" ] &&
	[ "$(tree_state_field last_seq)" = 26 ] &&
	[ "$(tree_state_field head_seq)" = 28 ] &&
	[ "$(report_field base_seq <"$WORK/stopped-body.json")" = 21 ] &&
	window_agrees "$WORK/stopped-body.json" pending spans
'

test_expect_success 'after the sync completes the window covers the head' '
	sync_tree at-28 &&
	[ ! -e "$PENDING" ] &&
	[ "$(tree_state_field last_seq)" = 28 ] &&
	keepalive "$WORK/at-28.json" &&
	[ "$(report_field base_seq <"$WORK/at-28.json")" = 21 ] &&
	window_agrees "$WORK/at-28.json" settled spans
'

test_done
