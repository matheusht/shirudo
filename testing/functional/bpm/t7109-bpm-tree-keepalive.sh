#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t7109 -- status --keepalive reads the tree keys and the loaded set of
# one point: a body taken while a sync is stopped between its load and its
# state says so in flags bit 4, and one taken after a sync carries the mask
# and roots of the outcomes record and state.json and the set the applied
# operations fold to.

cd "$(dirname "$0")/../.."
. ./integration-lib.sh
target_guard
command -v python3 >/dev/null 2>&1 || test_skip_all "no python3"

FIXTURES=${SHIRUDO_TEST_FIXTURES_DIR:?target fixture directory is not set}
REGISTRY="$FIXTURES/tree-oci"
TREE_REPO="$REGISTRY/shirudo/upatch-tree"
TREE_DIR=/var/lib/shirudo/bpm/upatch-tree
OUTCOMES=$TREE_DIR/outcomes
TREE_EVENTLOG=$TREE_DIR/tree-eventlog
PENDING=$TREE_DIR/pending.json
EVENTLOG=/var/lib/shirudo/eventlog
MATCH_PIN=/run/shirudo/bpffs/upatches/shirudo-test-tree-match/link
# The bundle lowers the keepalive window to the last 7 operations.
WINDOW=7
WORK=$(mktemp -d)
HOLDER_PID=

for fixture in \
	"$TREE_REPO/manifests/keepalive" \
	"$TREE_REPO/manifests/unmatched" \
	"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
	"$FIXTURES/cert.der" \
	"./helper/test-oci-registry.py"
do
	[ -s "$fixture" ] || test_skip_all "missing tree fixture: $fixture"
done

[ "$(tree_state_field tree_id)" = shirudo-test-tree ] &&
	[ "$(tree_state_field last_seq)" = 16 ] &&
	[ "$(tree_state_field head_seq)" = 16 ] &&
	[ ! -e "$PENDING" ] && [ ! -e "$MATCH_PIN" ] ||
	test_skip_all "tree state is not where t7107 leaves it"

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
	[ ! -e "$MATCH_PIN" ] ||
		"$SHIRUDO_BIN" upatch unload \
			"$FIXTURES/shirudo-test-tree-match.unload.upatch" \
			--no-precheck >/dev/null 2>&1 || true
	tree_cleanup_config
	rm -rf "$WORK"
}
trap cleanup EXIT

# Hold the lock event_append() takes, so that a sync stops where it
# appends an operation's line: after its load and the register extend,
# before the outcomes line and the state.
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

# The body in $1 is compact, has the keys of the format in their order,
# and its tree keys are those of state.json and the outcomes record over
# the last $WINDOW operations. With
# settled as $2, flags bits 2, 4 and 5 are clear and the loaded set is the
# fold of the operations the mask has applied in the publication of the
# reference $3; with pending, flags bit 4 is set.
keepalive_agrees()
{
	python3 - "$1" "$2" "$TREE_STATE_FILE" "$OUTCOMES" \
		"$TREE_REPO" "${3:-}" "$WINDOW" <<'PY'
import base64
import hashlib
import json
import pathlib
import sys

KEYS = ["schema", "boot_id", "version_id", "config_root", "kernel_release",
        "image_id", "image_version", "image_root", "verdict", "cond", "flags",
        "tamper", "integrity", "tree_id", "generation", "base_seq",
        "last_seq", "base_root", "projection_root", "mask", "set_sha256",
        "count", "not_ok"]
TREE_LOG_MISMATCH, TREE_OP_PENDING, SNAPSHOT_UNSETTLED = 4, 16, 32

body_path, mode, state_path, outcomes_path, repo = sys.argv[1:6]
reference, window = sys.argv[6], int(sys.argv[7])
raw = pathlib.Path(body_path).read_bytes()
if not raw.endswith(b"\n"):
    sys.exit("the body does not end in a newline")
raw = raw[:-1]
pairs = json.loads(raw, object_pairs_hook=lambda kv: kv)
if [key for key, _ in pairs] != KEYS:
    sys.exit(f"the keys are {[key for key, _ in pairs]}")
body = dict(pairs)
if json.dumps(body, separators=(",", ":")).encode() != raw:
    sys.exit("the body is not compact")

state = json.loads(pathlib.Path(state_path).read_bytes())
lines = [json.loads(text) for text in
         pathlib.Path(outcomes_path).read_text(encoding="utf-8").splitlines()]
outcome = {line["seq"]: line["outcome"] for line in lines}
head, last = state["head_seq"], state["last_seq"]
base = max(0, head - window)
for key in ("tree_id", "generation", "last_seq", "projection_root"):
    if body[key] != state[key]:
        sys.exit(f"{key} is {body[key]}, state.json has {state[key]}")
root = lines[base - 1]["projection_root"] if base else "00" * 32
if body["base_seq"] != base or body["base_root"] != root:
    sys.exit(f"the window starts at {body['base_seq']} {body['base_root']}")

mask = base64.b64decode(body["mask"], validate=True)
if len(mask) != (head - base + 3) // 4:
    sys.exit(f"the mask has {len(mask)} bytes for {head - base} operations")
for i in range(4 * len(mask)):
    seq = base + 1 + i
    code = mask[i // 4] >> (6 - 2 * (i % 4)) & 3
    want = outcome[seq] if seq <= last else 0
    if code != want:
        sys.exit(f"the mask gives {code} for {seq}, not {want}")

flags = body["flags"]
if mode == "pending":
    if not flags & TREE_OP_PENDING:
        sys.exit(f"flags {flags} lack the pending operation")
    sys.exit(0)
if flags & (TREE_LOG_MISMATCH | TREE_OP_PENDING | SNAPSHOT_UNSETTLED):
    sys.exit(f"flags {flags} say the tree is busy or does not agree")
if not reference:
    sys.exit(0)

manifest = json.loads((pathlib.Path(repo) / "manifests" / reference)
                      .read_bytes())
document = (pathlib.Path(repo) / "blobs" / manifest["layers"][0]["digest"])
operations = json.loads(document.read_bytes())["operations"]
loaded = {}
for op in operations:
    if op["seq"] > last or outcome[op["seq"]] != 1:
        continue
    if op["op"] == "add":
        loaded[op["id"]] = op["artifact"]["payload_sha256"][len("sha256:"):]
    else:
        loaded.pop(op["id"], None)
listing = "".join(f"{loaded[name]} {name}\n" for name in sorted(loaded))
want = hashlib.sha256(listing.encode()).hexdigest()
if body["set_sha256"] != want or body["count"] != len(loaded):
    sys.exit(f"the set is {body['set_sha256']} of {body['count']}, the "
             f"mask folds to {want} of {len(loaded)}")
if body["not_ok"] != 0:
    sys.exit(f"{body['not_ok']} loaded upatches are not ok")
PY
}

# The mask of the operations $2 to $3 alone, from the body in $1.
mask_of()
{
	python3 - "$1" "$2" "$3" <<'PY'
import base64
import json
import sys

body = json.load(open(sys.argv[1], encoding="utf-8"))
first, last = int(sys.argv[2]), int(sys.argv[3])
mask = base64.b64decode(body["mask"])
codes = [mask[(seq - 1 - body["base_seq"]) // 4] >>
         (6 - 2 * ((seq - 1 - body["base_seq"]) % 4)) & 3
         for seq in range(first, last + 1)]
packed = bytearray((len(codes) + 3) // 4)
for i, code in enumerate(codes):
    packed[i // 4] |= code << (6 - 2 * (i % 4))
print(base64.b64encode(bytes(packed)).decode())
PY
}

keepalive()
{
	"$SHIRUDO_BIN" status --keepalive >"$1"
}

# set -e reaches into $(...) under dash, so the status is caught here
# rather than read from $? after a failing command.
exit_status()
{
	status=0
	"$@" >/dev/null 2>&1 || status=$?
	echo "$status"
}

tree_registry_start "$REGISTRY" "$WORK"

test_expect_success 'the body carries the tree keys of state.json and the outcomes record' '
	keepalive "$WORK/before.json" &&
	keepalive_agrees "$WORK/before.json" settled
'

test_expect_success 'status --keepalive goes without --json and --otel' '
	[ "$(exit_status "$SHIRUDO_BIN" status --keepalive --json)" = 2 ] &&
	[ "$(exit_status "$SHIRUDO_BIN" status --keepalive --otel)" = 2 ]
'

# A test body runs in a subshell, which could not hand the lock holder
# to the cleanup: kill the sync here and let the body look at what is left.
# A running sync holds the config operation lock that status waits for, so
# the body is taken once the sync is gone and pending.json is all it left.
tree_configure keepalive
STOPPED=no
if hold_tree_eventlog; then
	BPM_OCI_SCHEME=http "$SHIRUDO_BIN" bpm tree sync \
		--report "$WORK/stopped.json" >/dev/null 2>&1 &
	SYNC_PID=$!
	if tree_op_measured 17; then
		STOPPED=yes
	fi
	kill -9 "$SYNC_PID" 2>/dev/null || true
	wait "$SYNC_PID" 2>/dev/null || true
fi
release_tree_eventlog
if [ "$STOPPED" = yes ] && ! keepalive "$WORK/stopped-body.json"; then
	STOPPED=no
fi

test_expect_success 'a body taken after a sync is killed after its load has flags bit 4' '
	[ "$STOPPED" = yes ] &&
	[ -e "$PENDING" ] &&
	[ -e "$MATCH_PIN" ] &&
	[ "$(tree_state_field last_seq)" = 16 ] &&
	[ "$(tree_state_field head_seq)" = 19 ] &&
	[ "$(report_field last_seq <"$WORK/stopped-body.json")" = 16 ] &&
	keepalive_agrees "$WORK/stopped-body.json" pending
'

test_expect_success 'a body taken after the sync finishes has the set its mask folds to' '
	tree_sync "$WORK/finished.json" &&
	[ "$(report_field last_seq <"$WORK/finished.json")" = 19 ] &&
	[ ! -e "$PENDING" ] &&
	[ -e "$MATCH_PIN" ] &&
	keepalive "$WORK/finished-body.json" &&
	keepalive_agrees "$WORK/finished-body.json" settled keepalive &&
	[ "$(mask_of "$WORK/finished-body.json" 17 19)" = VA== ]
'

test_expect_success 'operations the node passes over give the mask of node B' '
	tree_configure unmatched &&
	tree_sync "$WORK/unmatched.json" &&
	[ "$(report_field skipped <"$WORK/unmatched.json")" = 3 ] &&
	[ "$(tree_state_field last_seq)" = 22 ] &&
	keepalive "$WORK/unmatched-body.json" &&
	keepalive_agrees "$WORK/unmatched-body.json" settled unmatched &&
	[ "$(mask_of "$WORK/unmatched-body.json" 17 19)" = VA== ] &&
	[ "$(mask_of "$WORK/unmatched-body.json" 20 22)" = qA== ]
'

test_done
