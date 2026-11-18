#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t6003 -- the tamper and integrity points are the enums the LSM counts
# with and status names them from (bpf/lib/tamper.h, integrity.h), and a
# counter is only as good as its name; this keeps every member in the
# table of names and meanings rust/src/util/tamper.rs and util/integrity.c hold.
# Also checks that status reports the counters as absent, not as an
# error, where init has not run.

cd "$(dirname "$0")/../.."
. ./test-lib.sh

S=../shirudo
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

test_expect_success 'every point has a name and a meaning' '
	sed -n "s/^\tTAMPER_\([A-Z_]*\),$/\1/p" \
		../bpf/lib/tamper.h >"$W/points" &&
	sed -n "s/^\t\[TAMPER_\([A-Z_]*\)\] = { \"[A-Za-z]*\",$/\1/p" \
		../util/tamper.c >"$W/table" &&
	[ -s "$W/points" ] &&
	cmp "$W/points" "$W/table"
'

test_expect_success 'every integrity point has a name and a meaning' '
	sed -n "s/^\tINTEGRITY_\([A-Z_]*\),$/\1/p" \
		../bpf/lib/integrity.h >"$W/integrity-points" &&
	sed -n "s/^ *\/\/ INTEGRITY_\([A-Z_]*\)$/\1/p" \
		../rust/src/util/integrity.rs >"$W/integrity-table" &&
	[ -s "$W/integrity-points" ] &&
	cmp "$W/integrity-points" "$W/integrity-table"
'

test_expect_success 'status --json reports the counters as null without init' '
	if [ -e /run/shirudo/bpffs/tamper ]; then
		echo "skipping: a tamper map is pinned on this host"
	else
		"$S" status --json | python3 -c "
import json, sys
d = json.load(sys.stdin)
assert \"tamper_attempts\" in d and d[\"tamper_attempts\"] is None
assert \"integrity_attempts\" in d and d[\"integrity_attempts\"] is None
"
	fi
'

test_done
