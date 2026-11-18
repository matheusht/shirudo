#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/fuzz/run.sh -- run the named libFuzzer targets, or one for each
# fuzz-*.c here, for the given seconds on their seed corpora and FUZZ_JOBS
# of them at a time, keeping what they find in a scratch directory, or
# with FUZZ_CORPUS=<dir> in <dir>/<target> for the next run, merged down
# to the inputs that add coverage. A crash fails the run and leaves the
# input that caused it in testing/fuzz.
#
#   testing/fuzz/run.sh <seconds> [<target>...]

set -eu

# A relative FUZZ_CORPUS names a directory from where the caller stands.
case ${FUZZ_CORPUS:-} in
'' | /*) ;;
*) FUZZ_CORPUS=$PWD/$FUZZ_CORPUS ;;
esac
cd "$(dirname "$0")"
seconds=${1:?usage: run.sh <seconds> [<target>...]}
shift
if [ $# -eq 0 ]; then
	for c in corpus/*/; do
		t=${c#corpus/}
		set -- "$@" "${t%/}"
	done
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Each run adds what it found, so the kept corpus would grow without end:
# merge it into a fresh directory, which takes only the inputs that add
# coverage, and keep it unchanged when the merge fails.
keep() {
	min=$FUZZ_CORPUS/.$1.min
	rm -rf "$min"
	mkdir -p "$min"
	if ./fuzz-"$1" -merge=1 -timeout=10 -rss_limit_mb=2048 "$min" "$2" \
		>"$work/$1.merge.log" 2>&1; then
		rm -rf "$2"
		mv "$min" "$2"
	else
		rm -rf "$min"
		printf 'fuzz: %s: merge failed; the corpus stays as it was\n' \
			"$1" >&2
	fi
}

run() {
	status=0
	out=$work/$1
	if [ -n "${FUZZ_CORPUS:-}" ]; then
		out=$FUZZ_CORPUS/$1
	fi
	mkdir -p "$out"
	./fuzz-"$1" -max_total_time="$seconds" -timeout=10 \
		-rss_limit_mb=2048 -artifact_prefix="$PWD/crash-$1-" \
		"$out" "corpus/$1" >"$work/$1.log" 2>&1 || status=$?
	if [ "$status" -eq 0 ] && [ -n "${FUZZ_CORPUS:-}" ]; then
		keep "$1" "$out"
	fi
	echo $status >"$work/$1.rc"
}

# FUZZ_JOBS targets at a time, one per CPU unless told otherwise.
jobs=${FUZZ_JOBS:-$(nproc 2>/dev/null || echo 1)}
n=0
for t in "$@"; do
	run "$t" &
	n=$((n + 1))
	if [ $((n % jobs)) -eq 0 ]; then
		wait
	fi
done
wait

rc=0
for t in "$@"; do
	if [ "$(cat "$work/$t.rc")" = 0 ]; then
		printf 'fuzz: %s: %s\n' "$t" "$(tail -n 1 "$work/$t.log")"
	else
		tail -n 40 "$work/$t.log" >&2
		printf 'fuzz: %s failed; the input is in testing/fuzz/crash-%s-*\n' \
			"$t" "$t" >&2
		rc=1
	fi
done
exit $rc
