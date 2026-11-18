#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/fuzz/afl.sh -- run the named fuzz targets under afl-fuzz, or all
# of them, as run.sh does under libFuzzer: the builds of make -C testing afl,
# the comparison-logging one beside each, on the seed corpus and what
# FUZZ_CORPUS kept, FUZZ_JOBS at a time. A crash fails the run and leaves
# the input in testing/fuzz.
#
#   testing/fuzz/afl.sh <seconds> [<target>...]

set -eu

case ${FUZZ_CORPUS:-} in
'' | /*) ;;
*) FUZZ_CORPUS=$PWD/$FUZZ_CORPUS ;;
esac
cd "$(dirname "$0")"
root=$(cd ../.. && pwd)
bin=$root/build/fuzz-afl
cmplog=$root/build/fuzz-afl-cmplog
seconds=${1:?usage: afl.sh <seconds> [<target>...]}
shift
if [ $# -eq 0 ]; then
	for c in corpus/*/; do
		t=${c#corpus/}
		set -- "$@" "${t%/}"
	done
fi

# A runner has no core dump handler to keep and the governor is not
# ours to set; neither changes what afl-fuzz finds.
export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=${AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES-1}
export AFL_SKIP_CPUFREQ=${AFL_SKIP_CPUFREQ-1}
export AFL_TRY_AFFINITY=1 AFL_NO_UI=1 AFL_IGNORE_SEED_PROBLEMS=1

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# What afl-fuzz queued goes into the corpus libFuzzer keeps, named by its
# content as libFuzzer names inputs; the next libFuzzer run merges it.
keep() {
	for f in "$2"/default/queue/id:*; do
		[ -f "$f" ] || continue
		sum=$(sha1sum <"$f")
		cp "$f" "$FUZZ_CORPUS/$1/${sum%% *}"
	done
}

run() {
	status=0
	in=$work/$1.in
	out=$work/$1.out
	mkdir -p "$in"
	cp corpus/"$1"/* "$in"/ 2>/dev/null || :
	if [ -n "${FUZZ_CORPUS:-}" ]; then
		mkdir -p "$FUZZ_CORPUS/$1"
		cp "$FUZZ_CORPUS/$1"/* "$in"/ 2>/dev/null || :
	fi
	afl-fuzz -V "$seconds" -t 10000+ -i "$in" -o "$out" \
		-c "$cmplog/fuzz-$1" -- "$bin/fuzz-$1" \
		>"$work/$1.log" 2>&1 || status=$?
	n=0
	for f in "$out"/default/crashes/id:*; do
		[ -f "$f" ] || continue
		n=$((n + 1))
		cp "$f" "crash-afl-$1-$n"
	done
	[ "$n" -eq 0 ] || status=1
	if [ "$status" -eq 0 ] && [ -n "${FUZZ_CORPUS:-}" ]; then
		keep "$1" "$out"
	fi
	if [ -f "$out/default/fuzzer_stats" ]; then
		sed -n 's/^\(execs_done\|corpus_count\|edges_found\) *: //p' \
			"$out/default/fuzzer_stats" | paste -sd ' ' \
			>"$work/$1.stats"
	fi
	echo "$status" >"$work/$1.rc"
}

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
		set -- $(cat "$work/$t.stats" 2>/dev/null || echo '? ? ?')
		printf 'afl: %s: %s runs, %s inputs, %s edges\n' "$t" "$1" "$2" "$3"
	else
		tail -n 40 "$work/$t.log" >&2
		printf 'afl: %s failed; any input is in testing/fuzz/crash-afl-%s-*\n' \
			"$t" "$t" >&2
		rc=1
	fi
done
exit $rc
