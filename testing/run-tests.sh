#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/run-tests.sh [-t <regex>] [unit[/<suite>]|ci-checks|functional[/<family>]|end2end]...
# -- the tests of each tier named, all of them without an argument, that
# run on the build host: the unit tests and the operator tests (t?0??) in
# number order. A unit suite is the tests of a Rust module of that name,
# which ../build/unit/shirudo-unit holds, or a C one, ../build/unit/<suite>.
# The target tests run in the test VM through run-target-tests.sh.
# CI-friendly; the exit status counts the suites that failed.

set -eu

cd "$(dirname "$0")"
. ./test-filter.sh

[ $# -gt 0 ] || set -- unit ci-checks functional end2end
units=
rust_suites=
dirs=
for what; do
	case "$what" in
	unit) units="$units ../build/unit/*" ;;
	unit/*)
		suite=${what#unit/}
		if [ -n "$(find ../rust/src -path "*/$suite/tests.rs")" ]; then
			rust_suites="$rust_suites $suite"
			continue
		fi
		units="$units ../build/unit/$suite"
		;;
	functional) dirs="$dirs functional/*" ;;
	*) dirs="$dirs $what" ;;
	esac
	[ "$what" = unit ] || [ -e "$what" ] || [ -e "../build/$what" ] || {
		printf 'no tests %s\n' "$what" >&2
		exit 2
	}
done

# A C suite's binary while its source is there: one a suite since ported
# to Rust left behind is not.
unit_tests()
{
	for t in $units; do
		case "${t##*/}" in
		shirudo-unit) ;;
		*) [ -e "unit/${t##*/}.c" ] || continue ;;
		esac
		[ -f "$t" ] && [ -x "$t" ] && printf '%s\n' "$t"
	done
}

# The Rust suites named, as filters of the binary's test names.
rust_filters()
{
	for s in $rust_suites; do
		printf '::%s::tests::\n' "$s"
	done
}

operator_tests()
{
	for d in $dirs; do
		for t in "$d"/t*.sh; do
			case "${t##*/}" in
			t[0-9]0[0-9][0-9]-*.sh) printf '%s %s\n' "${t##*/}" "$t" ;;
			esac
		done
	done | sort | cut -d' ' -f2
}

fail=0
: "${SHIRUDO_TEST_SUITE_FAILURES_FILE:=}"
for t in $(unit_tests) ${rust_suites:+../build/unit/shirudo-unit} \
		$(operator_tests); do
	test_matches "$t" || continue
	case "$t" in
	*.sh) set -- sh "$t" ;;
	*/shirudo-unit) set -- "$t" $(rust_filters) ;;
	*) set -- "$t" ;;
	esac
	if "$@"; then
		:
	else
		fail=$((fail + 1))
		if [ -n "$SHIRUDO_TEST_SUITE_FAILURES_FILE" ]; then
			printf '%s\n' "$t" >>"$SHIRUDO_TEST_SUITE_FAILURES_FILE" 2>/dev/null || :
		fi
	fi
done

exit "$fail"
