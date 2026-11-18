#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# The MemorySanitizer suite: the unit tests and a run of every fuzz target
# for the seconds given, built with SANITIZE=memory against the libraries
# msan-deps.sh instrumented. What runs Lua is left out: LuaJIT's
# interpreter is assembly no sanitizer instruments, so what it hands back
# would read as uninitialized. ASan and UBSan cover those.
#
#   .github/scripts/msan-tests.sh [<seconds>]

set -eu

seconds=${1:-30}
prefix=${MSAN_PREFIX:-/tmp/shirudo-msan}
lua_units='upatch_decode'
lua_fuzzers='decoder'

# The libraries are found by the binaries' run path, not by
# LD_LIBRARY_PATH, which would hand them to every tool the build runs.
# The prefix's openssl is the ML-DSA one the configuration asks for.
export CC="${CC:-clang-23}"
export PATH="$prefix/bin:$PATH"
export PKG_CONFIG_PATH="$prefix/lib/pkgconfig"
export LDFLAGS="-Wl,-rpath,$prefix/lib"

cd "$(dirname "$0")/../.."

listed() {
	case " $2 " in *" $1 "*) return 0 ;; esac
	return 1
}

units=
for f in testing/unit/*.c; do
	s=${f##*/}
	s=${s%.c}
	[ "$s" = unit ] || listed "$s" "$lua_units" || units="$units unit/$s"
done
fuzzers=
for d in testing/fuzz/corpus/*/; do
	t=${d%/}
	t=${t##*/}
	listed "$t" "$lua_fuzzers" || fuzzers="$fuzzers $t"
done

# The builds run in parallel, the suites one after the other.
jobs=$(nproc)
make -j"$jobs" -C testing SANITIZE=memory build-unit
# shellcheck disable=SC2086 # one word per suite
make -C testing SANITIZE=memory $units
make -j"$jobs" -C testing fuzz SANITIZE=memory FUZZ_CC="$CC" \
	FUZZ_SECONDS="$seconds" FUZZERS="${fuzzers# }"
