#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0010 -- packaging/notices.sh: the licence notices a target and an
# operator package carry, against a staged dependency tree, stub dpkg
# tools and stand-in copyright files, and the gaps it refuses to ship.

cd "$(dirname "$0")/.."
. ./test-lib.sh
. ./package-notices-lib.sh
N=$(cd .. && pwd)/packaging/notices.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
setup_package_notices "$W"
mkdir -p "$W/out"

run() {
	with_package_notices "$@" >/dev/null 2>"$W/err"
}

T=$W/out/target
O=$W/out/operator

test_expect_success 'a target notice holds each component with its licence text' '
	run sh "$N" target "$T" "$W/out/target.rpm" &&
	grep -qx "openssl 3.5.9" "$T/THIRD-PARTY-LICENSES" &&
	grep -qx "OpenSSL Apache licence text" "$T/THIRD-PARTY-LICENSES" &&
	grep -qx "curl copying text" "$T/THIRD-PARTY-LICENSES" &&
	grep -qx "tpm2-tss licence text" "$T/THIRD-PARTY-LICENSES" &&
	grep -qx "tpm2-tss BSD-3-Clause text" "$T/THIRD-PARTY-LICENSES" &&
	grep -qx "LuaJIT copyright file" "$T/THIRD-PARTY-LICENSES" &&
	grep -qx "GCC copyright file" "$T/THIRD-PARTY-LICENSES" &&
	grep -q "^openssl (Rust crate) " "$T/THIRD-PARTY-LICENSES" &&
	grep -q "^miniz_oxide (Rust crate) " "$T/THIRD-PARTY-LICENSES" &&
	grep -q "^libbpf " "$T/THIRD-PARTY-LICENSES" &&
	grep -q "^Redistribution and use in source and binary forms" "$T/THIRD-PARTY-LICENSES" &&
	grep -q "^The Rust standard library " "$T/THIRD-PARTY-LICENSES" &&
	ls "$T"/rust-library-* >/dev/null
'

test_expect_success 'a copyright file pointing at common-licenses brings each text once' '
	test "$(grep -cx "LGPL-2.1 text" "$T/THIRD-PARTY-LICENSES")" = 1 &&
	test "$(grep -cx "GPL-2 text" "$T/THIRD-PARTY-LICENSES")" = 1 &&
	test "$(grep -cx "GPL-3 text" "$T/THIRD-PARTY-LICENSES")" = 1
'

test_expect_success 'the statically linked C library comes with its source and relinking' '
	grep -q "^The GNU C Library: source and relinking" "$T/THIRD-PARTY-LICENSES" &&
	tr "\n" " " <"$T/THIRD-PARTY-LICENSES" | tr -s " " | grep -q "source package glibc, version 2.42-1" &&
	grep -q "make target" "$T/THIRD-PARTY-LICENSES" &&
	grep -q "three years" "$T/THIRD-PARTY-LICENSES"
'

test_expect_success 'the rpm header names every licence and bundled component' '
	grep -q "^License: BSD-2-Clause AND " "$W/out/target.rpm" &&
	grep -q " AND Apache-2.0" "$W/out/target.rpm" &&
	grep -q " AND (LGPL-2.1-only OR BSD-2-Clause)" "$W/out/target.rpm" &&
	grep -q " AND LGPL-2.1-or-later" "$W/out/target.rpm" &&
	grep -q " AND curl" "$W/out/target.rpm" &&
	grep -qx "Provides: bundled(openssl) = 3.5.9" "$W/out/target.rpm" &&
	grep -qx "Provides: bundled(glibc) = 2.42" "$W/out/target.rpm" &&
	grep -q "^Provides: bundled(crate(openssl)) = " "$W/out/target.rpm" &&
	test "$(grep -c "^License:" "$W/out/target.rpm")" = 1
'

test_expect_success 'an operator notice carries vmlinux.h under the GPL and no target build' '
	run env -u SHIRUDO_TARGET_PKG_CONFIG_PATH -u SHIRUDO_TARGET_STATIC_LIBDIR \
		sh "$N" operator "$O" "$W/out/operator.rpm" &&
	grep -q "^vmlinux.h " "$O/THIRD-PARTY-LICENSES" &&
	grep -q "GNU GENERAL PUBLIC LICENSE" "$O/THIRD-PARTY-LICENSES" &&
	grep -q "^openssl (Rust crate) " "$O/THIRD-PARTY-LICENSES" &&
	! grep -q "GNU C Library: source" "$O/THIRD-PARTY-LICENSES" &&
	! grep -qx "openssl 3.5.9" "$O/THIRD-PARTY-LICENSES" &&
	grep -q " AND GPL-2.0-only" "$W/out/operator.rpm"
'

test_expect_success 'a build without its licence text fails' '
	mv "$W/curl/share" "$W/curl.share" &&
	! run sh "$N" target "$W/out/gap" &&
	grep -q "no licence text of curl" "$W/err" &&
	mv "$W/curl.share" "$W/curl/share"
'

test_expect_success 'a distribution package without its copyright file fails' '
	mv "$W/doc/libluajit-5.1-dev" "$W/doc.luajit" &&
	! run sh "$N" target "$W/out/gap" &&
	grep -q "libluajit-5.1-dev: no " "$W/err" &&
	mv "$W/doc.luajit" "$W/doc/libluajit-5.1-dev"
'

test_expect_success 'a common licence the host does not hold fails' '
	rm "$W/common/GPL-3" &&
	! run sh "$N" target "$W/out/gap" &&
	grep -q "common-licenses/GPL-3" "$W/err"
'

test_done
