#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0010 -- packaging/notices.sh: the licence notices a target and an
# operator package carry, against a staged dependency tree, stub dpkg
# tools and stand-in copyright files, and the gaps it refuses to ship.

cd "$(dirname "$0")/.."
. ./test-lib.sh
for t in jq pkg-config cargo rustc; do
	command -v $t >/dev/null 2>&1 || test_skip_all "$t not installed"
done
N=$(cd .. && pwd)/packaging/notices.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT

# A pkg-config file in <dir>/pkgconfig describing <dir>.
pc() {
	mkdir -p "$1/pkgconfig"
	printf 'libdir=%s\nName: %s\nDescription: %s\nVersion: %s\n' \
		"$1" "$2" "$2" "$3" >"$1/pkgconfig/$2.pc"
}

# A licence file <name> of the build under <libdir>, holding <text>.
licence() {
	mkdir -p "$1/../share/licenses/$2"
	printf '%s\n' "$4" >"$1/../share/licenses/$2/$3"
}

mkdir -p "$W/bin" "$W/sys" "$W/deps/lib" "$W/out" "$W/doc" "$W/common"
echo luajit >"$W/sys/libluajit-5.1.a"
for archive in libc.a libm.a libgcc.a libgcc_eh.a rcrt1.o; do
	printf '%s\n' "$archive" >"$W/sys/$archive"
done
pc "$W/openssl/lib" openssl 3.5.9
echo ssl >"$W/openssl/lib/libssl.a"
echo crypto >"$W/openssl/lib/libcrypto.a"
licence "$W/openssl/lib" openssl LICENSE.txt 'OpenSSL Apache licence text'
pc "$W/curl/lib" libcurl 8.18.0
echo curl >"$W/curl/lib/libcurl.a"
licence "$W/curl/lib" curl COPYING 'curl copying text'
pc "$W/deps/lib" tss2-esys 4.2.0
echo esys >"$W/deps/lib/libtss2-esys.a"
licence "$W/deps/lib" tpm2-tss LICENSE 'tpm2-tss licence text'
licence "$W/deps/lib" tpm2-tss BSD-3-Clause.txt 'tpm2-tss BSD-3-Clause text'
cp "$W/openssl/lib/libssl.a" "$W/openssl/lib/libcrypto.a" \
	"$W/sys/libluajit-5.1.a" "$W/deps/lib/"

mkdir -p "$W/doc/libluajit-5.1-dev" "$W/doc/libc6-dev" "$W/doc/libgcc-14-dev"
echo 'LuaJIT copyright file' >"$W/doc/libluajit-5.1-dev/copyright"
printf '%s\n' 'GNU C Library copyright file' \
	'see /usr/share/common-licenses/LGPL-2.1 and /usr/share/common-licenses/GPL-2.' \
	>"$W/doc/libc6-dev/copyright"
printf '%s\n' 'GCC copyright file' 'see /usr/share/common-licenses/GPL-3' \
	'and /usr/share/common-licenses/LGPL-2.1' >"$W/doc/libgcc-14-dev/copyright"
echo 'LGPL-2.1 text' >"$W/common/LGPL-2.1"
echo 'GPL-2 text' >"$W/common/GPL-2"
echo 'GPL-3 text' >"$W/common/GPL-3"

cat >"$W/bin/dpkg" <<'EOF'
#!/bin/sh
case $2 in
*/libluajit-5.1.a) echo "libluajit-5.1-dev:amd64: $2" ;;
*/libc.a|*/libm.a|*/rcrt1.o) echo "libc6-dev:amd64: $2" ;;
*/libgcc.a|*/libgcc_eh.a) echo "libgcc-14-dev:amd64: $2" ;;
*) echo "dpkg-query: no path found matching pattern $2" >&2; exit 1 ;;
esac
EOF
cat >"$W/bin/dpkg-query" <<'EOF'
#!/bin/sh
for p; do :; done
case $p in
libluajit-5.1-dev:amd64) echo 'libluajit-5.1-dev 2.1.0+openresty20250117-2 amd64 luajit' ;;
libc6-dev:amd64) echo 'libc6-dev 2.42-1 amd64 glibc' ;;
libgcc-14-dev:amd64) echo 'libgcc-14-dev 14.2.0-19 amd64 gcc-14' ;;
*) exit 1 ;;
esac
EOF
cat >"$W/bin/cc" <<'EOF'
#!/bin/sh
root=$(CDPATH= cd "$(dirname "$0")/../sys" && pwd)
printf '%s/%s\n' "$root" "${1#-print-file-name=}"
EOF
chmod +x "$W/bin/dpkg" "$W/bin/dpkg-query" "$W/bin/cc"

run() {
	env PATH="$W/bin:$PATH" SHIRUDO_CI_VERSION=v1.0 CC="$W/bin/cc" \
		SHIRUDO_TARGET_PKG_CONFIG_PATH="$W/curl/lib/pkgconfig:$W/openssl/lib/pkgconfig" \
		SHIRUDO_TARGET_STATIC_LIBDIR="$W/deps/lib" \
		SHIRUDO_DOC_ROOT="$W/doc" SHIRUDO_COMMON_LICENSES="$W/common" \
		TARGET_SYSTEM_LIBDIR="$W/sys" "$@" >/dev/null 2>"$W/err"
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
