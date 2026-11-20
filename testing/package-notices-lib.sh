# SPDX-License-Identifier: BSD-2-Clause
# shellcheck shell=sh
# Copyright (c) 2026 Authors of shirudo
#
# Static dependency metadata and licence texts for packaging tests.

# A pkg-config file in <dir>/pkgconfig describing <dir>.
package_notices_pc() {
	mkdir -p "$1/pkgconfig"
	printf 'libdir=%s\nName: %s\nDescription: %s\nVersion: %s\n' \
		"$1" "$2" "$2" "$3" >"$1/pkgconfig/$2.pc"
}

# A licence file <name> of the build under <libdir>, holding <text>.
package_notices_licence() {
	mkdir -p "$1/../share/licenses/$2"
	printf '%s\n' "$4" >"$1/../share/licenses/$2/$3"
}

setup_package_notices() {
	local W tool archive

	for tool in jq pkg-config cargo rustc; do
		command -v "$tool" >/dev/null 2>&1 ||
			test_skip_all "$tool not installed"
	done
	mkdir -p "$1"
	W=$(CDPATH= cd "$1" && pwd -P)
	PACKAGE_NOTICES_FIXTURE=$W
	PACKAGE_NOTICES_RUSTC=$(command -v rustc)

	mkdir -p "$W/bin" "$W/sys" "$W/deps/lib" "$W/doc" "$W/common"
	echo luajit >"$W/sys/libluajit-5.1.a"
	for archive in libc.a libm.a libgcc.a libgcc_eh.a rcrt1.o; do
		printf '%s\n' "$archive" >"$W/sys/$archive"
	done
	package_notices_pc "$W/openssl/lib" openssl 3.5.9
	echo ssl >"$W/openssl/lib/libssl.a"
	echo crypto >"$W/openssl/lib/libcrypto.a"
	package_notices_licence "$W/openssl/lib" openssl LICENSE.txt 'OpenSSL Apache licence text'
	package_notices_pc "$W/curl/lib" libcurl 8.18.0
	echo curl >"$W/curl/lib/libcurl.a"
	package_notices_licence "$W/curl/lib" curl COPYING 'curl copying text'
	package_notices_pc "$W/deps/lib" tss2-esys 4.2.0
	echo esys >"$W/deps/lib/libtss2-esys.a"
	package_notices_licence "$W/deps/lib" tpm2-tss LICENSE 'tpm2-tss licence text'
	package_notices_licence "$W/deps/lib" tpm2-tss BSD-3-Clause.txt 'tpm2-tss BSD-3-Clause text'
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
if [ "${2%/*}" != "$PACKAGE_NOTICES_FIXTURE/sys" ]; then
	PATH=${PATH#*:} exec dpkg "$@"
fi
case ${2##*/} in
libluajit-5.1.a) pkg=libluajit-5.1-dev ;;
libc.a|libm.a|rcrt1.o) pkg=libc6-dev ;;
libgcc.a|libgcc_eh.a) pkg=libgcc-14-dev ;;
*) exit 1 ;;
esac
printf '%s:amd64: %s\n' "$pkg" "$2"
EOF
	cat >"$W/bin/dpkg-query" <<'EOF'
#!/bin/sh
for p; do :; done
case $p in
libluajit-5.1-dev:amd64) echo 'libluajit-5.1-dev 2.1.0+openresty20250117-2 amd64 luajit' ;;
libc6-dev:amd64) echo 'libc6-dev 2.42-1 amd64 glibc' ;;
libgcc-14-dev:amd64) echo 'libgcc-14-dev 14.2.0-19 amd64 gcc-14' ;;
*) PATH=${PATH#*:} exec dpkg-query "$@" ;;
esac
EOF
	cat >"$W/cc" <<'EOF'
#!/bin/sh
root=$(CDPATH= cd "$(dirname "$0")/sys" && pwd)
printf '%s/%s\n' "$root" "${1#-print-file-name=}"
EOF
	mkdir -p "$W/rust/share/doc/rust"
	printf '%s\n' '<p>License: Apache-2.0 OR MIT</p>' \
		>"$W/rust/share/doc/rust/COPYRIGHT-library.html"
	cat >"$W/bin/rustc" <<'EOF'
#!/bin/sh
case "$*" in
'--print sysroot') CDPATH= cd "$(dirname "$0")/../rust" && pwd ;;
-V) echo 'rustc 1.88.0' ;;
*) exec "$SHIRUDO_TEST_RUSTC" "$@" ;;
esac
EOF
	chmod +x "$W/bin/dpkg" "$W/bin/dpkg-query" "$W/cc" "$W/bin/rustc"
}

with_package_notices() {
	local W=$PACKAGE_NOTICES_FIXTURE

	env PATH="$W/bin:$PATH" SHIRUDO_CI_VERSION=v1.0 CC="$W/cc" \
		SHIRUDO_TEST_RUSTC="$PACKAGE_NOTICES_RUSTC" \
		PACKAGE_NOTICES_FIXTURE="$W" \
		SHIRUDO_TARGET_PKG_CONFIG_PATH="$W/curl/lib/pkgconfig:$W/openssl/lib/pkgconfig" \
		SHIRUDO_TARGET_STATIC_LIBDIR="$W/deps/lib" \
		SHIRUDO_DOC_ROOT="$W/doc" SHIRUDO_COMMON_LICENSES="$W/common" \
		TARGET_SYSTEM_LIBDIR="$W/sys" "$@"
}
