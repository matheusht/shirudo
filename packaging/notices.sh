#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# packaging/notices.sh -- the copyright and licence notices of what a
# package carries besides shirudo's own code, which its licences ask to
# go with every copy: the components .github/scripts/gen-sbom.sh lists,
# the Rust standard library the programs link, and the vmlinux.h the
# operator package ships.
#
#   packaging/notices.sh <target|operator> <dir> [<rpm-header>]
#
# Writes into <dir> THIRD-PARTY-LICENSES, each component with where it
# comes from, its licence and the notices and licence texts it carries,
# and the Rust standard library's own notices beside it. <rpm-header>,
# when given, gets the License: and Provides: bundled() lines of an rpm
# spec. A component whose licence text cannot be found fails the script,
# so that no package goes out without one.
#
# A target package takes the dependency builds gen-sbom.sh takes, and
# their licence texts from <libdir>/../share/licenses/<name>, where make
# target-deps puts them. SHIRUDO_DOC_ROOT and SHIRUDO_COMMON_LICENSES
# stand in for /usr/share/doc and /usr/share/common-licenses.
set -eu

HOMEPAGE=https://github.com/shirudo-dev/shirudo
root=$(cd "$(dirname "$0")/.." && pwd)
docroot=${SHIRUDO_DOC_ROOT:-/usr/share/doc}
common=${SHIRUDO_COMMON_LICENSES:-/usr/share/common-licenses}

die() {
	printf 'notices: %s\n' "$*" >&2
	exit 1
}

if [ $# -lt 2 ] || [ $# -gt 3 ]; then
	printf 'usage: %s <target|operator> <dir> [<rpm-header>]\n' "$0" >&2
	exit 2
fi
role=$1
out=$2
header=${3:-}
case $role in
target|operator) ;;
*) die "unknown role $role" ;;
esac
command -v jq >/dev/null 2>&1 || die 'jq not found'
command -v rustc >/dev/null 2>&1 || die 'rustc not found'

version=${SHIRUDO_CI_VERSION:-$(git -C "$root" describe --tags --always --dirty 2>/dev/null ||
	cat "$root/VERSION")}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

SHIRUDO_CI_VERSION=$version "$root/.github/scripts/gen-sbom.sh" --components "$role" \
	>"$work/components" ||
	die 'cannot list the components'
mkdir -p "$out"
: >"$work/licences"
: >"$work/bundled"
: >"$work/common-seen"
exec 3>"$work/notice"

# Text wrapped at 78 columns, without the blanks fold leaves at the ends.
wrap() {
	fold -s -w 78 | sed 's/ *$//'
}

# section <title> <version> <licence> <what it is and where it comes from>
section() {
	printf '\n%s\n%s %s\n' \
		'==============================================================================' \
		"$1" "$2" >&3
	printf 'Licence: %s\n\n' "$3" >&3
	printf '%s\n' "$4" | wrap >&3
	printf '%s\n\n' \
		'==============================================================================' >&3
}

# record <SPDX expression>: a licence of what the package carries.
record() {
	printf '%s\n' "$1" >>"$work/licences"
}

# text <file>...: each file whole, under its name.
text() {
	for f; do
		[ -s "$f" ] || die "$f: no licence text"
		printf -- '--- %s\n\n' "${f##*/}" >&3
		cat "$f" >&3
		printf '\n' >&3
	done
}

# The texts of /usr/share/common-licenses a distribution's copyright file
# points at rather than holds, each once, as a package that leaves the
# distribution has to carry them itself.
common_texts() {
	for name in $(grep -o '/usr/share/common-licenses/[A-Za-z0-9.+_-]*' "$1" |
			sed 's,.*/,,; s/[.]$//' | sort -u); do
		grep -qxF "$name" "$work/common-seen" && continue
		[ -f "$common/$name" ] ||
			die "$1 points at /usr/share/common-licenses/$name, which $common does not hold"
		printf '%s\n' "$name" >>"$work/common-seen"
		printf -- '--- /usr/share/common-licenses/%s\n\n' "$name" >&3
		cat "$common/$name" >&3
		printf '\n' >&3
	done
}

# The BSD-2-Clause terms, from shirudo's own LICENSE without its title and
# copyright line.
bsd_terms() {
	sed -n '/^Redistribution and use/,$p' "$root/LICENSE"
}

crate_notice() {
	dir=$root/rust/vendor/$name
	files=$(find "$dir" -maxdepth 1 -type f \( -iname 'licen[cs]e*' -o \
		-iname 'copying*' -o -iname 'copyright*' -o -iname 'notice*' -o \
		-iname 'unlicense*' \) | sort)
	[ -n "$files" ] || die "the vendored crate $name holds no licence file"
	section "$name (Rust crate)" "$ver" "$lic" \
		"From crates.io, vendored in rust/vendor/$name of shirudo's source; linked into the programs."
	record "$lic"
	# shellcheck disable=SC2086
	text $files
	printf 'bundled(crate(%s)) = %s\n' "$name" "$ver" >>"$work/bundled"
}

libbpf_notice() {
	commit=$(sed -n 's/^commit=//p' "$root/vendor/libbpf/COMMIT")
	section libbpf "$ver" "$lic" \
		"From the Linux kernel's tools/lib/bpf at $commit, vendored in vendor/libbpf of shirudo's source and taken under BSD-2-Clause: the BPF headers the operator package carries, and the BPF loader code the programs embed. Its copyright notices:"
	grep -rhoE 'Copyright \([cC]\)[^*]*|Copyright [0-9][^*]*' "$root/vendor/libbpf" \
		--include='*.[ch]' | sed 's/[[:space:]]*$//' | sort -u >&3
	printf '\n' >&3
	bsd_terms >&3
	record "$lic"
	printf 'bundled(libbpf) = %s\n' "$ver" >>"$work/bundled"
}

# A dependency make target-deps builds from its release.
built_notice() {
	case $name in
	openssl) pc=openssl ;;
	curl) pc=libcurl ;;
	tpm2-tss) pc=tss2-esys ;;
	esac
	libdir=$(pkg-config --variable=libdir "$pc") || die "$pc.pc not found"
	dir=$libdir/../share/licenses/$name
	files=$(find "$dir" -type f 2>/dev/null | sort)
	[ -n "$files" ] ||
		die "no licence text of $name in $dir; copy its release's licence files there (make target-deps does)"
	section "$name" "$ver" "$lic" \
		"Built from its release ($dl) and linked statically into /usr/bin/shirudo."
	record "$lic"
	# shellcheck disable=SC2086
	text $files
	printf 'bundled(%s) = %s\n' "$name" "$ver" >>"$work/bundled"
}

# The static archives of a distribution package, with its copyright file.
deb_notice() {
	copyright=$docroot/$name/copyright
	[ -f "$copyright" ] || die "$name: no $copyright"
	src=$(printf '%s\n' "$purl" | sed -n 's/.*[?&]upstream=\([^&]*\).*/\1/p')
	section "$name" "$ver" "$lic" \
		"The static archives of this $os_name package, built from its source package $src, are linked into /usr/bin/shirudo. Its copyright file follows."
	text "$copyright"
	common_texts "$copyright"
	record "$lic"
	upstream=$(printf '%s\n' "$ver" | sed 's/^[0-9]*://; s/-[^-]*$//')
	printf 'bundled(%s) = %s\n' "$src" "$upstream" >>"$work/bundled"
	case $src in
	glibc) glibc_notice ;;
	esac
}

# The GNU C Library is linked statically, which the LGPL allows when the
# user can relink the program with a changed library and has its source.
glibc_notice() {
	case $os_id in
	debian) at="https://snapshot.debian.org/package/$src/${ver#*:}/" ;;
	ubuntu) at="https://launchpad.net/ubuntu/+source/$src/${ver#*:}" ;;
	*) at="the archive of $os_name" ;;
	esac
	section 'The GNU C Library: source and relinking' "$ver" "$lic" \
		"/usr/bin/shirudo is statically linked with the GNU C Library (glibc), which is licensed under the GNU Lesser General Public License, version 2.1 or later; its text is above. As that licence allows, you may change the library and link the program with your changed copy:"
	wrap >&3 <<-EOF
	- The library's complete source is the $os_name source package $src, version ${ver#*:}, from $at
	- shirudo is free software under BSD-2-Clause, and its complete source, version $version, is at $HOMEPAGE. Build your changed library, install its static archives (libc.a, libm.a and rcrt1.o) where the C compiler finds them, or give make a CC that finds them there, and run "make target" to link /usr/bin/shirudo with it; Documentation/contribute/code/developer-guide.rst gives the steps.
	- For at least three years after this package was released, the shirudo authors will give anyone who asks at $HOMEPAGE/issues a complete machine-readable copy of the source of the library linked here and of shirudo, for no more than the cost of providing it.

	EOF
}

rust_notice() {
	sysroot=$(rustc --print sysroot)
	rustver=$(rustc -V | cut -d' ' -f2)
	html=$sysroot/share/doc/rust/COPYRIGHT-library.html
	if [ -f "$html" ]; then
		cp "$html" "$out/rust-library-COPYRIGHT.html"
		file=rust-library-COPYRIGHT.html
		# A licence line, in the markup of whichever release wrote it.
		sed 's/<[^>]*>//g' "$html" |
			sed -n 's/^[[:space:]]*License: \(.*[^[:space:]]\)[[:space:]]*$/\1/p' |
			sort -u >"$work/rust-licences"
		[ -s "$work/rust-licences" ] || die "$html names no licence"
		cat "$work/rust-licences" >>"$work/licences"
	else
		# A distribution's toolchain: the copyright of the package that
		# installed the standard library.
		std=$(find "$sysroot/lib/rustlib" -name 'libstd-*.rlib' 2>/dev/null | head -n 1)
		[ -n "$std" ] || die "cannot find the Rust standard library under $sysroot"
		# dpkg names a package of one architecture among several with it,
		# libstd-rust-1.93-dev:amd64; its documentation goes by the name alone.
		owner=$(dpkg -S "$std" 2>/dev/null | sed -n 's/: .*//;s/,.*//;s/:.*//;1p') || :
		[ -n "$owner" ] && [ -f "$docroot/$owner/copyright" ] ||
			die "cannot find the copyright of the Rust standard library at $std"
		cp "$docroot/$owner/copyright" "$out/rust-library-copyright"
		file=rust-library-copyright
		record 'Apache-2.0 OR MIT'
	fi
	section 'The Rust standard library' "$rustver" 'Apache-2.0 OR MIT, and those of its dependencies' \
		"Linked into the programs. Its notices, and those of the crates it is built from, are in $file beside this file."
}

vmlinux_notice() {
	section vmlinux.h "(generated)" 'GPL-2.0-only' \
		"The types of the Linux kernel, which the operator package ships in source form as the header shirudo-build compiles BPF programs with, generated from the BTF of a build of the kernel's bpf-next tree. They are licensed as the kernel is, under the GNU General Public License, version 2, with the Linux syscall note for its user-space API. The kernel's source is at https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git."
	text "$root/packaging/licenses/GPL-2.0" "$root/packaging/licenses/Linux-syscall-note"
	record GPL-2.0-only
}

os_id=$(sed -n 's/^ID=//p' /etc/os-release 2>/dev/null | tr -d '"')
os_name=$(sed -n 's/^NAME=//p' /etc/os-release 2>/dev/null | tr -d '"')
os_name=${os_name:-"the build host's distribution"}
if [ "$role" = target ]; then
	PKG_CONFIG_PATH=${SHIRUDO_TARGET_PKG_CONFIG_PATH:-}:${SHIRUDO_TARGET_STATIC_LIBDIR:-}/pkgconfig
	export PKG_CONFIG_PATH
fi

wrap >&3 <<EOF
shirudo $version, $role package

shirudo is licensed under BSD-2-Clause; see its LICENSE. Its programs
also contain, and this package also carries, the components below,
each with where it comes from, its licence, and the notices and licence
texts that licence asks to go with every copy.
EOF

rust_notice
jq -r '[.name, .versionInfo, .licenseDeclared, .downloadLocation,
	.externalRefs[0].referenceLocator] | @tsv' "$work/components" >"$work/list"
while IFS='	' read -r name ver lic dl purl; do
	case $purl in
	pkg:cargo/*) crate_notice ;;
	pkg:generic/libbpf@*) libbpf_notice ;;
	pkg:generic/openssl@*|pkg:generic/curl@*|pkg:generic/tpm2-tss@*) built_notice ;;
	pkg:deb/*) deb_notice ;;
	*) die "no notice for $name ($purl)" ;;
	esac
done <"$work/list"
[ "$role" = operator ] && vmlinux_notice
if [ "$role" = operator ] || ! grep -q '^bundled(gcc-' "$work/bundled"; then
	wrap >&3 <<-EOF

	The programs also link GCC's unwinder (libgcc_eh) statically. The GCC Runtime Library Exception, version 3.1, lets a program compiled with it be distributed under terms of its own choice, and asks nothing of it.
	EOF
fi
exec 3>&-
cp "$work/notice" "$out/THIRD-PARTY-LICENSES"

if [ -n "$header" ]; then
	# The SPDX expression of everything in the package, each licence
	# once, an alternative parenthesised under AND.
	expr=$( { printf 'BSD-2-Clause\n'; cat "$work/licences"; } |
		grep -v '^NOASSERTION$' | awk '!seen[$0]++' |
		sed '/^(/!{/ OR \| AND /s/.*/(&)/;}' |
		awk 'NR > 1 { printf " AND " } { printf "%s", $0 } END { print "" }')
	{
		printf 'License: %s\n' "$expr"
		sort -u "$work/bundled" | sed 's/^/Provides: /'
	} >"$header"
fi
