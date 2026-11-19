#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/install-rust.sh -- install the distribution's rustc and
# cargo, of at least the release rust/Cargo.toml names, which the build
# runs by those names. The crate and its vendored crates build offline,
# so the toolchain is all it needs. Debian testing and unstable, as the
# LVH guests run them, Ubuntu 26.04 and Fedora 45 ship a release new
# enough; Ubuntu 24.04 only as a versioned rustc-1.<n> package, the
# newest of which goes in, with rustc and cargo in /usr/bin naming it.
#
#   .github/scripts/install-rust.sh
#
# Runs as root in a runner, container or LVH guest that is discarded
# afterwards: it installs packages and may replace /usr/bin/rustc.

set -eu

RUST_MINOR=88

die() {
	printf 'install-rust: %s\n' "$*" >&2
	exit 1
}

. /etc/os-release

case $ID in
fedora)
	dnf -q install -y rust cargo
	;;
debian | ubuntu)
	export DEBIAN_FRONTEND=noninteractive
	apt-get update
	minor=$(apt-cache policy rustc |
		sed -n 's/^ *Candidate: \([0-9]*:\)\{0,1\}1\.\([0-9]*\)\..*/\2/p')
	if [ "${minor:-0}" -ge "$RUST_MINOR" ]; then
		apt-get install -y --no-install-recommends rustc cargo
	else
		minor=$(apt-cache search --names-only '^cargo-1\.[0-9]+$' |
			sed -n 's/^cargo-1\.\([0-9]*\) .*/\1/p' | sort -n | tail -n 1)
		[ "${minor:-0}" -ge "$RUST_MINOR" ] ||
			die "$PRETTY_NAME has no Rust 1.$RUST_MINOR or newer"
		apt-get install -y --no-install-recommends "rustc-1.$minor" \
			"cargo-1.$minor"
		for tool in rustc cargo; do
			ln -sf "/usr/lib/rust-1.$minor/bin/$tool" "/usr/bin/$tool"
		done
	fi
	;;
*)
	die "$ID is not supported"
	;;
esac

version=$(rustc -V)
minor=$(printf '%s\n' "$version" | sed -n 's/^rustc 1\.\([0-9]*\)\..*/\1/p')
[ "${minor:-0}" -ge "$RUST_MINOR" ] ||
	die "$version is older than 1.$RUST_MINOR"
cargo -V >/dev/null
printf 'install-rust: %s\n' "$version"
