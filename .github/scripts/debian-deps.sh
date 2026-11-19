#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/debian-deps.sh -- install what a build on Debian testing
# needs: the distribution's compiler and libraries, which are new enough
# to need no toolchain of their own, clang 23 from unstable through
# install-clang.sh and Rust through install-rust.sh.
#
# Run as root in the checkout root, inside a throwaway container: it
# installs packages and changes the git configuration.

set -eu

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
	build-essential \
	ca-certificates \
	git \
	openssl \
	pkgconf \
	python3 \
	libcurl4-openssl-dev \
	libelf-dev \
	libluajit-5.1-dev \
	libssl-dev \
	libtss2-dev \
	zlib1g-dev
sh .github/scripts/install-clang.sh
sh .github/scripts/install-rust.sh
sh .github/scripts/install-static-libcrypto-deps.sh

git config --global --add safe.directory "$PWD"
