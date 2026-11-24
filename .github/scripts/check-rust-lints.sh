#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Generate only the BPF inputs embedded by the Rust crate, then check
# formatting and all four build configurations with Clippy.

set -eu

cd "$(dirname "$0")/../.."
make -f Makefile.shirudo -j4 \
  bpf/bpf2.skel.rs bpf/seal.skel.rs bpf/unload.bpf.o

cd rust
cargo fmt --check
cargo clippy --release --offline --target-dir ../build/rust-clippy -- -D warnings
cargo clippy --tests --offline --target-dir ../build/rust-clippy-test -- -D warnings
cargo clippy --release --features test-helpers --offline \
  --target-dir ../build/rust-clippy-helpers -- -D warnings
RUSTFLAGS="--cfg shirudo_fuzz" cargo clippy --release --offline \
  --target-dir ../build/rust-clippy-fuzz -- -D warnings
