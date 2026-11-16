// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * main() of the operator's artifact pipeline, which hands the command
 * line to shirudo_build_main() in rust/src/shirudo_build/. It stays in
 * C for the reason shirudo.c's does: the tests link the same Rust
 * library with a main() of their own.
 */

#include "bpm.h"

int main(int argc, char **argv)
{
	return shirudo_build_main(argc, argv);
}
