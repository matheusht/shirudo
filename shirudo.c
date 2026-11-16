// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * main(), which hands the command line to shirudo_main(), the dispatch
 * table of rust/src/builtin/commands.rs. It stays in C because the unit,
 * fuzz and helper executables link the same Rust library with a main()
 * of their own.
 */

#include "builtin.h"

int main(int argc, const char **argv)
{
	return shirudo_main(argc, argv);
}
