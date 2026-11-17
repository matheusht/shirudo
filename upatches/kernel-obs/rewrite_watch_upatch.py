#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
"""Replace kernel-obs watch trie values in a signed .upatch.

The tries are generated as bpm build generates them, at the capacities of
watch_generated.h beside this script, and `shirudo-build upatch set`
writes them into the package's .rodata and signs it anew.
"""

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from gen_watch import build_trie, read_networks
from gen_watch_rodata import encode, node_capacity

HERE = Path(__file__).resolve().parent
SYMBOLS = (("obs_watch_v4", 4), ("obs_watch_v6", 6))


def helper_path(explicit):
	if explicit:
		return explicit
	from_env = os.environ.get("SHIRUDO_BUILD")
	if from_env:
		return from_env
	in_tree = HERE.parents[1] / "tools" / "shirudo-build" / "shirudo-build"
	if in_tree.is_file() and os.access(in_tree, os.X_OK):
		return str(in_tree)
	return shutil.which("shirudo-build") or "shirudo-build"


def rewrite(args, tmp):
	input_path = Path(args.upatch)
	output_path = Path(args.output) if args.output else input_path
	networks = read_networks(Path(args.iplist))
	cmd = [helper_path(args.shirudo_build), "upatch", "set", str(input_path)]
	for symbol, version in SYMBOLS:
		nodes = build_trie(networks, version)
		capacity = node_capacity(symbol, HERE / "watch_generated.h")
		value = Path(tmp, f"{symbol}.bin")
		value.write_bytes(encode(nodes, capacity))
		cmd.append(f"{symbol}=@{value}")
		print(f"{symbol}: {len(nodes)} of {capacity} nodes", flush=True)
	for option in ("keys_dir", "key", "cert"):
		if getattr(args, option):
			cmd.extend((f"--{option.replace('_', '-')}", getattr(args, option)))
	if args.dry_run:
		subprocess.run(cmd + ["--dry-run"], check=True)
		return
	# Signed beside the output and renamed over it, so that an in-place
	# update replaces the input only once the result is whole.
	output_path.parent.mkdir(parents=True, exist_ok=True)
	fd, name = tempfile.mkstemp(prefix=".watch-signed-", dir=output_path.parent)
	os.close(fd)
	signed = Path(name)
	try:
		subprocess.run(cmd + ["-o", str(signed)], check=True)
		os.chmod(signed, input_path.stat().st_mode & 0o777)
		os.replace(signed, output_path)
	finally:
		signed.unlink(missing_ok=True)


def main():
	parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
	parser.add_argument("iplist", help="watch.list with IPv4/IPv6 addresses or CIDRs")
	parser.add_argument("upatch", help="existing signed kernel-obs .upatch")
	parser.add_argument("-o", "--output", help="output path; defaults to in-place update")
	parser.add_argument("--keys-dir", help="shirudo signing key directory")
	parser.add_argument("--key", help="ML-DSA-87 signing_key.pem")
	parser.add_argument("--cert", help="matching cert.der")
	parser.add_argument("--shirudo-build", help="path to the shirudo-build helper")
	parser.add_argument("--dry-run", action="store_true",
			    help="check that the tries fit the package without writing")
	args = parser.parse_args()
	try:
		with tempfile.TemporaryDirectory(prefix="watch-") as tmp:
			rewrite(args, tmp)
	except (OSError, ValueError, subprocess.CalledProcessError) as error:
		print(f"rewrite_watch_upatch.py: {error}", file=sys.stderr)
		return 1
	return 0


if __name__ == "__main__":
	raise SystemExit(main())
