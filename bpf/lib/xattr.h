/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_BPF_XATTR_H
#define SHIRUDO_BPF_XATTR_H

#define XATTR_SEAL	"security.bpf.shirudo"
#define XATTR_POLICY	"security.bpf.shirudo.policy"
#define XATTR_ANCESTOR	"security.bpf.shirudo.ancestor"
/* The label is a SHA-256 hex string (rust/src/util/seal.rs) -- always 64 bytes. */
#define LABEL_LEN	64

#endif /* SHIRUDO_BPF_XATTR_H */
