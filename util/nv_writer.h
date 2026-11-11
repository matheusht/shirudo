/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The TPM key that alone may extend the measurement register, which
 * rust/src/util/nv_writer.rs implements.
 */
#ifndef SHIRUDO_NV_WRITER_H
#define SHIRUDO_NV_WRITER_H

#include "tpm_wire.h"

int nv_writer_create(__u8 seed[TPM_DIGEST_LEN],
		     __u8 public[TPM_NV_RSA_BYTES]);
int nv_writer_read(__u8 seed[TPM_DIGEST_LEN],
		   __u8 public[TPM_NV_RSA_BYTES]);

#endif /* SHIRUDO_NV_WRITER_H */
