/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * TPM 2.0 wire-format helpers that need no TPM: policy digests, NV and
 * object names, and the attestation structures a verifier parses, which
 * rust/src/util/tpm_wire/ implements.
 */

#ifndef SHIRUDO_TPM_WIRE_H
#define SHIRUDO_TPM_WIRE_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <shirudo/byteorder.h>
#include <shirudo/misc.h>
#include <shirudo/tpm.h>

/* A TPM2B: the size, then the bytes. */
static inline size_t tpm_put2b(__u8 *p, const __u8 *data, size_t len)
{
	put_be16(p, (__u16)len);
	memcpy(p + 2, data, len);
	return 2 + len;
}

#define TPM_DIGEST_LEN		32
BUILD_BUG_ON_MSG(TPM_NAME_LEN != 2 + TPM_DIGEST_LEN,
		 "a name is the algorithm and its digest");
#define TPM_ALG_RSA		0x0001u
#define TPM_ALG_AES		0x0006u
#define TPM_ALG_SHA256		0x000Bu
#define TPM_ALG_ECC		0x0023u
#define TPM_ALG_ECDSA		0x0018u
#define TPM_ALG_RSASSA		0x0014u
#define TPM_ALG_NULL		0x0010u
#define TPM_ALG_CFB		0x0043u
#define TPM_ECC_NIST_P256	0x0003u
#define TPM_ST_ATTEST_NV	0x8014u
#define TPM_ST_ATTEST_QUOTE	0x8018u
#define TPM_GENERATED		0xFF544347u
#define TPM_PCR_SELECT_LEN	3
#define TPM_PCR_SELECTION_LEN	(7 + TPM_PCR_SELECT_LEN)
#define TPM_NV_POLICY_REF		"shirudo-nv-writer-v1"
#define TPM_WRITER_ATTRS		0x00040072u

void tpm_writer_public(const __u8 modulus[TPM_NV_RSA_BYTES],
		       __u8 out[TPM_NV_RSA_PUBLIC_AREA_LEN]);
int tpm_nv_extend_cphash(const __u8 name[TPM_NAME_LEN],
			 const __u8 event[32], __u8 out[32]) __must_check;
int tpm_writer_auth_hash(const __u8 *nonce, size_t nonce_len,
			 const __u8 cphash[32], __u8 out[32]) __must_check;
int tpm_policy_signed(const __u8 prev[32],
		      const __u8 writer_public[TPM_NV_RSA_BYTES],
		      __u8 out[32]) __must_check;
int tpm_policy_command_code(const __u8 prev[TPM_DIGEST_LEN],
			    __u32 command_code,
			    __u8 out[TPM_DIGEST_LEN]) __must_check;
int tpm_register_policy_final(const __u8 branch_written[32],
			      const __u8 branch_init[32],
			      const __u8 writer_public[TPM_NV_RSA_BYTES],
			      __u8 policy[32]) __must_check;

/*
 * Attributes of the measurement register: an extend-only NV index
 * whose contents clear at every TPM reset, written only under its
 * policy, readable by anyone, kept in TPM RAM until an orderly
 * shutdown (TPMA_NV_CLEAR_STCLEAR | ORDERLY | POLICYWRITE | OWNERREAD |
 * AUTHREAD | NO_DA | TPM2_NT_EXTEND).
 */
#define TPM_REGISTER_ATTRS	0x0E060048u
#define TPM_NV_WRITTEN		0x20000000u

int tpm_policy_nv_written(const __u8 prev[TPM_DIGEST_LEN],
			  bool written,
			  __u8 out[TPM_DIGEST_LEN]) __must_check;
int tpm_policy_pcr(const __u8 prev[TPM_DIGEST_LEN],
		   __u32 pcr_mask,
		   const __u8 pcr_digest[TPM_DIGEST_LEN],
		   __u8 out[TPM_DIGEST_LEN]) __must_check;
int tpm_policy_or(const __u8 a[TPM_DIGEST_LEN],
		  const __u8 b[TPM_DIGEST_LEN],
		  __u8 out[TPM_DIGEST_LEN]) __must_check;

/*
 * The register's write policy from the values the binding PCRs held
 * at binding time, given in PCR order: PolicyOR(PolicyNvWritten(YES),
 * PolicyNvWritten(NO) + PolicyPCR(mask, SHA-256(values))), followed by
 * PolicySigned and PolicyCommandCode(NV_Extend). The two branch
 * digests are what a session has to present to PolicyOR.
 */
int tpm_register_policy(__u32 pcr_mask,
			const __u8 *pcr_values, size_t n_values,
			const __u8 writer_public[TPM_NV_RSA_BYTES],
			__u8 branch_written[32],
			__u8 branch_init[32],
			__u8 policy[32]) __must_check;

/* Name of an NV index: nameAlg || SHA-256(TPMS_NV_PUBLIC). */
int tpm_nv_name(__u32 index, __u32 attrs,
		const __u8 policy[TPM_DIGEST_LEN],
		__u16 data_size,
		__u8 name[TPM_NAME_LEN]) __must_check;

int tpm_object_name(const __u8 *public, size_t len,
		    __u8 name[TPM_NAME_LEN]) __must_check;

/*
 * Qualified name of a primary object: nameAlg || SHA-256(hierarchy
 * handle || name). Attestations carry the signer's qualified name.
 */
#define TPM_RH_ENDORSEMENT	0x4000000Bu
int tpm_qualified_name(__u32 hierarchy,
		       const __u8 name[TPM_NAME_LEN],
		       __u8 out[TPM_NAME_LEN]) __must_check;

/*
 * The TCG default endorsement key templates: a restricted decryption
 * key under the endorsement hierarchy's policy, protecting with
 * AES-128-CFB (fixedTPM | fixedParent | sensitiveDataOrigin |
 * adminWithPolicy | restricted | decrypt).
 */
#define TPM_EK_ATTRS		0x000300B2u
extern const __u8 shirudo_tpm_ek_policy[TPM_DIGEST_LEN];

/*
 * A TPMT_PUBLIC of the shapes shirudo makes or checks: a SHA-256-named
 * P-256 or RSA-2048 key, its symmetric protector absent or
 * AES-128-CFB, its scheme absent or ECDSA with SHA-256.
 */
struct tpm_public {
	__u16		type;
	__u32		attrs;
	size_t		policy_len;	/* 0 or 32 */
	__u8		policy[TPM_DIGEST_LEN];
	__u16		sym_alg;
	__u16		sym_bits;
	__u16		sym_mode;
	__u16		scheme;
	__u16		scheme_hash;
	__u16		curve;		/* ECC */
	__u8		x[32];
	__u8		y[32];
	__u16		rsa_bits;	/* RSA */
	__u32		rsa_exponent;
	size_t		n_len;
	__u8		n[256];
};

int tpm_public_parse(const __u8 *buf, size_t len,
		     struct tpm_public *out) __must_check;
int tpm_public_marshal(const struct tpm_public *pub,
		       __u8 *out, size_t cap, size_t *len) __must_check;

struct tpm_ecc_public {
	__u32		attrs;
	__u16		scheme;
	__u16		hash;
	__u16		curve;
	__u8		x[32];
	__u8		y[32];
};

int tpm_ecc_public_parse(const __u8 *buf, size_t len,
			 struct tpm_ecc_public *out) __must_check;

/*
 * The key derivations of TPM 2.0 Part 1 with SHA-256: KDFa (SP800-108
 * in counter mode) and KDFe (SP800-56A one-step). Labels are given
 * without their terminating NUL, which the derivation adds.
 */
int tpm_kdfa(const __u8 *key, size_t key_len, const char *label,
	     const __u8 *ctx_u, size_t u_len,
	     const __u8 *ctx_v, size_t v_len,
	     __u8 *out, size_t out_len) __must_check;
int tpm_kdfe(const __u8 z[32], const char *label,
	     const __u8 *party_u, size_t u_len,
	     const __u8 *party_v, size_t v_len, __u8 out[32]) __must_check;

/*
 * Credential protection (Part 1, 24.4): from a seed shared with the
 * endorsement key, the TPM2B_ID_OBJECT contents that
 * TPM2_ActivateCredential accepts for the object of the given name:
 * the integrity HMAC and the credential encrypted under keys both
 * derived from the seed and the name.
 */
#define TPM_CREDENTIAL_LEN	32
#define TPM_ID_OBJECT_LEN	(2 + 32 + 2 + TPM_CREDENTIAL_LEN)
int tpm_credential_protect(const __u8 seed[32],
			   const __u8 name[TPM_NAME_LEN],
			   const __u8 credential[TPM_CREDENTIAL_LEN],
			   __u8 out[TPM_ID_OBJECT_LEN]) __must_check;

int tpm_ecdsa_signature_parse(const __u8 *buf, size_t len,
			      __u8 r[32], __u8 s[32]) __must_check;

struct tpm_attest {
	__u16		type;
	__u8		signer[TPM_NAME_LEN];
	size_t		signer_len;
	const __u8	*extra;
	size_t		extra_len;
	__u64		clock;
	__u32		reset_count;
	__u32		restart_count;
	bool		safe;
	__u64		firmware_version;
	/* TPM_ST_ATTEST_QUOTE */
	__u32		pcr_mask;
	__u8		pcr_digest[TPM_DIGEST_LEN];
	/* TPM_ST_ATTEST_NV */
	__u8		index_name[TPM_NAME_LEN];
	size_t		index_name_len;
	__u16		offset;
	const __u8	*nv_data;
	size_t		nv_len;
};

/*
 * Parse a TPMS_ATTEST produced by TPM2_Quote or TPM2_NV_Certify. Only a
 * single SHA-256 PCR bank is accepted in a quote. Pointers into the
 * input stay valid as long as buf does.
 */
int tpm_attest_parse(const __u8 *buf, size_t len,
		     struct tpm_attest *out) __must_check;

/*
 * The checks of attest verify and of the keepalive quote checker, in one
 * place so that neither gains a check the other lacks. tpm_attest_signer()
 * sets *is when the TPM named the key of ak_name, an endorsement primary,
 * as the signer. tpm_attest_verify() is 0 when the ECDSA signature over
 * SHA-256 of attest verifies with the point x, y, -EKEYREJECTED when it
 * does not, a point off the curve included, and -EBADMSG when sig does
 * not parse.
 */
int tpm_attest_signer(const struct tpm_attest *a,
		      const __u8 ak_name[TPM_NAME_LEN], bool *is) __must_check;
int tpm_attest_verify(const __u8 *attest, size_t len,
		      const __u8 *sig, size_t sig_len,
		      const __u8 x[32], const __u8 y[32]) __must_check;

#endif /* SHIRUDO_TPM_WIRE_H */
