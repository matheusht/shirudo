// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/keyctl.h>

#include <shirudo/string.h>

#include "util/keyring.h"
#include "util/keys.h"
#include "util/malloc.h"
#include "util/paths.h"

/*
 * init's enrolment, keyring_seal_set(), runs against a private keyring
 * rather than the sealed .bpf: it adds to and seals the keyring named.
 */
static key_serial_t test_ring;

/* Seal the ring as init seals the bpf keyring: no type, nothing more. */
static int seal_ring(key_serial_t ring)
{
	if (syscall(__NR_keyctl, KEYCTL_RESTRICT_KEYRING, ring, 0, 0, 0) < 0)
		return -errno;
	return 0;
}

/* Enrol <set> in the private ring and seal it, as init does the .bpf. */
static int enrol(const struct trusted_set *set)
{
	return keyring_seal_set(test_ring, test_ring, set);
}

static key_serial_t add(const char *type, const char *description,
			const void *payload, size_t len, key_serial_t ring)
{
	long ret = syscall(__NR_add_key, type, description, payload, len,
			   ring);

	return ret < 0 ? -errno : (key_serial_t)ret;
}

static int read_cert(const char *path, struct keyring_cert *cert)
{
	__u8 *der = NULL;
	size_t len = 0;
	int ret;

	ret = keys_read_der(path, &der, &len);
	if (ret)
		return ret;
	cert->der = der;
	cert->len = len;
	return 0;
}

static int expect(const char *what, int got, int want)
{
	if (got == want)
		return 0;
	fprintf(stderr, "%s: got %d, want %d\n", what, got, want);
	return 1;
}

/* Every link counts, of any type and whether it can be described. */
static int exact_case(const struct keyring_cert *a,
		      const struct keyring_cert *b)
{
	struct keyring_cert both[2] = { *a, *b }, swapped[2] = { *b, *a };
	struct keyring_cert twice[2] = { *a, *a };
	key_serial_t ring, key;
	int fails = 0;

	ring = add("keyring", "shirudo-test-exact", NULL, 0,
		   KEY_SPEC_THREAD_KEYRING);
	if (ring < 0)
		return ring;
	fails += expect("empty, none", keyring_holds_exactly(ring, NULL, 0), 1);
	fails += expect("empty, one", keyring_holds_exactly(ring, a, 1), 0);
	if (add("asymmetric", NULL, a->der, a->len, ring) < 0)
		return -EIO;
	fails += expect("one, one", keyring_holds_exactly(ring, a, 1), 1);
	fails += expect("one, none", keyring_holds_exactly(ring, NULL, 0), 0);
	fails += expect("one, two", keyring_holds_exactly(ring, both, 2), 0);
	if (add("asymmetric", NULL, b->der, b->len, ring) < 0)
		return -EIO;
	fails += expect("two, two", keyring_holds_exactly(ring, both, 2), 1);
	fails += expect("two, swapped",
			keyring_holds_exactly(ring, swapped, 2), 1);
	fails += expect("two, twice", keyring_holds_exactly(ring, twice, 2), 0);
	fails += expect("two, one", keyring_holds_exactly(ring, a, 1), 0);

	key = add("keyring", "shirudo-test-nested", NULL, 0, ring);
	fails += expect("nested keyring",
			key < 0 ? key : keyring_holds_exactly(ring, both, 2), 0);
	if (key > 0)
		keyring_unlink_key(ring, key);
	key = add("user", "shirudo-test-user", "x", 1, ring);
	fails += expect("user key",
			key < 0 ? key : keyring_holds_exactly(ring, both, 2), 0);
	if (key > 0)
		keyring_unlink_key(ring, key);
	key = add("user", "shirudo-test-hidden", "x", 1, ring);
	if (key > 0 && syscall(__NR_keyctl, KEYCTL_SETPERM, key, 0, 0, 0) < 0)
		key = -errno;
	fails += expect("key hidden from view",
			key < 0 ? key : keyring_holds_exactly(ring, both, 2), 0);
	if (key > 0)
		keyring_unlink_key(ring, key);
	fails += expect("two again", keyring_holds_exactly(ring, both, 2), 1);
	keyring_unlink_key(KEY_SPEC_THREAD_KEYRING, ring);
	return fails ? -EKEYREJECTED : 0;
}

/* <set> is the trusted set init enrols; <other> a certificate outside it. */
static int seal_case(const char *mode,
		     const struct trusted_set *set,
		     const struct keyring_cert *own,
		     const struct keyring_cert *other)
{
	int ret, fails = 0;

	test_ring = add("keyring", "shirudo-test-seal", NULL, 0,
			KEY_SPEC_THREAD_KEYRING);
	if (test_ring < 0)
		return test_ring;
	if (!strcmp(mode, "fresh")) {
		fails += expect("enrol and seal",
				enrol(set), 0);
		fails += expect("found sealed with the set",
				enrol(set), -EEXIST);
	} else if (!strcmp(mode, "foreign")) {
		if (add("asymmetric", NULL, other->der, other->len,
			test_ring) < 0)
			return -EIO;
		fails += expect("foreign key sealed in",
				enrol(set), -EKEYREJECTED);
		fails += expect("found sealed with a foreign key",
				enrol(set), -EKEYREJECTED);
	} else if (!strcmp(mode, "nested")) {
		if (add("keyring", "shirudo-test-nested", NULL, 0,
			test_ring) < 0)
			return -EIO;
		fails += expect("nested keyring sealed in",
				enrol(set), -EKEYREJECTED);
	} else if (!strcmp(mode, "restricted")) {
		if (add("asymmetric", NULL, own->der, own->len, test_ring) < 0 ||
		    syscall(__NR_keyctl, KEYCTL_RESTRICT_KEYRING, test_ring,
			    "asymmetric", "key_or_keyring:0:chain", 0) < 0)
			return -EIO;
		ret = enrol(set);
		fails += expect("restriction init did not install",
				ret == 0 || ret == -EEXIST, 0);
	} else if (!strcmp(mode, "empty")) {
		if (seal_ring(test_ring))
			return -EIO;
		fails += expect("sealed empty",
				enrol(set), -ENOKEY);
	} else {
		return -EINVAL;
	}
	keyring_unlink_key(KEY_SPEC_THREAD_KEYRING, test_ring);
	return fails ? -EKEYREJECTED : 0;
}

int main(int argc, char **argv)
{
	struct keyring_cert own = {}, other = {};
	struct trusted_set set = {};
	char keys[PATH_MAX];
	int ret;

	if (argc != 5) {
		fprintf(stderr, "usage: %s exact|fresh|foreign|nested|"
			"restricted|empty <keys-dir> <revoked-dir> <other.der>\n",
			argv[0]);
		return 2;
	}
	if (strsprintf(keys, sizeof(keys), "%s/%s", argv[2],
		       CERT_FILE) < 0)
		return 2;
	ret = read_cert(keys, &own);
	if (!ret)
		ret = read_cert(argv[4], &other);
	if (!ret && strcmp(argv[1], "exact"))
		ret = keys_load(argv[2], argv[3], false, &set);
	if (!ret)
		ret = strcmp(argv[1], "exact") ?
		     seal_case(argv[1], &set, &own, &other) :
		     exact_case(&own, &other);
	if (ret)
		fprintf(stderr, "keyring seal test %s: %s\n", argv[1],
			strerror(-ret));
	if (own.der)
		xfree((void *)own.der, own.len);
	if (other.der)
		xfree((void *)other.der, other.len);
	return ret ? 1 : 0;
}
