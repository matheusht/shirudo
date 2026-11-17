/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * .upatch container parser, which rust/src/util/upatch.rs implements.
 * On-disk layout in <shirudo/upatch.h>.
 */

#ifndef SHIRUDO_UTIL_UPATCH_H
#define SHIRUDO_UTIL_UPATCH_H

#include <shirudo/misc.h>
#include <shirudo/upatch.h>
#include <dirent.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/stat.h>

/* The largest container the parser accepts. */
#define UPATCH_FILE_MAX		(16u * 1024u * 1024u)

/* struct upatch_header as parse_header() reads it, in host order. */
struct upatch_host_header {
	__u64		magic;
	__u32		version;
	__u32		flags;
	char		name[UPATCH_NAME_MAX];
	__u8		payload_sha256[UPATCH_PAYLOAD_HASH_LEN];
	__u32		loader_insns_off;
	__u32		loader_insns_len;
	__u32		signature_off;
	__u32		signature_len;
	__u32		metadata_off;
	__u32		metadata_len;
	__u32		data_off;
	__u32		data_len;
	__u32		log_buf_sz;
	__u32		nr_maps;
	__u32		nr_progs;
	__u32		rodata_data_off;
	__u32		type;
	__u32		reserved1;
};

struct upatch {
	struct upatch_host_header	hdr;
	const __u8			*map;
	size_t				map_size;
	bool				owned;
	bool				rodata_offset_in_header;
	const struct upatch_decoder_blob *decoder_blob;
	__u32				decoder_blob_len;
	__u32				nr_decoders;
	const char			*signed_name;	/* UPATCH_NAME_MAX */
	const __u8			*signed_attach;
	__u32				signed_attach_len;
	const __u8			*signed_unload_payload;	/* 32 bytes */
	const void			*signed_policy_labels;
	__u32				signed_policy_labels_len;
	__u32				signed_policy_map_idx;
	__u32				signed_socket_policy_map_idx;
};

struct upatch_decoder_view {
	__u32		language;
	__u32		api_version;
	__u32		input_format;
	__u32		export_signal;
	char		upatch[64];
	char		map[16];
	char		source_name[64];
	char		entrypoint[32];
	const char	*source;
	__u32		source_len;
};

/*
 * Returns 0 on success, -errno on failure. Logs nothing -- caller
 * decides whether to emit user-facing diagnostics.
 */
int  upatch_open(const char *path, struct upatch *out);
int  upatch_open_fd(int fd, struct upatch *out);
int  upatch_open_memory(const void *data, size_t size,
			struct upatch *out);
void upatch_close(struct upatch *u);

/*
 * Section accessors. Pointers reference the mmap; valid only until
 * upatch_close().
 */
const void *upatch_loader(const struct upatch *u);
const void *upatch_signature(const struct upatch *u);
const void *upatch_metadata(const struct upatch *u);
const void *upatch_data(const struct upatch *u);

bool upatch_is_unload(const struct upatch *u);
const char *upatch_type_str(const struct upatch *u);

bool upatch_has_decoders(const struct upatch *u);
int upatch_decoder_view(const struct upatch *u, __u32 idx,
			struct upatch_decoder_view *out);

/*
 * The signed sections, NULL where the data carries none: the name,
 * NUL-padded to UPATCH_NAME_MAX like the header's; the attach
 * metadata of a load; the payload digest an unload directive expects.
 * A load or unload refuses what it needs and does not find; inspection
 * shows what there is.
 */
const char *upatch_signed_name(const struct upatch *u);

/*
 * A member of a set of measured upatches, as an init record and the
 * commands that predict one list it: a name upatch_name_valid() takes and
 * the 64 hex digits of its payload's SHA-256.
 */
bool upatch_member_valid(const char *name, const char *payload_hex);

/* The name in the header, which the file need not terminate, with a NUL. */
void upatch_header_name(const struct upatch *u, char out[UPATCH_NAME_MAX + 1]);
/*
 * Whether the header's name is the one the signed sections carry: the
 * header's is what the pins, the archive and the eventlog go by.
 */
bool upatch_name_signed(const struct upatch *u);
/*
 * The name the loader program takes, zero-padded to size: at most
 * size - 1 bytes of the header's, with every byte but those
 * bpf_obj_name_cpy() takes, an alphanumeric, '_' or '.', made '_'.
 */
void upatch_prog_name(const struct upatch *u, char *out, size_t size);
const void *upatch_signed_attach(const struct upatch *u,
				 __u32 *len);
const __u8 *upatch_signed_unload_payload(const struct upatch *u);

const void *upatch_signed_policy_labels(const struct upatch *u,
					__u32 *len);

/*
 * An upatch name: [A-Za-z0-9._-]+ not starting with '.', so nothing that
 * leaves the bpffs or the archive directory, and short enough for its pin
 * directory, which spells each '.' in two bytes, to fit NAME_MAX.
 */
bool upatch_name_valid(const char *name);

/* A scandir() filter for the archived .upatch files. */
int upatch_select(const struct dirent *e);

struct prog_spec {
	__u32 role;
	__u32 kind;
	__u64 offset;
	char target[UPATCH_ATTACH_TARGET_MAX];
	char map[UPATCH_PROG_MAP_MAX];
	char *uprobe_path;
	__u32 uprobe_path_len;
	__u8 build_id[UPATCH_BUILD_ID_MAX];
	__u32 build_id_len;
	__u64 *uprobe_offsets;
	__u32 nr_uprobe_offsets;
	int target_fd;
	struct stat target_stat;
};

/*
 * The attach metadata of a load upatch, parsed strictly into one spec
 * per program, target_fd -1. 0 or -errno; free with prog_specs_free().
 */
int prog_specs_parse(const void *metadata, __u32 metadata_len,
		     __u32 nr_maps, __u32 nr_progs, struct prog_spec **out);
void prog_specs_free(struct prog_spec *specs, __u32 nr_progs);

/*
 * The signed loader of builtin-upatch.c: upatch_apply() for init's boot
 * restore, and for the operations of rust/src/builtin/upatch/ops.rs
 * upatch_apply_signed(), which with verify_only checks the signature
 * alone, and upatch_trust_anchor(), the kernel's BPF keyring checked
 * against the anchor init froze. Each says what failed in rep.
 */
struct op_report;

int upatch_apply(const char *path);
int upatch_apply_signed(const char *path, bool verify_only,
			struct op_report *rep);
int upatch_trust_anchor(__s32 *keyring, __s32 *serial,
			struct op_report *rep);

/* The pins of upatch name removed, which detaches it: 0 or -errno. */
int upatch_remove_pins(const char *name);

#endif /* SHIRUDO_UTIL_UPATCH_H */
