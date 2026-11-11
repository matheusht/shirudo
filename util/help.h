/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The structured help every subcommand prints, which
 * rust/src/util/help.rs implements.
 */

#ifndef SHIRUDO_HELP_H
#define SHIRUDO_HELP_H

#include <stddef.h>

#include <shirudo/misc.h>

struct opt_spec;

struct help_item {
	const char	*name;
	const char	*summary;
};

/* A section lists items, or the options of a command's opt_spec table. */
struct help_section {
	const char			*header;
	const struct help_item	*items;
	size_t				n_items;
	const struct opt_spec		*options;
	size_t				n_options;
};

/* A section named h listing the items of the array a. */
#define HELP_ITEMS(h, a)						\
	{ .header = (h), .items = (a),					\
	  .n_items = ARRAY_SIZE(a) }

/* A section named h listing the options of the opt_spec array a. */
#define HELP_OPTIONS(h, a)						\
	{ .header = (h), .options = (a),				\
	  .n_options = ARRAY_SIZE(a) }

struct help {
	const char				*usage;
	const char				*summary;
	const struct help_section	*sections;
	size_t					n_sections;
	const char				*footer;
};

int is_help(const char *arg);

int is_list_cmds(const char *arg);

void print_help(const struct help *h);

/*
 * The names among n_names close enough to bad, a word the user typed
 * that matches none, printed as a did-you-mean block on stderr.
 */
void help_suggest(const char *bad, const char *const *names, size_t n_names);

/* What bash completion reads through --list-cmds. */
void print_subcmd_list(const struct help_item *items,
		       size_t n_items);

/*
 * NULL on failure with stderr already written: a did-you-mean block,
 * or the ambiguous matches.
 */
const char *resolve_subcommand(const char *cmd_label,
			       const char *input,
			       const struct help_item *subcmds,
			       size_t n_subcmds);

#endif /* SHIRUDO_HELP_H */
