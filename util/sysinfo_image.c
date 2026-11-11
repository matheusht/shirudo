// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Boot image identity remains here while the host overview moves to Rust.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "io.h"
#include "malloc.h"
#include "sysinfo.h"

static void read_first_line(const char *path, char *buf, size_t cap)
{
	ssize_t n;
	int fd;

	buf[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = read(fd, buf, cap - 1);
	close(fd);
	if (n <= 0 ||
	    span_to_str(buf, cap, buf, span_until(buf, (size_t)n, "\r\n")))
		buf[0] = '\0';
}
#define OS_RELEASE_SIZE_MAX	(64u * 1024u)
/* Above the COMMAND_LINE_SIZE of every architecture. */
#define CMDLINE_SIZE_MAX	8192u

static bool os_release_escapable(char c)
{
	return c == '"' || c == '\\' || c == '$' || c == '`';
}

static int os_release_unquote(const char *value, size_t len,
			      char out[SYSINFO_IMAGE_VALUE_MAX])
{
	bool double_quoted = false;
	size_t n = 0, i;

	if (len >= 2 && value[0] == value[len - 1] &&
	    (value[0] == '"' || value[0] == '\'')) {
		double_quoted = value[0] == '"';
		value++;
		len -= 2;
	}
	for (i = 0; i < len; i++) {
		if (double_quoted && value[i] == '\\' && i + 1 < len &&
		    os_release_escapable(value[i + 1]))
			i++;
		if ((__u8)value[i] < 0x20 || (__u8)value[i] > 0x7e ||
		    n == SYSINFO_IMAGE_VALUE_MAX - 1)
			return -EINVAL;
		out[n++] = value[i];
	}
	if (!n)
		return -EINVAL;
	out[n] = '\0';
	return 0;
}

static void os_release_value(const char *text, size_t len, const char *key,
			     char out[SYSINFO_IMAGE_VALUE_MAX])
{
	const char *end = text + len, *value = NULL, *line, *eol;
	size_t key_len = strlen(key), value_len = 0;

	for (line = text; line < end; line = eol < end ? eol + 1 : end) {
		eol = memchr(line, '\n', (size_t)(end - line));
		if (!eol)
			eol = end;
		if ((size_t)(eol - line) <= key_len ||
		    memcmp(line, key, key_len) || line[key_len] != '=')
			continue;
		value = line + key_len + 1;
		value_len = (size_t)(eol - value);
	}
	if (!value || os_release_unquote(value, value_len, out))
		out[0] = '\0';
}

/* os-release(5): /usr/lib/os-release stands in only where /etc has none. */
static int read_os_release(const char *path, const char *fallback,
			   char **text, size_t *len)
{
	int ret = read_file(path, OS_RELEASE_SIZE_MAX, text, len);

	if (ret == -ENOENT)
		ret = read_file(fallback, OS_RELEASE_SIZE_MAX, text, len);
	return ret;
}
static bool cmdline_space(char c)
{
	return c == ' ' || c == '\t' || c == '\n';
}

static int image_root_normalise(const char *arg, size_t len,
				char out[SYSINFO_IMAGE_ROOT_MAX])
{
	size_t i;

	if (len != SYSINFO_IMAGE_ROOT_MAX - 1)
		return -EINVAL;
	for (i = 0; i < len; i++) {
		if (!isxdigit((__u8)arg[i]))
			return -EINVAL;
		out[i] = (char)tolower((__u8)arg[i]);
	}
	out[len] = '\0';
	return 0;
}

struct cmdline_arg {
	const char *value;
	size_t len;
};

static void cmdline_arg_match(const char *arg, size_t len, const char *key,
			      struct cmdline_arg *found)
{
	size_t key_len = strlen(key);

	if (len < key_len || memcmp(arg, key, key_len))
		return;
	found->value = arg + key_len;
	found->len = len - key_len;
}

static void cmdline_image_root(const char *cmdline, size_t len,
			       char out[SYSINFO_IMAGE_ROOT_MAX])
{
	const char *end = cmdline + len, *arg, *arg_end;
	struct cmdline_arg roothash = {}, usrhash = {};
	const struct cmdline_arg *hash;

	for (arg = cmdline; arg < end; arg = arg_end) {
		while (arg < end && cmdline_space(*arg))
			arg++;
		arg_end = arg;
		while (arg_end < end && !cmdline_space(*arg_end))
			arg_end++;
		cmdline_arg_match(arg, (size_t)(arg_end - arg), "roothash=",
				  &roothash);
		cmdline_arg_match(arg, (size_t)(arg_end - arg), "usrhash=",
				  &usrhash);
	}
	hash = roothash.value ? &roothash : &usrhash;
	if (!hash->value || image_root_normalise(hash->value, hash->len, out))
		out[0] = '\0';
}

void sysinfo_image_read_at(const char *os_release,
			   const char *os_release_fallback,
			   const char *cmdline, struct sysinfo_image *img)
{
	char line[CMDLINE_SIZE_MAX] = {};
	size_t len;
	char *text;

	*img = (struct sysinfo_image){};
	if (!read_os_release(os_release, os_release_fallback, &text, &len)) {
		os_release_value(text, len, "IMAGE_ID", img->id);
		os_release_value(text, len, "IMAGE_VERSION", img->version);
		xfree(text, len + 1);
	}
	read_first_line(cmdline, line, sizeof(line));
	len = strlen(line);
	if (len < sizeof(line) - 1)
		cmdline_image_root(line, len, img->root);
}

void sysinfo_image_read(struct sysinfo_image *img)
{
	sysinfo_image_read_at("/etc/os-release", "/usr/lib/os-release",
			      "/proc/cmdline", img);
}
