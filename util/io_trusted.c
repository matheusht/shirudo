// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/*
 * Keep the current C pathname check while C commands still use
 * open_trusted(). Remove this file when those callers move to Rust.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <shirudo/string.h>

#include "io.h"
#include "log.h"
#include "paths.h"

static int open_path(const char *path, int flags)
{
	int fd = open(path, flags | O_CLOEXEC);

	return fd < 0 ? -errno : fd;
}

static bool under(const char *path, const char *dir)
{
	const char *below = str_after_prefix(path, dir);

	return below && *below == '/';
}

static bool trusted_owner(uid_t uid)
{
	return uid == 0 || uid == geteuid();
}

/* As many links as the kernel follows on the way to one file. */
#define TRUSTED_LINKS_MAX	40

struct trusted_walk {
	const char *path;	/* as the caller named it, for messages */
	char rest[PATH_MAX];	/* the names still to look up */
	int dirfd;		/* the directory the next name is looked up in */
	int links;
};

/* What fd is open on, named for a message. */
static const char *opened_path(int fd, char name[PATH_MAX])
{
	char link[32];
	ssize_t n;

	if (strsprintf(link, sizeof(link), "/proc/self/fd/%d", fd) < 0)
		return "?";
	n = readlink(link, name, PATH_MAX - 1);
	if (n < 0)
		return "?";
	name[n] = '\0';
	return name;
}

static int trusted_dir(const struct trusted_walk *walk)
{
	char name[PATH_MAX];
	struct stat st;

	if (fstat(walk->dirfd, &st))
		return -errno;
	if (!S_ISDIR(st.st_mode))
		return -ENOTDIR;
	if (trusted_owner(st.st_uid) &&
	    (!(st.st_mode & 022) ||
	     ((st.st_mode & S_ISVTX) && st.st_uid == 0)))
		return 0;
	pr_err("%s: directory %s, owner %u, mode %04o: refusing a file another user could replace",
	       walk->path, opened_path(walk->dirfd, name), (__u32)st.st_uid,
	       (__u32)(st.st_mode & 07777));
	return -EPERM;
}

static int walk_from_root(struct trusted_walk *walk)
{
	if (walk->dirfd >= 0)
		close(walk->dirfd);
	walk->dirfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
	return walk->dirfd < 0 ? -errno : 0;
}

/*
 * The target of the link open on fd goes ahead of the names left after
 * it. In a sticky directory a link is its owner's to replace, so another
 * user's link is refused wherever it is found.
 */
static int walk_link(struct trusted_walk *walk, int fd, uid_t owner,
		     const char *left)
{
	char target[PATH_MAX], name[PATH_MAX];
	ssize_t n;

	if (!trusted_owner(owner)) {
		pr_err("%s: link %s, owner %u: refusing a file another user could replace",
		       walk->path, opened_path(fd, name), (__u32)owner);
		return -EPERM;
	}
	if (++walk->links > TRUSTED_LINKS_MAX)
		return -ELOOP;
	n = readlinkat(fd, "", target, sizeof(target));
	if (n < 0)
		return -errno;
	if ((size_t)n >= sizeof(target))
		return -ENAMETOOLONG;
	target[n] = '\0';
	if (strsprintf(target + n, sizeof(target) - (size_t)n, "/%s", left) < 0 ||
	    strscpy(walk->rest, target, sizeof(walk->rest)) < 0)
		return -ENAMETOOLONG;
	return target[0] == '/' ? walk_from_root(walk) : 0;
}

/* The name that ends at end, looked up in the directory and not followed. */
static int walk_open(const struct trusted_walk *walk, const char *name,
		     char *end)
{
	char cut = *end;
	int fd, err;

	*end = '\0';
	fd = openat(walk->dirfd, name, O_PATH | O_NOFOLLOW | O_CLOEXEC);
	err = errno;
	*end = cut;
	return fd < 0 ? -err : fd;
}

static char *skip_slashes(char *s)
{
	while (*s == '/')
		s++;
	return s;
}

/*
 * The path resolved one name at a time, each directory checked through
 * the descriptor the next name is looked up in, and each link read
 * through the one it was found by: a lookup of the whole path by name
 * can go another way than the open of the file did, through a name
 * another user swapped in between or a link another user made. 0 when
 * it ends at the file *file describes, -ESTALE unlogged when at another.
 */
static int trusted_walk(struct trusted_walk *walk, const struct stat *file)
{
	char *name = walk->rest, *end;
	struct stat st;
	int fd, ret;
	bool link;

	for (;;) {
		ret = trusted_dir(walk);
		if (ret)
			return ret;
		name = skip_slashes(name);
		end = strchr(name, '/');
		if (!end)
			end = name + strlen(name);
		if (end == name)
			return -EISDIR;
		fd = walk_open(walk, name, end);
		if (fd < 0)
			return fd;
		if (fstat(fd, &st)) {
			ret = -errno;
			close(fd);
			return ret;
		}
		if (S_ISDIR(st.st_mode)) {
			close(walk->dirfd);
			walk->dirfd = fd;
			name = end;
			continue;
		}
		link = S_ISLNK(st.st_mode);
		ret = link ? walk_link(walk, fd, st.st_uid, end) : 0;
		close(fd);
		if (ret)
			return ret;
		if (!link)
			break;
		name = walk->rest;
	}
	if (*skip_slashes(end))
		return -ENOTDIR;
	return st.st_dev == file->st_dev && st.st_ino == file->st_ino ?
	       0 : -ESTALE;
}

static void report_stale(const char *path)
{
	pr_err("%s: names another file than the one opened; refusing it",
	       path);
}

static bool trusted_place(const char *path)
{
	return under(path, ETC_DIR) || under(path, VAR_LIB);
}

/* The file open on fd by itself, whatever path led to it. */
static int trusted_file(int fd, const char *path, bool secret,
			struct stat *st)
{
	if (fstat(fd, st))
		return -errno;
	if (!S_ISREG(st->st_mode) || !trusted_owner(st->st_uid) ||
	    (st->st_mode & (secret ? 077 : 022))) {
		pr_err("%s: owner %u, mode %04o: refusing a file another user "
		       "could %s", path, (__u32)st->st_uid,
		       (__u32)(st->st_mode & 07777),
		       secret ? "read or change" : "change");
		return -EPERM;
	}
	return 0;
}

/* check_trusted(), a file renamed over left for the caller to report. */
static int trusted_check(int fd, const char *path)
{
	struct trusted_walk walk = { .path = path, .dirfd = -1 };
	struct stat st;
	int ret;

	if (!trusted_place(path))
		return 0;
	ret = trusted_file(fd, path, false, &st);
	if (ret)
		return ret;
	if (strscpy(walk.rest, path, sizeof(walk.rest)) < 0)
		return -ENAMETOOLONG;
	ret = walk_from_root(&walk);
	if (!ret)
		ret = trusted_walk(&walk, &st);
	if (walk.dirfd >= 0)
		close(walk.dirfd);
	return ret;
}

/* Reopens of a name that an open_trusted() makes after its first open. */
#define TRUSTED_REOPENS		3

/*
 * Each attempt opens the name again and runs the whole check on its own
 * descriptor, so that one passes only what a single check passes. A
 * rename that an attempt absorbs is not reported; the last is.
 */
static int open_checked(const char *path, int flags,
			int (*opener)(const char *path, int flags))
{
	int attempt, fd, ret;

	for (attempt = 0;; attempt++) {
		fd = opener(path, flags);
		if (fd < 0)
			return fd;
		ret = trusted_check(fd, path);
		if (!ret)
			return fd;
		close(fd);
		if (ret != -ESTALE || attempt == TRUSTED_REOPENS)
			break;
	}
	if (ret == -ESTALE)
		report_stale(path);
	return ret;
}

int open_trusted(const char *path, int flags)
{
	return open_checked(path, flags, open_path);
}

