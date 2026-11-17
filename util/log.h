/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * syslog(3) wrappers under LOG_AUTHPRIV.
 */

#ifndef SHIRUDO_LOG_H
#define SHIRUDO_LOG_H

#include <stdarg.h>
#include <stdbool.h>

#include <shirudo/compiler.h>
#include <shirudo/types.h>

/*
 * Opens syslog. From then on a message goes to standard error as well,
 * unless that is the journal stream of a systemd service, where the
 * syslog record is the one copy.
 */
void log_init(void);

/*
 * Whether stream, the value of systemd's JOURNAL_STREAM, names the file
 * of device dev and inode ino: "<device>:<inode>" in decimal.
 */
bool log_stream_is(const char *stream, __u64 dev, __u64 ino);

/* Log a formatted message from C through rust/src/log.rs. */
void log_emit(int priority, const char *msg);

void pr_err(const char *fmt, ...)
	__printf(1, 2);
void pr_warn(const char *fmt, ...)
	__printf(1, 2);
void pr_info(const char *fmt, ...)
	__printf(1, 2);
void pr_audit(const char *fmt, ...)
	__printf(1, 2);

#endif /* SHIRUDO_LOG_H */
