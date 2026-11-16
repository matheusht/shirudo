/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_UTIL_UPATCH_MAPS_OTEL_H
#define SHIRUDO_UTIL_UPATCH_MAPS_OTEL_H

#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#include <shirudo/misc.h>

#include "upatch_maps.h"

enum otel_signal {
	/* Keep these values aligned with SHIRUDO_UPATCH_DECODER_EXPORT_*. */
	OTEL_LOG = 1,
	OTEL_METRIC = 2,
};

enum otel_mode {
	OTEL_AUTO,
	OTEL_FORCE_LOG,
	OTEL_FORCE_METRIC,
	OTEL_S3,
};

struct otel_opts {
	const char	*endpoint;
	const char	*tenant_id;
	const char	*s3_uri;
	bool		allow_insecure;
	__u32		retries;
	__u32		log_record_max_bytes;
	__u32		otlp_max_bytes;
};

int upatch_maps_otel_classify(const struct map_view *v,
			      enum otel_signal *signal,
			      char *reason, size_t reason_sz);
int upatch_maps_otel_build_log_file(const char *path,
				    const struct map_view *v,
				    char **out, size_t *out_len);
int upatch_maps_otel_build_metric_file(const char *path,
				       const struct map_view *v,
				       char **out, size_t *out_len);
int upatch_maps_otel_send(const struct map_view *v,
			  enum otel_mode mode,
			  const struct otel_opts *opts);
int upatch_maps_otel_send_file(const char *path,
			       const struct map_view *v,
			       enum otel_mode mode,
			       const struct otel_opts *opts);

/* Export using the matching decoder's signed, static signal selection. */
int upatch_maps_otel_send_decoded(const struct map_view *v,
				  enum otel_signal signal,
				  const struct otel_opts *opts);

/*
 * Send body_len bytes as the string body of one OTLP log with a single
 * string attribute. The receiver decodes the very bytes passed in; a
 * body with a NUL or malformed UTF-8 is -EILSEQ and nothing is sent.
 */
int otel_send_log_string(const struct otel_opts *opts,
			 const char *scope_name,
			 const char *event_name,
			 int severity_number,
			 const char *severity_text,
			 const char *body, size_t body_len,
			 const char *attr_key,
			 const char *attr_value) __must_check;
int otel_send_log_json(const struct otel_opts *opts,
		       const char *scope_name, const char *event_name,
		       int severity_number, const char *severity_text,
		       const char *status, const char *version_id,
		       __s64 tamper_attempts, const char *body_json,
		       size_t body_len) __must_check;
int otel_retry_after(const char *value, time_t now, __u64 *seconds);
int status_otel_severity(const char *status, const char **text);

#endif /* SHIRUDO_UTIL_UPATCH_MAPS_OTEL_H */
