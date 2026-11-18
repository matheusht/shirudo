// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
//
// A command reads its options from an opt_spec table through
// util/options.c, which holds every rule they follow; an argument
// compared with an option name by hand skips those rules.

virtual report

@r@
attribute name SEC;
expression E, F;
constant char[] S;
identifier f = {strcmp, strncmp, strcasecmp, strncasecmp, str_has_prefix,
		str_skip_prefix, str_has_prefix_nocase,
		str_skip_prefix_nocase, str_after_prefix,
		str_after_prefix_nocase, str_equals_nocase,
		str_contains};
identifier g = {span_equals, span_equals_str, span_has_prefix_nocase};
position p;
@@
(
  f@p(E, S, ...)
|
  f@p(S, E, ...)
|
  g@p(E, F, S)
)

@script:python depends on report@
p << r.p;
S << r.S;
@@
import ast
try:
    text = ast.literal_eval(S)
except (ValueError, SyntaxError):
    text = ""
exempt = ("testing/",)
if text.startswith("-") and len(text) > 1 and \
   not p[0].file.startswith(exempt):
    coccilib.report.print_report(p[0],
        "%s compared by hand; name it in the command's opt_spec table" % text)
