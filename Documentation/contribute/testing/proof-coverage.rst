..
   SPDX-License-Identifier: BSD-2-Clause
   Copyright (c) 2026 Authors of shirudo

:page-type: Reference
:audience: shirudo contributors

Proof coverage
==============

This page lists the CBMC proofs under :src:`testing/proofs/cbmc/` and the
Lean 4 proofs under :src:`testing/proofs/lean4/`, what each one proves and
for which inputs, the source files no proof reads and the parsers no
proof covers yet. :doc:`proofs` explains how to run and write them. CI
runs every proof after a push to main but the CBMC proofs
:src:`testing/proofs/cbmc/ci-skip.list` names, which need more time or
memory than CI gives a proof: only a run a developer starts checks
those.

CBMC proofs
-----------

Every CBMC proof shows that the code reads and writes nothing outside its
objects and has no undefined arithmetic for the inputs it covers, besides
the properties the table lists. "Every input" means every input of any
length. A bound such as "up to 22 bytes" means every input of that length
or shorter, and "lengths 0 to 6" every input of each of those lengths.

.. list-table::
   :header-rows: 1
   :widths: 22 26 18 34

   * - Proof
     - Code
     - Inputs
     - Properties
   * - ``string-number``
     - ``parse_u64()``, ``parse_x64()``, ``parse_s64()``, ``digits()``
     - Up to 22 bytes, past the 20 digits of the largest value
     - Refuses exactly what is empty or holds a non-digit; a number
       within its bounds and of the sign the string spells; nothing
       written on refusal; ``digits()`` finds the whole run
   * - ``string-number-model``
     - ``parse_u64()``, ``parse_x64()``
     - Up to 4 bytes
     - The value of the Lean model ``Shirudo.Number``, or ``-ERANGE``
       exactly where the model refuses
   * - ``string-utf8``
     - ``utf8_width()``
     - Every input
     - Equals Table 3-7 of the Unicode Standard, the well-formed byte
       sequences, row by row
   * - ``string-sanitize``
     - ``text_sanitize()``
     - Lengths 0 to 6, with and without line breaks
     - Leaves well-formed UTF-8 without a C0, DEL or C1 control but a
       kept line break; changes a byte only to ``?``; keeps every
       printable character
   * - ``string-copy``
     - ``strscpy()``
     - Strings and buffers up to 8 bytes
     - Terminates what it writes; the whole string and its length, or
       what fits and ``-E2BIG``
   * - ``string-span``
     - ``span_to_str()``
     - Spans and buffers up to 6 bytes, apart and the span in the buffer
     - A string exactly when no byte of the span is a NUL and the bytes
       fit with a terminator, ``-EINVAL`` and ``-E2BIG`` otherwise; the
       string is the bytes, terminated behind them; nothing past the
       span read and nothing written on a refusal
   * - ``string-suffix``
     - ``name_has_suffix()``
     - Names up to 6 bytes, suffixes up to 3
     - True exactly when the name's last bytes are the suffix and at
       least one byte comes before them
   * - ``string-prefix``
     - ``str_after_prefix()``, ``str_has_prefix_nocase()``,
       ``str_skip_prefix_nocase()``, ``span_equals_str()``,
       ``span_has_prefix_nocase()``
     - Strings and spans up to 5 bytes, prefixes up to 3
     - The rest of the string exactly where it starts with the prefix,
       in either case for the ``_nocase`` forms, and the empty prefix
       starts every string; a span equals a string of its length and
       bytes alone; nothing past a span's length is read
   * - ``string-tokens``
     - ``token_next()``, ``for_each_token()``
     - Lengths 0 to 4, one or two delimiters, every cursor
     - A token lies inside the span, holds no delimiter and has one or
       the span's end on either side; the cursor ends past it and past
       one delimiter; a walk gives the bytes that are no delimiter in
       order, each once, and no empty token
   * - ``string-search``
     - ``span_until()``, ``span_find()``, ``str_contains()``,
       ``str_equals_nocase()``
     - Lengths 0 to 5, one or two bytes in the set, needles up to 2
       bytes, strings up to 3
     - The length of what comes before the first byte of the set; the
       first place the needle lies in the span, or ``NULL`` exactly
       where it lies nowhere; nothing past the span is read; a string
       holds a needle where it lies in it; two strings are equal in
       either case exactly with the same letters and length
   * - ``hex``
     - ``hex_encode()``, ``hex_alloc()``, ``hex_decode()``,
       ``hex_decode_max()``
     - Up to 4 bytes, strings up to 9 characters
     - Lowercase hex that decodes back to the input, in the caller's
       buffer or one ``hex_alloc()`` allocates; a decode takes
       exactly ``2 * n`` hex digits of either case and yields their
       value, and ``hex_decode_max()`` any even count up to ``2 * cap``,
       reading no further than the digit after them
   * - ``hex-model``
     - ``hex_encode()``, ``hex_decode()``, ``hex_decode_max()``
     - Up to 8 bytes, strings up to 17 characters, counts and capacities
       up to 8 and past ``SIZE_MAX / 2``
     - The result and the bytes of the Lean model ``Shirudo.Hex``
   * - ``hex-digest``
     - ``sha256_digest_decode()``
     - Strings of 0, 6 to 8 and 70 to 72 bytes
     - Accepted exactly as ``sha256:`` and 64 hex digits of either case,
       into their value; a null pointer refused
   * - ``paths-bpffs-name``
     - ``upatch_bpffs_name()``, ``upatch_name_from_bpffs()``
     - Names up to 4 bytes, pin names up to 8
     - A name without ``~`` maps to a pin name without a dot and back to
       itself; a pin name without a dot that decodes is the encoding of
       what it decodes to
   * - ``paths-join``
     - ``path_join()``, ``format_key_path()``
     - Parts up to 2 bytes, every buffer size up to 7
     - The parts with one slash between them, terminated, exactly when
       they fit, else ``-ENAMETOOLONG``, with an empty string from
       ``path_join()``; no second slash after a key directory that ends
       in one, and ``-EINVAL`` without a buffer, a directory or a file
   * - ``paths-pin``
     - ``upatch_pin_path()``
     - A name and up to two parts of a byte each or none, buffers of 0,
       1 and 28 to 35 bytes
     - The pin directory, the pin name and each part after one slash,
       terminated, exactly when they fit, else ``-ENAMETOOLONG`` with an
       empty string
   * - ``paths-bpffs-name-model``
     - ``upatch_bpffs_name()``, ``upatch_name_from_bpffs()``
     - Up to 8 bytes, buffers up to 18
     - The result and the string of the Lean model ``Shirudo.PinName``
   * - ``bpm-state-entry``
     - ``on_state_entry()`` of :src:`util/bpm_state.c`
     - Any entry with a name and version of up to 6 bytes, into an empty
       or a full table; a path buffer of 40 bytes, which some of those
       paths outgrow, in place of ``PATH_MAX``, which none does
     - Kept exactly when name, version and source are valid, the path is
       ``BPM_PACKAGES_DIR/<name>/<version>`` and the table has room; kept
       as read, with the next read into a cleared entry; a refusal not
       counted, ``-E2BIG`` from a full table
   * - ``bpm-state-emit``
     - ``bpm_state_emit()`` with the writer of :src:`util/json.h`
     - None, one or both of two fixed entries, into buffers of 0 bytes
       and of each document's size with and without its NUL
     - 0 exactly when the document fits with its NUL, then the state
       document byte for byte and its length; nothing written past the
       buffer, nor to the length on ``-E2BIG``
   * - ``bpm-tree-manifest``
     - ``bpm_tree_manifest()``, ``tree_manifest_canonical()``, against
       ``bpm_oci_parse_manifest()``
     - Payload and signature layers of fixed digests and sizes of 0 and
       0, 1 and 4096, and 2\ :sup:`63` - 1 and 1; the SHA-256 of the
       empty config a stub
     - The manifest bpm tree append writes reads back as its two
       layers, and a node takes it as their canonical form; the layers
       swapped, or two payloads in the publisher's own form, refused
   * - ``bpm-tree-signers``
     - ``tree_source_open()``, ``tree_fetch_checked()``,
       ``tree_source_clear()``
     - Active or inactive image config; every signing-set count through
       capacity, every unvouched count through the set size, and parse,
       allocation, load, check and fetch failures
     - An active image fetch receives the same set whose load and check
       succeeded, only when it is nonempty and fully vouched; preflight
       failures refuse the fetch and every allocated set is released
   * - ``bpm-tree-overlap-model``
     - ``tree_selectors_disjoint()``, ``selector_covers()`` and the list,
       prefix and pair checks under them
     - Every two selectors of up to 2 entries a list and a map and 2
       values a pair, strings up to 2 bytes
     - The decisions of the Lean model ``Shirudo.TreeOverlap``, which
       proves them sound for what a node matches
   * - ``bpm-tree-overlap-live``
     - ``tree_add_live()``, ``tree_add_withdrawn()``
     - Publications of up to 3 operations, at every index; an ``op`` of
       up to 7 bytes, an id of up to 2, selectors of one architecture or
       none
     - ``addLive`` of the Lean model ``Shirudo.TreeOverlap``: live until
       a later operation is a delete of the same upatch whose selector
       covers its own
   * - ``bpm-tree-state-match``
     - ``tree_selector_matches()`` with ``read_config_stream()`` and the
       two readers that call it
     - Selectors of up to 2 release prefixes, build IDs and
       architectures against any release, machine and build ID, and of
       up to 2 labels against five fixed label lines or labels that
       cannot be read; strings up to 2 bytes. The node's files are
       stubs, and its label table holds 4 entries rather than 64,
       which the 3 labels never fill. Not a selector that names a
       kernel option
     - 1 exactly where ``selectorMatches`` of the Lean model
       ``Shirudo.TreeOverlap`` holds, 0 where not, an error only for
       labels it could not read; the labels closed and their line
       released
   * - ``bpm-tree-state-options``
     - ``selector_hash_build()``, ``selector_hash_find()``
     - Selectors of up to 2 kernel options, keys up to 2 bytes, a key
       twice among them
     - A key is found at the first pair that has it, where the config's
       value for it is kept, and no other key
   * - ``bpm-tree-state-pairs``
     - ``kv_add()``, ``kv_value()``, ``selector_values_match()``,
       ``hex32_valid()``
     - A key or a value of 0 to 2, 255 and 256 bytes into 0 to 2 pairs;
       up to 2 pairs and values of strings up to 2 bytes; digests up to
       65 bytes
     - A pair is added only below its limit and when both strings fit,
       whole, and a refusal counts nothing; ``kvValue`` and ``listHolds``
       of the Lean model ``Shirudo.TreeOverlap``; exactly 64 hex digits
   * - ``bpm-tree-state-pending``
     - ``tree_pending_parse()``, ``tree_pending_write()``
     - Any record ``json_parse()`` hands over and every operation
       ``tree_operation_validate()`` takes, ids up to 8 bytes; the
       emitter, the directory or the write failing. ``util/json.h`` is a
       stub that passes keys and values
     - Takes exactly a whole record of schema 1 with a positive seq, a
       upatch name and a sha256 digest; writes schema 1 and the
       operation's seq, id and digest once, which reads back as the
       operation's
   * - ``bpm-tree-state-replay``
     - ``tree_event_replay()``
     - Tree eventlogs of 0 to 3 lines of any records; the read or the
       hash failing. The JSON of a line, ``util/hex.c`` and SHA-256 are
       stubs
     - ``replayFrom`` of the Lean model ``Shirudo.TreeSync``: the root
       exactly when each line has its fields, a sequence number above
       the one before and the hash of the root before and its digest as
       its root; a refusal writes nothing and reads no further line
   * - ``bpm-tree-state-replay-lines``
     - ``tree_event_replay()`` with ``lines_len()``
     - Tree eventlogs of 0 to 4 and 6 bytes, any bytes, whose lines hold
       records that replay but for one at most
     - Each whole line read once and in order, nothing of a last line
       without its newline; a log with a NUL refused unread; the log
       released once
   * - ``bpm-tar-writer``
     - ``tar_entry()``, ``tar_octal()``, ``tar_write()`` of
       :src:`tools/shirudo-build/bpm-build.c`, against
       ``bpm_tar_header_ok()`` and ``bpm_tar_octal()``
     - Names of 1, 99 and 100 bytes, every size and mode, after members
       of every total up to 256 MiB, a file or a directory without
       content; the checksum for names that end in 16 free bytes; every
       value into a field of 8 and 12 bytes; ``gzwrite()`` a stub that
       takes every write
     - Refused before a byte is written or counted from 100 bytes of name
       on, and with ``EFBIG`` when the member takes the archive past the
       256 MiB the extractor unpacks; else counted, and one 512-byte
       header the reader takes, with its checksum, the name terminated
       in its field, no prefix, and name, size and type read back, uid,
       gid and mtime 0, the content padded to where the reader looks for
       the next header; a value wider than its field is refused
   * - ``bpm-beefile-targets``
     - ``build_target_ok()``, ``build_add_target()``, against
       ``bpm_archive_rel_ok()``
     - Targets of 0 to 8 bytes; up to 4 bytes into a table that holds one
       target
     - Takes exactly the paths the archive reader takes that have no
       final slash; a target joins the table once, none above or below
       one that is in it, and a refused one is not counted
   * - ``bpm-beefile-members``
     - ``build_entry_name()``, against ``package_member_name_ok()`` and
       ``bpm_archive_rel_ok()``
     - Targets of 0 to 6 bytes below a directory of 2, every buffer size
     - Refused exactly when it does not fit, with nothing written; else
       the directory, a slash and the target, terminated; a target bpm
       build takes is the member the reader finds, and the directory's
       own entry a path it takes
   * - ``bpm-beefile-names``
     - ``build_name_ok()``, against ``bpm_package_name_ok()`` and
       ``bpm_name_ok()``
     - Up to 129 bytes, past the 128-byte limit
     - Takes exactly the names the target takes as a package's, each one
       the repository index takes
   * - ``bpm-beefile-version``
     - ``build_version_ok()``, against ``bpm_version_ok()`` and
       ``bpm_archive_rel_ok()``
     - Versions of 5 to 9 bytes, behind a name of 1
     - A version bpm build takes is one the target takes, and
       ``<name>-<version>`` one component to the archive reader
   * - ``bpm-beefile-string``
     - ``build_parse_string()``, ``build_parse_value()``
     - Values of 0 to 12 bytes, every buffer size up to one byte more
     - Takes exactly a quoted string between blanks that fits, decoded as
       a reference decoder does, with ``\n``, ``\r``, ``\t``, ``\\`` and
       ``\"`` in a ``"..."`` string alone; nothing written past its
       buffer; a value read past is a string or starts as an array
   * - ``bpm-beefile-array``
     - ``build_parse_string_array()``
     - Values up to 10 bytes, a limit of 1 or 2 strings
     - One string or more up to the limit, each terminated, between
       brackets; no row past the limit written; a refused array is not
       counted
   * - ``bpm-beefile-array-long``
     - ``build_parse_string_array()``
     - One element of 1023 to 1025 bytes with its quotes, around the
       1024 its copy holds
     - Refused, as too long for the copy or for its row, and not
       counted
   * - ``bpm-beefile-fixes``
     - ``build_parse_fixes()``, ``bpm_fix_id_ok()``,
       ``bpm_strings_sort()``
     - Arrays of three IDs of 0 to 2 bytes each, of any bytes but a
       quote, a backslash and NUL; ``qsort()`` modelled as an insertion
       sort
     - Taken exactly when each ID is a nonempty run of
       ``[A-Za-z0-9._:-]`` and no two are the same, then kept whole and
       in ascending order; a second ``fixes`` in one table refused
   * - ``bpm-beefile-lines``
     - ``build_strip_comment()``, ``build_trim()``, ``build_bare_key()``
     - Lines of 0 to 10 bytes; a string, a ``#`` and 2 bytes behind it
     - A line is cut at a ``#`` or not at all, at the first one in a line
       without a quote, and a string the reader takes stays whole before
       its comment; trimming drops the blanks at both ends alone; a name
       is bare parts apart by single dots
   * - ``bpm-beefile-tables``
     - ``build_parse_spec()``, ``build_add_target()``
     - One table header after every count of its kind up to the limit;
       ``[upatches.tree]`` and the sub-tables without a upatch; four
       fixed targets
     - ``[[files]]``, ``[[upatches]]``, ``[[upatches.rodata]]`` and
       ``[[upatches.policy]]`` are counted below 128, 128, 16 and 64 and
       refused there; a table without its upatch is refused and counted
       nowhere; ``Beefile``, ``README.md``, ``cert.der`` and
       ``build-environment.json`` are no targets, nor is a path below
       one of them
   * - ``bpm-index-writer``
     - ``push_index()`` of :src:`tools/shirudo-build/bpm-publish.c`,
       against ``bpm_index_parse()``
     - One package of fixed short strings into a namespace without an
       index, of sizes 1, 2\ :sup:`63` - 1, 0 and -1; registry, clock
       and signer stubs
     - The document handed to the signer is one the target reads, with
       the one package and each field as pushed, but for a size of 0 or
       less, which the target refuses; one document signed, one manifest
       put
   * - ``bpm-index-append``
     - ``push_index()``, ``fetch_index()``, ``index_entry_compare()``,
       against ``bpm_index_parse()``
     - An index of one package as the registry serves it, and a push of
       another package, of the same version again, and of the same
       version with another digest; registry, signature check, clock and
       signer stubs
     - The index signed next is one the target reads, with the pushed
       package once and before the one listed, which is kept as it was;
       a version with other content is refused and nothing signed
   * - ``upatch-writer-header``
     - ``pack_header()`` of :src:`tools/shirudo-build/package.c`, read
       back by ``parse_header()``
     - Every value of every field and every name shorter than 256 bytes
     - The reader takes the header from a file of any size and reads back
       each value; the name is padded with zeros to its 256 bytes
   * - ``upatch-writer-sections``
     - ``compose_signed_data()``, read back by
       ``parse_signed_sections()``
     - Loader data of 0, 1, 7 and 8 bytes; a name with an unload digest,
       or with attach metadata of 1 to 8 bytes
     - The reader finds each section where the writer put it, at an
       8-byte boundary, with its bytes and length, the loader's data in
       front and zeros between; a count of 0 or above 8 and data past what
       a length field holds are refused, with nothing written
   * - ``upatch-writer-load``
     - The four sections of a load, through the same two functions
     - 1 byte of loader data, 3 of attach metadata, any 217 bytes as
       decoders and any 4188 as policy labels
     - Data of the length the format gives; the reader keeps the sections
       exactly when ``parse_decoders()`` and ``parse_policy_labels()``
       take those bytes, each at its offset behind its padding, with the
       maps the labels name
   * - ``upatch-writer-decoders``
     - ``parse_decoder_manifest()`` and ``build_decoder_blob()``, read
       back by ``parse_decoders()`` and ``upatch_decoder_view()``
     - 0 to 2 decoders with sources of 3 and 1 bytes; any manifest the
       writer takes for one decoder, names of 2 bytes for two
     - A section of the length the format gives, its reserved field zero;
       each view shows the manifest's values, its names padded with zeros
       and the source's bytes at its offset; no section without a decoder
       and none past what a length field holds
   * - ``upatch-writer-prog-specs``
     - ``build_prog_metadata()`` and the section parsers it calls, read
       back by ``prog_specs_parse()``; libbpf's object and the ELF
       resolver modelled
     - 22 objects of 0 to 2 programs from a table: the sections attached
       by BTF target, cgroup and netfilter, a test run, serializers of
       one and two maps, one with any 3 bytes behind its map's first,
       a map name at its limit, and the sections and programs the writer
       must refuse; any map count, any two map names and any output map,
       or none
     - A table of the length the format gives; the reader takes it and
       reads back each role, kind, target, offset and map; a refusal
       leaves nothing written and nothing allocated
   * - ``upatch-writer-kprobes``
     - The kprobe entries and the kprobe multi target block of
       ``build_prog_metadata()``
     - 23 objects from a table: a symbol of 1 to 127 bytes, alone or with
       a decimal or hexadecimal offset of up to 64 bits; a kprobe multi
       list of one name or two out of order, alone, beside another list
       or behind a uprobe; and the sections the writer must refuse, a
       symbol of 128 bytes, an offset behind ``kretprobe``, a glob, a name
       given twice and an empty name among them
     - The symbol and offset read back are the section's, and a list's
       names its own, sorted; a uprobe and a list in one object both read
       back; what the reader refuses, or would cut short, is refused.
       The mixed table's fixed structural fields are asserted and stored
       again as equal constants before the reader runs. The mixed table's
       growth request is asserted to match its exact base and final
       lengths before calling the original allocator with those extents.
       Its reader's allocation extents and two-byte, non-NUL path are
       asserted before equivalent fixed-size allocations and path copying
   * - ``upatch-writer-xdp``
     - The XDP entries of ``build_prog_metadata()``
     - ``xdp/`` with a first digit of 0 to 4, 8 or 9 and any 3 bytes
       behind it; one program, or two that start with 1 and 2 or both
       with 1
     - The device classes read back are the decimal mask of the section;
       a mask the reader refuses, and a class two programs select, are
       refused. The writer's fixed structural fields are asserted and
       stored again as equal constants before the reader runs; target
       block parser loops are unreachable
   * - ``upatch-writer-uprobes``
     - The uprobe target block of ``build_prog_metadata()``
     - 22 objects from a table: each uprobe section form at the path
       ``/x``, alone, before and behind another program, with any build
       ID of 1, 2, 3, 20 or 64 bytes and any one offset, or two rising
       ones for a glob; sections the writer must refuse; a resolver that
       fails
     - The reader takes the block and reads back each record's path,
       build ID and offsets for the program it names, a function's offset
       below 4 GiB; a refusal leaves nothing written and nothing allocated
   * - ``vouch-payload``
     - ``keys_vouch_payload()``, ``keys_verify_vouch()`` and
       ``keys_verify_signature()`` of :src:`util/keys.c`, the signature
       check a stub that takes the signed bytes from their signer alone
     - Certificates of 0 to 2 bytes, a set of two members, every
       allocation allowed to fail
     - What ``shirudo-build keys vouch`` signs is the prefix, its NUL and
       the certificate; the vouch admits that certificate under the
       member that signed it, and no other certificate of its length or
       longer; without memory nothing is written
   * - ``keepalive-emit``
     - ``keepalive_emit()``
     - Three fixed bodies, without a tree, with a tree and nothing else
       that may be null, and with every value, counters of 20, 2 and 1
       digits among them; the last of these with a last number of up to
       4 digits in a buffer that holds 0 to 3 of them; rooms of 0, 1 and
       240 bytes; a missing string, a bad hash and a byte that is not
       UTF-8
     - Each body one JSON object of 23 members by a byte-level
       recognizer, terminated in the buffer; another last number
       changes only its digits, without a leading zero, or is
       ``-ENOSPC`` exactly when it does not fit; ``-EINVAL`` and
       ``-EILSEQ`` for the bad inputs, and no body then
   * - ``keepalive-snapshot``
     - ``keepalive_snapshot()``, ``tree_state_same()``
     - Every answer of the state's reads, of any fields with strings of
       one byte, of pending.json's and of ``collect()``, over all
       ``KEEPALIVE_SNAPSHOT_TRIES`` tries
     - Tries up to the first whose two reads agree, the state handed
       back the first read of the last try; ``PENDING`` exactly when
       that try saw pending.json, ``UNSETTLED`` exactly when no try's
       reads agreed; ``collect()``'s error returned at once with no flag
       set
   * - ``keepalive-quote``
     - ``keepalive_quote_format()``, ``base64_encode()`` a stub that may
       fail
     - Every outcome of the three encodings, rooms of 1, 19, 20 and 21
       bytes
     - ``attest=``, ``sig=`` and ``ak=`` with the encodings of the
       attestation, its signature and the key, each in that order and
       into all its room, terminated; ``-E2BIG`` with nothing written
       when it does not fit; the first failed encoding's error
   * - ``otel-header-fields``
     - The OTLP header checks and ``percent_decode()``
     - Strings up to 32 bytes
     - Names exactly RFC 9110 tokens, values without controls but tab;
       each ``%XX`` decoded, a stray ``%`` and ``%00`` refused
   * - ``otel-retry-after``
     - ``otel_retry_after()``, ``response_header()``
     - Headers up to 32 bytes, dates modelled; lines of 139 to 142
       bytes whose value is 122 to 130 bytes once trimmed, around the
       128-byte buffer it is copied into
     - A delay is at most 30 seconds, the value itself when shorter; a
       header line read only within itself, its value copied only when
       it fits
   * - ``tpm-signer``
     - ``tpm_attest_signer()``, ``tpm_attest_verify()``
     - Every signer of up to 34 bytes and key name; attestations of up
       to 16 bytes and signatures of up to 72; SHA-256 recording its
       input and ECDSA as any verdict
     - The signer is the key exactly when it is ``0x000b`` and the
       SHA-256 of the endorsement hierarchy's handle and the key's name;
       a signature passes only on the digest of the whole attestation,
       an unparseable one is ``-EBADMSG`` and checks nothing, a rejection
       ``-EKEYREJECTED``
   * - ``attest-replay-model``
     - ``on_record()``
     - Eventlogs of 1 to 3 records: an init of any reset count, the load
       of a BPF upatch, the unload of a Java one, a tree operation or
       another type, each with or without a record word, a digest, fields
       that decode and a valid name; hex decoding and event digests as
       stubs, the record types and their tags as copies
     - Refuses exactly where ``step`` of ``Shirudo.AttestReplay`` does and
       keeps the records of the last init, their digests, which are
       derived, ``inits_epoch`` and the last init's reset count and digest
       as it does; a record without a digest is refused
   * - ``config-evidence-event``
     - ``on_event()``, ``append_event()`` of :src:`util/config_attest.c`
     - Every event the JSON parser can hand over, into a history of 0, 1,
       15, 16, 128, 4095 and 4096 events, allocations allowed to fail
     - Joins exactly when whole, with a positive sequence, a boot or
       update kind and a root of 64 hex digits, below 4096 events, as the
       values given; a refusal keeps the history as it was; room for
       more than 4096 events is never asked for
   * - ``config-evidence-parse``
     - ``config_evidence_parse()``, ``config_evidence_clear()``
     - Every value, or none, under each key of a config history of 0 to 2
       events, cut or malformed at any point; ``json_parse()`` a model of
       its contract, SHA-256 as any result
     - Takes exactly a history with every key, schema 1, a PCR from 0 to
       15 but 9 and 11 or the config NvPCR's index, 32-bit counts, 64 hex
       digits of initial value and one boot event then updates in
       sequence, as said, and names one out of order with
       ``EKEYREJECTED``; a refusal and evidence without a history return
       nothing, with nothing left allocated
   * - ``config-evidence-roundtrip``
     - ``config_evidence_emit()``, ``emit_hash()`` into
       ``config_evidence_parse()``
     - Every view of 0 to 2 events; the JSON writer a model that records
       each member under its key, ``json_parse()`` one that hands them to
       the schema
     - The parser returns every field the writer was given, exactly for a
       view that replays; a sequence past a ``__s64`` is refused with
       ``EOVERFLOW``; a view without a history writes nothing
   * - ``config-evidence-verify``
     - ``replay()``, ``config_evidence_verify()``,
       ``config_measure_event()``
     - Every view of 0 to 3 events, without events or past 4096 of them,
       every quote mask, TPM boot, PCR value, certified NvPCR value or
       none, and expectation; SHA-256 as any digest or failure
     - Passes exactly when the register is a PCR from 0 to 15 but 9 and 11
       that is quoted, or the config NvPCR, certified and with a history
       that starts at the digest of 64 zero bytes, and is the expected
       one, the reset count the quote's, the events one boot event then
       updates in sequence, the quoted or certified value the initial one
       extended by each event's digest in order, and the last root the
       expected one; a digest hashes the tag, the kind and the root; a
       root without its PCR is refused
   * - ``config-evidence-collect``
     - ``config_evidence_collect()``, ``collect_event()``
     - Every journal of 0 to 2 records and every active selection, the
       journal's reader a stub that may fail; SHA-256 as any result
     - Exports exactly the records of the selection's reset count, in order,
       when they are on its PCR from its initial value, one boot event
       then updates in sequence, and end at the selection; a refusal
       returns nothing, with nothing left allocated
   * - ``log-escape``
     - ``escape()`` of :src:`util/log.c`
     - Messages of 0 to 5 bytes, every buffer size
     - Terminated printable ASCII, every backslash a ``\\`` or three octal
       digits, decoding to the message or to a prefix cut between
       characters
   * - ``serializer-chunk``
     - ``serial_chunk_validate()``
     - Every chunk
     - Accepted exactly as the chunk asked for, by index, count, page and
       cursors, of this invocation and format, naming no more bytes than
       a chunk carries; ``-EINVAL`` without a chunk or for invocation 0
   * - ``similar-distance``
     - ``edit_distance()``
     - Two strings of 0 to 3 bytes each, caps 1 to 3
     - The Levenshtein distance by its definition when it is within the
       cap, and more than the cap when it is not
   * - ``similar-suggest``
     - ``suggest()``
     - A word of 0 to 2 bytes, up to two commands of 0 to 2 bytes each,
       every combination of the three lengths, capacities 0 to 2, with
       ``strlen()`` given the lengths
     - Commands of the table within the cap, each with its distance,
       nearest first, never more than the capacity, none nearer left out
   * - ``similar-resolve``
     - ``resolve()``
     - A word and up to three commands of 0 to 2 bytes, capacities 0 to 2
     - The first command that is the word, else the commands the word
       begins, else those that begin it, in table order, as many as the
       capacity takes and none written past it
   * - ``options-next``
     - ``opt_next()``, ``opt_u64()``
     - One call from any state a run reaches, on up to three arguments
       of 0 to 6 bytes, against a table with an option of each kind
     - Each call takes an argument, so a run ends; an argument or a
       value lies in an argument; a flag has no value; a value is there
       and not empty unless the option allows it; no option comes back
       twice unless it repeats; a number lies in its bounds
   * - ``options-long``
     - ``opt_unknown()`` through ``opt_next()``
     - One unknown option of 64 to 66 bytes, around the 65 its copy
       holds
     - Refused, and a name suggested for it only when it fits the copy
   * - ``options-table``
     - ``specs_valid()``, ``opt_list()`` through ``opt_next()``
     - Every table of up to two options built from names ``--a``,
       ``--b``, ``--a=``, ``--``, ``-a`` and none, a short name or none,
       every flag, a metavar or none, a summary or none, and a table
       past ``OPT_MAX``; ``--list-opts``, ``--list-cmds`` and ``-h``
     - A malformed table refused before any argument is read, a sound
       one read; each listing printed and the run done
   * - ``conditions-verdict``
     - ``status_verdict()``, ``status_reason()``
     - Every input
     - The first verdict of its order that applies; ``tampered`` exactly
       when a cause holds on a host that answered, whatever the other
       fields say; the reason of the first cause in the order of the
       reasons
   * - ``conditions-rows``
     - ``conditions()``, ``keyring_condition()``, ``conditions_print()``
     - Every input ``status`` can build: status codes of 0 or a negated
       errno, a replay result only with a register, pins counted or not
       checked; room for 0 to 8 rows; ``vsnprintf()`` modelled to keep
       its arguments
     - As many rows as there is room for, in the report's order; with
       room for all, each the first state of its row that applies, the
       worst first but for ``KeyringSealed``, formatted from that
       state's numbers and names; an ``ALERT`` only under ``tampered``,
       that of ``LsmAttached`` also under ``lsm-off``
   * - ``conditions-detail``
     - ``set_detail()``
     - Every text of up to 193 bytes; texts of 832 to 1024 bytes that
       start with a fixed 832
     - The whole text up to 191 bytes, else its first 188 and ``...``;
       ``?`` for a text of 1024 bytes
   * - ``keepalive-pack``
     - ``keepalive_mask()``, ``keepalive_cond()``
     - Masks of 0 to 9, 512 and 513 codes, every code and buffer size;
       0 to 7 conditions of every known type, one unknown, and every
       status. OpenSSL's encoder is a stub that keeps its input
     - A window past 512 or a code past two bits is ``-EINVAL``, a
       buffer too small ``-E2BIG``; else each code in its two bits, the
       first highest, the last byte padded with zeros. Each condition's
       pair at the place of its type name, from the first of that type,
       ``00`` for a missing one or an unknown status, none past seven
   * - ``sysinfo-image``
     - ``os_release_unquote()``, ``os_release_value()``,
       ``cmdline_image_root()``
     - Values and texts of 0 to 6 bytes; values of 255, 256 and 257
       bytes; command lines of a word, ``usrhash=`` and ``roothash=``,
       each there or not, with hashes of any 63, 64 or 65 bytes but
       blanks
     - A value taken exactly when one or more printable bytes remain
       after one pair of quotes and the escapes of double quotes, at
       most 255 of them; of a key's lines the last; the root
       ``roothash=`` names, else ``usrhash=``, in lowercase when it is
       64 hex digits, else none
   * - ``xdp-attrs``
     - ``attr_find()``, ``attr_string()``, ``attr_number()``,
       ``xdp_device_parse()`` of :src:`util/xdp.c`
     - Netlink replies of 0 to 12, 16, 20, 24, 28, 32 and 40 bytes
     - An attribute exactly in a run of whole attributes that names its
       type at most once, found where it lies; a string NUL-terminated
       within its room; a number only of its exact size; a device with
       an index, a name, terminated strings, and the bus and device of a
       devlink port
   * - ``kconfig-line``
     - ``kconfig_line()`` of :src:`util/kconfig.c`
     - Lines of 0 to 2, 10 and 21 to 23 bytes of any value, which reach
       an option set, one not set and every refusal
     - Nothing read or written outside the line; a name that is
       ``CONFIG_`` and more, in the line; a value in the line, or the
       ``n`` of an option not set; a comment sets an option only as one
       that is not set

Lean 4 proofs
-------------

Each proof holds for every input of the model; the last column says how
the model follows the C.

.. list-table::
   :header-rows: 1
   :widths: 22 30 26 22

   * - Model
     - Theorems
     - Assumptions
     - Follows the C
   * - ``Shirudo.Number``, ``parse_base()`` of :src:`util/string.c`
     - ``parse_exact``: for digit strings of every length, the value they
       spell, or ``-ERANGE`` exactly when it passes ``max``
     - ``max`` fits a ``__u64``
     - CBMC, ``string-number-model``, up to 4 bytes
   * - ``Shirudo.Chain``, the register of :src:`rust/src/util/chain.rs`
     - ``register_injective``, ``register_tagged_injective``: for an
       idealized hash, equal registers come from the same events, tagged
       the same, in the same order; ``register_injective_on``: the same
       with the hash injective only on the pairs the two sequences fold,
       which SHA-256 can be; ``register_eq_foldl``: the
       register folds the events in the order they came;
       ``history_ignores_outcomes``: a upatch tree's history root is the
       same on two nodes that processed operations of the same digests,
       whatever outcome each had; ``processAll_history``,
       ``historyRoot_append_one``: it takes one step per operation
     - The hash never yields the initial value and is injective on the
       (register, event) pairs: on every pair for ``register_injective``
       and ``register_tagged_injective``, which no hash onto 32 bytes
       is, so the two hold of an idealized hash only; on those folded for
       ``register_injective_on``. ``register_tagged_injective`` also
       takes the tagged encoding as injective, which ``Shirudo.Events``
       proves; none for the history root
     - Review; the history root's step is modeled by
       ``historyBytes`` of ``Shirudo.Events``.
   * - ``Shirudo.Events``, the event encodings of :src:`rust/src/util/chain.rs`
       and the history root's step of :src:`util/chain_history.c`
     - ``bytes_injective``: two admitted events hash the same bytes only
       when they are the same event, a Java load or unload never a BPF
       one; ``listing_injective``: the init event's listing spells one set,
       each member's type with it, while no name holds a newline;
       ``sorts_unique``: ``qsort()`` leaves a set of distinct names in one
       order; ``replay_injective_on``, ``replay_collision``: equal
       registers come from the same typed events in the same order, or
       the strings hashed hold a SHA-256 collision or a string that
       hashes to zero; ``verify_sound``: whatever extended the register
       the TPM certified, the values it folded in were the digests of
       the events ``attest verify`` expects, in order, or the strings the
       two folds hash hold such a collision; ``verify_events``,
       ``verify_history``: those digests name the events; ``upatch_cut``,
       ``listing_newline``, ``sorts_tie``: where the domain ends
     - SHA-256 maps no two different strings the histories hash to one
       digest and none to 32 zero bytes, for ``verify_sound`` only the
       64-byte strings of the folds; names ``upatch_name_valid()``
       accepts, and for a load or an unload ``attest predict`` expects
       any name of 1 to 256 bytes; sequence numbers of a ``__s64``
     - Review; the C harness for event encoding was removed with the
       C implementation
   * - ``Shirudo.Measured``, ``measured_event()`` of :src:`rust/src/util/measured.rs`
     - ``holds_iff``: ``measured_holds()`` finds a name and payload exactly
       when the last init, load or unload bearing on the name is its load
       with that payload; ``measuredSet_nodup``: each name once;
       ``measuredSet_init``: an init record starts the set over;
       ``holds_last_load``, ``not_holds_after_unload``
     - None
     - Review
   * - ``Shirudo.EventlogRecord``, ``walk_lines()`` and
       ``upatches_line()`` of :src:`rust/src/util/eventlog/` on the records
       :src:`builtin-upatch.c`, :src:`builtin-init.c`,
       :src:`builtin-keys.c` and :src:`builtin-bpm.c` write
     - ``read_upatch``, ``read_init``, ``read_key``, ``read_tree``: every
       record the writers give reads back as exactly the events
       ``Shirudo.Measured`` folds, whatever its other fields hold;
       ``load_from_fields``, ``unload_from_fields``, ``init_from_type``:
       from any line, a load or an unload comes only from that line's
       ``type`` and ``upatch`` member, or from an entry of an init
       record's ``set`` that names both its fields, each with a name and
       a payload ``upatch_member_valid()`` accepts, and an init event only
       from a ``type`` of ``init``
     - ``json_parse()`` hands over the members as the line holds them,
       its strings as ``Shirudo.JsonString`` proves them read; names
       ``upatch_name_valid()`` accepts and 64 hex digits from the
       writers; the limits on a key's, a string's and a line's length,
       on depth and on the number of keys, which only refuse more, are
       left out
     - Review; the ``eventlog`` unit suite reads a line whose set entry
       names no upatch
   * - ``Shirudo.AttestReplay``, ``on_record()``, ``verify_epoch()``,
       ``verify_replay()``, ``verify_derived()`` and the init check of
       ``verify_state()`` of :src:`rust/src/util/attest.rs`
     - ``select_sound``: when every check passes, the certified register
       value is the fold of the last init record and the records after
       it, that init carries the expected digest and the certified reset
       count, and every record after it names an event whose digest is
       its own; ``verify_history``: whatever extended the register, it
       was extended by the expected init event and then by exactly the
       events those records name, in order, or SHA-256 collides on the
       strings of the two folds; ``passes_witness``: the checks can pass
     - The register value and its certification as
       ``verify_register()`` checks them; the expected init event, which
       ``attest verify`` computes when given ``--cert``; SHA-256 as
       ``Shirudo.Events`` takes it for ``verify_history``
     - CBMC, ``attest-replay-model``, for ``on_record()`` up to three
       records; the checks after it by review
   * - ``Shirudo.SemVer``, ``semver::compare()`` of
       :src:`rust/src/util/bpm_package/`
     - ``compareStrings_refl``, ``compareStrings_swap``,
       ``compareStrings_trans``: a total order on strings of every
       length; ``compareStrings_eq_iff``, ``compareStrings_invalid``,
       ``compareStrings_valid``: equal exactly for the same version up to
       build metadata, and for strings that are not SemVer for the same
       bytes; ``numCmp_value`` and the other rules of SemVer 2.0.0
       precedence
     - None; numeric identifiers compare by value only without a leading
       zero, which ``semverParse_wellFormed`` shows the parser ensures
     - None since the port to Rust; the CBMC model went with
       ``util/bpm_package.c``
   * - ``Shirudo.PinName``, ``upatch_bpffs_name()`` and
       ``upatch_name_from_bpffs()`` of :src:`util/paths.h`
     - ``decode_encode``: a name without ``~`` decodes back from its
       encoding; ``dot_not_mem_encode``: an encoding holds no dot;
       ``encode_injective``: no two names without ``~`` share a pin;
       ``encode_decode``, ``tilde_not_mem_decode``: a pin name without a
       dot that decodes is the encoding of a name without ``~``;
       ``bpffsName_ok``, ``nameFromBpffs_ok``, ``pin_round_trip``: the
       same through the buffers, ``-ENAMETOOLONG`` exactly where the C
       refuses
     - A C string is shorter than 2^63 bytes
     - CBMC, ``paths-bpffs-name-model``, up to 8 bytes
   * - ``Shirudo.ArchivePath``, ``archive_rel_ok()``,
       ``package_member_name_ok()`` and the member checks of
       ``extract()`` of :src:`rust/src/util/bpm_package/`
     - ``relOk_iff``, ``relOk_plain``: the check takes exactly the relative
       paths of plain components, with or without a final ``/``;
       ``relOk_contained``: every name it takes, resolved below any
       directory, leads strictly below it, as does each directory on the
       way; ``memberNameOk_iff``: a member matches only as one plain
       component, ``/`` and the member; ``extract_contained``: every
       member extracted is a regular file or a directory strictly below
       ``dest``, or ``dest`` itself
     - Resolution as the kernel walks a path, ``.`` staying, ``..`` going
       up and an empty component refused; the extraction's limits on
       count, size and path length are left out
     - Review; the CBMC model of the two checks went with
       ``util/bpm_package.c`` in the port to Rust
   * - ``Shirudo.Hex``, :src:`util/hex.c`
     - ``decode_encode``, ``length_encode``, ``encode_lower``: an encoding
       is lowercase hex twice its length that decodes back;
       ``decode_spec``: ``hex_decode()`` takes exactly ``2 * n`` hex
       digits of either case, and its bytes encode back to them in
       lowercase; ``decodeMax_spec``: ``hex_decode_max()`` takes exactly
       the even runs of at most ``2 * cap``; ``encode_injective``
     - A string is shorter than ``SIZE_MAX``
     - CBMC, ``hex-model``, up to 8 bytes and 17 digits
   * - ``Shirudo.JsonString``, the strict ``put_string()`` that
       ``json_str()`` calls and ``Cursor::string()`` of
       :src:`rust/src/util/json/`
     - ``read_write``: the reader returns exactly every string the writer
       takes and stops at its closing quote; ``write_isSome``: the writer
       takes exactly well-formed UTF-8 without NUL; ``write_string``: it
       writes one ECMA-404 string in well-formed UTF-8, with no control
       byte and no ``"`` or ``\`` outside an escape; ``readString_wf``:
       whatever the reader returns, from any input, is well-formed UTF-8
       without NUL
     - The emitter has room; for ``read_write``, the string fits
       ``JSON_MAX_STRING_BYTES`` and the buffer; well-formed UTF-8 is
       Table 3-7, which the Rust core checks
     - None since the port to Rust; the CBMC models went with
       ``util/json.h``
   * - ``Shirudo.ConfigActivation``, the config activation of
       :src:`rust/src/util/config_update.rs` as ``image update``, ``image stage``,
       ``status`` and ``init`` drive it
     - ``consistent_or_refusing``, ``refusal_persists``: the PCR replays
       from the record with its config mounted, or every command but
       ``status`` and ``image status`` refuses, a pending or drifted state
       until the TPM boot changes; ``pending_until_reboot``,
       ``resume_keeps_pending``: on any TPM a pending activation stays
       pending through every resume and restart, until the reset count
       changes; ``extends_once``,
       ``extension_follows_pending``, ``interrupted_never_extends``: one
       extension per activation and TPM boot, after the pending record,
       none after an interruption; ``extension_follows_save``: on root's
       TPM, an extension only for the record its command saved, durable
       as pending; ``reboot_stale``, ``reboot_recovers``,
       ``boot_completion``: after a reboot commands refuse until ``init``
       records a boot event, which an uninterrupted ``init`` does for the
       root ``boot_target()`` takes, and from any journal ``init``
       completes only with the PCR holding exactly the selected config's
       boot event; ``staged_taken``, ``stage_then_reboot``: ``init`` takes
       a staged root only when the stage copies the completed record it
       starts from and is of an earlier TPM boot, and it does take one;
       ``mounted_selected``, ``consistent_mounted``: a command runs only
       with the config the record selects; ``configInUse_vouched``
       restates ``configInUse``, which follows ``current_config()`` and
       ``status_config()`` by review; ``journal_wellformed``,
       ``pcr_replay``, ``completion_by_complete``
     - Commands one at a time; atomic renames of ``state`` and
       ``next-boot``; a crash leaves a prefix of a line; only shirudo
       writes the config mount during a boot; only shirudo writes the
       journal, between boots too, which R14 says root can, for all but
       ``boot_completion`` and ``completion_by_complete``, which hold
       from any journal; PCRs reset only at a reboot, a TPM reset or a
       TPM Restart; PCRs compared as their lists of extensions, which
       ``pcr_value_eq_iff`` justifies for the idealized hash of
       ``register_injective`` and SHA-256 meets unless it collides among
       the values compared. The TPM boot is the reset count; the restart
       count, which only refuses more, is left out. All but
       ``journal_wellformed``, ``mounted_selected``, ``boot_completion``,
       ``completion_by_complete``, ``extension_follows_save`` and
       ``pending_until_reboot`` also take a calm TPM, whose reset count
       changes only between commands and never to a value it had, and
       which restarts without a reboot only by a resume between commands,
       which root breaks with a suspend, a TPM restart or ``TPM2_Clear``
       (R4 of :doc:`/security/threat-model`)
     - Review; the bounded C harness for these checks was removed when
       the journal moved to Rust
   * - ``Shirudo.UpatchLoad``, the load, unload and purge of
       :src:`builtin-upatch.c`, the gate of :src:`util/image_runtime.c` and
       the boot restore of :src:`builtin-init.c`
     - ``undo_pass_sound``: once a command's undo pass is done, every pin
       directory holds one link, of the payload its xattr names and this
       boot's records hold, and every archive file shirudo wrote is on
       record; ``loaded_once``: no name holds two links;
       ``recorded_runs``: every name the records hold is pinned with one
       link of that payload; ``commands_need_init``: with enforcement
       active, every command runs in a boot whose init record is on the
       log; ``init_restores_exactly``: an ``init`` whose every restore
       succeeds loads exactly the labeled archive files, of those the
       boot's revocations left, whose last record is a load of that
       payload, and the new boot's records hold exactly those;
       ``log_sublist_register``, ``register_length``,
       ``register_eq_log_iff``, ``replay_differs``: this boot's upatch
       records are a sublist of the register's upatch events, equal once
       the lock is free unless an append was lost, and a difference shows
       in the replay; dropping the lock, the undo pass, its refusal,
       the gate, the undo of a failed payload xattr, the lock across the
       purge or the restore's filter breaks the matching theorem
     - The lock excludes and a kill releases it; a kill keeps pins and
       files; pin directory removals, archive renames and appends are
       whole; a reboot clears pins and register and ``init`` runs as one
       step; no TPM Restart without a reboot, as hibernation is refused
       (A9 of :doc:`/security/threat-model`); root changes only unlabeled
       archive files and brings files back. For
       ``replay_differs`` the idealized hash of ``register_injective``;
       for the undo pass, which reads the set only when this boot's
       records fold to the register's value, those records taken as the
       register's events. Left out: the boot in which enforcement never
       came up, where ``image_enter()`` admits commands without an init
       record; the revocation purge ``init`` runs before the restore; a
       restore that fails, which is ``rebootFail``; key revocations and
       tree operations, which extend the same register
     - Review; the bounded C harness for the measured set was removed
       when that implementation moved to Rust
   * - ``Shirudo.TreeSync``, ``cmd_bpm_tree_sync()`` and
       ``tree_recover_pending()`` of :src:`builtin-bpm.c`
     - ``generation_mono``, ``lastSeq_mono``, ``log_grows``: between any two
       points of any history of syncs of signed publications, stops after
       any write and reboots, the generation, the cursor and the tree
       eventlog never go back; ``manifest_fixed``: at an equal generation
       only the recorded manifest; ``older_refused``,
       ``accepted_older_refused``: a publication older than one accepted
       writes nothing; ``log_increasing``, ``measured_increasing``: each
       operation applied at most once, in increasing order, in the tree
       eventlog and in this boot's records; ``recover_pending``,
       ``measured_kept``, ``recover_settles``: after a stop between
       ``pending.json`` and the commit, recovery appends the operation once,
       exactly when it was measured or appended, and otherwise leaves the
       cursor below it; nothing measured is lost; ``state_is_fold``,
       ``replay_not_bad``: the state is the fold of the tree eventlog but
       between an append and its commit; ``applied_signed``,
       ``applied_consistent``: an applied operation is one of a signed
       publication of the tree, and that of every one when the signer never
       gives a number two operations; ``outcomes_cover``,
       ``outcomes_fixed``, ``lastSeq_le_head``: the outcomes record has a
       line for every operation from 1 to the cursor, in order, no line
       at or below the cursor ever changes, and the cursor never passes
       the head of the recorded publication; ``recover_progress``,
       ``sync_progress``: given a checked publication that follows a
       reachable node and holds its pending operation when that is
       above the cursor, recovery refuses nothing and the sync runs to
       its end, recording the publication's head as the cursor. They
       cover a publication of any base, and a sync that walks only as a
       sync of each segment in turn; ``walk_same_ops``: the segments of a
       walk, each recorded before
       its operations, apply the operations of the tree taken as one
       publication, in its order, with the same ``pending.json``,
       register, tree eventlog and outcomes writes, and end at the same
       cursor and projection root
     - A sync that walks is taken as one sync per segment, which it is
       but for the state each segment but the last writes at its end, a
       pending record an earlier segment passed, which stays to the next
       sync rather than the next segment, and the cut a sync makes before
       a walk back that refuses; the base and prefix checks are left out
       of the model, as they only refuse more. A manifest digest names
       one publication; the hash is injective on every (root, digest)
       pair, an idealized hash, which no hash onto 32 bytes is, and
       never 64 zeros; only sync writes the tree files,
       each write whole, one sync at a time; the unlink of ``pending.json``
       succeeds; an extend and its eventlog record are one write. An
       outcome line holds whether the selector matched, not which of 1
       and 3, and no history root; the check that the record covers the
       cursor is a theorem, not a branch of the model
     - CBMC, all run in CI: ``bpm-tree-follows`` for
       ``tree_publication_follows()``; ``bpm-tree-sync-model`` and its
       two-operation variants and ``bpm-tree-sync-walk`` check
       ``cmd_bpm_tree_sync()``, its loop, recovery and a walk over one
       sealed segment against the C restatement of ``run``, ``recover``
       and ``loop``, writes and refusals alike;
       ``bpm-tree-recovery-model`` for pending recovery,
       ``bpm-tree-state-replay`` for ``tree_event_replay()``. The
       restatement, ``tree_parse()`` and the walk as one sync per
       segment by review
   * - ``Shirudo.TreeOverlap``, :src:`util/bpm_tree_overlap.c` against
       ``tree_selector_matches()`` of :src:`util/bpm_tree_state.c`
     - ``disjoint_sound``: no node matches two selectors that
       ``tree_selectors_disjoint()`` calls disjoint; ``covers_sound``: a
       selector that ``selector_covers()`` says covers another matches
       every node the other matches; ``addLive_false``: an add that
       ``tree_add_live()`` says is no longer live is followed by a delete
       of the same upatch that matches every node the add matches;
       ``prefixes_meet_iff``: two release prefixes take a common release
       exactly when one takes the other read as a release;
       ``disjoint_comm``, ``covers_refl``: the order of two selectors
       does not matter, and a selector covers itself
     - One node for both selectors: its release, machine, build ID,
       config values and labels are the same for the two matches, and
       ``/proc/config.gz`` and ``/boot/config-<release>`` give an option
       the same value; a match that returns an error is no answer
     - CBMC, ``bpm-tree-overlap-model`` and ``bpm-tree-overlap-live`` for
       the publisher's checks, ``bpm-tree-state-match``,
       ``bpm-tree-state-pairs`` and ``bpm-tree-state-options`` for the
       node's match, each on short selectors; the match of a kernel
       option against the config by review

Files without a proof
---------------------

A harness reads a source file by including it. Every file of
:src:`util/` and :src:`tools/shirudo-build/` that the repository tracks,
every ``builtin-*.c`` and :src:`shirudo.c` is read by a harness or
listed here with the reason,
and ``.github/scripts/check-docs.sh`` fails when a file is neither or
when a harness reads a file this list still names. A file a harness
reads is not proven whole: the tables above say which of its functions
a proof covers.

.. list-table::
   :header-rows: 1
   :widths: 46 54

   * - Files
     - Why no proof reads them
   * - :src:`util/harden.c`, :src:`util/identity.c`,
       :src:`util/image_cache.c`, :src:`util/image_config.c`,
       :src:`util/image_guards.c`, :src:`util/image_keys.c`,
       :src:`util/image_runtime.c`, :src:`util/initrd.c`,
       :src:`util/integrity.c`, :src:`util/java_agent.c`,
       :src:`util/kernel_prereq.c`, :src:`util/keyring.c`,
       :src:`util/preflight.c`, :src:`util/seal.c`,
       :src:`util/tamper.c`, :src:`util/upatch_maps.c`,
       :src:`util/upatch_pins.c`, :src:`util/upatch_resolve.c`,
       :src:`util/upatch_verify.c`
     - Mostly calls into the kernel, which CBMC has no body for: files,
       extended attributes, mounts, the device mapper, keyrings,
       ``bpf()``, netlink, ``/proc`` and the process's own limits
   * - :src:`util/crypto_openssl.c`, :src:`util/curl.c`,
       :src:`util/elf_target.c`, :src:`util/kernel_abi.c`,
       :src:`util/nv_writer.c`, :src:`util/sign.c`,
       :src:`util/tls_openssl.c`, :src:`util/tpm.c`,
       :src:`util/upatch_decode.c`
     - Mostly calls into a library a harness would have to model whole:
       OpenSSL, libcurl, libelf, the BTF reader of libbpf, tpm2-tss and
       LuaJIT
   * - :src:`util/format.c`, :src:`util/help.c`, :src:`util/report.c`,
       :src:`util/timefmt.c`, :src:`util/upatch_table.c`
     - Output for people: sizes, durations, help, the load report and
       the table of loaded upatches. ``proof.h`` models neither floating
       point conversions nor ``strftime()``, and the JSON they emit goes
       through the emitters the proofs cover
   * - :src:`util/loader.c`
     - Data only: the embedded BPF objects
   * - :src:`tools/shirudo-build/jar.c`
     - The builder's check of a jar the operator hands it, which reads
       the zip directory and has zlib inflate the manifest. The ``jar``
       unit cases run it on every truncation and every byte flip of a
       jar; no harness is written for it yet
   * - :src:`builtin-attest.c`, :src:`builtin-build.c`,
       :src:`builtin-config.c`, :src:`builtin-genkey.c`,
       :src:`builtin-image.c`, :src:`builtin-init.c`,
       :src:`builtin-keys.c`, :src:`builtin-status.c`,
       :src:`builtin-upatch.c`, :src:`builtin-version.c`,
       :src:`shirudo.c`, :src:`tools/shirudo-build/bpm-show.c`,
       :src:`tools/shirudo-build/compile.c`,
       :src:`tools/shirudo-build/image.c`,
       :src:`tools/shirudo-build/shirudo-build.c`,
       :src:`tools/shirudo-build/vmlinux.c`,
       :src:`tools/shirudo-build/vouch.c`
     - Commands: options, the order of calls into :src:`util/` and
       output. ``Shirudo.UpatchLoad`` models the protocols of ``init``,
       ``upatch load`` and ``upatch unload``, by review, and the tree
       sync harnesses read ``builtin-bpm.c``; no proof reads the other
       commands. ``vouch.c`` has OpenSSL sign the bytes
       ``keys_vouch_payload()`` gives it, which ``vouch-payload`` covers

Not covered yet
---------------

The fuzz targets in :doc:`test-coverage` cover these parsers; no proof
does: the JSON reader and writer of :src:`rust/src/util/json/`, the
OCI client of :src:`rust/src/util/bpm_oci/` and the package reader of
:src:`rust/src/util/bpm_package/` and the TPM wire module of
:src:`rust/src/util/tpm_wire/`, the eventlog of
:src:`rust/src/util/eventlog/` and site configuration in
:src:`rust/src/util/config.rs`, plus the kernel build ID and release readers in
:src:`rust/src/util/kernel_build_id.rs` and
:src:`rust/src/util/kernel_release.rs` and the registry source
and tree line parser in :src:`rust/src/util/bpm_source_config.rs`, plus the bootstrap file
and config root event in :src:`rust/src/util/image_bootstrap.rs` and
:src:`rust/src/util/config_measure.rs`, and config image parts in
:src:`rust/src/util/config_image.rs`, whose CBMC proofs went with the C
they proved when those modules moved to Rust; how ``json_parse()`` dispatches objects, arrays and maps to their
schemas, and the members and elements of a JSON document longer than
two bytes, the OTLP headers a configuration adds
and the collector's reply to an export, the registry references and URLs and the registry credentials
file, the lines a tree selector cuts a kernel configuration into and
the labels it reads,
the tree's ``state.json`` and its outcomes record, the evidence document
beyond its PCRs and its config
history, the config update record, the site configuration file, the
config image's settings and tree and the fields of a
``shirudo-quote-check`` row. Of the eventlog's lines, the Lean model
``Shirudo.EventlogRecord`` covers what the reader takes from the fields
``json_parse()`` returns, by review; the parse of a line itself, as the
replay and the walk of a boot read it, has the ``eventlog`` fuzz target
alone.
The ``.upatch`` reader, the TPM structures and the index and tree readers are covered part by part, as the table shows; what joins
those parts has no proof. So it is with the package state:
``bpm_state_parse()`` hands ``on_state_entry()`` to ``json_parse()``,
and neither that nor reading back what ``bpm_state_emit()`` writes has a
proof, as a string of any contents moves all that follows it in the
document, which costs CBMC more memory than it has. The ``bpm_state``
unit cases check both on fixed entries. Nor is the parse of a token server's answer proved as a whole.
The bpm_oci unit cases and the oci-http fuzz target read real answers. The zip directory walk of
``jar_premain_class()`` in :src:`tools/shirudo-build/jar.c` has neither
a fuzz target nor a proof; its unit cases cut and flip a jar byte by
byte.

Of :src:`rust/src/util/io.rs` the proofs cover ``lines_len()``,
``read_text_line()`` and the append of a record. ``pread()`` never fails
in them, so the retry of ``last_line_end()`` after ``EINTR`` and its
refusal of a short read have no proof, nor have the readers of whole
files, which go to the kernel.

Of :src:`util/paths.c` and :src:`util/serializer.c` the proofs cover the
functions the table names. ``key_paths()``, which calls
``format_key_path()`` twice, ``keys_dir_resolve()`` and
``path_exists()``, and the serializer's lock and invocation number, which
go to the environment or the kernel, have none, and neither has the loop
of :src:`util/upatch_maps.c` that puts a page together from the chunks
``serial_chunk_validate()`` accepted. ``edit_distance()`` of
:src:`util/similar.c` is proven on strings of up to 3 bytes: at its
limit of 64 CBMC ends a run on the code as it is and none on the code
broken, so no proof of the limit is kept. ``options-next`` takes
``parse_u64()`` by the contract ``string-number`` proves and leaves out
the text of the usage messages, which only ``pr_err()`` reads, and
``opt_choice()``, a comparison of the value with a fixed table, to the
unit cases. Of :src:`util/sysinfo.c` the
proofs cover the image identity's parsers; reading the files they parse,
and the readers of ``/proc`` and the root file system, go to the kernel
and have none. Of :src:`rust/src/util/attest.rs` the proofs cover the functions
the table names, and ``Shirudo.AttestReplay`` models how
``attest_verify()`` selects and replays the eventlog's records. The
other steps of ``verify_document()``, ``evidence_parse()`` to
``verify_register()``, ``verify_anchor()`` and
``verify_expected_pcrs()``, ``check_signed()`` and
``pcr_values_digest()``, which the target checks its quote with too,
have none; the ``attest`` fuzz target runs them. Neither has
``quote_covers()``, with which the target checks its own quote,
``read_file_base64()`` and ``attest_challenge_read()``, which read the
challenge on the target, or ``attest_challenge_make()`` and
``cert_describes()``, which read a target's evidence to make one.
The config NvPCR certification check, ``verify_config_nvpcr()``, has no
proof.

Of the other files the proofs read in part, these functions have no
proof: ``dns_name_valid()`` of :src:`util/string.c` at its limits of a
63-byte label and a 253-byte name, as names that long take CBMC past
8 GB; ``tpm_public_marshal()`` and ``tpm_writer_public()`` of
:src:`rust/src/util/tpm_wire/`, the first of which the ``tpm-wire`` fuzz target
round-trips; ``upatch_rodata_symbol_range()`` of
:src:`rust/src/util/upatch_rodata.rs`, the range of ``.rodata`` the builder
rewrites; ``chain_init_event()`` of :src:`rust/src/util/chain.rs` on a set that is
not empty; ``upatch_name_signed()``, ``upatch_member_valid()`` and
``prog_specs_xdp_classes()`` of :src:`rust/src/util/upatch.rs`; the reading of
the eventlog behind boot restore in :src:`rust/src/util/measured.rs`,
``init_of_live()``, ``record_event()`` and the walk of
``verified_upatches()``, and that ``upatches_line()`` of
:src:`rust/src/util/eventlog/` hands init the names and payloads whose events
``record_event()`` hashes, as no fuzz target reaches them and a proof
over one record of the two readers, ``json_parse()`` modelled, runs out
of 8 GB; ``check_table()`` of
:src:`rust/src/util/dm_verity.rs`, which takes or refuses the kernel's table of a
config image's mapping, as CBMC 5.95 keeps the parameters of the
4096-byte reply symbolic even where a harness writes them and runs out
of 8 GB on a whole table, and no fuzz target reaches it either; the
refusal of
``measured_event()`` at the set's capacity of ``MEASURED_MAX``, 4096
entries, whose proof runs past 40 minutes; and of :src:`util/xdp.c` the loop of
``nl_exchange()`` over a reply's messages, the requests ``attr_put()``
builds and the device class and selection that ``xdp_device_class()``,
``veth_peer()`` and ``xdp_device_selected()`` decide.
Logic of the files without a proof that sits between their calls and
could be proven, as neither a proof nor a fuzz target reads it:
``split_describe()`` and the match of ``keyring_holds_exactly()`` in
:src:`util/keyring.c`; ``guard_map_check()`` of :src:`util/identity.c`
and the guard link and program checks of :src:`util/image_guards.c`; the
host match of
``tls_classical_host_allowed()`` in :src:`util/tls_openssl.c`;
``pin_index()`` and the pin set of :src:`util/upatch_pins.c`;
``rc_is()``, ``public_from_tss()`` and ``marshal_signature()`` of
:src:`util/tpm.c`; the slot arithmetic of ``shirudo.page_slots()`` and
``shirudo.fixed_records()`` and the decoders' memory cap in
:src:`util/upatch_decode.c`; and the label comparisons of
:src:`util/seal.c`.

Within the operator's package builder and publisher, the proofs cover the
tar header, the member names, the Beefile's values, lines, names, fixes
and table limits, and the index and the tree publication on fixed
documents.
The Beefile's keys, defaults and the checks behind its last line,
``build_validate()``, the rodata commands, ``build_archive()`` and what
it puts into ``build-environment.json``, a publication with operations,
the manifests but the tree publication's, and the generation and
sequence numbers ``bpm tree append`` counts up have no proof. A value of any length in a JSON
document moves every byte behind it, and a tree operation takes 13 KiB
in each of its copies: a proof over either runs for minutes. Of
:src:`tools/shirudo-build/bpm-publish.c` the proofs read
``push_index()`` and what it calls; ``cmd_bpm_tree_append()`` and the
steps it runs, ``tree_append_parse()`` to ``tree_append_free()``, have
none.

Within the ``.upatch`` reader, the proofs cover its parts but not their
composition: ``upatch_parse()`` and ``upatch_open_memory()`` join the
header, the signed sections, the decoders and the policy labels the
proofs cover one by one, and a proof of the whole file runs out of
memory. A program table of two or more programs, and with it the rule
that two XDP programs select disjoint device classes, which the
``upatch`` unit cases check, ``find_rodata_data()``
on loaders of other shapes, ``btf_dump_cost()``, the ``.rodata`` printers
and the libbpf calls behind ``btf_rodata_btf()`` have no proof.

Within the ``.upatch`` writer, the proofs cover the functions that lay
out bytes, each with the reader of its part, but not what joins them:
``finalize_object()`` and ``package_resign_symbols()`` compute the
header's offsets around the loader libbpf generates and the signature
OpenSSL makes, ``build_package_load()`` writes the header of the policy
labels between its libbpf calls, and ``collect_decoder_manifests()``
picks the manifests out of ``.rodata``. The attach metadata is proven
for the sections of a table, not for every section name: a kprobe or
uprobe target of any bytes makes the reader's side of the proof too
large, and no proof reaches a uprobe path at its 4095-byte limit.
