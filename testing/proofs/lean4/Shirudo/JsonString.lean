-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Shirudo.Hex

/-!
The JSON strings of rust/src/util/json/, ported step by step from
util/json.c. The strict writer, `put_string()` with `lossy` false as
`json_str()` calls it on the bytes of a C string, writes
a quote, then `"` and `\` escaped, `\n`, `\r` and `\t` by name, every
other control byte as `\u00XX`, the other ASCII bytes as they are and
each sequence of Table 3-7 of the Unicode Standard as it is, and a quote;
it refuses a NUL or a byte that starts no such sequence with `-EILSEQ`.
The reader, `Cursor::string()`, takes the escapes of one letter and
`\uXXXX`, joining a high and a low surrogate into one code point and
refusing `\u0000` and a lone surrogate, refuses an unescaped control
byte, and copies each sequence of Table 3-7; `emit_byte()` refuses with
`-E2BIG` past `JSON_MAX_STRING_BYTES` and with `-ENOSPC` when `dst` has no
room for a byte and the NUL.

The models follow the code step by step on byte lists, each byte its value.
Well-formed UTF-8 is Table 3-7, row by row as `rowWidth` states it,
which `utf8_width()` of rust/src/text.rs checks; `%04x` writes four lowercase
hex digits. The writer's emitter is assumed to have room: a `put()` that
fails sets the sticky error that fails the whole document.

For byte strings of every length: the strict writer takes exactly the
well-formed UTF-8 without NUL; what it writes is a quote, the characters
of a string of ECMA-404 with no control byte at all and no `"` or `\`
outside an escape, in well-formed UTF-8, and a quote; and the reader,
with room for it, returns exactly the bytes it was written from and stops
at the closing quote, whatever follows. Whatever the reader returns, from
any input, is well-formed UTF-8 without NUL.
CBMC checked the C writer and reader against the model until the module
moved to Rust; nothing ties the Rust port to it but the review that it
follows the same steps.
-/

namespace Shirudo.JsonString
open Shirudo.Hex (nibble table)

/-- `"`. -/
def quote : Nat := 0x22

/-- `\`. -/
def backslash : Nat := 0x5c

/-! ### Well-formed UTF-8 -/

/-- The first row of Table 3-7 of the Unicode Standard, on the first
bytes of `n`: U+0000..U+007F. -/
def Row1 (n b0 : Nat) : Prop := 1 ≤ n ∧ b0 ≤ 0x7f

/-- The second row: U+0080..U+07FF. -/
def Row2 (n b0 b1 : Nat) : Prop :=
  2 ≤ n ∧ 0xc2 ≤ b0 ∧ b0 ≤ 0xdf ∧ 0x80 ≤ b1 ∧ b1 ≤ 0xbf

/-- The next four rows: U+0800..U+FFFF without the surrogates. -/
def Row3 (n b0 b1 b2 : Nat) : Prop :=
  3 ≤ n ∧ 0x80 ≤ b2 ∧ b2 ≤ 0xbf ∧
    ((b0 = 0xe0 ∧ 0xa0 ≤ b1 ∧ b1 ≤ 0xbf) ∨
     (0xe1 ≤ b0 ∧ b0 ≤ 0xec ∧ 0x80 ≤ b1 ∧ b1 ≤ 0xbf) ∨
     (b0 = 0xed ∧ 0x80 ≤ b1 ∧ b1 ≤ 0x9f) ∨
     (0xee ≤ b0 ∧ b0 ≤ 0xef ∧ 0x80 ≤ b1 ∧ b1 ≤ 0xbf))

/-- The last three rows: U+10000..U+10FFFF. -/
def Row4 (n b0 b1 b2 b3 : Nat) : Prop :=
  4 ≤ n ∧ 0x80 ≤ b2 ∧ b2 ≤ 0xbf ∧ 0x80 ≤ b3 ∧ b3 ≤ 0xbf ∧
    ((b0 = 0xf0 ∧ 0x90 ≤ b1 ∧ b1 ≤ 0xbf) ∨
     (0xf1 ≤ b0 ∧ b0 ≤ 0xf3 ∧ 0x80 ≤ b1 ∧ b1 ≤ 0xbf) ∨
     (b0 = 0xf4 ∧ 0x80 ≤ b1 ∧ b1 ≤ 0x8f))

instance (n b0 : Nat) : Decidable (Row1 n b0) := by unfold Row1; infer_instance
instance (n b0 b1 : Nat) : Decidable (Row2 n b0 b1) := by unfold Row2; infer_instance
instance (n b0 b1 b2 : Nat) : Decidable (Row3 n b0 b1 b2) := by
  unfold Row3; infer_instance
instance (n b0 b1 b2 b3 : Nat) : Decidable (Row4 n b0 b1 b2 b3) := by
  unfold Row4; infer_instance

/-- Table 3-7 row by row on the first bytes `b0` to `b3` of `n`: the
length of the well-formed sequence they start, or 0. The CBMC proof that
`utf8_width()` of util/string.c computed it for every input went with the
C in the port to Rust. -/
def rowWidth (n b0 b1 b2 b3 : Nat) : Nat :=
  if Row1 n b0 then 1
  else if Row2 n b0 b1 then 2
  else if Row3 n b0 b1 b2 then 3
  else if Row4 n b0 b1 b2 b3 then 4
  else 0

/-- `utf8_width(s, n)` on the `n` bytes `s`. -/
def width (s : List Nat) : Nat :=
  rowWidth s.length (s.getD 0 0) (s.getD 1 0) (s.getD 2 0) (s.getD 3 0)

/-- Well-formed UTF-8: the bytes are a sequence of rows of Table 3-7. -/
def wellFormed (s : List Nat) : Bool :=
  match s with
  | [] => true
  | c :: rest =>
    match width (c :: rest) with
    | 0 => false
    | n + 1 => wellFormed (rest.drop n)
termination_by s.length
decreasing_by simp only [List.length_cons, List.length_drop]; omega

theorem rowWidth_cases (n b0 b1 b2 b3 : Nat) :
    (rowWidth n b0 b1 b2 b3 = 1 ∧ Row1 n b0) ∨
    (rowWidth n b0 b1 b2 b3 = 2 ∧ Row2 n b0 b1) ∨
    (rowWidth n b0 b1 b2 b3 = 3 ∧ Row3 n b0 b1 b2) ∨
    (rowWidth n b0 b1 b2 b3 = 4 ∧ Row4 n b0 b1 b2 b3) ∨
    rowWidth n b0 b1 b2 b3 = 0 := by
  unfold rowWidth
  by_cases h1 : Row1 n b0
  · simp [h1]
  by_cases h2 : Row2 n b0 b1
  · simp [h1, h2]
  by_cases h3 : Row3 n b0 b1 b2
  · simp [h1, h2, h3]
  by_cases h4 : Row4 n b0 b1 b2 b3
  · simp [h1, h2, h3, h4]
  · simp [h1, h2, h3, h4]

theorem rowWidth_of_row1 (n b0 b1 b2 b3 : Nat) (h : Row1 n b0) :
    rowWidth n b0 b1 b2 b3 = 1 := by
  unfold rowWidth
  rw [ite_eq_left h]

theorem rowWidth_of_row2 (n b0 b1 b2 b3 : Nat) (h : Row2 n b0 b1) :
    rowWidth n b0 b1 b2 b3 = 2 := by
  have h1 : ¬ Row1 n b0 := by unfold Row1 Row2 at *; omega
  simp [rowWidth, h1, h]

theorem rowWidth_of_row3 (n b0 b1 b2 b3 : Nat) (h : Row3 n b0 b1 b2) :
    rowWidth n b0 b1 b2 b3 = 3 := by
  have h1 : ¬ Row1 n b0 := by unfold Row1 Row3 at *; omega
  have h2 : ¬ Row2 n b0 b1 := by unfold Row2 Row3 at *; omega
  simp [rowWidth, h1, h2, h]

theorem rowWidth_of_row4 (n b0 b1 b2 b3 : Nat) (h : Row4 n b0 b1 b2 b3) :
    rowWidth n b0 b1 b2 b3 = 4 := by
  have h1 : ¬ Row1 n b0 := by unfold Row1 Row4 at *; omega
  have h2 : ¬ Row2 n b0 b1 := by unfold Row2 Row4 at *; omega
  have h3 : ¬ Row3 n b0 b1 b2 := by unfold Row3 Row4 at *; omega
  simp [rowWidth, h1, h2, h3, h]

theorem rowWidth_le (n b0 b1 b2 b3 : Nat) :
    rowWidth n b0 b1 b2 b3 ≤ n ∧ rowWidth n b0 b1 b2 b3 ≤ 4 := by
  rcases rowWidth_cases n b0 b1 b2 b3 with ⟨h, r⟩ | ⟨h, r⟩ | ⟨h, r⟩ | ⟨h, r⟩ | h
  · unfold Row1 at r; omega
  · unfold Row2 at r; omega
  · unfold Row3 at r; omega
  · unfold Row4 at r; omega
  · omega

theorem width_le (s : List Nat) : width s ≤ s.length ∧ width s ≤ 4 :=
  rowWidth_le _ _ _ _ _

theorem getD_take_append (s t : List Nat) (n i : Nat) (hi : i < n)
    (hn : n ≤ s.length) : (s.take n ++ t).getD i 0 = s.getD i 0 := by
  simp only [List.getD_eq_getElem?_getD]
  rw [List.getElem?_append_left (by simp; omega), List.getElem?_take_of_lt hi]

/-- A sequence that starts a row keeps it whatever follows. -/
theorem width_prefix (s t : List Nat) (h : 0 < width s) :
    width (s.take (width s) ++ t) = width s := by
  have hle := width_le s
  have hl : width s ≤ (s.take (width s) ++ t).length := by simp; omega
  have g : ∀ i, i < width s →
      (s.take (width s) ++ t).getD i 0 = s.getD i 0 := fun i hi =>
    getD_take_append s t _ i hi hle.1
  generalize hw : width s = w at h hle hl g
  unfold width at hw ⊢
  generalize (s.take w ++ t).length = L' at hl
  rcases rowWidth_cases s.length (s.getD 0 0) (s.getD 1 0) (s.getD 2 0)
    (s.getD 3 0) with ⟨e, r⟩ | ⟨e, r⟩ | ⟨e, r⟩ | ⟨e, r⟩ | e <;> rw [e] at hw <;>
    subst hw
  · apply rowWidth_of_row1
    rw [g 0 (by omega)]; unfold Row1 at r ⊢; omega
  · apply rowWidth_of_row2
    rw [g 0 (by omega), g 1 (by omega)]; unfold Row2 at r ⊢; omega
  · apply rowWidth_of_row3
    rw [g 0 (by omega), g 1 (by omega), g 2 (by omega)]; unfold Row3 at r ⊢; omega
  · apply rowWidth_of_row4
    rw [g 0 (by omega), g 1 (by omega), g 2 (by omega), g 3 (by omega)]
    unfold Row4 at r ⊢; omega
  · omega

/-- `utf8_width(p, min(left, 4))` is `utf8_width(p, left)`. -/
theorem width_take4 (s : List Nat) : width (s.take 4) = width s := by
  unfold width
  have g : ∀ i, i < 4 → (s.take 4).getD i 0 = s.getD i 0 := by
    intro i hi
    simp only [List.getD_eq_getElem?_getD, List.getElem?_take_of_lt hi]
  rw [g 0 (by omega), g 1 (by omega), g 2 (by omega), g 3 (by omega),
    List.length_take]
  have e1 : (1 ≤ min 4 s.length) = (1 ≤ s.length) := by
    apply propext; omega
  have e2 : (2 ≤ min 4 s.length) = (2 ≤ s.length) := by
    apply propext; omega
  have e3 : (3 ≤ min 4 s.length) = (3 ≤ s.length) := by
    apply propext; omega
  have e4 : (4 ≤ min 4 s.length) = (4 ≤ s.length) := by
    apply propext; omega
  simp only [rowWidth, Row1, Row2, Row3, Row4, e1, e2, e3, e4]

/-- An ASCII byte is a row of its own. -/
theorem width_ascii (c : Nat) (rest : List Nat) (h : c ≤ 0x7f) :
    width (c :: rest) = 1 := by
  apply rowWidth_of_row1
  unfold Row1; simp; omega

/-- A byte from 0x80 starts no row of one byte. -/
theorem width_high (c : Nat) (rest : List Nat) (h : 0x80 ≤ c) :
    width (c :: rest) ≠ 1 := by
  unfold width
  rcases rowWidth_cases (c :: rest).length ((c :: rest).getD 0 0)
    ((c :: rest).getD 1 0) ((c :: rest).getD 2 0) ((c :: rest).getD 3 0)
    with ⟨e, r⟩ | ⟨e, _⟩ | ⟨e, _⟩ | ⟨e, _⟩ | e <;> rw [e]
  · unfold Row1 at r; simp at r; omega
  all_goals omega

/-- Every byte of a row of more than one byte is from 0x80. -/
theorem width_high_bytes (s : List Nat) (h : 2 ≤ width s) :
    ∀ i, i < width s → 0x80 ≤ s.getD i 0 := by
  intro i hi
  unfold width at h hi
  rcases rowWidth_cases s.length (s.getD 0 0) (s.getD 1 0) (s.getD 2 0)
    (s.getD 3 0) with ⟨e, r⟩ | ⟨e, r⟩ | ⟨e, r⟩ | ⟨e, r⟩ | e <;> rw [e] at h hi
  · omega
  · unfold Row2 at r
    rcases (by omega : i = 0 ∨ i = 1) with e | e <;> subst e <;> omega
  · unfold Row3 at r
    rcases (by omega : i = 0 ∨ i = 1 ∨ i = 2) with e | e | e <;> subst e <;> omega
  · unfold Row4 at r
    rcases (by omega : i = 0 ∨ i = 1 ∨ i = 2 ∨ i = 3) with e | e | e | e <;>
      subst e <;> omega
  · omega

/-! ### The writer -/

/-- `\u%04x` of `c`: `\u` and its four lowercase hex digits. -/
def uEscape (c : Nat) : List Nat :=
  [backslash, 0x75, table.getD (c / 4096 % 16) 0, table.getD (c / 256 % 16) 0,
   table.getD (c / 16 % 16) 0, table.getD (c % 16) 0]

/-- The loop of `put_string_n(e, s, len, false)` over the bytes from `p`:
`"` and `\` escaped, `\n`, `\r` and `\t` by name, every other control
byte as `\u00XX`, the other ASCII bytes as they are, and a sequence of
Table 3-7 as it is; `none` is `-EILSEQ`, for a NUL or a byte that starts
no sequence of the `utf8_width(p, min(left, 4))` bytes. -/
def writeBody (s : List Nat) : Option (List Nat) :=
  match s with
  | [] => some []
  | c :: rest =>
    if c = quote ∨ c = backslash then (writeBody rest).map ([backslash, c] ++ ·)
    else if c = 0x0a then (writeBody rest).map ([backslash, 0x6e] ++ ·)
    else if c = 0x0d then (writeBody rest).map ([backslash, 0x72] ++ ·)
    else if c = 0x09 then (writeBody rest).map ([backslash, 0x74] ++ ·)
    else if c ≠ 0 ∧ c < 0x20 then (writeBody rest).map (uEscape c ++ ·)
    else if c ≠ 0 ∧ c < 0x80 then (writeBody rest).map (c :: ·)
    else
      match (if c ≠ 0 then width ((c :: rest).take 4) else 0) with
      | 0 => none
      | n + 1 => (writeBody (rest.drop n)).map ((c :: rest).take (n + 1) ++ ·)
termination_by s.length
decreasing_by all_goals simp only [List.length_cons, List.length_drop]; omega

/-- `put_string_n(e, s, len, false)`, as `json_str()` calls it with the
bytes of a C string: the body between two quotes. The emitter is assumed
to have room, as a failed `put()` fails the whole document. -/
def write (s : List Nat) : Option (List Nat) :=
  (writeBody s).map (fun b => quote :: b ++ [quote])

/-! ### The reader -/

/-- `-EINVAL`, `-E2BIG` and `-ENOSPC`. -/
inductive Err where
  | inval
  | tooBig
  | noSpace
  deriving DecidableEq, Repr

/-- Where `parse_string()` decodes to: `dst` given or `NULL`, its `cap`,
and `JSON_MAX_STRING_BYTES`. -/
structure Room where
  dst : Bool
  cap : Nat
  max : Nat

/-- `emit_byte()`: `-E2BIG` past `JSON_MAX_STRING_BYTES`, `-ENOSPC` when
`dst` leaves no room for the byte and the NUL. -/
def emit (r : Room) (out : List Nat) (b : Nat) : Except Err (List Nat) :=
  if out.length ≥ r.max then .error .tooBig
  else if r.dst = true ∧ out.length + 1 ≥ r.cap then .error .noSpace
  else .ok (out ++ [b])

/-- `emit_byte()` on each byte in turn, stopping at the first error. -/
def emitAll (r : Room) (out : List Nat) : List Nat → Except Err (List Nat)
  | [] => .ok out
  | b :: bs =>
    match emit r out b with
    | .error e => .error e
    | .ok out' => emitAll r out' bs

/-- `utf8_emit()`: a code point below U+10000 as one, two or three bytes. -/
def utf8Emit (r : Room) (out : List Nat) (cp : Nat) : Except Err (List Nat) :=
  if cp < 0x80 then emit r out cp
  else if cp < 0x800 then
    emitAll r out [0xc0 ||| (cp >>> 6), 0x80 ||| (cp &&& 0x3f)]
  else
    emitAll r out [0xe0 ||| (cp >>> 12), 0x80 ||| ((cp >>> 6) &&& 0x3f),
      0x80 ||| (cp &&& 0x3f)]

/-- The four bytes `parse_string()` writes for a code point from U+10000. -/
def utf8Four (cp : Nat) : List Nat :=
  [0xf0 ||| (cp >>> 18), 0x80 ||| ((cp >>> 12) &&& 0x3f),
   0x80 ||| ((cp >>> 6) &&& 0x3f), 0x80 ||| (cp &&& 0x3f)]

/-- What `parse_string()` writes for the code point of an escape. -/
def emitCp (r : Room) (out : List Nat) (cp : Nat) : Except Err (List Nat) :=
  if cp < 0x10000 then utf8Emit r out cp else emitAll r out (utf8Four cp)

/-- `hex4()`: `v = (v << 4) | n` over four hex digits; `none` is -1. -/
def hex4 (ds : List Nat) : Option Nat :=
  ds.foldl (fun v ch =>
    match v, nibble ch with
    | some v, some n => some ((v <<< 4) ||| n)
    | _, _ => none) (some 0)

/-- The byte each escape of one letter stands for. -/
def simpleEscape (e : Nat) : Option Nat :=
  if e = 0x22 then some 0x22
  else if e = 0x5c then some 0x5c
  else if e = 0x2f then some 0x2f
  else if e = 0x62 then some 0x08
  else if e = 0x66 then some 0x0c
  else if e = 0x6e then some 0x0a
  else if e = 0x72 then some 0x0d
  else if e = 0x74 then some 0x09
  else none

/-- The code point of the `\u` escape whose digits start `s`, joined
with the low surrogate escape that must follow a high one, and the bytes
after it: `hex4()` and its checks in `parse_string()`. `\u0000`, a
digit missing and a lone surrogate are `-EINVAL`. -/
def uCodePoint (s : List Nat) : Except Err (Nat × List Nat) :=
  match s with
  | a :: b :: c :: d :: rest =>
    match hex4 [a, b, c, d] with
    | none => .error .inval
    | some cp =>
      if cp = 0 then .error .inval
      else if 0xd800 ≤ cp ∧ cp ≤ 0xdbff then
        match rest with
        | p0 :: p1 :: a' :: b' :: c' :: d' :: rest' =>
          if p0 ≠ backslash ∨ p1 ≠ 0x75 then .error .inval
          else
            match hex4 [a', b', c', d'] with
            | none => .error .inval
            | some lo =>
              if 0xdc00 ≤ lo ∧ lo ≤ 0xdfff then
                .ok (0x10000 + ((cp - 0xd800) <<< 10) + (lo - 0xdc00), rest')
              else .error .inval
        | _ => .error .inval
      else if 0xdc00 ≤ cp ∧ cp ≤ 0xdfff then .error .inval
      else .ok (cp, rest)
  | _ => .error .inval

theorem uCodePoint_shorter (s rest : List Nat) (cp : Nat)
    (h : uCodePoint s = .ok (cp, rest)) : rest.length < s.length := by
  unfold uCodePoint at h
  split at h
  · split at h
    · contradiction
    · split at h
      · contradiction
      · split at h
        · split at h
          · split at h
            · contradiction
            · split at h
              · contradiction
              · split at h
                · simp only [Except.ok.injEq, Prod.mk.injEq] at h
                  rw [← h.2]; simp; omega
                · contradiction
          · contradiction
        · split at h
          · contradiction
          · simp only [Except.ok.injEq, Prod.mk.injEq] at h
            rw [← h.2]; simp; omega
  · contradiction

/-- The loop of `parse_string()` on the bytes from `c->p` to `c->end`,
with `out` decoded so far: the decoded bytes and the bytes after the
closing quote. An escape of one letter stands for its byte, a `\u`
escape for the UTF-8 of its code point; an unescaped control byte is
refused, and any other byte must start a sequence of Table 3-7, which is
copied. -/
def readLoop (r : Room) (out : List Nat) (s : List Nat) :
    Except Err (List Nat × List Nat) :=
  match s with
  | [] => .error .inval
  | ch :: rest =>
    if ch = quote then .ok (out, rest)
    else if ch = backslash then
      match rest with
      | [] => .error .inval
      | e :: rest' =>
        match simpleEscape e with
        | some v =>
          match emit r out v with
          | .error x => .error x
          | .ok out' => readLoop r out' rest'
        | none =>
          if e ≠ 0x75 then .error .inval
          else
            match _hu : uCodePoint rest' with
            | .error x => .error x
            | .ok (cp, rest'') =>
              match emitCp r out cp with
              | .error x => .error x
              | .ok out' => readLoop r out' rest''
    else if ch < 0x20 then .error .inval
    else
      match width (ch :: rest) with
      | 0 => .error .inval
      | n + 1 =>
        match emitAll r out ((ch :: rest).take (n + 1)) with
        | .error x => .error x
        | .ok out' => readLoop r out' (rest.drop n)
termination_by s.length
decreasing_by
  all_goals simp only [List.length_cons, List.length_drop]
  all_goals first
    | omega
    | (have := uCodePoint_shorter _ _ _ _hu; omega)

/-- `parse_string(c, dst, cap)` on the bytes from `c->p` to `c->end`: the
decoded bytes and the bytes after the string. -/
def readString (r : Room) (s : List Nat) : Except Err (List Nat × List Nat) :=
  match s with
  | [] => .error .inval
  | q :: rest =>
    if q ≠ quote then .error .inval
    else
      match readLoop r [] rest with
      | .error x => .error x
      | .ok (out, rest') =>
        if r.dst = true ∧ r.cap = 0 then .error .noSpace else .ok (out, rest')

/-! ### Steps of the reader -/

theorem option_map_some {α β : Type} (f : α → β) (x : Option α) (b : β) :
    x.map f = some b ↔ ∃ a, x = some a ∧ f a = b := by
  cases x <;> simp

theorem shl4_or (v n : Nat) (hn : n < 16) : (v <<< 4) ||| n = v * 16 + n := by
  rw [← Nat.shiftLeft_add_eq_or_of_lt (by simpa using hn), Nat.shiftLeft_eq]

/-- `hex4()` reads back the four digits `%04x` writes. -/
theorem hex4_digits (c : Nat) (hc : c < 0x10000) :
    hex4 [table.getD (c / 4096 % 16) 0, table.getD (c / 256 % 16) 0,
      table.getD (c / 16 % 16) 0, table.getD (c % 16) 0] = some c := by
  simp only [hex4, List.foldl_cons, List.foldl_nil,
    Hex.nibble_table _ (Nat.mod_lt _ (by omega : 16 > 0))]
  rw [shl4_or _ _ (Nat.mod_lt _ (by omega)), shl4_or _ _ (Nat.mod_lt _ (by omega)),
    shl4_or _ _ (Nat.mod_lt _ (by omega)), shl4_or _ _ (Nat.mod_lt _ (by omega))]
  congr 1
  omega

theorem emit_ok (r : Room) (out : List Nat) (b : Nat) (hm : out.length < r.max)
    (hc : r.dst = true → out.length + 1 < r.cap) :
    emit r out b = .ok (out ++ [b]) := by
  unfold emit
  rw [ite_eq_right (by omega), ite_eq_right (fun h => by have := hc h.1; omega)]

theorem emitAll_ok (r : Room) (out u : List Nat) (hm : out.length + u.length ≤ r.max)
    (hc : r.dst = true → out.length + u.length < r.cap) :
    emitAll r out u = .ok (out ++ u) := by
  induction u generalizing out with
  | nil => simp [emitAll]
  | cons b u ih =>
    simp only [List.length_cons] at hm hc
    simp only [emitAll]
    rw [emit_ok r out b (by omega) (fun h => by have := hc h; omega)]
    simp only
    rw [ih (out ++ [b]) (by simp; omega) (fun h => by have := hc h; simp; omega)]
    simp

theorem readLoop_quote (r : Room) (out more : List Nat) :
    readLoop r out (quote :: more) = .ok (out, more) := by
  rw [readLoop.eq_def]
  simp

theorem readLoop_escape (r : Room) (out more : List Nat) (e v : Nat)
    (h : simpleEscape e = some v) :
    readLoop r out (backslash :: e :: more) =
      match emit r out v with
      | .error x => .error x
      | .ok out' => readLoop r out' more := by
  rw [readLoop.eq_def]
  simp only [backslash, quote, h]
  rfl

theorem readLoop_u (r : Room) (out more rest : List Nat) (cp : Nat)
    (h : uCodePoint more = .ok (cp, rest)) :
    readLoop r out (backslash :: 0x75 :: more) =
      match emitCp r out cp with
      | .error x => .error x
      | .ok out' => readLoop r out' rest := by
  rw [readLoop.eq_def]
  simp only [backslash, quote]
  simp only [simpleEscape, Nat.reduceEqDiff, ite_false, ite_true, ne_eq,
    not_true_eq_false]
  split
  · next x hx => rw [h] at hx; contradiction
  · next cp' rest' hx =>
    rw [h] at hx
    simp only [Except.ok.injEq, Prod.mk.injEq] at hx
    rw [hx.1, hx.2]

theorem uCodePoint_bmp (a b c d : Nat) (rest : List Nat) (cp : Nat)
    (h : hex4 [a, b, c, d] = some cp) (h0 : cp ≠ 0)
    (hs : ¬ (0xd800 ≤ cp ∧ cp ≤ 0xdfff)) :
    uCodePoint (a :: b :: c :: d :: rest) = .ok (cp, rest) := by
  rw [uCodePoint, h]
  simp only
  rw [ite_eq_right h0, ite_eq_right (by omega), ite_eq_right (by omega)]

/-- A byte from U+0020 but `"` and `\` that starts a sequence of Table
3-7 is copied with the rest of the sequence. -/
theorem readLoop_raw (r : Room) (out u more : List Nat) (hu : u ≠ [])
    (h0 : 0x20 ≤ u.getD 0 0) (hq : u.getD 0 0 ≠ quote)
    (hb : u.getD 0 0 ≠ backslash) (hw : width (u ++ more) = u.length) :
    readLoop r out (u ++ more) =
      match emitAll r out u with
      | .error x => .error x
      | .ok out' => readLoop r out' more := by
  obtain ⟨ch, u', rfl⟩ : ∃ ch u', u = ch :: u' := by
    cases u with
    | nil => contradiction
    | cons ch u' => exact ⟨ch, u', rfl⟩
  simp only [List.getD_cons_zero] at h0 hq hb
  simp only [List.cons_append] at hw ⊢
  rw [readLoop.eq_def]
  simp only [hq, hb, ite_false]
  rw [ite_eq_right (by omega), hw]
  simp only [List.length_cons, List.take_succ_cons, List.take_left',
    List.drop_left']

/-! ### The round trip -/

theorem write_nil : writeBody [] = some [] := by
  rw [writeBody.eq_def]

theorem writeBody_cons (c : Nat) (rest : List Nat) :
    writeBody (c :: rest) =
      if c = quote ∨ c = backslash then (writeBody rest).map ([backslash, c] ++ ·)
      else if c = 0x0a then (writeBody rest).map ([backslash, 0x6e] ++ ·)
      else if c = 0x0d then (writeBody rest).map ([backslash, 0x72] ++ ·)
      else if c = 0x09 then (writeBody rest).map ([backslash, 0x74] ++ ·)
      else if c ≠ 0 ∧ c < 0x20 then (writeBody rest).map (uEscape c ++ ·)
      else if c ≠ 0 ∧ c < 0x80 then (writeBody rest).map (c :: ·)
      else
        match (if c ≠ 0 then width ((c :: rest).take 4) else 0) with
        | 0 => none
        | n + 1 => (writeBody (rest.drop n)).map ((c :: rest).take (n + 1) ++ ·) := by
  rw [writeBody.eq_def]

/-- An escape of one letter reads back as its byte. -/
theorem step_escape (r : Room) (out s b' more : List Nat) (e c : Nat)
    (hv : simpleEscape e = some c) (hm : out.length < r.max)
    (hc : r.dst = true → out.length + 1 < r.cap)
    (ih : readLoop r (out ++ [c]) (b' ++ more) = .ok (out ++ [c] ++ s, more.drop 1))
    : readLoop r out (([backslash, e] ++ b') ++ more) =
      .ok (out ++ c :: s, more.drop 1) := by
  simp only [List.cons_append, List.nil_append]
  rw [readLoop_escape r out _ e c hv, emit_ok r out c hm hc]
  simp only
  rw [ih]
  simp

/-- What `put_string_n()` writes, `parse_string()` reads back: the bytes
it was written from, and the bytes after the closing quote. -/
theorem loop_write (r : Room) (rest : List Nat) :
    ∀ (s b out : List Nat), writeBody s = some b →
      out.length + s.length ≤ r.max →
      (r.dst = true → out.length + s.length < r.cap) →
      readLoop r out (b ++ quote :: rest) = .ok (out ++ s, rest)
  | [], b, out, h, _, _ => by
    rw [write_nil, Option.some.injEq] at h
    subst h
    simp [readLoop_quote]
  | c :: s, b, out, h, hm, hc => by
    simp only [List.length_cons] at hm hc
    have room : out.length < r.max ∧ (r.dst = true → out.length + 1 < r.cap) :=
      ⟨by omega, fun h => by have := hc h; omega⟩
    have next : ∀ (v : Nat) (b' : List Nat), writeBody s = some b' →
        readLoop r (out ++ [v]) (b' ++ quote :: rest) =
          .ok (out ++ [v] ++ s, rest) := fun v b' hb' =>
      loop_write r rest s b' (out ++ [v]) hb' (by simp; omega)
        (fun h => by have := hc h; simp; omega)
    rw [writeBody_cons] at h
    by_cases h1 : c = quote ∨ c = backslash
    · rw [ite_eq_left h1] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      have hv : simpleEscape c = some c := by
        rcases h1 with e | e <;> subst e <;> rfl
      have := step_escape r out s b' (quote :: rest) c c hv room.1 room.2
        (by rw [next c b' hb']; rfl)
      simpa using this
    rw [ite_eq_right h1] at h
    by_cases h2 : c = 0x0a
    · rw [ite_eq_left h2] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      subst h2
      have := step_escape r out s b' (quote :: rest) 0x6e 0x0a rfl room.1 room.2
        (by rw [next 0x0a b' hb']; rfl)
      simpa using this
    rw [ite_eq_right h2] at h
    by_cases h3 : c = 0x0d
    · rw [ite_eq_left h3] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      subst h3
      have := step_escape r out s b' (quote :: rest) 0x72 0x0d rfl room.1 room.2
        (by rw [next 0x0d b' hb']; rfl)
      simpa using this
    rw [ite_eq_right h3] at h
    by_cases h4 : c = 0x09
    · rw [ite_eq_left h4] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      subst h4
      have := step_escape r out s b' (quote :: rest) 0x74 0x09 rfl room.1 room.2
        (by rw [next 0x09 b' hb']; rfl)
      simpa using this
    rw [ite_eq_right h4] at h
    by_cases h5 : c ≠ 0 ∧ c < 0x20
    · rw [ite_eq_left h5] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      have hcp := uCodePoint_bmp _ _ _ _ (b' ++ quote :: rest) c
        (hex4_digits c (by omega)) h5.1 (by omega)
      have he : emitCp r out c = .ok (out ++ [c]) := by
        unfold emitCp utf8Emit
        rw [ite_eq_left (by omega), ite_eq_left (by omega)]
        exact emit_ok r out c room.1 room.2
      simp only [uEscape, List.cons_append, List.nil_append]
      rw [readLoop_u r out _ _ c hcp, he]
      simp only
      rw [next c b' hb']
      simp
    rw [ite_eq_right h5] at h
    by_cases h6 : c ≠ 0 ∧ c < 0x80
    · rw [ite_eq_left h6] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      have hw : width ([c] ++ (b' ++ quote :: rest)) = [c].length :=
        width_ascii c _ (by omega)
      have := readLoop_raw r out [c] (b' ++ quote :: rest) (by simp)
        (by simp; omega) (by simp only [List.getD_cons_zero]; exact fun e => h1 (Or.inl e))
        (by simp only [List.getD_cons_zero]; exact fun e => h1 (Or.inr e)) hw
      rw [List.singleton_append] at this
      rw [List.cons_append, this, emitAll_ok r out [c] (by simp; omega)
        (fun h => by have := hc h; simp; omega)]
      simp only
      rw [next c b' hb']
      simp
    rw [ite_eq_right h6] at h
    have hc0 : c ≠ 0 := by
      intro e; subst e; simp at h
    simp only [ne_eq, hc0, not_false_eq_true, ite_true, width_take4] at h
    have hhigh : 0x80 ≤ c := by omega
    split at h
    · contradiction
    · next n hn =>
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      have hle := width_le (c :: s)
      have hn1 : n ≠ 0 := fun e => width_high c s hhigh (by rw [hn, e])
      have hlen : n ≤ s.length := by simp at hle; omega
      have hu := width_prefix (c :: s) (b' ++ quote :: rest) (by omega)
      rw [hn] at hu
      have := readLoop_raw r out ((c :: s).take (n + 1)) (b' ++ quote :: rest)
        (by simp) (by simp; omega) (by simp [quote]; omega)
        (by simp [backslash]; omega) (by rw [hu]; simp; omega)
      rw [List.append_assoc, this, emitAll_ok r out _ (by simp; omega)
        (fun h => by have := hc h; simp; omega)]
      simp only
      have hr : out ++ (c :: s).take (n + 1) ++ s.drop n = out ++ c :: s := by
        rw [List.append_assoc, List.take_succ_cons, List.cons_append,
          List.take_append_drop]
      rw [loop_write r rest (s.drop n) b' (out ++ (c :: s).take (n + 1)) hb'
        (by simp; omega) (fun h => by have := hc h; simp; omega), hr]
termination_by s => s.length
decreasing_by all_goals simp only [List.length_cons, List.length_drop]; omega

/-- For every byte string the strict writer takes, of every length, the
reader returns exactly it, and the bytes after the string, when it fits
`JSON_MAX_STRING_BYTES` and the buffer. -/
theorem read_write (r : Room) (s w rest : List Nat) (h : write s = some w)
    (hm : s.length ≤ r.max) (hc : r.dst = true → s.length < r.cap) :
    readString r (w ++ rest) = .ok (s, rest) := by
  obtain ⟨b, hb, rfl⟩ := (option_map_some _ _ _).1 h
  have hl := loop_write r rest s b [] hb (by simpa using hm) (by simpa using hc)
  simp only [List.cons_append, List.append_assoc]
  unfold readString
  simp only [ne_eq, not_true_eq_false, ite_false, List.nil_append] at hl ⊢
  rw [hl]
  simp only
  rw [ite_eq_right (fun h => by have := hc h.1; omega)]

/-! ### What the writer takes -/

theorem wellFormed_nil : wellFormed [] = true := by
  rw [wellFormed.eq_def]

theorem wellFormed_cons (c : Nat) (rest : List Nat) :
    wellFormed (c :: rest) =
      match width (c :: rest) with
      | 0 => false
      | n + 1 => wellFormed (rest.drop n) := by
  rw [wellFormed.eq_def]

theorem wellFormed_ascii (c : Nat) (rest : List Nat) (h : c ≤ 0x7f) :
    wellFormed (c :: rest) = wellFormed rest := by
  rw [wellFormed_cons, width_ascii c rest h]
  rfl

theorem mem_take_getD (l : List Nat) (k x : Nat) (h : x ∈ l.take k) :
    ∃ i, i < k ∧ i < l.length ∧ l.getD i 0 = x := by
  obtain ⟨i, hi, e⟩ := List.mem_iff_getElem.1 h
  simp only [List.length_take] at hi
  refine ⟨i, by omega, by omega, ?_⟩
  rw [List.getElem_take] at e
  simp [List.getD_eq_getElem?_getD, List.getElem?_eq_getElem (by omega : i < l.length), e]

/-- The bytes of a row of more than one byte hold no NUL. -/
theorem nul_not_mem_row (l : List Nat) (h : 2 ≤ width l) : 0 ∉ l.take (width l) := by
  intro m
  obtain ⟨i, hi, _, e⟩ := mem_take_getD l _ 0 m
  have := width_high_bytes l h i hi
  omega

theorem writeBody_small (c : Nat) (s : List Nat) (h0 : c ≠ 0) (h : c < 0x80) :
    (writeBody (c :: s)).isSome = (writeBody s).isSome := by
  rw [writeBody_cons]
  by_cases h1 : c = quote ∨ c = backslash
  · rw [ite_eq_left h1, Option.isSome_map]
  rw [ite_eq_right h1]
  by_cases h2 : c = 0x0a
  · rw [ite_eq_left h2, Option.isSome_map]
  rw [ite_eq_right h2]
  by_cases h3 : c = 0x0d
  · rw [ite_eq_left h3, Option.isSome_map]
  rw [ite_eq_right h3]
  by_cases h4 : c = 0x09
  · rw [ite_eq_left h4, Option.isSome_map]
  rw [ite_eq_right h4]
  by_cases h5 : c ≠ 0 ∧ c < 0x20
  · rw [ite_eq_left h5, Option.isSome_map]
  rw [ite_eq_right h5, ite_eq_left ⟨h0, h⟩, Option.isSome_map]

/-- Past the escapes and ASCII, the writer copies a row of Table 3-7, or
refuses a NUL or a byte that starts none. -/
theorem writeBody_high (c : Nat) (s : List Nat) (h : ¬ (c ≠ 0 ∧ c < 0x80)) :
    writeBody (c :: s) =
      match (if c ≠ 0 then width (c :: s) else 0) with
      | 0 => none
      | n + 1 => (writeBody (s.drop n)).map ((c :: s).take (n + 1) ++ ·) := by
  have hq : ¬ (c = quote ∨ c = backslash) := by unfold quote backslash; omega
  rw [writeBody_cons, ite_eq_right hq, ite_eq_right (by omega), ite_eq_right (by omega),
    ite_eq_right (by omega), ite_eq_right (by omega), ite_eq_right h, width_take4]

/-- The strict writer takes exactly the well-formed UTF-8 without NUL, and
refuses everything else with `-EILSEQ`. -/
theorem writeBody_isSome : ∀ s : List Nat,
    (writeBody s).isSome = true ↔ wellFormed s = true ∧ 0 ∉ s
  | [] => by simp [write_nil, wellFormed]
  | c :: s => by
    by_cases h0 : c = 0
    · subst h0
      rw [writeBody_high 0 s (by omega)]
      simp
    by_cases h : c < 0x80
    · rw [writeBody_small c s h0 h, writeBody_isSome s, wellFormed_ascii c s (by omega)]
      simp only [List.mem_cons, not_or]
      constructor
      · intro ⟨a, b⟩; exact ⟨a, fun e => h0 e.symm, b⟩
      · intro ⟨a, _, b⟩; exact ⟨a, b⟩
    · rw [writeBody_high c s (by omega), ite_eq_left h0, wellFormed_cons]
      split
      · simp
      · next n hn =>
        have hn1 : n ≠ 0 := fun e => width_high c s (by omega) (by rw [hn, e])
        rw [Option.isSome_map, writeBody_isSome (s.drop n)]
        have hsplit : c :: s = (c :: s).take (n + 1) ++ s.drop n := by
          rw [List.take_succ_cons, List.cons_append, List.take_append_drop]
        have hnul := nul_not_mem_row (c :: s) (by omega)
        rw [hn] at hnul
        constructor
        · intro ⟨a, b⟩
          refine ⟨a, ?_⟩
          rw [hsplit, List.mem_append]
          intro m; rcases m with m | m
          · exact hnul m
          · exact b m
        · intro ⟨a, b⟩
          refine ⟨a, fun m => b ?_⟩
          rw [hsplit, List.mem_append]; exact Or.inr m
termination_by s => s.length
decreasing_by all_goals simp only [List.length_cons, List.length_drop]; omega

/-- `put_string_n()` writes a string exactly when it is well-formed UTF-8
without NUL, and through `json_str()` a C string holds none. -/
theorem write_isSome (s : List Nat) :
    (write s).isSome = true ↔ wellFormed s = true ∧ 0 ∉ s := by
  rw [write, Option.isSome_map]
  exact writeBody_isSome s

/-! ### What the writer writes -/

/-- The characters of a string of ECMA-404, section 9, in UTF-8: a
sequence of Table 3-7 from U+0020 but `"` and `\`, an escape of one
letter, or `\u` and four hex digits. -/
inductive Chars : List Nat → Prop
  | nil : Chars []
  | char (u rest : List Nat) : u ≠ [] → width u = u.length →
      0x20 ≤ u.getD 0 0 → u.getD 0 0 ≠ quote → u.getD 0 0 ≠ backslash →
      Chars rest → Chars (u ++ rest)
  | escape (e : Nat) (rest : List Nat) :
      e ∈ [0x22, 0x5c, 0x2f, 0x62, 0x66, 0x6e, 0x72, 0x74] →
      Chars rest → Chars (backslash :: e :: rest)
  | unicode (a b c d : Nat) (rest : List Nat) :
      Hex.isHex a = true → Hex.isHex b = true → Hex.isHex c = true →
      Hex.isHex d = true → Chars rest →
      Chars (backslash :: 0x75 :: a :: b :: c :: d :: rest)

theorem isHex_table (v : Nat) (h : v < 16) : Hex.isHex (table.getD v 0) = true := by
  unfold Hex.isHex
  rw [Hex.nibble_table v h]
  rfl

theorem writeBody_chars : ∀ (s b : List Nat), writeBody s = some b → Chars b
  | [], b, h => by
    rw [write_nil, Option.some.injEq] at h
    subst h; exact Chars.nil
  | c :: s, b, h => by
    rw [writeBody_cons] at h
    by_cases h1 : c = quote ∨ c = backslash
    · rw [ite_eq_left h1] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      apply Chars.escape c b'
      · rcases h1 with e | e <;> subst e <;> simp [quote, backslash]
      · exact writeBody_chars s b' hb'
    rw [ite_eq_right h1] at h
    by_cases h2 : c = 0x0a
    · rw [ite_eq_left h2] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      exact Chars.escape 0x6e b' (by simp) (writeBody_chars s b' hb')
    rw [ite_eq_right h2] at h
    by_cases h3 : c = 0x0d
    · rw [ite_eq_left h3] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      exact Chars.escape 0x72 b' (by simp) (writeBody_chars s b' hb')
    rw [ite_eq_right h3] at h
    by_cases h4 : c = 0x09
    · rw [ite_eq_left h4] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      exact Chars.escape 0x74 b' (by simp) (writeBody_chars s b' hb')
    rw [ite_eq_right h4] at h
    by_cases h5 : c ≠ 0 ∧ c < 0x20
    · rw [ite_eq_left h5] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      exact Chars.unicode _ _ _ _ b' (isHex_table _ (Nat.mod_lt _ (by omega)))
        (isHex_table _ (Nat.mod_lt _ (by omega))) (isHex_table _ (Nat.mod_lt _ (by omega)))
        (isHex_table _ (Nat.mod_lt _ (by omega))) (writeBody_chars s b' hb')
    rw [ite_eq_right h5] at h
    by_cases h6 : c ≠ 0 ∧ c < 0x80
    · rw [ite_eq_left h6] at h
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      have := Chars.char [c] b' (by simp) (width_ascii c [] (by omega))
        (by simp; omega) (by simp only [List.getD_cons_zero]; exact fun e => h1 (Or.inl e))
        (by simp only [List.getD_cons_zero]; exact fun e => h1 (Or.inr e))
        (writeBody_chars s b' hb')
      simpa using this
    rw [ite_eq_right h6] at h
    have hc0 : c ≠ 0 := by
      intro e; subst e; simp at h
    rw [ite_eq_left hc0] at h
    split at h
    · contradiction
    · next n hn =>
      rw [width_take4] at hn
      obtain ⟨b', hb', rfl⟩ := (option_map_some _ _ _).1 h
      have hle := width_le (c :: s)
      rw [hn, List.length_cons] at hle
      have hu := width_prefix (c :: s) [] (by omega)
      rw [List.append_nil, hn] at hu
      have hl : ((c :: s).take (n + 1)).length = n + 1 := by
        rw [List.length_take, List.length_cons]; omega
      apply Chars.char _ b' (by simp) (by rw [hl]; exact hu) (by simp; omega)
        (by simp; unfold quote; omega) (by simp; unfold backslash; omega)
      exact writeBody_chars (s.drop n) b' hb'
termination_by s => s.length
decreasing_by all_goals simp only [List.length_cons, List.length_drop]; omega

/-- Every byte of the characters of a string is from 0x20: no control
byte, escaped or not. -/
theorem chars_no_control (b : List Nat) (h : Chars b) : ∀ x ∈ b, 0x20 ≤ x := by
  induction h with
  | nil => simp
  | char u rest hne hw h0 _ _ _ ih =>
    intro x hx
    rw [List.mem_append] at hx
    rcases hx with hx | hx
    · rw [← List.take_length (l := u)] at hx
      obtain ⟨i, hi, _, e⟩ := mem_take_getD u _ x hx
      subst e
      by_cases i0 : i = 0
      · subst i0; exact h0
      · have := width_high_bytes u (by omega) i (by omega)
        omega
    · exact ih x hx
  | escape e rest he _ ih =>
    intro x hx
    simp only [List.mem_cons] at hx
    rcases hx with hx | hx | hx
    · subst hx; simp [backslash]
    · subst hx; simp at he; omega
    · exact ih x hx
  | unicode a b c d rest ha hb hc hd _ ih =>
    have hex : ∀ y, Hex.isHex y = true → 0x20 ≤ y := by
      intro y hy
      unfold Hex.isHex Hex.nibble at hy
      split at hy
      · omega
      · split at hy
        · omega
        · split at hy
          · omega
          · simp at hy
    intro x hx
    simp only [List.mem_cons] at hx
    rcases hx with hx | hx | hx | hx | hx | hx | hx
    · subst hx; simp [backslash]
    · subst hx; omega
    · subst hx; exact hex _ ha
    · subst hx; exact hex _ hb
    · subst hx; exact hex _ hc
    · subst hx; exact hex _ hd
    · exact ih x hx

theorem isHex_ascii (y : Nat) (h : Hex.isHex y = true) : y ≤ 0x7f := by
  unfold Hex.isHex Hex.nibble at h
  split at h
  · omega
  · split at h
    · omega
    · split at h
      · omega
      · simp at h

/-- The characters of a string are well-formed UTF-8. -/
theorem chars_wellFormed (b : List Nat) (h : Chars b) : wellFormed b = true := by
  induction h with
  | nil => simp [wellFormed]
  | char u rest hne hw _ _ _ _ ih =>
    obtain ⟨ch, u', rfl⟩ : ∃ ch u', u = ch :: u' := by
      cases u with
      | nil => contradiction
      | cons ch u' => exact ⟨ch, u', rfl⟩
    have hp := width_prefix (ch :: u') rest (by rw [hw]; simp)
    rw [hw, List.take_length] at hp
    simp only [List.cons_append] at hp ⊢
    rw [wellFormed_cons, hp]
    simp only [List.length_cons]
    rw [List.drop_left]
    exact ih
  | escape e rest he _ ih =>
    rw [wellFormed_ascii _ _ (by simp [backslash]),
      wellFormed_ascii _ _ (by simp at he; omega)]
    exact ih
  | unicode a b c d rest ha hb hc hd _ ih =>
    rw [wellFormed_ascii _ _ (by simp [backslash]), wellFormed_ascii _ _ (by omega),
      wellFormed_ascii _ _ (isHex_ascii a ha), wellFormed_ascii _ _ (isHex_ascii b hb),
      wellFormed_ascii _ _ (isHex_ascii c hc), wellFormed_ascii _ _ (isHex_ascii d hd)]
    exact ih

/-- What `json_str()` writes is one string of ECMA-404 in well-formed
UTF-8: a quote, characters with no unescaped `"`, `\` or control byte,
and a quote. `read_write` adds that the reader ends it at the last quote. -/
theorem write_string (s w : List Nat) (h : write s = some w) :
    ∃ body, w = quote :: body ++ [quote] ∧ Chars body ∧
      (∀ x ∈ body, 0x20 ≤ x) ∧ wellFormed body = true := by
  obtain ⟨b, hb, rfl⟩ := (option_map_some _ _ _).1 h
  have hc := writeBody_chars s b hb
  exact ⟨b, rfl, hc, chars_no_control b hc, chars_wellFormed b hc⟩

/-! ### What the reader returns -/

theorem emit_eq (r : Room) (out out' : List Nat) (b : Nat)
    (h : emit r out b = .ok out') : out' = out ++ [b] := by
  unfold emit at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · simp only [Except.ok.injEq] at h; exact h.symm

theorem emitAll_eq (r : Room) (u : List Nat) :
    ∀ out out', emitAll r out u = .ok out' → out' = out ++ u := by
  induction u with
  | nil => intro out out' h; simp only [emitAll, Except.ok.injEq] at h; simp [h]
  | cons b u ih =>
    intro out out' h
    simp only [emitAll] at h
    split at h
    · contradiction
    · next o he =>
      rw [ih o out' h, emit_eq r out o b he]
      simp

/-- A row of Table 3-7 is read as itself. -/
theorem wellFormed_row (u rest : List Nat) (hne : u ≠ []) (hw : width u = u.length) :
    wellFormed (u ++ rest) = wellFormed rest := by
  obtain ⟨ch, u', rfl⟩ : ∃ ch u', u = ch :: u' := by
    cases u with
    | nil => contradiction
    | cons ch u' => exact ⟨ch, u', rfl⟩
  have hp := width_prefix (ch :: u') rest (by rw [hw]; simp)
  rw [hw, List.take_length] at hp
  simp only [List.cons_append] at hp ⊢
  rw [wellFormed_cons, hp]
  simp only [List.length_cons]
  rw [List.drop_left]

/-- Well-formed UTF-8 followed by well-formed UTF-8 is well-formed. -/
theorem wellFormed_append : ∀ (a b : List Nat), wellFormed a = true →
    wellFormed b = true → wellFormed (a ++ b) = true
  | [], b, _, hb => hb
  | c :: rest, b, ha, hb => by
    rw [wellFormed_cons] at ha
    split at ha
    · contradiction
    · next n hn =>
      have hle := width_le (c :: rest)
      rw [hn] at hle
      have hrow : width ((c :: rest).take (n + 1)) = ((c :: rest).take (n + 1)).length := by
        have := width_prefix (c :: rest) [] (by omega)
        rw [List.append_nil, hn] at this
        rw [this, List.length_take]; simp at hle ⊢; omega
      have hsplit : (c :: rest) ++ b = (c :: rest).take (n + 1) ++ (rest.drop n ++ b) := by
        rw [List.take_succ_cons, List.cons_append, List.cons_append, ← List.append_assoc,
          List.take_append_drop]
      rw [hsplit, wellFormed_row _ _ (by simp) hrow]
      exact wellFormed_append (rest.drop n) b ha hb
termination_by a => a.length
decreasing_by simp only [List.length_cons, List.length_drop]; omega

theorem or_low (k x : Nat) (hk : k = 0x80 ∨ k = 0xc0 ∨ k = 0xe0 ∨ k = 0xf0)
    (hx : x < 0x100 - k) (h64 : x < 64) : k ||| x = k + x := by
  have h80 : ∀ y, y < 64 → 0x80 ||| y = 0x80 + y := by decide
  have hc0 : ∀ y, y < 64 → 0xc0 ||| y = 0xc0 + y := by decide
  have he0 : ∀ y, y < 32 → 0xe0 ||| y = 0xe0 + y := by decide
  have hf0 : ∀ y, y < 16 → 0xf0 ||| y = 0xf0 + y := by decide
  rcases hk with e | e | e | e <;> subst e
  · exact h80 x h64
  · exact hc0 x (by omega)
  · exact he0 x (by omega)
  · exact hf0 x (by omega)

theorem shr (x k : Nat) : x >>> k = x / 2 ^ k := Nat.shiftRight_eq_div_pow x k

theorem and3f (x : Nat) : x &&& 0x3f = x % 64 := by
  have := Nat.and_two_pow_sub_one_eq_mod x 6
  simpa using this

/-- The bytes `parse_string()` writes for a code point. -/
def cpBytes (cp : Nat) : List Nat :=
  if cp < 0x80 then [cp]
  else if cp < 0x800 then [0xc0 ||| (cp >>> 6), 0x80 ||| (cp &&& 0x3f)]
  else if cp < 0x10000 then
    [0xe0 ||| (cp >>> 12), 0x80 ||| ((cp >>> 6) &&& 0x3f), 0x80 ||| (cp &&& 0x3f)]
  else utf8Four cp

theorem emitCp_eq (r : Room) (out : List Nat) (cp : Nat) :
    emitCp r out cp = emitAll r out (cpBytes cp) := by
  unfold emitCp utf8Emit cpBytes
  by_cases h1 : cp < 0x80
  · simp only [h1, ite_true, (by omega : cp < 0x10000)]
    simp only [emitAll]
    cases emit r out cp <;> rfl
  · by_cases h2 : cp < 0x800
    · simp [h1, h2, (by omega : cp < 0x10000)]
    · by_cases h3 : cp < 0x10000
      · simp [h1, h2, h3]
      · simp [h1, h2, h3]

/-- A scalar value, not NUL, is written as a row of Table 3-7 without NUL. -/
theorem cpBytes_row (cp : Nat) (h0 : 0 < cp) (hmax : cp ≤ 0x10ffff)
    (hs : ¬ (0xd800 ≤ cp ∧ cp ≤ 0xdfff)) :
    cpBytes cp ≠ [] ∧ width (cpBytes cp) = (cpBytes cp).length ∧
      0 ∉ cpBytes cp := by
  unfold cpBytes
  by_cases h1 : cp < 0x80
  · simp only [h1, ite_true]
    refine ⟨by simp, width_ascii cp [] (by omega), by simp; omega⟩
  by_cases h2 : cp < 0x800
  · simp only [h1, h2, ite_true, ite_false]
    rw [shr, and3f, or_low 0xc0 _ (by omega) (by simp; omega) (by simp; omega),
      or_low 0x80 _ (by omega) (by omega) (by omega)]
    refine ⟨by simp, ?_, by simp; omega⟩
    apply rowWidth_of_row2
    unfold Row2; simp; omega
  by_cases h3 : cp < 0x10000
  · simp only [h1, h2, h3, ite_true, ite_false]
    rw [shr, shr, and3f, and3f,
      or_low 0xe0 _ (by omega) (by simp; omega) (by simp; omega),
      or_low 0x80 (cp / 2 ^ 6 % 64) (by omega) (by omega) (by omega),
      or_low 0x80 (cp % 64) (by omega) (by omega) (by omega)]
    refine ⟨by simp, ?_, by simp; omega⟩
    apply rowWidth_of_row3
    unfold Row3; simp; omega
  · simp only [h1, h2, h3, ite_false, utf8Four]
    rw [shr, shr, shr, and3f, and3f, and3f,
      or_low 0xf0 _ (by omega) (by simp; omega) (by simp; omega),
      or_low 0x80 (cp / 2 ^ 12 % 64) (by omega) (by omega) (by omega),
      or_low 0x80 (cp / 2 ^ 6 % 64) (by omega) (by omega) (by omega),
      or_low 0x80 (cp % 64) (by omega) (by omega) (by omega)]
    refine ⟨by simp, ?_, by simp; omega⟩
    apply rowWidth_of_row4
    unfold Row4; simp; omega

theorem hex4_lt (a b c d v : Nat) (h : hex4 [a, b, c, d] = some v) : v < 0x10000 := by
  simp only [hex4, List.foldl_cons, List.foldl_nil] at h
  cases ha : nibble a <;> cases hb : nibble b <;> cases hc : nibble c <;>
    cases hd : nibble d <;> simp only [ha, hb, hc, hd] at h <;> try contradiction
  next x y z w =>
    simp only [Option.some.injEq] at h
    have := Hex.nibble_lt a x ha
    have := Hex.nibble_lt b y hb
    have := Hex.nibble_lt c z hc
    have := Hex.nibble_lt d w hd
    rw [shl4_or _ _ (by omega), shl4_or _ _ (by omega), shl4_or _ _ (by omega),
      shl4_or _ _ (by omega)] at h
    omega

/-- A `\u` escape stands for a scalar value other than NUL. -/
theorem uCodePoint_scalar (s rest : List Nat) (cp : Nat)
    (h : uCodePoint s = .ok (cp, rest)) :
    0 < cp ∧ cp ≤ 0x10ffff ∧ ¬ (0xd800 ≤ cp ∧ cp ≤ 0xdfff) := by
  unfold uCodePoint at h
  split at h
  · split at h
    · contradiction
    · next a b c d _ _ hi hhex =>
      have hlt := hex4_lt a b c d hi hhex
      split at h
      · contradiction
      · next hne =>
        split at h
        · next hhi =>
          split at h
          · split at h
            · contradiction
            · split at h
              · contradiction
              · next a' b' c' d' _ _ lo hlo =>
                split at h
                · next hlor =>
                  simp only [Except.ok.injEq, Prod.mk.injEq] at h
                  rw [← h.1, Nat.shiftLeft_eq]
                  have : hi - 0xd800 < 1024 := by omega
                  refine ⟨by omega, ?_, by omega⟩
                  have : (hi - 0xd800) * 2 ^ 10 ≤ 1023 * 1024 := by
                    have := Nat.mul_le_mul_right (2 ^ 10) (by omega : hi - 0xd800 ≤ 1023)
                    simpa using this
                  omega
                · contradiction
          · contradiction
        · split at h
          · contradiction
          · simp only [Except.ok.injEq, Prod.mk.injEq] at h
            rw [← h.1]
            omega
  · contradiction

theorem simpleEscape_ascii (e v : Nat) (h : simpleEscape e = some v) :
    0 < v ∧ v ≤ 0x7f := by
  unfold simpleEscape at h
  repeat (split at h; · simp only [Option.some.injEq] at h; omega)
  contradiction

/-- What the loop of `parse_string()` adds to well-formed UTF-8 without NUL
keeps it so. -/
theorem readLoop_wf (r : Room) : ∀ (s out out' rest : List Nat),
    readLoop r out s = .ok (out', rest) → wellFormed out = true → 0 ∉ out →
      wellFormed out' = true ∧ 0 ∉ out'
  | [], _, _, _, h, _, _ => by rw [readLoop.eq_def] at h; contradiction
  | ch :: s, out, out', rest, h, hw, hn => by
    rw [readLoop.eq_def] at h
    simp only at h
    split at h
    · simp only [Except.ok.injEq, Prod.mk.injEq] at h
      rw [← h.1]; exact ⟨hw, hn⟩
    · split at h
      · cases hs : s with
        | nil => rw [hs] at h; simp only at h; contradiction
        | cons e rest' =>
          have hlt : rest'.length < s.length := by rw [hs]; simp
          rw [hs] at h
          simp only at h
          split at h
          · next v hv =>
            split at h
            · contradiction
            · next o ho =>
              have ⟨hv0, hv7⟩ := simpleEscape_ascii e v hv
              rw [emit_eq r out o v ho] at h
              refine readLoop_wf r rest' _ out' rest h ?_ ?_
              · exact wellFormed_append _ _ hw
                  (by rw [wellFormed_ascii v [] hv7, wellFormed_nil])
              · simp only [List.mem_append, List.mem_singleton, not_or]
                exact ⟨hn, by omega⟩
          · split at h
            · contradiction
            · split at h
              · contradiction
              · next cp rest'' hu =>
                split at h
                · contradiction
                · next o ho =>
                  have ⟨h0, hmax, hs⟩ := uCodePoint_scalar rest' rest'' cp hu
                  have ⟨hne, hrow, hnul⟩ := cpBytes_row cp h0 hmax hs
                  rw [emitCp_eq] at ho
                  rw [emitAll_eq r _ out o ho] at h
                  have := uCodePoint_shorter rest' rest'' cp hu
                  refine readLoop_wf r rest'' _ out' rest h ?_ ?_
                  · exact wellFormed_append _ _ hw
                      (by have := wellFormed_row _ [] hne hrow
                          rw [List.append_nil] at this; rw [this, wellFormed_nil])
                  · simp only [List.mem_append, not_or]; exact ⟨hn, hnul⟩
      · split at h
        · contradiction
        · next hb hc =>
          split at h
          · contradiction
          · next n hwn =>
            split at h
            · contradiction
            · next o ho =>
              rw [emitAll_eq r _ out o ho] at h
              have hle := width_le (ch :: s)
              rw [hwn] at hle
              have hrow : width ((ch :: s).take (n + 1)) =
                  ((ch :: s).take (n + 1)).length := by
                have := width_prefix (ch :: s) [] (by omega)
                rw [List.append_nil, hwn] at this
                rw [this, List.length_take]; simp at hle ⊢; omega
              have hnul : 0 ∉ (ch :: s).take (n + 1) := by
                by_cases hn0 : n = 0
                · subst hn0; simp; omega
                · have := nul_not_mem_row (ch :: s) (by omega)
                  rwa [hwn] at this
              refine readLoop_wf r (s.drop n) _ out' rest h ?_ ?_
              · exact wellFormed_append _ _ hw
                  (by have := wellFormed_row _ [] (by simp) hrow
                      rw [List.append_nil] at this; rw [this, wellFormed_nil])
              · simp only [List.mem_append, not_or]; exact ⟨hn, hnul⟩
termination_by s => s.length
decreasing_by
  all_goals simp only [List.length_cons, List.length_drop]
  all_goals omega

/-- Whatever `parse_string()` returns, from any input, is well-formed
UTF-8 without NUL: no escape can smuggle in a NUL that would cut the C
string short, or a lone surrogate or other ill-formed byte. -/
theorem readString_wf (r : Room) (s out rest : List Nat)
    (h : readString r s = .ok (out, rest)) :
    wellFormed out = true ∧ 0 ∉ out := by
  unfold readString at h
  split at h
  · contradiction
  · split at h
    · contradiction
    · split at h
      · contradiction
      · next o rest' hl =>
        split at h
        · contradiction
        · simp only [Except.ok.injEq, Prod.mk.injEq] at h
          rw [← h.1]
          exact readLoop_wf r _ [] o rest' hl wellFormed_nil (by simp)

end Shirudo.JsonString
