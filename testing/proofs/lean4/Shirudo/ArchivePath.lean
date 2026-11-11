-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

/-!
The member paths of rust/src/util/bpm_package/, ported step by step from
util/bpm_package.c, whose names the model keeps: the C below is that code,
and its `bpm_archive_rel_ok()` and `bpm_pkg_extract()` are the port's
`archive_rel_ok()` and `extract()`. `bpm_archive_rel_ok()` takes a name
from a .bee archive when it is not empty, does not start with `/`, and
none of the components between its slashes is empty, `.` or `..`; a final
`/`, as tar ends a directory member with, leaves no component after it.
`package_member_name_ok()` matches a member only as the whole path below
the archive's top directory. `bpm_pkg_extract()` takes the top directory
from the first member, refuses a member whose name fails the check, lies
outside that directory, or, below it, is empty for anything but a
directory or fails the check, and refuses every member but a regular file
(`0`) and a directory (`5`) before it writes. It then creates
`<dest>/<rel>`.

Path resolution is modelled as the kernel walks a path: a path splits
into the components between its slashes, one that starts with `/` starts
at the filesystem root, a final `/` names the directory before it, `.`
stays, `..` goes up, except at the filesystem root, and any other
component goes down. An empty component is refused, where the kernel and
the `for_each_token()` walk of util/seal.c skip it; no name the check
takes holds one. A directory is the list of its components from the
filesystem root. util/seal.c walks every component with `O_NOFOLLOW`, so
no symbolic link is followed, and the archive can create none.

For names of every length: every name the check takes, resolved below any
directory, leads strictly below it, and so does every directory the walk
passes through; the check takes exactly the relative paths of plain
components, with or without a final `/`; a member name matches exactly
when it is one plain component, a `/` and the member; and every member
`bpm_pkg_extract()` writes is a regular file or a directory strictly
below `dest`, or `dest` itself for the top directory. A string is its
bytes before the NUL, each byte its value.
CBMC checked the two checks of the C against the model on every name of
up to 10 bytes and member of up to 3 until the module moved to Rust;
nothing ties the Rust port to it but the review that it follows the same
steps, as the model of `bpm_pkg_extract()` always followed the C.
-/

namespace Shirudo.ArchivePath

/-- `/`. -/
def slash : Nat := 0x2f

/-- `.`. -/
def dot : Nat := 0x2e

/-- The type flag of a regular file, `0`. -/
def regType : Nat := 0x30

/-- The type flag of a directory, `5`. -/
def dirType : Nat := 0x35

/-- Not a `/`, what `strchr(p, '/')` skips. -/
def notSlash (c : Nat) : Bool := c != slash

/-- A component `bpm_archive_rel_ok()` refuses: an empty one, `.` or `..`. -/
def bad (comp : List Nat) : Bool := comp == [] || comp == [dot] || comp == [dot, dot]

theorem length_dropWhile_lt (p : List Nat) (r : List Nat) (c : Nat)
    (h : p.dropWhile notSlash = c :: r) : r.length < p.length := by
  have e := List.takeWhile_append_dropWhile (p := notSlash) (l := p)
  rw [h] at e
  have := congrArg List.length e
  simp only [List.length_append, List.length_cons] at this
  omega

/-- The loop of `bpm_archive_rel_ok()` from `p`: the component up to the
next `/` or the end is refused when bad, and the loop goes on past the
`/`, or stops at the end. -/
def relLoop (p : List Nat) : Bool :=
  if p = [] then true
  else if bad (p.takeWhile notSlash) then false
  else
    match _hq : p.dropWhile notSlash with
    | [] => true
    | _ :: r => relLoop r
termination_by p.length
decreasing_by exact length_dropWhile_lt _ _ _ _hq

/-- `bpm_archive_rel_ok(name)`. -/
def relOk (name : List Nat) : Bool :=
  match name with
  | [] => false
  | c :: _ => if c = slash then false else relLoop name

/-- A component a relative path may hold: not empty, no `/`, not `.` and
not `..`. -/
def Plain (c : List Nat) : Prop :=
  c ≠ [] ∧ slash ∉ c ∧ c ≠ [dot] ∧ c ≠ [dot, dot]

/-- Components joined by `/`. -/
def join : List (List Nat) → List Nat
  | [] => []
  | [c] => c
  | c :: cs => c ++ slash :: join cs

/-! ### Resolution -/

/-- A directory: the names of its components from the filesystem root. -/
abbrev Dir := List (List Nat)

/-- The parts of a string between its slashes, empty ones included. -/
def splitSlash : List Nat → List (List Nat)
  | [] => [[]]
  | c :: s =>
    if c = slash then [] :: splitSlash s
    else
      match splitSlash s with
      | p :: ps => (c :: p) :: ps
      | [] => [[c]]

/-- The components of a path: its parts, less the empty one a final `/`
leaves, since a final `/` names the directory before it. -/
def parts (s : List Nat) : List (List Nat) :=
  let ps := splitSlash s
  if 2 ≤ ps.length ∧ ps.getLast? = some [] then ps.dropLast else ps

/-- One component of a walk from directory `d`: an empty one is refused,
`.` stays, `..` goes up, except at the filesystem root, and a name goes
down. -/
def step (d : Dir) (c : List Nat) : Option Dir :=
  if c = [] then none
  else if c = [dot] then some d
  else if c = [dot, dot] then some d.dropLast
  else some (d ++ [c])

/-- The directories a walk from `d` passes through, the last one where it
leads. -/
def walk (d : Dir) : List (List Nat) → Option (List Dir)
  | [] => some []
  | c :: cs =>
    match step d c with
    | none => none
    | some d' => (walk d' cs).map (d' :: ·)

/-- Where path `s` leads from directory `root`, with each directory it
passes through: from the filesystem root when it starts with `/`. -/
def resolve (root : Dir) (s : List Nat) : Option (List Dir) :=
  match parts s with
  | [] :: c :: cs => walk [] (c :: cs)
  | cs => walk root cs

/-- Strictly below `root`. -/
def Below (root d : Dir) : Prop := ∃ e, e ≠ [] ∧ d = root ++ e

/-! ### The loop of the check -/

theorem notSlash_iff (c : Nat) : notSlash c = true ↔ c ≠ slash := by
  simp [notSlash]

theorem all_notSlash (c : List Nat) (h : slash ∉ c) :
    ∀ a ∈ c, notSlash a = true := by
  intro a ha
  rw [notSlash_iff]
  intro e; subst e; exact h ha

theorem takeWhile_comp (c rest : List Nat) (h : slash ∉ c) :
    (c ++ slash :: rest).takeWhile notSlash = c := by
  rw [List.takeWhile_append_of_pos (all_notSlash c h)]
  simp [notSlash]

theorem dropWhile_comp (c rest : List Nat) (h : slash ∉ c) :
    (c ++ slash :: rest).dropWhile notSlash = slash :: rest := by
  rw [List.dropWhile_append_of_pos (all_notSlash c h)]
  simp [notSlash]

theorem takeWhile_last (c : List Nat) (h : slash ∉ c) :
    c.takeWhile notSlash = c := by
  have := List.takeWhile_append_of_pos (l₂ := []) (all_notSlash c h)
  simpa using this

theorem dropWhile_last (c : List Nat) (h : slash ∉ c) :
    c.dropWhile notSlash = [] := by
  have := List.dropWhile_append_of_pos (l₂ := []) (all_notSlash c h)
  simpa using this

theorem bad_iff (c : List Nat) : bad c = true ↔ c = [] ∨ c = [dot] ∨ c = [dot, dot] := by
  simp [bad, or_assoc]

theorem plain_not_bad (c : List Nat) (h : Plain c) : bad c = false := by
  have ⟨h1, _, h3, h4⟩ := h
  cases hb : bad c
  · rfl
  · rw [bad_iff] at hb
    rcases hb with e | e | e <;> contradiction

theorem relLoop_comp (c rest : List Nat) (hs : slash ∉ c) :
    relLoop (c ++ slash :: rest) = if bad c then false else relLoop rest := by
  rw [relLoop.eq_def]
  rw [ite_eq_right (by simp), takeWhile_comp c rest hs]
  split
  · rfl
  · split
    · next hq => rw [dropWhile_comp c rest hs] at hq; simp at hq
    · next r hq =>
      rw [dropWhile_comp c rest hs] at hq
      simp only [List.cons.injEq] at hq
      rw [hq.2]

theorem relLoop_cons_comp (c rest : List Nat) (h : Plain c) :
    relLoop (c ++ slash :: rest) = relLoop rest := by
  rw [relLoop_comp c rest h.2.1, plain_not_bad c h]
  rfl

theorem relLoop_last (c : List Nat) (h : Plain c) : relLoop c = true := by
  have ⟨hne, hs, _, _⟩ := h
  obtain ⟨x, xs, hx⟩ : ∃ x xs, c = x :: xs := by
    cases c with
    | nil => contradiction
    | cons x xs => exact ⟨x, xs, rfl⟩
  rw [relLoop.eq_def]
  rw [ite_eq_right (by rw [hx]; simp), takeWhile_last c hs, plain_not_bad c h]
  simp only [Bool.false_eq_true, ite_false]
  split
  · rfl
  · next r hq => rw [dropWhile_last c hs] at hq; simp at hq

theorem relLoop_join (cs : List (List Nat)) (hne : cs ≠ [])
    (h : ∀ c ∈ cs, Plain c) :
    relLoop (join cs) = true ∧ relLoop (join cs ++ [slash]) = true := by
  induction cs with
  | nil => contradiction
  | cons c cs ih =>
    have hc := h c List.mem_cons_self
    cases cs with
    | nil =>
      refine ⟨relLoop_last c hc, ?_⟩
      simp only [join]
      rw [relLoop_cons_comp c [] hc]
      simp [relLoop]
    | cons d ds =>
      have ih' := ih (by simp) (fun x m => h x (List.mem_cons_of_mem c m))
      simp only [join]
      refine ⟨?_, ?_⟩
      · rw [relLoop_cons_comp c _ hc]
        exact ih'.1
      · rw [List.append_assoc, List.cons_append, relLoop_cons_comp c _ hc]
        exact ih'.2

theorem plain_of_takeWhile (p : List Nat) (hb : bad (p.takeWhile notSlash) = false) :
    Plain (p.takeWhile notSlash) := by
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro e; rw [e] at hb; simp [bad] at hb
  · intro m
    have := List.all_eq_true.1 (List.all_takeWhile (p := notSlash) (l := p)) _ m
    simp [notSlash] at this
  · intro e; rw [e] at hb; simp [bad] at hb
  · intro e; rw [e] at hb; simp [bad] at hb

theorem join_cons (c : List Nat) (cs : List (List Nat)) (hne : cs ≠ []) :
    join (c :: cs) = c ++ slash :: join cs := by
  cases cs with
  | nil => contradiction
  | cons d ds => rfl

/-- What the loop takes is empty, or plain components joined by `/`, with
or without a final `/`. -/
theorem relLoop_sound : ∀ (p : List Nat), relLoop p = true → p = [] ∨
    ∃ cs, cs ≠ [] ∧ (∀ c ∈ cs, Plain c) ∧ (p = join cs ∨ p = join cs ++ [slash])
  | [], _ => Or.inl rfl
  | x :: xs, h => by
    right
    rw [relLoop.eq_def] at h
    rw [ite_eq_right (by simp)] at h
    split at h
    · contradiction
    · next hb =>
      have hb' : bad ((x :: xs).takeWhile notSlash) = false := by
        simpa using hb
      have hp := plain_of_takeWhile (x :: xs) hb'
      have hsplit := List.takeWhile_append_dropWhile (p := notSlash) (l := x :: xs)
      generalize (x :: xs).takeWhile notSlash = c at hp hsplit
      split at h
      · next hq =>
        rw [hq, List.append_nil] at hsplit
        exact ⟨[c], by simp, by simpa using hp, Or.inl (by rw [← hsplit]; rfl)⟩
      · next s r hq =>
        have hs : s = slash := by
          have := List.head_dropWhile_not notSlash (l := x :: xs) (by simp [hq])
          simp only [hq, List.head_cons, notSlash] at this
          simpa using this
        subst hs
        have hlt := length_dropWhile_lt (x :: xs) r slash hq
        rw [hq] at hsplit
        rcases relLoop_sound r h with hr | ⟨cs, hne, hcs, hr⟩
        · subst hr
          exact ⟨[c], by simp, by simpa using hp, Or.inr (by rw [← hsplit]; rfl)⟩
        · refine ⟨c :: cs, by simp, ?_, ?_⟩
          · intro c' hc
            simp only [List.mem_cons] at hc
            rcases hc with hc | hc
            · rw [hc]; exact hp
            · exact hcs c' hc
          · rw [join_cons _ _ hne]
            rcases hr with hr | hr
            · left; rw [← hsplit, hr]
            · right; rw [← hsplit, hr, List.append_assoc, List.cons_append]
termination_by p => p.length
decreasing_by exact hlt

theorem relOk_cons (x : Nat) (xs : List Nat) :
    relOk (x :: xs) = if x = slash then false else relLoop (x :: xs) := rfl

/-- The check takes exactly the relative paths of plain components, with
or without a final `/`. -/
theorem relOk_iff (s : List Nat) :
    relOk s = true ↔ ∃ cs, cs ≠ [] ∧ (∀ c ∈ cs, Plain c) ∧
      (s = join cs ∨ s = join cs ++ [slash]) := by
  constructor
  · intro h
    cases s with
    | nil => simp [relOk] at h
    | cons x xs =>
      simp only [relOk] at h
      split at h
      · contradiction
      · rcases relLoop_sound (x :: xs) h with e | e
        · simp at e
        · exact e
  · intro ⟨cs, hne, hcs, hs⟩
    have hl := relLoop_join cs hne hcs
    obtain ⟨c, cs', rfl⟩ : ∃ c cs', cs = c :: cs' := by
      cases cs with
      | nil => contradiction
      | cons c cs' => exact ⟨c, cs', rfl⟩
    have ⟨hcne, hcs1, _, _⟩ := hcs c List.mem_cons_self
    obtain ⟨x, xs, hx⟩ : ∃ x xs, c = x :: xs := by
      cases c with
      | nil => contradiction
      | cons x xs => exact ⟨x, xs, rfl⟩
    have hxs : x ≠ slash := by
      intro e; subst e; exact hcs1 (by rw [hx]; exact List.mem_cons_self)
    have hhead : ∀ t, join (c :: cs') ++ t = x :: (xs ++ (join (c :: cs') ++ t).drop c.length) := by
      intro t
      cases cs' with
      | nil => simp [join, hx]
      | cons d ds => simp [join, hx]
    rcases hs with hs | hs
    · subst hs
      have := hhead []
      rw [List.append_nil] at this
      rw [this, relOk_cons, ite_eq_right hxs, ← this]
      exact hl.1
    · subst hs
      rw [hhead [slash], relOk_cons, ite_eq_right hxs, ← hhead [slash]]
      exact hl.2

/-! ### Resolution of what the check takes -/

theorem splitSlash_comp (c rest : List Nat) (h : slash ∉ c) :
    splitSlash (c ++ slash :: rest) = c :: splitSlash rest := by
  induction c with
  | nil => simp [splitSlash]
  | cons x c ih =>
    have hx : x ≠ slash := fun e => h (e ▸ List.mem_cons_self)
    have hc : slash ∉ c := fun m => h (List.mem_cons_of_mem x m)
    simp only [List.cons_append, splitSlash, hx, ite_false, ih hc]

theorem splitSlash_last (c : List Nat) (h : slash ∉ c) : splitSlash c = [c] := by
  induction c with
  | nil => rfl
  | cons x c ih =>
    have hx : x ≠ slash := fun e => h (e ▸ List.mem_cons_self)
    have hc : slash ∉ c := fun m => h (List.mem_cons_of_mem x m)
    simp only [splitSlash, hx, ite_false, ih hc]

theorem splitSlash_join (cs : List (List Nat)) (hne : cs ≠ [])
    (h : ∀ c ∈ cs, slash ∉ c) :
    splitSlash (join cs) = cs ∧ splitSlash (join cs ++ [slash]) = cs ++ [[]] := by
  induction cs with
  | nil => contradiction
  | cons c cs ih =>
    have hc := h c List.mem_cons_self
    cases cs with
    | nil =>
      simp only [join]
      exact ⟨splitSlash_last c hc, by rw [splitSlash_comp c [] hc]; rfl⟩
    | cons d ds =>
      have ih' := ih (by simp) (fun x m => h x (List.mem_cons_of_mem c m))
      simp only [join] at ih' ⊢
      refine ⟨by rw [splitSlash_comp c _ hc, ih'.1], ?_⟩
      rw [List.append_assoc, List.cons_append, splitSlash_comp c _ hc, ih'.2]
      rfl

theorem parts_join (cs : List (List Nat)) (hne : cs ≠ [])
    (h : ∀ c ∈ cs, Plain c) :
    parts (join cs) = cs ∧ parts (join cs ++ [slash]) = cs := by
  have hs := splitSlash_join cs hne (fun c m => (h c m).2.1)
  have hlast : cs.getLast? ≠ some [] := by
    intro e
    have := List.mem_of_getLast? e
    exact (h [] this).1 rfl
  unfold parts
  constructor
  · rw [hs.1]
    simp only [hlast, and_false, ite_false]
  · rw [hs.2]
    have hl : 2 ≤ (cs ++ [[]]).length := by
      cases cs with
      | nil => contradiction
      | cons _ _ => simp
    simp only [hl, List.getLast?_append, List.getLast?_singleton, Option.some_or,
      and_self, ite_true, List.dropLast_concat]

theorem walk_plain (cs : List (List Nat)) (h : ∀ c ∈ cs, Plain c) :
    ∀ d : Dir, ∃ ds, walk d cs = some ds ∧ ds.length = cs.length ∧
      ∀ x ∈ ds, Below d x := by
  induction cs with
  | nil => intro d; exact ⟨[], rfl, rfl, by simp⟩
  | cons c cs ih =>
    intro d
    have ⟨h1, _, h3, h4⟩ := h c List.mem_cons_self
    have hstep : step d c = some (d ++ [c]) := by
      simp [step, h1, h3, h4]
    have ⟨ds, hw, hl, hb⟩ := ih (fun x m => h x (List.mem_cons_of_mem c m)) (d ++ [c])
    refine ⟨(d ++ [c]) :: ds, by simp [walk, hstep, hw], by simp [hl], ?_⟩
    intro x hx
    simp only [List.mem_cons] at hx
    rcases hx with hx | hx
    · exact ⟨[c], by simp, hx⟩
    · have ⟨e, he, hxe⟩ := hb x hx
      exact ⟨c :: e, by simp, by rw [hxe]; simp⟩

theorem resolve_relative (root : Dir) (s : List Nat) (cs : List (List Nat))
    (hp : parts s = cs) (hc : ∀ c ∈ cs, c ≠ []) :
    resolve root s = walk root cs := by
  unfold resolve
  rw [hp]
  match cs, hc with
  | [], _ => rfl
  | [] :: _, hc => exact absurd rfl (hc [] List.mem_cons_self)
  | (_ :: _) :: _, _ => rfl

/-- Every name the check takes, resolved below any directory `root`, leads
strictly below it, and so does every directory the walk passes through. -/
theorem relOk_contained (root : Dir) (s : List Nat) (h : relOk s = true) :
    ∃ ds, resolve root s = some ds ∧ ds ≠ [] ∧ ∀ d ∈ ds, Below root d := by
  have ⟨cs, hne, hcs, hs⟩ := (relOk_iff s).1 h
  have hp := parts_join cs hne hcs
  have hps : parts s = cs := by
    rcases hs with hs | hs <;> rw [hs]
    · exact hp.1
    · exact hp.2
  rw [resolve_relative root s cs hps (fun c m => (hcs c m).1)]
  have ⟨ds, hw, hl, hb⟩ := walk_plain cs hcs root
  refine ⟨ds, hw, ?_, hb⟩
  intro e; subst e
  cases cs with
  | nil => contradiction
  | cons _ _ => simp at hl

/-- The check takes every relative path of plain components, with or
without a final `/`. -/
theorem relOk_plain (cs : List (List Nat)) (hne : cs ≠ [])
    (h : ∀ c ∈ cs, Plain c) :
    relOk (join cs) = true ∧ relOk (join cs ++ [slash]) = true :=
  ⟨(relOk_iff _).2 ⟨cs, hne, h, Or.inl rfl⟩,
   (relOk_iff _).2 ⟨cs, hne, h, Or.inr rfl⟩⟩

/-! ### Members -/

/-- `package_member_name_ok(name, member)`: `strchr(name, '/')` found, not
first, `name` not starting `./`, `member` taken by the check and the
same as what follows that `/`. -/
def memberNameOk (name member : List Nat) : Bool :=
  let t := name.takeWhile notSlash
  relOk name && decide (t.length < name.length) && decide (t ≠ []) &&
    decide (name.take 2 ≠ [dot, slash]) && relOk member &&
    decide (name.drop (t.length + 1) = member)

theorem split_at_slash (name : List Nat)
    (h : (name.takeWhile notSlash).length < name.length) :
    name = name.takeWhile notSlash ++
      slash :: name.drop ((name.takeWhile notSlash).length + 1) := by
  have hsplit := List.takeWhile_append_dropWhile (p := notSlash) (l := name)
  have hne : name.dropWhile notSlash ≠ [] := by
    intro e
    rw [e, List.append_nil] at hsplit
    rw [hsplit] at h
    omega
  obtain ⟨y, r, hyr⟩ : ∃ y r, name.dropWhile notSlash = y :: r := by
    cases hq : name.dropWhile notSlash with
    | nil => exact absurd hq hne
    | cons y r => exact ⟨y, r, rfl⟩
  have hy : y = slash := by
    have := List.head_dropWhile_not notSlash (l := name) hne
    simp only [hyr, List.head_cons, notSlash] at this
    simpa using this
  subst hy
  rw [hyr] at hsplit
  generalize name.takeWhile notSlash = tw at hsplit ⊢
  subst hsplit
  simp [List.drop_append]

theorem takeWhile_slash_free (name : List Nat) : slash ∉ name.takeWhile notSlash := by
  intro m
  have := List.all_eq_true.1 (List.all_takeWhile (p := notSlash) (l := name)) _ m
  simp [notSlash] at this

/-- A member name matches exactly when it is one plain component, a `/` and
the member, which the check takes: a member is found only in the
archive's top directory. -/
theorem memberNameOk_iff (name member : List Nat) :
    memberNameOk name member = true ↔
      ∃ t, Plain t ∧ relOk member = true ∧ name = t ++ slash :: member := by
  unfold memberNameOk
  simp only [Bool.and_eq_true, decide_eq_true_eq]
  constructor
  · intro ⟨⟨⟨⟨⟨hname, hlt⟩, hne⟩, h2⟩, hmem⟩, hdrop⟩
    have hsp := split_at_slash name hlt
    rw [hdrop] at hsp
    have hsf := takeWhile_slash_free name
    refine ⟨name.takeWhile notSlash, ?_, hmem, hsp⟩
    have hloop : relLoop name = true := by
      cases name with
      | nil => simp [relOk] at hname
      | cons x xs =>
        rw [relOk_cons] at hname
        split at hname
        · contradiction
        · exact hname
    rw [hsp, relLoop_comp _ _ hsf] at hloop
    have hb : bad (name.takeWhile notSlash) = false := by
      cases hb : bad (name.takeWhile notSlash)
      · rfl
      · rw [hb] at hloop; simp at hloop
    exact plain_of_takeWhile name hb
  · intro ⟨t, ht, hmem, hname⟩
    have ⟨cs, hne, hcs, hm⟩ := (relOk_iff member).1 hmem
    have htw : name.takeWhile notSlash = t := by
      rw [hname, takeWhile_comp t member ht.2.1]
    rw [htw]
    refine ⟨⟨⟨⟨⟨?_, ?_⟩, ht.1⟩, ?_⟩, hmem⟩, ?_⟩
    · apply (relOk_iff name).2
      refine ⟨t :: cs, by simp, ?_, ?_⟩
      · intro c hc
        simp only [List.mem_cons] at hc
        rcases hc with hc | hc
        · rw [hc]; exact ht
        · exact hcs c hc
      · rw [join_cons t cs hne, hname]
        rcases hm with hm | hm
        · left; rw [hm]
        · right; rw [hm]; simp
    · rw [hname]; simp
    · intro e
      rw [hname] at e
      have ⟨h1, h2, h3, _⟩ := ht
      match t, h1, h2, h3, e with
      | [x], _, _, h3, e =>
        simp only [List.cons_append, List.nil_append, List.take_succ_cons,
          List.take_zero, List.cons.injEq, and_true] at e
        exact h3 (by rw [e])
      | x :: y :: t', _, h2, _, e =>
        simp only [List.cons_append, List.take_succ_cons, List.take_zero,
          List.cons.injEq, and_true] at e
        exact h2 (by rw [← e.2]; simp)
    · rw [hname]; simp

/-! ### Extraction -/

/-- The top directory `bpm_pkg_extract()` takes from the first member: the
name up to its first `/`, which it must have, not first, and shorter
than the 256 bytes of `root`. -/
def topOf (name : List Nat) : Option (List Nat) :=
  let t := name.takeWhile notSlash
  if t.length < name.length ∧ t ≠ [] ∧ t.length < 256 then some t else none

/-- The top directory of the members before, or this member's for the
first. -/
def topFor (top : Option (List Nat)) (name : List Nat) : Option (List Nat) :=
  match top with
  | some t => some t
  | none => topOf name

/-- The checks `bpm_pkg_extract()` makes of a member's name and type
before it writes: the name passes the check, lies below the top
directory, and what follows it is empty only for a directory and passes
the check otherwise, and the member is a regular file or a directory.
Yields the top directory and the path it then creates below `dest`. The
limits on count, size and path length refuse more and are left out. -/
def extractMember (top : Option (List Nat)) (name : List Nat) (type : Nat) :
    Option (List Nat × List Nat) :=
  if relOk name = false then none
  else
    match topFor top name with
    | none => none
    | some t =>
      if name.take (t.length + 1) ≠ t ++ [slash] then none
      else if (name.drop (t.length + 1) = [] ∧ type ≠ dirType) ∨
          (name.drop (t.length + 1) ≠ [] ∧
            relOk (name.drop (t.length + 1)) = false) then none
      else if type ≠ regType ∧ type ≠ dirType then none
      else some (t, name.drop (t.length + 1))

/-- Every member `bpm_pkg_extract()` writes is a regular file or a
directory, no symbolic or hard link, and is created strictly below
`dest`, as is every directory on its way, or is `dest` itself for the
top directory. -/
theorem extract_contained (dest : Dir) (top : Option (List Nat))
    (name : List Nat) (type : Nat) (t rel : List Nat)
    (h : extractMember top name type = some (t, rel)) :
    (type = regType ∨ type = dirType) ∧
      ((rel = [] ∧ type = dirType) ∨
        ∃ ds, resolve dest rel = some ds ∧ ds ≠ [] ∧ ∀ d ∈ ds, Below dest d) := by
  unfold extractMember at h
  by_cases h1 : relOk name = false
  · rw [ite_eq_left h1] at h; contradiction
  rw [ite_eq_right h1] at h
  cases htop : topFor top name with
  | none => simp [htop] at h
  | some t' =>
    simp only [htop] at h
    by_cases h2 : name.take (t'.length + 1) ≠ t' ++ [slash]
    · rw [ite_eq_left h2] at h; contradiction
    rw [ite_eq_right h2] at h
    generalize hd : name.drop (t'.length + 1) = d at h
    by_cases h3 : (d = [] ∧ type ≠ dirType) ∨ (d ≠ [] ∧ relOk d = false)
    · rw [ite_eq_left h3] at h; contradiction
    rw [ite_eq_right h3] at h
    by_cases h4 : type ≠ regType ∧ type ≠ dirType
    · rw [ite_eq_left h4] at h; contradiction
    rw [ite_eq_right h4] at h
    simp only [Option.some.injEq, Prod.mk.injEq] at h
    obtain ⟨_, hr⟩ := h
    subst hr
    refine ⟨Classical.byContradiction fun hn =>
      h4 ⟨fun e => hn (Or.inl e), fun e => hn (Or.inr e)⟩, ?_⟩
    by_cases he : d = []
    · left; exact ⟨he, Classical.byContradiction fun hn => h3 (Or.inl ⟨he, hn⟩)⟩
    · right
      have hok : relOk d = true := by
        cases hr : relOk d
        · exact absurd (Or.inr ⟨he, hr⟩) h3
        · rfl
      exact relOk_contained dest d hok

end Shirudo.ArchivePath
