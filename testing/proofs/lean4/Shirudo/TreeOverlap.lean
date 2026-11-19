-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

/-!
Which operations of an upatch tree can meet on one node. `disjoint`,
`covers` and `addLive` follow rust/src/util/bpm_tree_overlap.rs,
`selectorMatches` follows `selector_matches()` of
rust/src/util/bpm_tree_state.rs, and the theorems show the first three
sound for the fourth: both selectors are held against one node, whose
two kernel configs agree.
-/

namespace Shirudo.TreeOverlap

/-- A C string: its bytes before the NUL. -/
abbrev Str := List Nat

/-! ### Lists of values -/

/-- `list_holds()`, and the loops of `selector_matches()` and
`selector_values_match()` that look for one string: `strcmp()` finds
`value` in the list. -/
def listHolds (list : List Str) (value : Str) : Bool :=
  list.any (fun s => s == value)

/-- `lists_share()`: a value of `a` is in `b`. -/
def listsShare (a b : List Str) : Bool :=
  a.any (fun s => listHolds b s)

/-- `list_within()`: every value of `inner` is in `outer`. -/
def listWithin (inner outer : List Str) : Bool :=
  inner.all (fun s => listHolds outer s)

theorem listHolds_iff (list : List Str) (value : Str) :
    listHolds list value = true ↔ value ∈ list := by
  simp [listHolds]

theorem listsShare_iff (a b : List Str) :
    listsShare a b = true ↔ ∃ v, v ∈ a ∧ v ∈ b := by
  simp [listsShare, listHolds_iff]

theorem listWithin_iff (inner outer : List Str) :
    listWithin inner outer = true ↔ ∀ v, v ∈ inner → v ∈ outer := by
  simp [listWithin, listHolds_iff]

theorem listsShare_comm (a b : List Str) : listsShare a b = listsShare b a := by
  rw [Bool.eq_iff_iff, listsShare_iff, listsShare_iff]
  exact ⟨fun ⟨v, ha, hb⟩ => ⟨v, hb, ha⟩, fun ⟨v, hb, ha⟩ => ⟨v, ha, hb⟩⟩

/-! ### Release prefixes -/

/-- `.` and `-`, which end a component of a kernel release. -/
def dot : Nat := 0x2e
def dash : Nat := 0x2d

/-- What `kernel_release_prefix_matches()` lets follow a prefix in a
release: its end, a `.` or a `-`. -/
def boundary : Str → Bool
  | [] => true
  | c :: _ => c == dot || c == dash

/-- `str_after_prefix(release, prefix)` finding the prefix, and then the
byte of the release after it. -/
def continues : Str → Str → Bool
  | release, [] => boundary release
  | [], _ :: _ => false
  | x :: release, y :: pre => x == y && continues release pre

/-- `kernel_release_prefix_matches()`: an empty prefix takes every
release. -/
def prefixMatches (release pre : Str) : Bool :=
  pre.isEmpty || continues release pre

/-- `prefixes_share()`: one prefix takes the other read as a release. -/
def prefixesShare (a b : List Str) : Bool :=
  a.any (fun x => b.any (fun y => prefixMatches x y || prefixMatches y x))

/-- `prefixes_within()`: each prefix of `inner`, read as a release, is
taken by one of `outer`. -/
def prefixesWithin (inner outer : List Str) : Bool :=
  inner.all (fun x => outer.any (fun y => prefixMatches x y))

theorem boundary_left (c t : Str) (h : boundary (c ++ t) = true) :
    boundary c = true := by
  cases c with
  | nil => rfl
  | cons x c => simpa [boundary] using h

theorem boundary_append (c t : Str) (hc : boundary c = true)
    (ht : boundary t = true) : boundary (c ++ t) = true := by
  cases c with
  | nil => simpa using ht
  | cons x c => simpa [boundary] using hc

/-- The release is the prefix and a rest that starts a new component. -/
theorem continues_iff (release pre : Str) :
    continues release pre = true ↔
      ∃ t, release = pre ++ t ∧ boundary t = true := by
  induction pre generalizing release with
  | nil => simp [continues]
  | cons y pre ih =>
    cases release with
    | nil => simp [continues]
    | cons x release =>
      simp only [continues, Bool.and_eq_true, beq_iff_eq, ih, List.cons_append,
        List.cons.injEq]
      constructor
      · rintro ⟨rfl, t, rfl, ht⟩
        exact ⟨t, ⟨rfl, rfl⟩, ht⟩
      · rintro ⟨t, ⟨rfl, rfl⟩, ht⟩
        exact ⟨rfl, t, rfl, ht⟩

theorem prefixMatches_iff (release pre : Str) :
    prefixMatches release pre = true ↔
      pre = [] ∨ ∃ t, release = pre ++ t ∧ boundary t = true := by
  simp [prefixMatches, continues_iff]

/-- A prefix takes itself read as a release. -/
theorem prefixMatches_self (s : Str) : prefixMatches s s = true :=
  (prefixMatches_iff s s).2 (Or.inr ⟨[], by simp, rfl⟩)

/-- Two prefixes that take one release: the longer continues the shorter
at a component boundary, so the shorter takes it read as a release. -/
theorem prefixes_meet (release a b : Str)
    (ha : prefixMatches release a = true)
    (hb : prefixMatches release b = true) :
    prefixMatches a b = true ∨ prefixMatches b a = true := by
  rw [prefixMatches_iff] at ha hb
  rcases hb with rfl | ⟨tb, hrb, hbt⟩
  · exact Or.inl ((prefixMatches_iff a []).2 (Or.inl rfl))
  rcases ha with rfl | ⟨ta, hra, hat⟩
  · exact Or.inr ((prefixMatches_iff b []).2 (Or.inl rfl))
  rw [hra] at hrb
  rcases List.append_eq_append_iff.1 hrb with ⟨c, rfl, rfl⟩ | ⟨c, rfl, rfl⟩
  · exact Or.inr ((prefixMatches_iff _ _).2
      (Or.inr ⟨c, rfl, boundary_left c tb hat⟩))
  · exact Or.inl ((prefixMatches_iff _ _).2
      (Or.inr ⟨c, rfl, boundary_left c ta hbt⟩))

/-- The comment above `prefixes_share()`: two prefixes take a common
release exactly when one takes the other read as a release. -/
theorem prefixes_meet_iff (a b : Str) :
    (∃ release, prefixMatches release a = true ∧
        prefixMatches release b = true) ↔
      (prefixMatches a b = true ∨ prefixMatches b a = true) := by
  constructor
  · rintro ⟨release, ha, hb⟩
    exact prefixes_meet release a b ha hb
  · rintro (h | h)
    · exact ⟨a, prefixMatches_self a, h⟩
    · exact ⟨b, h, prefixMatches_self b⟩

/-- A prefix that takes another read as a release takes every release
the other takes. -/
theorem prefix_within (release inner outer : Str)
    (hio : prefixMatches inner outer = true)
    (hri : prefixMatches release inner = true) :
    prefixMatches release outer = true := by
  rw [prefixMatches_iff] at hio hri
  rw [prefixMatches_iff]
  rcases hio with rfl | ⟨t1, rfl, h1⟩
  · exact Or.inl rfl
  rcases hri with h | ⟨t2, rfl, h2⟩
  · have h' : outer = [] ∧ t1 = [] := by simpa using h
    exact Or.inl h'.1
  · exact Or.inr ⟨t1 ++ t2, by simp, boundary_append t1 t2 h1 h2⟩

theorem prefixesShare_iff (a b : List Str) :
    prefixesShare a b = true ↔
      ∃ x, x ∈ a ∧ ∃ y, y ∈ b ∧
        (prefixMatches x y = true ∨ prefixMatches y x = true) := by
  simp [prefixesShare]

theorem prefixesShare_comm (a b : List Str) :
    prefixesShare a b = prefixesShare b a := by
  rw [Bool.eq_iff_iff, prefixesShare_iff, prefixesShare_iff]
  exact ⟨fun ⟨x, hx, y, hy, h⟩ => ⟨y, hy, x, hx, h.symm⟩,
    fun ⟨y, hy, x, hx, h⟩ => ⟨x, hx, y, hy, h.symm⟩⟩

/-! ### Selectors -/

/-- `struct tree_selector_kv`: a kernel option or a label and the values
a selector takes for it. -/
structure Pair where
  key : Str
  values : List Str

/-- `kvs_exclude()`: a key both name, with no value in common. -/
def kvsExclude (a b : List Pair) : Bool :=
  a.any (fun x => b.any (fun y =>
    x.key == y.key && !listsShare x.values y.values))

/-- `kvs_within()`: each pair of `outer` is held by a pair of `inner`
with its key and no value outside its own. -/
def kvsWithin (inner outer : List Pair) : Bool :=
  outer.all (fun y => inner.any (fun x =>
    x.key == y.key && listWithin x.values y.values))

/-- `struct tree_selector`. -/
structure Selector where
  releasePrefix : List Str
  buildId : List Str
  architecture : List Str
  kconfig : List Pair
  labels : List Pair

/-- `tree_selectors_disjoint()`. -/
def disjoint (a b : Selector) : Bool :=
  (!a.architecture.isEmpty && !b.architecture.isEmpty &&
      !listsShare a.architecture b.architecture) ||
    (!a.buildId.isEmpty && !b.buildId.isEmpty &&
      !listsShare a.buildId b.buildId) ||
    (!a.releasePrefix.isEmpty && !b.releasePrefix.isEmpty &&
      !prefixesShare a.releasePrefix b.releasePrefix) ||
    kvsExclude a.kconfig b.kconfig || kvsExclude a.labels b.labels

/-- `selector_covers()`. -/
def covers (outer inner : Selector) : Bool :=
  (outer.architecture.isEmpty ||
      (!inner.architecture.isEmpty &&
        listWithin inner.architecture outer.architecture)) &&
    (outer.buildId.isEmpty ||
      (!inner.buildId.isEmpty && listWithin inner.buildId outer.buildId)) &&
    (outer.releasePrefix.isEmpty ||
      (!inner.releasePrefix.isEmpty &&
        prefixesWithin inner.releasePrefix outer.releasePrefix)) &&
    kvsWithin inner.kconfig outer.kconfig &&
    kvsWithin inner.labels outer.labels

/-! ### What a node takes a selector to mean -/

/-- What `selector_matches()` reads of the node it runs on: the
release and the machine of `uname()`, `none` when it fails, the build ID
`kernel_build_id_read()` gives, `none` when it gives none, the value the
kernel config has for an option, `none` for an option it does not name,
and the pairs of node.labels in the order of the file. -/
structure Node where
  uname : Option (Str × Str)
  buildId : Option Str
  kconfig : Str → Option Str
  labels : List (Str × Str)

/-- `kv_value()`: the value of the first pair with the key. -/
def kvValue : List (Str × Str) → Str → Option Str
  | [], _ => none
  | (k, v) :: rest, key => if k == key then some v else kvValue rest key

/-- One pair of a selector against the node: the node has a value for
the key and `selector_values_match()` finds it among the pair's. -/
def pairHeld (value : Str → Option Str) (p : Pair) : Bool :=
  match value p.key with
  | none => false
  | some v => listHolds p.values v

/-- The build IDs of a selector against the node's: a node without one
matches none. -/
def buildIdHeld (id : Option Str) (ids : List Str) : Bool :=
  match id with
  | none => false
  | some v => listHolds ids v

/-- A selector that names nothing, the tree's wildcard. -/
def wildcard (s : Selector) : Bool :=
  s.releasePrefix.isEmpty && s.buildId.isEmpty && s.architecture.isEmpty &&
    s.kconfig.isEmpty && s.labels.isEmpty

/-- `selector_matches()` after `uname()`: each list that names
something takes the node's value, and each pair too. -/
def matchesOn (release machine : Str) (n : Node) (s : Selector) : Bool :=
  (s.releasePrefix.isEmpty ||
      s.releasePrefix.any (fun p => prefixMatches release p)) &&
    (s.buildId.isEmpty || buildIdHeld n.buildId s.buildId) &&
    (s.architecture.isEmpty || listHolds s.architecture machine) &&
    s.kconfig.all (pairHeld n.kconfig) &&
    s.labels.all (pairHeld (kvValue n.labels))

/-- `selector_matches()` returning true: the wildcard matches before
the node is read, and nothing else matches where `uname()` fails. -/
def selectorMatches (n : Node) (s : Selector) : Bool :=
  wildcard s ||
    match n.uname with
    | none => false
    | some (release, machine) => matchesOn release machine n s

/-! ### Soundness against that meaning -/

theorem kvsExclude_iff (a b : List Pair) :
    kvsExclude a b = true ↔
      ∃ x, x ∈ a ∧ ∃ y, y ∈ b ∧ x.key = y.key ∧
        listsShare x.values y.values = false := by
  simp [kvsExclude]

theorem kvsExclude_comm (a b : List Pair) :
    kvsExclude a b = kvsExclude b a := by
  rw [Bool.eq_iff_iff, kvsExclude_iff, kvsExclude_iff]
  constructor
  · rintro ⟨x, hx, y, hy, hk, hs⟩
    exact ⟨y, hy, x, hx, hk.symm, by rw [listsShare_comm]; exact hs⟩
  · rintro ⟨y, hy, x, hx, hk, hs⟩
    exact ⟨x, hx, y, hy, hk.symm, by rw [listsShare_comm]; exact hs⟩

theorem pairHeld_iff (value : Str → Option Str) (p : Pair) :
    pairHeld value p = true ↔ ∃ v, value p.key = some v ∧ v ∈ p.values := by
  unfold pairHeld
  cases h : value p.key with
  | none => simp
  | some v => simp [listHolds_iff]

/-- A node has one value for a key: pairs of one key that the node holds
share that value. -/
theorem held_not_exclude (value : Str → Option Str) (a b : List Pair)
    (ha : a.all (pairHeld value) = true) (hb : b.all (pairHeld value) = true) :
    kvsExclude a b = false := by
  rw [← Bool.not_eq_true, kvsExclude_iff]
  rintro ⟨x, hx, y, hy, hk, hs⟩
  obtain ⟨v, hv, hvx⟩ := (pairHeld_iff value x).1 (List.all_eq_true.1 ha x hx)
  obtain ⟨w, hw, hwy⟩ := (pairHeld_iff value y).1 (List.all_eq_true.1 hb y hy)
  rw [hk, hw] at hv
  have hwv : w = v := Option.some.inj hv
  have : listsShare x.values y.values = true :=
    (listsShare_iff _ _).2 ⟨v, hvx, hwv ▸ hwy⟩
  rw [hs] at this
  cases this

/-- The pairs of `outer` hold on a node on which those of `inner` do. -/
theorem held_within (value : Str → Option Str) (inner outer : List Pair)
    (hw : kvsWithin inner outer = true)
    (hi : inner.all (pairHeld value) = true) :
    outer.all (pairHeld value) = true := by
  rw [List.all_eq_true]
  intro y hy
  have hy' := List.all_eq_true.1 hw y hy
  obtain ⟨x, hx, hxy⟩ := List.any_eq_true.1 hy'
  rw [Bool.and_eq_true, beq_iff_eq, listWithin_iff] at hxy
  obtain ⟨v, hv, hvx⟩ := (pairHeld_iff value x).1 (List.all_eq_true.1 hi x hx)
  exact (pairHeld_iff value y).2 ⟨v, by rw [← hxy.1]; exact hv, hxy.2 v hvx⟩

theorem wildcard_matchesOn (release machine : Str) (n : Node) (s : Selector)
    (h : wildcard s = true) : matchesOn release machine n s = true := by
  simp only [wildcard, Bool.and_eq_true, List.isEmpty_iff] at h
  obtain ⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩ := h
  simp [matchesOn, h1, h2, h3, h4, h5]

theorem wildcard_not_disjoint (a b : Selector) (h : wildcard a = true) :
    disjoint a b = false := by
  simp only [wildcard, Bool.and_eq_true, List.isEmpty_iff] at h
  obtain ⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩ := h
  simp [disjoint, kvsExclude, h1, h2, h3, h4, h5]

/-- Only the wildcard covers the wildcard. -/
theorem covers_wildcard (outer inner : Selector) (h : covers outer inner = true)
    (hw : wildcard inner = true) : wildcard outer = true := by
  simp only [wildcard, Bool.and_eq_true, List.isEmpty_iff] at hw
  obtain ⟨⟨⟨⟨h1, h2⟩, h3⟩, h4⟩, h5⟩ := hw
  simp only [covers, kvsWithin, h1, h2, h3, h4, h5, List.isEmpty_nil,
    Bool.not_true, Bool.false_and, Bool.or_false, List.any_nil,
    Bool.and_eq_true, List.all_eq_true] at h
  obtain ⟨⟨⟨⟨g1, g2⟩, g3⟩, g4⟩, g5⟩ := h
  have k4 : outer.kconfig = [] := by
    cases hk : outer.kconfig with
    | nil => rfl
    | cons y ys =>
      exact absurd (g4 y (by rw [hk]; exact List.mem_cons_self)) (by simp)
  have k5 : outer.labels = [] := by
    cases hk : outer.labels with
    | nil => rfl
    | cons y ys =>
      exact absurd (g5 y (by rw [hk]; exact List.mem_cons_self)) (by simp)
  simp [wildcard, g1, g2, g3, k4, k5]

/-- No release, machine, build ID, config and labels match two selectors
that `tree_selectors_disjoint()` calls disjoint. -/
theorem disjoint_matchesOn (release machine : Str) (n : Node) (a b : Selector)
    (h : disjoint a b = true)
    (ha : matchesOn release machine n a = true)
    (hb : matchesOn release machine n b = true) : False := by
  simp only [matchesOn, Bool.and_eq_true, Bool.or_eq_true,
    List.isEmpty_iff] at ha hb
  obtain ⟨⟨⟨⟨har, hai⟩, haa⟩, hak⟩, hal⟩ := ha
  obtain ⟨⟨⟨⟨hbr, hbi⟩, hba⟩, hbk⟩, hbl⟩ := hb
  simp only [disjoint, Bool.or_eq_true, Bool.and_eq_true, Bool.not_eq_true',
    List.isEmpty_eq_false_iff, held_not_exclude n.kconfig _ _ hak hbk,
    held_not_exclude (kvValue n.labels) _ _ hal hbl, or_false,
    Bool.false_eq_true] at h
  rcases h with (⟨⟨hna, hnb⟩, hs⟩ | ⟨⟨hna, hnb⟩, hs⟩) | ⟨⟨hna, hnb⟩, hs⟩
  · rcases haa with haa | haa
    · exact hna haa
    rcases hba with hba | hba
    · exact hnb hba
    have : listsShare a.architecture b.architecture = true :=
      (listsShare_iff _ _).2
        ⟨machine, (listHolds_iff _ _).1 haa, (listHolds_iff _ _).1 hba⟩
    rw [hs] at this
    cases this
  · rcases hai with hai | hai
    · exact hna hai
    rcases hbi with hbi | hbi
    · exact hnb hbi
    cases hid : n.buildId with
    | none => simp [buildIdHeld, hid] at hai
    | some id =>
      simp only [buildIdHeld, hid] at hai hbi
      have : listsShare a.buildId b.buildId = true :=
        (listsShare_iff _ _).2
          ⟨id, (listHolds_iff _ _).1 hai, (listHolds_iff _ _).1 hbi⟩
      rw [hs] at this
      cases this
  · rcases har with har | har
    · exact hna har
    rcases hbr with hbr | hbr
    · exact hnb hbr
    obtain ⟨x, hx, hrx⟩ := List.any_eq_true.1 har
    obtain ⟨y, hy, hry⟩ := List.any_eq_true.1 hbr
    have : prefixesShare a.releasePrefix b.releasePrefix = true :=
      (prefixesShare_iff _ _).2
        ⟨x, hx, y, hy, prefixes_meet release x y hrx hry⟩
    rw [hs] at this
    cases this

/-- A selector that `selector_covers()` says covers another takes the
release, machine, build ID, config and labels the other takes. -/
theorem covers_matchesOn (release machine : Str) (n : Node)
    (outer inner : Selector) (h : covers outer inner = true)
    (hi : matchesOn release machine n inner = true) :
    matchesOn release machine n outer = true := by
  simp only [matchesOn, Bool.and_eq_true, Bool.or_eq_true,
    List.isEmpty_iff] at hi
  obtain ⟨⟨⟨⟨hir, hii⟩, hia⟩, hik⟩, hil⟩ := hi
  simp only [covers, Bool.and_eq_true, Bool.or_eq_true, Bool.not_eq_true',
    List.isEmpty_iff, List.isEmpty_eq_false_iff] at h
  obtain ⟨⟨⟨⟨ha, hb⟩, hr⟩, hk⟩, hl⟩ := h
  simp only [matchesOn, Bool.and_eq_true, Bool.or_eq_true, List.isEmpty_iff]
  refine ⟨⟨⟨⟨?_, ?_⟩, ?_⟩, held_within _ _ _ hk hik⟩, held_within _ _ _ hl hil⟩
  · rcases hr with hr | ⟨hne, hw⟩
    · exact Or.inl hr
    rcases hir with hir | hir
    · exact absurd hir hne
    obtain ⟨x, hx, hrx⟩ := List.any_eq_true.1 hir
    obtain ⟨y, hy, hxy⟩ := List.any_eq_true.1 (List.all_eq_true.1 hw x hx)
    exact Or.inr (List.any_eq_true.2
      ⟨y, hy, prefix_within release x y hxy hrx⟩)
  · rcases hb with hb | ⟨hne, hw⟩
    · exact Or.inl hb
    rcases hii with hii | hii
    · exact absurd hii hne
    cases hid : n.buildId with
    | none => simp [buildIdHeld, hid] at hii
    | some id =>
      simp only [buildIdHeld, hid] at hii ⊢
      exact Or.inr ((listHolds_iff _ _).2
        ((listWithin_iff _ _).1 hw id ((listHolds_iff _ _).1 hii)))
  · rcases ha with ha | ⟨hne, hw⟩
    · exact Or.inl ha
    rcases hia with hia | hia
    · exact absurd hia hne
    exact Or.inr ((listHolds_iff _ _).2
      ((listWithin_iff _ _).1 hw machine ((listHolds_iff _ _).1 hia)))

/-- No node matches two selectors that `tree_selectors_disjoint()` calls
disjoint. -/
theorem disjoint_sound (n : Node) (a b : Selector) (h : disjoint a b = true) :
    ¬(selectorMatches n a = true ∧ selectorMatches n b = true) := by
  rintro ⟨ha, hb⟩
  cases hwa : wildcard a with
  | true => rw [wildcard_not_disjoint a b hwa] at h; cases h
  | false =>
    cases hu : n.uname with
    | none => simp [selectorMatches, hwa, hu] at ha
    | some u =>
      obtain ⟨release, machine⟩ := u
      simp only [selectorMatches, hwa, hu, Bool.false_or] at ha
      have hb' : matchesOn release machine n b = true := by
        cases hwb : wildcard b with
        | true => exact wildcard_matchesOn release machine n b hwb
        | false => simpa [selectorMatches, hwb, hu] using hb
      exact disjoint_matchesOn release machine n a b h ha hb'

/-- A selector that `selector_covers()` says covers another matches
every node the other matches. -/
theorem covers_sound (n : Node) (outer inner : Selector)
    (h : covers outer inner = true) (hi : selectorMatches n inner = true) :
    selectorMatches n outer = true := by
  cases hwi : wildcard inner with
  | true => simp [selectorMatches, covers_wildcard outer inner h hwi]
  | false =>
    cases hu : n.uname with
    | none => simp [selectorMatches, hwi, hu] at hi
    | some u =>
      obtain ⟨release, machine⟩ := u
      simp only [selectorMatches, hwi, hu, Bool.false_or] at hi
      simp [selectorMatches, hu,
        covers_matchesOn release machine n outer inner h hi]

/-- The order of its two selectors does not matter to
`tree_selectors_disjoint()`. -/
theorem disjoint_comm (a b : Selector) : disjoint a b = disjoint b a := by
  simp only [disjoint, listsShare_comm b.architecture,
    listsShare_comm b.buildId, prefixesShare_comm b.releasePrefix,
    kvsExclude_comm b.kconfig, kvsExclude_comm b.labels,
    Bool.and_comm (!b.architecture.isEmpty),
    Bool.and_comm (!b.buildId.isEmpty),
    Bool.and_comm (!b.releasePrefix.isEmpty)]

theorem listWithin_self (l : List Str) : listWithin l l = true :=
  (listWithin_iff l l).2 (fun _ h => h)

/-- A selector covers itself: a delete with the selector of an add
reaches every node the add reached. -/
theorem covers_refl (s : Selector) : covers s s = true := by
  have hp : prefixesWithin s.releasePrefix s.releasePrefix = true := by
    simp only [prefixesWithin, List.all_eq_true, List.any_eq_true]
    exact fun x hx => ⟨x, hx, prefixMatches_self x⟩
  have hk : ∀ l : List Pair, kvsWithin l l = true := by
    intro l
    simp only [kvsWithin, List.all_eq_true, List.any_eq_true, Bool.and_eq_true,
      beq_iff_eq]
    exact fun y hy => ⟨y, hy, rfl, listWithin_self y.values⟩
  simp only [covers, listWithin_self, hp, hk, Bool.and_true]
  cases s.architecture <;> cases s.buildId <;> cases s.releasePrefix <;> rfl

/-! ### An add that a later delete ends -/

/-- An operation of a publication, as far as `tree_add_live()` reads it:
whether its `op` is `delete`, its upatch name and its selector. -/
structure Op where
  delete : Bool
  id : Str
  selector : Selector

/-- The test of the loop of `tree_add_live()`: a delete of the same
upatch whose selector covers the add's. -/
def ends (add later : Op) : Bool :=
  later.delete && later.id == add.id && covers later.selector add.selector

/-- `tree_add_live()`: no operation after `index` ends the one at it. -/
def addLive (ops : List Op) (index : Nat) : Bool :=
  match ops[index]? with
  | none => true
  | some add => (ops.drop (index + 1)).all (fun later => !ends add later)

/-- `tree_add_live()` says no exactly when an operation after `index`
ends the one at it. -/
theorem addLive_iff (ops : List Op) (index : Nat) :
    addLive ops index = false ↔
      ∃ add later j, ops[index]? = some add ∧ index < j ∧
        ops[j]? = some later ∧ ends add later = true := by
  unfold addLive
  cases hadd : ops[index]? with
  | none => simp
  | some add =>
    simp only [Option.some.injEq, exists_and_left, exists_eq_left']
    rw [← Bool.not_eq_true, List.all_eq_true]
    constructor
    · intro h
      apply Classical.byContradiction
      intro hn
      apply h
      intro later hl
      obtain ⟨k, hk⟩ := List.mem_iff_getElem?.1 hl
      rw [List.getElem?_drop] at hk
      cases he : ends add later with
      | false => rfl
      | true => exact absurd ⟨later, index + 1 + k, by omega, hk, he⟩ hn
    · rintro ⟨later, j, hj, hl, he⟩ h
      have hm : later ∈ ops.drop (index + 1) := by
        rw [List.mem_iff_getElem?]
        exact ⟨j - (index + 1), by
          rw [List.getElem?_drop]
          have : index + 1 + (j - (index + 1)) = j := by omega
          rw [this]; exact hl⟩
      have := h later hm
      rw [he] at this
      cases this

/-- An add that `tree_add_live()` says is no longer live is followed by
a delete of the same upatch whose selector matches every node the add's
selector matches. -/
theorem addLive_false (ops : List Op) (index : Nat)
    (h : addLive ops index = false) :
    ∃ add later j, ops[index]? = some add ∧ index < j ∧
      ops[j]? = some later ∧ later.delete = true ∧ later.id = add.id ∧
      ∀ n, selectorMatches n add.selector = true →
        selectorMatches n later.selector = true := by
  obtain ⟨add, later, j, hadd, hj, hl, he⟩ := (addLive_iff ops index).1 h
  simp only [ends, Bool.and_eq_true, beq_iff_eq] at he
  exact ⟨add, later, j, hadd, hj, hl, he.1.1, he.1.2,
    fun n hn => covers_sound n later.selector add.selector he.2 hn⟩

end Shirudo.TreeOverlap
