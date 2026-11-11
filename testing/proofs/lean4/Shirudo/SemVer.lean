-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Shirudo.Number

/-!
The version order of rust/src/util/bpm_package/, ported step by step from
util/bpm_package.c, whose names the model keeps: the C below is that code,
and its `semver_parse()`, `semver_identifiers()` and `strcmp()` are the
port's `parse()`, `identifiers()` and order of byte slices.
`bpm_semver_compare()` orders version strings by SemVer 2.0.0 precedence:
major, minor and patch by value, a version with a prerelease below the
same version without one, prerelease identifiers left to right, numeric
ones by value and below alphanumeric ones, which compare by their bytes,
and a list of them below a longer list it begins. Build metadata is
ignored. A string that is not SemVer sorts below every one that is, and
such strings sort among themselves by `strcmp()`. `bpm upgrade` installs
the highest version an index offers, so the order has to be total, or an
upgrade could go backwards or depend on the order of the index.

The model follows the C function by function: `semverParse` is
`semver_parse()` with `semver_identifiers()`, `identCmp` the body of the
loop of `prerelease_compare()`, `lex` that loop and `strcmp()`, and
`semverCompare` is `bpm_semver_compare()`. A string is its bytes before
the NUL, a core number the value `parse_u64()` gives, as `Shirudo.Number`
reads it, and an `Ordering` the sign the C returns.

For strings of every length the order is reflexive, reverses with its
arguments and is transitive, and two strings compare equal exactly when
they make the same version up to build metadata: two that are not SemVer
when their bytes are equal, two that are when their bytes before the `+`
are. Each layer is proved apart: numbers and bytes, one identifier, a list
of them, a prerelease and a version. The C compares two numeric
identifiers by length and then by bytes, which is their order by value
because no leading zero gets through `semver_identifiers()`; that, and
the other rules of SemVer's precedence, are proved of the model too.
CBMC checked the C against the model on every pair of strings of up to 9
bytes until the module moved to Rust; nothing ties the Rust port to it
but the review that it follows the same steps.
-/

namespace Shirudo.SemVer
open Shirudo

/-! ### Numbers and the total order -/

/-- Two numbers or two bytes compared as the C compares them:
`a != b ? (a > b ? 1 : -1) : 0`. -/
def cmpNat (x y : Nat) : Ordering :=
  if x = y then .eq else if x > y then .gt else .lt

/-- A comparison that is a total order: `.eq` on equal values alone,
reversed when its arguments are, and transitive. -/
structure TotalOrder {α : Type} (c : α → α → Ordering) : Prop where
  eq_iff : ∀ a b, c a b = .eq ↔ a = b
  swap : ∀ a b, c a b = (c b a).swap
  trans : ∀ a b d, c a b = .lt → c b d = .lt → c a d = .lt

theorem TotalOrder.refl {α : Type} {c : α → α → Ordering} (h : TotalOrder c)
    (a : α) : c a a = .eq :=
  (h.eq_iff a a).2 rfl

theorem TotalOrder.ne {α : Type} {c : α → α → Ordering} (h : TotalOrder c)
    {a b : α} (hne : c a b ≠ .eq) : a ≠ b :=
  fun he => hne ((h.eq_iff a b).2 he)

theorem cmpNat_of_lt {x y : Nat} (h : x < y) : cmpNat x y = .lt := by
  unfold cmpNat
  rw [ite_eq_right (by omega), ite_eq_right (by omega)]

theorem cmpNat_of_gt {x y : Nat} (h : x > y) : cmpNat x y = .gt := by
  unfold cmpNat
  rw [ite_eq_right (by omega), ite_eq_left h]

theorem cmpNat_self (x : Nat) : cmpNat x x = .eq := by
  simp [cmpNat]

theorem cmpNat_lt (x y : Nat) : cmpNat x y = .lt ↔ x < y := by
  rcases Nat.lt_trichotomy x y with h | h | h
  · simp [cmpNat_of_lt h, h]
  · subst h; simp [cmpNat_self]
  · simp [cmpNat_of_gt h]; omega

theorem cmpNat_succ (x y : Nat) : cmpNat (x + 1) (y + 1) = cmpNat x y := by
  rcases Nat.lt_trichotomy x y with h | h | h
  · rw [cmpNat_of_lt h, cmpNat_of_lt (by omega)]
  · subst h; rw [cmpNat_self, cmpNat_self]
  · rw [cmpNat_of_gt h, cmpNat_of_gt (by omega)]

/-- Numbers and bytes are totally ordered. -/
theorem cmpNat_total : TotalOrder cmpNat where
  eq_iff x y := by
    rcases Nat.lt_trichotomy x y with h | h | h
    · simp [cmpNat_of_lt h]; omega
    · subst h; simp [cmpNat_self]
    · simp [cmpNat_of_gt h]; omega
  swap x y := by
    rcases Nat.lt_trichotomy x y with h | h | h
    · simp [cmpNat_of_lt h, cmpNat_of_gt h, Ordering.swap]
    · subst h; simp [cmpNat_self, Ordering.swap]
    · simp [cmpNat_of_lt h, cmpNat_of_gt h, Ordering.swap]
  trans x y z hxy hyz := by
    rw [cmpNat_lt] at *
    omega

/-! ### Lists -/

/-- Two lists compared left to right: the first pair that `c` finds
different decides, and a list that ends first is below. This is the loop
of `prerelease_compare()` over identifiers, with its
`la ? 1 : lb ? -1 : 0` once a list ends, and `strcmp()` over bytes. -/
def lex {α : Type} (c : α → α → Ordering) : List α → List α → Ordering
  | [], [] => .eq
  | [], _ :: _ => .lt
  | _ :: _, [] => .gt
  | x :: xs, y :: ys =>
    match c x y with
    | .eq => lex c xs ys
    | o => o

theorem lex_cons {α : Type} (c : α → α → Ordering) (x y : α) (xs ys : List α) :
    lex c (x :: xs) (y :: ys) =
      if c x y = .eq then lex c xs ys else c x y := by
  cases h : c x y <;> simp [lex, h]

/-- The list layer: a total order on elements orders their lists totally. -/
theorem lex_total {α : Type} {c : α → α → Ordering} (h : TotalOrder c) :
    TotalOrder (lex c) where
  eq_iff a b := by
    induction a generalizing b with
    | nil => cases b <;> simp [lex]
    | cons x xs ih =>
      cases b with
      | nil => simp [lex]
      | cons y ys =>
        rw [lex_cons]
        by_cases hxy : c x y = .eq
        · have e := (h.eq_iff x y).1 hxy
          subst e
          simp [h.refl, ih]
        · simp [hxy, h.ne hxy]
  swap a b := by
    induction a generalizing b with
    | nil => cases b <;> simp [lex, Ordering.swap]
    | cons x xs ih =>
      cases b with
      | nil => simp [lex, Ordering.swap]
      | cons y ys =>
        rw [lex_cons, lex_cons, h.swap x y]
        cases c y x <;> simp [Ordering.swap, ih]
  trans a b d hab hbd := by
    induction a generalizing b d with
    | nil =>
      cases d with
      | nil => cases b <;> simp_all [lex]
      | cons z zs => simp [lex]
    | cons x xs ih =>
      cases b with
      | nil => simp [lex] at hab
      | cons y ys =>
        cases d with
        | nil => simp [lex] at hbd
        | cons z zs =>
          rw [lex_cons] at hab hbd ⊢
          by_cases hxy : c x y = .eq <;> by_cases hyz : c y z = .eq
          · have e1 := (h.eq_iff x y).1 hxy
            have e2 := (h.eq_iff y z).1 hyz
            subst e1; subst e2
            simp only [h.refl, ite_true] at hab hbd ⊢
            exact ih _ _ hab hbd
          · have e1 := (h.eq_iff x y).1 hxy
            subst e1
            simp_all
          · have e2 := (h.eq_iff y z).1 hyz
            subst e2
            simp_all
          · simp only [hxy, hyz, ite_false] at hab hbd
            have hxz := h.trans x y z hab hbd
            simp [hxz]

/-- SemVer 11.4.4: a list is below a longer list it begins. -/
theorem lex_prefix {α : Type} {c : α → α → Ordering} (h : TotalOrder c) :
    ∀ (xs : List α) (y : α) (ys : List α), lex c xs (xs ++ y :: ys) = .lt
  | [], _, _ => rfl
  | x :: xs, y, ys => by
    rw [List.cons_append, lex_cons, h.refl, ite_eq_left rfl]
    exact lex_prefix h xs y ys

/-- Pairs compared by `c1`, and by `c2` where `c1` finds them equal. -/
def thenCmp {α β : Type} (c1 : α → α → Ordering) (c2 : β → β → Ordering)
    (a b : α × β) : Ordering :=
  match c1 a.1 b.1 with
  | .eq => c2 a.2 b.2
  | o => o

theorem thenCmp_total {α β : Type} {c1 : α → α → Ordering}
    {c2 : β → β → Ordering} (h1 : TotalOrder c1) (h2 : TotalOrder c2) :
    TotalOrder (thenCmp c1 c2) where
  eq_iff a b := by
    unfold thenCmp
    cases h : c1 a.1 b.1
    · simp only [reduceCtorEq, false_iff]
      intro e; subst e; simp [h1.refl] at h
    · have e := (h1.eq_iff _ _).1 h
      rw [h2.eq_iff]
      cases a; cases b; simp_all
    · simp only [reduceCtorEq, false_iff]
      intro e; subst e; simp [h1.refl] at h
  swap a b := by
    unfold thenCmp
    rw [h1.swap a.1 b.1]
    cases c1 b.1 a.1 <;> simp [Ordering.swap, h2.swap a.2 b.2]
  trans a b d hab hbd := by
    unfold thenCmp at *
    cases h : c1 a.1 b.1 <;> cases h' : c1 b.1 d.1 <;>
      simp only [h, h', reduceCtorEq] at hab hbd
    case lt.lt => rw [h1.trans _ _ _ h h']
    case lt.eq => rw [← (h1.eq_iff _ _).1 h', h]
    case eq.lt => rw [(h1.eq_iff _ _).1 h, h']
    case eq.eq =>
      rw [(h1.eq_iff _ _).1 h, (h1.eq_iff _ _).1 h', h1.refl]
      exact h2.trans _ _ _ hab hbd

/-! ### Identifiers -/

/-- `memcmp()` over as many bytes as the shorter list has: the first byte
that differs decides. -/
def memcmp : List Nat → List Nat → Ordering
  | x :: xs, y :: ys => if x = y then memcmp xs ys else cmpNat x y
  | _, _ => .eq

theorem memcmp_cons (x y : Nat) (xs ys : List Nat) :
    memcmp (x :: xs) (y :: ys) =
      if cmpNat x y = .eq then memcmp xs ys else cmpNat x y := by
  by_cases h : x = y
  · subst h; simp [memcmp, cmpNat_self]
  · have : cmpNat x y ≠ .eq := fun he => h ((cmpNat_total.eq_iff x y).1 he)
    simp [memcmp, h, this]

theorem memcmp_eq_lex : ∀ a b : List Nat, a.length = b.length →
    memcmp a b = lex cmpNat a b
  | [], [], _ => rfl
  | [], _ :: _, h => by simp at h
  | _ :: _, [], h => by simp at h
  | x :: xs, y :: ys, h => by
    rw [memcmp_cons, lex_cons, memcmp_eq_lex xs ys (by simpa using h)]

/-- Two alphanumeric identifiers as `prerelease_compare()` compares them:
`memcmp()` of the shorter length, then the longer one above. -/
def alnumCmp (a b : List Nat) : Ordering :=
  match memcmp a b with
  | .eq => cmpNat a.length b.length
  | o => o

/-- That is the `strcmp()` order of their bytes, SemVer's ASCII order. -/
theorem alnumCmp_eq_lex : ∀ a b : List Nat, alnumCmp a b = lex cmpNat a b
  | [], [] => rfl
  | [], _ :: _ => by simp [alnumCmp, memcmp, lex, cmpNat_of_lt]
  | _ :: _, [] => by simp [alnumCmp, memcmp, lex, cmpNat_of_gt]
  | x :: xs, y :: ys => by
    have ih := alnumCmp_eq_lex xs ys
    rw [lex_cons, ← ih]
    unfold alnumCmp
    rw [memcmp_cons]
    by_cases h : cmpNat x y = .eq
    · simp [h, cmpNat_succ]
    · rw [ite_eq_right h]
      cases hc : cmpNat x y <;> simp_all

/-- Two numeric identifiers as `prerelease_compare()` compares them: the
longer one above, and `memcmp()` between two of one length. -/
def numCmp (a b : List Nat) : Ordering :=
  if a.length ≠ b.length then (if a.length > b.length then .gt else .lt)
  else memcmp a b

theorem numCmp_eq (a b : List Nat) :
    numCmp a b =
      if a.length = b.length then lex cmpNat a b
      else cmpNat a.length b.length := by
  unfold numCmp
  by_cases h : a.length = b.length
  · simp [h, memcmp_eq_lex a b h]
  · simp only [h, ne_eq, not_false_eq_true, ite_true, ite_false]
    unfold cmpNat
    simp [h]

/-- Numeric identifiers are totally ordered, leading zeros or not. -/
theorem numCmp_total : TotalOrder numCmp where
  eq_iff a b := by
    rw [numCmp_eq]
    by_cases h : a.length = b.length
    · rw [ite_eq_left h]
      exact (lex_total cmpNat_total).eq_iff a b
    · rw [ite_eq_right h, cmpNat_total.eq_iff]
      exact ⟨fun e => absurd e h, fun e => absurd (congrArg List.length e) h⟩
  swap a b := by
    rw [numCmp_eq, numCmp_eq]
    by_cases h : a.length = b.length
    · rw [ite_eq_left h, ite_eq_left h.symm]
      exact (lex_total cmpNat_total).swap a b
    · rw [ite_eq_right h, ite_eq_right (fun e => h e.symm)]
      exact cmpNat_total.swap _ _
  trans a b d hab hbd := by
    rw [numCmp_eq] at hab hbd ⊢
    by_cases h1 : a.length = b.length <;> by_cases h2 : b.length = d.length
    · rw [ite_eq_left h1] at hab
      rw [ite_eq_left h2] at hbd
      rw [ite_eq_left (h1.trans h2)]
      exact (lex_total cmpNat_total).trans _ _ _ hab hbd
    · rw [ite_eq_right h2, cmpNat_lt] at hbd
      rw [ite_eq_right (by omega), cmpNat_lt]
      omega
    · rw [ite_eq_right h1, cmpNat_lt] at hab
      rw [ite_eq_right (by omega), cmpNat_lt]
      omega
    · rw [ite_eq_right h1, cmpNat_lt] at hab
      rw [ite_eq_right h2, cmpNat_lt] at hbd
      rw [ite_eq_right (by omega), cmpNat_lt]
      omega

/-- A byte from `0` to `9`. -/
def isDigit (b : Nat) : Bool := 48 ≤ b && b ≤ 57

/-- `digits(a, na) == na`: every byte of the identifier a digit. -/
def numeric (id : List Nat) : Bool := id.all isDigit

/-- The body of the loop of `prerelease_compare()`: numeric identifiers by
`numCmp`, a numeric one below an alphanumeric one, and alphanumeric
ones by `alnumCmp`. -/
def identCmp (a b : List Nat) : Ordering :=
  if numeric a && numeric b then numCmp a b
  else if numeric a != numeric b then (if numeric a then .lt else .gt)
  else alnumCmp a b

theorem identCmp_eq (a b : List Nat) :
    identCmp a b =
      match numeric a, numeric b with
      | true, true => numCmp a b
      | true, false => .lt
      | false, true => .gt
      | false, false => lex cmpNat a b := by
  unfold identCmp
  cases numeric a <;> cases numeric b <;> simp [alnumCmp_eq_lex]

/-- The identifier layer: identifiers are totally ordered. -/
theorem identCmp_total : TotalOrder identCmp where
  eq_iff a b := by
    rw [identCmp_eq]
    cases ha : numeric a <;> cases hb : numeric b <;> simp only
    · exact (lex_total cmpNat_total).eq_iff a b
    · exact ⟨fun e => (nomatch e), fun e => by subst e; simp_all⟩
    · exact ⟨fun e => (nomatch e), fun e => by subst e; simp_all⟩
    · exact numCmp_total.eq_iff a b
  swap a b := by
    rw [identCmp_eq, identCmp_eq]
    cases ha : numeric a <;> cases hb : numeric b <;> simp only <;>
      first
      | rfl
      | exact (lex_total cmpNat_total).swap a b
      | exact numCmp_total.swap a b
  trans a b d hab hbd := by
    rw [identCmp_eq] at hab hbd ⊢
    cases ha : numeric a <;> cases hb : numeric b <;> cases hd : numeric d <;>
      simp only [ha, hb, hd, reduceCtorEq] at hab hbd ⊢
    · exact (lex_total cmpNat_total).trans _ _ _ hab hbd
    · exact numCmp_total.trans _ _ _ hab hbd

/-- SemVer 11.4.3: a numeric identifier is below an alphanumeric one. -/
theorem identCmp_numeric_alnum (a b : List Nat) (ha : numeric a = true)
    (hb : numeric b = false) : identCmp a b = .lt := by
  rw [identCmp_eq, ha, hb]

/-- SemVer 11.4.2: alphanumeric identifiers compare by their bytes. -/
theorem identCmp_alnum (a b : List Nat) (ha : numeric a = false)
    (hb : numeric b = false) : identCmp a b = lex cmpNat a b := by
  rw [identCmp_eq, ha, hb]

/-! ### Numbers by value -/

/-- More than one digit and the first a `0`, which `semver_parse()` and
`semver_identifiers()` refuse in a number. -/
def leadingZero (ds : List Nat) : Bool := ds.length > 1 && ds.head? == some 48

/-- The value of a digit string, most significant first, as
`Shirudo.Number` reads it. -/
def decimal (ds : List Nat) : Nat := Number.valueFrom 10 0 (ds.map (· - 48))

theorem valueFrom_split (v : Nat) (ds : List Nat) :
    Number.valueFrom 10 v ds =
      v * 10 ^ ds.length + Number.valueFrom 10 0 ds := by
  induction ds generalizing v with
  | nil => simp [Number.valueFrom]
  | cons d ds ih =>
    have h1 : Number.valueFrom 10 v (d :: ds) =
        Number.valueFrom 10 (v * 10 + d) ds := rfl
    have h2 : Number.valueFrom 10 0 (d :: ds) = Number.valueFrom 10 d ds := by
      simp [Number.valueFrom]
    rw [h1, h2, ih, ih d, List.length_cons, Nat.pow_succ, Nat.add_mul,
      Nat.mul_assoc v 10, Nat.mul_comm 10]
    omega

theorem decimal_cons (x : Nat) (xs : List Nat) :
    decimal (x :: xs) = (x - 48) * 10 ^ xs.length + decimal xs := by
  unfold decimal
  rw [List.map_cons]
  have : Number.valueFrom 10 0 ((x - 48) :: xs.map (· - 48)) =
      Number.valueFrom 10 (x - 48) (xs.map (· - 48)) := by
    simp [Number.valueFrom]
  rw [this, valueFrom_split, List.length_map]

theorem decimal_lt (ds : List Nat) (h : numeric ds = true) :
    decimal ds < 10 ^ ds.length := by
  induction ds with
  | nil => simp [decimal, Number.valueFrom]
  | cons x xs ih =>
    simp only [numeric, List.all_cons, Bool.and_eq_true, isDigit,
      decide_eq_true_eq] at h
    have ih' := ih h.2
    rw [decimal_cons, List.length_cons, Nat.pow_succ]
    have h1 : (x - 48 + 1) * 10 ^ xs.length ≤ 10 * 10 ^ xs.length :=
      Nat.mul_le_mul_right _ (by omega)
    have h2 : (x - 48 + 1) * 10 ^ xs.length =
        (x - 48) * 10 ^ xs.length + 10 ^ xs.length :=
      Nat.succ_mul _ _
    rw [Nat.mul_comm (10 ^ xs.length)]
    omega

theorem decimal_ge (x : Nat) (xs : List Nat) (h : 49 ≤ x) :
    10 ^ xs.length ≤ decimal (x :: xs) := by
  rw [decimal_cons]
  have : 1 * 10 ^ xs.length ≤ (x - 48) * 10 ^ xs.length :=
    Nat.mul_le_mul_right _ (by omega)
  omega

theorem lex_digits : ∀ a b : List Nat, numeric a = true → numeric b = true →
    a.length = b.length → lex cmpNat a b = cmpNat (decimal a) (decimal b)
  | [], [], _, _, _ => by simp [lex, decimal, Number.valueFrom, cmpNat_self]
  | [], _ :: _, _, _, h => by simp at h
  | _ :: _, [], _, _, h => by simp at h
  | x :: xs, y :: ys, ha, hb, hl => by
    simp only [numeric, List.all_cons, Bool.and_eq_true, isDigit,
      decide_eq_true_eq] at ha hb
    have hl' : xs.length = ys.length := by simpa using hl
    have ih := lex_digits xs ys ha.2 hb.2 hl'
    have bx := decimal_lt xs ha.2
    have by' := decimal_lt ys hb.2
    rw [← hl'] at by'
    rw [lex_cons, decimal_cons, decimal_cons, ← hl']
    rcases Nat.lt_trichotomy x y with h | h | h
    · have h1 : (x - 48 + 1) * 10 ^ xs.length ≤ (y - 48) * 10 ^ xs.length :=
        Nat.mul_le_mul_right _ (by omega)
      have h2 : (x - 48 + 1) * 10 ^ xs.length =
          (x - 48) * 10 ^ xs.length + 10 ^ xs.length := by
        rw [Nat.add_mul, Nat.one_mul]
      rw [cmpNat_of_lt h, cmpNat_of_lt (by omega)]
      simp
    · subst h
      rw [cmpNat_self, ih]
      simp only [ite_true]
      rcases Nat.lt_trichotomy (decimal xs) (decimal ys) with h | h | h
      · rw [cmpNat_of_lt h, cmpNat_of_lt (by omega)]
      · rw [h, cmpNat_self, cmpNat_self]
      · rw [cmpNat_of_gt h, cmpNat_of_gt (by omega)]
    · have h1 : (y - 48 + 1) * 10 ^ xs.length ≤ (x - 48) * 10 ^ xs.length :=
        Nat.mul_le_mul_right _ (by omega)
      have h2 : (y - 48 + 1) * 10 ^ xs.length =
          (y - 48) * 10 ^ xs.length + 10 ^ xs.length := by
        rw [Nat.add_mul, Nat.one_mul]
      rw [cmpNat_of_gt h, cmpNat_of_gt (by omega)]
      simp

/-- A number as SemVer writes it: digits, at least one, and no leading
zero. -/
def canonical (ds : List Nat) : Bool :=
  !ds.isEmpty && numeric ds && !leadingZero ds

theorem canonical_ge (ds : List Nat) (h : canonical ds = true)
    (hl : 1 < ds.length) : 10 ^ (ds.length - 1) ≤ decimal ds := by
  match ds, h with
  | x :: y :: ys, h =>
    simp [canonical, numeric, leadingZero, isDigit] at h
    have := decimal_ge x (y :: ys) (by omega)
    simpa using this

/-- SemVer 11.4.1: the C's order of two numbers, by length and then by
bytes, is their order by value, for numbers of every length. It holds
only without a leading zero: `01` is longer than `2` and of less value. -/
theorem numCmp_value (a b : List Nat) (ha : canonical a = true)
    (hb : canonical b = true) :
    numCmp a b = cmpNat (decimal a) (decimal b) := by
  have na : numeric a = true := by
    simp only [canonical, Bool.and_eq_true] at ha; exact ha.1.2
  have nb : numeric b = true := by
    simp only [canonical, Bool.and_eq_true] at hb; exact hb.1.2
  have la : 0 < a.length := by
    cases a <;> simp_all [canonical]
  have lb : 0 < b.length := by
    cases b <;> simp_all [canonical]
  rw [numCmp_eq]
  by_cases h : a.length = b.length
  · rw [ite_eq_left h]
    exact lex_digits a b na nb h
  · rw [ite_eq_right h]
    have ua := decimal_lt a na
    have ub := decimal_lt b nb
    rcases Nat.lt_or_gt_of_ne h with h' | h'
    · have vb := canonical_ge b hb (by omega)
      have : 10 ^ a.length ≤ 10 ^ (b.length - 1) :=
        Nat.pow_le_pow_right (by omega) (by omega)
      rw [cmpNat_of_lt h', cmpNat_of_lt (by omega)]
    · have va := canonical_ge a ha (by omega)
      have : 10 ^ b.length ≤ 10 ^ (a.length - 1) :=
        Nat.pow_le_pow_right (by omega) (by omega)
      rw [cmpNat_of_gt h', cmpNat_of_gt (by omega)]

/-! ### Versions -/

/-- The prerelease step of `bpm_semver_compare()`: a version without a
prerelease above one with, `va.pre_len ? -1 : vb.pre_len ? 1 : 0`, and
`prerelease_compare()` between two that have one. -/
def preCmp (pa pb : List (List Nat)) : Ordering :=
  if pa = [] ∨ pb = [] then
    (if pa ≠ [] then .lt else if pb ≠ [] then .gt else .eq)
  else lex identCmp pa pb

/-- The prerelease layer: prereleases are totally ordered, and having none
is above them all. -/
theorem preCmp_total : TotalOrder preCmp where
  eq_iff a b := by
    cases a <;> cases b <;> simp [preCmp, (lex_total identCmp_total).eq_iff]
  swap a b := by
    cases a <;> cases b <;> simp [preCmp, Ordering.swap]
    exact (lex_total identCmp_total).swap _ _
  trans a b d hab hbd := by
    cases a <;> cases b <;> cases d <;> simp_all [preCmp]
    exact (lex_total identCmp_total).trans _ _ _ hab hbd

/-- `strcmp()` on the bytes of two strings, the NUL that ends one below
every byte of the other. -/
def strcmp (a b : List Nat) : Ordering := lex cmpNat a b

/-- What `semver_parse()` makes of a string: a version with its core
numbers, prerelease and build identifiers, or the bytes of a string it
refuses. -/
inductive Version where
  | valid (major minor patch : Nat) (pre build : List (List Nat))
  | invalid (bytes : List Nat)

/-- The version with its build metadata dropped, which precedence ignores. -/
def Version.withoutBuild : Version → Version
  | .valid ma mi pa pre _ => .valid ma mi pa pre []
  | .invalid s => .invalid s

/-- `bpm_semver_compare()`: a string that is not SemVer below a version, two
such strings by `strcmp()`, and two versions by major, minor and patch,
the first that differs deciding, and then by `preCmp`. -/
def semverCompare : Version → Version → Ordering
  | .invalid a, .invalid b => strcmp a b
  | .invalid _, .valid .. => .lt
  | .valid .., .invalid _ => .gt
  | .valid ma na pa ra _, .valid mb nb pb rb _ =>
    match lex cmpNat [ma, na, pa] [mb, nb, pb] with
    | .eq => preCmp ra rb
    | o => o

theorem semverCompare_valid (ma na pa mb nb pb : Nat)
    (ra rb ba bb : List (List Nat)) :
    semverCompare (.valid ma na pa ra ba) (.valid mb nb pb rb bb) =
      thenCmp (lex cmpNat) preCmp ([ma, na, pa], ra) ([mb, nb, pb], rb) :=
  rfl

theorem validTotal : TotalOrder (thenCmp (lex cmpNat) preCmp) :=
  thenCmp_total (lex_total cmpNat_total) preCmp_total

/-- Two versions compare equal exactly when they are equal up to build
metadata, and two refused strings exactly when their bytes are. -/
theorem semverCompare_eq_iff (a b : Version) :
    semverCompare a b = .eq ↔ a.withoutBuild = b.withoutBuild := by
  cases a <;> cases b
  · rw [semverCompare_valid, validTotal.eq_iff]
    simp [Version.withoutBuild, and_assoc]
  · simp [semverCompare, Version.withoutBuild]
  · simp [semverCompare, Version.withoutBuild]
  · simp [semverCompare, strcmp, (lex_total cmpNat_total).eq_iff,
      Version.withoutBuild]

/-- Every version is equal to itself. -/
theorem semverCompare_refl (a : Version) : semverCompare a a = .eq :=
  (semverCompare_eq_iff a a).2 rfl

/-- Swapping the arguments reverses the order. -/
theorem semverCompare_swap (a b : Version) :
    semverCompare a b = (semverCompare b a).swap := by
  cases a <;> cases b
  · simp only [semverCompare_valid]; exact validTotal.swap _ _
  · rfl
  · rfl
  · exact (lex_total cmpNat_total).swap _ _

/-- The order is transitive. -/
theorem semverCompare_trans (a b c : Version) (hab : semverCompare a b = .lt)
    (hbc : semverCompare b c = .lt) : semverCompare a c = .lt := by
  cases a <;> cases b <;> cases c
  case valid.valid.valid =>
    rw [semverCompare_valid] at hab hbc ⊢
    exact validTotal.trans _ _ _ hab hbc
  case invalid.invalid.invalid =>
    exact (lex_total cmpNat_total).trans _ _ _ hab hbc
  all_goals simp only [semverCompare, reduceCtorEq] at hab hbc ⊢

/-- SemVer 11.2: the first of major, minor and patch that differs decides. -/
theorem semverCompare_core (ma na pa mb nb pb : Nat)
    (ra rb ba bb : List (List Nat))
    (h : lex cmpNat [ma, na, pa] [mb, nb, pb] ≠ .eq) :
    semverCompare (.valid ma na pa ra ba) (.valid mb nb pb rb bb) =
      lex cmpNat [ma, na, pa] [mb, nb, pb] := by
  rw [semverCompare_valid]
  unfold thenCmp
  cases hc : lex cmpNat [ma, na, pa] [mb, nb, pb] <;> simp_all

/-- SemVer 11.3: a prerelease is below its release. -/
theorem semverCompare_prerelease (ma na pa : Nat) (r : List Nat)
    (rs ba bb : List (List Nat)) :
    semverCompare (.valid ma na pa (r :: rs) ba) (.valid ma na pa [] bb) =
      .lt := by
  rw [semverCompare_valid]
  simp [thenCmp, (lex_total cmpNat_total).refl, preCmp]

/-- SemVer 11.4.4 for versions: a prerelease is below a longer one it
begins. -/
theorem semverCompare_prerelease_prefix (ma na pa : Nat) (r y : List Nat)
    (rs ys ba bb : List (List Nat)) :
    semverCompare (.valid ma na pa (r :: rs) ba)
      (.valid ma na pa (r :: rs ++ y :: ys) bb) = .lt := by
  rw [semverCompare_valid]
  simp only [thenCmp, (lex_total cmpNat_total).refl, preCmp]
  simp only [List.cons_append, reduceCtorEq, or_self, ite_false]
  rw [← List.cons_append]
  exact lex_prefix identCmp_total (r :: rs) y ys

/-- A string that is not SemVer is below every version. -/
theorem semverCompare_invalid_valid (s : List Nat) (ma na pa : Nat)
    (r b : List (List Nat)) :
    semverCompare (.invalid s) (.valid ma na pa r b) = .lt := rfl

/-! ### Parsing -/

/-- `isalnum()` in the C locale, or `-`: a byte of an identifier. -/
def isIdentByte (b : Nat) : Bool :=
  isDigit b || (65 ≤ b && b ≤ 90) || (97 ≤ b && b ≤ 122) || b == 45

/-- The bytes before the first `sep`, and those after it if there is one. -/
def breakAt (sep : Nat) : List Nat → List Nat × Option (List Nat)
  | [] => ([], none)
  | x :: xs =>
    if x = sep then ([], some xs)
    else (x :: (breakAt sep xs).1, (breakAt sep xs).2)

/-- The pieces between the `sep` bytes: `a.b` gives `a` and `b`, and the
empty string one empty piece. -/
def splitOn (sep : Nat) : List Nat → List (List Nat)
  | [] => [[]]
  | x :: xs =>
    if x = sep then [] :: splitOn sep xs
    else
      match splitOn sep xs with
      | [] => [[x]]
      | id :: ids => (x :: id) :: ids

/-- A core number as `semver_parse()` reads it: digits without a leading
zero, and the value `parse_u64()` gives below 2^64. -/
def numeral (ds : List Nat) : Option Nat :=
  if !ds.isEmpty && numeric ds && !leadingZero ds then
    Number.parse 10 (Number.u64Limit - 1) (ds.map (· - 48))
  else none

/-- One identifier as `semver_identifiers()` takes it: not empty, of
`[0-9A-Za-z-]`, and in a prerelease no number with a leading zero. -/
def identOk (pre : Bool) (id : List Nat) : Bool :=
  !id.isEmpty && id.all isIdentByte && !(pre && numeric id && leadingZero id)

/-- `semver_identifiers()` on a prerelease or build metadata, if the string
has one: the pieces between its dots, each of them taken. -/
def identifiers (pre : Bool) : Option (List Nat) → Option (List (List Nat))
  | none => some []
  | some s =>
    if (splitOn 46 s).all (identOk pre) then some (splitOn 46 s) else none

/-- `semver_parse()`: three numbers between dots, a prerelease after a `-`
and build metadata after a `+`, or the string refused. -/
def semverParse (s : List Nat) : Version :=
  match splitOn 46 (breakAt 45 (breakAt 43 s).1).1 with
  | [x, y, z] =>
    match numeral x, numeral y, numeral z,
      identifiers true (breakAt 45 (breakAt 43 s).1).2,
      identifiers false (breakAt 43 s).2 with
    | some ma, some mi, some pa, some pr, some bu => .valid ma mi pa pr bu
    | _, _, _, _, _ => .invalid s
  | _ => .invalid s

/-- What `semver_parse()` makes sure of in a version it accepts. -/
def Version.WellFormed : Version → Prop
  | .valid ma mi pa pre build =>
    ma < Number.u64Limit ∧ mi < Number.u64Limit ∧ pa < Number.u64Limit ∧
      (∀ id ∈ pre, identOk true id = true) ∧
      (∀ id ∈ build, identOk false id = true)
  | .invalid _ => True

theorem numeral_lt (ds : List Nat) (v : Nat) (h : numeral ds = some v) :
    v < Number.u64Limit := by
  unfold numeral at h
  split at h
  · rw [Number.parse_exact 10 _ _ (by omega) (by simp [Number.u64Limit])] at h
    split at h
    · simp at h; simp [Number.u64Limit] at *; omega
    · simp at h
  · simp at h

theorem identifiers_ok (pre : Bool) (s : Option (List Nat))
    (ids : List (List Nat)) (h : identifiers pre s = some ids) :
    ∀ id ∈ ids, identOk pre id = true := by
  cases s with
  | none => simp [identifiers] at h; subst h; simp
  | some s =>
    simp only [identifiers] at h
    split at h
    · next hall =>
      simp at h; subst h
      exact List.all_eq_true.1 hall
    · simp at h

/-- A refused string keeps its bytes. -/
theorem semverParse_invalid (s t : List Nat) (h : semverParse s = .invalid t) :
    t = s := by
  unfold semverParse at h
  split at h
  · split at h <;> simp_all
  · simp_all

/-- Every version `semverParse` yields is well formed. -/
theorem semverParse_wellFormed (s : List Nat) : (semverParse s).WellFormed := by
  unfold semverParse
  split
  · split
    · simp only [Version.WellFormed]
      exact ⟨numeral_lt _ _ ‹_›, numeral_lt _ _ ‹_›, numeral_lt _ _ ‹_›,
        identifiers_ok _ _ _ ‹_›, identifiers_ok _ _ _ ‹_›⟩
    · trivial
  · trivial

/-- The two parts of `breakAt` put back together. -/
def rejoin (sep : Nat) : List Nat × Option (List Nat) → List Nat
  | (pre, none) => pre
  | (pre, some rest) => pre ++ sep :: rest

theorem rejoin_breakAt (sep : Nat) (s : List Nat) :
    rejoin sep (breakAt sep s) = s := by
  induction s with
  | nil => rfl
  | cons x xs ih =>
    by_cases h : x = sep
    · simp [breakAt, rejoin, h]
    · simp only [breakAt, h, ite_false]
      revert ih
      cases breakAt sep xs with
      | mk p r => cases r <;> simp [rejoin]

/-- The pieces with `sep` between them, which undoes `splitOn`. -/
def joinOn (sep : Nat) : List (List Nat) → List Nat
  | [] => []
  | [x] => x
  | x :: y :: ys => x ++ sep :: joinOn sep (y :: ys)

theorem splitOn_ne_nil (sep : Nat) (s : List Nat) : splitOn sep s ≠ [] := by
  cases s with
  | nil => simp [splitOn]
  | cons x xs =>
    simp only [splitOn]
    split
    · simp
    · split <;> simp

theorem joinOn_cons_cons (sep x : Nat) (id : List Nat) (ids : List (List Nat)) :
    joinOn sep ((x :: id) :: ids) = x :: joinOn sep (id :: ids) := by
  cases ids <;> simp [joinOn]

theorem joinOn_splitOn (sep : Nat) (s : List Nat) :
    joinOn sep (splitOn sep s) = s := by
  induction s with
  | nil => rfl
  | cons x xs ih =>
    by_cases h : x = sep
    · subst h
      have hne := splitOn_ne_nil x xs
      simp only [splitOn, ite_true]
      revert ih hne
      cases splitOn x xs with
      | nil => simp
      | cons id ids => simp [joinOn]
    · simp only [splitOn, h, ite_false]
      have hne := splitOn_ne_nil sep xs
      revert ih hne
      cases splitOn sep xs with
      | nil => simp
      | cons id ids => intro ih _; rw [joinOn_cons_cons, ih]

theorem numeral_some (ds : List Nat) (v : Nat) (h : numeral ds = some v) :
    canonical ds = true ∧ decimal ds = v := by
  unfold numeral at h
  split at h
  · next hc =>
    rw [Number.parse_exact 10 _ _ (by omega) (by simp [Number.u64Limit])] at h
    split at h
    · simp only [Option.some.injEq] at h
      refine ⟨?_, h⟩
      simp only [canonical]
      simpa [Bool.and_comm] using hc
    · simp at h
  · simp at h

theorem numeral_injective (x y : List Nat) (v : Nat) (hx : numeral x = some v)
    (hy : numeral y = some v) : x = y := by
  have ⟨cx, vx⟩ := numeral_some x v hx
  have ⟨cy, vy⟩ := numeral_some y v hy
  have h := numCmp_value x y cx cy
  rw [vx, vy, cmpNat_self] at h
  exact (numCmp_total.eq_iff x y).1 h

theorem identifiers_some (pre : Bool) (s : Option (List Nat))
    (ids : List (List Nat)) (h : identifiers pre s = some ids) :
    s = none ∧ ids = [] ∨ ∃ t, s = some t ∧ ids = splitOn 46 t := by
  cases s with
  | none => simp [identifiers] at h; simp [h]
  | some t =>
    simp only [identifiers] at h
    split at h
    · simp at h; simp [h]
    · simp at h

theorem identifiers_injective (pre : Bool) (s t : Option (List Nat))
    (ids : List (List Nat)) (hs : identifiers pre s = some ids)
    (ht : identifiers pre t = some ids) : s = t := by
  rcases identifiers_some pre s ids hs with ⟨e1, e2⟩ | ⟨s', e1, e2⟩ <;>
    rcases identifiers_some pre t ids ht with ⟨f1, f2⟩ | ⟨t', f1, f2⟩
  · rw [e1, f1]
  · exact absurd (f2.symm.trans e2) (splitOn_ne_nil 46 t')
  · exact absurd (e2.symm.trans f2) (splitOn_ne_nil 46 s')
  · rw [e1, f1, ← joinOn_splitOn 46 s', ← joinOn_splitOn 46 t', ← e2, ← f2]

/-- Whether `semver_parse()` accepted the string. -/
def Version.isValid : Version → Bool
  | .valid .. => true
  | .invalid _ => false

theorem semverParse_valid (s : List Nat) (ma mi pa : Nat)
    (pr bu : List (List Nat)) (h : semverParse s = .valid ma mi pa pr bu) :
    ∃ x y z, splitOn 46 (breakAt 45 (breakAt 43 s).1).1 = [x, y, z] ∧
      numeral x = some ma ∧ numeral y = some mi ∧ numeral z = some pa ∧
      identifiers true (breakAt 45 (breakAt 43 s).1).2 = some pr := by
  unfold semverParse at h
  split at h
  · next x y z hs =>
    split at h
    · next hx hy hz hpr _ =>
      simp only [Version.valid.injEq] at h
      obtain ⟨rfl, rfl, rfl, rfl, rfl⟩ := h
      exact ⟨x, y, z, hs, hx, hy, hz, hpr⟩
    · simp at h
  · simp at h

/-- Numeric identifiers of a prerelease compare by value. -/
theorem identCmp_value (a b : List Nat) (ha : identOk true a = true)
    (hb : identOk true b = true) (na : numeric a = true)
    (nb : numeric b = true) :
    identCmp a b = cmpNat (decimal a) (decimal b) := by
  have ca : canonical a = true := by
    simp_all [identOk, canonical]
  have cb : canonical b = true := by
    simp_all [identOk, canonical]
  rw [identCmp_eq, na, nb]
  exact numCmp_value a b ca cb

/-! ### Version strings -/

/-- `bpm_semver_compare()` on two strings, given as their bytes before the
NUL. -/
def compareStrings (a b : List Nat) : Ordering :=
  semverCompare (semverParse a) (semverParse b)

/-- Every string compares equal to itself. -/
theorem compareStrings_refl (a : List Nat) : compareStrings a a = .eq :=
  semverCompare_refl _

/-- `bpm_semver_compare(a, b)` is `-bpm_semver_compare(b, a)`. -/
theorem compareStrings_swap (a b : List Nat) :
    compareStrings a b = (compareStrings b a).swap :=
  semverCompare_swap _ _

/-- A string below a second that is below a third is below the third. -/
theorem compareStrings_trans (a b c : List Nat)
    (hab : compareStrings a b = .lt) (hbc : compareStrings b c = .lt) :
    compareStrings a c = .lt :=
  semverCompare_trans _ _ _ hab hbc

/-- Two strings compare equal exactly when they make the same version up
to build metadata. -/
theorem compareStrings_eq_iff (a b : List Nat) :
    compareStrings a b = .eq ↔
      (semverParse a).withoutBuild = (semverParse b).withoutBuild :=
  semverCompare_eq_iff _ _

/-- Two strings that are not SemVer compare equal exactly when their bytes
are equal. -/
theorem compareStrings_invalid (a b a' b' : List Nat)
    (ha : semverParse a = .invalid a') (hb : semverParse b = .invalid b') :
    compareStrings a b = .eq ↔ a = b := by
  rw [compareStrings_eq_iff, ha, hb, semverParse_invalid a a' ha,
    semverParse_invalid b b' hb]
  simp [Version.withoutBuild]

/-- Two SemVer strings compare equal exactly when their bytes before the
build metadata are equal. -/
theorem compareStrings_valid (a b : List Nat)
    (ha : (semverParse a).isValid = true)
    (hb : (semverParse b).isValid = true) :
    compareStrings a b = .eq ↔ (breakAt 43 a).1 = (breakAt 43 b).1 := by
  rw [compareStrings_eq_iff]
  cases hpa : semverParse a with
  | invalid _ => simp [hpa, Version.isValid] at ha
  | valid ma mi pa pr bu =>
    cases hpb : semverParse b with
    | invalid _ => simp [hpb, Version.isValid] at hb
    | valid mb nb pb qr qu =>
      obtain ⟨x, y, z, hs, hx, hy, hz, hpr⟩ := semverParse_valid a _ _ _ _ _ hpa
      obtain ⟨x', y', z', hs', hx', hy', hz', hqr⟩ :=
        semverParse_valid b _ _ _ _ _ hpb
      simp only [Version.withoutBuild, Version.valid.injEq, and_true]
      constructor
      · rintro ⟨rfl, rfl, rfl, rfl⟩
        have ex := numeral_injective x x' _ hx hx'
        have ey := numeral_injective y y' _ hy hy'
        have ez := numeral_injective z z' _ hz hz'
        subst ex; subst ey; subst ez
        have hcore : (breakAt 45 (breakAt 43 a).1).1 =
            (breakAt 45 (breakAt 43 b).1).1 := by
          rw [← joinOn_splitOn 46 (breakAt 45 (breakAt 43 a).1).1,
            ← joinOn_splitOn 46 (breakAt 45 (breakAt 43 b).1).1, hs, hs']
        have hpre := identifiers_injective true _ _ _ hpr hqr
        rw [← rejoin_breakAt 45 (breakAt 43 a).1,
          ← rejoin_breakAt 45 (breakAt 43 b).1]
        revert hcore hpre
        cases breakAt 45 (breakAt 43 a).1
        cases breakAt 45 (breakAt 43 b).1
        intro hcore hpre
        simp only at hcore hpre
        rw [hcore, hpre]
      · intro hmain
        rw [hmain] at hs hpr
        rw [hs] at hs'
        simp only [List.cons.injEq, and_true] at hs'
        obtain ⟨rfl, rfl, rfl⟩ := hs'
        rw [hx] at hx'; rw [hy] at hy'; rw [hz] at hz'; rw [hpr] at hqr
        simp only [Option.some.injEq] at hx' hy' hz' hqr
        exact ⟨hx', hy', hz', hqr⟩

end Shirudo.SemVer
