-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

/-!
The number parsers of rust/src/text.rs, `parse_base()` of util/string.c
before the port to Rust. Each reads the digits most significant first and refuses with `-ERANGE` once the value would reach
2^64 or pass `max`. For digit strings of every length it yields exactly
the value they spell, or that refusal when the value passes `max`.
-/

namespace Shirudo.Number

/-- 2^64, the first value a `__u64` cannot hold. -/
def u64Limit : Nat := 18446744073709551616

/-- The value of the digits `ds`, read most significant first onto `v`. -/
def valueFrom (base v : Nat) (ds : List Nat) : Nat :=
  ds.foldl (fun v d => v * base + d) v

/-- One digit of `parse_base()`: the checked multiply and add, then `max`. -/
def step (base max : Nat) : Option Nat → Nat → Option Nat
  | none, _ => none
  | some v, d =>
    if v * base + d < u64Limit ∧ v * base + d ≤ max then
      some (v * base + d)
    else
      none

/-- `parse_base()` on the digit values `ds`; `none` is `-ERANGE`. -/
def parse (base max : Nat) (ds : List Nat) : Option Nat :=
  ds.foldl (step base max) (some 0)

theorem foldl_none (base max : Nat) (ds : List Nat) :
    ds.foldl (step base max) none = none := by
  induction ds with
  | nil => rfl
  | cons d ds ih => simpa [List.foldl, step] using ih

theorem valueFrom_ge (base v : Nat) (ds : List Nat) (hb : 0 < base) :
    v ≤ valueFrom base v ds := by
  induction ds generalizing v with
  | nil => simp [valueFrom]
  | cons d ds ih =>
    have hm : v ≤ v * base := Nat.le_mul_of_pos_right v hb
    have hrest := ih (v * base + d)
    simp only [valueFrom, List.foldl] at hrest ⊢
    omega

theorem parseFrom (base max v : Nat) (ds : List Nat) (hb : 0 < base)
    (hmax : max < u64Limit) (hv : v ≤ max) :
    ds.foldl (step base max) (some v) =
      if valueFrom base v ds ≤ max then some (valueFrom base v ds)
      else none := by
  induction ds generalizing v with
  | nil => simp [valueFrom, hv]
  | cons d ds ih =>
    have hnext : valueFrom base v (d :: ds) =
        valueFrom base (v * base + d) ds := rfl
    rw [hnext]
    by_cases h : v * base + d ≤ max
    · have hs : step base max (some v) d = some (v * base + d) := by
        simp [step, h, Nat.lt_of_le_of_lt h hmax]
      simp only [List.foldl, hs]
      exact ih (v * base + d) h
    · have hs : step base max (some v) d = none := by
        simp [step, h]
      simp only [List.foldl, hs, foldl_none]
      have hge := valueFrom_ge base (v * base + d) ds hb
      have hgt : ¬ valueFrom base (v * base + d) ds ≤ max := by omega
      simp [hgt]

/-- The value of an accepted number, or `-ERANGE` exactly when it passes
`max`, for digit strings of every length and every `max` a `__u64` holds. -/
theorem parse_exact (base max : Nat) (ds : List Nat) (hb : 0 < base)
    (hmax : max < u64Limit) :
    parse base max ds =
      if valueFrom base 0 ds ≤ max then some (valueFrom base 0 ds)
      else none :=
  parseFrom base max 0 ds hb hmax (Nat.zero_le _)

end Shirudo.Number
