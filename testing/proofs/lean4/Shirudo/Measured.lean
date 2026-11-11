-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

/-!
The measured set of rust/src/util/measured.rs: the upatches the eventlog
records as loaded, each with the payload of its load.
`eventlog_upatches()` and `eventlog_boot_upatches()` of
rust/src/util/eventlog/ walk the records in order and call
`measured_event()` for each load and unload they measure: an init record
gives `EVENTLOG_UPATCH_INIT`, which starts the set over, then a load for
each upatch of its set, an `upatch_load` record a load and an
`upatch_unload` record an unload. The walk stops at the first error, and
`measured_set_log()` and `measured_set_boot()` fail with it.

`measured_event()` keeps the set in an array: a load overwrites the
payload of the entry of its name, or appends one and refuses a 4097th
with `-ENOSPC`, and refuses with `-EINVAL` what does not fit an entry; an
unload moves the last entry into the place of the one of its name.
`measured_holds()` looks for an entry of a name and payload. `init`
restores an archive only when the set holds its name and payload, and
`status` and the next upatch command undo a pin or an archive it does
not hold.

The model follows `measured_event()` statement by statement on a list for
the array, its length for `s->n`. For every sequence of events the fold
accepts, the set holds each name at most once (`measuredSet_nodup`), and
holds a name with a payload exactly when the last event that bears on
the name, an init or a load or unload of it, is a load of it with that
payload (`holds_iff`): an upatch is in the set when its last load is
followed by neither an unload of it nor an init record, with that load's
payload, whatever payload the unload names. An init record starts the
set over (`measuredSet_init`): what comes before it changes the set only
by failing, so `measured_set_log()` gives the set of the last init on.
`Record.events` is what `upatches_line()` makes of each record shirudo
writes, a set only in an init record.
-/

namespace Shirudo.Measured

/-- `MEASURED_MAX` of rust/src/util/measured.rs. -/
def measuredMax : Nat := 4096

/-- `UPATCH_NAME_MAX`: an entry's name holds this many bytes and a NUL. -/
def nameMax : Nat := 256

/-- `2 * UPATCH_PAYLOAD_HASH_LEN`: the payload's hex digits an entry
holds before its NUL. -/
def payloadHexMax : Nat := 64

/-- `enum eventlog_upatch_event` with the name and payload hex the walk
passes; a C string is its bytes before the NUL. -/
inductive Event where
  | init
  | load (name payloadHex : List UInt8)
  | unload (name payloadHex : List UInt8)
deriving DecidableEq

/-- `struct measured_entry`. -/
structure Entry where
  name : List UInt8
  payloadHex : List UInt8
deriving DecidableEq

/-- The errors `measured_event()` returns. -/
inductive Error where
  | nospc
  | inval
deriving DecidableEq

/-- The loop of `measured_event()` that looks for `name`: the index of the
first entry of that name, or `s->n` when there is none. -/
def find (s : List Entry) (name : List UInt8) : Nat :=
  s.findIdx fun e => e.name == name

/-- `s->entries[i] = s->entries[--s->n]`. -/
def swapRemove (s : List Entry) (i : Nat) : List Entry :=
  match s.getLast? with
  | some last => (s.set i last).dropLast
  | none => s

/-- `measured_event()`. -/
def measuredEvent (s : List Entry) : Event → Except Error (List Entry)
  | .init => .ok []
  | .unload name _ =>
    if find s name < s.length then .ok (swapRemove s (find s name))
    else .ok s
  | .load name payloadHex =>
    if find s name = s.length ∧ s.length = measuredMax then .error .nospc
    else if nameMax < name.length ∨ payloadHexMax < payloadHex.length then
      .error .inval
    else if find s name < s.length then
      .ok (s.set (find s name) ⟨name, payloadHex⟩)
    else .ok (s ++ [⟨name, payloadHex⟩])

/-- `measured_set_fold()`: the events in order from an empty set, stopping
at the first error. -/
def measuredSet (events : List Event) : Except Error (List Entry) :=
  events.foldlM measuredEvent []

/-- `measured_holds()`. -/
def measuredHolds (s : List Entry) (name payloadHex : List UInt8) : Bool :=
  s.any fun e => e.name == name && e.payloadHex == payloadHex

/-- Whether an event bears on `name`: an init, which starts the set over,
or a load or an unload of that name. -/
def Event.about (name : List UInt8) : Event → Bool
  | .init => true
  | .load n _ => n == name
  | .unload n _ => n == name

/-- The last of `events` that bears on `name`. -/
def lastAbout (name : List UInt8) (events : List Event) : Option Event :=
  (events.filter (Event.about name)).getLast?

/-! ### The array operations -/

theorem find_lt_iff (s : List Entry) (name : List UInt8) :
    find s name < s.length ↔ ∃ e ∈ s, e.name = name := by
  simp [find, List.findIdx_lt_length]

theorem find_name {s : List Entry} {name : List UInt8}
    (h : find s name < s.length) : s[find s name].name = name := by
  have := List.findIdx_getElem (w := h)
  simp only [beq_iff_eq] at this
  exact this

/-- The entry `find()` stops at splits the array. -/
theorem find_split {s : List Entry} {name : List UInt8}
    (h : find s name < s.length) :
    ∃ pre x post, s = pre ++ x :: post ∧ pre.length = find s name ∧
      x.name = name :=
  ⟨s.take (find s name), s[find s name], s.drop (find s name + 1),
    by rw [← List.drop_eq_getElem_cons h, List.take_append_drop],
    by simp [Nat.min_eq_left (Nat.le_of_lt h)],
    find_name h⟩

theorem set_split (pre post : List Entry) (x v : Entry) :
    (pre ++ x :: post).set pre.length v = pre ++ v :: post := by
  simp

theorem swapRemove_split (pre post : List Entry) (x : Entry) :
    (swapRemove (pre ++ x :: post) pre.length).Perm (pre ++ post) := by
  rcases List.eq_nil_or_concat post with rfl | ⟨post', last, rfl⟩
  · simp [swapRemove]
  · simp only [List.concat_eq_append, swapRemove]
    have hl : (pre ++ x :: (post' ++ [last])).getLast? = some last := by
      rw [← List.cons_append, ← List.append_assoc]
      simp only [List.getLast?_append, List.getLast?_singleton, Option.some_or]
    simp only [hl]
    rw [set_split]
    have hd : (pre ++ last :: (post' ++ [last])).dropLast =
        pre ++ last :: post' := by
      rw [← List.cons_append, ← List.append_assoc, List.dropLast_concat]
    rw [hd, ← List.append_assoc]
    exact List.perm_middle.trans (List.perm_append_singleton _ _).symm

theorem nodup_split {pre post : List Entry} {x : Entry}
    (h : ((pre ++ x :: post).map Entry.name).Nodup) :
    ((pre ++ post).map Entry.name).Nodup ∧
      ∀ y ∈ pre ++ post, y.name ≠ x.name := by
  have hp := (List.perm_middle (a := x) (l₁ := pre) (l₂ := post)).map
    Entry.name
  rw [hp.nodup_iff, List.map_cons, List.nodup_cons] at h
  refine ⟨h.2, fun y hy hyx => h.1 ?_⟩
  exact List.mem_map.mpr ⟨y, hy, hyx⟩

theorem mem_split_ne {pre post : List Entry} {x y : Entry}
    (hne : y.name ≠ x.name) : y ∈ pre ++ x :: post ↔ y ∈ pre ++ post := by
  simp only [List.mem_append, List.mem_cons]
  constructor
  · rintro (h | rfl | h)
    · exact Or.inl h
    · exact absurd rfl hne
    · exact Or.inr h
  · rintro (h | h)
    · exact Or.inl h
    · exact Or.inr (Or.inr h)

theorem nodup_split_set {pre post : List Entry} {x v : Entry}
    (h : ((pre ++ x :: post).map Entry.name).Nodup) (hv : v.name = x.name) :
    ((pre ++ v :: post).map Entry.name).Nodup := by
  simpa [hv] using h

/-! ### One event -/

/-- What `measured_event()` does to the set: names stay distinct, and the
set holds a name with a payload afterwards exactly when the event bears
on the name and is a load of it with that payload, or does not bear on
it and the set held them before. -/
theorem measuredEvent_spec {s s' : List Entry} {e : Event}
    (hnd : (s.map Entry.name).Nodup) (h : measuredEvent s e = .ok s') :
    (s'.map Entry.name).Nodup ∧
      ∀ name p, ⟨name, p⟩ ∈ s' ↔
        if e.about name then e = .load name p else ⟨name, p⟩ ∈ s := by
  cases e with
  | init =>
    simp only [measuredEvent, Except.ok.injEq] at h
    subst h
    simp [Event.about]
  | unload n q =>
    simp only [measuredEvent] at h
    by_cases hf : find s n < s.length
    · simp only [hf, ite_true, Except.ok.injEq] at h
      obtain ⟨pre, x, post, hs, hlen, hx⟩ := find_split hf
      rw [← hlen, hs] at h
      subst h
      subst hs
      have hp := swapRemove_split pre post x
      obtain ⟨hnd', hne⟩ := nodup_split hnd
      refine ⟨(hp.map Entry.name).nodup_iff.mpr hnd', fun name p => ?_⟩
      rw [hp.mem_iff]
      by_cases hn : n = name
      · subst hn
        simp only [Event.about, beq_self_eq_true, ite_true, reduceCtorEq,
          iff_false]
        exact fun hm => hne _ hm hx.symm
      · have hb : (n == name) = false := by simpa using hn
        simp only [Event.about, hb, Bool.false_eq_true, ite_false]
        exact (mem_split_ne (by simp; rw [hx]; exact Ne.symm hn)).symm
    · simp only [hf, ite_false, Except.ok.injEq] at h
      subst h
      refine ⟨hnd, fun name p => ?_⟩
      by_cases hn : n = name
      · subst hn
        simp only [Event.about, beq_self_eq_true, ite_true, reduceCtorEq,
          iff_false]
        exact fun hm => hf ((find_lt_iff _ _).mpr ⟨_, hm, rfl⟩)
      · have hb : (n == name) = false := by simpa using hn
        simp [Event.about, hb]
  | load n q =>
    simp only [measuredEvent] at h
    split at h
    · cases h
    split at h
    · cases h
    by_cases hf : find s n < s.length
    · simp only [hf, ite_true, Except.ok.injEq] at h
      obtain ⟨pre, x, post, hs, hlen, hx⟩ := find_split hf
      rw [← hlen, hs, set_split] at h
      subst h
      subst hs
      obtain ⟨_, hne⟩ := nodup_split hnd
      refine ⟨nodup_split_set hnd (by simp [hx]), fun name p => ?_⟩
      by_cases hn : n = name
      · subst hn
        simp only [Event.about, beq_self_eq_true, ite_true, Event.load.injEq,
          true_and]
        rw [List.mem_append, List.mem_cons, Entry.mk.injEq]
        constructor
        · rintro (hm | ⟨-, rfl⟩ | hm)
          · exact absurd hx.symm (hne _ (List.mem_append_left _ hm))
          · rfl
          · exact absurd hx.symm (hne _ (List.mem_append_right _ hm))
        · rintro rfl
          exact Or.inr (Or.inl ⟨rfl, rfl⟩)
      · have hb : (n == name) = false := by simpa using hn
        simp only [Event.about, hb, Bool.false_eq_true, ite_false]
        rw [mem_split_ne (by simp; exact Ne.symm hn),
          mem_split_ne (by simp; rw [hx]; exact Ne.symm hn)]
    · simp only [hf, ite_false, Except.ok.injEq] at h
      subst h
      have hnone : ∀ x ∈ s, x.name ≠ n := fun x hx hxn =>
        hf ((find_lt_iff _ _).mpr ⟨x, hx, hxn⟩)
      refine ⟨?_, fun name p => ?_⟩
      · rw [List.map_append, List.nodup_append]
        refine ⟨hnd, by simp, ?_⟩
        intro a ha b hb
        simp only [List.map_cons, List.map_nil, List.mem_singleton] at hb
        obtain ⟨x, hx, rfl⟩ := List.mem_map.mp ha
        rw [hb]
        exact hnone x hx
      · rw [List.mem_append, List.mem_singleton]
        by_cases hn : n = name
        · subst hn
          have : (⟨n, p⟩ : Entry) ∉ s := fun hm => hnone _ hm rfl
          simp [Event.about, this, eq_comm]
        · have hb : (n == name) = false := by simpa using hn
          simp [Event.about, hb, Ne.symm hn]

/-! ### The fold -/

theorem measuredSet_append (es : List Event) (e : Event) :
    measuredSet (es ++ [e]) = measuredSet es >>= fun s => measuredEvent s e :=
  by simp [measuredSet, List.foldlM_append]

theorem lastAbout_append (name : List UInt8) (es : List Event) (e : Event) :
    lastAbout name (es ++ [e]) =
      if e.about name then some e else lastAbout name es := by
  unfold lastAbout
  rw [List.filter_append]
  by_cases h : e.about name <;> simp [h, List.getLast?_append]

/-- For every sequence of events the fold accepts, the set it gives holds
each name at most once, and holds a name with a payload exactly when the
last event bearing on the name is a load of it with that payload. -/
theorem measuredSet_spec :
    ∀ (events : List Event) (s : List Entry), measuredSet events = .ok s →
      (s.map Entry.name).Nodup ∧
        ∀ name p, ⟨name, p⟩ ∈ s ↔ lastAbout name events = some (.load name p)
  := by
  intro events
  rw [← List.reverse_reverse events]
  induction events.reverse with
  | nil =>
    intro s h
    simp only [List.reverse_nil, measuredSet, List.foldlM_nil, pure,
      Except.pure, Except.ok.injEq] at h
    subst h
    simp [lastAbout]
  | cons e rs ih =>
    intro s h
    rw [List.reverse_cons] at h ⊢
    generalize rs.reverse = es at h ih ⊢
    rw [measuredSet_append] at h
    cases hes : measuredSet es with
    | error err => simp [hes, Except.bind, bind] at h
    | ok s0 =>
      simp only [hes] at h
      obtain ⟨hnd0, hmem0⟩ := ih s0 hes
      obtain ⟨hnd, hstep⟩ := measuredEvent_spec hnd0 h
      refine ⟨hnd, fun name p => ?_⟩
      rw [hstep, lastAbout_append]
      by_cases ha : e.about name
      · simp [ha]
      · simp [ha, hmem0]

/-- Each upatch appears in the measured set once at most. -/
theorem measuredSet_nodup {events : List Event} {s : List Entry}
    (h : measuredSet events = .ok s) : (s.map Entry.name).Nodup :=
  (measuredSet_spec events s h).1

theorem measuredHolds_iff (s : List Entry) (name p : List UInt8) :
    measuredHolds s name p = true ↔ ⟨name, p⟩ ∈ s := by
  simp only [measuredHolds, List.any_eq_true, Bool.and_eq_true, beq_iff_eq]
  constructor
  · rintro ⟨⟨n, q⟩, hm, rfl, rfl⟩
    exact hm
  · intro hm
    exact ⟨_, hm, rfl, rfl⟩

/-- What `init` relies on to restore an archive: `measured_holds()` finds a
name and payload in the set exactly when the last event that bears on the
name, a load or an unload of it or an init record, is a load of it with
that payload. -/
theorem holds_iff {events : List Event} {s : List Entry}
    (h : measuredSet events = .ok s) (name p : List UInt8) :
    measuredHolds s name p = true ↔
      lastAbout name events = some (.load name p) := by
  rw [measuredHolds_iff]
  exact (measuredSet_spec events s h).2 name p

theorem lastAbout_tail (name : List UInt8) (pre post : List Event) (e : Event)
    (he : e.about name = true) (hpost : ∀ x ∈ post, x.about name = false) :
    lastAbout name (pre ++ e :: post) = some e := by
  unfold lastAbout
  have : post.filter (Event.about name) = [] :=
    List.filter_eq_nil_iff.mpr (fun x hx => by simp [hpost x hx])
  simp [List.filter_append, he, this]

/-- A load that no later unload of its upatch and no later init record
follows is in the set with its payload. -/
theorem holds_last_load {pre post : List Event} {s : List Entry}
    {name p : List UInt8} (h : measuredSet (pre ++ .load name p :: post) = .ok s)
    (hpost : ∀ x ∈ post, x.about name = false) :
    measuredHolds s name p = true :=
  (holds_iff h name p).mpr (lastAbout_tail name pre post _ (by simp [Event.about])
    hpost)

/-- After an unload of an upatch, which no later load of it follows, the
set holds it with no payload, whatever payload the unload names. -/
theorem not_holds_after_unload {pre post : List Event} {s : List Entry}
    {name q : List UInt8}
    (h : measuredSet (pre ++ .unload name q :: post) = .ok s)
    (hpost : ∀ x ∈ post, x.about name = false) (p : List UInt8) :
    measuredHolds s name p = false := by
  have hl := lastAbout_tail name pre post (.unload name q)
    (by simp [Event.about]) hpost
  cases hh : measuredHolds s name p
  · rfl
  · rw [holds_iff h, hl] at hh
    cases hh

/-- An init record starts the set over: the events before it change the
set only by failing. -/
theorem measuredSet_init (pre post : List Event) :
    measuredSet (pre ++ .init :: post) =
      measuredSet pre >>= fun _ => measuredSet post := by
  simp only [measuredSet, List.foldlM_append, List.foldlM_cons, measuredEvent]
  cases List.foldlM measuredEvent [] pre <;> rfl

/-- The events `upatches_line()` gives for each record shirudo writes. -/
inductive Record where
  | init (set : List (List UInt8 × List UInt8))
  | upatchLoad (name payloadHex : List UInt8)
  | upatchUnload (name payloadHex : List UInt8)
  | other

def Record.events : Record → List Event
  | .init set => .init :: set.map fun m => .load m.1 m.2
  | .upatchLoad n p => [.load n p]
  | .upatchUnload n p => [.unload n p]
  | .other => []

/-- `measured_set_log()` over a log of records: the set holds an upatch
with a payload exactly when the last init record, load or unload that
bears on it is its load with that payload, or an init record that lists
it, last with that payload. -/
theorem holds_records {records : List Record} {s : List Entry}
    (h : measuredSet (records.flatMap Record.events) = .ok s)
    (name p : List UInt8) :
    measuredHolds s name p = true ↔
      lastAbout name (records.flatMap Record.events) = some (.load name p) :=
  holds_iff h name p

end Shirudo.Measured
