-- SPDX-License-Identifier: BSD-2-Clause
-- Copyright (c) 2026 Authors of shirudo

import Shirudo.Chain

/-!
`bpm tree sync`, `cmd_bpm_tree_sync()` of builtin-bpm.c. It reads the
node's state, fetches a signed tree publication, refuses one that
`TreePublication::parse()`, `publication_check()`, `operation_validate()` or
`publication_follows()` refuses, cuts the outcomes record to the cursor,
runs `tree_recover_pending()` and writes the state with the publication's
generation, manifest digest and head. Then, for each operation past the
cursor that its selector matches, it writes `pending.json`, installs the
upatch, extends the register and records the `tree_op` event, appends a line
to the tree eventlog and one to the outcomes record, writes the state with
the new cursor and projection root and unlinks `pending.json`; one the
selector does not match gets its outcome line and moves the cursor. At the
end it writes the state again, for the cursor a run of unmatched operations
moved.

The model describes the Rust sync step by step: a node is its five files, a sync the
list of writes it makes, each atomic, and a crash or a refusal after some of
them the writes before it. Root picks every input: any publication the
node's key signed, in any manifest a registry wraps it in, the selector's
answers, where each sync stops, and reboots, which start this boot's
records afresh. `Later` orders every two points of the node's history,
those inside one sync included.

For every such history the node never goes back: the generation and the
cursor never decrease and the tree eventlog only grows (`generation_mono`,
`lastSeq_mono`, `log_grows`); at an equal generation only the recorded
manifest is held (`manifest_fixed`); a publication of an earlier generation
than one the node accepted is refused (`accepted_older_refused`). Each
operation is applied at most once, in increasing order, in the tree eventlog
and in this boot's records (`log_increasing`, `measured_increasing`). After a
crash between writing `pending.json` and committing the state, recovery
appends the pending operation exactly when this boot measured it or its line
is there, at most once, and otherwise leaves the cursor below it
(`recover_pending`); nothing measured is lost (`measured_kept`). The state is
the fold of the operations the tree eventlog records, but in the window
between appending a line and writing the state (`state_is_fold`), which
recovery closes (`recover_settles`). Every applied operation is one of a
signed publication of the node's tree (`applied_signed`), and the one every
such publication has at its number when the signer never gives a number two
operations (`applied_consistent`). The outcomes record has a line for every
operation from 1 to the cursor, in order (`outcomes_cover`), no line at or
below the cursor ever changes (`outcomes_fixed`), and the cursor never passes
the head of the recorded publication (`lastSeq_le_head`). And the node can
always go on: given a checked publication that follows it and holds its
pending operation when that is above the cursor, recovery refuses nothing
(`recover_progress`) and the sync runs to its end, recording the
publication's head as the cursor whatever the selector says
(`sync_progress`).

The generation rests on the generation check of `Follows`, on the parse
refusing a negative generation, and on a manifest digest naming one
publication. The cursor
and the order rest on the loop's own cursor check and recovery's; that each
operation is applied once rests on recovery's comparison of the replayed
root and on its look at this boot's records, with the hash injective,
an idealized hash (see `Assumptions`). The outcomes record rests on the
order of the writes, a line before the state that covers it, on the cut
at the start of a sync, on recovery writing the lines of the operations
the stopped sync passed over, and on `publication_check()` numbering the
operations without a gap;
the head on the state written at acceptance and on the cursor check of
`Follows`. The parent check of `Follows` is not needed by any of these
theorems. `Assumptions` states what the code cannot show.

The model also assumes what review of the C shows: only sync writes these
files, which the seal ensures; a write is whole or absent, as
`seal::write_file()` renames and `append_line()` drops a line it did not
finish, and `outcome_append()` appends the same way, with every reader
of the record skipping a last line without its newline; syncs run one at a
time under the BPM lock; the unlink of
`pending.json`, whose result sync ignores, succeeds; and an extend with its
eventlog record is one write, as a stop between them leaves the register
ahead of the log. Installing or removing the upatch writes nothing the model
holds: it succeeds or stops the sync. A stop after an install and before its
measure leaves the operation pending and unmeasured, so the next sync
applies it again, and that goes on to measure it: `upatch_install()` takes
the payload already loaded under the name as installed, and
`upatch_remove()` an upatch already gone as removed.
The CBMC harnesses for the former C tree implementation were removed
when that implementation moved to Rust. This model remains a review
reference for the Rust implementation.

A publication that starts past the cursor is a segment the node reaches by
walking back through the sealed segments before it. The sync then takes
the segments oldest first, each recorded at acceptance and its operations
applied, as `run` takes one publication: the oldest segment with the cut
of the outcomes record and recovery, and each later one, which starts at
the cursor the one before left, with neither. Such a sync is close to a
sync of each segment in turn: it leaves out the state `run` writes at the
end of a segment, which the next segment's record at acceptance
overwrites with the same cursor and root, and the cut of each later
segment, which would keep every line. It differs in two ways no `Step`
takes: a pending record an earlier segment's loop passed over stays until
the next sync's recovery removes it, where a sync of the next segment
would remove it at once, and a sync whose walk back refuses has already
cut the outcomes record to the cursor, without a publication that follows
the node. `Step` has no walk, so the theorems here cover a sync that walks
only by that argument, not by proof; `walk_same_ops` shows that the
segments apply the operations the unsegmented tree applies, in its order,
with the same records. The base check and the prefix check of the walk
only refuse more; the model leaves them out, as it does the digest
checks.
-/

namespace Shirudo.TreeSync
open Shirudo

/-! ### What the node and a publication hold -/

/-- An operation of `struct tree_operation`, as far as sync reads it: its
sequence number, upatch name and operation digest, the 32 bytes
`sha256_digest_decode()` takes from its `sha256:` string. The pending record,
`struct tree_pending`, holds the same three fields. -/
structure Op (I D : Type) where
  seq : Int
  id : I
  digest : D
deriving DecidableEq

/-- `struct tree_publication`; `parent` is `none` for an empty
`parent_manifest_digest`. -/
structure Pub (T M I D : Type) where
  treeId : T
  generation : Int
  parent : Option M
  baseSeq : Int
  ops : List (Op I D)
  headSeq : Int

/-- `struct tree_state`: `root` is `projection_root`, which sync writes into
`projection_root_tpm` too, `manifest` is `none` for an empty
`manifest_digest`, and `headSeq` is `head_seq`, the head of the recorded
publication. `segment_base_seq` is left out: no write of the model depends
on it. -/
structure State (T M D : Type) where
  treeId : T
  generation : Int
  lastSeq : Int
  root : D
  manifest : Option M
  headSeq : Int

/-- A line `event_append()` adds to the tree eventlog. -/
structure Line (D : Type) where
  seq : Int
  digest : D
  root : D

/-- A line `outcome_append()` adds to the outcomes record: the
operation's number, whether its selector matched, and the projection root
after it. `matched` is outcome 1 or 3, which the install's answer tells
apart and no write of the model depends on, and its absence outcome 2. The
line's history root is left out: it is a fold over the operations' digests
alone, as `Shirudo.Chain.history_ignores_outcomes` shows. -/
structure OLine (D : Type) where
  seq : Int
  matched : Bool
  root : D

/-- What sync reads and writes on the node: `state.json`, `pending.json`, the
tree eventlog, oldest line first, the `tree_op` records of this boot's
eventlog, the ones `eventlog_tree_op_measured()` reads, and the outcomes
record, oldest line first. `none` and `[]` are files that do not exist. -/
structure Node (T M I D : Type) where
  state : Option (State T M D)
  pending : Option (Op I D)
  log : List (Line D)
  measured : List (Int × D)
  outcomes : List (OLine D)

/-- The writes of a sync, each atomic: `pending_write()`, the extend and
eventlog record of `tree_measure_operation()`, `event_append()`,
`outcome_append()`, `state_write()`, the unlink of `pending.json` and
`outcomes_resume()`, which keeps the first `k` lines. -/
inductive Write (T M I D : Type) where
  | pending (o : Op I D)
  | measure (seq : Int) (d : D)
  | append (l : Line D)
  | outcome (l : OLine D)
  | state (s : State T M D)
  | unlink
  | truncate (k : Nat)

variable {T M I D : Type}

/-- The node after one write. -/
def Write.apply : Write T M I D → Node T M I D → Node T M I D
  | .pending o, n => { n with pending := some o }
  | .measure s d, n => { n with measured := n.measured ++ [(s, d)] }
  | .append l, n => { n with log := n.log ++ [l] }
  | .outcome l, n => { n with outcomes := n.outcomes ++ [l] }
  | .state s, n => { n with state := some s }
  | .unlink, n => { n with pending := none }
  | .truncate k, n => { n with outcomes := n.outcomes.take k }

/-- The node after the writes `ws`, in order. -/
def applyAll (ws : List (Write T M I D)) (n : Node T M I D) : Node T M I D :=
  ws.foldl (fun n w => w.apply n) n

/-- The node before its first sync. -/
def Node.empty : Node T M I D := ⟨none, none, [], [], []⟩

/-- The cursor the run starts from: the state's, 0 without one. -/
def cursor (n : Node T M I D) : Int :=
  match n.state with
  | some s => s.lastSeq
  | none => 0

/-! ### The checks before anything is applied -/

/-- What `TreePublication::parse()` and `publication_check()` require of a
publication's numbers: a generation of 0 or more, a base of 0 or more, and
operations numbered from base + 1 to head without a gap. A segment past
the first, base above 0, is one of these too; the keys that name its
sealed predecessor and its history root are left out with the digests. -/
def Checked (pub : Pub T M I D) : Prop :=
  0 ≤ pub.generation ∧ 0 ≤ pub.baseSeq ∧
    pub.headSeq = pub.baseSeq + pub.ops.length ∧
    pub.ops.map (·.seq) =
      (List.range pub.ops.length).map
        (fun i : Nat => pub.baseSeq + 1 + (i : Int))

instance (pub : Pub T M I D) : Decidable (Checked pub) := by
  unfold Checked; infer_instance

/-- What the sync takes of `publication_follows()`, a return of 0,
as represented by `Follows` here. A publication that starts past the cursor,
for which the function asks for a walk, is applied as the segments of the
walk, each of which returns 0 in its turn; see `run`. Without a state, a
base of 0; with
one, the same tree, a later generation unless it is the same manifest, the
recorded manifest as parent when it is the next generation and names one,
and the cursor between base and head. -/
def Follows [DecidableEq T] [DecidableEq M] (pub : Pub T M I D) :
    Option (State T M D) → M → Prop
  | none, _ => pub.baseSeq = 0
  | some s, m =>
    s.treeId = pub.treeId ∧
    (s.manifest = some m ∨ s.generation < pub.generation) ∧
    (s.manifest = some m ∨ pub.generation ≠ s.generation + 1 ∨
      pub.parent = none ∨ pub.parent = s.manifest) ∧
    pub.baseSeq ≤ s.lastSeq ∧ s.lastSeq ≤ pub.headSeq

instance [DecidableEq T] [DecidableEq M] (pub : Pub T M I D)
    (st : Option (State T M D)) (m : M) : Decidable (Follows pub st m) := by
  cases st <;> unfold Follows <;> infer_instance

section hash
variable (H : D → D → D) (init : D)

/-- The projection root of the lines `log`: it starts at 64 zeros, `init`,
and each operation takes it to `SHA256(root ‖ digest)`. -/
def rootOf (log : List (Line D)) : D :=
  (log.map (·.digest)).foldl H init

/-- The root of the lines `log` with one more line. -/
theorem rootOf_append (log : List (Line D)) (l : Line D) :
    rootOf H init (log ++ [l]) = H (rootOf H init log) l.digest := by
  simp [rootOf, List.foldl_append]

/-- No operation leaves the projection root where it was, so a root tells
whether the line of an operation is there, for the idealized hash of
`Chain.register_injective`, injective on every (root, digest) pair. -/
theorem rootOf_ne_next (hH : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (hinit : ∀ a b, H a b ≠ init) (log : List (Line D)) (d : D) :
    rootOf H init log ≠ H (rootOf H init log) d := by
  intro h
  have hr : ∀ L : List (Line D),
      rootOf H init L = Chain.register H init (L.map (·.digest)).reverse := by
    intro L
    rw [Chain.register_eq_foldl, List.reverse_reverse]
    rfl
  rw [hr] at h
  have h' : Chain.register H init (log.map (·.digest)).reverse =
      Chain.register H init (d :: (log.map (·.digest)).reverse) := h
  have := Chain.register_injective H init hH hinit _ _ h'
  have hl := congrArg List.length this
  simp at hl

end hash

/-! ### Runs stopped after any write -/

/-- `P` holds of the node before each write of `ws` and after the last,
and `R` of the node before and after each write. -/
def Along (P : Node T M I D → Prop) (R : Node T M I D → Node T M I D → Prop) :
    List (Write T M I D) → Node T M I D → Prop
  | [], n => P n
  | w :: ws, n => P n ∧ R n (w.apply n) ∧ Along P R ws (w.apply n)

theorem applyAll_nil (n : Node T M I D) : applyAll [] n = n := rfl

theorem applyAll_cons (w : Write T M I D) (ws : List (Write T M I D))
    (n : Node T M I D) :
    applyAll (w :: ws) n = applyAll ws (w.apply n) := rfl

theorem applyAll_append (ws ws' : List (Write T M I D)) (n : Node T M I D) :
    applyAll (ws ++ ws') n = applyAll ws' (applyAll ws n) := by
  simp [applyAll, List.foldl_append]

theorem along_first {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop}
    {ws : List (Write T M I D)} {n : Node T M I D} (h : Along P R ws n) :
    P n := by
  cases ws <;> simp only [Along] at h
  · exact h
  · exact h.1

/-- `P` holds wherever the writes stop. -/
theorem along_take {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop}
    {ws : List (Write T M I D)} {n : Node T M I D} (h : Along P R ws n)
    (k : Nat) :
    P (applyAll (ws.take k) n) := by
  induction ws generalizing n k with
  | nil => simp only [List.take_nil]; exact h
  | cons w ws ih =>
    cases k with
    | zero => exact along_first h
    | succ k =>
      simp only [Along] at h
      simpa [applyAll_cons] using ih h.2.2 k

/-- A relation that holds across each write, reflexive and transitive,
holds from any point of the writes to any later one. -/
theorem along_between {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop}
    (hrefl : ∀ x, R x x) (htrans : ∀ a b c, R a b → R b c → R a c)
    {ws : List (Write T M I D)} {n : Node T M I D} (h : Along P R ws n) :
    ∀ i j, i ≤ j → R (applyAll (ws.take i) n) (applyAll (ws.take j) n) := by
  induction ws generalizing n with
  | nil => intro i j _; simp only [List.take_nil]; exact hrefl _
  | cons w ws ih =>
    simp only [Along] at h
    intro i j hij
    cases i with
    | zero =>
      cases j with
      | zero => exact hrefl _
      | succ j =>
        simp only [List.take_zero, List.take_succ_cons, applyAll_cons]
        exact htrans _ _ _ h.2.1 (ih h.2.2 0 j (Nat.zero_le _))
    | succ i =>
      cases j with
      | zero => omega
      | succ j =>
        simp only [List.take_succ_cons, applyAll_cons]
        exact ih h.2.2 i j (by omega)

theorem along_append {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop}
    {ws ws' : List (Write T M I D)} {n : Node T M I D} (h : Along P R ws n)
    (h' : Along P R ws' (applyAll ws n)) : Along P R (ws ++ ws') n := by
  induction ws generalizing n with
  | nil => exact h'
  | cons w ws ih =>
    simp only [Along] at h ⊢
    exact ⟨h.1, h.2.1, ih h.2.2 h'⟩

theorem along_nil {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop} {n : Node T M I D} (h : P n) :
    Along P R [] n := by
  simp only [Along]
  exact h

theorem along_cons {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop} {w : Write T M I D}
    {ws : List (Write T M I D)} {n : Node T M I D} (h0 : P n)
    (hR : R n (w.apply n)) (h : Along P R ws (w.apply n)) :
    Along P R (w :: ws) n := by
  simp only [Along]
  exact ⟨h0, hR, h⟩

theorem along_one {P : Node T M I D → Prop}
    {R : Node T M I D → Node T M I D → Prop} {w : Write T M I D}
    {n : Node T M I D} (h0 : P n) (hR : R n (w.apply n)) (h1 : P (w.apply n)) :
    Along P R [w] n :=
  along_cons h0 hR (along_nil h1)

/-! ### The tree eventlog -/

section replay
variable [DecidableEq D] (H : D → D → D) (init : D)

/-- The loop of `event_replay()`, from the previous line's sequence
number and the chain: each line above the one before, and the root it
records the chain. -/
def replayFrom : Int → D → List (Line D) → Option (Int × D)
  | s, c, [] => some (s, c)
  | s, c, l :: ls =>
    if s < l.seq ∧ l.root = H c l.digest then replayFrom l.seq (H c l.digest) ls
    else none

/-- What `event_replay()` returns: `-ENOENT`, `-EINVAL` or the root. -/
inductive Replay (D : Type) where
  | missing
  | bad
  | ok (root : D)

/-- `event_replay()`. sync never writes an empty tree eventlog, and
`append_line()` drops a line an append did not finish, so the lines it
appended are what the file holds. -/
def replay : List (Line D) → Replay D
  | [] => .missing
  | l :: ls =>
    match replayFrom H 0 init (l :: ls) with
    | some (_, r) => .ok r
    | none => .bad

theorem replayFrom_append (s : Int) (c : D) (ls : List (Line D)) (l : Line D) :
    replayFrom H s c (ls ++ [l]) =
      match replayFrom H s c ls with
      | some (t, r) =>
        if t < l.seq ∧ l.root = H r l.digest then some (l.seq, H r l.digest)
        else none
      | none => none := by
  induction ls generalizing s c with
  | nil => simp [replayFrom]
  | cons x xs ih =>
    simp only [List.cons_append, replayFrom]
    split
    · exact ih _ _
    · rfl

/-- A replay that succeeds returns the root of the lines, and their
numbers rise from above where it started to where it ends. -/
theorem replayFrom_some {s : Int} {c : D} {ls : List (Line D)} {t : Int} {r : D}
    (h : replayFrom H s c ls = some (t, r)) :
    r = (ls.map (·.digest)).foldl H c ∧ s ≤ t ∧ (t = s ∨ ∃ l ∈ ls, l.seq = t) ∧
      (∀ l ∈ ls, s < l.seq ∧ l.seq ≤ t) ∧
      (ls.map (·.seq)).Pairwise (· < ·) := by
  induction ls generalizing s c with
  | nil =>
    simp [replayFrom] at h
    obtain ⟨rfl, rfl⟩ := h
    simp
  | cons x xs ih =>
    simp only [replayFrom] at h
    split at h
    · rename_i hx
      obtain ⟨h1, h2, h3, h4, h5⟩ := ih h
      refine ⟨by simpa using h1, by omega, ?_, ?_, ?_⟩
      · rcases h3 with h3 | ⟨l, hl, hlt⟩
        · exact Or.inr ⟨x, by simp, h3.symm⟩
        · exact Or.inr ⟨l, by simp [hl], hlt⟩
      · intro l hl
        simp only [List.mem_cons] at hl
        rcases hl with rfl | hl
        · exact ⟨hx.1, h2⟩
        · have := h4 l hl; omega
      · simp only [List.map_cons, List.pairwise_cons, List.mem_map]
        refine ⟨?_, h5⟩
        rintro _ ⟨l, hl, rfl⟩
        exact (h4 l hl).1
    · simp at h

/-- The tree eventlog replays. -/
def Replays (log : List (Line D)) : Prop :=
  ∃ x, replayFrom H 0 init log = some x

theorem replays_nil : Replays H init ([] : List (Line D)) := ⟨_, rfl⟩

theorem replays_seq {log : List (Line D)} (h : Replays H init log) :
    (∀ l ∈ log, 0 < l.seq) ∧ (log.map (·.seq)).Pairwise (· < ·) := by
  obtain ⟨⟨t, r⟩, h⟩ := h
  have := replayFrom_some H h
  exact ⟨fun l hl => (this.2.2.2.1 l hl).1, this.2.2.2.2⟩

theorem replays_append {log : List (Line D)} {l : Line D}
    (h : Replays H init log)
    (hlt : ∀ x ∈ log, x.seq < l.seq) (hpos : 0 < l.seq)
    (hroot : l.root = H (rootOf H init log) l.digest) :
    Replays H init (log ++ [l]) := by
  obtain ⟨⟨t, r⟩, h⟩ := h
  obtain ⟨h1, -, h3, -, -⟩ := replayFrom_some H h
  have ht : t < l.seq := by
    rcases h3 with h3 | ⟨x, hx, rfl⟩
    · omega
    · exact hlt x hx
  refine ⟨(l.seq, H r l.digest), ?_⟩
  rw [replayFrom_append, h]
  have : l.root = H r l.digest := by rw [hroot, h1]; rfl
  simp [ht, this]

theorem replay_ok {log : List (Line D)} (h : Replays H init log)
    (hne : log ≠ []) :
    replay H init log = .ok (rootOf H init log) := by
  obtain ⟨⟨t, r⟩, h⟩ := h
  have h1 := (replayFrom_some H h).1
  cases log with
  | nil => exact absurd rfl hne
  | cons x xs =>
    simp only [replay, h, h1]
    rfl

end replay

/-! ### The lines of the outcomes record -/

/-- `tree_outcomes_passed()`: the lines of the operations between the cursor
`lo` and the pending operation's number `hi`, which the sync that stopped
passed over, each with the projection root it left where it was. -/
def passed (lo hi : Int) (root : D) : List (Op I D) → List (OLine D)
  | [] => []
  | o :: os =>
    if hi ≤ o.seq then []
    else if o.seq ≤ lo then passed lo hi root os
    else ⟨o.seq, false, root⟩ :: passed lo hi root os

/-- The lines `tree_recover_pending()` appends once the pending operation
`p` is applied, from the state `st` it starts from: those of the operations
passed over, then the operation's own. -/
def recLines (H : D → D → D) (pub : Pub T M I D) (st : State T M D)
    (p : Op I D) : List (OLine D) :=
  passed st.lastSeq p.seq st.root pub.ops ++ [⟨p.seq, true, H st.root p.digest⟩]

/-- How recovery completes an applied operation: its lines, the state and
the unlink of `pending.json`. -/
def complete (ls : List (OLine D)) (st : State T M D) : List (Write T M I D) :=
  ls.map Write.outcome ++ [.state st, .unlink]

section sync
variable [DecidableEq T] [DecidableEq M] [DecidableEq I] [DecidableEq D]
variable (H : D → D → D) (init : D)

/-- The state `cmd_bpm_tree_sync()` starts from when the node has none. -/
def fresh (t : T) : State T M D := ⟨t, 0, 0, init, none, 0⟩

/-- `tree_recover_pending()`: the writes it makes and the state the loop
goes on from, or `none` for a refusal before it writes anything. Every
refusal after a write stops the run as a crash there does. A pending
operation at or below the cursor is removed before the publication is
looked at, as the cursor was committed past it and the publication may no
longer hold it. An operation it finds applied gets its outcome lines
before the state that covers them. -/
def recover (n : Node T M I D) (pub : Pub T M I D) (st : State T M D) :
    Option (List (Write T M I D) × State T M D) :=
  match n.pending with
  | none => some ([], st)
  | some p =>
    if p.seq ≤ st.lastSeq then some ([.unlink], st)
    else
      match pub.ops.find?
          (fun o => o.seq = p.seq ∧ o.id = p.id ∧ o.digest = p.digest) with
      | none => none
      | some o =>
        let next := H st.root p.digest
        let st' := { st with root := next, lastSeq := o.seq }
        let unapplied :=
          if (o.seq, o.digest) ∈ n.measured then
            some (.append ⟨o.seq, o.digest, next⟩ ::
              complete (recLines H pub st p) st', st')
          else some ([], st)
        match replay H init n.log with
        | .missing => unapplied
        | .bad => none
        | .ok r =>
          if r = next then some (complete (recLines H pub st p) st', st')
          else if r = st.root then unapplied
          else none

/-- The loop of `cmd_bpm_tree_sync()` over the operations, with `sel` what
`selector_matches()` says of each: the writes and the state it ends
with. An operation at or below the cursor is passed over, one the selector
does not match gets its outcome line and moves the cursor in memory, and one
it does is applied, its outcome line written before its state. -/
def loop (sel : Op I D → Bool) :
    State T M D → List (Op I D) → List (Write T M I D) × State T M D
  | st, [] => ([], st)
  | st, o :: os =>
    if o.seq ≤ st.lastSeq then loop sel st os
    else if sel o then
      let st' := { st with root := H st.root o.digest, lastSeq := o.seq }
      let r := loop sel st' os
      ([.pending o, .measure o.seq o.digest,
        .append ⟨o.seq, o.digest, H st.root o.digest⟩,
        .outcome ⟨o.seq, true, H st.root o.digest⟩, .state st',
        .unlink] ++ r.1,
        r.2)
    else
      let r := loop sel { st with lastSeq := o.seq } os
      ([.outcome ⟨o.seq, false, st.root⟩] ++ r.1, r.2)

/-- One `bpm tree sync` of the publication `pub`, fetched with the manifest
digest `m`, run to its end: the writes it makes, in order. A publication it
accepts has the outcomes record cut to the cursor first, and is recorded
with its head once recovery is done and before the loop: `acc` is the state
`cmd_bpm_tree_sync()` writes at acceptance. The check that the record covers
the cursor is not a branch here: `outcomes_cover` shows that no node a
history of syncs leaves fails it. -/
def run (n : Node T M I D) (pub : Pub T M I D) (m : M) (sel : Op I D → Bool) :
    List (Write T M I D) :=
  if Checked pub ∧ Follows pub n.state m then
    .truncate (cursor n).toNat ::
      match recover H init n pub (n.state.getD (fresh init pub.treeId)) with
      | none => []
      | some (ws, st) =>
        let acc := { st with generation := pub.generation, manifest := some m,
                             headSeq := pub.headSeq }
        let r := loop H sel acc pub.ops
        let last := { r.2 with generation := pub.generation, manifest := some m }
        ws ++ [.state acc] ++ r.1 ++ [.state last]
  else []

/-- What can happen to the node between two moments: a sync of a
publication the node verifies, stopped after any of its writes, or a
reboot, which starts this boot's records afresh. `Signed pub m` holds of a
publication signed by the key the node trusts, fetched with any manifest
digest `m` a registry wraps it in. -/
inductive Step (Signed : Pub T M I D → M → Prop) :
    Node T M I D → Node T M I D → Prop where
  | sync {n : Node T M I D} {pub : Pub T M I D} {m : M} (sel : Op I D → Bool)
      (k : Nat) : Signed pub m →
      Step Signed n (applyAll ((run H init n pub m sel).take k) n)
  | reboot {n : Node T M I D} : Step Signed n { n with measured := [] }

/-- Any number of steps. -/
inductive Steps (Signed : Pub T M I D → M → Prop) :
    Node T M I D → Node T M I D → Prop where
  | refl (n : Node T M I D) : Steps Signed n n
  | tail {n n' n'' : Node T M I D} :
      Steps Signed n n' → Step H init Signed n' n'' → Steps Signed n n''

end sync

/-! ### What every reachable node keeps -/

/-- The `(seq, digest)` of each line, as a `tree_op` record holds them. -/
def events (log : List (Line D)) : List (Int × D) :=
  log.map fun l => (l.seq, l.digest)

/-- This boot's `tree_op` records are the last lines of the tree eventlog:
the operations applied since the boot began. -/
def Suffix (log : List (Line D)) (meas : List (Int × D)) : Prop :=
  ∃ L1 L2, log = L1 ++ L2 ∧ meas = events L2

/-- From `n` to `n'` nothing went back: the tree eventlog only grew, and the
state, once there, kept its tree, raised neither its generation nor its
cursor less than it had, and changed its manifest only with a later
generation. -/
structure Mono (n n' : Node T M I D) : Prop where
  log : ∃ L, n'.log = n.log ++ L
  state : ∀ s, n.state = some s → ∃ s', n'.state = some s' ∧
    s'.treeId = s.treeId ∧
    s.generation ≤ s'.generation ∧ s.lastSeq ≤ s'.lastSeq ∧
    (s'.generation = s.generation →
      s.manifest = none ∨ s'.manifest = s.manifest)

theorem Mono.refl (n : Node T M I D) : Mono n n :=
  ⟨⟨[], by simp⟩, fun s hs => ⟨s, hs, rfl, Int.le_refl _, Int.le_refl _,
    fun _ => Or.inr rfl⟩⟩

theorem Mono.trans {a b c : Node T M I D} (h1 : Mono a b) (h2 : Mono b c) :
    Mono a c := by
  refine ⟨?_, ?_⟩
  · obtain ⟨L, hL⟩ := h1.log
    obtain ⟨L', hL'⟩ := h2.log
    exact ⟨L ++ L', by rw [hL', hL, List.append_assoc]⟩
  · intro s hs
    obtain ⟨s', hs', ht, hg, hl, hm⟩ := h1.state s hs
    obtain ⟨s'', hs'', ht', hg', hl', hm'⟩ := h2.state s' hs'
    refine ⟨s'', hs'', ht'.trans ht, Int.le_trans hg hg', Int.le_trans hl hl',
      fun he => ?_⟩
    have e1 : s'.generation = s.generation := by omega
    have e2 : s''.generation = s'.generation := by omega
    rcases hm e1 with h | h
    · exact Or.inl h
    · rcases hm' e2 with h' | h'
      · rw [← h]; exact Or.inl h'
      · exact Or.inr (h'.trans h)

/-- A write that leaves the state alone and appends to the tree eventlog at
most. -/
theorem Mono.of_state {n n' : Node T M I D} (hs : n'.state = n.state)
    (hl : ∃ L, n'.log = n.log ++ L) : Mono n n' :=
  ⟨hl, fun s h => ⟨s, hs.trans h, rfl, Int.le_refl _, Int.le_refl _,
    fun _ => Or.inr rfl⟩⟩

/-- Two nodes that differ in the outcomes record at most, which nothing
above reads. -/
structure Same (n n' : Node T M I D) : Prop where
  state : n'.state = n.state
  pending : n'.pending = n.pending
  log : n'.log = n.log
  measured : n'.measured = n.measured

theorem cursor_of_state {n n' : Node T M I D} (hs : n'.state = n.state) :
    cursor n' = cursor n := by
  unfold cursor
  rw [hs]

theorem Mono.of_same {n n' : Node T M I D} (h : Same n n') : Mono n n' :=
  Mono.of_state h.state ⟨[], by rw [h.log, List.append_nil]⟩

/-- Outcome lines change the outcomes record alone. -/
theorem same_outcomes : ∀ (ls : List (OLine D)) (n : Node T M I D),
    Same n (applyAll (ls.map Write.outcome) n)
  | [], _ => ⟨rfl, rfl, rfl, rfl⟩
  | l :: ls, n =>
    have h := same_outcomes ls ((Write.outcome l).apply n)
    ⟨h.state, h.pending, h.log, h.measured⟩

/-- Completing an operation leaves the tree eventlog and this boot's
records as they were. -/
theorem complete_core (ls : List (OLine D)) (s : State T M D)
    (n : Node T M I D) :
    (applyAll (complete ls s) n).log = n.log ∧
      (applyAll (complete ls s) n).measured = n.measured := by
  unfold complete
  rw [applyAll_append]
  exact ⟨(same_outcomes ls n).log, (same_outcomes ls n).measured⟩

section inv
variable [DecidableEq D] (H : D → D → D) (init : D)

/-- The projection root of the node's state, 64 zeros without one. -/
def rootAt (n : Node T M I D) : D :=
  match n.state with
  | some s => s.root
  | none => init

/-- The state is the fold of the tree eventlog, and its cursor at or past
every line of it. -/
def Clean (n : Node T M I D) : Prop :=
  rootAt init n = rootOf H init n.log ∧ ∀ l ∈ n.log, l.seq ≤ cursor n

/-- Where a run stopped, as far as the pending operation goes: the state
is the fold of the tree eventlog and this boot's records are its last
lines, with `pending.json` behind the cursor, or ahead of it and not yet
measured; or the pending operation is measured as well; or its line is
appended too, and the state not yet written. -/
def Window (n : Node T M I D) : Prop :=
  (Clean H init n ∧ Suffix n.log n.measured) ∨
  (∃ p, n.pending = some p ∧ cursor n < p.seq ∧ Clean H init n ∧
    ∃ L1 L2, n.log = L1 ++ L2 ∧ n.measured = events L2 ++ [(p.seq, p.digest)]) ∨
  (∃ p L0, n.pending = some p ∧ cursor n < p.seq ∧
    n.log = L0 ++ [⟨p.seq, p.digest, H (rootOf H init L0) p.digest⟩] ∧
    rootAt init n = rootOf H init L0 ∧ (∀ l ∈ L0, l.seq ≤ cursor n) ∧
    Suffix n.log n.measured)

/-- What every node a sync can leave holds: its tree eventlog replays, the
cursor is not negative, a recorded manifest is that of a signed
publication of the recorded generation, every line is an operation of a
signed publication of the recorded tree, without a state every line is
the pending operation's, and the window it stopped in. -/
structure Inv (Signed : Pub T M I D → M → Prop) (n : Node T M I D) : Prop where
  replays : Replays H init n.log
  cursor_nonneg : 0 ≤ cursor n
  bound : ∀ s m, n.state = some s → s.manifest = some m →
    ∃ p, Signed p m ∧ p.generation = s.generation
  applied : ∀ s, n.state = some s → ∀ l ∈ n.log, ∃ p m, Signed p m ∧
    p.treeId = s.treeId ∧ ∃ o ∈ p.ops, o.seq = l.seq ∧ o.digest = l.digest
  stateless : n.state = none → ∀ l ∈ n.log,
    ∃ p, n.pending = some p ∧ l.seq = p.seq ∧ l.digest = p.digest
  window : Window H init n

/-- Between two operations of the loop, the node `n` and the state `st`
the run holds: the node is clean, `st` its state with the cursor moved past
skipped operations, of the publication's tree, and recording `pub` with
`m` at the end goes forward. -/
structure LoopRel (Signed : Pub T M I D → M → Prop) (pub : Pub T M I D) (m : M)
    (n : Node T M I D) (st : State T M D) : Prop where
  replays : Replays H init n.log
  cursor_nonneg : 0 ≤ cursor n
  bound : ∀ s m, n.state = some s → s.manifest = some m →
    ∃ p, Signed p m ∧ p.generation = s.generation
  applied : ∀ s, n.state = some s → ∀ l ∈ n.log, ∃ p m, Signed p m ∧
    p.treeId = s.treeId ∧ ∃ o ∈ p.ops, o.seq = l.seq ∧ o.digest = l.digest
  clean : Clean H init n
  suffix : Suffix n.log n.measured
  root : st.root = rootAt init n
  le : cursor n ≤ st.lastSeq
  agree : ∀ s, n.state = some s →
    s.treeId = st.treeId ∧ s.generation = st.generation ∧
    s.manifest = st.manifest
  nolog : n.state = none → n.log = []
  tree : st.treeId = pub.treeId
  signed : Signed pub m
  gen : st.generation ≤ pub.generation ∧
    (pub.generation = st.generation → st.manifest = none ∨ st.manifest = some m)
  stBound : ∀ m', st.manifest = some m' →
    ∃ p, Signed p m' ∧ p.generation = st.generation

theorem LoopRel.inv {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D}
    (h : LoopRel H init Signed pub m n st) : Inv H init Signed n :=
  ⟨h.replays, h.cursor_nonneg, h.bound, h.applied,
    fun hs => by simp [h.nolog hs], Or.inl ⟨h.clean, h.suffix⟩⟩

theorem Inv.empty (Signed : Pub T M I D → M → Prop) :
    Inv H init Signed Node.empty :=
  ⟨replays_nil H init, by simp [cursor, Node.empty], by simp [Node.empty],
    by simp [Node.empty], by simp [Node.empty],
    Or.inl ⟨⟨by simp [rootAt, rootOf, Node.empty], by simp [Node.empty]⟩,
      [], [], by simp [Node.empty], by simp [Node.empty, events]⟩⟩

end inv

/-! ### The outcomes record changes nothing above -/

theorem rootAt_of_state {init : D} {n n' : Node T M I D}
    (hs : n'.state = n.state) : rootAt init n' = rootAt init n := by
  unfold rootAt
  rw [hs]

theorem Clean.of_same [DecidableEq D] {H : D → D → D} {init : D}
    {n n' : Node T M I D} (hs : Same n n') (h : Clean H init n) :
    Clean H init n' := by
  unfold Clean at h ⊢
  rw [rootAt_of_state hs.state, hs.log, cursor_of_state hs.state]
  exact h

theorem clean_eq [DecidableEq D] {H : D → D → D} {init : D}
    {n n' : Node T M I D} (hs : Same n n') :
    Clean H init n' = Clean H init n := by
  unfold Clean
  rw [rootAt_of_state hs.state, hs.log, cursor_of_state hs.state]

theorem Window.of_same [DecidableEq D] {H : D → D → D} {init : D}
    {n n' : Node T M I D} (hs : Same n n') (h : Window H init n) :
    Window H init n' := by
  unfold Window at h ⊢
  rw [clean_eq hs, hs.pending, hs.log, hs.measured, cursor_of_state hs.state,
    rootAt_of_state hs.state]
  exact h

theorem Inv.of_same [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} {n n' : Node T M I D} (hs : Same n n')
    (h : Inv H init Signed n) : Inv H init Signed n' where
  replays := by rw [hs.log]; exact h.replays
  cursor_nonneg := by rw [cursor_of_state hs.state]; exact h.cursor_nonneg
  bound := by rw [hs.state]; exact h.bound
  applied := by rw [hs.state, hs.log]; exact h.applied
  stateless := by rw [hs.state, hs.log, hs.pending]; exact h.stateless
  window := Window.of_same hs h.window

theorem LoopRel.of_same [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} {pub : Pub T M I D} {m : M}
    {n n' : Node T M I D} {st : State T M D}
    (h : LoopRel H init Signed pub m n st) (hs : Same n n') :
    LoopRel H init Signed pub m n' st where
  replays := by rw [hs.log]; exact h.replays
  cursor_nonneg := by rw [cursor_of_state hs.state]; exact h.cursor_nonneg
  bound := by rw [hs.state]; exact h.bound
  applied := by rw [hs.state, hs.log]; exact h.applied
  clean := Clean.of_same hs h.clean
  suffix := by rw [hs.log, hs.measured]; exact h.suffix
  root := by rw [rootAt_of_state hs.state]; exact h.root
  le := by rw [cursor_of_state hs.state]; exact h.le
  agree := by rw [hs.state]; exact h.agree
  nolog := by rw [hs.state, hs.log]; exact h.nolog
  tree := h.tree
  signed := h.signed
  gen := h.gen
  stBound := h.stBound

/-- Outcome lines, stopped after any of them. -/
theorem along_outcomes [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} :
    ∀ (ls : List (OLine D)) (n : Node T M I D), Inv H init Signed n →
      Along (Inv H init Signed) Mono (ls.map Write.outcome) n
  | [], _, hinv => along_nil hinv
  | l :: ls, n, hinv =>
    have hsm : Same n ((Write.outcome l).apply n) := ⟨rfl, rfl, rfl, rfl⟩
    along_cons hinv (Mono.of_same hsm)
      (along_outcomes ls ((Write.outcome l).apply n) (Inv.of_same hsm hinv))

/-! ### A sync keeps the invariant and goes forward -/

section loop
variable [DecidableEq D] (H : D → D → D) (init : D)

/-- The state written after an operation's line, then `pending.json`
unlinked: the end of an applied operation, in the loop and in recovery. -/
theorem commit {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D} {o : Op I D} {L0 : List (Line D)}
    (hinv : Inv H init Signed n)
    (hlog : n.log = L0 ++ [⟨o.seq, o.digest, H st.root o.digest⟩])
    (hroot : st.root = rootOf H init L0) (hbelow : ∀ l ∈ L0, l.seq ≤ st.lastSeq)
    (hgt : st.lastSeq < o.seq) (hsuf : Suffix n.log n.measured)
    (happ : ∀ l ∈ n.log, ∃ p m, Signed p m ∧ p.treeId = st.treeId ∧
      ∃ o' ∈ p.ops, o'.seq = l.seq ∧ o'.digest = l.digest)
    (hle : cursor n ≤ st.lastSeq)
    (hagree : ∀ s, n.state = some s →
      s.treeId = st.treeId ∧ s.generation = st.generation ∧
      s.manifest = st.manifest)
    (htree : st.treeId = pub.treeId) (hsigned : Signed pub m)
    (hgen : st.generation ≤ pub.generation ∧
      (pub.generation = st.generation →
        st.manifest = none ∨ st.manifest = some m))
    (hstb : ∀ m', st.manifest = some m' →
      ∃ p, Signed p m' ∧ p.generation = st.generation) :
    Along (Inv H init Signed) Mono
      [.state ⟨st.treeId, st.generation, o.seq, H st.root o.digest,
          st.manifest, st.headSeq⟩,
        .unlink] n ∧
      LoopRel H init Signed pub m
        (applyAll [.state ⟨st.treeId, st.generation, o.seq, H st.root o.digest,
          st.manifest, st.headSeq⟩, .unlink] n)
        ⟨st.treeId, st.generation, o.seq, H st.root o.digest, st.manifest,
          st.headSeq⟩ := by
  simp only [Along, applyAll, List.foldl, Write.apply]
  have hcur0 := hinv.cursor_nonneg
  have hclean : ∀ q, Clean H init (⟨some ⟨st.treeId, st.generation, o.seq,
      H st.root o.digest, st.manifest, st.headSeq⟩, q, n.log, n.measured,
      n.outcomes⟩ :
        Node T M I D) := by
    intro q
    refine ⟨?_, ?_⟩
    · show H st.root o.digest = _
      rw [hlog, rootOf_append, hroot]
    · intro l hl
      show l.seq ≤ o.seq
      rw [hlog] at hl
      rcases List.mem_append.1 hl with hl | hl
      · have := hbelow l hl; omega
      · simp only [List.mem_singleton] at hl; subst hl; exact Int.le_refl _
  have hmono' : ∀ q, Mono n (⟨some ⟨st.treeId, st.generation, o.seq,
      H st.root o.digest, st.manifest, st.headSeq⟩, q, n.log, n.measured,
      n.outcomes⟩ :
        Node T M I D) := by
    intro q
    refine ⟨⟨[], by simp⟩, fun s hs =>
      ⟨_, rfl, (hagree s hs).1.symm, ?_, ?_, fun _ => ?_⟩⟩
    · exact Int.le_of_eq (hagree s hs).2.1
    · have : cursor n = s.lastSeq := by simp [cursor, hs]
      show s.lastSeq ≤ o.seq
      omega
    · exact Or.inr (hagree s hs).2.2.symm
  have hinv' : ∀ q, Inv H init Signed (⟨some ⟨st.treeId, st.generation, o.seq,
      H st.root o.digest, st.manifest, st.headSeq⟩, q, n.log, n.measured,
      n.outcomes⟩ :
        Node T M I D) := by
    intro q
    refine ⟨hinv.replays, by show 0 ≤ o.seq; omega, ?_, ?_, by simp,
      Or.inl ⟨hclean q, hsuf⟩⟩
    · intro s m' hs hm
      simp only [Option.some.injEq] at hs
      subst hs
      exact hstb m' hm
    · intro s hs
      simp only [Option.some.injEq] at hs
      subst hs
      exact happ
  refine ⟨⟨hinv, hmono' _, hinv' _, Mono.of_state rfl ⟨[], by simp⟩,
    hinv' _⟩, ?_⟩
  obtain ⟨-, hc', hb', ha', -, -⟩ := hinv' none
  exact ⟨hinv.replays, hc', hb', ha', hclean none, hsuf, rfl, Int.le_refl _,
    fun s hs => by
      simp only [Option.some.injEq] at hs; subst hs; exact ⟨rfl, rfl, rfl⟩,
    by simp, htree, hsigned, hgen, hstb⟩

/-- `commit` from a node that differs from the one its facts are stated of
in the outcomes record alone: the operation's outcome line goes in between
its tree eventlog line and its state. -/
theorem commit' {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n0 n : Node T M I D} {st : State T M D} {o : Op I D} {L0 : List (Line D)}
    (hs : Same n0 n) (hinv : Inv H init Signed n0)
    (hlog : n0.log = L0 ++ [⟨o.seq, o.digest, H st.root o.digest⟩])
    (hroot : st.root = rootOf H init L0) (hbelow : ∀ l ∈ L0, l.seq ≤ st.lastSeq)
    (hgt : st.lastSeq < o.seq) (hsuf : Suffix n0.log n0.measured)
    (happ : ∀ l ∈ n0.log, ∃ p m, Signed p m ∧ p.treeId = st.treeId ∧
      ∃ o' ∈ p.ops, o'.seq = l.seq ∧ o'.digest = l.digest)
    (hle : cursor n0 ≤ st.lastSeq)
    (hagree : ∀ s, n0.state = some s →
      s.treeId = st.treeId ∧ s.generation = st.generation ∧
      s.manifest = st.manifest)
    (htree : st.treeId = pub.treeId) (hsigned : Signed pub m)
    (hgen : st.generation ≤ pub.generation ∧
      (pub.generation = st.generation →
        st.manifest = none ∨ st.manifest = some m))
    (hstb : ∀ m', st.manifest = some m' →
      ∃ p, Signed p m' ∧ p.generation = st.generation) :
    Along (Inv H init Signed) Mono
      [.state ⟨st.treeId, st.generation, o.seq, H st.root o.digest,
          st.manifest, st.headSeq⟩,
        .unlink] n ∧
      LoopRel H init Signed pub m
        (applyAll [.state ⟨st.treeId, st.generation, o.seq, H st.root o.digest,
          st.manifest, st.headSeq⟩, .unlink] n)
        ⟨st.treeId, st.generation, o.seq, H st.root o.digest, st.manifest,
          st.headSeq⟩ :=
  commit H init (Inv.of_same hs hinv) (hs.log.trans hlog) hroot hbelow hgt
    (by rw [hs.log, hs.measured]; exact hsuf)
    (by rw [hs.log]; exact happ)
    (by rw [cursor_of_state hs.state]; exact hle)
    (by rw [hs.state]; exact hagree)
    htree hsigned hgen hstb

/-- `commit` after the outcome lines `ls`: how recovery completes an
operation, stopped after any of its writes. -/
theorem complete_inv {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D} {o : Op I D} {L0 : List (Line D)}
    (ls : List (OLine D)) (hinv : Inv H init Signed n)
    (hlog : n.log = L0 ++ [⟨o.seq, o.digest, H st.root o.digest⟩])
    (hroot : st.root = rootOf H init L0) (hbelow : ∀ l ∈ L0, l.seq ≤ st.lastSeq)
    (hgt : st.lastSeq < o.seq) (hsuf : Suffix n.log n.measured)
    (happ : ∀ l ∈ n.log, ∃ p m, Signed p m ∧ p.treeId = st.treeId ∧
      ∃ o' ∈ p.ops, o'.seq = l.seq ∧ o'.digest = l.digest)
    (hle : cursor n ≤ st.lastSeq)
    (hagree : ∀ s, n.state = some s →
      s.treeId = st.treeId ∧ s.generation = st.generation ∧
      s.manifest = st.manifest)
    (htree : st.treeId = pub.treeId) (hsigned : Signed pub m)
    (hgen : st.generation ≤ pub.generation ∧
      (pub.generation = st.generation →
        st.manifest = none ∨ st.manifest = some m))
    (hstb : ∀ m', st.manifest = some m' →
      ∃ p, Signed p m' ∧ p.generation = st.generation) :
    Along (Inv H init Signed) Mono
      (complete ls ⟨st.treeId, st.generation, o.seq, H st.root o.digest,
          st.manifest, st.headSeq⟩) n ∧
      LoopRel H init Signed pub m
        (applyAll (complete ls ⟨st.treeId, st.generation, o.seq,
          H st.root o.digest, st.manifest, st.headSeq⟩) n)
        ⟨st.treeId, st.generation, o.seq, H st.root o.digest, st.manifest,
          st.headSeq⟩ := by
  have hlo := along_outcomes (Signed := Signed) ls n hinv
  obtain ⟨hca, hcr⟩ := commit' H init (pub := pub) (same_outcomes ls n) hinv
    hlog hroot hbelow hgt hsuf happ hle hagree htree hsigned hgen hstb
  unfold complete
  refine ⟨along_append hlo hca, ?_⟩
  rw [applyAll_append]
  exact hcr

/-- One operation the loop applies, stopped after any of its writes. -/
theorem loop_apply {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D} {o : Op I D}
    (h : LoopRel H init Signed pub m n st) (hgt : st.lastSeq < o.seq)
    (ho : o ∈ pub.ops) :
    Along (Inv H init Signed) Mono
      [.pending o, .measure o.seq o.digest,
        .append ⟨o.seq, o.digest, H st.root o.digest⟩,
        .outcome ⟨o.seq, true, H st.root o.digest⟩,
        .state { st with root := H st.root o.digest, lastSeq := o.seq },
        .unlink] n ∧
      LoopRel H init Signed pub m
        (applyAll [.pending o, .measure o.seq o.digest,
          .append ⟨o.seq, o.digest, H st.root o.digest⟩,
          .outcome ⟨o.seq, true, H st.root o.digest⟩,
          .state { st with root := H st.root o.digest, lastSeq := o.seq },
          .unlink] n)
        { st with root := H st.root o.digest, lastSeq := o.seq } := by
  obtain ⟨hrep, hcur0, hbound, happ, ⟨hroot, hbelow⟩, ⟨L1, L2, hlog, hmeas⟩,
    hst, hle,
    hagree, hnolog, htree, hsigned, hgen, hstb⟩ := h
  have hlt : cursor n < o.seq := by omega
  have hpos : 0 < o.seq := by omega
  have hnext : H st.root o.digest = H (rootOf H init n.log) o.digest := by
    rw [hst, hroot]
  have hrep3 :
      Replays H init (n.log ++ [⟨o.seq, o.digest, H st.root o.digest⟩]) :=
    replays_append H init hrep
      (fun x hx => by have := hbelow x hx; show x.seq < o.seq; omega) hpos hnext
  have happ' : ∀ l ∈ n.log ++ [⟨o.seq, o.digest, H st.root o.digest⟩],
      ∃ p m, Signed p m ∧ p.treeId = st.treeId ∧
      ∃ o' ∈ p.ops, o'.seq = l.seq ∧ o'.digest = l.digest := by
    intro l hl
    rcases List.mem_append.1 hl with hl | hl
    · cases hs : n.state with
      | none => simp [hnolog hs] at hl
      | some s =>
        obtain ⟨p, m', h1, h2, h3⟩ := happ s hs l hl
        exact ⟨p, m', h1, h2.trans (hagree s hs).1, h3⟩
    · simp only [List.mem_singleton] at hl
      subst hl
      exact ⟨pub, m, hsigned, htree.symm, o, ho, rfl, rfl⟩
  have hsuf3 : Suffix (n.log ++ [⟨o.seq, o.digest, H st.root o.digest⟩])
      (n.measured ++ [(o.seq, o.digest)]) :=
    ⟨L1, L2 ++ [⟨o.seq, o.digest, H st.root o.digest⟩],
      by rw [hlog, List.append_assoc],
      by rw [hmeas]; simp [events]⟩
  have hinvn : Inv H init Signed n :=
    ⟨hrep, hcur0, hbound, happ, fun hs => by simp [hnolog hs],
      Or.inl ⟨⟨hroot, hbelow⟩, L1, L2, hlog, hmeas⟩⟩
  have hinv1 :
      Inv H init Signed
        (⟨n.state, some o, n.log, n.measured, n.outcomes⟩ : Node T M I D) :=
    ⟨hrep, hcur0, hbound, happ, fun hs => by simp [hnolog hs],
      Or.inl ⟨⟨hroot, hbelow⟩, L1, L2, hlog, hmeas⟩⟩
  have hinv2 : Inv H init Signed (⟨n.state, some o, n.log,
      n.measured ++ [(o.seq, o.digest)], n.outcomes⟩ : Node T M I D) :=
    ⟨hrep, hcur0, hbound, happ, fun hs => by simp [hnolog hs],
      Or.inr (Or.inl ⟨o, rfl, hlt, ⟨hroot, hbelow⟩, L1, L2, hlog,
        by rw [hmeas]⟩)⟩
  have hinv3 : Inv H init Signed (⟨n.state, some o,
      n.log ++ [⟨o.seq, o.digest, H st.root o.digest⟩],
      n.measured ++ [(o.seq, o.digest)], n.outcomes⟩ : Node T M I D) := by
    refine ⟨hrep3, hcur0, hbound, fun s hs l hl => ?_, fun hs l hl => ?_,
      Or.inr (Or.inr ⟨o, n.log, rfl, hlt, by rw [hnext], hroot, hbelow, hsuf3⟩)⟩
    · obtain ⟨p, m', h1, h2, h3⟩ := happ' l hl
      exact ⟨p, m', h1, h2.trans (hagree s hs).1.symm, h3⟩
    · rw [hnolog hs] at hl
      simp only [List.nil_append, List.mem_singleton] at hl
      subst hl
      exact ⟨o, rfl, rfl, rfl⟩
  have hsm : Same (⟨n.state, some o,
      n.log ++ [⟨o.seq, o.digest, H st.root o.digest⟩],
      n.measured ++ [(o.seq, o.digest)], n.outcomes⟩ : Node T M I D)
      ⟨n.state, some o, n.log ++ [⟨o.seq, o.digest, H st.root o.digest⟩],
        n.measured ++ [(o.seq, o.digest)],
        n.outcomes ++ [⟨o.seq, true, H st.root o.digest⟩]⟩ :=
    ⟨rfl, rfl, rfl, rfl⟩
  obtain ⟨hc, hr⟩ := commit' H init (pub := pub) hsm hinv3 rfl
    (hst.trans hroot)
    (fun l hl => by have := hbelow l hl; omega) hgt hsuf3 happ' hle hagree
    htree hsigned
    hgen hstb
  simp only [Along, applyAll, List.foldl, Write.apply] at hc hr ⊢
  exact ⟨⟨hinvn, Mono.of_state rfl ⟨[], by simp⟩, hinv1,
    Mono.of_state rfl ⟨[], by simp⟩,
    hinv2, Mono.of_state rfl ⟨_, rfl⟩, hinv3, Mono.of_same hsm, hc⟩, hr⟩

/-- An operation the selector does not match moves the cursor in memory;
its outcome line is nothing the relation reads. -/
theorem LoopRel.skip {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D} {s : Int}
    (h : LoopRel H init Signed pub m n st) (hs : st.lastSeq ≤ s) :
    LoopRel H init Signed pub m n { st with lastSeq := s } :=
  { h with le := Int.le_trans h.le hs }

/-- The loop, stopped after any of its writes. -/
theorem loop_inv {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    (sel : Op I D → Bool) :
    ∀ (os : List (Op I D)) (n : Node T M I D) (st : State T M D),
      (∀ o ∈ os, o ∈ pub.ops) → LoopRel H init Signed pub m n st →
      Along (Inv H init Signed) Mono (loop H sel st os).1 n ∧
        LoopRel H init Signed pub m (applyAll (loop H sel st os).1 n)
          (loop H sel st os).2
  | [], _, _, _, h => ⟨h.inv, h⟩
  | o :: os, n, st, hsub, h => by
    have hsub' : ∀ o' ∈ os, o' ∈ pub.ops :=
      fun o' ho' => hsub o' (by simp [ho'])
    simp only [loop]
    split
    · exact loop_inv sel os n st hsub' h
    · rename_i hgt
      split
      · obtain ⟨ha, hr⟩ := loop_apply H init h (by omega) (hsub o (by simp))
        obtain ⟨ha', hr'⟩ := loop_inv sel os _ _ hsub' hr
        refine ⟨along_append ha ha', ?_⟩
        rw [applyAll_append]
        exact hr'
      · have hr1 : LoopRel H init Signed pub m
            ((Write.outcome ⟨o.seq, false, st.root⟩).apply n)
            { st with lastSeq := o.seq } :=
          (h.skip H init (by omega)).of_same ⟨rfl, rfl, rfl, rfl⟩
        obtain ⟨ha', hr'⟩ := loop_inv sel os _ _ hsub' hr1
        refine ⟨along_append
          (along_one h.inv (Mono.of_same ⟨rfl, rfl, rfl, rfl⟩) hr1.inv) ha', ?_⟩
        rw [applyAll_append]
        exact hr'

/-- A write that records the publication, with any head: the one at
acceptance and the one once the loop is done. -/
theorem final_write {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D} (hd : Int)
    (h : LoopRel H init Signed pub m n st) :
    Inv H init Signed ((Write.state ⟨st.treeId, pub.generation, st.lastSeq,
        st.root,
        some m, hd⟩).apply n) ∧
      Mono n ((Write.state ⟨st.treeId, pub.generation, st.lastSeq, st.root,
        some m, hd⟩).apply n) := by
  obtain ⟨hrep, hcur0, -, happ, ⟨hroot, hbelow⟩, hsuf, hst, hle, hagree,
    hnolog, htree,
    hsigned, ⟨hgen, hgen'⟩, -⟩ := h
  simp only [Write.apply]
  refine ⟨⟨hrep, by show 0 ≤ st.lastSeq; omega, ?_, ?_, by simp,
    Or.inl ⟨⟨?_, ?_⟩, hsuf⟩⟩,
    ⟨[], by simp⟩, fun s hs => ⟨_, rfl, ?_, ?_, ?_, fun he => ?_⟩⟩
  · intro s m' hs hm
    simp only [Option.some.injEq] at hs
    subst hs
    simp only [Option.some.injEq] at hm
    subst hm
    exact ⟨pub, hsigned, rfl⟩
  · intro s hs l hl
    simp only [Option.some.injEq] at hs
    subst hs
    cases hs' : n.state with
    | none => simp [hnolog hs'] at hl
    | some s0 =>
      obtain ⟨p, m', h1, h2, h3⟩ := happ s0 hs' l hl
      exact ⟨p, m', h1, h2.trans (hagree s0 hs').1, h3⟩
  · show st.root = _
    rw [hst, hroot]
  · intro l hl
    show l.seq ≤ st.lastSeq
    have := hbelow l hl
    omega
  · exact (hagree s hs).1.symm
  · show s.generation ≤ pub.generation
    rw [(hagree s hs).2.1]
    exact hgen
  · have : cursor n = s.lastSeq := by simp [cursor, hs]
    show s.lastSeq ≤ st.lastSeq
    omega
  · have he' : pub.generation = st.generation := by
      rw [← (hagree s hs).2.1]; exact he
    rw [(hagree s hs).2.2]
    rcases hgen' he' with h0 | h0
    · exact Or.inl h0
    · exact Or.inr h0.symm

/-- The write that records a publication at acceptance: the loop goes on
from the state it wrote. -/
theorem accept_write {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    {n : Node T M I D} {st : State T M D} (hd : Int)
    (h : LoopRel H init Signed pub m n st) :
    Inv H init Signed ((Write.state ⟨st.treeId, pub.generation, st.lastSeq,
        st.root, some m, hd⟩).apply n) ∧
      Mono n ((Write.state ⟨st.treeId, pub.generation, st.lastSeq, st.root,
        some m, hd⟩).apply n) ∧
      LoopRel H init Signed pub m
        ((Write.state ⟨st.treeId, pub.generation, st.lastSeq, st.root,
          some m, hd⟩).apply n)
        ⟨st.treeId, pub.generation, st.lastSeq, st.root, some m, hd⟩ := by
  obtain ⟨hfi, hfm⟩ := final_write H init hd h
  refine ⟨hfi, hfm, ?_⟩
  obtain ⟨hrep, hcur0, -, -, ⟨hroot, hbelow⟩, hsuf, hst, hle, -, -, htree,
    hsigned, -, -⟩ := h
  simp only [Write.apply] at hfi ⊢
  exact ⟨hrep, by show 0 ≤ st.lastSeq; omega, hfi.bound, hfi.applied,
    ⟨by show st.root = _; rw [hst, hroot],
      fun l hl => by show l.seq ≤ st.lastSeq; have := hbelow l hl; omega⟩,
    hsuf, rfl, Int.le_refl _,
    fun s hs => by
      simp only [Option.some.injEq] at hs; subst hs; exact ⟨rfl, rfl, rfl⟩,
    by simp, htree, hsigned, ⟨Int.le_refl _, fun _ => Or.inr rfl⟩,
    fun m' hm => by
      simp only [Option.some.injEq] at hm
      subst hm
      exact ⟨pub, hsigned, rfl⟩⟩

end loop

/-- Recovery reads nothing of the outcomes record. -/
theorem recover_same [DecidableEq I] [DecidableEq D] {H : D → D → D} {init : D}
    {n n' : Node T M I D} (hs : Same n n') (pub : Pub T M I D)
    (st : State T M D) :
    recover H init n' pub st = recover H init n pub st := by
  unfold recover
  rw [hs.pending, hs.measured, hs.log]

/-- Recovery only goes on with a pending operation above the cursor that
the publication has. -/
theorem recover_found [DecidableEq I] [DecidableEq D] {H : D → D → D} {init : D}
    {n : Node T M I D} {pub : Pub T M I D} {st0 st : State T M D}
    {ws : List (Write T M I D)} {p : Op I D}
    (hrec : recover H init n pub st0 = some (ws, st))
    (hp : n.pending = some p) (hlt : st0.lastSeq < p.seq) :
    ∃ o ∈ pub.ops, o.seq = p.seq := by
  unfold recover at hrec
  simp only [hp] at hrec
  split at hrec
  · omega
  split at hrec
  · simp at hrec
  rename_i o hf
  have hos := List.find?_some hf
  simp only [decide_eq_true_eq] at hos
  exact ⟨o, List.mem_of_find?_eq_some hf, hos.1⟩

/-! ### Recovery and a whole run -/

section run
variable [DecidableEq T] [DecidableEq M] [DecidableEq I] [DecidableEq D]
variable (H : D → D → D) (init : D)

omit [DecidableEq I] in
/-- The state a run starts from, its own or a fresh one: it is the node's,
of the publication's tree, and recording `pub` with `m` at the end goes
forward. -/
theorem start_facts {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    (hbind : ∀ p p' m, Signed p m → Signed p' m → p = p')
    {n : Node T M I D} (hinv : Inv H init Signed n)
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m) :
    (n.state.getD (fresh init pub.treeId)).root = rootAt init n ∧
      (n.state.getD (fresh init pub.treeId)).lastSeq = cursor n ∧
      (∀ s, n.state = some s →
        s.treeId = (n.state.getD (fresh init pub.treeId)).treeId ∧
        s.generation = (n.state.getD (fresh init pub.treeId)).generation ∧
        s.manifest = (n.state.getD (fresh init pub.treeId)).manifest) ∧
      (n.state.getD (fresh init pub.treeId)).treeId = pub.treeId ∧
      ((n.state.getD (fresh init pub.treeId)).generation ≤ pub.generation ∧
        (pub.generation = (n.state.getD (fresh init pub.treeId)).generation →
          (n.state.getD (fresh init pub.treeId)).manifest = none ∨
          (n.state.getD (fresh init pub.treeId)).manifest = some m)) ∧
      (∀ m', (n.state.getD (fresh init pub.treeId)).manifest = some m' →
        ∃ p, Signed p m' ∧
          p.generation =
            (n.state.getD (fresh init pub.treeId)).generation) := by
  cases hs : n.state with
  | none =>
    refine ⟨by simp [rootAt, fresh, hs], by simp [cursor, fresh, hs], by simp,
      by simp [fresh], ⟨by simpa [fresh] using hchk.1, fun _ => Or.inl rfl⟩,
      by simp [fresh]⟩
  | some s =>
    simp only [hs, Follows] at hfol
    refine ⟨by simp [rootAt, hs], by simp [cursor, hs], ?_, hfol.1, ?_,
      fun m' hm => hinv.bound s m' hs hm⟩
    · intro s' hs'
      simp only [Option.some.injEq] at hs'
      subst hs'
      exact ⟨rfl, rfl, rfl⟩
    · simp only [Option.getD_some]
      rcases hfol.2.1 with hm | hlt
      · obtain ⟨p0, hp0, hg⟩ := hinv.bound s m hs hm
        have := hbind _ _ _ hp0 hsig
        subst this
        exact ⟨Int.le_of_eq hg.symm, fun _ => Or.inr hm⟩
      · exact ⟨Int.le_of_lt hlt, fun he => absurd he (by omega)⟩

omit [DecidableEq T] [DecidableEq M] [DecidableEq I] in
/-- Without a state, a clean node has an empty tree eventlog. -/
theorem nolog_of_clean {Signed : Pub T M I D → M → Prop} {n : Node T M I D}
    (hinv : Inv H init Signed n) (hc : Clean H init n) (hs : n.state = none) :
    n.log = [] := by
  have h0 : cursor n = 0 := by simp [cursor, hs]
  have hpos := (replays_seq H init hinv.replays).1
  cases hl : n.log with
  | nil => rfl
  | cons l ls =>
    have h1 := hpos l (by simp [hl])
    have h2 := hc.2 l (by simp [hl])
    omega

omit [DecidableEq I] in
/-- A clean node goes on from the state it starts from. -/
theorem LoopRel.start {Signed : Pub T M I D → M → Prop}
    {pub : Pub T M I D} {m : M}
    (hbind : ∀ p p' m, Signed p m → Signed p' m → p = p')
    {n : Node T M I D} (hinv : Inv H init Signed n) (hclean : Clean H init n)
    (hsuf : Suffix n.log n.measured)
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m) :
    LoopRel H init Signed pub m n (n.state.getD (fresh init pub.treeId)) := by
  obtain ⟨hr, hc, ha, ht, hg, hb⟩ :=
    start_facts H init hbind hinv hchk hfol hsig
  exact ⟨hinv.replays, hinv.cursor_nonneg, hinv.bound, hinv.applied, hclean,
    hsuf, hr, Int.le_of_eq hc.symm, ha, nolog_of_clean H init hinv hclean, ht,
    hsig, hg, hb⟩

/-- What `tree_recover_pending()` writes, by where the run before it
stopped: nothing without a pending operation; the unlink alone when the
cursor is at or past it; nothing, leaving the cursor below it, when it is
neither measured nor appended; its line, then its outcome lines, the state
and the unlink when it is measured and not appended; and the outcome lines,
the state and the unlink when it is appended. `lines` gives the outcome
lines of a pending operation, and a state recovery writes keeps the head
the node recorded. -/
def RecoverSpec (n : Node T M I D) (lines : Op I D → List (OLine D))
    (ws : List (Write T M I D)) (st : State T M D) : Prop :=
  match n.pending with
  | none => ws = [] ∧ st.lastSeq = cursor n
  | some p =>
    (p.seq ≤ cursor n ∧ ws = [.unlink] ∧ st.lastSeq = cursor n) ∨
    (cursor n < p.seq ∧ (p.seq, p.digest) ∉ n.measured ∧
      (p.seq, p.digest) ∉ events n.log ∧
      ws = [] ∧ st.lastSeq = cursor n) ∨
    (cursor n < p.seq ∧ (p.seq, p.digest) ∈ n.measured ∧
      (p.seq, p.digest) ∉ events n.log ∧
      (∃ r, ws = .append ⟨p.seq, p.digest, r⟩ :: complete (lines p) st) ∧
      st.lastSeq = p.seq ∧ ∀ s, n.state = some s → st.headSeq = s.headSeq) ∨
    (cursor n < p.seq ∧ (p.seq, p.digest) ∈ events n.log ∧
      ws = complete (lines p) st ∧
      st.lastSeq = p.seq ∧ ∀ s, n.state = some s → st.headSeq = s.headSeq)

/-- `tree_recover_pending()`, stopped after any of its writes: every node
it leaves keeps the invariant and goes forward, the loop goes on from a
clean node, and it writes what `RecoverSpec` says. -/
theorem recover_inv {Signed : Pub T M I D → M → Prop}
    (hbind : ∀ p p' m, Signed p m → Signed p' m → p = p')
    (hH : ∀ a b c d, H a b = H c d → a = c ∧ b = d)
    (hinit : ∀ a b, H a b ≠ init)
    {n : Node T M I D} {pub : Pub T M I D} {m : M} (hinv : Inv H init Signed n)
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m)
    {ws : List (Write T M I D)} {st : State T M D}
    (hrec : recover H init n pub (n.state.getD (fresh init pub.treeId)) =
      some (ws, st)) :
    Along (Inv H init Signed) Mono ws n ∧
      LoopRel H init Signed pub m (applyAll ws n) st ∧
      RecoverSpec n (recLines H pub (n.state.getD (fresh init pub.treeId)))
        ws st := by
  obtain ⟨hst0r, hst0c, hagree, htree, hgen, hstb⟩ :=
    start_facts H init hbind hinv hchk hfol hsig
  have hgo : Clean H init n → Suffix n.log n.measured →
      LoopRel H init Signed pub m n (n.state.getD (fresh init pub.treeId)) :=
    fun hc hs => LoopRel.start H init hbind hinv hc hs hchk hfol hsig
  -- What the tree eventlog replays to on a clean node.
  have hrepl : Clean H init n →
      replay H init n.log = .missing ∨
      replay H init n.log = .ok (rootAt init n) := by
    intro hc
    cases hl : n.log with
    | nil => exact Or.inl rfl
    | cons l ls =>
      right
      rw [← hl, replay_ok H init hinv.replays (by simp [hl]), hc.1]
  unfold recover at hrec
  cases hp : n.pending with
  | none =>
    simp only [hp, Option.some.injEq, Prod.mk.injEq] at hrec
    obtain ⟨rfl, rfl⟩ := hrec
    have hw : Clean H init n ∧ Suffix n.log n.measured := by
      rcases hinv.window with h | ⟨p, hp', _⟩ | ⟨p, _, hp', _⟩
      · exact h
      · simp [hp] at hp'
      · simp [hp] at hp'
    refine ⟨hinv, hgo hw.1 hw.2, ?_⟩
    simp only [RecoverSpec, hp]
    exact ⟨by trivial, hst0c⟩
  | some p =>
    simp only [hp] at hrec
    split at hrec
    · rename_i hle
      simp only [Option.some.injEq, Prod.mk.injEq] at hrec
      obtain ⟨rfl, rfl⟩ := hrec
      have hw : Clean H init n ∧ Suffix n.log n.measured := by
        rcases hinv.window with h | ⟨p', hp', hlt, _⟩ | ⟨p', _, hp', hlt, _⟩
        · exact h
        · rw [hp, Option.some.injEq] at hp'; subst hp'; omega
        · rw [hp, Option.some.injEq] at hp'; subst hp'; omega
      have hinv' : Inv H init Signed
          (⟨n.state, none, n.log, n.measured, n.outcomes⟩ : Node T M I D) :=
        ⟨hinv.replays, hinv.cursor_nonneg, hinv.bound, hinv.applied,
          fun hs => by simp [nolog_of_clean H init hinv hw.1 hs], Or.inl hw⟩
      have hspec :
          RecoverSpec n (recLines H pub (n.state.getD (fresh init pub.treeId)))
            [.unlink] (n.state.getD (fresh init pub.treeId)) := by
        simp only [RecoverSpec, hp]
        exact Or.inl ⟨by omega, trivial, hst0c⟩
      simp only [Along, applyAll, List.foldl, Write.apply]
      exact ⟨⟨hinv, Mono.of_state rfl ⟨[], by simp⟩, hinv'⟩,
        LoopRel.start H init
          (n := ⟨n.state, none, n.log, n.measured, n.outcomes⟩) hbind
          hinv' hw.1 hw.2
          hchk hfol hsig, hspec⟩
    rename_i hgt
    split at hrec
    · simp at hrec
    rename_i o hf
    have ho : o ∈ pub.ops := List.mem_of_find?_eq_some hf
    have hos := List.find?_some hf
    simp only [decide_eq_true_eq] at hos
    have hop : o = p := by
      obtain ⟨h1, h2, h3⟩ := hos
      cases o
      cases p
      simp only at h1 h2 h3
      subst h1 h2 h3
      rfl
    subst hop
    have hlt : cursor n < o.seq := by omega
    -- The pending operation has no line at or below the cursor.
    have hnotin : ∀ L : List (Line D), (∀ l ∈ L, l.seq ≤ cursor n) →
        (o.seq, o.digest) ∉ events L := by
      intro L hL hin
      simp only [events, List.mem_map, Prod.mk.injEq] at hin
      obtain ⟨l, hl, hs, -⟩ := hin
      have := hL l hl
      omega
    rcases hinv.window with ⟨hc, hsuf⟩ | ⟨p', hp', -, hc, L1, L2, hlog, hmeas⟩ |
        ⟨p', L0, hp', -, hlog, hroot, hbelow, hsuf⟩
    · -- Clean, the operation not measured: the loop retries it.
      have hnm : (o.seq, o.digest) ∉ n.measured := by
        obtain ⟨L1, L2, hlog, hmeas⟩ := hsuf
        rw [hmeas]
        exact hnotin L2 (fun l hl =>
          hc.2 l (by rw [hlog]; exact List.mem_append_right _ hl))
      have hne : rootAt init n ≠
          H (n.state.getD (fresh init pub.treeId)).root o.digest := by
        rw [hst0r, hc.1]; exact rootOf_ne_next H init hH hinit _ _
      rcases hrepl hc with h | h <;> rw [h] at hrec <;> simp only at hrec
      · rw [ite_eq_right hnm] at hrec
        simp only [Option.some.injEq, Prod.mk.injEq] at hrec
        obtain ⟨rfl, rfl⟩ := hrec
        refine ⟨hinv, hgo hc hsuf, ?_⟩
        simp only [RecoverSpec, hp]
        exact Or.inr (Or.inl ⟨hlt, hnm, hnotin n.log hc.2, trivial, hst0c⟩)
      · rw [ite_eq_right hne, ite_eq_left hst0r.symm, ite_eq_right hnm] at hrec
        simp only [Option.some.injEq, Prod.mk.injEq] at hrec
        obtain ⟨rfl, rfl⟩ := hrec
        refine ⟨hinv, hgo hc hsuf, ?_⟩
        simp only [RecoverSpec, hp]
        exact Or.inr (Or.inl ⟨hlt, hnm, hnotin n.log hc.2, trivial, hst0c⟩)
    · -- Measured, its line not appended: append it, then commit.
      rw [hp, Option.some.injEq] at hp'
      subst hp'
      have hm : (o.seq, o.digest) ∈ n.measured := by rw [hmeas]; simp
      have hne : rootAt init n ≠
          H (n.state.getD (fresh init pub.treeId)).root o.digest := by
        rw [hst0r, hc.1]; exact rootOf_ne_next H init hH hinit _ _
      have hroot0 :
          (n.state.getD (fresh init pub.treeId)).root = rootOf H init n.log :=
        hst0r.trans hc.1
      have hrep1 : Replays H init (n.log ++ [⟨o.seq, o.digest,
          H (n.state.getD (fresh init pub.treeId)).root o.digest⟩]) :=
        replays_append H init hinv.replays
          (fun x hx => by have := hc.2 x hx; show x.seq < o.seq; omega) (by
            have := hinv.cursor_nonneg; show 0 < o.seq; omega) (by rw [hroot0])
      have hnolog := nolog_of_clean H init hinv hc
      have happ1 : ∀ l ∈ n.log ++ [⟨o.seq, o.digest,
          H (n.state.getD (fresh init pub.treeId)).root o.digest⟩],
          ∃ q m', Signed q m' ∧
          q.treeId = (n.state.getD (fresh init pub.treeId)).treeId ∧
          ∃ o' ∈ q.ops, o'.seq = l.seq ∧ o'.digest = l.digest := by
        intro l hl
        rcases List.mem_append.1 hl with hl | hl
        · rcases Option.eq_none_or_eq_some n.state with hs | ⟨s, hs⟩
          · simp [hnolog hs] at hl
          · obtain ⟨q, m', h1, h2, h3⟩ := hinv.applied s hs l hl
            exact ⟨q, m', h1, h2.trans (hagree s hs).1, h3⟩
        · simp only [List.mem_singleton] at hl
          subst hl
          exact ⟨pub, m, hsig, htree.symm, o, ho, rfl, rfl⟩
      have hinv1 : Inv H init Signed (⟨n.state, n.pending,
          n.log ++ [⟨o.seq, o.digest,
          H (n.state.getD (fresh init pub.treeId)).root o.digest⟩],
          n.measured, n.outcomes⟩ :
          Node T M I D) := by
        refine ⟨hrep1, hinv.cursor_nonneg, hinv.bound, fun s hs l hl => ?_,
          fun hs l hl => ?_, Or.inr (Or.inr ⟨o, n.log, hp, hlt,
            by rw [hroot0], hc.1, hc.2,
            L1, L2 ++ [_], by rw [hlog, List.append_assoc],
            by rw [hmeas]; simp [events]⟩)⟩
        · obtain ⟨q, m', h1, h2, h3⟩ := happ1 l hl
          exact ⟨q, m', h1, h2.trans (hagree s hs).1.symm, h3⟩
        · rw [hnolog hs] at hl
          simp only [List.nil_append, List.mem_singleton] at hl
          subst hl
          exact ⟨o, hp, rfl, rfl⟩
      rcases hrepl hc with h | h <;> rw [h] at hrec <;> simp only at hrec
      all_goals first
        | rw [ite_eq_right hne, ite_eq_left hst0r.symm, ite_eq_left hm] at hrec
        | rw [ite_eq_left hm] at hrec
      all_goals
        simp only [Option.some.injEq, Prod.mk.injEq] at hrec
        obtain ⟨rfl, rfl⟩ := hrec
        obtain ⟨hca, hcr⟩ :=
          complete_inv H init (pub := pub) (L0 := n.log)
          (recLines H pub (n.state.getD (fresh init pub.treeId)) o) hinv1 rfl
          hroot0
          (fun l hl => by have := hc.2 l hl; omega) (by omega)
          ⟨L1, L2 ++ [_], by rw [hlog, List.append_assoc],
            by rw [hmeas]; simp [events]⟩
          happ1 (Int.le_of_eq hst0c.symm) hagree htree hsig hgen hstb
        refine ⟨⟨hinv, Mono.of_state rfl ⟨_, rfl⟩, hca⟩, hcr, ?_⟩
        simp only [RecoverSpec, hp]
        exact Or.inr (Or.inr (Or.inl
          ⟨hlt, hm, hnotin n.log hc.2, ⟨_, rfl⟩, trivial,
            fun s hs => by simp [hs]⟩))
    · -- Its line appended too: commit.
      rw [hp, Option.some.injEq] at hp'
      subst hp'
      have hroot0 :
          (n.state.getD (fresh init pub.treeId)).root = rootOf H init L0 :=
        hst0r.trans hroot
      have hok : replay H init n.log =
          .ok (H (n.state.getD (fresh init pub.treeId)).root o.digest) := by
        rw [replay_ok H init hinv.replays (by simp [hlog]), hlog,
          rootOf_append, hroot0]
      rw [hok] at hrec
      simp only [ite_true, Option.some.injEq, Prod.mk.injEq] at hrec
      obtain ⟨rfl, rfl⟩ := hrec
      have happ0 : ∀ l ∈ n.log, ∃ q m', Signed q m' ∧
          q.treeId = (n.state.getD (fresh init pub.treeId)).treeId ∧
          ∃ o' ∈ q.ops, o'.seq = l.seq ∧ o'.digest = l.digest := by
        intro l hl
        rcases Option.eq_none_or_eq_some n.state with hs | ⟨s, hs⟩
        · obtain ⟨q, hq, h1, h2⟩ := hinv.stateless hs l hl
          rw [hp, Option.some.injEq] at hq
          subst hq
          exact ⟨pub, m, hsig, htree.symm, _, ho, h1.symm, h2.symm⟩
        · obtain ⟨q, m', h1, h2, h3⟩ := hinv.applied s hs l hl
          exact ⟨q, m', h1, h2.trans (hagree s hs).1, h3⟩
      obtain ⟨hca, hcr⟩ := complete_inv H init (pub := pub) (L0 := L0)
        (recLines H pub (n.state.getD (fresh init pub.treeId)) o) hinv
        (by rw [hlog, hroot0]) hroot0
        (fun l hl => by have := hbelow l hl; omega) (by omega) hsuf happ0
        (Int.le_of_eq hst0c.symm) hagree htree hsig hgen hstb
      refine ⟨hca, hcr, ?_⟩
      simp only [RecoverSpec, hp]
      exact Or.inr (Or.inr (Or.inr
        ⟨hlt, by rw [hlog]; simp [events], trivial, trivial,
          fun s hs => by simp [hs]⟩))

/-- What the theorems assume and the C cannot show. A manifest digest
names one publication: it is the SHA-256 of the manifest, and
`bpm_oci_get_signed()` takes the one payload layer the manifest names by
its SHA-256 and checks it, while a registry may wrap one publication in any
number of manifests. And the projection hash is injective on (root,
digest) pairs and never the 64 zeros, the idealized hash of
`Chain.register_injective`. No hash onto 32 bytes is injective on every
pair, so the theorems that rest on `hash_inj` hold of SHA-256 only as far
as no two of the pairs it folds on the node collide, as
`Chain.register_injective_on` states for the register; the proofs here do
not narrow it to those pairs. -/
structure Assumptions (H : D → D → D) (init : D)
    (Signed : Pub T M I D → M → Prop) : Prop where
  binds : ∀ p p' m, Signed p m → Signed p' m → p = p'
  hash_inj : ∀ a b c d, H a b = H c d → a = c ∧ b = d
  hash_init : ∀ a b, H a b ≠ init

/-- A whole sync, stopped after any of its writes. -/
theorem run_inv {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} {pub : Pub T M I D} {m : M} (sel : Op I D → Bool)
    (hinv : Inv H init Signed n) (hsig : Signed pub m) :
    Along (Inv H init Signed) Mono (run H init n pub m sel) n := by
  unfold run
  split
  · rename_i hc
    obtain ⟨hchk, hfol⟩ := hc
    have hsm : Same n ((Write.truncate (cursor n).toNat).apply n) :=
      ⟨rfl, rfl, rfl, rfl⟩
    have hinv0 := Inv.of_same hsm hinv
    refine along_cons hinv (Mono.of_same hsm) ?_
    split
    · exact along_nil hinv0
    · rename_i ws st hrec
      obtain ⟨hw, hr, -⟩ := recover_inv H init ha.binds ha.hash_inj
        ha.hash_init hinv0 hchk
        hfol hsig ((recover_same hsm pub _).trans hrec)
      obtain ⟨hai, ham, hr1⟩ := accept_write H init pub.headSeq hr
      obtain ⟨hl, hr'⟩ := loop_inv H init sel pub.ops _ _ (fun _ ho => ho) hr1
      refine along_append (along_append
        (along_append hw (along_one hr.inv ham hai)) ?_) ?_
      · rw [applyAll_append]
        exact hl
      · rw [applyAll_append, applyAll_append]
        exact along_one hr'.inv (final_write H init _ hr').2
          (final_write H init _ hr').1
  · exact hinv

/-- One step keeps the invariant and goes forward. -/
theorem step_inv {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hinv : Inv H init Signed n)
    (h : Step H init Signed n n') :
    Inv H init Signed n' ∧ Mono n n' := by
  cases h with
  | sync sel k hsig =>
    have h := run_inv H init ha sel hinv hsig
    exact ⟨along_take h k,
      along_between Mono.refl (fun _ _ _ => Mono.trans) h 0 k
      (Nat.zero_le _)⟩
  | reboot =>
    refine ⟨⟨hinv.replays, hinv.cursor_nonneg, hinv.bound, hinv.applied,
      hinv.stateless,
      ?_⟩, Mono.of_state rfl ⟨[], by simp⟩⟩
    rcases hinv.window with ⟨hc, -⟩ | ⟨p, hp, -, hc, -⟩ |
        ⟨p, L0, hp, hlt, hlog, hroot, hbelow, -⟩
    · exact Or.inl ⟨hc, n.log, [], by simp, rfl⟩
    · exact Or.inl ⟨hc, n.log, [], by simp, rfl⟩
    · exact Or.inr (Or.inr
        ⟨p, L0, hp, hlt, hlog, hroot, hbelow, n.log, [], by simp, rfl⟩)

theorem Steps.trans {Signed : Pub T M I D → M → Prop} {a b c : Node T M I D}
    (h1 : Steps H init Signed a b) (h2 : Steps H init Signed b c) :
    Steps H init Signed a c := by
  induction h2 with
  | refl => exact h1
  | tail _ hs ih => exact Steps.tail ih hs

theorem steps_inv {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hinv : Inv H init Signed n)
    (h : Steps H init Signed n n') :
    Inv H init Signed n' ∧ Mono n n' := by
  induction h with
  | refl => exact ⟨hinv, Mono.refl _⟩
  | tail _ hs ih =>
    obtain ⟨hi, hm⟩ := ih
    obtain ⟨hi', hm'⟩ := step_inv H init ha hi hs
    exact ⟨hi', hm.trans hm'⟩

/-- A node some sequence of syncs, crashes and reboots leaves, from before
its first sync. -/
def Reach (Signed : Pub T M I D → M → Prop) (n : Node T M I D) : Prop :=
  Steps H init Signed Node.empty n

/-- Every node a sequence of syncs, crashes and reboots leaves keeps the
invariant. -/
theorem reach_inv {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (h : Reach H init Signed n) : Inv H init Signed n :=
  (steps_inv H init ha (Inv.empty H init Signed) h).1

/-- Two points of the node's history in order: any number of steps
apart, two points of one sync where a crash could stop it, or a chain of
those. It orders every two nodes a sequence of syncs, crashes and reboots
passes through, those a sync passes on its way included. -/
inductive Later (Signed : Pub T M I D → M → Prop) :
    Node T M I D → Node T M I D → Prop where
  | steps {n n' : Node T M I D} : Steps H init Signed n n' → Later Signed n n'
  | within {n0 : Node T M I D} {pub : Pub T M I D} {m : M} (sel : Op I D → Bool)
      {i j : Nat} : Reach H init Signed n0 → Signed pub m → i ≤ j →
      Later Signed (applyAll ((run H init n0 pub m sel).take i) n0)
        (applyAll ((run H init n0 pub m sel).take j) n0)
  | trans {a b c : Node T M I D} :
      Later Signed a b → Later Signed b c → Later Signed a c

theorem later_reach {Signed : Pub T M I D → M → Prop} {n n' : Node T M I D}
    (hr : Reach H init Signed n) (h : Later H init Signed n n') :
    Reach H init Signed n' := by
  induction h with
  | steps hs => exact hr.trans H init hs
  | within sel h0 hsig _ => exact Steps.tail h0 (Step.sync sel _ hsig)
  | trans _ _ ih1 ih2 => exact ih2 (ih1 hr)

/-- Every later point of the node's history keeps the invariant and is
forward of an earlier one. -/
theorem later_mono {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (h : Later H init Signed n n') :
    Mono n n' := by
  induction h with
  | steps hs => exact (steps_inv H init ha (reach_inv H init ha hr) hs).2
  | within sel h0 hsig hij =>
    exact along_between Mono.refl (fun _ _ _ => Mono.trans)
      (run_inv H init ha sel (reach_inv H init ha h0) hsig) _ _ hij
  | trans h1 _ ih1 ih2 => exact (ih1 hr).trans (ih2 (later_reach H init hr h1))

/-! ### The node never goes back -/

/-- The generation never decreases, between any two points of any
sequence of syncs of any signed publications, crashes and reboots. -/
theorem generation_mono {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n')
    {s : State T M D} (hst : n.state = some s) :
    ∃ s', n'.state = some s' ∧ s'.treeId = s.treeId ∧
      s.generation ≤ s'.generation := by
  obtain ⟨s', h1, h2, h3, -⟩ := (later_mono H init ha hr hs).state s hst
  exact ⟨s', h1, h2, h3⟩

/-- At an equal generation the node only ever holds the manifest it
recorded, at any later point of its history. -/
theorem manifest_fixed {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n')
    {s s' : State T M D} {mf : M} (hst : n.state = some s)
    (hm : s.manifest = some mf)
    (hst' : n'.state = some s') (hg : s'.generation = s.generation) :
    s'.manifest = some mf := by
  obtain ⟨s'', h1, -, -, -, h5⟩ := (later_mono H init ha hr hs).state s hst
  rw [hst', Option.some.injEq] at h1
  subst h1
  rcases h5 hg with h | h
  · rw [hm] at h; cases h
  · rw [h, hm]

/-- The cursor never decreases, between any two points of the node's
history. -/
theorem lastSeq_mono {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n')
    {s : State T M D} (hst : n.state = some s) :
    ∃ s', n'.state = some s' ∧ s.lastSeq ≤ s'.lastSeq := by
  obtain ⟨s', h1, -, -, h4, -⟩ := (later_mono H init ha hr hs).state s hst
  exact ⟨s', h1, h4⟩

/-- `Follows` refuses a publication of an earlier generation than the
node's, or of its generation in another manifest, so a sync of it writes
nothing. -/
theorem older_refused {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) {s : State T M D}
    (hst : n.state = some s) {q : Pub T M I D} {mq : M} (hq : Signed q mq)
    (hold : q.generation < s.generation ∨
      (q.generation = s.generation ∧ s.manifest ≠ some mq))
    (sel : Op I D → Bool) :
    run H init n q mq sel = [] := by
  have hinv := reach_inv H init ha hr
  unfold run
  rw [ite_eq_right]
  rintro ⟨-, hfol⟩
  rw [hst] at hfol
  obtain ⟨-, hgen, -⟩ := hfol
  rcases hgen with hm | hlt
  · obtain ⟨p0, hp0, hg⟩ := hinv.bound s mq hst hm
    have := ha.binds _ _ _ hp0 hq
    subst this
    rcases hold with h | ⟨-, h⟩
    · omega
    · exact h hm
  · rcases hold with h | ⟨h, -⟩ <;> omega

/-- Once the node has accepted a publication, recording its manifest,
every later sync of a publication of an earlier generation writes
nothing. -/
theorem accepted_older_refused {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n')
    {s : State T M D} {p : Pub T M I D} {mp : M} (hst : n.state = some s)
    (hm : s.manifest = some mp) (hp : Signed p mp)
    {q : Pub T M I D} {mq : M} (hq : Signed q mq)
    (hold : q.generation < p.generation)
    (sel : Op I D → Bool) :
    run H init n' q mq sel = [] := by
  have hinv := reach_inv H init ha hr
  obtain ⟨p0, hp0, hg⟩ := hinv.bound s mp hst hm
  have := ha.binds _ _ _ hp0 hp
  subst this
  obtain ⟨s', hs', -, hge⟩ := generation_mono H init ha hr hs hst
  exact older_refused H init ha (later_reach H init hr hs) hs' hq
    (Or.inl (by omega)) sel

/-! ### Each operation once, in order, and the state its fold -/

/-- The tree eventlog holds each operation at most once, in increasing
order of sequence number. -/
theorem log_increasing {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    (n.log.map (·.seq)).Pairwise (· < ·) ∧ ∀ l ∈ n.log, 0 < l.seq :=
  let h := replays_seq H init (reach_inv H init ha hr).replays
  ⟨h.2, h.1⟩

/-- The tree eventlog only grows: with `log_increasing`, an operation is
applied at most once over the node's whole history. -/
theorem log_grows {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n') :
    ∃ L, n'.log = n.log ++ L :=
  (later_mono H init ha hr hs).log

omit [DecidableEq T] [DecidableEq M] [DecidableEq I] [DecidableEq D] in
theorem suffix_pairwise {log L2 : List (Line D)} {L1 : List (Line D)}
    (hlog : log = L1 ++ L2) (h : (log.map (·.seq)).Pairwise (· < ·)) :
    ((events L2).map Prod.fst).Pairwise (· < ·) := by
  rw [hlog, List.map_append, List.pairwise_append] at h
  simpa [events, List.map_map, Function.comp_def] using h.2.1

/-- This boot's eventlog measures each operation at most once, in
increasing order. -/
theorem measured_increasing {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    (n.measured.map Prod.fst).Pairwise (· < ·) := by
  have hinv := reach_inv H init ha hr
  have hlog := (replays_seq H init hinv.replays).2
  rcases hinv.window with ⟨-, L1, L2, hl, hm⟩ |
      ⟨p, -, hlt, hc, L1, L2, hl, hm⟩ |
      ⟨-, -, -, -, -, -, -, L1, L2, hl, hm⟩
  · rw [hm]; exact suffix_pairwise hl hlog
  · rw [hm, List.map_append, List.pairwise_append]
    refine ⟨suffix_pairwise hl hlog, by simp, ?_⟩
    intro a ha b hb
    simp only [events, List.map_map, List.mem_map, Function.comp_def] at ha
    obtain ⟨l, hl2, rfl⟩ := ha
    simp only [List.map_cons, List.map_nil, List.mem_singleton] at hb
    subst hb
    have := hc.2 l (by rw [hl]; exact List.mem_append_right _ hl2)
    show l.seq < p.seq
    omega
  · rw [hm]; exact suffix_pairwise hl hlog

/-- Nothing measured is lost: every operation this boot measured has its
line in the tree eventlog, or is the pending one, still ahead of the
cursor, which the next recovery completes. -/
theorem measured_kept {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    ∀ e ∈ n.measured, e ∈ events n.log ∨
      ∃ p, n.pending = some p ∧ e = (p.seq, p.digest) ∧ cursor n < p.seq := by
  have hinv := reach_inv H init ha hr
  have hsub : ∀ {L1 L2 : List (Line D)} {e}, n.log = L1 ++ L2 → e ∈ events L2 →
      e ∈ events n.log := by
    intro L1 L2 e hl he
    rw [hl, events, List.map_append]
    exact List.mem_append_right _ he
  intro e he
  rcases hinv.window with ⟨-, L1, L2, hl, hm⟩ |
      ⟨p, hp, hlt, -, L1, L2, hl, hm⟩ |
      ⟨-, -, -, -, -, -, -, L1, L2, hl, hm⟩
  · rw [hm] at he; exact Or.inl (hsub hl he)
  · rw [hm, List.mem_append] at he
    rcases he with he | he
    · exact Or.inl (hsub hl he)
    · simp only [List.mem_singleton] at he
      exact Or.inr ⟨p, hp, he, hlt⟩
  · rw [hm] at he; exact Or.inl (hsub hl he)

/-- A crash between writing `pending.json` and committing the state: the
recovery of the next sync appends the pending operation's line exactly
when this boot measured it or its line is there already, appends at most
that one line, and otherwise leaves the cursor below the operation, so the
loop applies it; afterwards everything measured is in the tree eventlog. -/
theorem recover_pending {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) {pub : Pub T M I D} {m : M}
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m)
    {p : Op I D} (hp : n.pending = some p) (hlt : cursor n < p.seq)
    {ws : List (Write T M I D)} {st : State T M D}
    (hrec : recover H init n pub (n.state.getD (fresh init pub.treeId)) =
      some (ws, st)) :
    (∃ L, (applyAll ws n).log = n.log ++ L ∧ L.length ≤ 1) ∧
      ((p.seq, p.digest) ∈ events (applyAll ws n).log ↔
        (p.seq, p.digest) ∈ n.measured ∨ (p.seq, p.digest) ∈ events n.log) ∧
      ((p.seq, p.digest) ∉ events (applyAll ws n).log → st.lastSeq < p.seq) ∧
      ∀ e ∈ (applyAll ws n).measured, e ∈ events (applyAll ws n).log := by
  have hinv := reach_inv H init ha hr
  obtain ⟨-, hrel, hspec⟩ :=
    recover_inv H init ha.binds ha.hash_inj ha.hash_init hinv hchk hfol hsig
      hrec
  have hkept :
      ∀ e ∈ (applyAll ws n).measured, e ∈ events (applyAll ws n).log := by
    obtain ⟨L1, L2, hl, hm⟩ := hrel.suffix
    intro e he
    rw [hm] at he
    rw [hl, events, List.map_append]
    exact List.mem_append_right _ he
  simp only [RecoverSpec, hp] at hspec
  rcases hspec with ⟨hle, -⟩ | ⟨-, hnm, hnl, rfl, hst⟩ |
      ⟨-, hm, hnl, ⟨r, hws⟩, -⟩ |
      ⟨-, hl, hws, -⟩
  · omega
  · exact ⟨⟨[], by simp [applyAll], by simp⟩,
      ⟨fun h => Or.inr h, fun h => h.elim (fun h' => absurd h' hnm) id⟩,
      fun _ => by omega, hkept⟩
  · have hlg : (applyAll ws n).log = n.log ++ [⟨p.seq, p.digest, r⟩] := by
      rw [hws, applyAll_cons]
      exact (complete_core _ _ _).1
    have hin : (p.seq, p.digest) ∈ events (applyAll ws n).log := by
      rw [hlg]
      simp [events]
    exact ⟨⟨_, hlg, by simp⟩, ⟨fun _ => Or.inl hm, fun _ => hin⟩,
      fun h => absurd hin h, hkept⟩
  · have hlg : (applyAll ws n).log = n.log := by
      rw [hws]
      exact (complete_core _ _ _).1
    have hin : (p.seq, p.digest) ∈ events (applyAll ws n).log := by
      rw [hlg]
      exact hl
    exact ⟨⟨[], by rw [hlg, List.append_nil], by simp⟩,
      ⟨fun h => by rw [hlg] at h; exact Or.inr h, fun _ => hin⟩,
      fun h => absurd hin h, hkept⟩

/-- After recovery the state is the fold of the tree eventlog, the cursor
at or past all of it, and every operation this boot measured in it: the
loop starts from a node with nothing half done. -/
theorem recover_settles {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) {pub : Pub T M I D} {m : M}
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m)
    {ws : List (Write T M I D)} {st : State T M D}
    (hrec : recover H init n pub (n.state.getD (fresh init pub.treeId)) =
      some (ws, st)) :
    rootAt init (applyAll ws n) = rootOf H init (applyAll ws n).log ∧
      st.root = rootOf H init (applyAll ws n).log ∧
      (∀ l ∈ (applyAll ws n).log, l.seq ≤ st.lastSeq) ∧
      ∀ e ∈ (applyAll ws n).measured, e ∈ events (applyAll ws n).log := by
  obtain ⟨-, hrel, -⟩ := recover_inv H init ha.binds ha.hash_inj ha.hash_init
    (reach_inv H init ha hr) hchk hfol hsig hrec
  obtain ⟨L1, L2, hl, hm⟩ := hrel.suffix
  refine ⟨hrel.clean.1, hrel.root.trans hrel.clean.1,
    fun l h => Int.le_trans (hrel.clean.2 l h) hrel.le, fun e he => ?_⟩
  rw [hm] at he
  rw [hl, events, List.map_append]
  exact List.mem_append_right _ he

/-- The recorded state is the fold of the operations the tree eventlog
says the node applied, but for a run stopped between appending the
pending operation's line and writing the state, which recovery
completes. -/
theorem state_is_fold {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    (rootAt init n = rootOf H init n.log ∧ ∀ l ∈ n.log, l.seq ≤ cursor n) ∨
      ∃ p L0, n.pending = some p ∧ cursor n < p.seq ∧
        n.log = L0 ++ [⟨p.seq, p.digest, H (rootOf H init L0) p.digest⟩] ∧
        rootAt init n = rootOf H init L0 ∧ ∀ l ∈ L0, l.seq ≤ cursor n := by
  rcases (reach_inv H init ha hr).window with ⟨hc, -⟩ | ⟨-, -, -, hc, -⟩ |
      ⟨p, L0, hp, hlt, hl, hroot, hbelow, -⟩
  · exact Or.inl hc
  · exact Or.inl hc
  · exact Or.inr ⟨p, L0, hp, hlt, hl, hroot, hbelow⟩

/-- `event_replay()` never refuses the tree eventlog of a reachable
node, so recovery never fails on it. -/
theorem replay_not_bad {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    replay H init n.log ≠ .bad := by
  have hrep := (reach_inv H init ha hr).replays
  cases hl : n.log with
  | nil => simp [replay]
  | cons l ls =>
    rw [← hl, replay_ok H init hrep (by simp [hl])]
    simp

/-! ### The operations applied are the signed ones -/

/-- Every line of the tree eventlog is an operation of a signed
publication of the recorded tree. -/
theorem applied_signed {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) {s : State T M D}
    (hst : n.state = some s) {l : Line D} (hl : l ∈ n.log) :
    ∃ p m, Signed p m ∧ p.treeId = s.treeId ∧
      ∃ o ∈ p.ops, o.seq = l.seq ∧ o.digest = l.digest :=
  (reach_inv H init ha hr).applied s hst l hl

/-- When the signer never gives one sequence number two operations within
a tree, every line of the tree eventlog is the operation every signed
publication of the recorded tree has at that number. -/
theorem applied_consistent {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed)
    (hcons : ∀ p m p' m', Signed p m → Signed p' m' → p.treeId = p'.treeId →
      ∀ o ∈ p.ops, ∀ o' ∈ p'.ops, o.seq = o'.seq → o = o')
    {n : Node T M I D} (hr : Reach H init Signed n) {s : State T M D}
    (hst : n.state = some s) {l : Line D} (hl : l ∈ n.log)
    {q : Pub T M I D} {mq : M} (hq : Signed q mq) (hqt : q.treeId = s.treeId)
    {o : Op I D} (ho : o ∈ q.ops) (hos : o.seq = l.seq) :
    o.digest = l.digest := by
  obtain ⟨p, m, hp, hpt, o', ho', h1, h2⟩ := applied_signed H init ha hr hst hl
  have := hcons q mq p m hq hp (hqt.trans hpt.symm) o ho o' ho'
    (hos.trans h1.symm)
  rw [this, h2]

end run

/-! ### The outcomes record -/

/-- The sequence numbers 1 to `k`, in order. -/
def upto : Nat → List Int
  | 0 => []
  | k + 1 => upto k ++ [(k : Int) + 1]

theorem upto_length : ∀ k : Nat, (upto k).length = k
  | 0 => rfl
  | k + 1 => by
    show (upto k ++ [(k : Int) + 1]).length = k + 1
    rw [List.length_append, upto_length k, List.length_singleton]

theorem take_length_append {α : Type} :
    ∀ (xs ys : List α), (xs ++ ys).take xs.length = xs
  | [], _ => rfl
  | x :: xs, ys => congrArg (x :: ·) (take_length_append xs ys)

theorem take_append_le {α : Type} :
    ∀ (xs ys : List α) (k : Nat), k ≤ xs.length →
      (xs ++ ys).take k = xs.take k
  | _, _, 0, _ => rfl
  | [], _, _ + 1, h => absurd h (Nat.not_succ_le_zero _)
  | x :: xs, ys, k + 1, h =>
    congrArg (x :: ·) (take_append_le xs ys k (Nat.le_of_succ_le_succ h))

theorem take_take_le {α : Type} :
    ∀ (xs : List α) (k t : Nat), k ≤ t → (xs.take t).take k = xs.take k
  | _, 0, _, _ => rfl
  | [], _ + 1, t, _ => by cases t <;> rfl
  | _ :: _, _ + 1, 0, h => absurd h (Nat.not_succ_le_zero _)
  | x :: xs, k + 1, t + 1, h =>
    congrArg (x :: ·) (take_take_le xs k t (Nat.le_of_succ_le_succ h))

/-- The operations are numbered from `a + 1` on without a gap. -/
def Consec : Int → List (Op I D) → Prop
  | _, [] => True
  | a, o :: os => o.seq = a + 1 ∧ Consec (a + 1) os

theorem consec_of_range : ∀ (os : List (Op I D)) (a : Int),
    os.map (·.seq) =
      (List.range os.length).map (fun i : Nat => a + 1 + (i : Int)) →
    Consec a os
  | [], _, _ => trivial
  | o :: os, a, h => by
    rw [List.length_cons, List.range_succ_eq_map, List.map_cons, List.map_cons,
      List.map_map] at h
    obtain ⟨h1, h2⟩ := List.cons.inj h
    show o.seq = a + 1 ∧ Consec (a + 1) os
    refine ⟨by simpa using h1, consec_of_range os (a + 1) ?_⟩
    rw [h2]
    apply List.map_congr_left
    intro i _
    show a + 1 + ((i + 1 : Nat) : Int) = a + 1 + 1 + (i : Int)
    omega

/-- What `Checked` says of a publication's numbers, as the loops read
them. -/
theorem consec_of_checked {pub : Pub T M I D} (h : Checked pub) :
    Consec pub.baseSeq pub.ops ∧
      pub.baseSeq + (pub.ops.length : Int) = pub.headSeq := by
  obtain ⟨-, -, hh, hm⟩ := h
  exact ⟨consec_of_range pub.ops pub.baseSeq hm, by omega⟩

/-- A publication that follows the node starts at or before its cursor. -/
theorem base_le_cursor [DecidableEq T] [DecidableEq M] {pub : Pub T M I D}
    {n : Node T M I D} {m : M} (h : Follows pub n.state m) :
    pub.baseSeq ≤ cursor n := by
  cases hs : n.state with
  | none =>
    simp only [hs, Follows] at h
    simp [cursor, hs, h]
  | some s =>
    simp only [hs, Follows] at h
    simp only [cursor, hs]
    exact h.2.2.2.1

theorem consec_mem {o : Op I D} : ∀ (os : List (Op I D)) (a : Int),
    Consec a os → o ∈ os → a < o.seq ∧ o.seq ≤ a + (os.length : Int)
  | [], _, _, h => by cases h
  | x :: xs, a, hc, h => by
    simp only [Consec] at hc
    obtain ⟨hx, hc'⟩ := hc
    simp only [List.length_cons]
    rcases List.mem_cons.1 h with rfl | h'
    · omega
    · have := consec_mem xs (a + 1) hc' h'
      omega

/-- The record holds the lines of 1 to `k`, in order, and no other. -/
def Exact (n : Node T M I D) (k : Int) : Prop :=
  ∃ c : Nat, (c : Int) = k ∧ n.outcomes.map (·.seq) = upto c

/-- The outcomes record covers the cursor: it starts with a line for each
operation from 1 to the cursor, in order. What follows them is what a sync
that stopped left behind. -/
def Covers (n : Node T M I D) : Prop :=
  ∃ (c : Nat) (pre rest : List (OLine D)),
    (c : Int) = cursor n ∧ n.outcomes = pre ++ rest ∧ pre.map (·.seq) = upto c

/-- What every node a sync can leave holds of the outcomes record and of
the head: the record covers the cursor, the cursor is at or below the head
of the recorded publication, and so is a pending operation, which is only
there with a state. -/
structure OInv (n : Node T M I D) : Prop where
  covers : Covers n
  head : ∀ s, n.state = some s → s.lastSeq ≤ s.headSeq
  pend : ∀ p, n.pending = some p → ∃ s, n.state = some s ∧ p.seq ≤ s.headSeq

/-- From `n` to `n'` the cursor did not go back and no line at or below the
cursor of `n` changed. -/
def OMono (n n' : Node T M I D) : Prop :=
  cursor n ≤ cursor n' ∧
    ∀ k : Nat, (k : Int) ≤ cursor n → n'.outcomes.take k = n.outcomes.take k

theorem OMono.refl (n : Node T M I D) : OMono n n :=
  ⟨Int.le_refl _, fun _ _ => rfl⟩

theorem OMono.trans {a b c : Node T M I D} (h1 : OMono a b) (h2 : OMono b c) :
    OMono a c :=
  ⟨Int.le_trans h1.1 h2.1,
    fun k hk => (h2.2 k (Int.le_trans hk h1.1)).trans (h1.2 k hk)⟩

theorem OMono.inert {n n' : Node T M I D} (ho : n'.outcomes = n.outcomes)
    (hs : n'.state = n.state) : OMono n n' :=
  ⟨Int.le_of_eq (cursor_of_state hs).symm, fun _ _ => by rw [ho]⟩

theorem OMono.append {n : Node T M I D} {l : OLine D}
    (hlen : ∀ k : Nat, (k : Int) ≤ cursor n → k ≤ n.outcomes.length) :
    OMono n ((Write.outcome l).apply n) :=
  ⟨Int.le_refl _, fun k hk => take_append_le n.outcomes [l] k (hlen k hk)⟩

theorem Covers.of_eq {n n' : Node T M I D} (ho : n'.outcomes = n.outcomes)
    (hc : cursor n' = cursor n) (h : Covers n) : Covers n' := by
  unfold Covers at h ⊢
  obtain ⟨c, pre, rest, h1, h2, h3⟩ := h
  exact ⟨c, pre, rest, h1.trans hc.symm, ho.trans h2, h3⟩

theorem Covers.append {n : Node T M I D} {l : OLine D} (h : Covers n) :
    Covers ((Write.outcome l).apply n) := by
  unfold Covers at h ⊢
  obtain ⟨c, pre, rest, h1, h2, h3⟩ := h
  refine ⟨c, pre, rest ++ [l], h1, ?_, h3⟩
  show n.outcomes ++ [l] = pre ++ (rest ++ [l])
  rw [h2, List.append_assoc]

theorem OInv.inert {n n' : Node T M I D} (h : OInv n)
    (ho : n'.outcomes = n.outcomes) (hs : n'.state = n.state)
    (hp : ∀ p, n'.pending = some p →
      ∃ s, n'.state = some s ∧ p.seq ≤ s.headSeq) : OInv n' :=
  ⟨Covers.of_eq ho (cursor_of_state hs) h.covers,
    by rw [hs]; exact h.head, hp⟩

theorem OInv.empty : OInv (Node.empty : Node T M I D) :=
  ⟨⟨0, [], [], rfl, rfl, rfl⟩,
    fun s hs => absurd (show (none : Option (State T M D)) = some s from hs)
      (by simp),
    fun p hp => absurd (show (none : Option (Op I D)) = some p from hp)
      (by simp)⟩

theorem exact_len {n : Node T M I D} {k : Int} (h : Exact n k) :
    ∀ j : Nat, (j : Int) ≤ k → j ≤ n.outcomes.length := by
  obtain ⟨c, hc, he⟩ := h
  intro j hj
  have hl := congrArg List.length he
  rw [List.length_map, upto_length] at hl
  omega

theorem exact_append {n : Node T M I D} {k : Int} {l : OLine D}
    (h : Exact n k) (hl : l.seq = k + 1) :
    Exact ((Write.outcome l).apply n) l.seq := by
  obtain ⟨c, hc, he⟩ := h
  have hs : l.seq = (c : Int) + 1 := by omega
  have e1 : (n.outcomes ++ [l]).map (·.seq) =
      n.outcomes.map (·.seq) ++ [l.seq] := by simp
  refine ⟨c + 1, by omega, ?_⟩
  show (n.outcomes ++ [l]).map (·.seq) = upto c ++ [(c : Int) + 1]
  rw [e1, he, hs]

theorem exact_covers {n : Node T M I D} {k : Int} (h : Exact n k)
    (hk : cursor n = k) : Covers n := by
  obtain ⟨c, hc, he⟩ := h
  exact ⟨c, n.outcomes, [], hc.trans hk.symm, by simp, he⟩

/-- Outcome lines after a record that reaches the cursor, stopped after
any of them. -/
theorem along_olines : ∀ (ls : List (OLine D)) (n : Node T M I D), OInv n →
    (∀ k : Nat, (k : Int) ≤ cursor n → k ≤ n.outcomes.length) →
    Along OInv OMono (ls.map Write.outcome) n ∧
      OInv (applyAll (ls.map Write.outcome) n) ∧
      (applyAll (ls.map Write.outcome) n).outcomes = n.outcomes ++ ls
  | [], n, ho, _ => ⟨along_nil ho, ho, (by simp : n.outcomes = n.outcomes ++ [])⟩
  | l :: ls, n, ho, hlen => by
    have h1 : OInv ((Write.outcome l).apply n) :=
      ⟨Covers.append ho.covers, ho.head, ho.pend⟩
    obtain ⟨ha, hoe, he⟩ := along_olines ls ((Write.outcome l).apply n) h1
      (fun k hk => by
        have := hlen k hk
        show k ≤ (n.outcomes ++ [l]).length
        rw [List.length_append]
        omega)
    have e2 : n.outcomes ++ [l] ++ ls = n.outcomes ++ l :: ls := by simp
    exact ⟨along_cons ho (OMono.append hlen) ha, hoe, he.trans e2⟩

/-- The lines of the operations recovery finds passed over continue a
record of 1 to `c` up to the number before the pending operation's. -/
theorem passed_ext (lo hi : Int) (root : D) :
    ∀ (os : List (Op I D)) (a : Int) (c : Nat), Consec a os → lo ≤ c →
      a ≤ c → ((c : Int) = a ∨ (c : Int) = lo) → (c : Int) < hi →
      hi ≤ a + (os.length : Int) + 1 →
      ∃ c' : Nat, (c' : Int) = hi - 1 ∧
        upto c ++ (passed lo hi root os).map (·.seq) = upto c'
  | [], _, c, _, _, _, _, _, hhi =>
    ⟨c, by simp only [List.length_nil] at hhi; omega,
      (by simp [passed] : upto c ++ (passed lo hi root []).map (·.seq) = upto c)⟩
  | o :: os, a, c, hcs, hlo, hac, hca, hlt, hhi => by
    simp only [Consec] at hcs
    obtain ⟨hoa, hcs'⟩ := hcs
    simp only [List.length_cons] at hhi
    by_cases h1 : hi ≤ o.seq
    · have hp : passed lo hi root (o :: os) = [] := by
        simp only [passed, ite_eq_left h1]
      refine ⟨c, by omega, ?_⟩
      rw [hp]
      simp
    · by_cases h2 : o.seq ≤ lo
      · have hp : passed lo hi root (o :: os) = passed lo hi root os := by
          simp only [passed, ite_eq_right h1, ite_eq_left h2]
        rw [hp]
        exact passed_ext lo hi root os (a + 1) c hcs' hlo (by omega)
          (Or.inr (by omega)) hlt (by omega)
      · have hp : passed lo hi root (o :: os) =
            ⟨o.seq, false, root⟩ :: passed lo hi root os := by
          simp only [passed, ite_eq_right h1, ite_eq_right h2]
        obtain ⟨c', hc', he⟩ := passed_ext lo hi root os (a + 1) (c + 1) hcs'
          (by omega) (by omega) (Or.inl (by omega)) (by omega) (by omega)
        have hseq : o.seq = (c : Int) + 1 := by omega
        refine ⟨c', hc', ?_⟩
        rw [hp, ← he]
        have e1 : upto c ++ List.map (·.seq)
              ((⟨o.seq, false, root⟩ : OLine D) :: passed lo hi root os) =
            upto c ++ [o.seq] ++ List.map (·.seq) (passed lo hi root os) := by
          simp
        have e2 : upto c ++ [o.seq] = upto (c + 1) :=
          congrArg (fun x => upto c ++ [x]) hseq
        exact e1.trans (congrArg (· ++ List.map (·.seq) (passed lo hi root os)) e2)

/-- Between two operations of the loop, as far as the outcomes record and
the head go: the record holds exactly the lines up to the cursor the run
holds, which is at or below the head of the publication, and the state on
the node records that head. -/
structure ORel (pub : Pub T M I D) (n : Node T M I D) (st : State T M D) :
    Prop where
  lines : Exact n st.lastSeq
  le : cursor n ≤ st.lastSeq
  bound : st.lastSeq ≤ pub.headSeq
  headEq : st.headSeq = pub.headSeq
  disk : ∃ s, n.state = some s ∧ s.headSeq = pub.headSeq
  oinv : OInv n

/-- One operation the loop applies, stopped after any of its writes. -/
theorem oloop_apply {pub : Pub T M I D} {n : Node T M I D} {st : State T M D}
    {o : Op I D} (r : D) (h : ORel pub n st) (hseq : o.seq = st.lastSeq + 1)
    (hle : o.seq ≤ pub.headSeq) :
    Along OInv OMono
      [.pending o, .measure o.seq o.digest, .append ⟨o.seq, o.digest, r⟩,
        .outcome ⟨o.seq, true, r⟩,
        .state { st with root := r, lastSeq := o.seq }, .unlink] n ∧
      ORel pub
        (applyAll [.pending o, .measure o.seq o.digest,
          .append ⟨o.seq, o.digest, r⟩, .outcome ⟨o.seq, true, r⟩,
          .state { st with root := r, lastSeq := o.seq }, .unlink] n)
        { st with root := r, lastSeq := o.seq } := by
  obtain ⟨hex, hcl, -, hhe, ⟨s0, hs0, hs0h⟩, hoi⟩ := h
  have h1 : OInv ((Write.pending o).apply n) :=
    hoi.inert rfl rfl (fun p hp => ⟨s0, hs0, by
      have hpo : o = p := Option.some.inj hp
      rw [← hpo]
      omega⟩)
  have h2 : OInv ((Write.measure o.seq o.digest).apply ((Write.pending o).apply n)) :=
    h1.inert rfl rfl h1.pend
  have h3 : OInv ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n))) :=
    h2.inert rfl rfl h2.pend
  have h4 : OInv ((Write.outcome ⟨o.seq, true, r⟩).apply
      ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n)))) :=
    ⟨Covers.append h3.covers, h3.head, h3.pend⟩
  have hx4 : Exact ((Write.outcome ⟨o.seq, true, r⟩).apply
      ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n)))) o.seq :=
    exact_append (n := ((Write.append ⟨o.seq, o.digest, r⟩).apply
        ((Write.measure o.seq o.digest).apply
        ((Write.pending o).apply n)))) (l := ⟨o.seq, true, r⟩) hex hseq
  have h5 : OInv ((Write.state { st with root := r, lastSeq := o.seq }).apply
      ((Write.outcome ⟨o.seq, true, r⟩).apply
      ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n))))) :=
    ⟨exact_covers (n := ((Write.state { st with root := r, lastSeq := o.seq }).apply
        ((Write.outcome ⟨o.seq, true, r⟩).apply
        ((Write.append ⟨o.seq, o.digest, r⟩).apply
        ((Write.measure o.seq o.digest).apply
        ((Write.pending o).apply n)))))) hx4 rfl,
      fun s hs => by
        have e : ({ st with root := r, lastSeq := o.seq } : State T M D) = s :=
          Option.some.inj hs
        rw [← e]
        show o.seq ≤ st.headSeq
        omega,
      fun p hp => ⟨{ st with root := r, lastSeq := o.seq }, rfl, by
        have hpo : o = p := Option.some.inj hp
        rw [← hpo]
        show o.seq ≤ st.headSeq
        omega⟩⟩
  have h6 : OInv (Write.unlink.apply
      ((Write.state { st with root := r, lastSeq := o.seq }).apply
      ((Write.outcome ⟨o.seq, true, r⟩).apply
      ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n)))))) :=
    ⟨Covers.of_eq (n := ((Write.state { st with root := r, lastSeq := o.seq }).apply
        ((Write.outcome ⟨o.seq, true, r⟩).apply
        ((Write.append ⟨o.seq, o.digest, r⟩).apply
        ((Write.measure o.seq o.digest).apply
        ((Write.pending o).apply n)))))) rfl rfl h5.covers, h5.head,
      fun p hp => absurd (show (none : Option (Op I D)) = some p from hp)
        (by simp)⟩
  have m1 : OMono n ((Write.pending o).apply n) := OMono.inert rfl rfl
  have m2 : OMono ((Write.pending o).apply n) ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n)) := OMono.inert rfl rfl
  have m3 : OMono ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n)) ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n))) := OMono.inert rfl rfl
  have m4 : OMono ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n))) ((Write.outcome ⟨o.seq, true, r⟩).apply
      ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n)))) :=
    OMono.append (fun k hk => exact_len hex k (Int.le_trans hk hcl))
  have m5 : OMono ((Write.outcome ⟨o.seq, true, r⟩).apply
      ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n)))) ((Write.state { st with root := r, lastSeq := o.seq }).apply
      ((Write.outcome ⟨o.seq, true, r⟩).apply
      ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n))))) :=
    ⟨by show cursor n ≤ o.seq; omega, fun _ _ => rfl⟩
  have m6 : OMono ((Write.state { st with root := r, lastSeq := o.seq }).apply
      ((Write.outcome ⟨o.seq, true, r⟩).apply
      ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n))))) (Write.unlink.apply
      ((Write.state { st with root := r, lastSeq := o.seq }).apply
      ((Write.outcome ⟨o.seq, true, r⟩).apply
      ((Write.append ⟨o.seq, o.digest, r⟩).apply
      ((Write.measure o.seq o.digest).apply
      ((Write.pending o).apply n)))))) := OMono.inert rfl rfl
  exact ⟨along_cons hoi m1 (along_cons h1 m2 (along_cons h2 m3
      (along_cons h3 m4 (along_cons h4 m5 (along_cons h5 m6 (along_nil h6)))))),
    ⟨hx4, Int.le_refl _, hle, hhe,
      ⟨{ st with root := r, lastSeq := o.seq }, rfl, hhe⟩, h6⟩⟩

/-- An operation the selector does not match: its line, and the cursor
moved in memory. -/
theorem oloop_skip {pub : Pub T M I D} {n : Node T M I D} {st : State T M D}
    {o : Op I D} (r : D) (h : ORel pub n st) (hseq : o.seq = st.lastSeq + 1)
    (hle : o.seq ≤ pub.headSeq) :
    Along OInv OMono [.outcome ⟨o.seq, false, r⟩] n ∧
      ORel pub ((Write.outcome ⟨o.seq, false, r⟩).apply n)
        { st with lastSeq := o.seq } := by
  obtain ⟨hex, hcl, -, hhe, hd, hoi⟩ := h
  have h1 : OInv ((Write.outcome ⟨o.seq, false, r⟩).apply n) :=
    ⟨Covers.append hoi.covers, hoi.head, hoi.pend⟩
  exact ⟨along_one hoi
      (OMono.append (fun k hk => exact_len hex k (Int.le_trans hk hcl))) h1,
    ⟨exact_append (l := ⟨o.seq, false, r⟩) hex hseq,
      by show cursor n ≤ o.seq; omega, hle, hhe, hd, h1⟩⟩

/-- The loop, stopped after any of its writes: every operation past the
cursor is the next one, so each line continues the record. -/
theorem oloop_inv {H : D → D → D} {pub : Pub T M I D} (sel : Op I D → Bool) :
    ∀ (os : List (Op I D)) (n : Node T M I D) (st : State T M D) (a : Int),
      Consec a os → a ≤ st.lastSeq → a + (os.length : Int) ≤ pub.headSeq →
      ORel pub n st →
      Along OInv OMono (loop H sel st os).1 n ∧
        ORel pub (applyAll (loop H sel st os).1 n) (loop H sel st os).2
  | [], _, _, _, _, _, _, h => ⟨h.oinv, h⟩
  | o :: os, n, st, a, hcs, hal, hb, h => by
    simp only [Consec] at hcs
    obtain ⟨hoa, hcs'⟩ := hcs
    simp only [List.length_cons] at hb
    simp only [loop]
    split
    · exact oloop_inv sel os n st (a + 1) hcs' (by omega) (by omega) h
    · rename_i hgt
      have hseq : o.seq = st.lastSeq + 1 := by omega
      split
      · obtain ⟨ha, hr⟩ := oloop_apply (H st.root o.digest) h hseq (by omega)
        obtain ⟨ha', hr'⟩ := oloop_inv sel os _ _ (a + 1) hcs'
          (by show a + 1 ≤ o.seq; omega) (by omega) hr
        refine ⟨along_append ha ha', ?_⟩
        rw [applyAll_append]
        exact hr'
      · obtain ⟨ha, hr⟩ := oloop_skip st.root h hseq (by omega)
        obtain ⟨ha', hr'⟩ := oloop_inv sel os _ _ (a + 1) hcs'
          (by show a + 1 ≤ o.seq; omega) (by omega) hr
        refine ⟨along_append ha ha', ?_⟩
        rw [applyAll_append]
        exact hr'

/-- A write of the state the loop holds, with any generation and manifest:
the one once the loop is done. -/
theorem ofinal {pub : Pub T M I D} {n : Node T M I D} {st : State T M D}
    (g : Int) (mf : Option M) (h : ORel pub n st) :
    OInv ((Write.state ⟨st.treeId, g, st.lastSeq, st.root, mf,
        st.headSeq⟩).apply n) ∧
      OMono n ((Write.state ⟨st.treeId, g, st.lastSeq, st.root, mf,
        st.headSeq⟩).apply n) := by
  obtain ⟨hex, hcl, hb, hhe, ⟨s0, hs0, hs0h⟩, hoi⟩ := h
  refine ⟨⟨exact_covers (n := (Write.state ⟨st.treeId, g, st.lastSeq, st.root,
      mf, st.headSeq⟩).apply n) hex rfl, fun s hs => ?_, fun p hp => ?_⟩,
    ⟨hcl, fun _ _ => rfl⟩⟩
  · have e : (⟨st.treeId, g, st.lastSeq, st.root, mf, st.headSeq⟩ :
        State T M D) = s := Option.some.inj hs
    rw [← e]
    show st.lastSeq ≤ st.headSeq
    omega
  · obtain ⟨s1, hs1, hps⟩ := hoi.pend p hp
    have e : s1 = s0 := Option.some.inj (hs1.symm.trans hs0)
    rw [e] at hps
    exact ⟨⟨st.treeId, g, st.lastSeq, st.root, mf, st.headSeq⟩, rfl, by
      show p.seq ≤ st.headSeq
      omega⟩

/-- Recovery completing an applied operation, as far as the outcomes
record and the head go, stopped after any of its writes: the lines continue
the record to the operation's number before the state that covers them. -/
theorem ocomplete_inv {H : D → D → D} {pub : Pub T M I D} {n : Node T M I D}
    {st0 st : State T M D} {p : Op I D} (hx : Exact n (cursor n)) (ho : OInv n)
    (hcs : Consec pub.baseSeq pub.ops)
    (hlen : pub.baseSeq + (pub.ops.length : Int) = pub.headSeq)
    (hbc : pub.baseSeq ≤ cursor n)
    (hst0 : st0.lastSeq = cursor n) (hlt : cursor n < p.seq)
    (hph : p.seq ≤ pub.headSeq) (hl : st.lastSeq = p.seq)
    (hh : ∀ s, n.state = some s → st.headSeq = s.headSeq)
    (hpn : n.pending = some p) :
    Along OInv OMono (complete (recLines H pub st0 p) st) n ∧
      Exact (applyAll (complete (recLines H pub st0 p) st) n) st.lastSeq ∧
      cursor (applyAll (complete (recLines H pub st0 p) st) n) ≤ st.lastSeq ∧
      OInv (applyAll (complete (recLines H pub st0 p) st) n) ∧
      ∀ q, (applyAll (complete (recLines H pub st0 p) st) n).pending = some q →
        q.seq ≤ pub.headSeq := by
  have hlenx := exact_len hx
  obtain ⟨c, hc, he⟩ := hx
  obtain ⟨s1, hs1, hps⟩ := ho.pend p hpn
  have hhs := hh s1 hs1
  obtain ⟨c', hc', hext⟩ := passed_ext st0.lastSeq p.seq st0.root pub.ops
    pub.baseSeq c hcs (by omega) (by omega) (Or.inr (by omega)) (by omega)
    (by omega)
  obtain ⟨hal, hoL, heq⟩ := along_olines
    (passed st0.lastSeq p.seq st0.root pub.ops ++
      [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)]) n ho hlenx
  have hsame := same_outcomes
    (passed st0.lastSeq p.seq st0.root pub.ops ++
      [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)]) n
  have hcL : cursor (applyAll ((passed st0.lastSeq p.seq st0.root pub.ops ++
      [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)]).map Write.outcome) n) = cursor n :=
    cursor_of_state hsame.state
  have hxL : Exact (applyAll ((passed st0.lastSeq p.seq st0.root pub.ops ++
      [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)]).map Write.outcome) n)
      st.lastSeq := by
    have e3 : (n.outcomes ++ (passed st0.lastSeq p.seq st0.root pub.ops ++
          [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)])).map (·.seq) =
        n.outcomes.map (·.seq) ++
          (passed st0.lastSeq p.seq st0.root pub.ops).map (·.seq) ++
          [p.seq] := by
      simp
    have hs : p.seq = (c' : Int) + 1 := by omega
    unfold Exact
    refine ⟨c' + 1, by omega, ?_⟩
    rw [heq, e3, he, hext]
    show upto c' ++ [p.seq] = upto c' ++ [(c' : Int) + 1]
    rw [hs]
  have hS : OInv ((Write.state st).apply
      (applyAll ((passed st0.lastSeq p.seq st0.root pub.ops ++
        [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)]).map Write.outcome) n)) :=
    ⟨exact_covers (n := (Write.state st).apply
        (applyAll ((passed st0.lastSeq p.seq st0.root pub.ops ++
          [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)]).map Write.outcome) n)) hxL rfl,
      fun s hs => by
        have e : st = s := Option.some.inj hs
        rw [← e]
        omega,
      fun q hq => ⟨st, rfl, by
        have e : p = q :=
          Option.some.inj (hpn.symm.trans (hsame.pending.symm.trans hq))
        rw [← e]
        omega⟩⟩
  have mS : OMono
      (applyAll ((passed st0.lastSeq p.seq st0.root pub.ops ++
        [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)]).map Write.outcome) n)
      ((Write.state st).apply
        (applyAll ((passed st0.lastSeq p.seq st0.root pub.ops ++
          [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)]).map Write.outcome) n)) :=
    ⟨by
      show cursor (applyAll ((passed st0.lastSeq p.seq st0.root pub.ops ++
        [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)]).map Write.outcome) n) ≤
          st.lastSeq
      omega, fun _ _ => rfl⟩
  have hU : OInv (Write.unlink.apply ((Write.state st).apply
      (applyAll ((passed st0.lastSeq p.seq st0.root pub.ops ++
        [(⟨p.seq, true, H st0.root p.digest⟩ : OLine D)]).map Write.outcome) n))) :=
    ⟨Covers.of_eq rfl rfl hS.covers, hS.head,
      fun q hq => absurd (show (none : Option (Op I D)) = some q from hq)
        (by simp)⟩
  unfold complete recLines
  rw [applyAll_append]
  exact ⟨along_append hal
      (along_cons hoL mS (along_cons hS (OMono.inert rfl rfl) (along_nil hU))),
    hxL, Int.le_refl _, hU,
    fun q hq => absurd (show (none : Option (Op I D)) = some q from hq)
      (by simp)⟩

/-- `tree_recover_pending()`, as far as the outcomes record and the head
go, stopped after any of its writes, from a record cut to the cursor. The
loop goes on from a record that holds exactly the lines up to its cursor,
and an operation still pending is one of the publication. -/
theorem orecover_inv {H : D → D → D} {pub : Pub T M I D} {n : Node T M I D}
    {st0 st : State T M D} {ws : List (Write T M I D)}
    (hx : Exact n (cursor n)) (ho : OInv n) (hcs : Consec pub.baseSeq pub.ops)
    (hlen : pub.baseSeq + (pub.ops.length : Int) = pub.headSeq)
    (hbc : pub.baseSeq ≤ cursor n)
    (hst0 : st0.lastSeq = cursor n) (hcur : cursor n ≤ pub.headSeq)
    (hfound : ∀ p, n.pending = some p → cursor n < p.seq →
      ∃ o ∈ pub.ops, o.seq = p.seq)
    (hspec : RecoverSpec n (recLines H pub st0) ws st) :
    Along OInv OMono ws n ∧ Exact (applyAll ws n) st.lastSeq ∧
      cursor (applyAll ws n) ≤ st.lastSeq ∧ st.lastSeq ≤ pub.headSeq ∧
      OInv (applyAll ws n) ∧
      ∀ q, (applyAll ws n).pending = some q → q.seq ≤ pub.headSeq := by
  cases hp : n.pending with
  | none =>
    simp only [RecoverSpec, hp] at hspec
    obtain ⟨rfl, hl⟩ := hspec
    exact ⟨along_nil ho, by rw [hl]; exact hx, Int.le_of_eq hl.symm,
      by omega, ho, fun q hq => absurd (hp.symm.trans hq) (by simp)⟩
  | some p =>
    simp only [RecoverSpec, hp] at hspec
    have hph : cursor n < p.seq → p.seq ≤ pub.headSeq := fun hlt => by
      obtain ⟨o, hom, hop⟩ := hfound p hp hlt
      have hoh := (consec_mem pub.ops pub.baseSeq hcs hom).2
      omega
    rcases hspec with ⟨-, rfl, hl⟩ | ⟨hlt, -, -, rfl, hl⟩ |
        ⟨hlt, -, -, ⟨r, rfl⟩, hl, hh⟩ | ⟨hlt, -, rfl, hl, hh⟩
    · have h1 : OInv ((Write.unlink : Write T M I D).apply n) :=
        ⟨Covers.of_eq rfl rfl ho.covers, ho.head,
          fun q hq => absurd (show (none : Option (Op I D)) = some q from hq)
            (by simp)⟩
      exact ⟨along_one ho (OMono.inert rfl rfl) h1, by rw [hl]; exact hx,
        Int.le_of_eq hl.symm, by omega, h1,
        fun q hq => absurd (show (none : Option (Op I D)) = some q from hq)
          (by simp)⟩
    · exact ⟨along_nil ho, by rw [hl]; exact hx, Int.le_of_eq hl.symm,
        by omega, ho, fun q hq => by
          have e : p = q := Option.some.inj (hp.symm.trans hq)
          rw [← e]
          exact hph hlt⟩
    · have h1 : OInv ((Write.append ⟨p.seq, p.digest, r⟩ :
          Write T M I D).apply n) :=
        ho.inert rfl rfl ho.pend
      obtain ⟨ha, hxe, hcu, hoi, hpe⟩ := ocomplete_inv (H := H) (pub := pub)
        (n := (Write.append ⟨p.seq, p.digest, r⟩ : Write T M I D).apply n)
        (st0 := st0) (st := st) hx h1 hcs hlen hbc hst0 hlt (hph hlt) hl hh hp
      exact ⟨along_cons ho (OMono.inert rfl rfl) ha, hxe, hcu, by omega, hoi,
        hpe⟩
    · obtain ⟨ha, hxe, hcu, hoi, hpe⟩ := ocomplete_inv (H := H) (pub := pub)
        (st0 := st0) (st := st) hx ho hcs hlen hbc hst0 hlt (hph hlt) hl hh hp
      exact ⟨ha, hxe, hcu, by omega, hoi, hpe⟩

/-- A whole sync, as far as the outcomes record and the head go, stopped
after any of its writes. -/
theorem orun_inv [DecidableEq T] [DecidableEq M] [DecidableEq I]
    [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} (ha : Assumptions H init Signed)
    {n : Node T M I D} {pub : Pub T M I D} {m : M} (sel : Op I D → Bool)
    (hinv : Inv H init Signed n) (ho : OInv n) (hsig : Signed pub m) :
    Along OInv OMono (run H init n pub m sel) n := by
  unfold run
  split
  · rename_i hc
    obtain ⟨hchk, hfol⟩ := hc
    obtain ⟨hcs, hlen⟩ := consec_of_checked hchk
    have hbc := base_le_cursor hfol
    have hb0 := hchk.2.1
    have hsm : Same n ((Write.truncate (cursor n).toNat).apply n) :=
      ⟨rfl, rfl, rfl, rfl⟩
    have hinv0 := Inv.of_same hsm hinv
    have hcur : cursor n ≤ pub.headSeq := by
      cases hs : n.state with
      | none =>
        have h0 : cursor n = 0 := by simp [cursor, hs]
        omega
      | some s =>
        have hf := hfol
        simp only [hs, Follows] at hf
        have h5 := hf.2.2.2.2
        have h0 : cursor n = s.lastSeq := by simp [cursor, hs]
        omega
    obtain ⟨c, pre, rest, hc, hpre, hmap⟩ := ho.covers
    have ht : (cursor n).toNat = c := by
      have h2 : ((c : Int)).toNat = c := rfl
      rw [hc] at h2
      exact h2
    have hpl : pre.length = c := by
      have h3 := congrArg List.length hmap
      rw [List.length_map, upto_length] at h3
      exact h3
    have htk : n.outcomes.take (cursor n).toNat = pre := by
      rw [ht, hpre, ← hpl]
      exact take_length_append pre rest
    have hx0 : Exact ((Write.truncate (cursor n).toNat).apply n) (cursor n) := by
      refine ⟨c, hc, ?_⟩
      show (n.outcomes.take (cursor n).toNat).map (·.seq) = upto c
      rw [htk]
      exact hmap
    have ho0 : OInv ((Write.truncate (cursor n).toNat).apply n) :=
      ⟨exact_covers (n := (Write.truncate (cursor n).toNat).apply n) hx0 rfl,
        ho.head, ho.pend⟩
    have hm0 : OMono n ((Write.truncate (cursor n).toNat).apply n) :=
      ⟨Int.le_refl _, fun k hk =>
        take_take_le n.outcomes k (cursor n).toNat (by rw [ht]; omega)⟩
    refine along_cons ho hm0 ?_
    split
    · exact along_nil ho0
    · rename_i ws st hrec
      have hrec0 := (recover_same hsm pub _).trans hrec
      obtain ⟨-, -, hspec⟩ := recover_inv H init ha.binds ha.hash_inj
        ha.hash_init hinv0 hchk hfol hsig hrec0
      have hst0 := (start_facts H init ha.binds hinv0 hchk hfol hsig).2.1
      obtain ⟨haw, hxw, hcw, hbw, how, hpw⟩ := orecover_inv hx0 ho0 hcs hlen
        hbc hst0 hcur (fun p hp hlt => recover_found hrec0 hp
          (Int.lt_of_le_of_lt (Int.le_of_eq hst0) hlt)) hspec
      have hnn : pub.baseSeq ≤ st.lastSeq := by
        have hm := along_between OMono.refl (fun _ _ _ => OMono.trans) haw 0
          ws.length (Nat.zero_le _)
        simp only [List.take_zero, applyAll_nil, List.take_length] at hm
        have hm1 := hm.1
        have : cursor ((Write.truncate (cursor n).toNat).apply n) = cursor n :=
          rfl
        omega
      have hoA : OInv ((Write.state ⟨st.treeId, pub.generation, st.lastSeq,
          st.root, some m, pub.headSeq⟩).apply
          (applyAll ws ((Write.truncate (cursor n).toNat).apply n))) :=
        ⟨exact_covers (n := (Write.state ⟨st.treeId, pub.generation,
            st.lastSeq, st.root, some m, pub.headSeq⟩).apply
            (applyAll ws ((Write.truncate (cursor n).toNat).apply n))) hxw rfl,
          fun s hs => by
            have e : (⟨st.treeId, pub.generation, st.lastSeq, st.root, some m,
                pub.headSeq⟩ : State T M D) = s := Option.some.inj hs
            rw [← e]
            exact hbw,
          fun p hp => ⟨⟨st.treeId, pub.generation, st.lastSeq, st.root, some m,
            pub.headSeq⟩, rfl, hpw p hp⟩⟩
      have hmA : OMono (applyAll ws ((Write.truncate (cursor n).toNat).apply n))
          ((Write.state ⟨st.treeId, pub.generation, st.lastSeq, st.root, some m,
            pub.headSeq⟩).apply
            (applyAll ws ((Write.truncate (cursor n).toNat).apply n))) :=
        ⟨hcw, fun _ _ => rfl⟩
      have hrA : ORel pub ((Write.state ⟨st.treeId, pub.generation, st.lastSeq,
          st.root, some m, pub.headSeq⟩).apply
          (applyAll ws ((Write.truncate (cursor n).toNat).apply n)))
          ⟨st.treeId, pub.generation, st.lastSeq, st.root, some m,
            pub.headSeq⟩ :=
        ⟨hxw, Int.le_refl _, hbw, rfl,
          ⟨⟨st.treeId, pub.generation, st.lastSeq, st.root, some m,
            pub.headSeq⟩, rfl, rfl⟩, hoA⟩
      obtain ⟨hl, hr'⟩ := oloop_inv (H := H) sel pub.ops _
        ⟨st.treeId, pub.generation, st.lastSeq, st.root, some m, pub.headSeq⟩
        pub.baseSeq hcs hnn (by omega) hrA
      refine along_append (along_append
        (along_append haw (along_one how hmA hoA)) ?_) ?_
      · rw [applyAll_append]
        exact hl
      · rw [applyAll_append, applyAll_append]
        exact along_one hr'.oinv (ofinal pub.generation (some m) hr').2
          (ofinal pub.generation (some m) hr').1
  · exact ho

/-- One step keeps what holds of the outcomes record and the head. -/
theorem ostep_inv [DecidableEq T] [DecidableEq M] [DecidableEq I]
    [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hinv : Inv H init Signed n) (ho : OInv n)
    (h : Step H init Signed n n') : OInv n' ∧ OMono n n' := by
  cases h with
  | sync sel k hsig =>
    have h := orun_inv ha sel hinv ho hsig
    exact ⟨along_take h k,
      along_between OMono.refl (fun _ _ _ => OMono.trans) h 0 k
      (Nat.zero_le _)⟩
  | reboot =>
    exact ⟨⟨Covers.of_eq rfl rfl ho.covers, ho.head, ho.pend⟩,
      OMono.inert rfl rfl⟩

theorem osteps_inv [DecidableEq T] [DecidableEq M] [DecidableEq I]
    [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hinv : Inv H init Signed n) (ho : OInv n)
    (h : Steps H init Signed n n') : OInv n' ∧ OMono n n' := by
  induction h with
  | refl => exact ⟨ho, OMono.refl _⟩
  | tail hst hs ih =>
    obtain ⟨hi, hm⟩ := ih
    obtain ⟨hi', hm'⟩ :=
      ostep_inv ha (steps_inv H init ha hinv hst).1 hi hs
    exact ⟨hi', OMono.trans hm hm'⟩

theorem reach_oinv [DecidableEq T] [DecidableEq M] [DecidableEq I]
    [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} (ha : Assumptions H init Signed)
    {n : Node T M I D} (h : Reach H init Signed n) : OInv n :=
  (osteps_inv ha (Inv.empty H init Signed) OInv.empty h).1

theorem later_omono [DecidableEq T] [DecidableEq M] [DecidableEq I]
    [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (h : Later H init Signed n n') : OMono n n' := by
  induction h with
  | steps hs =>
    exact (osteps_inv ha (reach_inv H init ha hr) (reach_oinv ha hr) hs).2
  | within sel h0 hsig hij =>
    exact along_between OMono.refl (fun _ _ _ => OMono.trans)
      (orun_inv ha sel (reach_inv H init ha h0) (reach_oinv ha h0) hsig) _ _ hij
  | trans h1 _ ih1 ih2 =>
    exact OMono.trans (ih1 hr) (ih2 (later_reach H init hr h1))

/-- The outcomes record has a line for every operation from 1 to the
cursor, in order, on every node a sequence of syncs, crashes and reboots
leaves: a sync never finds a state its record does not cover. -/
theorem outcomes_cover [DecidableEq T] [DecidableEq M] [DecidableEq I]
    [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) :
    ∃ (c : Nat) (pre rest : List (OLine D)), (c : Int) = cursor n ∧
      n.outcomes = pre ++ rest ∧ pre.map (·.seq) = upto c :=
  (reach_oinv ha hr).covers

/-- No line at or below the cursor ever changes: the first lines of the
record, as many as the cursor says, are the same at every later point of
the node's history. -/
theorem outcomes_fixed [DecidableEq T] [DecidableEq M] [DecidableEq I]
    [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} (ha : Assumptions H init Signed)
    {n n' : Node T M I D} (hr : Reach H init Signed n)
    (hs : Later H init Signed n n') {k : Nat} (hk : (k : Int) ≤ cursor n) :
    n'.outcomes.take k = n.outcomes.take k :=
  (later_omono ha hr hs).2 k hk

/-- The cursor never passes the head of the publication the state
records. -/
theorem lastSeq_le_head [DecidableEq T] [DecidableEq M] [DecidableEq I]
    [DecidableEq D] {H : D → D → D} {init : D}
    {Signed : Pub T M I D → M → Prop} (ha : Assumptions H init Signed)
    {n : Node T M I D} (hr : Reach H init Signed n) {s : State T M D}
    (hst : n.state = some s) : s.lastSeq ≤ s.headSeq :=
  (reach_oinv ha hr).head s hst

/-! ### A node can always go on -/

section progress
variable [DecidableEq T] [DecidableEq M] [DecidableEq I] [DecidableEq D]
variable (H : D → D → D) (init : D)

omit [DecidableEq T] [DecidableEq M] [DecidableEq I] [DecidableEq D] in
/-- The loop over a publication's operations, numbered from `a + 1` on,
from a cursor between `a` and the last of them, leaves the cursor at the
last, whatever the selector says of each. -/
theorem loop_lastSeq (sel : Op I D → Bool) :
    ∀ (os : List (Op I D)) (a : Int) (st : State T M D),
      Consec a os → a ≤ st.lastSeq → st.lastSeq ≤ a + (os.length : Int) →
      (loop H sel st os).2.lastSeq = a + (os.length : Int)
  | [], a, st, _, h1, h2 => by
    simp only [loop, List.length_nil] at h2 ⊢
    omega
  | o :: os, a, st, hc, h1, h2 => by
    obtain ⟨ho, hc'⟩ := hc
    simp only [List.length_cons] at h2 ⊢
    unfold loop
    split
    · have := loop_lastSeq sel os (a + 1) st hc' (by omega) (by omega)
      omega
    · split
      · have := loop_lastSeq sel os (a + 1)
          { st with root := H st.root o.digest, lastSeq := o.seq } hc'
          (by simp only; omega) (by simp only; omega)
        simp only at this ⊢
        omega
      · have := loop_lastSeq sel os (a + 1) { st with lastSeq := o.seq } hc'
          (by simp only; omega) (by simp only; omega)
        simp only at this ⊢
        omega

/-- `tree_recover_pending()` refuses no reachable node that a publication
holding its pending operation reaches, when that operation is above the
cursor: one at or below the cursor is removed whatever the publication
holds, and one above it is found, its record and its line telling whether
it was applied. -/
theorem recover_progress {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed) {n : Node T M I D}
    (hr : Reach H init Signed n) {pub : Pub T M I D}
    (hpend : ∀ p, n.pending = some p → cursor n < p.seq → p ∈ pub.ops) :
    recover H init n pub (n.state.getD (fresh init pub.treeId)) ≠ none := by
  have hinv := reach_inv H init ha hr
  have hc0 : (n.state.getD (fresh init pub.treeId)).lastSeq = cursor n := by
    cases hs : n.state <;> simp [cursor, fresh, hs]
  have hr0 : (n.state.getD (fresh init pub.treeId)).root = rootAt init n := by
    cases hs : n.state <;> simp [rootAt, fresh, hs]
  unfold recover
  cases hp : n.pending with
  | none => simp
  | some p =>
    simp only
    split
    · simp
    rename_i hgt
    have hlt : cursor n < p.seq := by omega
    -- What the tree eventlog replays to: the state's root, or the root
    -- after the pending operation when its line is appended.
    have hrep : replay H init n.log = .missing ∨
        replay H init n.log = .ok (n.state.getD (fresh init pub.treeId)).root ∨
        replay H init n.log =
          .ok (H (n.state.getD (fresh init pub.treeId)).root p.digest) := by
      have hclean : Clean H init n → replay H init n.log = .missing ∨
          replay H init n.log = .ok (n.state.getD (fresh init pub.treeId)).root
          := by
        intro hc
        cases hl : n.log with
        | nil => exact Or.inl rfl
        | cons l ls =>
          right
          rw [← hl, replay_ok H init hinv.replays (by simp [hl]), hr0, hc.1]
      rcases hinv.window with ⟨hc, -⟩ | ⟨-, -, -, hc, -⟩ |
          ⟨p', L0, hp', -, hlog, hroot, -, -⟩
      · rcases hclean hc with h | h
        · exact Or.inl h
        · exact Or.inr (Or.inl h)
      · rcases hclean hc with h | h
        · exact Or.inl h
        · exact Or.inr (Or.inl h)
      · rw [hp, Option.some.injEq] at hp'
        subst hp'
        right; right
        rw [replay_ok H init hinv.replays (by simp [hlog]), hlog,
          rootOf_append, hr0, hroot]
    split
    · rename_i hf
      exact absurd (List.find?_eq_none.1 hf p (hpend p hp hlt)) (by simp)
    rename_i o hf
    have hos := List.find?_some hf
    simp only [decide_eq_true_eq] at hos
    rcases hrep with h | h | h <;> rw [h] <;> (repeat' split) <;>
      first
        | exact Option.some_ne_none _
        | (exfalso; contradiction)
        | (exfalso; injections; subst_vars; contradiction)

/-- A reachable node syncs every checked publication that follows it and
holds its pending operation, when that is above the cursor, to the end:
whatever the selector says, the sync makes no refusal and its last write
records the publication's head as the cursor. A pending operation the
publication no longer holds stops nothing once the cursor passed it. -/
theorem sync_progress {Signed : Pub T M I D → M → Prop}
    (ha : Assumptions H init Signed) {n : Node T M I D}
    (hr : Reach H init Signed n) {pub : Pub T M I D} {m : M}
    (hchk : Checked pub) (hfol : Follows pub n.state m) (hsig : Signed pub m)
    (hpend : ∀ p, n.pending = some p → cursor n < p.seq → p ∈ pub.ops)
    (sel : Op I D → Bool) :
    ∃ ws st, run H init n pub m sel = ws ++ [.state st] ∧
      st.lastSeq = pub.headSeq ∧ st.manifest = some m := by
  have hinv := reach_inv H init ha hr
  obtain ⟨⟨ws, st⟩, hrec⟩ := Option.ne_none_iff_exists'.1
    (recover_progress H init ha hr hpend)
  obtain ⟨-, -, hspec⟩ := recover_inv H init ha.binds ha.hash_inj ha.hash_init
    hinv hchk hfol hsig hrec
  obtain ⟨hcs, hlen⟩ := consec_of_checked hchk
  have hbc := base_le_cursor hfol
  have hch : cursor n ≤ pub.headSeq := by
    cases hs : n.state with
    | none =>
      have h0 : cursor n = 0 := by simp [cursor, hs]
      have := hchk.2.1
      omega
    | some s =>
      have hf := hfol
      simp only [hs, Follows] at hf
      have h0 : cursor n = s.lastSeq := by simp [cursor, hs]
      omega
  -- Recovery leaves the cursor where it was or at the pending operation,
  -- one of the publication's.
  have hst : pub.baseSeq ≤ st.lastSeq ∧ st.lastSeq ≤ pub.headSeq := by
    unfold RecoverSpec at hspec
    cases hp : n.pending with
    | none =>
      simp only [hp] at hspec
      omega
    | some p =>
      simp only [hp] at hspec
      rcases hspec with ⟨-, -, hl⟩ | ⟨-, -, -, -, hl⟩ |
          ⟨hlt, -, -, -, hl, -⟩ | ⟨hlt, -, -, hl, -⟩
      · omega
      · omega
      all_goals
        have := (consec_mem pub.ops pub.baseSeq hcs (hpend p hp hlt)).2
        omega
  unfold run
  split
  · rw [hrec]
    refine ⟨.truncate (cursor n).toNat :: _, _, rfl, ?_, rfl⟩
    exact loop_lastSeq H sel pub.ops pub.baseSeq _ hcs (by simp only; omega)
      (by simp only; omega) |>.trans hlen
  · rename_i hn
    exact absurd ⟨hchk, hfol⟩ hn

end progress

/-! ### A walk applies the tree's operations -/

section walk
variable (H : D → D → D)

/-- The writes that do not name a state: `pending.json`, its unlink, the
register with its eventlog record, the tree eventlog and the outcomes
record. -/
def Write.core : Write T M I D → Bool
  | .state _ => false
  | .truncate _ => false
  | _ => true

/-- The loop over two runs of operations is the loop over the first, then
over the second from where it left. -/
theorem loop_append (sel : Op I D → Bool) :
    ∀ (st : State T M D) (xs ys : List (Op I D)),
      loop H sel st (xs ++ ys) =
        ((loop H sel st xs).1 ++ (loop H sel (loop H sel st xs).2 ys).1,
          (loop H sel (loop H sel st xs).2 ys).2)
  | st, [], ys => by simp [loop]
  | st, o :: xs, ys => by
    simp only [List.cons_append, loop]
    split
    · exact loop_append sel st xs ys
    · split
      · rw [loop_append sel _ xs ys]
        simp
      · rw [loop_append sel _ xs ys]
        simp

/-- What the loop does depends on the cursor and the root of the state it
starts from alone, not on the publication the state names. -/
theorem loop_core_congr (sel : Op I D → Bool) :
    ∀ (os : List (Op I D)) (s s' : State T M D),
      s.lastSeq = s'.lastSeq → s.root = s'.root →
      (loop H sel s os).1.filter Write.core =
          (loop H sel s' os).1.filter Write.core ∧
        (loop H sel s os).2.lastSeq = (loop H sel s' os).2.lastSeq ∧
        (loop H sel s os).2.root = (loop H sel s' os).2.root
  | [], s, s', hl, hr => by simp [loop, hl, hr]
  | o :: os, s, s', hl, hr => by
    simp only [loop]
    by_cases h0 : o.seq ≤ s'.lastSeq
    · have h0' : o.seq ≤ s.lastSeq := by omega
      simp only [h0, h0', ↓reduceIte]
      exact loop_core_congr sel os s s' hl hr
    · have h0' : ¬o.seq ≤ s.lastSeq := by omega
      simp only [h0, h0', ↓reduceIte]
      by_cases hs : sel o = true
      · obtain ⟨h1, h2, h3⟩ := loop_core_congr sel os
          { s with root := H s.root o.digest, lastSeq := o.seq }
          { s' with root := H s'.root o.digest, lastSeq := o.seq } rfl
          (by simp [hr])
        simp only [hs, ↓reduceIte]
        refine ⟨?_, h2, h3⟩
        rw [List.filter_append, List.filter_append, h1]
        simp [List.filter_cons, Write.core, hr]
      · obtain ⟨h1, h2, h3⟩ := loop_core_congr sel os
          { s with lastSeq := o.seq } { s' with lastSeq := o.seq } rfl hr
        simp only [hs, Bool.false_eq_true, ↓reduceIte]
        refine ⟨?_, h2, h3⟩
        rw [List.filter_append, List.filter_append, h1]
        simp [List.filter_cons, Write.core, hr]

/-- The walk forwards over the segments, oldest first: each one recorded at
acceptance, `f`, which names the segment and keeps the cursor and the root,
then its operations. -/
def walkLoop (sel : Op I D → Bool) :
    State T M D → List ((State T M D → State T M D) × List (Op I D)) →
      List (Write T M I D) × State T M D
  | st, [] => ([], st)
  | st, (f, os) :: segs =>
    let r := loop H sel (f st) os
    let w := walkLoop sel r.2 segs
    (.state (f st) :: r.1 ++ w.1, w.2)

/-- A walk applies the operations the unsegmented tree has, in its order:
every write but those of the state, `pending.json`, the register and its
eventlog record, the tree eventlog and the outcomes record, is the one the
operations of all the segments taken as one publication make, and the walk
ends at the same cursor and projection root. Only what the state names, the
segment and its head and base, differs. -/
theorem walk_same_ops (sel : Op I D → Bool) :
    ∀ (segs : List ((State T M D → State T M D) × List (Op I D)))
      (st : State T M D),
      (∀ p ∈ segs, ∀ s, (p.1 s).lastSeq = s.lastSeq ∧ (p.1 s).root = s.root) →
      (walkLoop H sel st segs).1.filter Write.core =
          (loop H sel st (segs.map Prod.snd).flatten).1.filter Write.core ∧
        (walkLoop H sel st segs).2.lastSeq =
          (loop H sel st (segs.map Prod.snd).flatten).2.lastSeq ∧
        (walkLoop H sel st segs).2.root =
          (loop H sel st (segs.map Prod.snd).flatten).2.root
  | [], st, _ => by simp [walkLoop, loop]
  | (f, os) :: segs, st, hf => by
    obtain ⟨hfl, hfr⟩ := hf (f, os) List.mem_cons_self st
    obtain ⟨c1, c2, c3⟩ := loop_core_congr H sel os (f st) st hfl hfr
    obtain ⟨w1, w2, w3⟩ := walk_same_ops sel segs (loop H sel (f st) os).2
      (fun p hp => hf p (List.mem_cons_of_mem _ hp))
    obtain ⟨d1, d2, d3⟩ := loop_core_congr H sel (segs.map Prod.snd).flatten
      (loop H sel (f st) os).2 (loop H sel st os).2 c2 c3
    simp only [walkLoop, List.map_cons, List.flatten_cons]
    rw [loop_append H sel st os]
    refine ⟨?_, w2.trans d2, w3.trans d3⟩
    simp only [List.cons_append, List.filter_cons, List.filter_append]
    simp only [Write.core, Bool.false_eq_true, ↓reduceIte]
    rw [c1, w1, d1]

end walk

end Shirudo.TreeSync
